"""Host-side allowlist credential proxy (dark-factory M17 Task 2). Stdlib only.

SECURITY PROPERTY: the provider token is read HOST-SIDE from an environment
variable (`os.environ[token_env]`, resolved at request time -- never at
config load, never baked into a mount/argv/env the builder can read) and
injected into a forwarded request's auth header. It NEVER appears in a
proxy log line (`log_message` is a no-op here, and the server's own error
handler is silenced too -- see `_Server.handle_error`) and NEVER appears in
a client-visible response (the 403/500/502 refusal bodies are fixed,
token-free JSON; a forwarded response is relayed byte-for-byte from
upstream, and this proxy never echoes a request header back into a
response). A destination host that is NOT in the allowlist is refused with
403 and NOTHING is forwarded -- the allowlist check happens strictly before
any upstream connection is attempted.

Protocol: this is a classic forward proxy. The client sends an
absolute-URI request line (`GET http(s)://host/path HTTP/1.1`), exactly
what Python's `http.client`/`requests`/`curl -x` send when configured with
an HTTP_PROXY pointed at this server. The proxy parses the target host out
of that absolute URI, checks it against the allowlist, and -- if allowed --
opens a connection directly to that host:port (a real TLS connection via
`http.client.HTTPSConnection` when the target scheme is `https`, a plain
`HTTPConnection` when it's `http`), forwards the request (injecting the
auth header if the client didn't already send one), and relays the response
back unchanged (minus hop-by-hop headers).

Architecture -- this is an INJECTING proxy (see references/enterprise.md,
M17 Task 4): the builder speaks plaintext to this local proxy, and the
PROXY opens the real (TLS, for https targets) leg to the provider and
injects the credential THERE. That is the only proxy shape that can inject
a credential at all -- the token is added on the proxy->provider leg, so it
never leaves the host in the clear and never enters the sandbox. Opaque
`CONNECT` tunneling is the OPPOSITE model: the proxy relays encrypted bytes
end-to-end and by design cannot see or inject anything inside the tunnel.
So `do_CONNECT` is a clean 501 stub (it refuses rather than hanging or
half-implementing a tunnel), and the allowlist + host-side injection
property holds fully on the implemented forward path -- which is what the
M17 end-to-end test exercises. Fronting arbitrary CONNECT-using clients in
production would require TLS interception (a trusted CA installed in the
container so the proxy can terminate + re-originate TLS) -- a deliberate,
documented deferral, not a gap in the injection guarantee.

Runnable standalone:

    python df_proxy.py --port 8080 --allowlist api.example.com,api.other.com \\
        --token-env PROVIDER_TOKEN --header authorization

`serve(allowlist, token_env, *, header="authorization", port=0) -> (httpd, port)`
starts the same server on a background daemon thread for tests (ephemeral
port when port=0). Callers should call ``httpd.shutdown(); httpd.server_close()``
when done.
"""
import argparse
import http.client
import http.server
import json
import os
import threading
from urllib.parse import urlsplit, urlunsplit

_HEADER_CHOICES = ("authorization", "x-api-key")

# Headers that are connection-scoped (either hop-by-hop per RFC 7230 6.1, or
# ones this proxy recomputes itself) and must never be blindly copied through
# in either direction.
_HOP_BY_HOP = {
    "connection", "proxy-connection", "keep-alive", "transfer-encoding",
    "upgrade", "te", "trailer", "proxy-authenticate", "proxy-authorization",
}
_RESPONSE_STRIP = _HOP_BY_HOP | {"content-length"}


class AllowlistError(RuntimeError):
    """Raised for proxy CONFIGURATION problems (bad allowlist, bad header
    name, ...). Per-request allowlist denials are never an exception -- they
    are a 403 HTTP response, handled entirely inside the request handler."""


def _make_handler(allowlist, token_env, header):
    if not isinstance(allowlist, (list, tuple)) or not allowlist:
        raise AllowlistError("allowlist must be a non-empty list of hostnames")
    if not isinstance(token_env, str) or not token_env:
        raise AllowlistError("token_env must be a non-empty string (an env var NAME)")
    if header not in _HEADER_CHOICES:
        raise AllowlistError(f"header must be one of {_HEADER_CHOICES}, got {header!r}")

    allow = {h.lower() for h in allowlist}

    class _Handler(http.server.BaseHTTPRequestHandler):
        server_version = "df-proxy/1"
        protocol_version = "HTTP/1.1"

        def _send_json(self, status, obj):
            body = json.dumps(obj).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
            self.close_connection = True

        def _forward(self):
            parts = urlsplit(self.path)
            if parts.scheme not in ("http", "https") or not parts.hostname:
                self._send_json(
                    400,
                    {"error": "proxy requires an absolute-URI request target "
                              "(e.g. GET http://host/path)"},
                )
                return

            host = parts.hostname.lower()
            if host not in allow:
                # THE allowlist gate: refused before any upstream socket is
                # even opened -- nothing is forwarded, ever, for a host that
                # doesn't match.
                self._send_json(403, {"error": "host not in egress allowlist"})
                return

            port = parts.port or (443 if parts.scheme == "https" else 80)
            target = urlunsplit(("", "", parts.path or "/", parts.query, ""))

            length = int(self.headers.get("Content-Length", 0) or 0)
            body = self.rfile.read(length) if length else None

            fwd_headers = {
                k: v for k, v in self.headers.items() if k.lower() not in _HOP_BY_HOP
            }
            fwd_headers["Host"] = host if port in (80, 443) else f"{host}:{port}"
            fwd_headers["Connection"] = "close"

            if self.headers.get(header) is None:
                # Host-side read, at REQUEST time -- never at config load,
                # never cached anywhere, never passed to log_message/print.
                token = os.environ.get(token_env)
                if not token:
                    self._send_json(
                        500,
                        {"error": f"proxy misconfigured: {token_env} is not set "
                                  "in the proxy's environment"},
                    )
                    return
                if header == "authorization":
                    fwd_headers["Authorization"] = f"Bearer {token}"
                else:
                    fwd_headers["x-api-key"] = token
                # `token` goes out of scope at the end of this `if` block and
                # is never referenced again in this function -- it is not
                # logged, not put in any exception message, and not echoed
                # back to the client on any path below.

            conn = None
            try:
                if parts.scheme == "https":
                    # Real TLS upstream leg: the injecting-proxy model is
                    # builder -> proxy (local plaintext) -> proxy opens a
                    # genuine TLS connection to the provider and injects the
                    # token THERE, so the credential is never sent in the
                    # clear to a real HTTPS provider. Uses the system default
                    # verified TLS context (HTTPSConnection's default).
                    conn = http.client.HTTPSConnection(host, port, timeout=30)
                else:
                    conn = http.client.HTTPConnection(host, port, timeout=30)
                conn.request(self.command, target, body=body, headers=fwd_headers)
                resp = conn.getresponse()
                resp_body = resp.read()
            except (OSError, http.client.HTTPException, ValueError) as e:
                # Fail closed with a clean 502 for EVERY upstream error --
                # not only OSError. An http.client.HTTPException (a malformed
                # status line, IncompleteRead, ...) or a ValueError from
                # putheader must not escape and reset the client connection
                # with no HTTP response. Only the exception CLASS name is
                # surfaced -- never its message (which could echo a forwarded
                # header) and never the token.
                self._send_json(
                    502,
                    {"error": f"upstream request failed: {e.__class__.__name__}"},
                )
                return
            finally:
                if conn is not None:
                    try:
                        conn.close()
                    except Exception:
                        pass

            self.send_response(resp.status)
            for k, v in resp.getheaders():
                if k.lower() in _RESPONSE_STRIP:
                    continue
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(resp_body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(resp_body)
            self.close_connection = True

        do_GET = _forward
        do_POST = _forward
        do_PUT = _forward
        do_PATCH = _forward
        do_DELETE = _forward
        do_HEAD = _forward

        def do_CONNECT(self):
            # HTTPS tunneling: a documented, noted extension (see module
            # docstring) -- not implemented in M17 Task 2. Refuse cleanly
            # rather than hang or half-implement a tunnel.
            self._send_json(
                501,
                {"error": "CONNECT tunneling not implemented; use plain HTTP forwarding"},
            )

        def log_message(self, format, *args):  # noqa: A002 (stdlib signature)
            pass  # never log -- see module docstring's SECURITY PROPERTY

    return _Handler


class _Server(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, addr, handler_cls):
        super().__init__(addr, handler_cls)

    def handle_error(self, request, client_address):
        # Never print a traceback. The "token is never logged" property must
        # hold even on an unexpected exception, not only on the explicitly
        # handled 403/500/502 paths above -- socketserver's default
        # handle_error prints a full traceback to stderr, which this
        # overrides to a hard no-op.
        pass


def serve(allowlist, token_env, *, header="authorization", port=0):
    """Start the host-side credential proxy on a background daemon thread.

    allowlist: non-empty list of hostnames (exact match, case-insensitive)
        the proxy will forward requests to; anything else gets 403 with
        NOTHING forwarded.
    token_env: the NAME of an environment variable read HOST-SIDE (from
        os.environ, at request time) and injected as the auth header for
        any allowlisted request that doesn't already carry one from the
        client. Never an inline token value.
    header: "authorization" (default, injects `Authorization: Bearer
        <token>`) or "x-api-key" (injects `x-api-key: <token>`).

    Returns ``(httpd, port)`` -- port is the actual bound port (useful when
    port=0 requests an ephemeral one). Caller owns shutdown:
    ``httpd.shutdown(); httpd.server_close()``.
    """
    handler_cls = _make_handler(allowlist, token_env, header)
    httpd = _Server(("127.0.0.1", port), handler_cls)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd, httpd.server_address[1]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument(
        "--allowlist", required=True,
        help="comma-separated list of allowlisted hostnames",
    )
    ap.add_argument(
        "--token-env", required=True,
        help="NAME of the environment variable carrying the provider token "
             "(read host-side at request time; never a literal token)",
    )
    ap.add_argument("--header", choices=_HEADER_CHOICES, default="authorization")
    args = ap.parse_args()

    allowlist = [h.strip() for h in args.allowlist.split(",") if h.strip()]
    handler_cls = _make_handler(allowlist, args.token_env, args.header)
    httpd = _Server(("0.0.0.0", args.port), handler_cls)
    print(f"df_proxy: listening on :{args.port}, allowlist={allowlist}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
