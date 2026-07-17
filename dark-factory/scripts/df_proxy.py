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
documented deferral, not a gap in the injection guarantee. This is also
exactly why a builder cannot reach this proxy via urllib's ordinary
HTTP(S)_PROXY handling: urllib CONNECT-tunnels an https:// target through
an env-configured proxy, which lands on the 501 stub -- see
references/enterprise.md's "API-adapter proxy mode" section and the
`DF_PROXY_DESCRIPTOR` transport the adapters use instead (M30/DF-03).

Runnable standalone:

    python df_proxy.py --port 8080 --allowlist api.example.com,api.other.com \\
        --token-env PROVIDER_TOKEN --header authorization

`serve(allowlist, token_env, *, header="authorization", port=0,
capability_token=None, capability_token_env=None, provider=None,
allowed_method_path=None) -> (httpd, port)` starts the same server on a
background daemon thread for tests (ephemeral port when port=0). Callers
should call ``httpd.shutdown(); httpd.server_close()`` when done.

M30 (DF-03) hardening -- three additions on top of the M17 shape, all
fail-closed:

- **Capability token.** Every forwarded request must present
  `Proxy-Authorization: Bearer <token>` matching the proxy's capability
  token, or it is refused (407) BEFORE any allowlist/upstream work --
  nothing is forwarded. This is a *local workload* credential (which
  process on this host may use the injecting proxy at all), completely
  distinct from the *provider* credential the proxy injects -- it is
  never sent to the provider (`Proxy-Authorization` is already stripped as
  hop-by-hop) and never logged. `serve()` accepts an explicit
  `capability_token`, or a `capability_token_env` (name of an env var read
  once at serve() time), or -- if neither is given -- generates one via
  `secrets.token_urlsafe` and exposes it as `httpd.capability_token` so the
  caller can hand it to whatever it authorizes (e.g. a container descriptor).
- **Exact origin match.** The allowlist used to match hostname only (any
  port, any scheme) -- a request to an allowlisted host on an unexpected
  port was silently forwarded. `serve()` now resolves each allowlist entry
  to a canonical `(scheme, host, port)` set via `parse_allowlist_entry`
  (bare `"host"` -> the two DEFAULT ports only, `"host:port"` -> that exact
  port on both schemes, `"scheme://host[:port]"` -> exactly that one
  origin) and every incoming request's target origin must match exactly.
  Ambiguous request forms (userinfo in the URL) are refused outright.
- **Provider method/path lock.** When `provider` (or an explicit
  `allowed_method_path=(method, path)` override) is given, a request that
  is about to receive an INJECTED credential (i.e. the client sent no auth
  header of its own) must also match that method+path exactly, or it is
  refused (403) and NOTHING is forwarded/injected -- so a stolen capability
  token can ride the injecting proxy only to the one endpoint it was scoped
  for, not to arbitrary provider APIs. A client-supplied auth header (never
  the injection path) is not method/path-restricted.
"""
import argparse
import hmac
import http.client
import http.server
import json
import os
import secrets
import sys
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

_DEFAULT_PORTS = {"http": 80, "https": 443}

# Default injected-credential method+path lock per provider (M30/DF-03 Part
# B, defense-in-depth): a capability token scoped to one of these providers
# can only ride the injecting proxy to this one endpoint. Operator-overridable
# via `allowed_method_path`.
_PROVIDER_METHOD_PATH = {
    "anthropic": ("POST", "/v1/messages"),
    "openai": ("POST", "/v1/chat/completions"),
}


class AllowlistError(RuntimeError):
    """Raised for proxy CONFIGURATION problems (bad allowlist, bad header
    name, ...). Per-request allowlist denials are never an exception -- they
    are a 403 HTTP response, handled entirely inside the request handler."""


def parse_allowlist_entry(entry):
    """Parse ONE allowlist entry into a set of canonical `(scheme, host,
    port)` origin tuples -- the ONE strict canonical-origin parser used both
    to build the proxy's allow-set and (via df_config.py's credential_proxy
    coherence check) to read a host back out of a configured entry. Accepted
    forms:

      - `"host"` -- bare hostname; expands to EXACTLY the two default-port
        origins `(http, host, 80)` and `(https, host, 443)`. This is
        intentionally narrower than the pre-M30 behavior (which matched
        `host` on ANY port) -- an arbitrary port on an allowlisted host is
        no longer implicitly allowed.
      - `"host:port"` -- an exact port, either scheme: `(http, host, port)`
        and `(https, host, port)`.
      - `"scheme://host"` or `"scheme://host:port"` -- exactly one origin,
        `scheme` must be `http` or `https`, port defaults per scheme when
        omitted.

    Ambiguous/ill-formed entries (userinfo, a path/query/fragment, more than
    one bare `:`, a non-numeric or out-of-range port, an empty host) raise
    `AllowlistError` naming the problem -- never guessed at."""
    if not isinstance(entry, str) or not entry:
        raise AllowlistError(f"allowlist entry must be a non-empty string, got {entry!r}")
    if "://" in entry:
        parts = urlsplit(entry)
        if parts.scheme not in ("http", "https"):
            raise AllowlistError(f"allowlist entry has an unsupported scheme: {entry!r}")
        if "@" in parts.netloc:
            raise AllowlistError(f"allowlist entry must not contain userinfo: {entry!r}")
        if not parts.hostname:
            raise AllowlistError(f"allowlist entry is missing a host: {entry!r}")
        if parts.path not in ("", "/") or parts.query or parts.fragment:
            raise AllowlistError(
                f"allowlist entry must be a bare origin (no path/query/fragment): {entry!r}"
            )
        port = parts.port if parts.port is not None else _DEFAULT_PORTS[parts.scheme]
        return {(parts.scheme, parts.hostname.lower(), port)}
    if "@" in entry:
        raise AllowlistError(f"allowlist entry must not contain userinfo: {entry!r}")
    if entry.count(":") > 1:
        raise AllowlistError(
            f"ambiguous allowlist entry (use scheme://host:port): {entry!r}"
        )
    if ":" in entry:
        host, _, port_s = entry.partition(":")
        if not host:
            raise AllowlistError(f"allowlist entry is missing a host: {entry!r}")
        try:
            port = int(port_s)
        except ValueError:
            raise AllowlistError(
                f"allowlist entry has a non-numeric port: {entry!r}"
            ) from None
        if not (1 <= port <= 65535):
            raise AllowlistError(f"allowlist entry port out of range 1..65535: {entry!r}")
        host = host.lower()
        return {("http", host, port), ("https", host, port)}
    host = entry.lower()
    return {("http", host, _DEFAULT_PORTS["http"]), ("https", host, _DEFAULT_PORTS["https"])}


def _resolve_capability_token(capability_token, capability_token_env):
    if capability_token is not None:
        if not isinstance(capability_token, str) or not capability_token:
            raise AllowlistError("capability_token must be a non-empty string")
        return capability_token
    if capability_token_env is not None:
        if not isinstance(capability_token_env, str) or not capability_token_env:
            raise AllowlistError(
                "capability_token_env must be a non-empty string (an env var NAME)"
            )
        value = os.environ.get(capability_token_env)
        if not value:
            raise AllowlistError(
                f"capability_token_env {capability_token_env!r} is not set "
                "in this process's environment"
            )
        return value
    # Neither given: generate one. This is ALWAYS enforced (never "no
    # token required") -- a caller that doesn't wire an explicit token
    # still gets a proxy that refuses every unauthenticated request; it
    # just has to read `httpd.capability_token` back to authorize anyone.
    return secrets.token_urlsafe(32)


def _resolve_method_path(provider, allowed_method_path):
    if allowed_method_path is not None:
        method, path = allowed_method_path
        if not isinstance(method, str) or not method or not isinstance(path, str) or not path:
            raise AllowlistError("allowed_method_path must be a (method, path) pair of strings")
        return (method.upper(), path)
    if provider is not None:
        if provider not in _PROVIDER_METHOD_PATH:
            raise AllowlistError(
                f"provider must be one of {sorted(_PROVIDER_METHOD_PATH)}, got {provider!r}"
            )
        return _PROVIDER_METHOD_PATH[provider]
    return None


def _make_handler(allowlist, token_env, header, capability_token, method_path):
    if not isinstance(allowlist, (list, tuple)) or not allowlist:
        raise AllowlistError("allowlist must be a non-empty list of hostnames")
    if not isinstance(token_env, str) or not token_env:
        raise AllowlistError("token_env must be a non-empty string (an env var NAME)")
    if header not in _HEADER_CHOICES:
        raise AllowlistError(f"header must be one of {_HEADER_CHOICES}, got {header!r}")

    allow_origins = set()
    for entry in allowlist:
        allow_origins |= parse_allowlist_entry(entry)

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
            # Capability-token gate FIRST, before anything else is even
            # parsed: a workload that can't prove it's authorized to use
            # this injecting proxy gets refused before the target host, the
            # method/path, or anything else about the request is examined.
            # NOTHING is forwarded. Constant-time comparison (hmac.compare_
            # digest) so response timing can't be used to brute-force the
            # token a byte at a time.
            presented = self.headers.get("Proxy-Authorization")
            expected = f"Bearer {capability_token}"
            if presented is None or not hmac.compare_digest(presented, expected):
                self._send_json(407, {"error": "proxy authentication required"})
                return

            parts = urlsplit(self.path)
            if parts.scheme not in ("http", "https") or not parts.hostname:
                self._send_json(
                    400,
                    {"error": "proxy requires an absolute-URI request target "
                              "(e.g. GET http://host/path)"},
                )
                return
            if "@" in parts.netloc:
                # Ambiguous form (userinfo in the request target) -- refused
                # rather than guessed at, same posture as the allowlist parser.
                self._send_json(
                    400, {"error": "proxy request target must not contain userinfo"}
                )
                return

            host = parts.hostname.lower()
            port = parts.port if parts.port is not None else _DEFAULT_PORTS[parts.scheme]
            origin = (parts.scheme, host, port)
            if origin not in allow_origins:
                # THE allowlist gate: refused before any upstream socket is
                # even opened -- nothing is forwarded, ever, for an origin
                # (scheme, host, AND port) that doesn't match exactly.
                self._send_json(403, {"error": "origin not in egress allowlist"})
                return

            target = urlunsplit(("", "", parts.path or "/", parts.query, ""))

            length = int(self.headers.get("Content-Length", 0) or 0)
            body = self.rfile.read(length) if length else None

            fwd_headers = {
                k: v for k, v in self.headers.items() if k.lower() not in _HOP_BY_HOP
            }
            fwd_headers["Host"] = host if port in (80, 443) else f"{host}:{port}"
            fwd_headers["Connection"] = "close"

            if self.headers.get(header) is None:
                # This IS the credential-injection path (the client sent no
                # auth header of its own) -- defense-in-depth: lock it to the
                # provider's expected method+path BEFORE reading or injecting
                # any token, so a request that strayed off the one endpoint
                # this proxy is scoped for never gets the credential at all.
                if method_path is not None:
                    exp_method, exp_path = method_path
                    if self.command != exp_method or parts.path != exp_path:
                        self._send_json(
                            403,
                            {"error": "method/path not allowed for credential injection"},
                        )
                        return
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


def serve(allowlist, token_env, *, header="authorization", port=0,
          capability_token=None, capability_token_env=None, provider=None,
          allowed_method_path=None):
    """Start the host-side credential proxy on a background daemon thread.

    allowlist: non-empty list of allowlist entries (see
        `parse_allowlist_entry` for the accepted forms); anything whose
        (scheme, host, port) doesn't match exactly gets 403 with NOTHING
        forwarded.
    token_env: the NAME of an environment variable read HOST-SIDE (from
        os.environ, at request time) and injected as the auth header for
        any allowlisted request that doesn't already carry one from the
        client. Never an inline token value.
    header: "authorization" (default, injects `Authorization: Bearer
        <token>`) or "x-api-key" (injects `x-api-key: <token>`).
    capability_token / capability_token_env: the LOCAL workload credential
        (distinct from the provider token above) every request must present
        via `Proxy-Authorization: Bearer <token>`, or it is refused (407)
        before anything else. Give an explicit token, or the NAME of an env
        var to read it from once at serve() time; if neither is given, one
        is generated (`secrets.token_urlsafe`) and exposed as
        `httpd.capability_token` -- a token is ALWAYS enforced, never optional.
    provider / allowed_method_path: optional injected-credential method+path
        lock (M30/DF-03 Part B). `provider="anthropic"|"openai"` applies that
        provider's default lock (`POST /v1/messages` / `POST
        /v1/chat/completions`); `allowed_method_path=(method, path)` sets a
        custom one. Only a request receiving an INJECTED credential (client
        sent no auth header of its own) is checked against it. Neither given
        -> no method/path restriction (legacy behavior).

    Returns ``(httpd, port)`` -- port is the actual bound port (useful when
    port=0 requests an ephemeral one), and `httpd.capability_token` is the
    resolved capability token (whether given explicitly, read from env, or
    generated). Caller owns shutdown: ``httpd.shutdown(); httpd.server_close()``.
    """
    resolved_token = _resolve_capability_token(capability_token, capability_token_env)
    method_path = _resolve_method_path(provider, allowed_method_path)
    handler_cls = _make_handler(allowlist, token_env, header, resolved_token, method_path)
    httpd = _Server(("127.0.0.1", port), handler_cls)
    httpd.capability_token = resolved_token
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd, httpd.server_address[1]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument(
        "--allowlist", required=True,
        help="comma-separated list of allowlisted origins (see "
             "parse_allowlist_entry for the accepted forms)",
    )
    ap.add_argument(
        "--token-env", required=True,
        help="NAME of the environment variable carrying the provider token "
             "(read host-side at request time; never a literal token)",
    )
    ap.add_argument("--header", choices=_HEADER_CHOICES, default="authorization")
    ap.add_argument(
        "--capability-token", default=None,
        help="the LOCAL workload credential clients must present via "
             "Proxy-Authorization: Bearer <token>; generated and printed "
             "(to stderr) if omitted -- this is NEVER the provider token",
    )
    ap.add_argument(
        "--capability-token-env", default=None,
        help="NAME of an env var to read the capability token from instead "
             "of --capability-token",
    )
    ap.add_argument(
        "--provider", choices=sorted(_PROVIDER_METHOD_PATH), default=None,
        help="lock injected-credential requests to this provider's expected "
             "method+path (defense-in-depth; default: no restriction)",
    )
    args = ap.parse_args()

    allowlist = [h.strip() for h in args.allowlist.split(",") if h.strip()]
    resolved_token = _resolve_capability_token(args.capability_token, args.capability_token_env)
    method_path = _resolve_method_path(args.provider, None)
    handler_cls = _make_handler(
        allowlist, args.token_env, args.header, resolved_token, method_path
    )
    httpd = _Server(("0.0.0.0", args.port), handler_cls)
    print(f"df_proxy: listening on :{args.port}, allowlist={allowlist}")
    if args.capability_token is None and args.capability_token_env is None:
        # Only the auto-generated case is ever surfaced -- an explicitly
        # given token (CLI arg or env var) is the caller's own secret and is
        # never echoed back. stderr, not stdout, to keep stdout parse-clean.
        print(f"df_proxy: generated capability token: {resolved_token}", file=sys.stderr)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
