"""M17 Task 2: df_proxy -- host-side allowlist credential proxy.

The proxy's SECURITY PROPERTY under test: the provider token is read
HOST-SIDE from an env var and injected into forwarded requests; it NEVER
appears in a proxy log line or a client-visible response, and a
non-allowlisted destination host is refused (403) with nothing forwarded.

This suite covers df_proxy.py in isolation (allow/deny, host-side
injection, grep-proofing) plus the df_config.py `credential_proxy` block
validation (shape + inline-token rejection).
"""
import contextlib
import http.client
import http.server
import io
import json
import socket
import ssl
import tempfile
import threading

import pytest

import df_config
import df_proxy
from df_proxy import AllowlistError, serve
from test_config import write_config

TOKEN_ENV = "DF_PROXY_TEST_TOKEN"
TOKEN_VALUE = "sk-super-secret-value-0123456789"
# M30 (DF-03): the LOCAL workload capability token every test client presents
# via Proxy-Authorization -- distinct from TOKEN_VALUE (the PROVIDER secret
# the proxy injects). Every serve() call below is given this explicit token
# so tests are deterministic; _client_request attaches it by default.
CAP_TOKEN = "cap-test-token-do-not-confuse-with-provider-secret"


# ---------------------------------------------------------------------------
# Stub upstream: a tiny loopback http.server acting as the allowlisted host.
# It records every request's headers in a plain Python list (visible directly
# to the test process, in-memory -- NOT round-tripped through any HTTP
# response body) so tests can assert "the upstream saw the header" without
# ever needing to echo the token back through the proxy to the client.
# ---------------------------------------------------------------------------

class _StubHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _handle(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length:
            self.rfile.read(length)
        self.server.received.append(dict(self.headers.items()))
        body = b'{"ok":true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    do_GET = _handle
    do_POST = _handle

    def log_message(self, format, *args):
        pass


class _StubServer(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, addr):
        self.received = []
        super().__init__(addr, _StubHandler)


def start_stub():
    httpd = _StubServer(("127.0.0.1", 0))
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    return httpd, httpd.server_address[1]


# --- TLS upstream stub: proves the proxy opens a REAL TLS leg to an https
# target and injects the token on that leg (never sending it in the clear to
# a real provider). Uses a self-signed cert (via `cryptography`, already a
# repo dep for df_custody); the proxy's upstream TLS verification is disabled
# FOR THIS TEST ONLY (clearly scoped) since a self-signed loopback cert isn't
# in any system trust store -- production uses the default VERIFIED context.

def _self_signed_cert_files():
    import datetime as _dt
    import ipaddress
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(days=1))
        .not_valid_after(_dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    f = tempfile.NamedTemporaryFile(mode="wb", suffix=".pem", delete=False)
    f.write(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ))
    f.write(cert.public_bytes(serialization.Encoding.PEM))
    f.close()
    return f.name


class _TLSStubServer(_StubServer):
    def __init__(self, addr, certfile):
        super().__init__(addr)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile)
        self.socket = ctx.wrap_socket(self.socket, server_side=True)


def start_tls_stub():
    certfile = _self_signed_cert_files()
    httpd = _TLSStubServer(("127.0.0.1", 0), certfile)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    return httpd, httpd.server_address[1]


def start_bad_upstream():
    """A raw TCP server that answers every connection with a NON-HTTP status
    line then closes -- makes http.client raise BadStatusLine (an
    http.client.HTTPException, NOT an OSError) so we can prove the proxy
    fails closed with a clean 5xx rather than resetting the client."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    port = srv.getsockname()[1]

    def loop():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            try:
                conn.recv(65536)
                conn.sendall(b"GARBAGE NOT AN HTTP STATUS LINE\r\n\r\n")
            except OSError:
                pass
            finally:
                conn.close()

    threading.Thread(target=loop, daemon=True).start()
    return srv, port


def _client_request(proxy_port, method, absolute_url, headers=None, body=None,
                     cap_token=CAP_TOKEN):
    conn = http.client.HTTPConnection("127.0.0.1", proxy_port, timeout=10)
    try:
        headers = dict(headers or {})
        if cap_token is not None:
            # Default-attached so every pre-existing test in this file keeps
            # working against the now-mandatory capability-token gate without
            # having to know about it; pass cap_token=None to test the gate
            # itself (missing/omitted token).
            headers.setdefault("Proxy-Authorization", f"Bearer {cap_token}")
        conn.request(method, absolute_url, body=body, headers=headers)
        resp = conn.getresponse()
        resp_body = resp.read()
        return resp.status, dict(resp.getheaders()), resp_body
    finally:
        conn.close()


@pytest.fixture
def stub():
    httpd, port = start_stub()
    yield httpd, port
    httpd.shutdown()
    httpd.server_close()


@pytest.fixture
def proxy(stub, monkeypatch):
    _stub_httpd, stub_port = stub
    monkeypatch.setenv(TOKEN_ENV, TOKEN_VALUE)
    # Exact-origin allowlisting (M30/DF-03): the stub binds an EPHEMERAL
    # port, so the bare-hostname default-ports-only form wouldn't match it --
    # the allowlist entry must name this port explicitly.
    httpd, port = serve(
        allowlist=[f"127.0.0.1:{stub_port}"], token_env=TOKEN_ENV,
        capability_token=CAP_TOKEN,
    )
    yield httpd, port, stub_port
    httpd.shutdown()
    httpd.server_close()


# ---------------------------------------------------------------------------
# Allowlisted request: forwarded + auth header injected host-side
# ---------------------------------------------------------------------------

def test_allowlisted_request_is_forwarded(proxy, stub):
    httpd, port, stub_port = proxy
    stub_httpd, _stub_port = stub
    status, _headers, body = _client_request(
        port, "GET", f"http://127.0.0.1:{stub_port}/echo"
    )
    assert status == 200
    assert json.loads(body) == {"ok": True}
    assert len(stub_httpd.received) == 1


def test_injected_auth_header_came_from_env_client_never_sent_it(proxy, stub):
    httpd, port, stub_port = proxy
    stub_httpd, _stub_port = stub
    client_headers = {}  # the CLIENT sends no Authorization header at all
    _client_request(port, "GET", f"http://127.0.0.1:{stub_port}/echo", headers=client_headers)

    assert len(stub_httpd.received) == 1
    seen = stub_httpd.received[0]
    assert seen.get("Authorization") == f"Bearer {TOKEN_VALUE}"
    assert "Authorization" not in client_headers


def test_client_supplied_auth_header_is_not_overridden(proxy, stub):
    httpd, port, stub_port = proxy
    stub_httpd, _stub_port = stub
    client_auth = "Bearer client-own-token-value"
    _client_request(
        port, "GET", f"http://127.0.0.1:{stub_port}/echo",
        headers={"Authorization": client_auth},
    )
    assert len(stub_httpd.received) == 1
    seen = stub_httpd.received[0]
    # The proxy must forward exactly what the client sent -- never override
    # an auth header the client already supplied -- and the host-side token
    # must NOT appear anywhere in what was forwarded.
    assert seen.get("Authorization") == client_auth
    assert TOKEN_VALUE not in json.dumps(seen)


def test_x_api_key_header_variant_injects_bare_token(stub, monkeypatch):
    _stub_httpd, stub_port = stub
    monkeypatch.setenv(TOKEN_ENV, TOKEN_VALUE)
    httpd, port = serve(
        allowlist=[f"127.0.0.1:{stub_port}"], token_env=TOKEN_ENV, header="x-api-key",
        capability_token=CAP_TOKEN,
    )
    try:
        _client_request(port, "GET", f"http://127.0.0.1:{stub_port}/echo")
        assert len(_stub_httpd.received) == 1
        seen = _stub_httpd.received[0]
        assert seen.get("x-api-key") == TOKEN_VALUE
        assert "Authorization" not in seen
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_post_body_is_forwarded_unchanged(proxy, stub):
    httpd, port, stub_port = proxy
    stub_httpd, _stub_port = stub
    payload = b'{"hello":"world"}'
    status, _headers, body = _client_request(
        port, "POST", f"http://127.0.0.1:{stub_port}/echo",
        headers={"Content-Type": "application/json"}, body=payload,
    )
    assert status == 200
    assert len(stub_httpd.received) == 1


# ---------------------------------------------------------------------------
# Non-allowlisted host: 403, NOTHING forwarded
# ---------------------------------------------------------------------------

def test_non_allowlisted_host_refused_403(proxy, stub):
    httpd, port, _stub_port = proxy
    status, _headers, body = _client_request(
        port, "GET", "http://not-allowed.example.test/secret",
    )
    assert status == 403
    assert json.loads(body) == {"error": "origin not in egress allowlist"}


def test_non_allowlisted_host_upstream_never_contacted(proxy, stub):
    httpd, port, stub_port = proxy
    stub_httpd, _stub_port = stub
    # Same PORT as the stub, but a host string that isn't in the allowlist --
    # proves the block happens on the hostname check, before any connection.
    _client_request(port, "GET", "http://not-allowed.example.test/secret")
    assert stub_httpd.received == []


def test_non_allowlisted_host_case_insensitive_match_still_blocks(stub, monkeypatch):
    _stub_httpd, stub_port = stub
    monkeypatch.setenv(TOKEN_ENV, TOKEN_VALUE)
    httpd, port = serve(
        allowlist=["API.Example.Test"], token_env=TOKEN_ENV, capability_token=CAP_TOKEN,
    )
    try:
        status, _headers, body = _client_request(port, "GET", "http://other.example.test/x")
        assert status == 403
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_allowlist_match_is_case_insensitive_for_allowed_host(stub, monkeypatch):
    stub_httpd, stub_port = stub
    monkeypatch.setenv(TOKEN_ENV, TOKEN_VALUE)
    httpd, port = serve(
        allowlist=[f"127.0.0.1:{stub_port}"], token_env=TOKEN_ENV, capability_token=CAP_TOKEN,
    )
    try:
        status, _headers, _body = _client_request(port, "GET", f"http://127.0.0.1:{stub_port}/x")
        assert status == 200
        assert len(stub_httpd.received) == 1
    finally:
        httpd.shutdown()
        httpd.server_close()


# ---------------------------------------------------------------------------
# Real TLS upstream leg: an https target is forwarded over genuine TLS with
# the token injected on the proxy->provider leg (never sent in the clear).
# ---------------------------------------------------------------------------

def test_https_target_forwarded_over_real_tls_with_injected_token(monkeypatch):
    tls_httpd, tls_port = start_tls_stub()
    # TEST-ONLY: trust the self-signed loopback cert by disabling upstream TLS
    # verification for the proxy's default HTTPSConnection context. Production
    # keeps the default VERIFIED context (system trust store). This proves the
    # upstream leg is genuinely TLS -- a plaintext HTTPConnection could not
    # complete a handshake with this server at all.
    monkeypatch.setattr(ssl, "_create_default_https_context", ssl._create_unverified_context)
    monkeypatch.setenv(TOKEN_ENV, TOKEN_VALUE)
    proxy_httpd, proxy_port = serve(
        allowlist=[f"127.0.0.1:{tls_port}"], token_env=TOKEN_ENV, capability_token=CAP_TOKEN,
    )
    try:
        captured_err = io.StringIO()
        with contextlib.redirect_stderr(captured_err):
            status, _headers, body = _client_request(
                proxy_port, "GET", f"https://127.0.0.1:{tls_port}/secure"
            )
        assert status == 200
        assert len(tls_httpd.received) == 1
        seen = tls_httpd.received[0]
        # The upstream (reached over TLS) saw the host-side injected token...
        assert seen.get("Authorization") == f"Bearer {TOKEN_VALUE}"
        # ...and it never leaked to the client response or any log line.
        assert TOKEN_VALUE not in body.decode("utf-8", errors="replace")
        assert TOKEN_VALUE not in captured_err.getvalue()
    finally:
        proxy_httpd.shutdown()
        proxy_httpd.server_close()
        tls_httpd.shutdown()
        tls_httpd.server_close()


# ---------------------------------------------------------------------------
# Fail-closed 5xx for ALL upstream errors -- including http.client.HTTPException
# (a malformed status line), not only OSError. Client gets a clean 5xx, not a
# connection reset, and the token is absent from the response.
# ---------------------------------------------------------------------------

def test_malformed_upstream_status_line_returns_clean_5xx(monkeypatch):
    srv, bad_port = start_bad_upstream()
    monkeypatch.setenv(TOKEN_ENV, TOKEN_VALUE)
    proxy_httpd, proxy_port = serve(
        allowlist=[f"127.0.0.1:{bad_port}"], token_env=TOKEN_ENV, capability_token=CAP_TOKEN,
    )
    try:
        status, _headers, body = _client_request(
            proxy_port, "GET", f"http://127.0.0.1:{bad_port}/x"
        )
        # A clean 5xx response -- NOT a reset connection (which would surface
        # as a RemoteDisconnected/BadStatusLine raised in _client_request).
        assert status == 502
        text = body.decode("utf-8", errors="replace")
        assert TOKEN_VALUE not in text
        # Only the exception class name is surfaced, never an internal message.
        assert "BadStatusLine" in text or "upstream request failed" in text
    finally:
        proxy_httpd.shutdown()
        proxy_httpd.server_close()
        srv.close()


# ---------------------------------------------------------------------------
# CONNECT: documented as a noted extension, refused cleanly (not hung)
# ---------------------------------------------------------------------------

def test_connect_method_refused_not_implemented(proxy):
    httpd, port, _stub_port = proxy
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        conn.request("CONNECT", "127.0.0.1:443")
        resp = conn.getresponse()
        assert resp.status == 501
        resp.read()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Grep-proofing: the token value appears in NO proxy stderr/log line and NO
# client-visible response body, across the full happy-path request.
# ---------------------------------------------------------------------------

def test_token_never_in_proxy_stderr_log(proxy, stub):
    httpd, port, stub_port = proxy
    captured_out, captured_err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(captured_out), contextlib.redirect_stderr(captured_err):
        _client_request(port, "GET", f"http://127.0.0.1:{stub_port}/echo")
        _client_request(port, "GET", "http://not-allowed.example.test/secret")
    assert TOKEN_VALUE not in captured_out.getvalue()
    assert TOKEN_VALUE not in captured_err.getvalue()


def test_token_never_in_client_visible_response_body(proxy, stub):
    httpd, port, stub_port = proxy
    _status, _headers, body = _client_request(
        port, "GET", f"http://127.0.0.1:{stub_port}/echo"
    )
    assert TOKEN_VALUE not in body.decode("utf-8", errors="replace")


def test_token_never_in_403_response_body(proxy):
    httpd, port, _stub_port = proxy
    _status, _headers, body = _client_request(
        port, "GET", "http://not-allowed.example.test/secret"
    )
    assert TOKEN_VALUE not in body.decode("utf-8", errors="replace")


def test_missing_token_env_returns_500_never_crashes(stub, monkeypatch):
    _stub_httpd, stub_port = stub
    monkeypatch.delenv(TOKEN_ENV, raising=False)
    httpd, port = serve(
        allowlist=[f"127.0.0.1:{stub_port}"], token_env=TOKEN_ENV, capability_token=CAP_TOKEN,
    )
    try:
        status, _headers, body = _client_request(port, "GET", f"http://127.0.0.1:{stub_port}/echo")
        assert status == 500
        assert TOKEN_ENV in body.decode("utf-8")
        assert TOKEN_VALUE not in body.decode("utf-8")
    finally:
        httpd.shutdown()
        httpd.server_close()


# ---------------------------------------------------------------------------
# serve() / AllowlistError config-time validation
# ---------------------------------------------------------------------------

def test_serve_empty_allowlist_raises_allowlist_error():
    with pytest.raises(AllowlistError, match="allowlist"):
        serve(allowlist=[], token_env=TOKEN_ENV)


def test_serve_bad_token_env_raises_allowlist_error():
    with pytest.raises(AllowlistError, match="token_env"):
        serve(allowlist=["a.example.test"], token_env="")


def test_serve_bad_header_raises_allowlist_error():
    with pytest.raises(AllowlistError, match="header"):
        serve(allowlist=["a.example.test"], token_env=TOKEN_ENV, header="cookie")


# ---------------------------------------------------------------------------
# M30 (DF-03) Part B: capability token -- every request must present
# Proxy-Authorization: Bearer <token> matching the proxy's, or it is refused
# (407) BEFORE the allowlist/upstream is even examined. NOTHING forwarded.
# ---------------------------------------------------------------------------

def test_missing_capability_token_refused_407(proxy, stub):
    httpd, port, stub_port = proxy
    stub_httpd, _stub_port = stub
    status, _headers, body = _client_request(
        port, "GET", f"http://127.0.0.1:{stub_port}/echo", cap_token=None,
    )
    assert status == 407
    assert stub_httpd.received == []
    assert TOKEN_VALUE not in body.decode("utf-8", errors="replace")


def test_wrong_capability_token_refused_407(proxy, stub):
    httpd, port, stub_port = proxy
    stub_httpd, _stub_port = stub
    status, _headers, body = _client_request(
        port, "GET", f"http://127.0.0.1:{stub_port}/echo", cap_token="not-the-real-token",
    )
    assert status == 407
    assert stub_httpd.received == []


def test_capability_token_never_forwarded_to_upstream(proxy, stub):
    httpd, port, stub_port = proxy
    stub_httpd, _stub_port = stub
    _client_request(port, "GET", f"http://127.0.0.1:{stub_port}/echo")
    assert len(stub_httpd.received) == 1
    # Proxy-Authorization is hop-by-hop -- it authenticates the workload to
    # THIS proxy and must never reach the upstream provider.
    assert "Proxy-Authorization" not in stub_httpd.received[0]
    assert CAP_TOKEN not in json.dumps(stub_httpd.received[0])


def test_serve_without_explicit_capability_token_generates_one(stub, monkeypatch):
    _stub_httpd, stub_port = stub
    monkeypatch.setenv(TOKEN_ENV, TOKEN_VALUE)
    httpd, port = serve(allowlist=[f"127.0.0.1:{stub_port}"], token_env=TOKEN_ENV)
    try:
        assert httpd.capability_token  # non-empty, auto-generated
        # Unauthenticated request refused...
        status, _headers, _body = _client_request(
            port, "GET", f"http://127.0.0.1:{stub_port}/echo", cap_token=None,
        )
        assert status == 407
        # ...the GENERATED token, read back off httpd, works.
        status, _headers, _body = _client_request(
            port, "GET", f"http://127.0.0.1:{stub_port}/echo",
            cap_token=httpd.capability_token,
        )
        assert status == 200
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_serve_capability_token_env_is_read_once_at_serve_time(stub, monkeypatch):
    _stub_httpd, stub_port = stub
    monkeypatch.setenv(TOKEN_ENV, TOKEN_VALUE)
    monkeypatch.setenv("DF_PROXY_TEST_CAP_TOKEN", "cap-from-env-value")
    httpd, port = serve(
        allowlist=[f"127.0.0.1:{stub_port}"], token_env=TOKEN_ENV,
        capability_token_env="DF_PROXY_TEST_CAP_TOKEN",
    )
    try:
        assert httpd.capability_token == "cap-from-env-value"
        status, _headers, _body = _client_request(
            port, "GET", f"http://127.0.0.1:{stub_port}/echo", cap_token="cap-from-env-value",
        )
        assert status == 200
    finally:
        httpd.shutdown()
        httpd.server_close()


# ---------------------------------------------------------------------------
# M30 (DF-03) Part B: exact (scheme, host, port) origin match -- an
# allowlisted HOST on an unexpected port (or scheme) is refused, not
# silently forwarded.
# ---------------------------------------------------------------------------

def test_allowlisted_host_wrong_port_refused_403(proxy, stub):
    httpd, port, stub_port = proxy
    stub_httpd, _stub_port = stub
    # proxy fixture's allowlist names ONLY stub_port -- a request to the same
    # host on a DIFFERENT (unlisted) port must be refused, even though the
    # bare host matches.
    other_port = stub_port + 1 if stub_port < 65535 else stub_port - 1
    status, _headers, _body = _client_request(
        port, "GET", f"http://127.0.0.1:{other_port}/echo",
    )
    assert status == 403
    assert stub_httpd.received == []


def test_bare_host_allowlist_entry_permits_default_ports_only(stub, monkeypatch):
    _stub_httpd, stub_port = stub
    monkeypatch.setenv(TOKEN_ENV, TOKEN_VALUE)
    # A bare-hostname entry (no port) expands to the two DEFAULT ports
    # only (80/443) -- NOT "any port" (the pre-M30 behavior this closes).
    httpd, port = serve(
        allowlist=["127.0.0.1"], token_env=TOKEN_ENV, capability_token=CAP_TOKEN,
    )
    try:
        # The stub's ephemeral port is (overwhelmingly likely) neither 80
        # nor 443, so this must be refused even though the host matches.
        status, _headers, _body = _client_request(
            port, "GET", f"http://127.0.0.1:{stub_port}/echo",
        )
        assert status == 403
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_host_colon_port_allowlist_entry_permits_both_schemes_at_that_port():
    origins = df_proxy.parse_allowlist_entry("api.example.test:9443")
    assert origins == {
        ("http", "api.example.test", 9443),
        ("https", "api.example.test", 9443),
    }


def test_scheme_prefixed_allowlist_entry_is_exact_one_origin():
    assert df_proxy.parse_allowlist_entry("https://api.example.test") == {
        ("https", "api.example.test", 443)
    }
    assert df_proxy.parse_allowlist_entry("http://api.example.test:8080") == {
        ("http", "api.example.test", 8080)
    }


@pytest.mark.parametrize("bad", [
    "user@api.example.test",
    "https://user:pass@api.example.test",
    "api.example.test:80:443",
    "https://api.example.test/v1",
    "ftp://api.example.test",
    "",
    123,
])
def test_ambiguous_or_malformed_allowlist_entries_rejected(bad):
    with pytest.raises(AllowlistError):
        df_proxy.parse_allowlist_entry(bad)


def test_request_with_userinfo_in_target_refused_400(proxy):
    httpd, port, stub_port = proxy
    status, _headers, _body = _client_request(
        port, "GET", f"http://user:pass@127.0.0.1:{stub_port}/echo",
    )
    assert status == 400


# ---------------------------------------------------------------------------
# M30 (DF-03) Part B: provider method/path lock on the INJECTED-credential
# path only -- a client-supplied header is never restricted by it.
# ---------------------------------------------------------------------------

def test_provider_lock_blocks_wrong_path_for_injection(stub, monkeypatch):
    _stub_httpd, stub_port = stub
    monkeypatch.setenv(TOKEN_ENV, TOKEN_VALUE)
    httpd, port = serve(
        allowlist=[f"127.0.0.1:{stub_port}"], token_env=TOKEN_ENV,
        capability_token=CAP_TOKEN, provider="anthropic",
    )
    try:
        status, _headers, body = _client_request(
            port, "POST", f"http://127.0.0.1:{stub_port}/v1/OTHER-endpoint",
        )
        assert status == 403
        assert _stub_httpd.received == []
        assert TOKEN_VALUE not in body.decode("utf-8", errors="replace")
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_provider_lock_allows_correct_method_path(stub, monkeypatch):
    _stub_httpd, stub_port = stub
    monkeypatch.setenv(TOKEN_ENV, TOKEN_VALUE)
    httpd, port = serve(
        allowlist=[f"127.0.0.1:{stub_port}"], token_env=TOKEN_ENV,
        capability_token=CAP_TOKEN, provider="anthropic", header="x-api-key",
    )
    try:
        status, _headers, _body = _client_request(
            port, "POST", f"http://127.0.0.1:{stub_port}/v1/messages",
        )
        assert status == 200
        assert len(_stub_httpd.received) == 1
        assert _stub_httpd.received[0].get("x-api-key") == TOKEN_VALUE
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_provider_lock_does_not_apply_to_client_supplied_header(stub, monkeypatch):
    # The method/path lock guards the INJECTION path only -- a request that
    # already carries its own auth header is forwarded exactly like before
    # (no injection happens, so there is no injected credential to scope).
    _stub_httpd, stub_port = stub
    monkeypatch.setenv(TOKEN_ENV, TOKEN_VALUE)
    httpd, port = serve(
        allowlist=[f"127.0.0.1:{stub_port}"], token_env=TOKEN_ENV,
        capability_token=CAP_TOKEN, provider="anthropic", header="x-api-key",
    )
    try:
        status, _headers, _body = _client_request(
            port, "GET", f"http://127.0.0.1:{stub_port}/echo",
            headers={"x-api-key": "client-own-key"},
        )
        assert status == 200
        assert _stub_httpd.received[0].get("x-api-key") == "client-own-key"
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_serve_bad_provider_raises_allowlist_error():
    with pytest.raises(AllowlistError, match="provider"):
        serve(allowlist=["a.example.test"], token_env=TOKEN_ENV, provider="not-a-real-provider")


# ---------------------------------------------------------------------------
# df_config.py: cfg["_proxy"] shape validation
# ---------------------------------------------------------------------------

def test_credential_proxy_absent_defaults_disabled(tmp_path):
    cr = tmp_path / "control"
    write_config(cr)
    cfg = df_config.load_config(str(cr))
    assert cfg["_proxy"] == {"enabled": False}


def test_credential_proxy_valid_enabled_block(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, credential_proxy={
        "enabled": True,
        "allowlist": ["api.example.test", "api.other.test"],
        "token_env": "PROVIDER_TOKEN",
    })
    cfg = df_config.load_config(str(cr))
    assert cfg["_proxy"] == {
        "enabled": True,
        "allowlist": ["api.example.test", "api.other.test"],
        "token_env": "PROVIDER_TOKEN",
        "header": "authorization",
    }


def test_credential_proxy_x_api_key_header(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, credential_proxy={
        "enabled": True, "allowlist": ["api.example.test"],
        "token_env": "PROVIDER_TOKEN", "header": "x-api-key",
    })
    cfg = df_config.load_config(str(cr))
    assert cfg["_proxy"]["header"] == "x-api-key"


def test_credential_proxy_disabled_with_extra_fields_still_disabled(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, credential_proxy={
        "enabled": False, "allowlist": ["api.example.test"], "token_env": "PROVIDER_TOKEN",
    })
    cfg = df_config.load_config(str(cr))
    # allowlist/token_env are only meaningful (and only validated) when
    # enabled: true -- a disabled block always collapses to exactly this.
    assert cfg["_proxy"] == {"enabled": False}


def test_credential_proxy_non_dict_block_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, credential_proxy="oops")
    with pytest.raises(df_config.ConfigError, match="credential_proxy"):
        df_config.load_config(str(cr))


def test_credential_proxy_inline_token_rejected_even_when_enabled(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, credential_proxy={
        "enabled": True, "allowlist": ["api.example.test"],
        "token": "sk-inline-literal-secret",
    })
    with pytest.raises(df_config.ConfigError, match="token"):
        df_config.load_config(str(cr))


def test_credential_proxy_inline_token_rejected_even_when_disabled(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, credential_proxy={
        "enabled": False, "token": "sk-inline-literal-secret",
    })
    with pytest.raises(df_config.ConfigError, match="token"):
        df_config.load_config(str(cr))


def test_credential_proxy_enabled_empty_allowlist_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, credential_proxy={
        "enabled": True, "allowlist": [], "token_env": "PROVIDER_TOKEN",
    })
    with pytest.raises(df_config.ConfigError, match="allowlist"):
        df_config.load_config(str(cr))


def test_credential_proxy_enabled_missing_allowlist_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, credential_proxy={"enabled": True, "token_env": "PROVIDER_TOKEN"})
    with pytest.raises(df_config.ConfigError, match="allowlist"):
        df_config.load_config(str(cr))


def test_credential_proxy_enabled_missing_token_env_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, credential_proxy={"enabled": True, "allowlist": ["api.example.test"]})
    with pytest.raises(df_config.ConfigError, match="token_env"):
        df_config.load_config(str(cr))


@pytest.mark.parametrize("bad", ["lowercase_name", "1LEADING_DIGIT", "has-dash", "", 12345, None])
def test_credential_proxy_malformed_token_env_rejected(tmp_path, bad):
    cr = tmp_path / "control"
    write_config(cr, credential_proxy={
        "enabled": True, "allowlist": ["api.example.test"], "token_env": bad,
    })
    with pytest.raises(df_config.ConfigError, match="token_env"):
        df_config.load_config(str(cr))


def test_credential_proxy_bad_header_value_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, credential_proxy={
        "enabled": True, "allowlist": ["api.example.test"],
        "token_env": "PROVIDER_TOKEN", "header": "cookie",
    })
    with pytest.raises(df_config.ConfigError, match="header"):
        df_config.load_config(str(cr))


def test_credential_proxy_allowlist_non_string_entry_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, credential_proxy={
        "enabled": True, "allowlist": ["api.example.test", 123], "token_env": "PROVIDER_TOKEN",
    })
    with pytest.raises(df_config.ConfigError, match="allowlist"):
        df_config.load_config(str(cr))


def test_credential_proxy_enabled_not_bool_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, credential_proxy={"enabled": "yes"})
    with pytest.raises(df_config.ConfigError, match="enabled"):
        df_config.load_config(str(cr))


# ---------------------------------------------------------------------------
# M30 (DF-03) Part C: adapter <-> provider host <-> allowlist <-> injection
# header coherence, checked at config LOAD time -- a wrong pairing between
# roles.builder.adapter (one of the two API adapters) and credential_proxy's
# header/allowlist fails to LOAD, rather than failing only when a real
# enterprise run tries (and fails) to reach the provider.
# ---------------------------------------------------------------------------

def _api_adapter_roles(name):
    return {"builder": {"adapter": f"/some/path/{name}", "timeout_s": 60}}


def test_credential_proxy_anthropic_adapter_wrong_header_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, roles=_api_adapter_roles("api_anthropic"), credential_proxy={
        "enabled": True, "allowlist": ["api.anthropic.com"],
        "token_env": "PROVIDER_TOKEN", "header": "authorization",
    })
    with pytest.raises(df_config.ConfigError, match="header"):
        df_config.load_config(str(cr))


def test_credential_proxy_openai_adapter_wrong_header_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, roles=_api_adapter_roles("api_openai"), credential_proxy={
        "enabled": True, "allowlist": ["api.openai.com"],
        "token_env": "PROVIDER_TOKEN", "header": "x-api-key",
    })
    with pytest.raises(df_config.ConfigError, match="header"):
        df_config.load_config(str(cr))


def test_credential_proxy_anthropic_adapter_missing_host_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, roles=_api_adapter_roles("api_anthropic"), credential_proxy={
        "enabled": True, "allowlist": ["api.openai.com"],
        "token_env": "PROVIDER_TOKEN", "header": "x-api-key",
    })
    with pytest.raises(df_config.ConfigError, match="allowlist"):
        df_config.load_config(str(cr))


def test_credential_proxy_openai_adapter_missing_host_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, roles=_api_adapter_roles("api_openai"), credential_proxy={
        "enabled": True, "allowlist": ["api.anthropic.com"],
        "token_env": "PROVIDER_TOKEN", "header": "authorization",
    })
    with pytest.raises(df_config.ConfigError, match="allowlist"):
        df_config.load_config(str(cr))


def test_credential_proxy_anthropic_adapter_correct_pairing_loads(tmp_path):
    cr = tmp_path / "control"
    cfg = write_config(cr, roles=_api_adapter_roles("api_anthropic"), credential_proxy={
        "enabled": True, "allowlist": ["api.anthropic.com"],
        "token_env": "PROVIDER_TOKEN", "header": "x-api-key",
    })
    loaded = df_config.load_config(str(cr))
    assert loaded["_proxy"]["enabled"] is True


def test_credential_proxy_openai_adapter_correct_pairing_loads(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, roles=_api_adapter_roles("api_openai"), credential_proxy={
        "enabled": True, "allowlist": ["api.openai.com"],
        "token_env": "PROVIDER_TOKEN", "header": "authorization",
    })
    loaded = df_config.load_config(str(cr))
    assert loaded["_proxy"]["enabled"] is True


def test_credential_proxy_anthropic_adapter_host_port_allowlist_form_loads(tmp_path):
    # allowlist entries may use df_proxy's "host:port" / "scheme://host"
    # forms too -- the coherence check reads the HOST back out via
    # df_proxy.parse_allowlist_entry, not a literal string match.
    cr = tmp_path / "control"
    write_config(cr, roles=_api_adapter_roles("api_anthropic"), credential_proxy={
        "enabled": True, "allowlist": ["https://api.anthropic.com:443"],
        "token_env": "PROVIDER_TOKEN", "header": "x-api-key",
    })
    loaded = df_config.load_config(str(cr))
    assert loaded["_proxy"]["enabled"] is True


def test_credential_proxy_non_api_adapter_skips_coherence_check(tmp_path):
    # A CLI adapter (or any non-api_* adapter) never reads DF_PROXY_DESCRIPTOR
    # -- the coherence check simply doesn't apply, no matter how the
    # allowlist/header are set.
    cr = tmp_path / "control"
    write_config(cr, credential_proxy={
        "enabled": True, "allowlist": ["totally-unrelated.example.test"],
        "token_env": "PROVIDER_TOKEN", "header": "authorization",
    })
    loaded = df_config.load_config(str(cr))
    assert loaded["_proxy"]["enabled"] is True


def test_credential_proxy_disabled_skips_coherence_check_even_for_api_adapter(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, roles=_api_adapter_roles("api_anthropic"), credential_proxy={
        "enabled": False, "allowlist": ["api.openai.com"],
        "token_env": "PROVIDER_TOKEN", "header": "authorization",
    })
    loaded = df_config.load_config(str(cr))
    assert loaded["_proxy"] == {"enabled": False}
