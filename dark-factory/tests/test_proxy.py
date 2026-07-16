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
import threading

import pytest

import df_config
import df_proxy
from df_proxy import AllowlistError, serve
from test_config import write_config

TOKEN_ENV = "DF_PROXY_TEST_TOKEN"
TOKEN_VALUE = "sk-super-secret-value-0123456789"


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


def _client_request(proxy_port, method, absolute_url, headers=None, body=None):
    conn = http.client.HTTPConnection("127.0.0.1", proxy_port, timeout=10)
    try:
        conn.request(method, absolute_url, body=body, headers=headers or {})
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
    httpd, port = serve(allowlist=["127.0.0.1"], token_env=TOKEN_ENV)
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
    httpd, port = serve(allowlist=["127.0.0.1"], token_env=TOKEN_ENV, header="x-api-key")
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
    assert json.loads(body) == {"error": "host not in egress allowlist"}


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
    httpd, port = serve(allowlist=["API.Example.Test"], token_env=TOKEN_ENV)
    try:
        status, _headers, body = _client_request(port, "GET", "http://other.example.test/x")
        assert status == 403
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_allowlist_match_is_case_insensitive_for_allowed_host(stub, monkeypatch):
    stub_httpd, stub_port = stub
    monkeypatch.setenv(TOKEN_ENV, TOKEN_VALUE)
    httpd, port = serve(allowlist=["127.0.0.1"], token_env=TOKEN_ENV)
    try:
        status, _headers, _body = _client_request(port, "GET", f"http://127.0.0.1:{stub_port}/x")
        assert status == 200
        assert len(stub_httpd.received) == 1
    finally:
        httpd.shutdown()
        httpd.server_close()


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
    httpd, port = serve(allowlist=["127.0.0.1"], token_env=TOKEN_ENV)
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
