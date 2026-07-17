"""M30 (DF-03, High): the enterprise credential proxy and the shipped API
adapters were incompatible -- enterprise passes env=None to the builder
container (df_proxy is supposed to inject the provider key host-side), but
api_anthropic/api_openai (a) exited when their key env var was absent and
(b) set their OWN auth header (blocking injection), and even a "just don't
exit" fix couldn't work because an HTTPS request via urllib+HTTP(S)_PROXY
CONNECT-tunnels through the proxy, landing on df_proxy's 501 CONNECT stub
(opaque tunnels cannot be credential-injected).

This is the KEY end-to-end proof that the fix (adapter `DF_PROXY_DESCRIPTOR`
proxy mode + df_proxy's plaintext absolute-URI forward form) actually
closes that gap: a REAL in-process df_proxy (`df_proxy.serve`), a REAL
adapter subprocess with NO provider key anywhere in its environment, and a
REAL stub "provider" HTTP server that RECORDS the headers it receives --
so injection is proven by what the far end of the wire actually saw, not by
inspecting the adapter's own request construction.

Also proves the two refusal paths df_proxy's hardening adds (M30 Part B):
a request without the right capability token, and a request to an
origin/port outside the allowlist, are both refused with nothing forwarded.
And that DF_PROXY_DESCRIPTOR UNSET still drives the pre-M30 direct-key path
byte-identically (no regression to the existing, non-enterprise adapters).
"""
import http.server
import json
import os
import subprocess
import sys
import threading

import pytest

import df_proxy
from df_proxy import serve

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS_DIR = os.path.join(HERE, "..", "scripts")
ADAPTER_ANTHROPIC = os.path.join(SCRIPTS_DIR, "adapters", "api_anthropic")
ADAPTER_OPENAI = os.path.join(SCRIPTS_DIR, "adapters", "api_openai")

PROVIDER_TOKEN_ENV = "DF_TRANSPORT_TEST_PROVIDER_TOKEN"
PROVIDER_TOKEN_VALUE = "sk-real-provider-secret-DO-NOT-LEAK-0123456789"
CAP_TOKEN = "cap-transport-test-token-abc123"
DIRECT_KEY = "direct-mode-test-key-do-not-confuse-with-provider-token"


# ---------------------------------------------------------------------------
# In-process stub "provider": records every request's method/path/headers so
# a test can assert on exactly what the far end of the wire saw, without any
# secret ever having to be echoed back through a response body.
# ---------------------------------------------------------------------------

class _RecordingHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _handle(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length) if length else b""
        self.server.received.append({
            "method": self.command,
            "path": self.path,
            "headers": dict(self.headers.items()),
            "body": body,
        })
        if self.path == "/v1/messages":
            reply_text = json.dumps({"files": {"greet.py": "print('hi')\n"}})
            resp = {
                "content": [{"type": "text", "text": reply_text}],
                "usage": {"input_tokens": 7, "output_tokens": 9},
            }
        elif self.path == "/v1/chat/completions":
            reply_text = json.dumps({"files": {"greet.py": "print('hi')\n"}})
            resp = {
                "choices": [{"message": {"content": reply_text}}],
                "usage": {"prompt_tokens": 7, "completion_tokens": 9},
            }
        else:
            self._write(404, {"error": "not found"})
            return
        self._write(200, resp)

    def _write(self, status, obj):
        payload = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload)
        self.close_connection = True

    do_GET = _handle
    do_POST = _handle

    def log_message(self, *a):
        pass


class _RecordingServer(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, addr):
        self.received = []
        super().__init__(addr, _RecordingHandler)


def _start_provider_stub():
    httpd = _RecordingServer(("127.0.0.1", 0))
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    return httpd, httpd.server_address[1]


@pytest.fixture
def provider_stub():
    httpd, port = _start_provider_stub()
    yield httpd, port
    httpd.shutdown()
    httpd.server_close()


def _start_proxy(stub_port, provider, header, monkeypatch):
    monkeypatch.setenv(PROVIDER_TOKEN_ENV, PROVIDER_TOKEN_VALUE)
    httpd, port = serve(
        allowlist=[f"127.0.0.1:{stub_port}"],
        token_env=PROVIDER_TOKEN_ENV,
        header=header,
        capability_token=CAP_TOKEN,
        provider=provider,
    )
    return httpd, port


def _make_req(tmp_path, timeout_s=20):
    ws = tmp_path / "ws"
    ws.mkdir(parents=True, exist_ok=True)
    pf = tmp_path / "prompt.md"
    pf.write_text("Build greet.py per SPEC.", encoding="utf-8")
    return {
        "adapter_protocol": "0.1",
        "role": "builder",
        "workdir": str(ws),
        "prompt_file": str(pf),
        "timeout_s": timeout_s,
        "confine": False,
    }


def _invoke_adapter(adapter, req, env_overrides):
    env = dict(os.environ)
    # Enterprise's real posture is env=None into the builder container --
    # scrub any provider key that might be sitting in the parent test
    # process's own environment so the adapter genuinely has NONE, matching
    # what df_container passes at enterprise (not just "unset by us here").
    env.pop("ANTHROPIC_API_KEY", None)
    env.pop("OPENAI_API_KEY", None)
    env.update(env_overrides)
    return subprocess.run(
        [adapter], input=json.dumps(req), capture_output=True, text=True,
        timeout=30, env=env,
    )


# ---------------------------------------------------------------------------
# THE key assertion: adapter (subprocess, NO provider key in env) -> proxy
# mode -> the STUB PROVIDER receives the INJECTED credential; the adapter
# never sent its own auth header at all.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("adapter,provider,header,path,inj_header", [
    (ADAPTER_ANTHROPIC, "anthropic", "x-api-key", "/v1/messages", "x-api-key"),
    (ADAPTER_OPENAI, "openai", "authorization", "/v1/chat/completions", "Authorization"),
])
def test_adapter_proxy_mode_credential_is_injected_not_sent_by_adapter(
    tmp_path, provider_stub, monkeypatch, adapter, provider, header, path, inj_header,
):
    stub_httpd, stub_port = provider_stub
    proxy_httpd, proxy_port = _start_proxy(stub_port, provider, header, monkeypatch)
    try:
        descriptor = json.dumps({
            "endpoint": f"http://127.0.0.1:{proxy_port}",
            "provider": provider,
            "target_base_url": f"http://127.0.0.1:{stub_port}",
            "capability_token": CAP_TOKEN,
        })
        req = _make_req(tmp_path)
        proc = _invoke_adapter(adapter, req, {"DF_PROXY_DESCRIPTOR": descriptor})

        assert proc.returncode == 0, proc.stderr
        resp = json.loads(proc.stdout)
        assert resp["status"] == "ok", resp.get("detail")
        assert os.path.isfile(os.path.join(req["workdir"], "greet.py"))

        # THE key assertion: the far end of the wire (the stub provider, NOT
        # the adapter's own request construction) received the credential
        # the PROXY injected -- proving the proxy's host-side injection
        # actually reached the provider leg through this adapter's transport.
        assert len(stub_httpd.received) == 1
        seen = stub_httpd.received[0]
        assert seen["method"] == "POST"
        assert seen["path"] == path
        expected_value = (
            PROVIDER_TOKEN_VALUE if inj_header == "x-api-key"
            else f"Bearer {PROVIDER_TOKEN_VALUE}"
        )
        assert seen["headers"].get(inj_header) == expected_value

        # The adapter never had a provider key to send -- and the only way
        # the stub could see the REAL PROVIDER_TOKEN_VALUE (which was never
        # in the adapter's env) is that df_proxy injected it. The capability
        # token (a DIFFERENT secret) must never reach the provider leg.
        assert CAP_TOKEN not in json.dumps(seen["headers"])
        assert CAP_TOKEN not in seen["body"].decode("utf-8", errors="replace")
        assert "Proxy-Authorization" not in seen["headers"]

        # No secret leaked to the adapter's own stdout/stderr or written files.
        assert PROVIDER_TOKEN_VALUE not in proc.stdout
        assert PROVIDER_TOKEN_VALUE not in proc.stderr
        assert CAP_TOKEN not in proc.stdout
        assert CAP_TOKEN not in proc.stderr
    finally:
        proxy_httpd.shutdown()
        proxy_httpd.server_close()


def test_adapter_proxy_mode_never_requires_provider_key_env(tmp_path, provider_stub, monkeypatch):
    # A no-api-key exit under proxy mode would be exactly the DF-03 bug --
    # confirm the adapter builds successfully with ANTHROPIC_API_KEY absent
    # from its entire environment (already enforced by _invoke_adapter, but
    # asserted explicitly here as the regression this milestone closes).
    stub_httpd, stub_port = provider_stub
    proxy_httpd, proxy_port = _start_proxy(stub_port, "anthropic", "x-api-key", monkeypatch)
    try:
        descriptor = json.dumps({
            "endpoint": f"http://127.0.0.1:{proxy_port}",
            "provider": "anthropic",
            "target_base_url": f"http://127.0.0.1:{stub_port}",
            "capability_token": CAP_TOKEN,
        })
        req = _make_req(tmp_path)
        proc = _invoke_adapter(ADAPTER_ANTHROPIC, req, {"DF_PROXY_DESCRIPTOR": descriptor})
        resp = json.loads(proc.stdout)
        assert resp["status"] == "ok", resp.get("detail")
        assert "no api key" not in (resp.get("detail") or "").lower()
    finally:
        proxy_httpd.shutdown()
        proxy_httpd.server_close()


# ---------------------------------------------------------------------------
# Refusal paths: the proxy fails closed on a missing/wrong capability token
# and on a non-allowlisted origin/port -- nothing forwarded to the stub.
# ---------------------------------------------------------------------------

def test_request_without_capability_token_is_refused_by_proxy(provider_stub, monkeypatch):
    stub_httpd, stub_port = provider_stub
    proxy_httpd, proxy_port = _start_proxy(stub_port, "anthropic", "x-api-key", monkeypatch)
    try:
        import http.client
        conn = http.client.HTTPConnection("127.0.0.1", proxy_port, timeout=10)
        try:
            body = b'{"model":"m","messages":[]}'
            conn.request(
                "POST", f"http://127.0.0.1:{stub_port}/v1/messages",
                body=body, headers={"content-type": "application/json"},
                # deliberately NO Proxy-Authorization header
            )
            resp = conn.getresponse()
            status = resp.status
            resp.read()
        finally:
            conn.close()
        assert status == 407
        assert stub_httpd.received == []
    finally:
        proxy_httpd.shutdown()
        proxy_httpd.server_close()


def test_request_to_non_allowlisted_origin_is_refused_by_proxy(provider_stub, monkeypatch):
    stub_httpd, stub_port = provider_stub
    proxy_httpd, proxy_port = _start_proxy(stub_port, "anthropic", "x-api-key", monkeypatch)
    try:
        import http.client
        conn = http.client.HTTPConnection("127.0.0.1", proxy_port, timeout=10)
        try:
            # A DIFFERENT port from the one allowlisted for this proxy --
            # same host, so this proves exact (scheme, host, port) matching,
            # not just a hostname check.
            other_port = stub_port + 1 if stub_port < 65535 else stub_port - 1
            conn.request(
                "POST", f"http://127.0.0.1:{other_port}/v1/messages",
                body=b"{}",
                headers={
                    "content-type": "application/json",
                    "Proxy-Authorization": f"Bearer {CAP_TOKEN}",
                },
            )
            resp = conn.getresponse()
            status = resp.status
            resp.read()
        finally:
            conn.close()
        assert status == 403
        assert stub_httpd.received == []
    finally:
        proxy_httpd.shutdown()
        proxy_httpd.server_close()


# ---------------------------------------------------------------------------
# DF_PROXY_DESCRIPTOR UNSET: byte-identical to the pre-M30 direct-key path.
# No regression to the existing (non-enterprise) adapter behavior.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("adapter,base_url_env,key_env,path,inj_header,inj_value_fmt", [
    # http.client title-cases the header name it's given on the wire
    # ("x-api-key" -> "X-Api-Key") -- this is the pre-existing (byte-
    # identical, unchanged by M30) direct-mode wire format, not something
    # this milestone introduces.
    (ADAPTER_ANTHROPIC, "ANTHROPIC_BASE_URL", "ANTHROPIC_API_KEY", "/v1/messages",
     "X-Api-Key", "{key}"),
    (ADAPTER_OPENAI, "OPENAI_BASE_URL", "OPENAI_API_KEY", "/v1/chat/completions",
     "Authorization", "Bearer {key}"),
])
def test_adapter_direct_mode_unaffected_when_descriptor_unset(
    tmp_path, provider_stub, adapter, base_url_env, key_env, path, inj_header, inj_value_fmt,
):
    stub_httpd, stub_port = provider_stub
    req = _make_req(tmp_path)
    env = {base_url_env: f"http://127.0.0.1:{stub_port}", key_env: DIRECT_KEY}
    # DF_PROXY_DESCRIPTOR is NOT set.
    proc = _invoke_adapter(adapter, req, env)
    assert proc.returncode == 0, proc.stderr
    resp = json.loads(proc.stdout)
    assert resp["status"] == "ok", resp.get("detail")
    assert os.path.isfile(os.path.join(req["workdir"], "greet.py"))

    assert len(stub_httpd.received) == 1
    seen = stub_httpd.received[0]
    assert seen["path"] == path
    assert seen["headers"].get(inj_header) == inj_value_fmt.format(key=DIRECT_KEY)
    # The adapter itself sent this header directly -- no Proxy-Authorization
    # at all in direct mode (there is no proxy in this path).
    assert "Proxy-Authorization" not in seen["headers"]
