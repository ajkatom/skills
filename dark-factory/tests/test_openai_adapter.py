"""Tests for the api_openai builder adapter: a stdlib Chat Completions client
that lets a real model build inside a container with no CLI installed.
Mirrors test_api_adapter.py (api_anthropic) exactly, driven end-to-end as a
subprocess (protocol 0.1 stdin/stdout) against tests/fixtures/stub_chat_api --
deterministic, no paid calls, no network beyond 127.0.0.1.
"""
import json
import os
import subprocess
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ADAPTER = os.path.join(HERE, "..", "scripts", "adapters", "api_openai")
STUB = os.path.join(HERE, "fixtures", "stub_chat_api")

TEST_KEY = "test-secret-KEY-do-not-leak"


def _start_stub(tmp_path, mode):
    ep_file = tmp_path / "stub_endpoint"
    env = dict(os.environ, DF_ENDPOINT_FILE=str(ep_file), DF_STUB_MODE=mode)
    proc = subprocess.Popen([sys.executable, STUB], env=env)
    deadline = time.time() + 10
    while time.time() < deadline and not ep_file.exists():
        time.sleep(0.05)
    assert ep_file.exists(), "stub never became ready"
    endpoint = ep_file.read_text(encoding="utf-8").strip()
    return proc, f"http://{endpoint}"


def _stop_stub(proc):
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)


def _stub_request_count(base_url):
    with urllib.request.urlopen(base_url + "/_requests", timeout=5) as resp:
        return json.loads(resp.read())["count"]


def make_req(tmp_path, timeout_s=20):
    # workdir is nested two levels inside tmp_path so "../../x" escapes the
    # workdir but lands at a deterministic, collision-free spot (tmp_path/x)
    # that this test file owns and can assert on.
    ws = tmp_path / "nested" / "ws"
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


def invoke(req, env_overrides):
    env = dict(os.environ)
    env.update(env_overrides)
    return subprocess.run(
        [ADAPTER], input=json.dumps(req), capture_output=True, text=True,
        timeout=30, env=env,
    )


def test_greet_mode_writes_file_ok(tmp_path):
    stub_proc, base = _start_stub(tmp_path, "greet")
    try:
        req = make_req(tmp_path)
        proc = invoke(req, {"OPENAI_BASE_URL": base, "OPENAI_API_KEY": TEST_KEY})
        assert proc.returncode == 0, proc.stderr
        resp = json.loads(proc.stdout)
        assert resp["adapter_protocol"] == "0.1"
        assert resp["status"] == "ok", resp.get("detail")

        greet = os.path.join(req["workdir"], "greet.py")
        assert os.path.isfile(greet)
        out = subprocess.run(
            [sys.executable, "greet.py", "World"],
            cwd=req["workdir"], capture_output=True, text=True,
        )
        assert out.stdout.strip() == "Hello, World!"
        assert _stub_request_count(base) == 1
    finally:
        _stop_stub(stub_proc)


def test_usage_reported_and_mapped_to_protocol_field_names(tmp_path):
    # The stub returns OpenAI-shaped {"prompt_tokens","completion_tokens"};
    # the adapter must map these onto the protocol-uniform
    # input_tokens/output_tokens field names (same names api_anthropic uses).
    stub_proc, base = _start_stub(tmp_path, "greet")
    try:
        req = make_req(tmp_path)
        proc = invoke(req, {"OPENAI_BASE_URL": base, "OPENAI_API_KEY": TEST_KEY})
        resp = json.loads(proc.stdout)
        assert resp["status"] == "ok"
        assert resp["usage"] == {
            "known": True, "input_tokens": 123, "output_tokens": 456,
        }
    finally:
        _stop_stub(stub_proc)


def test_no_usage_block_reports_known_false(tmp_path):
    stub_proc, base = _start_stub(tmp_path, "nousage")
    try:
        req = make_req(tmp_path)
        proc = invoke(req, {"OPENAI_BASE_URL": base, "OPENAI_API_KEY": TEST_KEY})
        resp = json.loads(proc.stdout)
        assert resp["status"] == "ok"
        assert resp["usage"] == {"known": False}
    finally:
        _stop_stub(stub_proc)


def test_malformed_usage_block_is_fail_soft(tmp_path):
    stub_proc, base = _start_stub(tmp_path, "badusage")
    try:
        req = make_req(tmp_path)
        proc = invoke(req, {"OPENAI_BASE_URL": base, "OPENAI_API_KEY": TEST_KEY})
        resp = json.loads(proc.stdout)
        assert resp["status"] == "ok"  # a malformed usage block must never fail the build
        assert resp["usage"] == {"known": False}
    finally:
        _stop_stub(stub_proc)


def test_symlink_escape_rejected(tmp_path):
    # A symlink planted in the workspace pointing OUTSIDE must not let a reply
    # path through it write outside (realpath check in _safe_join).
    stub_proc, base = _start_stub(tmp_path, "symlinkesc")
    try:
        req = make_req(tmp_path)
        outside = tmp_path / "OUTSIDE_TARGET"
        outside.mkdir()
        os.symlink(str(outside), os.path.join(req["workdir"], "evil_link"))
        proc = invoke(req, {"OPENAI_BASE_URL": base, "OPENAI_API_KEY": TEST_KEY})
        resp = json.loads(proc.stdout)
        assert resp["status"] == "error"
        assert not (outside / "pwned.txt").exists()  # nothing written through the link
    finally:
        _stop_stub(stub_proc)


def test_write_phase_oserror_rolls_back_no_partial_tree(tmp_path):
    # An OSError mid-write (a returned relpath collides with a pre-existing
    # plain file where a dir is needed) must roll back the files already
    # written this call — the documented "never a partial tree" invariant.
    stub_proc, base = _start_stub(tmp_path, "collide")
    try:
        req = make_req(tmp_path)
        # pre-create a plain file "b" so makedirs for "b/c.txt" OSErrors,
        # AFTER "a.txt" is already written.
        open(os.path.join(req["workdir"], "b"), "w").close()
        proc = invoke(req, {"OPENAI_BASE_URL": base, "OPENAI_API_KEY": TEST_KEY})
        resp = json.loads(proc.stdout)
        assert resp["status"] == "error"
        # a.txt was written first then rolled back -> gone
        assert not os.path.exists(os.path.join(req["workdir"], "a.txt"))
    finally:
        _stop_stub(stub_proc)


def test_unsafe_paths_rejected_all_or_nothing(tmp_path):
    stub_proc, base = _start_stub(tmp_path, "unsafe")
    try:
        req = make_req(tmp_path)
        proc = invoke(req, {"OPENAI_BASE_URL": base, "OPENAI_API_KEY": TEST_KEY})
        assert proc.returncode == 0, proc.stderr
        resp = json.loads(proc.stdout)
        assert resp["status"] == "error"
        assert resp["detail"]

        # Neither escape target was written -- ANYWHERE -- not even the one
        # that (had it been written) would land inside tmp_path but outside
        # workdir, and not the absolute-path one.
        assert not os.path.exists(os.path.join(tmp_path, "escaped"))
        assert not os.path.exists(os.path.join(tmp_path, "nested", "escaped"))
        assert not os.path.exists("/etc/escaped")
        # And the reply was all-or-nothing: workdir is untouched.
        assert os.listdir(req["workdir"]) == []
    finally:
        _stop_stub(stub_proc)


def test_badshape_or_nonjson_reply_rejected(tmp_path):
    stub_proc, base = _start_stub(tmp_path, "badshape")
    try:
        req = make_req(tmp_path)
        proc = invoke(req, {"OPENAI_BASE_URL": base, "OPENAI_API_KEY": TEST_KEY})
        assert proc.returncode == 0, proc.stderr
        resp = json.loads(proc.stdout)
        assert resp["status"] == "error"
        assert os.listdir(req["workdir"]) == []
    finally:
        _stop_stub(stub_proc)


def test_missing_api_key_errors_without_any_http_call(tmp_path):
    stub_proc, base = _start_stub(tmp_path, "greet")
    try:
        req = make_req(tmp_path)
        env = dict(os.environ, OPENAI_BASE_URL=base)
        env.pop("OPENAI_API_KEY", None)
        proc = subprocess.run(
            [ADAPTER], input=json.dumps(req), capture_output=True, text=True,
            timeout=30, env=env,
        )
        assert proc.returncode == 0, proc.stderr
        resp = json.loads(proc.stdout)
        assert resp["status"] == "error"
        assert "no api key" in resp["detail"].lower()
        assert os.listdir(req["workdir"]) == []
        assert _stub_request_count(base) == 0
    finally:
        _stop_stub(stub_proc)


def test_http_500_rejected(tmp_path):
    stub_proc, base = _start_stub(tmp_path, "http500")
    try:
        req = make_req(tmp_path)
        proc = invoke(req, {"OPENAI_BASE_URL": base, "OPENAI_API_KEY": TEST_KEY})
        assert proc.returncode == 0, proc.stderr
        resp = json.loads(proc.stdout)
        assert resp["status"] == "error"
        assert os.listdir(req["workdir"]) == []
    finally:
        _stop_stub(stub_proc)


def test_api_key_never_leaks_to_stdout_stderr_or_workspace(tmp_path):
    stub_proc, base = _start_stub(tmp_path, "greet")
    try:
        req = make_req(tmp_path)
        proc = invoke(req, {"OPENAI_BASE_URL": base, "OPENAI_API_KEY": TEST_KEY})
        assert TEST_KEY not in proc.stdout
        assert TEST_KEY not in proc.stderr
        for root, _dirs, files in os.walk(req["workdir"]):
            for fn in files:
                content = open(
                    os.path.join(root, fn), encoding="utf-8", errors="replace"
                ).read()
                assert TEST_KEY not in content
    finally:
        _stop_stub(stub_proc)


def test_unreachable_base_url_errors_cleanly(tmp_path):
    req = make_req(tmp_path)
    # Nothing is listening on this port -- connection refused, not a hang.
    proc = invoke(req, {
        "OPENAI_BASE_URL": "http://127.0.0.1:1",
        "OPENAI_API_KEY": TEST_KEY,
    })
    assert proc.returncode == 0, proc.stderr
    resp = json.loads(proc.stdout)
    assert resp["status"] == "error"
    assert os.listdir(req["workdir"]) == []
