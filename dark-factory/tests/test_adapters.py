import json
import os
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
FAKE = os.path.join(HERE, "fixtures", "fake_builder")
CLAUDE_ADAPTER = os.path.join(HERE, "..", "scripts", "adapters", "claude")


def invoke(adapter, req):
    proc = subprocess.run(
        [adapter], input=json.dumps(req), capture_output=True, text=True, timeout=30
    )
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


def make_req(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir(exist_ok=True)
    pf = tmp_path / "prompt.md"
    pf.write_text("Build greet.py per SPEC.", encoding="utf-8")
    return {
        "adapter_protocol": "0.1",
        "role": "builder",
        "workdir": str(ws),
        "prompt_file": str(pf),
        "timeout_s": 20,
    }


def test_fake_builder_writes_buggy_version_first(tmp_path):
    req = make_req(tmp_path)
    resp = invoke(FAKE, req)
    assert resp["status"] == "ok" and resp["adapter_protocol"] == "0.1"
    out = subprocess.run(
        ["python3", "greet.py", "World"],
        cwd=req["workdir"], capture_output=True, text=True,
    )
    assert out.stdout.strip() == "Hi, World!"  # deliberately wrong greeting


def test_fake_builder_fixes_after_feedback(tmp_path):
    req = make_req(tmp_path)
    invoke(FAKE, req)
    (tmp_path / "ws" / "feedback.json").write_text(
        json.dumps({"failures": [{"behavior_id": "BHV-001", "taxonomy": ["wrong_output"]}]}),
        encoding="utf-8",
    )
    invoke(FAKE, req)
    out = subprocess.run(
        ["python3", "greet.py", "World"],
        cwd=req["workdir"], capture_output=True, text=True,
    )
    assert out.stdout.strip() == "Hello, World!"


def test_fake_builder_usage_error_both_versions(tmp_path):
    req = make_req(tmp_path)
    invoke(FAKE, req)
    out = subprocess.run(
        ["python3", "greet.py"], cwd=req["workdir"], capture_output=True, text=True
    )
    assert out.returncode == 2 and "usage:" in out.stderr


def test_claude_adapter_reports_error_when_cli_missing(tmp_path):
    req = make_req(tmp_path)
    env = dict(os.environ, PATH="/nonexistent-bin")
    proc = subprocess.run(
        [CLAUDE_ADAPTER], input=json.dumps(req),
        capture_output=True, text=True, timeout=30, env=env,
    )
    assert proc.returncode == 0
    resp = json.loads(proc.stdout)
    assert resp["status"] == "error"
    assert "claude" in resp["detail"]
