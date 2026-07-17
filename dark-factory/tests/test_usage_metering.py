"""Tests for M25 Task 1: real cost metering.

`api_anthropic` (M24) now surfaces the Messages API's real top-level
`"usage": {"input_tokens", "output_tokens"}` block through the adapter
protocol-0.1 response as `usage: {"known": bool, "input_tokens", "output_tokens"}`,
and the supervisor accumulates AUTHORITATIVE run totals from it at the M8
builder-call accounting site -- additive alongside (never inside)
`estimated_usd`'s admission/alert/pause path. FAIL-SOFT by construction: an
absent or malformed usage block never fails a build and never raises; an
adapter that reports `known:false` (or no `usage` key at all) is
byte-identical to pre-M25 behavior.

Part 1 drives `adapters/api_anthropic` as a real subprocess against
`tests/fixtures/stub_messages_api` (same harness as test_api_adapter.py).
Part 2 drives `supervisor.run`/`resume` with a monkeypatched
`supervisor.invoke_adapter` (same harness as test_confine_config.py /
test_hardened_config.py) -- no real adapter binary, no network.
"""
import json
import os
import subprocess
import sys
import time

import supervisor
from test_supervisor import setup_control, read_journal
from test_hardened_config import GREET_PY

HERE = os.path.dirname(os.path.abspath(__file__))
ADAPTER = os.path.join(HERE, "..", "scripts", "adapters", "api_anthropic")
STUB = os.path.join(HERE, "fixtures", "stub_messages_api")
TEST_KEY = "test-secret-KEY-do-not-leak"


# ---------------------------------------------------------------------------
# Part 1: api_anthropic adapter (subprocess, against the stub) -- protocol
# response usage block.
# ---------------------------------------------------------------------------

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


def _invoke(req, env_overrides):
    env = dict(os.environ)
    env.update(env_overrides)
    return subprocess.run(
        [ADAPTER], input=json.dumps(req), capture_output=True, text=True,
        timeout=30, env=env,
    )


def test_adapter_reports_known_usage_from_stub(tmp_path):
    stub_proc, base = _start_stub(tmp_path, "greet")
    try:
        req = _make_req(tmp_path)
        proc = _invoke(req, {"ANTHROPIC_BASE_URL": base, "ANTHROPIC_API_KEY": TEST_KEY})
        assert proc.returncode == 0, proc.stderr
        resp = json.loads(proc.stdout)
        assert resp["status"] == "ok", resp.get("detail")
        assert resp["usage"] == {"known": True, "input_tokens": 123, "output_tokens": 456}
    finally:
        _stop_stub(stub_proc)


def test_adapter_reports_known_false_when_stub_omits_usage(tmp_path):
    stub_proc, base = _start_stub(tmp_path, "nousage")
    try:
        req = _make_req(tmp_path)
        proc = _invoke(req, {"ANTHROPIC_BASE_URL": base, "ANTHROPIC_API_KEY": TEST_KEY})
        assert proc.returncode == 0, proc.stderr
        resp = json.loads(proc.stdout)
        assert resp["status"] == "ok", resp.get("detail")  # build proceeds regardless
        assert resp["usage"] == {"known": False}
        assert os.path.isfile(os.path.join(req["workdir"], "greet.py"))
    finally:
        _stop_stub(stub_proc)


def test_adapter_malformed_usage_never_fails_build_known_false(tmp_path):
    # usage IS present but input_tokens is not int-able -- fail-soft: the
    # build still succeeds, metering just reports known:False.
    stub_proc, base = _start_stub(tmp_path, "badusage")
    try:
        req = _make_req(tmp_path)
        proc = _invoke(req, {"ANTHROPIC_BASE_URL": base, "ANTHROPIC_API_KEY": TEST_KEY})
        assert proc.returncode == 0, proc.stderr
        resp = json.loads(proc.stdout)
        assert resp["status"] == "ok", resp.get("detail")
        assert resp["usage"] == {"known": False}
        assert os.path.isfile(os.path.join(req["workdir"], "greet.py"))
    finally:
        _stop_stub(stub_proc)


def test_adapter_error_path_usage_always_known_false(tmp_path):
    # Back-compat: an adapter ERROR response's usage block is byte-identical
    # to pre-M25 -- {"known": False} -- even though the stub's canned 200
    # reply now carries a usage block (badshape short-circuits before any
    # reply is even parsed as {"files": ...}).
    stub_proc, base = _start_stub(tmp_path, "badshape")
    try:
        req = _make_req(tmp_path)
        proc = _invoke(req, {"ANTHROPIC_BASE_URL": base, "ANTHROPIC_API_KEY": TEST_KEY})
        assert proc.returncode == 0, proc.stderr
        resp = json.loads(proc.stdout)
        assert resp["status"] == "error"
        assert resp["usage"] == {"known": False}
    finally:
        _stop_stub(stub_proc)


# ---------------------------------------------------------------------------
# Part 2: supervisor -- monkeypatched supervisor.invoke_adapter, no real
# adapter/stub involved. Mirrors test_confine_config.py's harness.
# ---------------------------------------------------------------------------

def _ok_write_greet(workdir):
    with open(os.path.join(workdir, "greet.py"), "w", encoding="utf-8") as f:
        f.write(GREET_PY)


def test_converged_run_accumulates_known_usage_totals(tmp_path, monkeypatch):
    cr = setup_control(tmp_path, "/usr/local/bin/claude", checkpoint="auto")

    def fake_invoke(adapter, role, workdir, prompt_file, timeout_s,
                    exec_prefix=None, env_extra=None, env_full=None, confine=False):
        _ok_write_greet(workdir)
        return {"adapter_protocol": "0.1", "status": "ok",
                "usage": {"known": True, "input_tokens": 123, "output_tokens": 456}}, None

    monkeypatch.setattr(supervisor, "invoke_adapter", fake_invoke)

    rc = supervisor.run(str(cr), None)
    assert rc == 0

    entries, _ = read_journal(cr)
    states = [e["state"] for e in entries]
    assert "CONVERGED" in states
    build = next(e for e in entries if e["state"] == "BUILD")
    assert build["data"]["usage_known"] is True
    assert build["data"]["builder_input_tokens"] == 123
    assert build["data"]["builder_output_tokens"] == 456


def test_known_false_usage_leaves_totals_zero(tmp_path, monkeypatch):
    cr = setup_control(tmp_path, "/usr/local/bin/claude", checkpoint="auto")

    def fake_invoke(adapter, role, workdir, prompt_file, timeout_s,
                    exec_prefix=None, env_extra=None, env_full=None, confine=False):
        _ok_write_greet(workdir)
        return {"adapter_protocol": "0.1", "status": "ok",
                "usage": {"known": False}}, None

    monkeypatch.setattr(supervisor, "invoke_adapter", fake_invoke)

    rc = supervisor.run(str(cr), None)
    assert rc == 0

    entries, _ = read_journal(cr)
    build = next(e for e in entries if e["state"] == "BUILD")
    assert build["data"]["usage_known"] is False
    assert build["data"]["builder_input_tokens"] == 0
    assert build["data"]["builder_output_tokens"] == 0


def test_missing_usage_key_leaves_totals_zero(tmp_path, monkeypatch):
    # An adapter that predates M25 entirely -- resp has no "usage" key at
    # all (not even {"known": False}). Byte-identical to today: build
    # proceeds, totals stay zero, no KeyError.
    cr = setup_control(tmp_path, "/usr/local/bin/claude", checkpoint="auto")

    def fake_invoke(adapter, role, workdir, prompt_file, timeout_s,
                    exec_prefix=None, env_extra=None, env_full=None, confine=False):
        _ok_write_greet(workdir)
        return {"adapter_protocol": "0.1", "status": "ok"}, None

    monkeypatch.setattr(supervisor, "invoke_adapter", fake_invoke)

    rc = supervisor.run(str(cr), None)
    assert rc == 0

    entries, _ = read_journal(cr)
    build = next(e for e in entries if e["state"] == "BUILD")
    assert build["data"]["usage_known"] is False
    assert build["data"]["builder_input_tokens"] == 0
    assert build["data"]["builder_output_tokens"] == 0


def test_malformed_usage_block_never_raises(tmp_path, monkeypatch):
    # A grab-bag of malformed usage shapes, one per (non-converging)
    # iteration: not a dict, known:True but missing tokens, known:True but
    # a non-numeric token, known:True but a None token. None of these may
    # raise -- the run must proceed and eventually converge on a final,
    # well-formed call; every malformed call leaves totals untouched (0).
    cr = setup_control(tmp_path, "/usr/local/bin/claude", checkpoint="auto",
                       max_iterations=5)

    bad_usages = [
        "oops-not-a-dict",
        {"known": True},  # missing input_tokens/output_tokens
        {"known": True, "input_tokens": "abc", "output_tokens": 456},
        {"known": True, "input_tokens": 12, "output_tokens": None},
    ]
    calls = []

    def fake_invoke(adapter, role, workdir, prompt_file, timeout_s,
                    exec_prefix=None, env_extra=None, env_full=None, confine=False):
        calls.append(1)
        if len(calls) <= len(bad_usages):
            with open(os.path.join(workdir, "greet.py"), "w", encoding="utf-8") as f:
                f.write("print('nope')\n")  # keeps dev cohort failing -> loop continues
            usage = bad_usages[len(calls) - 1]
            return {"adapter_protocol": "0.1", "status": "ok", "usage": usage}, None
        _ok_write_greet(workdir)
        return {"adapter_protocol": "0.1", "status": "ok",
                "usage": {"known": True, "input_tokens": 1, "output_tokens": 2}}, None

    monkeypatch.setattr(supervisor, "invoke_adapter", fake_invoke)

    rc = supervisor.run(str(cr), None)  # must not raise
    assert rc == 0

    entries, _ = read_journal(cr)
    builds = [e for e in entries if e["state"] == "BUILD"]
    assert len(builds) == len(bad_usages) + 1
    for b in builds[:-1]:
        assert b["data"]["usage_known"] is False
        assert b["data"]["builder_input_tokens"] == 0
        assert b["data"]["builder_output_tokens"] == 0
    # only the final, well-formed call ever accumulates.
    assert builds[-1]["data"]["usage_known"] is True
    assert builds[-1]["data"]["builder_input_tokens"] == 1
    assert builds[-1]["data"]["builder_output_tokens"] == 2


def test_resume_reloads_accumulated_tokens_no_double_count(tmp_path, monkeypatch):
    cr = setup_control(tmp_path, "/usr/local/bin/claude", checkpoint="pause")

    def fake_invoke_incomplete(adapter, role, workdir, prompt_file, timeout_s,
                               exec_prefix=None, env_extra=None, env_full=None, confine=False):
        with open(os.path.join(workdir, "greet.py"), "w", encoding="utf-8") as f:
            f.write("print('not what the spec wants')\n")
        return {"adapter_protocol": "0.1", "status": "ok",
                "usage": {"known": True, "input_tokens": 100, "output_tokens": 200}}, None

    monkeypatch.setattr(supervisor, "invoke_adapter", fake_invoke_incomplete)

    rc = supervisor.run(str(cr), None)
    assert rc == supervisor.PAUSED

    _, run_id = read_journal(cr)
    run_dir = cr / "runs" / run_id
    state = json.loads((run_dir / "state.json").read_text(encoding="utf-8"))
    assert state["builder_input_tokens"] == 100
    assert state["builder_output_tokens"] == 200
    assert state["usage_known"] is True

    def fake_invoke_fixed(adapter, role, workdir, prompt_file, timeout_s,
                          exec_prefix=None, env_extra=None, env_full=None, confine=False):
        _ok_write_greet(workdir)
        return {"adapter_protocol": "0.1", "status": "ok",
                "usage": {"known": True, "input_tokens": 50, "output_tokens": 70}}, None

    monkeypatch.setattr(supervisor, "invoke_adapter", fake_invoke_fixed)

    rc2 = supervisor.resume(str(cr), "continue")
    assert rc2 == 0

    entries2, _ = read_journal(cr)
    builds = [e for e in entries2 if e["state"] == "BUILD"]
    assert len(builds) == 2  # 1 before pause + 1 after resume, no double count
    assert builds[0]["data"]["builder_input_tokens"] == 100
    assert builds[0]["data"]["builder_output_tokens"] == 200
    # additive, not re-summed from scratch: 100+50 / 200+70, never 100+100.
    assert builds[-1]["data"]["builder_input_tokens"] == 150
    assert builds[-1]["data"]["builder_output_tokens"] == 270
    assert builds[-1]["data"]["usage_known"] is True

    assert not (run_dir / "state.json").exists()  # cleared on the terminal outcome
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["outcome"] in ("COMPLETE_QUALIFIED", "COMPLETE_UNQUALIFIED")


def test_load_state_defaults_absent_usage_fields_to_zero(tmp_path):
    # A pre-M25 state.json (no builder_input_tokens/builder_output_tokens/
    # usage_known keys at all) must resume cleanly with a fresh (zeroed)
    # token count -- additive field, no KeyError, no fabricated totals.
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "state.json").write_text(json.dumps({
        "state_version": "0.1", "next_iter": 2, "feedback": None,
        "workspace": str(tmp_path / "ws"), "run_dir": str(run_dir),
        "dev_status": {}, "regressions": [], "builder_calls": 1,
        "estimated_usd": 0.0, "budget_alerted": False, "reason": "checkpoint",
    }), encoding="utf-8")

    state = supervisor.load_state(str(run_dir))
    assert state["builder_input_tokens"] == 0
    assert state["builder_output_tokens"] == 0
    assert state["usage_known"] is False
