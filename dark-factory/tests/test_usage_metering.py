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

M25 Task 2 (Parts 3-5 below): `df_config`'s optional `budget.token_pricing`
(dollars per MILLION tokens, keyed by "<model>" or "default"); the
supervisor's `actual_usd` computation (default-entry pricing x the
Task-1-accumulated authoritative tokens) threaded onto EVERY terminal
manifest as `usage = {"known", "input_tokens", "output_tokens",
"actual_usd"}`, fresh + resume + abort branches, exactly like M8's `budget`
field. Part 3 is config-only (df_config, no supervisor). Part 4 reuses Part
2's monkeypatched-invoke_adapter harness. Part 5 is the real-adapter e2e
(supervisor.run driving the REAL api_anthropic binary as a subprocess
against the stub, no monkeypatching) proving manifest.usage carries real
tokens end to end.
"""
import json
import os
import subprocess
import sys
import time

import pytest

import df_config
import supervisor
from test_budget import _set_budget
from test_config import write_config
from test_supervisor import setup_control, read_journal, scenario, MARKER
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

    # M36b: the rebuild+converge resume pauses before ship; the ship-resume
    # seals WITHOUT a builder call, so token totals do not change again.
    rc2 = supervisor.resume(str(cr), "continue")
    assert rc2 == supervisor.PAUSED  # converge -> AWAIT_SHIP
    rc3 = supervisor.resume(str(cr), "continue")
    assert rc3 == 0

    entries2, _ = read_journal(cr)
    builds = [e for e in entries2 if e["state"] == "BUILD"]
    assert len(builds) == 2  # 1 before pause + 1 after resume, no double count (ship-resume adds none)
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


# ---------------------------------------------------------------------------
# Part 3 (M25 Task 2): df_config -- budget.token_pricing validation +
# injection. Config-only, no supervisor involved.
# ---------------------------------------------------------------------------

def test_token_pricing_valid_config_injected_into_budget(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, budget={
        "billing": "subscription",
        "token_pricing": {
            "default": {"input_per_mtok": 3.0, "output_per_mtok": 15.0},
            "claude-sonnet-5": {"input_per_mtok": 3.0, "output_per_mtok": 15.0},
        },
    })
    cfg = df_config.load_config(str(cr))
    assert cfg["_budget"]["token_pricing"] == {
        "default": {"input_per_mtok": 3.0, "output_per_mtok": 15.0},
        "claude-sonnet-5": {"input_per_mtok": 3.0, "output_per_mtok": 15.0},
    }


def test_token_pricing_absent_defaults_to_empty_dict(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, budget={"billing": "subscription"})
    cfg = df_config.load_config(str(cr))
    assert cfg["_budget"]["token_pricing"] == {}


def test_token_pricing_negative_price_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, budget={
        "billing": "subscription",
        "token_pricing": {"default": {"input_per_mtok": -1.0, "output_per_mtok": 15.0}},
    })
    with pytest.raises(df_config.ConfigError, match="token_pricing"):
        df_config.load_config(str(cr))


def test_token_pricing_not_a_dict_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, budget={"billing": "subscription", "token_pricing": "oops"})
    with pytest.raises(df_config.ConfigError, match="token_pricing"):
        df_config.load_config(str(cr))


def test_token_pricing_entry_not_a_dict_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, budget={"billing": "subscription",
                              "token_pricing": {"default": "oops"}})
    with pytest.raises(df_config.ConfigError, match="token_pricing"):
        df_config.load_config(str(cr))


def test_token_pricing_missing_field_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, budget={"billing": "subscription",
                              "token_pricing": {"default": {"input_per_mtok": 3.0}}})
    with pytest.raises(df_config.ConfigError, match="token_pricing"):
        df_config.load_config(str(cr))


def test_token_pricing_non_numeric_field_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, budget={"billing": "subscription",
                              "token_pricing": {"default": {"input_per_mtok": "cheap",
                                                             "output_per_mtok": 15.0}}})
    with pytest.raises(df_config.ConfigError, match="token_pricing"):
        df_config.load_config(str(cr))


# ---------------------------------------------------------------------------
# Part 4 (M25 Task 2): supervisor -- actual_usd math + `usage` on every
# terminal manifest. Same monkeypatched-invoke_adapter harness as Part 2.
# ---------------------------------------------------------------------------

def test_actual_usd_computed_with_default_pricing_on_converged_manifest(tmp_path, monkeypatch):
    cr = setup_control(tmp_path, "/usr/local/bin/claude", checkpoint="auto")
    _set_budget(cr, {"billing": "subscription",
                      "token_pricing": {"default": {"input_per_mtok": 3.0,
                                                     "output_per_mtok": 15.0}}})

    def fake_invoke(adapter, role, workdir, prompt_file, timeout_s,
                    exec_prefix=None, env_extra=None, env_full=None, confine=False):
        _ok_write_greet(workdir)
        return {"adapter_protocol": "0.1", "status": "ok",
                "usage": {"known": True, "input_tokens": 1000, "output_tokens": 2000}}, None

    monkeypatch.setattr(supervisor, "invoke_adapter", fake_invoke)

    rc = supervisor.run(str(cr), None)
    assert rc == 0

    _, run_id = read_journal(cr)
    manifest = json.loads((cr / "runs" / run_id / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["usage"]["known"] is True
    assert manifest["usage"]["input_tokens"] == 1000
    assert manifest["usage"]["output_tokens"] == 2000
    # 1000/1e6 * 3.0 (input) + 2000/1e6 * 15.0 (output) = 0.003 + 0.03 = 0.033
    assert manifest["usage"]["actual_usd"] == pytest.approx(0.033)


def test_actual_usd_null_when_usage_known_but_no_pricing_configured(tmp_path, monkeypatch):
    # setup_control's default budget ({"billing": "subscription"}) carries
    # NO token_pricing -- df_config defaults it to {}. Tokens are still
    # honestly recorded; actual_usd stays null (no price to apply).
    cr = setup_control(tmp_path, "/usr/local/bin/claude", checkpoint="auto")

    def fake_invoke(adapter, role, workdir, prompt_file, timeout_s,
                    exec_prefix=None, env_extra=None, env_full=None, confine=False):
        _ok_write_greet(workdir)
        return {"adapter_protocol": "0.1", "status": "ok",
                "usage": {"known": True, "input_tokens": 500, "output_tokens": 700}}, None

    monkeypatch.setattr(supervisor, "invoke_adapter", fake_invoke)

    rc = supervisor.run(str(cr), None)
    assert rc == 0

    _, run_id = read_journal(cr)
    manifest = json.loads((cr / "runs" / run_id / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["usage"]["known"] is True
    assert manifest["usage"]["input_tokens"] == 500
    assert manifest["usage"]["output_tokens"] == 700
    assert manifest["usage"]["actual_usd"] is None


def test_manifest_usage_known_false_and_actual_usd_null_when_unreported(tmp_path, monkeypatch):
    # Pricing IS configured, but the adapter never reported usage -- known
    # stays False and actual_usd stays null regardless (never fabricated
    # from a price alone).
    cr = setup_control(tmp_path, "/usr/local/bin/claude", checkpoint="auto")
    _set_budget(cr, {"billing": "subscription",
                      "token_pricing": {"default": {"input_per_mtok": 3.0,
                                                     "output_per_mtok": 15.0}}})

    def fake_invoke(adapter, role, workdir, prompt_file, timeout_s,
                    exec_prefix=None, env_extra=None, env_full=None, confine=False):
        _ok_write_greet(workdir)
        return {"adapter_protocol": "0.1", "status": "ok", "usage": {"known": False}}, None

    monkeypatch.setattr(supervisor, "invoke_adapter", fake_invoke)

    rc = supervisor.run(str(cr), None)
    assert rc == 0

    _, run_id = read_journal(cr)
    manifest = json.loads((cr / "runs" / run_id / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["usage"] == {
        "known": False, "input_tokens": 0, "output_tokens": 0, "actual_usd": None,
    }


def test_manifest_usage_present_on_aborted_by_human_after_resume(tmp_path, monkeypatch):
    # Covers both an ABORT terminal AND a resumed run in one shot: pause
    # (checkpoint) accumulates real usage, persisted to state.json, then
    # `resume --decision abort` seals a terminal manifest carrying that
    # SAME persisted usage (never re-zeroed, never double-counted).
    cr = setup_control(tmp_path, "/usr/local/bin/claude", checkpoint="pause")
    _set_budget(cr, {"billing": "subscription",
                      "token_pricing": {"default": {"input_per_mtok": 3.0,
                                                     "output_per_mtok": 15.0}}})

    def fake_invoke_incomplete(adapter, role, workdir, prompt_file, timeout_s,
                               exec_prefix=None, env_extra=None, env_full=None, confine=False):
        with open(os.path.join(workdir, "greet.py"), "w", encoding="utf-8") as f:
            f.write("print('not what the spec wants')\n")
        return {"adapter_protocol": "0.1", "status": "ok",
                "usage": {"known": True, "input_tokens": 200, "output_tokens": 300}}, None

    monkeypatch.setattr(supervisor, "invoke_adapter", fake_invoke_incomplete)
    rc = supervisor.run(str(cr), None)
    assert rc == supervisor.PAUSED

    rc2 = supervisor.resume(str(cr), "abort")
    assert rc2 == 2

    _, run_id = read_journal(cr)
    manifest = json.loads((cr / "runs" / run_id / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["outcome"] == "ABORTED_BY_HUMAN"
    assert manifest["usage"]["known"] is True
    assert manifest["usage"]["input_tokens"] == 200
    assert manifest["usage"]["output_tokens"] == 300
    # 200/1e6 * 3.0 + 300/1e6 * 15.0 = 0.0006 + 0.0045 = 0.0051
    assert manifest["usage"]["actual_usd"] == pytest.approx(0.0051)


def test_manifest_usage_after_resume_converged_accumulates_across_pause(tmp_path, monkeypatch):
    cr = setup_control(tmp_path, "/usr/local/bin/claude", checkpoint="pause")
    _set_budget(cr, {"billing": "subscription",
                      "token_pricing": {"default": {"input_per_mtok": 2.0,
                                                     "output_per_mtok": 10.0}}})

    def fake_invoke_incomplete(adapter, role, workdir, prompt_file, timeout_s,
                               exec_prefix=None, env_extra=None, env_full=None, confine=False):
        with open(os.path.join(workdir, "greet.py"), "w", encoding="utf-8") as f:
            f.write("print('not what the spec wants')\n")
        return {"adapter_protocol": "0.1", "status": "ok",
                "usage": {"known": True, "input_tokens": 100, "output_tokens": 200}}, None

    monkeypatch.setattr(supervisor, "invoke_adapter", fake_invoke_incomplete)
    rc = supervisor.run(str(cr), None)
    assert rc == supervisor.PAUSED

    def fake_invoke_fixed(adapter, role, workdir, prompt_file, timeout_s,
                          exec_prefix=None, env_extra=None, env_full=None, confine=False):
        _ok_write_greet(workdir)
        return {"adapter_protocol": "0.1", "status": "ok",
                "usage": {"known": True, "input_tokens": 50, "output_tokens": 70}}, None

    monkeypatch.setattr(supervisor, "invoke_adapter", fake_invoke_fixed)
    # M36b: converge -> before-ship pause -> seal-reentry (no builder call).
    rc2 = supervisor.resume(str(cr), "continue")
    assert rc2 == supervisor.PAUSED
    rc3 = supervisor.resume(str(cr), "continue")
    assert rc3 == 0

    _, run_id = read_journal(cr)
    manifest = json.loads((cr / "runs" / run_id / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["outcome"] in ("COMPLETE_QUALIFIED", "COMPLETE_UNQUALIFIED")
    assert manifest["usage"]["known"] is True
    assert manifest["usage"]["input_tokens"] == 150
    assert manifest["usage"]["output_tokens"] == 270
    # 150/1e6 * 2.0 + 270/1e6 * 10.0 = 0.0003 + 0.0027 = 0.003
    assert manifest["usage"]["actual_usd"] == pytest.approx(0.003)


def test_manifest_usage_present_and_estimated_usd_admission_unaffected(tmp_path, monkeypatch):
    # M8 self-check: token_pricing/actual_usd is additive and NEVER changes
    # the estimated_usd admission/pause path -- a per_call_usd budget still
    # pauses on ITS OWN estimate, unaffected by actual_usd being present.
    cr = setup_control(tmp_path, "/usr/local/bin/claude", checkpoint="auto")
    _set_budget(cr, {"billing": "api", "per_call_usd": 1.0, "max_usd": 1.0,
                      "token_pricing": {"default": {"input_per_mtok": 3.0,
                                                     "output_per_mtok": 15.0}}})

    def fake_invoke(adapter, role, workdir, prompt_file, timeout_s,
                    exec_prefix=None, env_extra=None, env_full=None, confine=False):
        # never converges on its own; forces a 2nd call, which the $1 cap
        # must refuse admission for BEFORE it happens.
        with open(os.path.join(workdir, "greet.py"), "w", encoding="utf-8") as f:
            f.write("print('nope')\n")
        return {"adapter_protocol": "0.1", "status": "ok",
                "usage": {"known": True, "input_tokens": 10, "output_tokens": 20}}, None

    monkeypatch.setattr(supervisor, "invoke_adapter", fake_invoke)
    rc = supervisor.run(str(cr), None)
    assert rc == supervisor.PAUSED  # unchanged M8 behavior

    _, run_id = read_journal(cr)
    entries, _ = read_journal(cr)
    pause = next(e for e in entries if e["state"] == "BUDGET_PAUSE")
    assert pause["data"]["estimated_usd"] == 1.0  # M8 estimate, byte-identical
    run_dir = cr / "runs" / run_id
    assert not (run_dir / "manifest.json").exists()  # pause is non-terminal, as before
    state = json.loads((run_dir / "state.json").read_text(encoding="utf-8"))
    assert state["builder_input_tokens"] == 10
    assert state["builder_output_tokens"] == 20
    assert state["usage_known"] is True


# ---------------------------------------------------------------------------
# Part 5 (M25 Task 2): CLI-subprocess-ish e2e -- supervisor.run driving the
# REAL api_anthropic adapter binary (no monkeypatched invoke_adapter) against
# the stub, proving manifest.usage carries the real reported tokens all the
# way from the HTTP response through the adapter subprocess through the
# supervisor's accounting into the sealed manifest.
# ---------------------------------------------------------------------------

def _setup_single_scenario_control(tmp_path, adapter, budget=None):
    cr = tmp_path / "control"
    (cr / "scenarios").mkdir(parents=True)
    config = {
        "config_version": "0.1", "autonomy": 4, "assurance": "cooperative",
        "feedback": "ids", "max_iterations": 3,
        "workspace_root": str(tmp_path / "ws"),
        "roles": {"builder": {"adapter": adapter, "timeout_s": 30}},
        "budget": budget or {"billing": "subscription"},
        "checkpoint": "auto",
    }
    (cr / "config.json").write_text(json.dumps(config), encoding="utf-8")
    (cr / "spec.md").write_text(
        "# greet CLI\nCreate greet.py; `python3 greet.py World` prints "
        "`Hello, World!` and exits 0.\n", encoding="utf-8",
    )
    sc = scenario("BHV-001-S1", "BHV-001", ["python3", "greet.py", "World"],
                  {"exit_code": 0, "stdout_equals": "Hello, World!"},
                  f"{MARKER} greets World")
    (cr / "scenarios" / "s0.json").write_text(json.dumps(sc), encoding="utf-8")
    return cr


def test_e2e_manifest_usage_carries_real_tokens_from_adapter(tmp_path, monkeypatch):
    stub_proc, base = _start_stub(tmp_path, "greet")
    try:
        monkeypatch.setenv("ANTHROPIC_BASE_URL", base)
        monkeypatch.setenv("ANTHROPIC_API_KEY", TEST_KEY)
        cr = _setup_single_scenario_control(
            tmp_path, ADAPTER,
            budget={"billing": "subscription",
                    "token_pricing": {"default": {"input_per_mtok": 3.0,
                                                   "output_per_mtok": 15.0}}},
        )

        rc = supervisor.run(str(cr), None)
        assert rc == 0

        entries, run_id = read_journal(cr)
        assert "CONVERGED" in [e["state"] for e in entries]
        manifest = json.loads(
            (cr / "runs" / run_id / "manifest.json").read_text(encoding="utf-8"))
        # the stub's canned "greet" reply carries usage {123, 456} (see
        # fixtures/stub_messages_api docstring) -- these are REAL tokens
        # reported by the (stub) API, flowed through the real adapter
        # subprocess, accumulated by the real supervisor, sealed into the
        # real manifest -- nothing here is monkeypatched.
        assert manifest["usage"]["known"] is True
        assert manifest["usage"]["input_tokens"] == 123
        assert manifest["usage"]["output_tokens"] == 456
        expected = 123 / 1e6 * 3.0 + 456 / 1e6 * 15.0
        assert manifest["usage"]["actual_usd"] == pytest.approx(expected)
    finally:
        _stop_stub(stub_proc)
