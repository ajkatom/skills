"""M36a Task 6: per-mode end-to-end pause behavior.

  H1 directed  -- pauses BEFORE build 2 (after resuming the after-verify pause)
                  AND does NOT pause before ship (before_ship is deferred).
  H2 supervised-- pauses after verify (== today's default), converges on resume.
  H3 guarded   -- runs straight to seal with NO per-iteration pause, but PAUSEs
                  on a forced budget cap.
  H4 lights-out-- runs straight to seal with NO pause and, on a forced budget
                  cap, TERMINATES BUDGET_HALTED (never PAUSED). Uses a mocked
                  hardened backend (H4 requires hardened/enterprise) so it needs
                  no Docker.
  + the host-isolation security fix e2e: a standard run that opts out of
    default-deny host reads seals HOST_ISOLATION_LIMITED (qualified False).
"""
import json
import os

import pytest

import df_container
import df_sandbox
import supervisor
from test_supervisor import FAKE, STUBBORN, setup_control, read_journal


def _states(cr):
    return [e["state"] for e in read_journal(cr)[0]]


def _set_mode(cr, mode):
    p = cr / "config.json"
    cfg = json.loads(p.read_text())
    for k in ("autonomy", "checkpoint"):
        cfg.pop(k, None)
    cfg["intervention_mode"] = mode
    p.write_text(json.dumps(cfg))


def _set_budget(cr, budget):
    p = cr / "config.json"
    cfg = json.loads(p.read_text())
    cfg["budget"] = budget
    p.write_text(json.dumps(cfg))


# --- H1 directed ------------------------------------------------------------

def test_h1_pauses_before_build_2_then_converges(tmp_path):
    cr = setup_control(tmp_path, FAKE)
    _set_mode(cr, "directed")

    assert supervisor.run(str(cr), None) == 10          # pause after verify 1
    assert _states(cr)[-1] == "CHECKPOINT"

    assert supervisor.resume(str(cr), "continue") == 10  # pause BEFORE build 2
    run_dir = cr / "runs" / os.listdir(cr / "runs")[0]
    assert (run_dir / "checkpoint_build_2.md").exists()
    phases = [e["data"].get("phase") for e in read_journal(cr)[0]
              if e["state"] == "CHECKPOINT"]
    assert phases == ["AWAIT_VERIFY_1", "AWAIT_BUILD_2"]
    # only ONE build so far -- the before-build pause is BEFORE the dispatch.
    assert _states(cr).count("BUILD") == 1

    assert supervisor.resume(str(cr), "continue") == 0   # approved build -> converge
    st = _states(cr)
    assert st[-1] == "CONVERGED"
    assert st.count("BUILD") == 2                         # no duplicate dispatch
    m = json.loads((run_dir / "manifest.json").read_text())
    assert m["intervention_mode"] == "H1"


# --- H2 supervised (default) ------------------------------------------------

def test_h2_pauses_after_verify_only(tmp_path):
    cr = setup_control(tmp_path, FAKE)
    _set_mode(cr, "supervised")

    assert supervisor.run(str(cr), None) == 10
    assert _states(cr)[-1] == "CHECKPOINT"
    # H2 does NOT gate the rebuild: one resume converges straight to seal (no
    # before-build pause, no before-ship pause).
    assert supervisor.resume(str(cr), "continue") == 0
    st = _states(cr)
    assert st[-1] == "CONVERGED"
    assert "AWAIT_BUILD_2" not in [
        e["data"].get("phase") for e in read_journal(cr)[0] if e["state"] == "CHECKPOINT"]


# --- H3 guarded -------------------------------------------------------------

def test_h3_runs_straight_through_no_pause(tmp_path):
    cr = setup_control(tmp_path, FAKE)
    _set_mode(cr, "guarded")
    assert supervisor.run(str(cr), None) == 0            # no pause at all
    st = _states(cr)
    assert "CHECKPOINT" not in st
    assert st[-1] == "CONVERGED"


def test_h3_pauses_on_budget_cap(tmp_path):
    cr = setup_control(tmp_path, STUBBORN, max_iterations=4)
    _set_mode(cr, "guarded")
    _set_budget(cr, {"billing": "api", "per_call_usd": 1.0, "max_usd": 1.0})
    assert supervisor.run(str(cr), None) == 10           # budget guard PAUSES under H3
    st = _states(cr)
    assert "BUDGET_PAUSE" in st and "BUDGET_HALTED" not in st


# --- H4 lights-out (mocked hardened backend; no Docker needed) --------------

def _mock_hardened(monkeypatch):
    import test_hardened_config as H
    H._patch_hardened_probes(monkeypatch, os_ok=True, dk_ok=True)

    def fake_invoke(adapter, role, workdir, prompt_file, timeout_s,
                    exec_prefix=None, env_extra=None, **kw):
        # A converging build: write the correct greet.py so dev+final pass.
        with open(os.path.join(workdir, "greet.py"), "w", encoding="utf-8") as f:
            f.write(H.GREET_PY)
        return {"adapter_protocol": "0.1", "status": "ok"}, None

    monkeypatch.setattr(supervisor, "invoke_adapter", fake_invoke)


def _hardened_mode_control(tmp_path, mode, budget=None):
    cr = setup_control(tmp_path, FAKE)
    p = cr / "config.json"
    cfg = json.loads(p.read_text())
    cfg["assurance"] = "hardened"
    for k in ("autonomy", "checkpoint"):
        cfg.pop(k, None)
    cfg["intervention_mode"] = mode
    if budget is not None:
        cfg["budget"] = budget
    p.write_text(json.dumps(cfg))
    return cr


def test_h4_runs_straight_to_seal_never_pauses(tmp_path, monkeypatch):
    _mock_hardened(monkeypatch)
    cr = _hardened_mode_control(tmp_path, "lights_out")
    rc = supervisor.run(str(cr), None)
    assert rc == 0
    st = _states(cr)
    assert "CHECKPOINT" not in st and "BUDGET_PAUSE" not in st
    m = json.loads((cr / "runs" / os.listdir(cr / "runs")[0] / "manifest.json").read_text())
    assert m["intervention_mode"] == "H4"


def test_h4_budget_cap_terminates_budget_halted_never_pauses(tmp_path, monkeypatch):
    _mock_hardened(monkeypatch)
    # per_call_usd=1.0, max_usd=0.5: the FIRST call's admission (est_after=1.0 >
    # 0.5) trips the budget guard -- under H4 that is a fail-closed TERMINAL,
    # not a pause.
    cr = _hardened_mode_control(tmp_path, "lights_out",
                                budget={"billing": "api", "per_call_usd": 1.0, "max_usd": 0.5})
    rc = supervisor.run(str(cr), None)
    assert rc == 3                                       # terminal, not PAUSED(10)
    st = _states(cr)
    assert "BUDGET_HALTED" in st
    assert "BUDGET_PAUSE" not in st and "CHECKPOINT" not in st
    run_dir = cr / "runs" / os.listdir(cr / "runs")[0]
    assert not (run_dir / "state.json").exists()         # no resumable pause
    m = json.loads((run_dir / "manifest.json").read_text())
    assert m["outcome"] == "BUDGET_HALTED"
    assert m["qualified"] is False
    assert "qualification" in m


# --- the host-isolation security fix, end to end ----------------------------

def test_standard_optout_seals_host_isolation_limited(tmp_path):
    b = df_sandbox.current_backend()
    if not (b and b.available()):
        pytest.skip("no OS sandbox primitive for a standard run")
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")  # H3; single-shot
    p = cr / "config.json"
    cfg = json.loads(p.read_text())
    cfg["assurance"] = "standard"
    cfg["candidate_host_read"] = "allow_host_read"          # opt OUT of default-deny
    p.write_text(json.dumps(cfg))

    assert supervisor.run(str(cr), None) == 0
    m = json.loads((cr / "runs" / os.listdir(cr / "runs")[0] / "manifest.json").read_text())
    # THE fix: qualified is now gated on host_isolation, so this seals the
    # distinct HOST_ISOLATION_LIMITED (pre-M36a it was COMPLETE_QUALIFIED).
    assert m["outcome"] == "HOST_ISOLATION_LIMITED"
    assert m["qualified"] is False
    assert m["qualification"]["substates"] == {
        "barrier": True, "host_isolation": False, "control_plane": True,
        "app_security": True, "waiver_validity": True}
