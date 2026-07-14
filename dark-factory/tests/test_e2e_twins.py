"""M3a acceptance (Task 6, final): a twin-using task builds and verifies via
the supervisor CLI, and twins compose with OS isolation.

Proves:
  1. (always) a twin-enabled cooperative run CONVERGES; the built greet.py
     genuinely talks to the twin (not a stub) — both via the live audit
     trail captured during the run AND via an independent post-hoc
     re-execution against a freshly-started twin instance; and no twin
     process survives the run (pgrep -f twin_greeter is empty).
  2. (backend-guarded) under assurance: standard, the same twin-using run
     still converges QUALIFIED (manifest qualified:true / COMPLETE_QUALIFIED)
     — the sandboxed candidate reached the localhost twin AND the real
     holdout scenarios remain OS-denied to a process wrapped by the same
     backend. Skips cleanly if no OS sandbox primitive is available.
"""
import json
import os
import subprocess
import sys
import time

import pytest

import df_sandbox
from test_supervisor_twins import FAKE_TWIN_BUILDER, GREETER, _no_twin_orphans, _twin_control

SUP = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts", "supervisor.py")


def _journal(cr):
    run_id = os.listdir(cr / "runs")[0]
    run_dir = cr / "runs" / run_id
    lines = (run_dir / "journal.jsonl").read_text(encoding="utf-8").strip().splitlines()
    return [json.loads(l) for l in lines], run_dir


def _workspace_from_journal(entries):
    for e in entries:
        if e["state"] == "SNAPSHOT":
            return e["data"]["workspace"]
    return None


def _start_fresh_twin(tmp_path, name="fresh_twin"):
    """Start an INDEPENDENT instance of the greeter-twin fixture, separate
    from whatever the supervisor started and already reaped. Used to
    re-execute the built greet.py after the supervisor run has fully exited
    (its own twin is gone by then — teardown happens in the run's finally
    block, before the CLI process returns). If greet.py were a stub that
    just hardcoded 'Hello, World!' rather than actually calling the twin,
    this independent re-execution (with a name never seen in any scenario
    the builder was shown) would still print the hardcoded string instead
    of matching a fresh, different greeting."""
    ep_file = tmp_path / f"{name}_endpoint"
    env = dict(os.environ, DF_ENDPOINT_FILE=str(ep_file))
    proc = subprocess.Popen([sys.executable, GREETER], env=env)
    deadline = time.time() + 10
    while time.time() < deadline and not ep_file.exists():
        time.sleep(0.05)
    assert ep_file.exists(), "fresh twin instance never became ready"
    endpoint = ep_file.read_text(encoding="utf-8").strip()
    return proc, endpoint


def test_twin_run_converges_talks_to_real_twin_and_leaves_no_orphans(tmp_path):
    cr = _twin_control(tmp_path, FAKE_TWIN_BUILDER)

    proc = subprocess.run(
        [sys.executable, SUP, "run", "--control-root", str(cr)],
        capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == 0, proc.stderr

    entries, run_dir = _journal(cr)
    states = [e["state"] for e in entries]
    assert "CONVERGED" in states
    assert "TWIN_ERROR" not in states

    workspace = _workspace_from_journal(entries)
    assert workspace is not None
    assert os.path.exists(os.path.join(workspace, "greet.py"))

    # 1. Live audit-trail proof: the verifier's own recorded observation,
    #    captured WHILE the supervisor-managed twin was up, shows the built
    #    code produced the twin's actual greeting (not a canned string).
    converged_iter = next(e["data"]["iteration"] for e in entries if e["state"] == "CONVERGED")
    report = json.loads(
        (run_dir / f"verifier_report_iter_{converged_iter}.json").read_text(encoding="utf-8")
    )
    result = next(r for r in report["results"] if r["id"] == "BHV-001-S1")
    assert result["pass"] is True
    assert result["observed"]["stdout"].strip() == "Hello, World!"

    # 2. Independent proof: no twin process survives the run (always-reap).
    assert _no_twin_orphans()

    # 3. Independent post-hoc re-execution against a FRESH twin instance
    #    (the supervisor's own twin is already gone) with a name that never
    #    appeared in any scenario/spec text — proves greet.py is generic,
    #    real client code, not a memorized/stubbed response.
    fresh, endpoint = _start_fresh_twin(tmp_path)
    try:
        env = dict(os.environ, DF_TWIN_GREETER=endpoint)
        out = subprocess.run(
            [sys.executable, "greet.py", "Fable"], cwd=workspace,
            capture_output=True, text=True, env=env, timeout=10,
        )
        assert out.returncode == 0, out.stderr
        assert out.stdout.strip() == "Hello, Fable!"
    finally:
        fresh.terminate()
        try:
            fresh.wait(timeout=5)
        except subprocess.TimeoutExpired:
            fresh.kill()
            fresh.wait(timeout=5)

    assert _no_twin_orphans()


@pytest.mark.skipif(sys.platform not in ("darwin", "linux"), reason="needs a real sandbox backend")
def test_standard_tier_twin_run_converges_qualified_and_holdout_still_denied(tmp_path):
    b = df_sandbox.current_backend()
    if not (b and b.available()):
        pytest.skip("no OS sandbox primitive")

    cr = _twin_control(tmp_path, FAKE_TWIN_BUILDER)
    p = cr / "config.json"
    cfg = json.loads(p.read_text())
    cfg["assurance"] = "standard"
    p.write_text(json.dumps(cfg))

    proc = subprocess.run(
        [sys.executable, SUP, "run", "--control-root", str(cr)],
        capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    assert "COOPERATIVE MODE" not in proc.stderr  # not silently downgraded

    entries, run_dir = _journal(cr)
    states = [e["state"] for e in entries]
    assert "CONVERGED" in states
    assert "TWIN_ERROR" not in states

    m = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert m["outcome"] == "COMPLETE_QUALIFIED"
    assert m["qualified"] is True
    assert m["denial_probe_passed"] is True

    # Twins + OS isolation compose: no twin process survives even though the
    # candidate ran wrapped by the sandbox to reach it over localhost.
    assert _no_twin_orphans()

    # Independent OS-level proof: a process wrapped by the same backend still
    # cannot read the real holdout scenarios living under the control root —
    # reaching the twin does not open a hole to the holdout.
    secret = next((cr / "scenarios").glob("*.json"))
    pref = b.wrap_prefix(str(cr), str(tmp_path / "ws"))
    denied = subprocess.run(pref + ["cat", str(secret)], capture_output=True, text=True)
    assert denied.returncode != 0
