"""M7 e2e acceptance: the fail-closed pre-build gate (coverage + mutation),
driven as a real subprocess against the supervisor CLI (matches
test_e2e_final_exam.py's pattern).

  (a) behaviors.json fully covered by discriminating dev scenarios -> the
      gate passes silently and the run converges; manifest carries
      coverage.checked=True/uncovered_dev=[] and oracle.mutation_validated=True.
  (b) behaviors.json declares a behavior with no dev scenario -> exit 2,
      COVERAGE_GATE_FAILED, and the builder never runs (no BUILD entry).
  (c) a scenario whose `then` is inert/tautological
      ({"stdout_contains": ""}) -> exit 2, ORACLE_GATE_FAILED, no BUILD entry
      (mutation validation runs BEFORE coverage and blocks the build).
  (d) no behaviors.json at all -> back-compat: converges, coverage.checked=False.
"""
import json
import os
import subprocess
import sys

from test_supervisor import FAKE, MARKER, setup_control

HERE = os.path.dirname(os.path.abspath(__file__))
SUP = os.path.join(HERE, "..", "scripts", "supervisor.py")


def _write_behaviors(cr, ids):
    (cr / "behaviors.json").write_text(
        json.dumps({"behaviors": [{"id": bid} for bid in ids]}), encoding="utf-8"
    )


def _add_scenario(cr, sid, bid, run, then, name):
    sc = {
        "ir_version": "0.1", "id": sid, "behavior_id": bid,
        "title": f"{MARKER} {name}", "given": f"{MARKER} workspace has greet.py",
        "when": {"run": run, "timeout_s": 10}, "then": then,
    }
    (cr / "scenarios" / f"{name}.json").write_text(json.dumps(sc), encoding="utf-8")


def _run(cr):
    return subprocess.run(
        [sys.executable, SUP, "run", "--control-root", str(cr)],
        capture_output=True, text=True, timeout=120,
    )


def _run_dir(cr):
    run_id = os.listdir(cr / "runs")[0]
    return cr / "runs" / run_id


def _journal(run_dir):
    lines = (run_dir / "journal.jsonl").read_text(encoding="utf-8").strip().splitlines()
    return [json.loads(l) for l in lines]


def test_full_coverage_and_discriminating_scenarios_converges(tmp_path):
    # setup_control's default scenarios: BHV-001 (S1, S2), BHV-002 (S1), all
    # dev cohort, all with discriminating `then` (exit_code + stdout/stderr
    # assertions) -> both gates pass.
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")
    _write_behaviors(cr, ["BHV-001", "BHV-002"])

    proc = _run(cr)
    assert proc.returncode == 0, proc.stderr

    run_dir = _run_dir(cr)
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["coverage"]["checked"] is True
    assert manifest["coverage"]["uncovered_dev"] == []
    assert manifest["coverage"]["orphan_scenarios"] == []
    assert manifest["oracle"]["mutation_validated"] is True
    assert manifest["oracle"]["inert"] == []

    entries = _journal(run_dir)
    states = [e["state"] for e in entries]
    assert "GATE_PASSED" in states
    assert "BUILD" in states  # the builder did run


def test_uncovered_behavior_blocks_build(tmp_path):
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")
    # BHV-003 is declared but has no scenario at all -> uncovered_dev.
    _write_behaviors(cr, ["BHV-001", "BHV-002", "BHV-003"])

    proc = _run(cr)
    assert proc.returncode == 2, proc.stdout + proc.stderr

    run_dir = _run_dir(cr)
    entries = _journal(run_dir)
    states = [e["state"] for e in entries]
    assert "COVERAGE_GATE_FAILED" in states
    assert "BUILD" not in states  # the builder never ran

    gate_entry = next(e for e in entries if e["state"] == "COVERAGE_GATE_FAILED")
    assert gate_entry["data"]["uncovered"] == ["BHV-003"]
    assert gate_entry["data"]["orphans"] == []

    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["outcome"] == "GATE_FAILED"
    assert manifest["qualified"] is False
    assert manifest["coverage"]["uncovered_dev"] == ["BHV-003"]
    assert manifest["oracle"]["mutation_validated"] is True  # mutation gate passed first


def test_inert_scenario_blocks_build_before_coverage(tmp_path):
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")
    # A tautological check: "" is a substring of any stdout, so this scenario
    # can never fail regardless of what the build does -> inert.
    _add_scenario(
        cr, "BHV-001-S9", "BHV-001", ["python3", "greet.py", "World"],
        {"stdout_contains": ""}, "inert",
    )

    proc = _run(cr)
    assert proc.returncode == 2, proc.stdout + proc.stderr

    run_dir = _run_dir(cr)
    entries = _journal(run_dir)
    states = [e["state"] for e in entries]
    assert "ORACLE_GATE_FAILED" in states
    assert "BUILD" not in states  # the builder never ran
    assert "COVERAGE_GATE_FAILED" not in states  # mutation gate runs first and blocks

    gate_entry = next(e for e in entries if e["state"] == "ORACLE_GATE_FAILED")
    assert gate_entry["data"]["inert"] == ["BHV-001-S9"]

    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["outcome"] == "GATE_FAILED"
    assert manifest["qualified"] is False
    assert manifest["oracle"]["mutation_validated"] is False
    assert manifest["oracle"]["inert"] == ["BHV-001-S9"]
    assert manifest["coverage"]["checked"] is False


def test_no_behaviors_json_is_back_compat(tmp_path):
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")  # no behaviors.json authored

    proc = _run(cr)
    assert proc.returncode == 0, proc.stderr

    run_dir = _run_dir(cr)
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["coverage"] == {"checked": False}
    assert manifest["oracle"]["mutation_validated"] is True

    entries = _journal(run_dir)
    states = [e["state"] for e in entries]
    assert "GATE_PASSED" in states
    assert "BUILD" in states
