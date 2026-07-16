"""e2e mandatory security gates (M9-3): drive the supervisor CLI as a real
subprocess, matching test_e2e_final_exam.py / test_e2e_budget.py's pattern.

  (a) a clean artifact + security_gates.enabled -> converges exit 0,
      manifest security.checked==True, security.failed==[], and
      run_dir/security_report.json exists.
  (b) fake_builder_secret writes a WORKING greet.py (every scenario passes)
      PLUS a config.py with a planted fake AWS key, fail_on: ["secret_scan"]
      -> the run still ends SECURITY_GATE_FAILED, exit 3, qualified False,
      journal has SECURITY_GATE_FAILED — proving gates are independent of
      scenario pass. The planted secret VALUE must never appear in any run
      artifact (manifest, journal, security_report) — only the rule name.
  (c) no security_gates block at all -> converges exit 0,
      manifest security.checked==False (back-compatible default).
"""
import json
import os
import subprocess
import sys

from test_supervisor import FAKE, setup_control, terminal_state

HERE = os.path.dirname(os.path.abspath(__file__))
FAKE_SECRET = os.path.join(HERE, "fixtures", "fake_builder_secret")
SUP = os.path.join(HERE, "..", "scripts", "supervisor.py")

PLANTED_SECRET = "AKIAABCDEFGHIJKLMNOP"


def _run(cr, *args):
    return subprocess.run([sys.executable, SUP, *args, "--control-root", str(cr)],
                          capture_output=True, text=True, timeout=120)


def _set_security_gates(cr, security_gates):
    cfg_path = cr / "config.json"
    cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
    cfg["security_gates"] = security_gates
    cfg_path.write_text(json.dumps(cfg), encoding="utf-8")


def _journal(cr, run_id):
    lines = (cr / "runs" / run_id / "journal.jsonl").read_text(encoding="utf-8")
    return [json.loads(l) for l in lines.strip().splitlines()]


def _walk_all_files(root):
    for dirpath, _, filenames in os.walk(root):
        for name in filenames:
            yield os.path.join(dirpath, name)


def test_clean_artifact_converges_with_security_checked(tmp_path):
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")
    _set_security_gates(cr, {"enabled": True})

    proc = _run(cr, "run")
    assert proc.returncode == 0, proc.stderr

    run_id = os.listdir(cr / "runs")[0]
    run_dir = cr / "runs" / run_id
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["security"]["checked"] is True
    assert manifest["security"]["failed"] == []
    assert (run_dir / "security_report.json").exists()

    entries = _journal(cr, run_id)
    states = [e["state"] for e in entries]
    assert "SECURITY_GATES" in states
    sg = next(e for e in entries if e["state"] == "SECURITY_GATES")
    assert sg["data"]["checked"] is True
    assert sg["data"]["failed"] == []


def test_planted_secret_rejects_artifact_independent_of_scenario_pass(tmp_path):
    cr = setup_control(tmp_path, FAKE_SECRET, checkpoint="auto")
    _set_security_gates(cr, {"enabled": True, "fail_on": ["secret_scan"]})

    proc = _run(cr, "run")
    assert proc.returncode == 3, proc.stderr

    run_id = os.listdir(cr / "runs")[0]
    run_dir = cr / "runs" / run_id
    workspace = tmp_path / "ws" / run_id

    entries = _journal(cr, run_id)
    states = [e["state"] for e in entries]
    # The build itself succeeded and every dev scenario passed (fake_builder_secret
    # writes a WORKING greet.py) — CONVERGED-adjacent states happened, proving the
    # rejection is NOT a scenario failure.
    assert "VERIFY" in states
    verify_entries = [e for e in entries if e["state"] == "VERIFY"]
    assert verify_entries[-1]["data"]["passing"] == verify_entries[-1]["data"]["total"]
    assert "SECURITY_GATE_FAILED" in states
    assert "CONVERGED" not in states

    sgf = next(e for e in entries if e["state"] == "SECURITY_GATE_FAILED")
    assert sgf["data"]["failed"] == ["secret_scan"]

    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["outcome"] == "SECURITY_GATE_FAILED"
    assert manifest["qualified"] is False
    assert manifest["security"]["checked"] is True
    assert manifest["security"]["failed"] == ["secret_scan"]
    assert manifest["security"]["gates"]["secret_scan"]["status"] == "fail"

    print_out = proc.stdout
    assert "security gate failed" in print_out.lower()
    assert "secret_scan" in print_out

    # The planted secret VALUE must never leak into any run artifact — only
    # the rule name ("secret_scan"/"aws_access_key") may appear. Structurally
    # non-vacuous: assert we actually scanned files before asserting absence.
    checked_any = False
    for path in _walk_all_files(str(run_dir)):
        checked_any = True
        with open(path, "rb") as f:
            data = f.read()
        assert PLANTED_SECRET.encode() not in data, f"planted secret leaked into {path}"
    assert checked_any, "run_dir is empty — scan would be vacuous"
    assert proc.stdout.count(PLANTED_SECRET) == 0
    assert proc.stderr.count(PLANTED_SECRET) == 0

    # But the planted secret DOES still exist in the workspace artifact itself
    # (that's what got scanned) — confirms the scan wasn't vacuous either.
    assert (workspace / "config.py").exists()
    assert PLANTED_SECRET in (workspace / "config.py").read_text(encoding="utf-8")


def test_no_security_block_converges_with_security_unchecked(tmp_path):
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")
    # No _set_security_gates call at all — absent security_gates block.

    proc = _run(cr, "run")
    assert proc.returncode == 0, proc.stderr

    run_id = os.listdir(cr / "runs")[0]
    run_dir = cr / "runs" / run_id
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["security"] == {"checked": False}
    assert not (run_dir / "security_report.json").exists()

    entries = _journal(cr, run_id)
    states = [e["state"] for e in entries]
    assert "SECURITY_GATES" not in states
    assert "SECURITY_GATE_FAILED" not in states
    assert terminal_state(entries)["state"] == "CONVERGED"


def test_resumed_converge_also_runs_security_gates(tmp_path):
    """M6 lesson (resume() also produces terminal manifests): the CONVERGED
    branch that runs security gates lives inside _run_loop, which BOTH run()
    and resume(--decision continue) funnel through — so a paused-then-resumed
    run must get the exact same gate treatment as a fresh converge, with no
    separate wiring needed. checkpoint (pause) mode + FAKE (buggy-then-fixed)
    forces a pause on iteration 1, then resume converges on iteration 2.
    """
    cr = setup_control(tmp_path, FAKE)  # pause mode (autonomy 4 default)
    _set_security_gates(cr, {"enabled": True})

    p1 = _run(cr, "run")
    assert p1.returncode == 10, p1.stderr  # paused at checkpoint, non-terminal

    run_id = os.listdir(cr / "runs")[0]
    run_dir = cr / "runs" / run_id
    assert not (run_dir / "manifest.json").exists()
    assert not (run_dir / "security_report.json").exists()

    p2 = _run(cr, "resume", "--decision", "continue")
    assert p2.returncode == 0, p2.stderr  # converged after resume

    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["outcome"] == "COMPLETE_UNQUALIFIED"
    assert manifest["security"]["checked"] is True
    assert manifest["security"]["failed"] == []
    assert (run_dir / "security_report.json").exists()

    entries = _journal(cr, run_id)
    states = [e["state"] for e in entries]
    assert "SECURITY_GATES" in states
    assert terminal_state(entries)["state"] == "CONVERGED"
