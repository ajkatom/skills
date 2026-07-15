"""e2e budget pause/resume (M8-3): drive the supervisor CLI as a subprocess.

Uses STUBBORN (never converges — BHV-001 always fails, so it keeps making
builder calls every iteration) rather than FAKE's buggy-then-fixed 2-call
path, so the pause/raise/resume flow is exercised across MORE than one call
on each side of the pause.
"""
import json
import os
import subprocess
import sys

from test_supervisor import STUBBORN, setup_control

SUP = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "scripts", "supervisor.py"
)


def _run(cr, *args):
    return subprocess.run([sys.executable, SUP, *args, "--control-root", str(cr)],
                          capture_output=True, text=True, timeout=120)


def _set_budget(cr, budget):
    cfg_path = cr / "config.json"
    cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
    cfg["budget"] = budget
    cfg_path.write_text(json.dumps(cfg), encoding="utf-8")


def _journal(cr, run_id):
    lines = (cr / "runs" / run_id / "journal.jsonl").read_text(encoding="utf-8")
    return [json.loads(l) for l in lines.strip().splitlines()]


def test_api_budget_pause_then_raise_and_resume_counts_across_segments(tmp_path):
    cr = setup_control(tmp_path, STUBBORN, max_iterations=4, checkpoint="auto")
    _set_budget(cr, {"billing": "api", "per_call_usd": 1.0, "max_usd": 1.0})

    p1 = _run(cr, "run")
    assert p1.returncode == 10, p1.stderr

    run_id = os.listdir(cr / "runs")[0]
    run_dir = cr / "runs" / run_id
    entries = _journal(cr, run_id)
    states = [e["state"] for e in entries]
    # call 1 (est_after=1.0, not > cap) is admitted; call 2's admission
    # (est_after=2.0 > 1.0) pauses BEFORE the 2nd call is made.
    assert states.count("BUILD") == 1
    assert "BUDGET_PAUSE" in states
    pause = next(e for e in entries if e["state"] == "BUDGET_PAUSE")
    assert pause["data"]["builder_calls"] == 1
    assert pause["data"]["estimated_usd"] == 1.0
    pre_pause_calls = pause["data"]["builder_calls"]

    # The raise-and-resume instruction is PRINTED (stdout), not sys.stderr.write
    # (see supervisor._run_loop's BUDGET_PAUSE branch — it uses print()).
    assert "budget cap reached" in p1.stdout
    assert "raise budget.max_usd" in p1.stdout.lower()
    assert "resume --control-root" in p1.stdout
    assert "--decision continue" in p1.stdout
    assert not (run_dir / "manifest.json").exists()  # pause is non-terminal
    state = json.loads((run_dir / "state.json").read_text(encoding="utf-8"))
    assert state["reason"] == "budget"
    assert state["builder_calls"] == 1

    # Raise the cap and resume. STUBBORN never converges, so this segment
    # runs the remaining iterations to CAP_REACHED (exit 3) — per the plan,
    # that's fine: the point under test is that the run RESUMED PAST the
    # budget pause and made MORE builder calls, with no reset/double-count.
    _set_budget(cr, {"billing": "api", "per_call_usd": 1.0, "max_usd": 100.0})
    p2 = _run(cr, "resume", "--decision", "continue")
    assert p2.returncode == 3, p2.stderr

    entries2 = _journal(cr, run_id)
    states2 = [e["state"] for e in entries2]
    assert states2.count("BUDGET_PAUSE") == 1  # not re-triggered after the raise
    assert states2[-1] == "CAP_REACHED"
    total_builds = states2.count("BUILD")
    assert total_builds > 1  # more calls happened after resume

    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["outcome"] == "CAP_REACHED"
    total_calls = manifest["budget"]["builder_calls"]
    # Structurally non-vacuous: strictly more than the pre-pause count, and
    # equal to the number of BUILD journal entries across BOTH segments —
    # i.e. no reset on resume and no double-count of the pre-pause call.
    assert total_calls > pre_pause_calls
    assert total_calls == total_builds
    assert manifest["budget"]["estimated_usd"] == total_calls * 1.0
    assert manifest["budget"]["enforced"] is True
    assert manifest["budget"]["cap_usd"] == 100.0  # the raised cap, re-read on resume


def test_subscription_budget_never_pauses_with_stubborn_builder(tmp_path):
    cr = setup_control(tmp_path, STUBBORN, max_iterations=2, checkpoint="auto")
    _set_budget(cr, {"billing": "subscription"})

    p = _run(cr, "run")
    assert p.returncode == 3, p.stderr  # hits the iteration cap, never a $ budget pause

    run_id = os.listdir(cr / "runs")[0]
    entries = _journal(cr, run_id)
    states = [e["state"] for e in entries]
    assert "BUDGET_PAUSE" not in states
    assert states[-1] == "CAP_REACHED"
    assert states.count("BUILD") == 2  # both iterations ran; nothing was blocked

    manifest = json.loads(
        (cr / "runs" / run_id / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["budget"]["billing"] == "subscription"
    assert manifest["budget"]["enforced"] is False
    assert manifest["budget"]["builder_calls"] == 2
