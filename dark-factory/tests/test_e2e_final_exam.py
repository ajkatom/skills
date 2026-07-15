"""M6 e2e acceptance: the sealed FINAL cohort stays hidden from the builder
across a real subprocess run of the supervisor CLI, in both outcomes:

  (a) dev + final both pass -> exit 0, manifest final_exam.passed == True.
  (b) THE HEADLINE BARRIER: a unique MARKER embedded in the FINAL scenarios'
      title/given never appears anywhere the builder could see it — not in
      any prompt_iter_*.md, not in the workspace's DARK_FACTORY_PROMPT.md,
      not in any feedback file (run_dir or workspace), and nowhere in the
      workspace tree at all. The held-out exam stays hidden even though it
      ran and even though its verdict (pass/fail) escapes as behavior-IDs.
  (c) dev passes but the sealed exam fails (fake_builder_final) -> exit 3,
      FINAL_EXAM_FAILED, qualified False, and the barrier still holds: the
      final MARKER never leaked and no feedback file references the final
      behavior-ID (final was never fed back into the loop).

Driven as a real subprocess (not an in-process call) so this exercises the
actual CLI contract, matching test_e2e_loop.py's pattern.
"""
import json
import os
import subprocess
import sys

from test_final_exam import FAKE_FINAL, FINAL_MARKER, add_final_scenario, _run_dir_and_workspace
from test_supervisor import FAKE, setup_control

SUP = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "scripts", "supervisor.py"
)


def walk_files(root):
    for dirpath, _, filenames in os.walk(root):
        for name in filenames:
            yield os.path.join(dirpath, name)


def _assert_final_marker_never_leaked(run_dir, workspace, final_behavior_id=None):
    """The headline barrier assertion. Structurally non-vacuous: each scan
    asserts it found and inspected at least one real file before asserting
    the marker's absence from it, so a directory silently being empty can
    never masquerade as a pass."""
    # (1) run_dir prompt_iter_*.md — the control-plane audit copy of every prompt.
    prompt_files = [n for n in os.listdir(run_dir) if n.startswith("prompt_iter_")]
    assert prompt_files, "no prompt_iter_*.md found — scan would be vacuous"
    for name in prompt_files:
        text = (run_dir / name).read_text(encoding="utf-8")
        assert FINAL_MARKER not in text, f"final marker leaked into {name}"
        if final_behavior_id:
            assert final_behavior_id not in text, f"final behavior_id leaked into {name}"

    # (2) the workspace's DARK_FACTORY_PROMPT.md — what the builder actually reads.
    ws_prompt = workspace / "DARK_FACTORY_PROMPT.md"
    assert ws_prompt.exists(), "DARK_FACTORY_PROMPT.md missing — scan would be vacuous"
    text = ws_prompt.read_text(encoding="utf-8")
    assert FINAL_MARKER not in text
    if final_behavior_id:
        assert final_behavior_id not in text

    # (3) every feedback file, in run_dir (audit copy) and workspace (live copy).
    feedback_files = [n for n in os.listdir(run_dir) if n.startswith("feedback_iter_")]
    assert feedback_files, "no feedback_iter_*.json found — scan would be vacuous"
    for name in feedback_files:
        text = (run_dir / name).read_text(encoding="utf-8")
        assert FINAL_MARKER not in text, f"final marker leaked into {name}"
        if final_behavior_id:
            assert final_behavior_id not in text, f"final behavior_id leaked into {name}"
    ws_feedback = workspace / "feedback.json"
    assert ws_feedback.exists(), "workspace feedback.json missing — scan would be vacuous"
    text = ws_feedback.read_text(encoding="utf-8")
    assert FINAL_MARKER not in text
    if final_behavior_id:
        assert final_behavior_id not in text

    # (4) nowhere in the whole workspace filesystem (belt + suspenders on (2)/(3)).
    ws_files = list(walk_files(workspace))
    assert ws_files, "workspace is empty — scan would be vacuous"
    for path in ws_files:
        with open(path, "rb") as f:
            assert FINAL_MARKER.encode() not in f.read(), f"final marker leaked into {path}"


def test_e2e_dev_and_final_pass_marker_never_leaks(tmp_path):
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")
    add_final_scenario(
        cr, "BHV-901-S1", "BHV-901",
        ["python3", "greet.py", "Zephyr"],
        {"exit_code": 0, "stdout_equals": "Hello, Zephyr!"},
        f"{FINAL_MARKER} greets Zephyr",
    )

    proc = subprocess.run(
        [sys.executable, SUP, "run", "--control-root", str(cr)],
        capture_output=True, text=True, timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    assert FINAL_MARKER not in proc.stdout and FINAL_MARKER not in proc.stderr

    run_id = os.listdir(cr / "runs")[0]
    run_dir, workspace = _run_dir_and_workspace(cr, run_id, tmp_path)
    assert run_dir.exists() and workspace.exists()

    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["final_exam"] == {"ran": True, "passed": True, "count": 1}
    assert manifest["outcome"] == "COMPLETE_UNQUALIFIED"  # cooperative tier

    ver = subprocess.run(
        [sys.executable, SUP, "verify-manifest", "--run-dir", str(run_dir)],
        capture_output=True, text=True,
    )
    assert ver.returncode == 0, ver.stdout + ver.stderr
    assert "OK" in ver.stdout

    _assert_final_marker_never_leaked(run_dir, workspace)


def test_e2e_final_exam_failure_is_terminal_and_hidden(tmp_path):
    cr = setup_control(tmp_path, FAKE_FINAL, checkpoint="auto")
    add_final_scenario(
        cr, "BHV-901-S1", "BHV-901",
        ["python3", "greet.py", "Zephyr"],
        # fake_builder_final's corrected greet.py prints "Hello, Zephyr!" —
        # one "!" short of what this sealed scenario demands.
        {"exit_code": 0, "stdout_equals": "Hello, Zephyr!!!"},
        f"{FINAL_MARKER} greets Zephyr loudly",
    )

    proc = subprocess.run(
        [sys.executable, SUP, "run", "--control-root", str(cr)],
        capture_output=True, text=True, timeout=120,
    )
    assert proc.returncode == 3, proc.stderr
    assert FINAL_MARKER not in proc.stdout and FINAL_MARKER not in proc.stderr

    run_id = os.listdir(cr / "runs")[0]
    run_dir, workspace = _run_dir_and_workspace(cr, run_id, tmp_path)
    assert run_dir.exists() and workspace.exists()

    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["outcome"] == "FINAL_EXAM_FAILED"
    assert manifest["qualified"] is False
    assert manifest["final_exam"] == {"ran": True, "passed": False, "count": 1}

    ver = subprocess.run(
        [sys.executable, SUP, "verify-manifest", "--run-dir", str(run_dir)],
        capture_output=True, text=True,
    )
    assert ver.returncode == 0, ver.stdout + ver.stderr
    assert "OK" in ver.stdout

    # Barrier holds even on a rejected artifact: marker AND behavior-ID absent.
    _assert_final_marker_never_leaked(run_dir, workspace, final_behavior_id="BHV-901")

    # Final was never fed back: no feedback file references the final
    # behavior-ID (redundant with the helper above, kept explicit per the
    # "final not fed back" contract distinct from the "content hidden" one).
    for name in os.listdir(run_dir):
        if name.startswith("feedback_iter_"):
            fb = json.loads((run_dir / name).read_text(encoding="utf-8"))
            ids = {f["behavior_id"] for f in fb.get("failures", [])}
            assert "BHV-901" not in ids, f"final behavior-ID fed back in {name}"
