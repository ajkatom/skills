"""M1 acceptance: the walking-skeleton loop converges WITHOUT the builder
ever seeing the holdout. Scenario titles/givens carry a unique MARKER string;
we assert the marker never appears anywhere the builder could look."""
import json
import os
import subprocess
import sys

from test_supervisor import FAKE, MARKER, setup_control

SUP = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "scripts", "supervisor.py"
)


def walk_files(root):
    for dirpath, _, filenames in os.walk(root):
        for name in filenames:
            yield os.path.join(dirpath, name)


def test_e2e_converges_and_never_leaks_holdout(tmp_path):
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")
    ws_root = tmp_path / "ws"

    proc = subprocess.run(
        [sys.executable, SUP, "run", "--control-root", str(cr)],
        capture_output=True, text=True, timeout=120,
    )
    assert proc.returncode == 0, proc.stderr

    # 1. It converged: the built artifact actually implements the spec.
    run_id = os.listdir(cr / "runs")[0]
    run_dir = cr / "runs" / run_id
    workspace = None
    for entry in json.loads("[" + ",".join(
        (run_dir / "journal.jsonl").read_text(encoding="utf-8").strip().splitlines()
    ) + "]"):
        if entry["state"] == "SNAPSHOT":
            workspace = entry["data"]["workspace"]
    assert workspace is not None
    out = subprocess.run(["python3", "greet.py", "Alon"], cwd=workspace,
                         capture_output=True, text=True)
    assert out.stdout.strip() == "Hello, Alon!"

    # 2. THE INVARIANT: no holdout content anywhere the builder could look.
    #    (a) not in the workspace filesystem
    for path in walk_files(workspace):
        with open(path, "rb") as f:
            assert MARKER.encode() not in f.read(), f"holdout leaked into {path}"
    #    (b) no scenarios directory materialized in the workspace
    assert not os.path.exists(os.path.join(workspace, "scenarios"))
    #    (c) not in any builder prompt
    for name in os.listdir(run_dir):
        if name.startswith("prompt_iter_"):
            text = (run_dir / name).read_text(encoding="utf-8")
            assert MARKER not in text, f"holdout leaked into {name}"
    #    (d) not in any feedback file, and feedback is schema-clean
    import id_feedback
    for name in os.listdir(run_dir):
        if name.startswith("feedback_iter_"):
            fb = json.loads((run_dir / name).read_text(encoding="utf-8"))
            id_feedback.validate_feedback(fb)
            assert MARKER not in json.dumps(fb)
    #    (e) not in supervisor stdout/stderr
    assert MARKER not in proc.stdout and MARKER not in proc.stderr

    # 3. The audit chain verifies.
    ver = subprocess.run(
        [sys.executable, SUP, "verify-manifest", "--run-dir", str(run_dir)],
        capture_output=True, text=True,
    )
    assert ver.returncode == 0

    # 4. Honesty: the run is explicitly unqualified (cooperative tier).
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["qualified"] is False
    assert manifest["outcome"] == "COMPLETE_UNQUALIFIED"
    assert "COOPERATIVE MODE" in proc.stderr
