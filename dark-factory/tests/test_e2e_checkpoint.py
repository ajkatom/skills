import json
import os
import subprocess
import sys

from test_supervisor import FAKE, MARKER, setup_control

SUP = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "scripts", "supervisor.py"
)


def _run(cr, *args):
    return subprocess.run([sys.executable, SUP, *args, "--control-root", str(cr)],
                          capture_output=True, text=True, timeout=120)


def test_pause_then_resume_converges_without_leaking_holdout(tmp_path):
    cr = setup_control(tmp_path, FAKE)  # pause mode (autonomy 4 default)

    p1 = _run(cr, "run")
    assert p1.returncode == 10, p1.stderr           # paused at checkpoint
    run_id = os.listdir(cr / "runs")[0]
    run_dir = cr / "runs" / run_id
    assert (run_dir / "checkpoint_iter_1.md").exists()
    assert (run_dir / "state.json").exists()

    # MARKER (planted in scenario titles/givens) must not be in anything the human-review
    # surface shares with the builder, nor in the checkpoint artifacts.
    for name in os.listdir(run_dir):
        if name.startswith(("prompt_iter_", "feedback_iter_", "checkpoint_iter_")) or name == "state.json":
            assert MARKER not in (run_dir / name).read_text(encoding="utf-8"), name

    # M36b: H2 converges into a before-ship pause; a second resume seals.
    p2 = _run(cr, "resume", "--decision", "continue")
    assert p2.returncode == 10, p2.stderr           # converged -> AWAIT_SHIP pause
    assert (run_dir / "checkpoint_ship.md").exists()
    assert MARKER not in (run_dir / "checkpoint_ship.md").read_text(encoding="utf-8")
    p3 = _run(cr, "resume", "--decision", "continue")
    assert p3.returncode == 0, p3.stderr            # seal-reentry (no rebuild)
    assert not (run_dir / "state.json").exists()
    manifest = json.loads((run_dir / "manifest.json").read_text())
    assert manifest["outcome"] == "COMPLETE_UNQUALIFIED"

    # built artifact really works; MARKER absent from the whole workspace
    st = json.loads("[" + ",".join(
        (run_dir / "journal.jsonl").read_text().strip().splitlines()) + "]")
    workspace = next(e["data"]["workspace"] for e in st if e["state"] == "SNAPSHOT")
    out = subprocess.run(["python3", "greet.py", "World"], cwd=workspace,
                         capture_output=True, text=True)
    assert out.stdout.strip() == "Hello, World!"
    for dp, _, fns in os.walk(workspace):
        for fn in fns:
            assert MARKER.encode() not in open(os.path.join(dp, fn), "rb").read()
