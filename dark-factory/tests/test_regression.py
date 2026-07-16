import json
import os

import supervisor
from test_supervisor import FAKE, setup_control, read_journal, terminal_state

HERE = os.path.dirname(os.path.abspath(__file__))
FAKE_REGRESS = os.path.join(HERE, "fixtures", "fake_builder_regress")


def test_regression_journaled_and_in_manifest(tmp_path):
    cr = setup_control(tmp_path, FAKE_REGRESS, max_iterations=2, checkpoint="auto")
    rc = supervisor.run(str(cr), None)
    # BHV-002 never passes -> never converges -> cap reached.
    assert rc == 3

    entries, run_id = read_journal(cr)
    states = [e["state"] for e in entries]
    assert states.count("BUILD") == 2
    assert "CONVERGED" not in states
    assert terminal_state(entries)["state"] == "CAP_REACHED"

    regression_entries = [e for e in entries if e["state"] == "REGRESSION"]
    assert len(regression_entries) == 1
    reg = regression_entries[0]
    assert reg["data"]["iteration"] == 2
    assert reg["data"]["behavior_id"] == "BHV-001"
    # barrier: only the behavior id, nothing else scenario-shaped
    assert set(reg["data"].keys()) == {"iteration", "behavior_id"}

    run_dir = cr / "runs" / run_id
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["outcome"] == "CAP_REACHED"
    assert manifest["regressions"] == ["BHV-001"]


def test_no_regression_when_monotonic(tmp_path):
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")
    rc = supervisor.run(str(cr), None)
    assert rc == 0

    entries, run_id = read_journal(cr)
    states = [e["state"] for e in entries]
    assert "CONVERGED" in states
    assert not any(e["state"] == "REGRESSION" for e in entries)

    run_dir = cr / "runs" / run_id
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["regressions"] == []
