import json
import os

import pytest

import supervisor
from test_supervisor import FAKE, setup_control, read_journal

SAMPLE_REPORT = {
    "report_version": "0.1",
    "all_pass": False,
    "results": [
        {"id": "BHV-001-S1", "behavior_id": "BHV-001", "pass": False,
         "taxonomy": "wrong_output", "observed": {"exit_code": 0, "stdout": "x", "stderr": ""}},
        {"id": "BHV-002-S1", "behavior_id": "BHV-002", "pass": True,
         "taxonomy": None, "observed": {"exit_code": 2, "stdout": "", "stderr": "usage"}},
    ],
}


def test_save_and_load_state_roundtrip(tmp_path):
    rd = tmp_path / "runs" / "r1"
    rd.mkdir(parents=True)
    supervisor.save_state(str(rd), next_iter=3, feedback={"failing_count": 1}, workspace="/ws/x")
    st = supervisor.load_state(str(rd))
    assert st["state_version"] == "0.1"
    assert st["next_iter"] == 3
    assert st["feedback"] == {"failing_count": 1}
    assert st["workspace"] == "/ws/x"
    assert st["run_dir"] == str(rd)


def test_latest_paused_run_picks_newest_with_state(tmp_path):
    cr = tmp_path / "control"
    (cr / "runs" / "20260101T000000Z-aaaa").mkdir(parents=True)
    newer = cr / "runs" / "20260201T000000Z-bbbb"
    newer.mkdir(parents=True)
    # only the newer one is paused (has state.json)
    supervisor.save_state(str(newer), 2, None, str(tmp_path / "ws"))
    assert supervisor.latest_paused_run(str(cr)) == str(newer)


def test_latest_paused_run_none_when_no_state(tmp_path):
    cr = tmp_path / "control"
    (cr / "runs" / "20260101T000000Z-aaaa").mkdir(parents=True)
    assert supervisor.latest_paused_run(str(cr)) is None


def test_checkpoint_report_has_ids_and_results_no_scenario_text(tmp_path):
    rd = tmp_path / "runs" / "r1"
    rd.mkdir(parents=True)
    path = supervisor.write_checkpoint_report(str(rd), 1, SAMPLE_REPORT)
    text = open(path, encoding="utf-8").read()
    assert "BHV-001" in text and "BHV-002" in text
    assert "wrong_output" in text
    assert "1/2" in text  # passing summary
    # observed exit codes are fine for the (trusted) human; raw stdout bodies are not echoed
    assert "stdout" not in text


def test_pause_mode_stops_after_first_iteration_with_exit_10(tmp_path):
    cr = setup_control(tmp_path, FAKE)  # FAKE builds buggy first, fixes after feedback
    # setup_control defaults autonomy 4 → checkpoint pause
    rc = supervisor.run(str(cr), None)
    assert rc == 10
    entries, run_id = read_journal(cr)
    states = [e["state"] for e in entries]
    assert states.count("BUILD") == 1  # paused after iteration 1
    assert "CHECKPOINT" in states
    assert "CONVERGED" not in states
    run_dir = cr / "runs" / run_id
    assert (run_dir / "state.json").exists()
    assert (run_dir / "checkpoint_iter_1.md").exists()
    assert not (run_dir / "manifest.json").exists()  # pause is non-terminal


def test_auto_mode_runs_to_convergence_without_pausing(tmp_path):
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")
    rc = supervisor.run(str(cr), None)
    assert rc == 0
    entries, _ = read_journal(cr)
    states = [e["state"] for e in entries]
    assert "CHECKPOINT" not in states and "CONVERGED" in states
