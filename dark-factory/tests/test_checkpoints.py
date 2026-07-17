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
    # M36a Task 3: save_state now writes state_version 0.2 (phase-aware FSM
    # chain). This call did not request a chain append (chain_append defaults
    # False), so no fsm_chain.jsonl is created and the recorded head is None.
    assert st["state_version"] == "0.2"
    assert st["phase"] == "checkpoint"       # defaults to reason when unspecified
    assert st["fsm_chain_head"] is None
    assert st["build_approved_through"] == 0
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


def test_resume_continue_converges(tmp_path):
    cr = setup_control(tmp_path, FAKE)  # pause mode (H2)
    assert supervisor.run(str(cr), None) == 10          # paused after iter 1
    # M36b: H2 now pauses BEFORE ship on convergence — iter 2 converges but
    # pauses at AWAIT_SHIP, and a SECOND resume seals it (no rebuild).
    assert supervisor.resume(str(cr), "continue") == 10  # converged; before-ship pause
    assert supervisor.resume(str(cr), "continue") == 0   # seals (seal-reentry)
    entries, run_id = read_journal(cr)
    states = [e["state"] for e in entries]
    assert states.count("BUILD") == 2 and "CONVERGED" in states
    assert "SHIP_RESUME" in states
    assert not (cr / "runs" / run_id / "state.json").exists()  # cleared at terminal
    assert (cr / "runs" / run_id / "manifest.json").exists()


def test_resume_abort_exits_2_and_is_terminal(tmp_path):
    cr = setup_control(tmp_path, FAKE)
    assert supervisor.run(str(cr), None) == 10
    assert supervisor.resume(str(cr), "abort") == 2
    entries, run_id = read_journal(cr)
    assert entries[-1]["state"] == "ABORTED_BY_HUMAN"
    assert not (cr / "runs" / run_id / "state.json").exists()


def test_resume_accept_is_waived_and_exits_0(tmp_path):
    cr = setup_control(tmp_path, FAKE)
    assert supervisor.run(str(cr), None) == 10
    assert supervisor.resume(str(cr), "accept") == 0
    entries, run_id = read_journal(cr)
    assert entries[-1]["state"] == "ACCEPTED_BY_HUMAN"
    manifest = json.loads((cr / "runs" / run_id / "manifest.json").read_text())
    assert manifest["outcome"] == "ACCEPTED_WAIVED"
    assert manifest["qualified"] is False


def test_resume_with_no_paused_run_exits_2(tmp_path):
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")
    assert supervisor.run(str(cr), None) == 0  # converges, no pause
    assert supervisor.resume(str(cr), "continue") == 2  # nothing to resume


def test_resume_accept_forces_qualified_false_even_for_qualified_tier(tmp_path, monkeypatch):
    cr = setup_control(tmp_path, FAKE)  # pause mode
    assert supervisor.run(str(cr), None) == 10
    # Simulate a future qualified tier: force load_config to report _qualified True.
    real_load = supervisor.load_config
    def fake_load(control_root):
        cfg = real_load(control_root)
        cfg["_qualified"] = True
        return cfg
    monkeypatch.setattr(supervisor, "load_config", fake_load)
    assert supervisor.resume(str(cr), "accept") == 0
    run_id = os.listdir(cr / "runs")[0]
    manifest = json.loads((cr / "runs" / run_id / "manifest.json").read_text())
    assert manifest["outcome"] == "ACCEPTED_WAIVED"
    assert manifest["qualified"] is False   # forced, not inherited


def test_resume_on_locked_control_root_exits_2(tmp_path):
    cr = setup_control(tmp_path, FAKE)
    assert supervisor.run(str(cr), None) == 10   # paused; run() released its lock on return
    lock = supervisor.acquire_lock(str(cr))       # hold the lock
    try:
        assert supervisor.resume(str(cr), "continue") == 2
    finally:
        supervisor.release_lock(lock)


def test_resume_emits_cooperative_banner_on_stderr(tmp_path, capsys):
    cr = setup_control(tmp_path, FAKE)  # pause mode, cooperative tier
    assert supervisor.run(str(cr), None) == 10
    capsys.readouterr()  # clear
    # M36b: H2 pauses before ship; a second resume seals. The cooperative banner
    # is re-emitted on every resume (isolation re-probed each time).
    assert supervisor.resume(str(cr), "continue") == 10  # before-ship pause
    assert supervisor.resume(str(cr), "continue") == 0   # seals
    err = capsys.readouterr().err
    assert "COOPERATIVE MODE" in err


def test_resume_manifest_preserves_snapshot_sha256(tmp_path):
    # a project-src run yields a non-None snapshot hash that must survive resume
    src = tmp_path / "proj"
    src.mkdir()
    (src / "seed.txt").write_text("hi", encoding="utf-8")
    cr = setup_control(tmp_path, FAKE)
    assert supervisor.run(str(cr), str(src)) == 10       # paused after iter 1
    # M36b: converge pauses before ship; a second resume seals.
    assert supervisor.resume(str(cr), "continue") == 10  # before-ship pause
    assert supervisor.resume(str(cr), "continue") == 0   # seals
    run_id = os.listdir(cr / "runs")[0]
    manifest = json.loads((cr / "runs" / run_id / "manifest.json").read_text())
    # find the SNAPSHOT journal value and confirm the manifest matches (not None)
    entries = [json.loads(l) for l in (cr / "runs" / run_id / "journal.jsonl").read_text().splitlines()]
    snap = next(e["data"]["snapshot_sha256"] for e in entries if e["state"] == "SNAPSHOT")
    assert snap is not None
    assert manifest["snapshot_sha256"] == snap


def test_resume_abort_manifest_has_final_exam(tmp_path):
    cr = setup_control(tmp_path, FAKE)  # pause mode
    assert supervisor.run(str(cr), None) == 10
    assert supervisor.resume(str(cr), "abort") == 2
    run_id = os.listdir(cr / "runs")[0]
    manifest = json.loads((cr / "runs" / run_id / "manifest.json").read_text())
    assert manifest["final_exam"] == {"ran": False, "passed": None, "count": 0}


def test_resume_accept_manifest_has_final_exam(tmp_path):
    cr = setup_control(tmp_path, FAKE)  # pause mode
    assert supervisor.run(str(cr), None) == 10
    assert supervisor.resume(str(cr), "accept") == 0
    run_id = os.listdir(cr / "runs")[0]
    manifest = json.loads((cr / "runs" / run_id / "manifest.json").read_text())
    assert manifest["final_exam"] == {"ran": False, "passed": None, "count": 0}
