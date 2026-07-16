import json
import os

import supervisor
from test_supervisor import FAKE, setup_control, read_journal, terminal_state

HERE = os.path.dirname(os.path.abspath(__file__))
FAKE_FINAL = os.path.join(HERE, "fixtures", "fake_builder_final")
FINAL_MARKER = "FINAL-HOLDOUT-7f2a"


def add_final_scenario(cr, sid, bid, run, then, title):
    """Author a sealed FINAL-cohort scenario into an existing control root."""
    sc = {
        "ir_version": "0.1", "id": sid, "behavior_id": bid, "cohort": "final",
        "title": title, "given": f"{FINAL_MARKER} sealed exam — never shown to the builder",
        "when": {"run": run, "timeout_s": 10}, "then": then,
    }
    existing = list((cr / "scenarios").glob("final*.json"))
    path = cr / "scenarios" / f"final{len(existing)}.json"
    path.write_text(json.dumps(sc), encoding="utf-8")


def _run_dir_and_workspace(cr, run_id, tmp_path):
    run_dir = cr / "runs" / run_id
    ws = tmp_path / "ws" / run_id
    return run_dir, ws


def test_dev_converges_then_final_passes_qualified_or_complete(tmp_path):
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")
    add_final_scenario(
        cr, "BHV-901-S1", "BHV-901",
        ["python3", "greet.py", "Zephyr"],
        {"exit_code": 0, "stdout_equals": "Hello, Zephyr!"},
        f"{FINAL_MARKER} greets Zephyr",
    )
    rc = supervisor.run(str(cr), None)
    assert rc == 0

    entries, run_id = read_journal(cr)
    states = [e["state"] for e in entries]
    assert "FINAL_EXAM" in states
    fe_entry = next(e for e in entries if e["state"] == "FINAL_EXAM")
    assert fe_entry["data"]["ran"] is True
    assert fe_entry["data"]["passing"] == 1 and fe_entry["data"]["total"] == 1
    assert terminal_state(entries)["state"] == "CONVERGED"

    run_dir, _ = _run_dir_and_workspace(cr, run_id, tmp_path)
    m = json.load(open(run_dir / "manifest.json", encoding="utf-8"))
    assert m["final_exam"] == {"ran": True, "passed": True, "count": 1}
    assert m["outcome"] == "COMPLETE_UNQUALIFIED"  # cooperative tier
    assert os.path.exists(run_dir / "final_exam_report.json")


def test_final_failure_is_terminal_and_not_fed_back(tmp_path):
    cr = setup_control(tmp_path, FAKE_FINAL, checkpoint="auto")
    add_final_scenario(
        cr, "BHV-901-S1", "BHV-901",
        ["python3", "greet.py", "Zephyr"],
        # the corrected greet.py prints "Hello, Zephyr!" — one "!" short.
        {"exit_code": 0, "stdout_equals": "Hello, Zephyr!!!"},
        f"{FINAL_MARKER} greets Zephyr loudly",
    )
    rc = supervisor.run(str(cr), None)
    assert rc == 3

    entries, run_id = read_journal(cr)
    states = [e["state"] for e in entries]
    assert terminal_state(entries)["state"] == "FINAL_EXAM_FAILED"
    failed_entry = terminal_state(entries)
    assert failed_entry["data"]["failing"] == ["BHV-901"]
    # dev did converge before the sealed exam ran
    assert "CONVERGED" not in states  # CONVERGED is only journaled on true success
    assert any(e["state"] == "FINAL_EXAM" for e in entries)

    run_dir, ws = _run_dir_and_workspace(cr, run_id, tmp_path)
    m = json.load(open(run_dir / "manifest.json", encoding="utf-8"))
    assert m["outcome"] == "FINAL_EXAM_FAILED"
    assert m["qualified"] is False
    assert m["final_exam"] == {"ran": True, "passed": False, "count": 1}

    # --- BARRIER: the sealed final cohort's content/id must never cross back ---
    for name in os.listdir(run_dir):
        if name.startswith("prompt_iter_") or name.startswith("feedback_iter_"):
            text = (run_dir / name).read_text(encoding="utf-8")
            assert FINAL_MARKER not in text, f"final marker leaked into {name}"
            assert "BHV-901" not in text, f"final behavior_id leaked into {name}"
    ws_feedback = ws / "feedback.json"
    if ws_feedback.exists():
        text = ws_feedback.read_text(encoding="utf-8")
        assert FINAL_MARKER not in text
        assert "BHV-901" not in text
    ws_prompt = ws / "DARK_FACTORY_PROMPT.md"
    if ws_prompt.exists():
        text = ws_prompt.read_text(encoding="utf-8")
        assert FINAL_MARKER not in text
        assert "BHV-901" not in text


def test_no_final_cohort_back_compat(tmp_path, capsys):
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")  # no final scenarios authored
    rc = supervisor.run(str(cr), None)
    assert rc == 0

    captured = capsys.readouterr()
    assert "no sealed final exam administered" in captured.out

    entries, run_id = read_journal(cr)
    fe_entry = next(e for e in entries if e["state"] == "FINAL_EXAM")
    assert fe_entry["data"]["ran"] is False

    run_dir, _ = _run_dir_and_workspace(cr, run_id, tmp_path)
    m = json.load(open(run_dir / "manifest.json", encoding="utf-8"))
    assert m["final_exam"] == {"ran": False, "passed": None, "count": 0}
