import json

import supervisor
from test_supervisor import FAKE, setup_control, read_journal


def _set_budget(cr, budget):
    cfg_path = cr / "config.json"
    cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
    cfg["budget"] = budget
    cfg_path.write_text(json.dumps(cfg), encoding="utf-8")


def _drop_budget(cr):
    cfg_path = cr / "config.json"
    cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
    cfg.pop("budget", None)
    cfg_path.write_text(json.dumps(cfg), encoding="utf-8")


def test_api_budget_pause_and_resume(tmp_path):
    # FAKE needs exactly 2 builder calls to converge (buggy, then fixed-by-feedback).
    # per_call_usd=1.0, max_usd=1.0: call 1 (est_after=1.0) is admitted (not > cap);
    # call 2's admission (est_after=2.0 > 1.0) must pause BEFORE the 2nd call is made.
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")
    _set_budget(cr, {"billing": "api", "per_call_usd": 1.0, "max_usd": 1.0})

    rc = supervisor.run(str(cr), None)
    assert rc == 10

    entries, run_id = read_journal(cr)
    states = [e["state"] for e in entries]
    assert states.count("BUILD") == 1
    assert "BUDGET_PAUSE" in states
    pause = next(e for e in entries if e["state"] == "BUDGET_PAUSE")
    assert pause["data"]["builder_calls"] == 1
    assert pause["data"]["estimated_usd"] == 1.0

    run_dir = cr / "runs" / run_id
    assert not (run_dir / "manifest.json").exists()  # pause is non-terminal
    state = json.loads((run_dir / "state.json").read_text(encoding="utf-8"))
    assert state["builder_calls"] == 1
    assert state["estimated_usd"] == 1.0
    assert state["reason"] == "budget"

    # Raise the cap and resume — must NOT double-count the first (already-spent) call.
    _set_budget(cr, {"billing": "api", "per_call_usd": 1.0, "max_usd": 10.0})
    rc2 = supervisor.resume(str(cr), "continue")
    assert rc2 == 0

    entries2, _ = read_journal(cr)
    states2 = [e["state"] for e in entries2]
    assert states2.count("BUILD") == 2  # 1 before pause + 1 after resume, no double count
    assert "CONVERGED" in states2

    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["outcome"] == "COMPLETE_UNQUALIFIED"
    assert manifest["budget"]["builder_calls"] == 2
    assert manifest["budget"]["estimated_usd"] == 2.0
    assert manifest["budget"]["enforced"] is True


def test_85_percent_alert(tmp_path):
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")
    _set_budget(cr, {"billing": "api", "per_call_usd": 0.85, "max_usd": 1.0, "alert_at": 0.85})

    supervisor.run(str(cr), None)

    entries, _ = read_journal(cr)
    alerts = [e for e in entries if e["state"] == "BUDGET_ALERT"]
    assert len(alerts) == 1  # emitted once, not repeated every iteration
    assert alerts[0]["data"]["estimated_usd"] == 0.85
    assert alerts[0]["data"]["builder_calls"] == 1


def test_subscription_never_pauses(tmp_path):
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")
    _set_budget(cr, {"billing": "subscription"})

    rc = supervisor.run(str(cr), None)
    assert rc == 0

    entries, _ = read_journal(cr)
    states = [e["state"] for e in entries]
    assert "BUDGET_PAUSE" not in states
    assert "CONVERGED" in states


def test_max_calls_hard_cap(tmp_path):
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")
    _set_budget(cr, {"billing": "subscription", "max_calls": 1})

    rc = supervisor.run(str(cr), None)
    assert rc == 10

    entries, run_id = read_journal(cr)
    states = [e["state"] for e in entries]
    assert states.count("BUILD") == 1
    assert "BUDGET_PAUSE" in states
    pause = next(e for e in entries if e["state"] == "BUDGET_PAUSE")
    assert pause["data"]["max_calls"] == 1
    assert pause["data"]["builder_calls"] == 1

    run_dir = cr / "runs" / run_id
    assert not (run_dir / "manifest.json").exists()


def test_no_budget_block_unchanged(tmp_path):
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")
    _drop_budget(cr)

    rc = supervisor.run(str(cr), None)
    assert rc == 0

    entries, run_id = read_journal(cr)
    states = [e["state"] for e in entries]
    assert "BUDGET_PAUSE" not in states
    assert "CONVERGED" in states

    manifest = json.loads((cr / "runs" / run_id / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["budget"]["enforced"] is False
    assert manifest["budget"]["billing"] == "subscription"
