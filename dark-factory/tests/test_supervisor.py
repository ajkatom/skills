import json
import os

import pytest

import supervisor

HERE = os.path.dirname(os.path.abspath(__file__))
FAKE = os.path.join(HERE, "fixtures", "fake_builder")
STUBBORN = os.path.join(HERE, "fixtures", "fake_builder_stubborn")
MARKER = "HOLDOUT-MARKER-93e1"

TOY_SPEC = """# greet CLI
Create an executable python file `greet.py` in the workspace root.
- `python3 greet.py <name>` prints exactly `Hello, <name>!` and exits 0.
- `python3 greet.py` with no arguments prints `usage: greet.py <name>` to stderr and exits 2.
"""


def scenario(sid, bid, run, then, title):
    return {
        "ir_version": "0.1", "id": sid, "behavior_id": bid,
        "title": title, "given": f"{MARKER} workspace has greet.py",
        "when": {"run": run, "timeout_s": 10}, "then": then,
    }


def setup_control(tmp_path, adapter, max_iterations=5):
    cr = tmp_path / "control"
    (cr / "scenarios").mkdir(parents=True)
    (cr / "config.json").write_text(json.dumps({
        "config_version": "0.1", "autonomy": 4, "assurance": "cooperative",
        "feedback": "ids", "max_iterations": max_iterations,
        "workspace_root": str(tmp_path / "ws"),
        "roles": {"builder": {"adapter": adapter, "timeout_s": 30}},
        "budget": {"billing": "subscription"},
    }), encoding="utf-8")
    (cr / "spec.md").write_text(TOY_SPEC, encoding="utf-8")
    scs = [
        scenario("BHV-001-S1", "BHV-001", ["python3", "greet.py", "World"],
                 {"exit_code": 0, "stdout_equals": "Hello, World!"},
                 f"{MARKER} greets World"),
        scenario("BHV-001-S2", "BHV-001", ["python3", "greet.py", "Alon"],
                 {"exit_code": 0, "stdout_equals": "Hello, Alon!"},
                 f"{MARKER} greets Alon"),
        scenario("BHV-002-S1", "BHV-002", ["python3", "greet.py"],
                 {"exit_code": 2, "stderr_contains": "usage:"},
                 f"{MARKER} usage error"),
    ]
    for i, sc in enumerate(scs):
        (cr / "scenarios" / f"s{i}.json").write_text(json.dumps(sc), encoding="utf-8")
    return cr


def read_journal(cr):
    runs = os.listdir(cr / "runs")
    assert len(runs) == 1
    lines = (cr / "runs" / runs[0] / "journal.jsonl").read_text(encoding="utf-8")
    return [json.loads(l) for l in lines.strip().splitlines()], runs[0]


def test_converging_run_exits_zero_and_journals(tmp_path):
    cr = setup_control(tmp_path, FAKE)
    rc = supervisor.run(str(cr), None)
    assert rc == 0
    entries, _ = read_journal(cr)
    states = [e["state"] for e in entries]
    assert states[0] == "INIT" and states[1] == "SNAPSHOT"
    assert "CONVERGED" in states and states[-1] == "COMPLETE_UNQUALIFIED"
    # two iterations: buggy then fixed
    assert states.count("BUILD") == 2 and states.count("FEEDBACK") == 1


def test_stubborn_run_hits_cap_with_exit_3(tmp_path):
    cr = setup_control(tmp_path, STUBBORN, max_iterations=2)
    rc = supervisor.run(str(cr), None)
    assert rc == 3
    entries, _ = read_journal(cr)
    states = [e["state"] for e in entries]
    assert states[-1] == "CAP_REACHED" and states.count("BUILD") == 2
    # cap message names failing behaviors, not scenario content
    cap = entries[-1]["data"]
    assert cap["failing_behaviors"] == ["BHV-001"]


def test_lock_prevents_concurrent_runs(tmp_path):
    cr = setup_control(tmp_path, FAKE)
    lock = supervisor.acquire_lock(str(cr))
    try:
        with pytest.raises(supervisor.LockError):
            supervisor.acquire_lock(str(cr))
    finally:
        supervisor.release_lock(lock)
    # released -> can acquire again
    supervisor.release_lock(supervisor.acquire_lock(str(cr)))


def test_stale_lock_is_reclaimed(tmp_path):
    cr = setup_control(tmp_path, FAKE)
    cr_lock = cr / ".lock"
    cr_lock.write_text("999999999", encoding="utf-8")  # dead pid
    lock = supervisor.acquire_lock(str(cr))
    supervisor.release_lock(lock)


def test_adapter_hard_failure_aborts_with_exit_2(tmp_path):
    cr = setup_control(tmp_path, "/bin/false")  # exits nonzero, no protocol output
    rc = supervisor.run(str(cr), None)
    assert rc == 2
    entries, _ = read_journal(cr)
    assert entries[-1]["state"] == "ABORTED_BUILD_ERROR"


def test_prompt_contains_spec_and_feedback_but_never_scenarios(tmp_path):
    cr = setup_control(tmp_path, FAKE)
    supervisor.run(str(cr), None)
    _, run_id = read_journal(cr)
    run_dir = cr / "runs" / run_id
    p1 = (run_dir / "prompt_iter_1.md").read_text(encoding="utf-8")
    p2 = (run_dir / "prompt_iter_2.md").read_text(encoding="utf-8")
    assert "greet.py" in p1 and MARKER not in p1
    assert "BHV-001" in p2 and MARKER not in p2  # iteration 2 carries ID feedback
    assert "Hello, <name>!" in p1  # spec text is fine — it is SHARED


def test_live_pid_lock_is_not_reclaimed(tmp_path):
    cr = setup_control(tmp_path, FAKE)
    cr_lock = cr / ".lock"
    cr_lock.write_text(str(os.getpid()), encoding="utf-8")  # this process — alive
    with pytest.raises(supervisor.LockError):
        supervisor.acquire_lock(str(cr))


def test_run_on_locked_control_root_exits_2(tmp_path):
    cr = setup_control(tmp_path, FAKE)
    lock = supervisor.acquire_lock(str(cr))
    try:
        assert supervisor.run(str(cr), None) == 2
    finally:
        supervisor.release_lock(lock)


def test_adapter_missing_status_aborts_with_exit_2(tmp_path):
    bad_adapter = tmp_path / "bad_adapter.py"
    bad_adapter.write_text(
        "#!/usr/bin/env python3\n"
        "import json\n"
        "print(json.dumps({\"adapter_protocol\": \"0.1\"}))\n",
        encoding="utf-8",
    )
    os.chmod(str(bad_adapter), 0o755)
    cr = setup_control(tmp_path, str(bad_adapter))
    rc = supervisor.run(str(cr), None)
    assert rc == 2
    entries, _ = read_journal(cr)
    assert entries[-1]["state"] == "ABORTED_BUILD_ERROR"
