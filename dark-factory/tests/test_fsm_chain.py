"""M36a Task 3: the versioned, phase-aware, hash-chained FSM checkpoint.
Chain builds on a pause + validates on resume; a corrupted entry refuses with
FSM_CHAIN_CORRUPT (exit 2); a pre-M36a 0.1 state resumes via the no-chain
back-compat path (FSM_CHAIN_ABSENT_LEGACY)."""
import json
import os

import supervisor
from test_supervisor import FAKE, setup_control, read_journal


def _states(cr):
    entries, _ = read_journal(cr)
    return [e["state"] for e in entries]


def test_chain_entry_helpers_roundtrip(tmp_path):
    rd = tmp_path / "runs" / "r1"
    rd.mkdir(parents=True)
    assert supervisor._fsm_chain_head(str(rd)) is None
    h0 = supervisor._fsm_chain_append(str(rd), "AWAIT_VERIFY_1", "scenhash", None)
    h1 = supervisor._fsm_chain_append(str(rd), "AWAIT_BUILD_2", "scenhash", "objid")
    assert h0 != h1
    assert supervisor._fsm_chain_head(str(rd)) == h1
    ok, detail = supervisor._validate_fsm_chain(str(rd), h1)
    assert ok, detail
    # wrong expected head -> not ok
    ok, _ = supervisor._validate_fsm_chain(str(rd), h0)
    assert not ok


def test_chain_built_on_pause_and_verified_on_resume(tmp_path):
    cr = setup_control(tmp_path, FAKE)  # H2 default -> pauses after verify 1
    assert supervisor.run(str(cr), None) == 10
    run_id = os.listdir(cr / "runs")[0]
    run_dir = cr / "runs" / run_id
    chain = run_dir / "fsm_chain.jsonl"
    assert chain.exists()
    lines = [json.loads(l) for l in chain.read_text().splitlines()]
    assert len(lines) == 1
    assert lines[0]["phase"] == "AWAIT_VERIFY_1"
    assert lines[0]["seq"] == 0 and lines[0]["prev_chain"] is None
    # state records the head; every entry binds the scenario-set hash.
    state = json.loads((run_dir / "state.json").read_text())
    assert state["state_version"] == "0.2"
    assert state["fsm_chain_head"] == lines[0]["entry_hash"]
    assert lines[0]["bound_ids"]["scenario_set_sha256"]

    # resume validates the chain (FSM_CHAIN_VERIFIED journaled), converges, and
    # M36b appends an AWAIT_SHIP transition (the chain EXTENDS, not breaks).
    assert supervisor.resume(str(cr), "continue") == 10  # converge -> AWAIT_SHIP
    lines2 = [json.loads(l) for l in chain.read_text().splitlines()]
    assert lines2[-1]["phase"] == "AWAIT_SHIP"
    assert lines2[-1]["seq"] == len(lines2) - 1 and lines2[-1]["prev_chain"] == lines2[-2]["entry_hash"]
    # the AWAIT_SHIP transition binds the frozen artifact object_id.
    assert lines2[-1]["bound_ids"]["artifact_object_id"]
    # a second resume re-validates the extended chain and seals (no rebuild).
    assert supervisor.resume(str(cr), "continue") == 0
    st = _states(cr)
    assert "FSM_CHAIN_VERIFIED" in st
    assert "SHIP_RESUME" in st
    assert st[-1] == "CONVERGED"


def test_corrupted_chain_refuses_resume(tmp_path):
    cr = setup_control(tmp_path, FAKE)
    assert supervisor.run(str(cr), None) == 10
    run_id = os.listdir(cr / "runs")[0]
    run_dir = cr / "runs" / run_id
    chain = run_dir / "fsm_chain.jsonl"
    lines = chain.read_text().splitlines()
    e = json.loads(lines[0])
    e["phase"] = "TAMPERED"            # entry_hash no longer matches
    lines[0] = json.dumps(e)
    chain.write_text("\n".join(lines) + "\n")

    assert supervisor.resume(str(cr), "continue") == 2  # fail-closed
    st = _states(cr)
    assert "FSM_CHAIN_CORRUPT" in st
    assert st[-1] == "FSM_CHAIN_CORRUPT"
    # refusal is BEFORE any seal -- the paused state is untouched, no manifest.
    assert (run_dir / "state.json").exists()
    assert not (run_dir / "manifest.json").exists()


def test_malformed_chain_line_refuses_resume_with_exit_2(tmp_path):
    # The most likely accidental corruption: a truncated/half-written JSON line
    # (crash or disk-full mid-append). It must route to FSM_CHAIN_CORRUPT +
    # exit 2, NOT escape as an uncaught JSONDecodeError -> traceback/exit 1.
    cr = setup_control(tmp_path, FAKE)
    assert supervisor.run(str(cr), None) == 10
    run_dir = cr / "runs" / os.listdir(cr / "runs")[0]
    chain = run_dir / "fsm_chain.jsonl"
    lines = chain.read_text().splitlines()
    lines[-1] = lines[-1][: len(lines[-1]) // 2]   # truncate the last line's JSON
    chain.write_text("\n".join(lines) + "\n")

    assert supervisor.resume(str(cr), "continue") == 2   # fail-closed, not a traceback
    st = _states(cr)
    assert "FSM_CHAIN_CORRUPT" in st
    assert st[-1] == "FSM_CHAIN_CORRUPT"
    assert not (run_dir / "manifest.json").exists()


def test_truncated_chain_refuses_resume(tmp_path):
    cr = setup_control(tmp_path, FAKE)
    assert supervisor.run(str(cr), None) == 10
    run_dir = cr / "runs" / os.listdir(cr / "runs")[0]
    # Delete the chain file but keep state.json's recorded (non-None) head:
    # the recorded head references a chain that is gone -> corruption.
    (run_dir / "fsm_chain.jsonl").unlink()
    assert supervisor.resume(str(cr), "continue") == 2
    assert "FSM_CHAIN_CORRUPT" in _states(cr)


def test_legacy_0_1_state_resumes_without_chain(tmp_path):
    cr = setup_control(tmp_path, FAKE)
    assert supervisor.run(str(cr), None) == 10
    run_dir = cr / "runs" / os.listdir(cr / "runs")[0]
    # Downgrade the paused state to a pre-M36a 0.1 shape: no FSM fields, no
    # chain file -- exactly what an old paused run looks like.
    state = json.loads((run_dir / "state.json").read_text())
    for k in ("phase", "fsm_chain_head", "build_approved_through"):
        state.pop(k, None)
    state["state_version"] = "0.1"
    (run_dir / "state.json").write_text(json.dumps(state))
    (run_dir / "fsm_chain.jsonl").unlink()

    # Legacy path resumes + rebuilds; M36b then pauses before ship (a fresh 0.2
    # AWAIT_SHIP checkpoint), and a second resume seals it.
    assert supervisor.resume(str(cr), "continue") == 10  # legacy path -> converge -> AWAIT_SHIP
    st = _states(cr)
    assert "FSM_CHAIN_ABSENT_LEGACY" in st
    assert "FSM_CHAIN_CORRUPT" not in st
    assert supervisor.resume(str(cr), "continue") == 0   # seal-reentry (now a 0.2 chain)
    st = _states(cr)
    assert st[-1] == "CONVERGED"
