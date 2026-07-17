"""M36b (Part C) e2e tests for the before-ship approval pause (H1/H2) and its
seal-reentry resume. The critical invariant: resuming FROM an AWAIT_SHIP pause
SEALS the already-frozen artifact WITHOUT re-dispatching a builder — proven by
asserting the builder-call count is unchanged across the ship-resume."""
import json
import os

import supervisor
from test_supervisor import FAKE, setup_control


def _states(cr):
    run_id = os.listdir(cr / "runs")[0]
    return [json.loads(l)["state"]
            for l in (cr / "runs" / run_id / "journal.jsonl").read_text().splitlines()]


def _builder_calls(cr):
    return _states(cr).count("BUILD")


def _set_mode(cr, mode):
    p = cr / "config.json"
    cfg = json.loads(p.read_text())
    cfg["intervention_mode"] = mode
    cfg.pop("autonomy", None)
    cfg.pop("checkpoint", None)
    p.write_text(json.dumps(cfg))


def _drive_to_await_ship(cr):
    """Run + resume until the run parks at the AWAIT_SHIP pause. FAKE converges
    on iteration 2, so H2 first pauses after verify 1, then (on resume)
    converges and pauses before ship."""
    assert supervisor.run(str(cr), None) == supervisor.PAUSED     # after-verify pause
    assert supervisor.resume(str(cr), "continue") == supervisor.PAUSED  # converge -> AWAIT_SHIP
    run_id = os.listdir(cr / "runs")[0]
    return run_id


def test_h2_pauses_before_ship_then_continue_seals_without_rebuild(tmp_path):
    cr = setup_control(tmp_path, FAKE)  # default -> H2
    run_id = _drive_to_await_ship(cr)
    run_dir = cr / "runs" / run_id

    # AWAIT_SHIP checkpoint schema: state.json phase + ship_meta, a human review
    # surface, and the frozen artifact bound.
    assert (run_dir / "checkpoint_ship.md").exists()
    state = json.loads((run_dir / "state.json").read_text())
    assert state["phase"] == "AWAIT_SHIP"
    assert state["reason"] == "ship"
    meta = state["ship_meta"]
    assert set(meta) == {"object_id", "artifact_field", "final_exam", "converged_iteration"}
    assert meta["artifact_field"]["object_id"] == meta["object_id"]

    calls_before = _builder_calls(cr)
    assert calls_before == 2  # buggy iter 1 + fixed iter 2

    # Continue: seals WITHOUT re-dispatching a builder.
    assert supervisor.resume(str(cr), "continue") == 0
    calls_after = _builder_calls(cr)
    assert calls_after == calls_before, "ship-resume must NOT re-dispatch a builder"

    st = _states(cr)
    assert "SHIP_RESUME" in st
    assert st[-1] == "CONVERGED"
    assert not (run_dir / "state.json").exists()  # cleared at terminal
    manifest = json.loads((run_dir / "manifest.json").read_text())
    assert manifest["outcome"] == "COMPLETE_UNQUALIFIED"  # cooperative tier
    assert manifest["artifact"]["object_id"] == meta["object_id"]


def test_h1_also_pauses_before_ship(tmp_path):
    cr = setup_control(tmp_path, FAKE)
    _set_mode(cr, "directed")  # H1
    # H1 adds a before-build pause too, so the drive takes an extra resume.
    assert supervisor.run(str(cr), None) == supervisor.PAUSED          # after verify 1
    assert supervisor.resume(str(cr), "continue") == supervisor.PAUSED  # before build 2
    assert supervisor.resume(str(cr), "continue") == supervisor.PAUSED  # converge -> AWAIT_SHIP
    run_id = os.listdir(cr / "runs")[0]
    state = json.loads((cr / "runs" / run_id / "state.json").read_text())
    assert state["phase"] == "AWAIT_SHIP"
    calls_before = _builder_calls(cr)
    assert supervisor.resume(str(cr), "continue") == 0
    assert _builder_calls(cr) == calls_before
    assert _states(cr)[-1] == "CONVERGED"


def test_ship_abort_seals_ship_declined(tmp_path):
    cr = setup_control(tmp_path, FAKE)  # H2
    run_id = _drive_to_await_ship(cr)
    run_dir = cr / "runs" / run_id
    calls_before = _builder_calls(cr)

    assert supervisor.resume(str(cr), "abort") == 2
    assert _builder_calls(cr) == calls_before  # abort never dispatches either

    st = _states(cr)
    assert "SHIP_DECLINED" in st
    assert not (run_dir / "state.json").exists()
    manifest = json.loads((run_dir / "manifest.json").read_text())
    assert manifest["outcome"] == "SHIP_DECLINED"
    assert manifest["qualified"] is False
    # The declined candidate's frozen artifact is still bound (auditable).
    assert manifest["artifact"]["object_id"]


def test_ship_meta_object_id_disagreeing_with_chain_refuses_to_seal(tmp_path):
    # M36b hardening: ship_meta rides in state.json (a non-HMAC store); the
    # AWAIT_SHIP FSM chain head binds the authoritative artifact_object_id. A
    # hand-edited state.json pointing the seal at a different object must be
    # REFUSED fail-closed (exit 2), never sealed.
    cr = setup_control(tmp_path, FAKE)  # H2
    run_id = _drive_to_await_ship(cr)
    run_dir = cr / "runs" / run_id
    calls_before = _builder_calls(cr)

    state = json.loads((run_dir / "state.json").read_text())
    # Substitute a syntactically-valid-but-different object_id in ship_meta only
    # (the FSM chain still binds the ORIGINAL id — resume re-validates the chain,
    # which stays intact, then the cross-check catches the ship_meta divergence).
    state["ship_meta"]["object_id"] = "0" * 64
    (run_dir / "state.json").write_text(json.dumps(state))

    assert supervisor.resume(str(cr), "continue") == 2  # fail-closed refusal
    assert _builder_calls(cr) == calls_before           # never dispatched
    st = _states(cr)
    assert "SHIP_META_MISMATCH" in st
    assert "CONVERGED" not in st                         # never sealed
    assert (run_dir / "state.json").exists()             # still paused, not cleared
    assert not (run_dir / "manifest.json").exists()


def test_h3_and_h4_do_not_pause_before_ship(tmp_path):
    # H3 (guarded/auto): a single run converges straight through, no ship pause.
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")  # -> H3
    assert supervisor.run(str(cr), None) == 0
    st = _states(cr)
    assert st[-1] == "CONVERGED"
    assert "SHIP_RESUME" not in st
    run_id = os.listdir(cr / "runs")[0]
    assert not (cr / "runs" / run_id / "checkpoint_ship.md").exists()
