"""M36a Task 3: the versioned, phase-aware, hash-chained FSM checkpoint.
Chain builds on a pause + validates on resume; a corrupted entry refuses with
FSM_CHAIN_CORRUPT (exit 2); a pre-M36a 0.1 state resumes via the no-chain
back-compat path (FSM_CHAIN_ABSENT_LEGACY)."""
import json
import os

import supervisor
from test_supervisor import FAKE, MARKER, scenario, setup_control, read_journal


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


# ---------------------------------------------------------------------------
# RA-05/M45: the run-start scenario bundle is SEALED (into the FSM chain
# genesis + state.json) and ENFORCED on resume. Editing the hidden acceptance
# criteria between pause and resume is refused fail-closed
# (SCENARIO_BUNDLE_CHANGED, exit 2); an UNCHANGED bundle resumes normally.
# ---------------------------------------------------------------------------

def test_unchanged_bundle_resumes_and_seal_verified(tmp_path):
    # The primary false-positive guard: a normal pause/resume with the SAME
    # scenario files must resume byte-compatibly. `_scenario_set_hash` is
    # computed identically at run-start and resume (same control_root/scenarios
    # dir; the generated-scenarios dir participates in NEITHER), so the seal
    # matches and the run proceeds.
    cr = setup_control(tmp_path, FAKE)
    assert supervisor.run(str(cr), None) == 10
    assert supervisor.resume(str(cr), "continue") == 10  # converge -> AWAIT_SHIP
    st = _states(cr)
    assert "SCENARIO_BUNDLE_VERIFIED" in st
    assert "SCENARIO_BUNDLE_CHANGED" not in st
    # and it seals all the way through, unaffected.
    assert supervisor.resume(str(cr), "continue") == 0
    assert _states(cr)[-1] == "CONVERGED"


def test_dev_cohort_scenario_edit_between_pause_and_resume_refused(tmp_path):
    # A dev-cohort (builder-visible) scenario edited across the pause: the
    # sealed run-start hash no longer matches the live control root -> refuse.
    cr = setup_control(tmp_path, FAKE)  # all scenarios default to cohort "dev"
    assert supervisor.run(str(cr), None) == 10
    run_dir = cr / "runs" / os.listdir(cr / "runs")[0]

    p = cr / "scenarios" / "s0.json"
    sc = json.loads(p.read_text())
    sc["then"]["stdout_equals"] = "Hello, Mars!"   # silently move the goalposts
    p.write_text(json.dumps(sc))

    assert supervisor.resume(str(cr), "continue") == 2   # fail-closed
    st = _states(cr)
    assert "SCENARIO_BUNDLE_CHANGED" in st
    assert st[-1] == "SCENARIO_BUNDLE_CHANGED"
    # refusal is BEFORE any build/seal -- the paused state is untouched.
    assert not (run_dir / "manifest.json").exists()


def test_final_cohort_scenario_edit_between_pause_and_resume_refused(tmp_path):
    # The critical case: the HIDDEN holdout (cohort "final", never shown to the
    # builder) edited across the pause. `_scenario_set_hash` covers EVERY .json
    # in the scenarios dir regardless of cohort, so a final-cohort edit is
    # caught exactly like a dev-cohort one -- the acceptance criteria cannot be
    # swapped after the run started.
    cr = setup_control(tmp_path, FAKE)
    # Mark one scenario as the hidden final holdout before the run starts.
    fp = cr / "scenarios" / "s2.json"
    fsc = json.loads(fp.read_text())
    fsc["cohort"] = "final"
    fp.write_text(json.dumps(fsc))

    assert supervisor.run(str(cr), None) == 10
    run_dir = cr / "runs" / os.listdir(cr / "runs")[0]

    # Now tamper with the sealed final-cohort criteria across the pause.
    fsc = json.loads(fp.read_text())
    fsc["then"]["stderr_contains"] = "TOTALLY-DIFFERENT-EXPECTATION"
    fp.write_text(json.dumps(fsc))

    assert supervisor.resume(str(cr), "continue") == 2
    st = _states(cr)
    assert "SCENARIO_BUNDLE_CHANGED" in st
    assert st[-1] == "SCENARIO_BUNDLE_CHANGED"
    assert not (run_dir / "manifest.json").exists()


def test_added_scenario_file_between_pause_and_resume_refused(tmp_path):
    # Not only edits: ADDING a scenario file to the control root across the
    # pause also changes the sealed set -> refuse (an operator can't slip an
    # easier criterion in on resume).
    cr = setup_control(tmp_path, FAKE)
    assert supervisor.run(str(cr), None) == 10
    (cr / "scenarios" / "s_extra.json").write_text(json.dumps(
        scenario("BHV-003-S1", "BHV-003", ["python3", "greet.py", "Extra"],
                 {"exit_code": 0, "stdout_equals": "Hello, Extra!"},
                 f"{MARKER} extra")))
    assert supervisor.resume(str(cr), "continue") == 2
    assert "SCENARIO_BUNDLE_CHANGED" in _states(cr)


def _strip_run_start_hash_records(cr, run_dir):
    """Remove ALL THREE run-start scenario-set hash records: the chain, the
    state.json field (downgraded to 0.1), and the journal INIT event's
    scenario_set_sha256 -- what a genuinely pre-seal run looks like OR what a
    same-user actor must do to force the unenforced legacy path."""
    state = json.loads((run_dir / "state.json").read_text())
    for k in ("phase", "fsm_chain_head", "build_approved_through", "scenario_set_sha256"):
        state.pop(k, None)
    state["state_version"] = "0.1"
    (run_dir / "state.json").write_text(json.dumps(state))
    (run_dir / "fsm_chain.jsonl").unlink()
    # Strip the journal INIT event's run-start hash (the third record).
    jpath = run_dir / "journal.jsonl"
    out = []
    for line in jpath.read_text().splitlines():
        if not line.strip():
            continue
        e = json.loads(line)
        if e.get("state") == "INIT":
            e.get("data", {}).pop("scenario_set_sha256", None)
        out.append(json.dumps(e))
    jpath.write_text("\n".join(out) + "\n")


def test_journal_init_fallback_catches_edit_when_chain_and_state_field_gone(tmp_path):
    # R1: a POST-M45 run whose state.json is downgraded to 0.1 and whose chain +
    # state.json field are deleted -- but the journal INIT record is intact --
    # STILL enforces the seal via the journal fallback. An edited bundle is
    # refused (previously this forced the unenforced UNSEALED_LEGACY path).
    cr = setup_control(tmp_path, FAKE)
    assert supervisor.run(str(cr), None) == 10
    run_dir = cr / "runs" / os.listdir(cr / "runs")[0]
    state = json.loads((run_dir / "state.json").read_text())
    for k in ("phase", "fsm_chain_head", "build_approved_through", "scenario_set_sha256"):
        state.pop(k, None)
    state["state_version"] = "0.1"
    (run_dir / "state.json").write_text(json.dumps(state))
    (run_dir / "fsm_chain.jsonl").unlink()
    # journal INIT deliberately left intact -> its scenario_set_sha256 is the
    # surviving run-start record.

    p = cr / "scenarios" / "s0.json"
    sc = json.loads(p.read_text())
    sc["then"]["stdout_equals"] = "Hello, Pluto!"
    p.write_text(json.dumps(sc))

    assert supervisor.resume(str(cr), "continue") == 2
    st = _states(cr)
    assert "SCENARIO_BUNDLE_CHANGED" in st
    assert "SCENARIO_BUNDLE_UNSEALED_LEGACY" not in st


def test_truly_pre_seal_state_no_records_anywhere_unsealed_legacy(tmp_path):
    # The genuinely-unsealed run: NO run-start hash in the chain, the state.json
    # field, OR the journal INIT event. There is nothing to enforce, so resume
    # journals SCENARIO_BUNDLE_UNSEALED_LEGACY (auditable) and proceeds -- we
    # cannot enforce an immutability that was never established.
    cr = setup_control(tmp_path, FAKE)
    assert supervisor.run(str(cr), None) == 10
    run_dir = cr / "runs" / os.listdir(cr / "runs")[0]
    _strip_run_start_hash_records(cr, run_dir)

    assert supervisor.resume(str(cr), "continue") == 10  # legacy -> converge -> AWAIT_SHIP
    st = _states(cr)
    assert "SCENARIO_BUNDLE_UNSEALED_LEGACY" in st
    assert "SCENARIO_BUNDLE_CHANGED" not in st


def test_legacy_state_with_persisted_field_still_enforces_edit(tmp_path):
    # A 0.1-downgraded state that RETAINS the additive scenario_set_sha256
    # field (a run paused by M45+ code but whose chain is unavailable) still
    # enforces the seal via that field: an edit is caught even without a chain.
    cr = setup_control(tmp_path, FAKE)
    assert supervisor.run(str(cr), None) == 10
    run_dir = cr / "runs" / os.listdir(cr / "runs")[0]
    state = json.loads((run_dir / "state.json").read_text())
    for k in ("phase", "fsm_chain_head", "build_approved_through"):
        state.pop(k, None)
    state["state_version"] = "0.1"          # keep scenario_set_sha256
    (run_dir / "state.json").write_text(json.dumps(state))
    (run_dir / "fsm_chain.jsonl").unlink()

    p = cr / "scenarios" / "s1.json"
    sc = json.loads(p.read_text())
    sc["then"]["stdout_equals"] = "changed"
    p.write_text(json.dumps(sc))

    assert supervisor.resume(str(cr), "continue") == 2
    assert "SCENARIO_BUNDLE_CHANGED" in _states(cr)
