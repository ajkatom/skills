"""M61 (Codex R6): attempt-aware + rollback-aware ship crash recovery.

  * DF-R6-01 — the idempotency_key is STABLE per (run_id, action, index), so a
    reconciled retry reuses it. Matching results to intents by KEY let an OLD
    `reconciled_unknown` result resolve a NEW intent, and a second crash then
    silently re-fired a production action with no fresh reconcile decision.
    Resolution is now per-ATTEMPT (`attempt_id`, fresh per dispatch).
  * DF-R6-02 — `already_done` counted every historical `ok` as permanently
    applied, ignoring a later SHIP_ROLLED_BACK: re-entry skipped an action that
    was actually undone and could seal SHIPPED with that effect absent. The
    applied set is now computed by an ordered pass that subtracts rollbacks, and
    a dangling SHIP_ROLLBACK_INTENT is an explicit unknown outcome.
  * DF-R6-09 — one SHIP_EVIDENCE_PENDING event sealed TWO records/anchors/
    off-box versions; it now seals exactly once.
"""
import json
import os
import shutil
import sys

import pytest

import df_ship
import supervisor
from test_ship import build_sealed_run, _base_config
from test_m49_ship_integrity import _counter_action


def _write_journal(run_dir, events):
    with open(os.path.join(run_dir, "ship_journal.jsonl"), "w", encoding="utf-8") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")


def _ev(state, **data):
    return {"ts": "2026-07-20T00:00:00Z", "state": state, "data": data}


# ---------------------------------------------------------------------------
# DF-R6-01 — attempt-aware forward resolution
# ---------------------------------------------------------------------------

def test_old_reconciled_result_does_not_resolve_a_new_retry_intent(tmp_path):
    # The auditor's exact trace: intent K → reconciled_unknown K → new intent K.
    rd = str(tmp_path); idk = df_ship.idempotency_key("run1", "deploy", 0)
    _write_journal(rd, [
        _ev("SHIP_ACTION_INTENT", action="deploy", index=0, idempotency_key=idk,
            attempt_id="a1"),
        _ev("SHIP_ACTION_RESULT", action="deploy", index=0, idempotency_key=idk,
            attempt_id="a1", status="reconciled_unknown"),
        _ev("SHIP_ACTION_INTENT", action="deploy", index=0, idempotency_key=idk,
            attempt_id="a2"),
    ])
    unresolved = supervisor._unresolved_ship_action(rd)
    assert unresolved is not None, "the retry's intent must still be UNRESOLVED"
    assert unresolved["attempt_id"] == "a2"


def test_matching_result_for_the_same_attempt_does_resolve(tmp_path):
    rd = str(tmp_path); idk = df_ship.idempotency_key("run1", "deploy", 0)
    _write_journal(rd, [
        _ev("SHIP_ACTION_INTENT", action="deploy", index=0, idempotency_key=idk,
            attempt_id="a1"),
        _ev("SHIP_ACTION_RESULT", action="deploy", index=0, idempotency_key=idk,
            attempt_id="a1", status="ok"),
    ])
    assert supervisor._unresolved_ship_action(rd) is None
    assert supervisor._ship_completed_actions(rd) == {"deploy"}


def test_two_crashes_after_reconcile_still_refuse_exit_11(tmp_path, monkeypatch):
    # End-to-end: crash → reconcile → crash again must return SHIP_UNKNOWN_OUTCOME
    # again (a fresh human decision), never a silent third dispatch.
    cr = tmp_path / "control"
    deploy, counter = _counter_action(tmp_path)
    cfg, run_dir, oid, rid = build_sealed_run(
        tmp_path, cr, _base_config(tmp_path, "standard", {"actions": [deploy]}), {"a.txt": "v1"})

    # Simulate a crash mid-dispatch: run_actions journals the intent then "crashes".
    def _crash_after_intent(actions, ship_ws, **kw):
        j = kw["journal"]
        j.write("SHIP_ACTION_INTENT", action="deploy", index=0,
                idempotency_key=df_ship.idempotency_key(kw["run_id"], "deploy", 0),
                attempt_id="crash1", reversible=True, approval_ref=None, toolchain=None)
        raise KeyboardInterrupt("simulated crash before the result")

    monkeypatch.setattr(df_ship, "run_actions", _crash_after_intent)
    with pytest.raises(KeyboardInterrupt):
        supervisor.ship_cmd(str(cr), str(run_dir))

    # 1st re-entry: unknown outcome, exit 11.
    monkeypatch.undo()
    assert supervisor.ship_cmd(str(cr), str(run_dir)) == supervisor.UNKNOWN_OUTCOME
    assert not counter.exists(), "nothing re-ran under a plain continue"

    # Operator reconciles, and the retry ALSO crashes before its result.
    def _crash_after_retry_intent(actions, ship_ws, **kw):
        j = kw["journal"]
        j.write("SHIP_ACTION_INTENT", action="deploy", index=0,
                idempotency_key=df_ship.idempotency_key(kw["run_id"], "deploy", 0),
                attempt_id="crash2", reversible=True, approval_ref=None, toolchain=None)
        raise KeyboardInterrupt("simulated crash on the reconciled retry")

    monkeypatch.setattr(df_ship, "run_actions", _crash_after_retry_intent)
    with pytest.raises(KeyboardInterrupt):
        supervisor.ship_cmd(str(cr), str(run_dir), decision="reconcile")
    monkeypatch.undo()

    # 2nd re-entry: MUST be unknown again (pre-M61 this silently re-dispatched).
    assert supervisor.ship_cmd(str(cr), str(run_dir)) == supervisor.UNKNOWN_OUTCOME
    assert not counter.exists()


# ---------------------------------------------------------------------------
# DF-R6-02 — rollback-aware applied set
# ---------------------------------------------------------------------------

def test_rolled_back_action_is_not_reported_completed(tmp_path):
    # The auditor's exact trace: prepare ok → deploy failed → ROLLED_BACK prepare.
    rd = str(tmp_path)
    _write_journal(rd, [
        _ev("SHIP_ACTION_RESULT", action="prepare", idempotency_key="k1",
            attempt_id="b1", status="ok"),
        _ev("SHIP_ACTION_RESULT", action="deploy", idempotency_key="k2",
            attempt_id="b2", status="failed"),
        _ev("SHIP_ROLLED_BACK", action="prepare", attempt_id="r1"),
    ])
    assert supervisor._ship_completed_actions(rd) == set(), "an UNDONE action is not done"
    # the authenticated set must match the skip set exactly
    assert [f["name"] for f in supervisor._ship_completed_action_facts(rd)] == []


def test_reapplied_after_rollback_is_completed_again(tmp_path):
    rd = str(tmp_path)
    _write_journal(rd, [
        _ev("SHIP_ACTION_RESULT", action="prepare", idempotency_key="k1",
            attempt_id="b1", status="ok"),
        _ev("SHIP_ROLLED_BACK", action="prepare", attempt_id="r1"),
        _ev("SHIP_ACTION_INTENT", action="prepare", index=0, idempotency_key="k1",
            attempt_id="b3", toolchain={"action": "prepare"}, reversible=True,
            approval_ref=None),
        _ev("SHIP_ACTION_RESULT", action="prepare", idempotency_key="k1",
            attempt_id="b3", status="ok"),
    ])
    assert supervisor._ship_completed_actions(rd) == {"prepare"}
    facts = supervisor._ship_completed_action_facts(rd)
    assert len(facts) == 1 and facts[0]["toolchain"] == {"action": "prepare"}


def test_failed_rollback_is_an_unknown_effect_neither_skipped_nor_rerun(tmp_path):
    # Self-review correction: a FAILED rollback proves NOTHING — the effect may
    # still be fully applied. Skipping risks OMISSION; silently re-running risks
    # DUPLICATING a non-idempotent production action. It must be an explicit
    # unknown state requiring an operator decision.
    rd = str(tmp_path)
    _write_journal(rd, [
        _ev("SHIP_ACTION_RESULT", action="prepare", idempotency_key="k1",
            attempt_id="b1", status="ok"),
        _ev("SHIP_ROLLBACK_FAILED", action="prepare", attempt_id="r1", exit=1),
    ])
    st = supervisor._ship_action_recovery_state(rd)
    assert st["unknown_effect"] == {"prepare"}
    assert supervisor._ship_completed_actions(rd) == set(), "not silently skipped"


def test_failed_rollback_refuses_exit_11_until_the_operator_decides(tmp_path, monkeypatch):
    cr = tmp_path / "control"
    prep, prep_counter = _counter_action(tmp_path, name="prepare")
    cfg, run_dir, oid, rid = build_sealed_run(
        tmp_path, cr, _base_config(tmp_path, "standard", {"actions": [prep]}),
        {"a.txt": "v1"})
    # A journal where prepare applied, then its rollback FAILED, then a crash
    # (no terminal record sealed).
    _write_journal(str(run_dir), [
        _ev("SHIP_ACTION_INTENT", action="prepare", index=0,
            idempotency_key=df_ship.idempotency_key(rid, "prepare", 0), attempt_id="b1"),
        _ev("SHIP_ACTION_RESULT", action="prepare", index=0,
            idempotency_key=df_ship.idempotency_key(rid, "prepare", 0),
            attempt_id="b1", status="ok"),
        _ev("SHIP_ROLLBACK_INTENT", action="prepare", attempt_id="r1"),
        _ev("SHIP_ROLLBACK_FAILED", action="prepare", attempt_id="r1", exit=1),
    ])
    assert supervisor.ship_cmd(str(cr), str(run_dir)) == supervisor.UNKNOWN_OUTCOME
    assert not prep_counter.exists(), "must NOT silently re-run a possibly-applied action"
    # abort seals the honest terminal instead of guessing.
    assert supervisor.ship_cmd(str(cr), str(run_dir), decision="abort") == 3
    rec = json.loads((run_dir / "ship_result.json").read_text())
    assert rec["outcome"] == df_ship.SHIP_FAILED
    assert not prep_counter.exists()


def test_successful_rollback_then_rerun_clears_the_unknown_state(tmp_path):
    rd = str(tmp_path)
    _write_journal(rd, [
        _ev("SHIP_ACTION_RESULT", action="prepare", idempotency_key="k1",
            attempt_id="b1", status="ok"),
        _ev("SHIP_ROLLBACK_FAILED", action="prepare", attempt_id="r1", exit=1),
        # operator reconciled; the action re-ran successfully
        _ev("SHIP_ACTION_INTENT", action="prepare", index=0, idempotency_key="k1",
            attempt_id="b2"),
        _ev("SHIP_ACTION_RESULT", action="prepare", idempotency_key="k1",
            attempt_id="b2", status="ok"),
    ])
    st = supervisor._ship_action_recovery_state(rd)
    assert st["unknown_effect"] == set(), "a fresh success resolves the unknown state"
    assert supervisor._ship_completed_actions(rd) == {"prepare"}


def test_dangling_rollback_intent_is_an_unknown_outcome(tmp_path):
    rd = str(tmp_path)
    _write_journal(rd, [
        _ev("SHIP_ACTION_RESULT", action="prepare", idempotency_key="k1",
            attempt_id="c1", status="ok"),
        _ev("SHIP_ROLLBACK_INTENT", action="prepare", attempt_id="r9"),
    ])
    unresolved = supervisor._unresolved_ship_action(rd)
    assert unresolved is not None and unresolved["attempt_id"] == "r9"
    st = supervisor._ship_action_recovery_state(rd)
    assert st["unresolved_rollback"]["attempt_id"] == "r9"
    assert st["unresolved_forward"] is None


# ---------------------------------------------------------------------------
# Legacy (pre-M61) journals still recover correctly.
# ---------------------------------------------------------------------------

def test_legacy_journal_without_attempt_id_still_resolves_by_key(tmp_path):
    rd = str(tmp_path)
    _write_journal(rd, [
        _ev("SHIP_ACTION_INTENT", action="deploy", index=0, idempotency_key="kk"),
        _ev("SHIP_ACTION_RESULT", action="deploy", index=0, idempotency_key="kk",
            status="ok"),
    ])
    assert supervisor._unresolved_ship_action(rd) is None
    assert supervisor._ship_completed_actions(rd) == {"deploy"}


def test_legacy_dangling_intent_is_still_unresolved(tmp_path):
    rd = str(tmp_path)
    _write_journal(rd, [
        _ev("SHIP_ACTION_INTENT", action="deploy", index=0, idempotency_key="kk"),
    ])
    assert supervisor._unresolved_ship_action(rd) is not None


# ---------------------------------------------------------------------------
# DF-R6-09 — one event, one seal
# ---------------------------------------------------------------------------

def test_evidence_pending_seals_exactly_once(tmp_path, monkeypatch):
    from test_m56b_anchor_recovery import _fail_anchor_for, _named_counter_action
    cr = tmp_path / "control"
    prep, prep_counter = _named_counter_action(tmp_path, "prep")
    cfg, run_dir, oid, rid = build_sealed_run(
        tmp_path, cr,
        _base_config(tmp_path, "standard", {"actions": [prep]}, signed=True),
        {"a.txt": "v1"})
    restore = _fail_anchor_for(monkeypatch, "ship-action-ok", action_name="prep")
    rc = supervisor.ship_cmd(str(cr), str(run_dir))
    assert rc == supervisor.SHIP_EVIDENCE_PENDING_EXIT
    restore()

    events = [json.loads(l) for l in
              (run_dir / "ship_journal.jsonl").read_text(encoding="utf-8").strip().splitlines()]
    terminals = [e for e in events if e["state"] == df_ship.SHIP_EVIDENCE_PENDING]
    assert len(terminals) == 1, f"one event must seal ONE terminal, got {len(terminals)}"


def test_mixed_legacy_and_upgraded_journal_does_not_falsely_resolve(tmp_path):
    # An upgrade mid-run: the pre-M61 intent/result pair carries no attempt_id,
    # the retry's intent does. The LEGACY result must not resolve the new attempt.
    rd = str(tmp_path)
    _write_journal(rd, [
        _ev("SHIP_ACTION_INTENT", action="deploy", index=0, idempotency_key="k"),
        _ev("SHIP_ACTION_RESULT", action="deploy", index=0, idempotency_key="k",
            status="reconciled_unknown"),
        _ev("SHIP_ACTION_INTENT", action="deploy", index=0, idempotency_key="k",
            attempt_id="new1"),
    ])
    unresolved = supervisor._unresolved_ship_action(rd)
    assert unresolved is not None and unresolved["attempt_id"] == "new1"


def test_facts_use_the_reapplied_attempts_intent_not_the_rolled_back_one(tmp_path):
    # A rolled-back-then-reapplied action must authenticate against the toolchain
    # of the attempt that is CURRENTLY applied, never the superseded one.
    rd = str(tmp_path)
    _write_journal(rd, [
        _ev("SHIP_ACTION_INTENT", action="a", index=0, idempotency_key="k",
            attempt_id="x1", toolchain={"sha256": "OLD"}, reversible=True,
            approval_ref=None),
        _ev("SHIP_ACTION_RESULT", action="a", idempotency_key="k", attempt_id="x1",
            status="ok"),
        _ev("SHIP_ROLLED_BACK", action="a", attempt_id="r1"),
        _ev("SHIP_ACTION_INTENT", action="a", index=0, idempotency_key="k",
            attempt_id="x2", toolchain={"sha256": "NEW"}, reversible=True,
            approval_ref=None),
        _ev("SHIP_ACTION_RESULT", action="a", idempotency_key="k", attempt_id="x2",
            status="ok"),
    ])
    facts = supervisor._ship_completed_action_facts(rd)
    assert [f["toolchain"] for f in facts] == [{"sha256": "NEW"}]


def test_stray_rollback_events_do_not_crash_recovery(tmp_path):
    rd = str(tmp_path)
    _write_journal(rd, [
        _ev("SHIP_ROLLED_BACK", action="never-applied"),
        _ev("SHIP_ROLLED_BACK"),  # no action key at all
    ])
    st = supervisor._ship_action_recovery_state(rd)
    assert st["applied"] == {} and st["unknown_effect"] == set()
