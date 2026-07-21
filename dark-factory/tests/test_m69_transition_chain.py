"""M69 (Codex R8): DF-R8-01 monotonic authenticated ship-transition chain +
DF-R8-05 per-token-type chain namespaces.

  * DF-R8-01 — the applied-set reducer keys by action NAME, so a genuine, signed
    forward completion COPIED back into the journal after its signed rollback
    silently re-added a rolled-back action: the copy carries a real, anchored
    token and the per-attempt duplicate guard cannot see it (the dict dedupes to
    one fact). Every forward completion and successful rollback now binds a
    monotonic `seq` into its signed token; recovery verifies the seqs are
    contiguous and strictly increasing in journal order (0..N-1). Replay
    (duplicate seq), reorder (out-of-order seqs), and interior deletion (a seq
    gap) are all refused, and a rewritten `seq` yields a token that was never
    anchored → refused.
  * DF-R8-05 — intent / completion / rollback tokens previously shared one chain
    namespace (`{run}.ship-action.`). `_is_no_action_terminal` therefore treated a
    genuine PRE-SPAWN intent (which every dispatched action signs) as proof the
    run shipped, and refused the governed no-action reseal of a real
    materialize-failure / reconcile-abort. The three token types now anchor under
    distinct namespaces (ship-action / ship-action-intent / ship-rollback); only a
    completion or a rollback proves something ran.
"""
import json
import sys

import supervisor
from test_ship import build_sealed_run, _base_config
from test_m49_ship_integrity import _counter_action
from test_m66_attempt_bound import _signed_prep_deploy_run


def _mk(p):
    p.mkdir(parents=True, exist_ok=True)
    return p


def _multi_action_run(tmp_path, names):
    actions = [_counter_action(_mk(tmp_path / n), name=n)[0] for n in names]
    cr = tmp_path / "control"
    cfg, run_dir, oid, rid = build_sealed_run(
        tmp_path, cr, _base_config(tmp_path, "standard", {"actions": actions}, signed=True),
        {"app.txt": "v1"})
    return cr, run_dir, cfg, rid


def _two_reversible_then_fail_run(tmp_path):
    """A signed run: prep1(ok), prep2(ok) — both reversible — then a failing
    deploy → both preps rolled back in reverse → SHIP_FAILED. Returns
    (cr, run_dir, cfg, rid)."""
    import sys as _sys
    p1, _ = _counter_action(_mk(tmp_path / "p1"), name="prep1", reversible=True)
    p2, _ = _counter_action(_mk(tmp_path / "p2"), name="prep2", reversible=True)
    p1["rollback"] = [_sys.executable, p1["run"][1], p1["run"][2]]
    p2["rollback"] = [_sys.executable, p2["run"][1], p2["run"][2]]
    fail = tmp_path / "fail.py"
    fail.write_text("import sys\nsys.exit(1)\n", encoding="utf-8")
    deploy = {"name": "deploy", "run": [_sys.executable, str(fail)],
              "reversible": True, "timeout_s": 30}
    cr = tmp_path / "control"
    cfg, run_dir, oid, rid = build_sealed_run(
        tmp_path, cr,
        _base_config(tmp_path, "standard", {"actions": [p1, p2, deploy]}, signed=True),
        {"app.txt": "v1"})
    return cr, run_dir, cfg, rid


def _read_journal(run_dir):
    return [json.loads(l) for l in
            (run_dir / "ship_journal.jsonl").read_text(encoding="utf-8").splitlines()]


def _write_journal(run_dir, events):
    (run_dir / "ship_journal.jsonl").write_text(
        "".join(json.dumps(e) + "\n" for e in events), encoding="utf-8")


# ---------------------------------------------------------------------------
# DF-R8-01 — ordered monotonic transition chain
# ---------------------------------------------------------------------------

def test_honest_multi_action_run_still_authenticates(tmp_path):
    cr, run_dir, cfg, rid = _multi_action_run(tmp_path, ["a", "b"])
    assert supervisor.ship_cmd(str(cr), str(run_dir)) == 0
    ok, why = supervisor._authenticate_ship_actions(cfg, str(cr), str(run_dir), rid)
    assert ok, why  # no false positive


def test_replayed_completion_after_rollback_is_refused(tmp_path):
    # THE R8-01 repro: a genuine signed completion copied after its signed rollback.
    cr, run_dir, cfg, rid, _c = _signed_prep_deploy_run(tmp_path)
    assert supervisor.ship_cmd(str(cr), str(run_dir)) == 3  # SHIP_FAILED, prep rolled back
    events = _read_journal(run_dir)
    old_ok = next(e for e in events if e.get("state") == "SHIP_ACTION_RESULT"
                  and e.get("data", {}).get("action") == "prep"
                  and e.get("data", {}).get("status") == "ok")
    with open(run_dir / "ship_journal.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps(old_ok) + "\n")
    # The replay DOES re-add prep to the applied set (the reducer dedupes by name)...
    assert "prep" in supervisor._ship_action_recovery_state(str(run_dir))["applied"]
    # ...but the ordered chain refuses it (its seq repeats).
    ok, why = supervisor._authenticate_ship_actions(cfg, str(cr), str(run_dir), rid)
    assert not ok and "out of sequence" in why


def test_replayed_completion_with_rewritten_seq_is_refused(tmp_path):
    # Defense in depth: rewriting the replayed completion's seq to look contiguous
    # yields a token that was never signed at that seq.
    cr, run_dir, cfg, rid, _c = _signed_prep_deploy_run(tmp_path)
    assert supervisor.ship_cmd(str(cr), str(run_dir)) == 3
    events = _read_journal(run_dir)
    old_ok = next(e for e in events if e.get("state") == "SHIP_ACTION_RESULT"
                  and e.get("data", {}).get("action") == "prep"
                  and e.get("data", {}).get("status") == "ok")
    forged = json.loads(json.dumps(old_ok))
    forged["data"]["seq"] = 2  # after the rollback (seq 1), so 0,1,2 looks contiguous
    with open(run_dir / "ship_journal.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps(forged) + "\n")
    ok, why = supervisor._authenticate_ship_actions(cfg, str(cr), str(run_dir), rid)
    assert not ok and "not anchored" in why


def test_deleted_tail_rollback_journal_lines_are_refused(tmp_path):
    # Opus review F1: the seq-chain is journal-driven, so deleting BOTH of a
    # rollback's journal lines (SHIP_ROLLBACK_INTENT + the tail SHIP_ROLLED_BACK)
    # leaves the rolled-back action's completion (seq 0) unpopped and the remaining
    # seqs still contiguous — silently re-adding the action with its effect GONE.
    # The chain->journal reverse check (every anchored rollback token must be
    # claimed by a journaled SHIP_ROLLED_BACK) refuses it.
    cr, run_dir, cfg, rid, _c = _signed_prep_deploy_run(tmp_path)
    assert supervisor.ship_cmd(str(cr), str(run_dir)) == 3
    events = _read_journal(run_dir)
    kept = [e for e in events
            if e.get("state") not in ("SHIP_ROLLBACK_INTENT", "SHIP_ROLLED_BACK")]
    _write_journal(run_dir, kept)
    # The reducer DOES re-add prep (the rollback that popped it is gone)...
    assert "prep" in supervisor._ship_action_recovery_state(str(run_dir))["applied"]
    # ...and there is no unresolved intent to halt on (both lines were deleted)...
    assert supervisor._unresolved_ship_action(str(run_dir)) is None
    # ...but the orphaned signed rollback token is attributable to no surviving
    # SHIP_ROLLBACK_INTENT → refused.
    ok, why = supervisor._authenticate_ship_actions(cfg, str(cr), str(run_dir), rid)
    assert not ok and "no surviving SHIP_ROLLBACK_INTENT" in why


def test_decoy_rollback_intent_cannot_cover_a_deleted_rollback(tmp_path):
    # Opus re-review: the orphan check attributes by the ROLLBACK INTENT, and the
    # rollback token is NOT seq-bound, so it recomputes exactly from (action,
    # attempt_id). An attacker who deletes prep's real rollback lines AND plants a
    # decoy SHIP_ROLLBACK_INTENT (to inflate the surviving-intent set) cannot cover
    # the orphan: the decoy recomputes to a DIFFERENT, unanchored token.
    cr, run_dir, cfg, rid, _c = _signed_prep_deploy_run(tmp_path)
    assert supervisor.ship_cmd(str(cr), str(run_dir)) == 3
    events = _read_journal(run_dir)
    kept = [e for e in events
            if e.get("state") not in ("SHIP_ROLLBACK_INTENT", "SHIP_ROLLED_BACK")]
    kept.append({"ts": "t", "state": "SHIP_ROLLBACK_INTENT",
                 "data": {"action": "prep", "attempt_id": "decoy-attempt"}})
    _write_journal(run_dir, kept)
    ok, why = supervisor._authenticate_ship_actions(cfg, str(cr), str(run_dir), rid)
    assert not ok and "no surviving SHIP_ROLLBACK_INTENT" in why


def test_rollback_before_its_completion_is_refused(tmp_path):
    # Rollback ordering is enforced by applied-set membership (rollbacks are not
    # seq-bound): a SHIP_ROLLED_BACK moved AHEAD of the completion it removes — so
    # the reducer would treat the pop as a no-op and then re-apply the action — is
    # refused (the action is not currently applied at that journal position).
    cr, run_dir, cfg, rid, _c = _signed_prep_deploy_run(tmp_path)
    assert supervisor.ship_cmd(str(cr), str(run_dir)) == 3
    events = _read_journal(run_dir)
    rb_idx = next(i for i, e in enumerate(events) if e.get("state") == "SHIP_ROLLED_BACK")
    comp_idx = next(i for i, e in enumerate(events)
                    if e.get("state") == "SHIP_ACTION_RESULT"
                    and e.get("data", {}).get("action") == "prep"
                    and e.get("data", {}).get("status") == "ok")
    rb = events.pop(rb_idx)
    events.insert(comp_idx, rb)  # move the rollback before prep's completion
    _write_journal(run_dir, events)
    ok, why = supervisor._authenticate_ship_actions(cfg, str(cr), str(run_dir), rid)
    assert not ok and "before that action is applied" in why


def test_rollback_crash_window_does_not_false_brick(tmp_path):
    # Opus re-review: a legit multi-rollback crash-window (a rollback's token is
    # anchored, but its SHIP_ROLLED_BACK was not journaled before a crash) leaves a
    # surviving SHIP_ROLLBACK_INTENT. The orphan check must ATTRIBUTE the anchored
    # token to that intent and NOT refuse — otherwise a sanctioned reconcile is
    # permanently bricked (abort-only). Because the rollback token is not seq-bound,
    # it recomputes from the surviving intent and authenticates.
    cr, run_dir, cfg, rid = _two_reversible_then_fail_run(tmp_path)
    assert supervisor.ship_cmd(str(cr), str(run_dir)) == 3
    events = _read_journal(run_dir)
    # crash-window: drop prep1's SHIP_ROLLED_BACK but KEEP its SHIP_ROLLBACK_INTENT
    kept = [e for e in events if not (e.get("state") == "SHIP_ROLLED_BACK"
            and e.get("data", {}).get("action") == "prep1")]
    _write_journal(run_dir, kept)
    assert (supervisor._ship_action_recovery_state(str(run_dir))["unresolved_rollback"]
            or {}).get("action") == "prep1"
    ok, why = supervisor._authenticate_ship_actions(cfg, str(cr), str(run_dir), rid)
    assert ok, why  # NOT a false orphan brick


def test_planted_rollback_failed_collision_halts_not_skips(tmp_path):
    # Opus re-review F3: SHIP_ROLLBACK_FAILED is unauthenticated and its attempt_id
    # (resolution) is decoupled from its action (applied.pop). An attacker deletes
    # prep1's SHIP_ROLLED_BACK (keep its intent, so the orphan check still
    # attributes the anchored token) and plants SHIP_ROLLBACK_FAILED with a
    # DIFFERENT action (prep2) but prep1's rollback attempt_id — to spoof
    # resolution of prep1's dangling intent by attempt_id alone. Action-bound
    # rollback resolution defeats it: the forged event resolves (prep2, rb1), not
    # (prep1, rb1), so prep1's intent stays unresolved → halt, never a skip.
    cr, run_dir, cfg, rid = _two_reversible_then_fail_run(tmp_path)
    assert supervisor.ship_cmd(str(cr), str(run_dir)) == 3
    events = _read_journal(run_dir)
    rb1 = next(e for e in events if e.get("state") == "SHIP_ROLLBACK_INTENT"
               and e.get("data", {}).get("action") == "prep1")["data"]["attempt_id"]
    events = [e for e in events if not (e.get("state") == "SHIP_ROLLED_BACK"
              and e.get("data", {}).get("action") == "prep1")]
    idx = next(i for i, e in enumerate(events) if e.get("state") == "SHIP_ROLLED_BACK"
               and e.get("data", {}).get("action") == "prep2")
    events.insert(idx, {"ts": "t", "state": "SHIP_ROLLBACK_FAILED",
                        "data": {"action": "prep2", "attempt_id": rb1}})
    _write_journal(run_dir, events)
    assert "prep1" in supervisor._ship_action_recovery_state(str(run_dir))["applied"]
    assert (supervisor._ship_action_recovery_state(str(run_dir))["unresolved_rollback"]
            or {}).get("action") == "prep1"
    (run_dir / "ship_result.json").unlink()
    assert supervisor.ship_cmd(str(cr), str(run_dir)) == supervisor.UNKNOWN_OUTCOME
    for e in _read_journal(run_dir):
        if e.get("state") == "SHIP_STARTED":
            assert "prep1" not in (e.get("data", {}).get("already_done") or [])


def test_reorder_shadow_rollback_deletion_halts_not_skips(tmp_path):
    # Opus re-review F2: the intent-orphan check attributes a deleted rollback's
    # anchored token to a SURVIVING SHIP_ROLLBACK_INTENT, so the attacker keeps the
    # intent (to satisfy the orphan check) but REORDERS it behind another, resolved
    # rollback intent — dodging a LATEST-only unresolved check. With every
    # unresolved intent surfaced, prep1's dangling rollback re-triggers the
    # SHIP_UNKNOWN_OUTCOME halt: prep1 (effect rolled back / gone) is NEVER silently
    # skipped on the re-ship.
    cr, run_dir, cfg, rid = _two_reversible_then_fail_run(tmp_path)
    assert supervisor.ship_cmd(str(cr), str(run_dir)) == 3
    events = _read_journal(run_dir)
    # delete prep1's SHIP_ROLLED_BACK (keep its intent) → prep1 re-added to applied
    events = [e for e in events if not (e.get("state") == "SHIP_ROLLED_BACK"
              and e.get("data", {}).get("action") == "prep1")]
    ri1 = next(e for e in events if e.get("state") == "SHIP_ROLLBACK_INTENT"
               and e.get("data", {}).get("action") == "prep1")
    ri2 = next(e for e in events if e.get("state") == "SHIP_ROLLBACK_INTENT"
               and e.get("data", {}).get("action") == "prep2")
    events.remove(ri1)
    events.insert(events.index(ri2), ri1)  # prep1 intent now BEHIND prep2's (resolved)
    _write_journal(run_dir, events)
    # prep1 is (wrongly) in the applied set...
    assert "prep1" in supervisor._ship_action_recovery_state(str(run_dir))["applied"]
    # ...but its dangling rollback intent is surfaced despite not being the latest...
    assert (supervisor._ship_action_recovery_state(str(run_dir))["unresolved_rollback"]
            or {}).get("action") == "prep1"
    # ...so the re-ship HALTS (unknown outcome), never skipping prep1.
    (run_dir / "ship_result.json").unlink()
    assert supervisor.ship_cmd(str(cr), str(run_dir)) == supervisor.UNKNOWN_OUTCOME
    # and prep1 is NOT recorded as an already-done skip.
    states = _read_journal(run_dir)
    started = [e for e in states if e.get("state") == "SHIP_STARTED"]
    for e in started:
        assert "prep1" not in (e.get("data", {}).get("already_done") or [])


def test_reordered_completions_are_refused(tmp_path):
    cr, run_dir, cfg, rid = _multi_action_run(tmp_path, ["a", "b"])
    assert supervisor.ship_cmd(str(cr), str(run_dir)) == 0
    events = _read_journal(run_dir)
    ok_idxs = [i for i, e in enumerate(events)
               if e.get("state") == "SHIP_ACTION_RESULT"
               and e.get("data", {}).get("status") == "ok"]
    assert len(ok_idxs) == 2
    i, j = ok_idxs
    events[i], events[j] = events[j], events[i]
    _write_journal(run_dir, events)
    ok, why = supervisor._authenticate_ship_actions(cfg, str(cr), str(run_dir), rid)
    assert not ok and "out of sequence" in why


def test_deleted_interior_completion_leaves_a_gap_and_is_refused(tmp_path):
    cr, run_dir, cfg, rid = _multi_action_run(tmp_path, ["a", "b", "c"])
    assert supervisor.ship_cmd(str(cr), str(run_dir)) == 0
    events = _read_journal(run_dir)
    kept = [e for e in events if not (e.get("state") == "SHIP_ACTION_RESULT"
            and e.get("data", {}).get("action") == "b"
            and e.get("data", {}).get("status") == "ok")]
    _write_journal(run_dir, kept)
    ok, why = supervisor._authenticate_ship_actions(cfg, str(cr), str(run_dir), rid)
    assert not ok and "out of sequence" in why


def test_planted_bare_rollback_without_token_is_refused(tmp_path):
    # A same-user writer appends a bare SHIP_ROLLED_BACK (no signed token) for a
    # real applied action to force a duplicate re-run — refused (no anchored token).
    cr, run_dir, cfg, rid = _multi_action_run(tmp_path, ["a"])
    assert supervisor.ship_cmd(str(cr), str(run_dir)) == 0
    with open(run_dir / "ship_journal.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps({"ts": "t", "state": "SHIP_ROLLED_BACK",
                            "data": {"action": "a", "attempt_id": "planted"}}) + "\n")
    ok, why = supervisor._authenticate_ship_actions(cfg, str(cr), str(run_dir), rid)
    assert not ok and "not anchored" in why


def test_stripped_seq_is_fail_closed(tmp_path):
    # A completion whose signed `seq` field is removed (a pre-chain legacy line or
    # a stripped field) fails closed — never silently trusted.
    cr, run_dir, cfg, rid = _multi_action_run(tmp_path, ["a"])
    assert supervisor.ship_cmd(str(cr), str(run_dir)) == 0
    events = _read_journal(run_dir)
    for e in events:
        if e.get("state") == "SHIP_ACTION_RESULT" and e.get("data", {}).get("status") == "ok":
            e["data"].pop("seq", None)
    _write_journal(run_dir, events)
    ok, why = supervisor._authenticate_ship_actions(cfg, str(cr), str(run_dir), rid)
    assert not ok and "seq" in why


def test_seq_survives_evidence_pending_repair(tmp_path, monkeypatch):
    # A completion re-signed by the evidence-repair path must continue the chain
    # (seq = max+1), so the recovered run still authenticates end-to-end.
    from test_m56b_anchor_recovery import _fail_anchor_for, _named_counter_action
    import df_ship
    cr = tmp_path / "control"
    prep, prep_counter = _named_counter_action(tmp_path, "prep")
    deploy, deploy_counter = _named_counter_action(tmp_path, "deploy")
    cfg, run_dir, oid, rid = build_sealed_run(
        tmp_path, cr,
        _base_config(tmp_path, "standard", {"actions": [prep, deploy]}, signed=True),
        {"app.txt": "v1"})
    restore = _fail_anchor_for(monkeypatch, "ship-action-ok", action_name="prep")
    assert supervisor.ship_cmd(str(cr), str(run_dir)) == supervisor.SHIP_EVIDENCE_PENDING_EXIT
    restore()
    assert supervisor.ship_cmd(str(cr), str(run_dir), decision="repair-evidence") == 0
    ok, why = supervisor._authenticate_ship_actions(cfg, str(cr), str(run_dir), rid)
    assert ok, why


# ---------------------------------------------------------------------------
# DF-R8-05 — per-token-type namespaces; genuine intent doesn't block the reseal
# ---------------------------------------------------------------------------

def test_genuine_intent_does_not_block_no_action_reseal(tmp_path):
    cr = tmp_path / "control"
    deploy, counter = _counter_action(_mk(tmp_path / "d"), name="deploy")
    cfg, run_dir, oid, rid = build_sealed_run(
        tmp_path, cr, _base_config(tmp_path, "standard", {"actions": [deploy]}, signed=True),
        {"app.txt": "v1"})
    attempt, idk = "intent-before-crash", "stable-idk"
    payload = supervisor._ship_action_intent_payload(
        rid, "deploy", idk, None, True, None, attempt_id=attempt)
    # the real committer anchors intents under the ship-action-intent namespace
    assert supervisor._anchor_ship_local(cfg, str(cr), rid, payload,
                                         "ship-action-intent") == "anchored"
    record = {"ship_version": "1", "outcome": "SHIP_FAILED", "actions": [],
              "rollbacks": [], "rollback_failed": False, "pending_action": None,
              "failed_action": "deploy", "ship_workspace_object_id": oid,
              "ts": "2026-07-20T00:00:00Z"}
    text = supervisor.canonical_json(record)
    (run_dir / "ship_result.json").write_text(text, encoding="utf-8")
    _write_journal(run_dir, [
        {"ts": "t", "state": "SHIP_ACTION_INTENT",
         "data": {"action": "deploy", "idempotency_key": idk, "attempt_id": attempt}},
        {"ts": "t", "state": "SHIP_RECONCILE_ABORT",
         "data": {"action": "deploy", "kind": "action"}},
        {"ts": "t", "state": "SHIP_TERMINAL_ANCHOR_PENDING",
         "data": {"outcome": "SHIP_FAILED", "record_sha256": supervisor.sha256_str(text)}},
    ])
    # A genuine pre-spawn intent no longer counts as "shipped something".
    assert supervisor._is_no_action_terminal(
        str(run_dir), rid, record, cfg=cfg, control_root=str(cr))
    # The governed abort reseals the FAILED terminal; no action runs.
    assert supervisor.ship_cmd(str(cr), str(run_dir), decision="abort") == 3
    assert not counter.exists()


def test_a_real_completion_token_still_blocks_the_reseal(tmp_path):
    # The inverse: a signed COMPLETION (something really ran) must still route
    # through full evidence binding, never the no-action reseal shortcut.
    cr = tmp_path / "control"
    deploy, counter = _counter_action(_mk(tmp_path / "d"), name="deploy")
    cfg, run_dir, oid, rid = build_sealed_run(
        tmp_path, cr, _base_config(tmp_path, "standard", {"actions": [deploy]}, signed=True),
        {"app.txt": "v1"})
    payload = supervisor._ship_action_commit_payload(
        rid, "deploy", "idk", None, True, None, attempt_id="a1", seq=0)
    assert supervisor._anchor_ship_local(cfg, str(cr), rid, payload,
                                         "ship-action") == "anchored"
    record = {"ship_version": "1", "outcome": "SHIP_FAILED", "actions": [],
              "failed_action": "deploy", "ship_workspace_object_id": oid,
              "ts": "2026-07-20T00:00:00Z"}
    assert not supervisor._is_no_action_terminal(
        str(run_dir), rid, record, cfg=cfg, control_root=str(cr))
