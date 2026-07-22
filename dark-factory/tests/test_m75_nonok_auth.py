"""M75 (Codex R9): DF-R9-02 — an UNAUTHENTICATED non-`ok` result may not resolve a
signed intent.

The recovery reducer marked an intent resolved for ANY SHIP_ACTION_RESULT status,
but only `ok` is signed. So a same-user writer could append a forged `failed` (or
other non-`ok`) result for a genuine dangling SIGNED intent whose action ALREADY
RAN — recovery reported no unresolved action, and a plain `ship` (without reconcile
consent) RE-RAN it (a duplicate), bypassing the SHIP_UNKNOWN_OUTCOME gate.

Fix: a signed dispatch is AUTHENTICALLY resolved only by a signed completion (ran +
exited 0) or a signed operator-reconcile token. An anchored intent with no
authenticated outcome is UNKNOWN — the operator must reconcile (consent to a
duplicate) or abort. The reconcile decision signs a `ship-action-reconciled` token
so a FORGED reconciled_unknown can't spoof it.
"""
import json
import subprocess

import supervisor
from test_ship import _base_config, build_sealed_run
from test_m49_ship_integrity import _counter_action


def _dangling_signed_forged(tmp_path, forged_status="failed"):
    """A signed run where a genuine intent was anchored and the action RAN, but a
    forged non-`ok` result (no completion) claims a terminal outcome. Returns
    (cr, run_dir, cfg, rid, counter)."""
    action, counter = _counter_action(tmp_path, name="deploy", reversible=True)
    cr = tmp_path / "control"
    cfg, run_dir, oid, rid = build_sealed_run(
        tmp_path, cr, _base_config(tmp_path, "standard", {"actions": [action]}, signed=True),
        {"x.txt": "v1"})
    att, idk = "genuine-crashed-attempt", "stable-idk"
    payload = supervisor._ship_action_intent_payload(
        rid, "deploy", idk, None, True, None, attempt_id=att)
    supervisor._anchor_ship_local(cfg, str(cr), rid, payload, "ship-action-intent")
    jp = run_dir / "ship_journal.jsonl"
    with open(jp, "a", encoding="utf-8") as f:
        f.write(json.dumps({"ts": "t", "state": "SHIP_ACTION_INTENT",
                            "data": {"action": "deploy", "idempotency_key": idk,
                                     "attempt_id": att, "toolchain": None,
                                     "reversible": True, "approval_ref": None}}) + "\n")
    subprocess.run(action["run"], check=True)  # the action's real effect happened
    with open(jp, "a", encoding="utf-8") as f:
        f.write(json.dumps({"ts": "t", "state": "SHIP_ACTION_RESULT",
                            "data": {"action": "deploy", "idempotency_key": idk,
                                     "attempt_id": att, "status": forged_status,
                                     "exit": 1, "timed_out": False}}) + "\n")
    return cr, run_dir, cfg, rid, counter


def test_forged_failed_halts_unknown_no_duplicate(tmp_path):
    cr, run_dir, cfg, rid, counter = _dangling_signed_forged(tmp_path)
    assert counter.read_text() == "x"  # ran once
    assert supervisor.ship_cmd(str(cr), str(run_dir)) == supervisor.UNKNOWN_OUTCOME
    assert counter.read_text() == "x"  # NOT re-run


def test_forged_reconciled_unknown_halts_unknown(tmp_path):
    # An unsigned reconciled_unknown (no signed reconcile token) is just as forgeable
    # and must not resolve the signed intent either.
    cr, run_dir, cfg, rid, counter = _dangling_signed_forged(tmp_path, "reconciled_unknown")
    assert supervisor.ship_cmd(str(cr), str(run_dir)) == supervisor.UNKNOWN_OUTCOME
    assert counter.read_text() == "x"


def test_repair_evidence_does_not_bypass(tmp_path):
    # The forged non-ok has nothing for repair-evidence to repair; it must not fall
    # through to a silent re-run (the post-repair dangling gate catches it).
    cr, run_dir, cfg, rid, counter = _dangling_signed_forged(tmp_path)
    assert supervisor.ship_cmd(str(cr), str(run_dir), decision="repair-evidence") != 0
    assert counter.read_text() == "x"


def test_reconcile_reruns_and_signs_token(tmp_path):
    # Operator reconcile: re-runs (consented duplicate) and signs a reconcile token
    # so it authenticates and does not loop.
    cr, run_dir, cfg, rid, counter = _dangling_signed_forged(tmp_path)
    rc = supervisor.ship_cmd(str(cr), str(run_dir), decision="reconcile")
    assert rc != supervisor.SHIP_STATE_UNAUTHENTICATED
    assert counter.read_text() == "xx"  # re-ran once under consent
    # a signed reconcile token now exists for the attempt
    import df_audit, df_audit_chain
    key = df_audit.load_key(cfg["_audit"]["key_path"])
    entries = df_audit_chain.read_chain(str(cr / "audit-chain.jsonl"))
    assert any(str(e.get("invocation", "")).startswith(f"{rid}.ship-action-reconciled.")
               for e in entries)


def test_deleted_intent_line_halts_unauthenticated(tmp_path):
    # DF-R9-02 (opus review of M75): the equivalent of the forged non-`ok` vector is
    # to DELETE the SHIP_ACTION_INTENT journal line for a signed dispatch whose
    # action ran but whose completion never anchored. Both journal-driven checks then
    # see nothing, so recovery would re-run it. The chain->journal intent coverage
    # check in _authenticate_ship_actions refuses (fail-closed) — no re-run.
    cr, run_dir, cfg, rid, counter = _dangling_signed_forged(tmp_path)
    jp = run_dir / "ship_journal.jsonl"
    lines = [ln for ln in jp.read_text().splitlines()
             if json.loads(ln).get("state") != "SHIP_ACTION_INTENT"]
    jp.write_text("\n".join(lines) + "\n")
    assert counter.read_text() == "x"  # ran once
    assert supervisor.ship_cmd(str(cr), str(run_dir)) == supervisor.SHIP_STATE_UNAUTHENTICATED
    assert counter.read_text() == "x"  # NOT re-run


def test_intent_coverage_direct(tmp_path):
    cr, run_dir, cfg, rid, counter = _dangling_signed_forged(tmp_path)
    # with the intent line present, authentication passes the intent-coverage gate
    ok, _why = supervisor._authenticate_ship_actions(cfg, str(cr), str(run_dir), rid)
    assert ok is True
    # delete the intent line → an anchored intent is now orphaned → refuse
    jp = run_dir / "ship_journal.jsonl"
    lines = [ln for ln in jp.read_text().splitlines()
             if json.loads(ln).get("state") != "SHIP_ACTION_INTENT"]
    jp.write_text("\n".join(lines) + "\n")
    ok2, why2 = supervisor._authenticate_ship_actions(cfg, str(cr), str(run_dir), rid)
    assert ok2 is False and "SHIP_ACTION_INTENT" in why2


def test_direct_dangling_check(tmp_path):
    cr, run_dir, cfg, rid, counter = _dangling_signed_forged(tmp_path)
    d = supervisor._dangling_signed_dispatch(cfg, str(cr), str(run_dir), rid)
    assert d is not None and d.get("action") == "deploy"


def test_genuine_shipped_run_not_flagged(tmp_path):
    # No false positive: a normal successful signed ship (completion anchored) is
    # not dangling.
    action, counter = _counter_action(tmp_path, name="deploy", reversible=True)
    cr = tmp_path / "control"
    cfg, run_dir, oid, rid = build_sealed_run(
        tmp_path, cr, _base_config(tmp_path, "standard", {"actions": [action]}, signed=True),
        {"x.txt": "v1"})
    assert supervisor.ship_cmd(str(cr), str(run_dir)) == 0
    assert supervisor._dangling_signed_dispatch(cfg, str(cr), str(run_dir), rid) is None
    assert supervisor.ship_cmd(str(cr), str(run_dir)) == 0  # idempotent re-entry
