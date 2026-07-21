"""M66 (Codex R7): DF-R7-01 attempt-bound signed ship transitions + DF-R7-02
non-null support-file digest at dispatch.

  * DF-R7-01 — M61 added a fresh `attempt_id` to the JOURNAL but never to the
    SIGNED intent/completion payload, and rollback transitions were unsigned. So
    (a) after a real rollback, an OLD signed completion token authenticated a
    PLANTED later `ok` for the same stable fields (skipping an absent effect),
    and (b) a planted bare `SHIP_ROLLED_BACK` forced a real applied action to
    re-run (a duplicate). attempt_id is now bound into every signed payload, and
    a successful rollback anchors its own signed token — recovery authenticates
    both the applied `ok` set AND the rollback removals.
  * DF-R7-02 — `_verify_support_files_at_dispatch` compared only when the sealed
    digest was non-null, so a `sha256: null` (or missing/duplicate) sealed entry
    accepted ANY readable file. It now requires exactly one sealed 64-hex entry
    per configured support file, and actual == expected.
"""
import hashlib
import json
import os
import sys

import pytest

import df_ship
import supervisor
from test_ship import build_sealed_run, _base_config
from test_m49_ship_integrity import _counter_action


class _J:
    def __init__(self):
        self.events = []

    def write(self, state, **data):
        self.events.append((state, data))


# ---------------------------------------------------------------------------
# DF-R7-01 — attempt_id bound into signed payloads; rollback transitions signed
# ---------------------------------------------------------------------------

def test_signed_payloads_bind_attempt_id():
    a1 = supervisor._ship_action_commit_payload("run", "deploy", "idk", None, True, None,
                                                attempt_id="a1")
    a2 = supervisor._ship_action_commit_payload("run", "deploy", "idk", None, True, None,
                                                attempt_id="a2")
    assert '"attempt_id"' in a1
    assert supervisor.sha256_str(a1) != supervisor.sha256_str(a2), \
        "distinct attempts must produce distinct tokens"
    i1 = supervisor._ship_action_intent_payload("run", "deploy", "idk", None, True, None,
                                                attempt_id="a1")
    assert '"attempt_id"' in i1
    rb = supervisor._ship_rollback_payload("run", "deploy", "r1")
    assert '"ship-rollback-ok"' in rb


def _signed_prep_deploy_run(tmp_path):
    """A signed run whose ship has prep(ok) then a failing deploy → prep is
    rolled back. Returns (cr, run_dir, cfg, rid, prep_counter)."""
    cr = tmp_path / "control"
    prep, prep_counter = _counter_action(tmp_path, name="prep")
    fail_script = tmp_path / "fail.py"
    fail_script.write_text("import sys\nsys.exit(1)\n", encoding="utf-8")
    deploy = {"name": "deploy", "run": [sys.executable, str(fail_script)],
              "reversible": True, "timeout_s": 30}
    prep["rollback"] = [sys.executable, prep["run"][1], prep["run"][2]]  # counter++ again
    cfg, run_dir, oid, rid = build_sealed_run(
        tmp_path, cr, _base_config(tmp_path, "standard", {"actions": [prep, deploy]},
                                   signed=True),
        {"a.txt": "v1"})
    return cr, run_dir, cfg, rid, prep_counter


def test_planted_rollback_cannot_force_a_rerun(tmp_path):
    # DF-R7-01 consequence 1: a same-user writer appends a bare SHIP_ROLLED_BACK
    # for a signed, applied action to make recovery drop + re-run it (duplicate).
    # It has no signed rollback token → authentication refuses.
    cr = tmp_path / "control"
    deploy, counter = _counter_action(tmp_path)
    cfg, run_dir, oid, rid = build_sealed_run(
        tmp_path, cr, _base_config(tmp_path, "standard", {"actions": [deploy]}, signed=True),
        {"a.txt": "v1"})
    assert supervisor.ship_cmd(str(cr), str(run_dir)) == 0  # legit SHIPPED, counter==x
    assert counter.read_text() == "x"

    # Append a forged, unsigned SHIP_ROLLED_BACK for the applied action.
    with open(run_dir / "ship_journal.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps({"ts": "2026-07-20T00:00:00Z", "state": "SHIP_ROLLED_BACK",
                            "data": {"action": "deploy", "attempt_id": "forged-rb"}}) + "\n")
    ok, why = supervisor._authenticate_ship_actions(cfg, str(cr), str(run_dir), rid)
    assert not ok, "an unsigned planted rollback must fail authentication"
    assert "rollback" in why


def test_planted_new_ok_after_rollback_is_not_authenticated_by_old_token(tmp_path):
    # DF-R7-01 consequence 2: a real a1 completion is signed; attacker journals a
    # real rollback then a planted a2 `ok` (unsigned). The old a1 token must NOT
    # authenticate the a2 attempt now that attempt_id is bound.
    cr, run_dir, cfg, rid, prep_counter = _signed_prep_deploy_run(tmp_path)
    # Run to SHIP_FAILED (deploy fails, prep rolled back — both signed).
    assert supervisor.ship_cmd(str(cr), str(run_dir)) == 3
    # Attacker appends a planted, unsigned a2 `ok` for prep (claiming re-applied).
    idk = df_ship.idempotency_key(rid, "prep", 0)
    with open(run_dir / "ship_journal.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps({"ts": "2026-07-20T00:00:01Z", "state": "SHIP_ACTION_RESULT",
                            "data": {"action": "prep", "idempotency_key": idk,
                                     "attempt_id": "planted-a2", "status": "ok"}}) + "\n")
    ok, why = supervisor._authenticate_ship_actions(cfg, str(cr), str(run_dir), rid)
    assert not ok, "a planted new-attempt ok must not be authenticated by the old token"


def test_legit_signed_ship_with_rollback_still_authenticates(tmp_path):
    # Non-vacuity: a genuine signed run whose rollback ran legitimately still
    # authenticates (the rollback carries its own signed token).
    cr, run_dir, cfg, rid, prep_counter = _signed_prep_deploy_run(tmp_path)
    assert supervisor.ship_cmd(str(cr), str(run_dir)) == 3  # SHIP_FAILED, prep rolled back
    ok, why = supervisor._authenticate_ship_actions(cfg, str(cr), str(run_dir), rid)
    assert ok, why


# ---------------------------------------------------------------------------
# DF-R7-02 — null / missing / duplicate sealed digest refused at dispatch
# ---------------------------------------------------------------------------

def _seal(path, sha):
    return {"builder_identity": {"support_files": [{"path": path, "sha256": sha}]}}


def test_null_sealed_digest_is_refused(tmp_path):
    p = tmp_path / "h.py"; p.write_text("V=1\n", encoding="utf-8")
    err = supervisor._verify_support_files_at_dispatch(
        {"_support_files": [str(p)]}, _seal(str(p), None), _J())
    assert err is not None and "no valid sealed sha256" in err


def test_missing_sealed_entry_is_refused(tmp_path):
    p = tmp_path / "h.py"; p.write_text("V=1\n", encoding="utf-8")
    err = supervisor._verify_support_files_at_dispatch(
        {"_support_files": [str(p)]}, {"builder_identity": {"support_files": []}}, _J())
    assert err is not None and "exactly one sealed" in err


def test_duplicate_sealed_entry_is_refused(tmp_path):
    p = tmp_path / "h.py"; p.write_text("V=1\n", encoding="utf-8")
    good = hashlib.sha256(b"V=1\n").hexdigest()
    mb = {"builder_identity": {"support_files": [
        {"path": str(p), "sha256": good}, {"path": str(p), "sha256": good}]}}
    err = supervisor._verify_support_files_at_dispatch({"_support_files": [str(p)]}, mb, _J())
    assert err is not None and "exactly one sealed" in err


def test_non_hex_sealed_digest_is_refused(tmp_path):
    p = tmp_path / "h.py"; p.write_text("V=1\n", encoding="utf-8")
    err = supervisor._verify_support_files_at_dispatch(
        {"_support_files": [str(p)]}, _seal(str(p), "not-a-real-sha256"), _J())
    assert err is not None and "no valid sealed sha256" in err


def test_valid_sealed_digest_matching_bytes_passes(tmp_path):
    p = tmp_path / "h.py"; p.write_text("V=1\n", encoding="utf-8")
    good = hashlib.sha256(b"V=1\n").hexdigest()
    assert supervisor._verify_support_files_at_dispatch(
        {"_support_files": [str(p)]}, _seal(str(p), good), _J()) is None


def test_planted_rollback_end_to_end_through_ship_cmd_does_not_rerun(tmp_path):
    # Opus-review M66-A: the HEADLINE attack, end-to-end through ship_cmd (the
    # direct-call test above missed the `and already_done` call-site guard). A
    # single-action signed run, planted unsigned SHIP_ROLLED_BACK, must REFUSE —
    # the real applied action must NOT re-run (no duplicate).
    cr = tmp_path / "control"
    deploy, counter = _counter_action(tmp_path)
    cfg, run_dir, oid, rid = build_sealed_run(
        tmp_path, cr, _base_config(tmp_path, "standard", {"actions": [deploy]}, signed=True),
        {"a.txt": "v1"})
    assert supervisor.ship_cmd(str(cr), str(run_dir)) == 0
    assert counter.read_text() == "x", "ran exactly once"
    # Same-user tamper: delete the terminal record + plant an unsigned rollback.
    (run_dir / "ship_result.json").unlink()
    with open(run_dir / "ship_journal.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps({"ts": "2026-07-20T00:00:00Z", "state": "SHIP_ROLLED_BACK",
                            "data": {"action": "deploy", "attempt_id": "forged"}}) + "\n")
    rc = supervisor.ship_cmd(str(cr), str(run_dir))
    assert rc == supervisor.SHIP_STATE_UNAUTHENTICATED, f"must refuse, got {rc}"
    assert counter.read_text() == "x", "the action must NOT have re-run (no duplicate)"


def test_replayed_signed_rollback_is_refused(tmp_path):
    # Mini-audit finding: a REAL signed rollback token appended TWICE (replay,
    # e.g. after the action was re-applied) must refuse — not silently remove the
    # re-applied action and force a duplicate.
    cr, run_dir, cfg, rid, prep_counter = _signed_prep_deploy_run(tmp_path)
    assert supervisor.ship_cmd(str(cr), str(run_dir)) == 3  # SHIP_FAILED, prep rolled back (signed)
    # Duplicate the real SHIP_ROLLED_BACK line (same signed attempt_id).
    lines = (run_dir / "ship_journal.jsonl").read_text(encoding="utf-8").splitlines()
    rb_line = next(l for l in lines if '"SHIP_ROLLED_BACK"' in l)
    with open(run_dir / "ship_journal.jsonl", "a", encoding="utf-8") as f:
        f.write(rb_line + "\n")
    ok, why = supervisor._authenticate_ship_actions(cfg, str(cr), str(run_dir), rid)
    # DF-R8-01: the transition-chain check now catches an identical replayed
    # rollback EARLIER — the second SHIP_ROLLED_BACK targets an action that is no
    # longer applied (membership check), before the per-attempt duplicate guard.
    # Either way it is a fail-closed refusal, never a silent re-run.
    assert not ok and ("REPLAYED" in why or "before that action is applied" in why)
