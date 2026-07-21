"""M56b (Codex R5): DF-R5-02 — ship anchor failures are RECOVERABLE, never bricks.

  * A succeeded action whose completion token cannot be signed journals
    `evidence_pending` (never an unbacked `ok`), the loop STOPS, and the run
    seals the DISTINCT recoverable SHIP_EVIDENCE_PENDING (exit 13). Re-entry
    runs an AUTHENTICATED evidence-only repair: the completion token is
    re-signed from the facts bound by the action's SIGNED PRE-SPAWN intent
    token, then the remaining actions continue. Real actions NEVER re-run.
  * A signer that is down BEFORE the spawn halts WITHOUT running the action
    (journal `not_run_evidence_halt`); the retry simply re-runs it.
  * A terminal SHIP_FAILED sealed during a signer outage journals a
    SHIP_TERMINAL_ANCHOR_PENDING marker; re-entry re-anchors it ONLY after
    re-verifying the record against the signed + journaled evidence — a
    planted terminal + planted marker is refused, never laundered into the
    signed chain.

Deterministic; reuses the M53/M49/M56 sealed-run + counter-action harness.
"""
import json
import shutil
import sys

import pytest

import df_custody
import df_ship
import supervisor
from test_ship import build_sealed_run, _base_config
from test_m49_ship_integrity import _counter_action

try:
    import cryptography  # noqa: F401
    _CRYPTO = True
except ImportError:
    _CRYPTO = False


def _named_counter_action(tmp_path, name, reversible=True):
    """Like test_m49's _counter_action but with a PER-NAME counter file, so two
    actions in one ship can each prove exactly-once independently."""
    sub = tmp_path / f"ctr_{name}"
    sub.mkdir(exist_ok=True)
    action, counter = _counter_action(sub, name=name, reversible=reversible)
    return action, counter


def _fail_anchor_for(monkeypatch, payload_kind, action_name=None):
    """Selectively fail supervisor._anchor_ship_local for per-action tokens of
    `payload_kind` ('ship-action-ok' | 'ship-action-intent'), optionally only for
    one action — the deterministic 'signer outage' switch. Returns a restore fn."""
    orig = supervisor._anchor_ship_local

    def wrapper(cfg, control_root, run_id, payload, kind):
        # DF-R8-05: per-action tokens now anchor under DISTINCT chain namespaces
        # (ship-action / ship-action-intent / ship-rollback); match the outage on
        # the PAYLOAD kind across all three so an intent-token outage is still hit.
        if kind in ("ship-action", "ship-action-intent", "ship-rollback"):
            p = json.loads(payload)
            if p.get("kind") == payload_kind and (
                    action_name is None or p.get("action") == action_name):
                return "anchor_failed"
        return orig(cfg, control_root, run_id, payload, kind)

    monkeypatch.setattr(supervisor, "_anchor_ship_local", wrapper)
    return lambda: monkeypatch.setattr(supervisor, "_anchor_ship_local", orig)


def _journal_states(run_dir):
    lines = (run_dir / "ship_journal.jsonl").read_text(encoding="utf-8")
    return [json.loads(l) for l in lines.strip().splitlines()]


def _result_statuses(run_dir, action):
    return [e["data"].get("status") for e in _journal_states(run_dir)
            if e["state"] == "SHIP_ACTION_RESULT" and e["data"].get("action") == action]


# ---------------------------------------------------------------------------
# The auditor's repro 1 class: completion-anchor failure mid-sequence.
# ---------------------------------------------------------------------------

def test_completion_anchor_failure_is_recoverable_not_a_brick(tmp_path, monkeypatch):
    cr = tmp_path / "control"
    prep, prep_counter = _named_counter_action(tmp_path, "prep")
    deploy, deploy_counter = _named_counter_action(tmp_path, "deploy")
    cfg, run_dir, oid, rid = build_sealed_run(
        tmp_path, cr,
        _base_config(tmp_path, "standard", {"actions": [prep, deploy]}, signed=True),
        {"app.txt": "v1"})

    restore = _fail_anchor_for(monkeypatch, "ship-action-ok", action_name="prep")
    rc = supervisor.ship_cmd(str(cr), str(run_dir))
    assert rc == supervisor.SHIP_EVIDENCE_PENDING_EXIT, f"expected 13, got {rc}"
    assert prep_counter.read_text() == "x", "prep RAN (the outage hit AFTER it)"
    assert not deploy_counter.exists(), "the loop STOPS — deploy must not run"
    assert _result_statuses(run_dir, "prep") == ["evidence_pending"], \
        "never an unbacked journal `ok`"
    rec = json.loads((run_dir / "ship_result.json").read_text())
    assert rec["outcome"] == df_ship.SHIP_EVIDENCE_PENDING

    # Signer recovers. A PLAIN retry repairs NOTHING (the success claim sat in
    # the writable journal during the outage — the operator must consent).
    restore()
    rc_noconsent = supervisor.ship_cmd(str(cr), str(run_dir))
    assert rc_noconsent == supervisor.SHIP_EVIDENCE_PENDING_EXIT
    assert _result_statuses(run_dir, "prep") == ["evidence_pending"], "nothing repaired"
    assert not deploy_counter.exists(), "and nothing further ran"

    # Explicit consent -> the retry repairs the evidence and CONTINUES.
    rc2 = supervisor.ship_cmd(str(cr), str(run_dir), decision="repair-evidence")
    assert rc2 == 0, f"recovered retry must finish the ship, got {rc2}"
    assert prep_counter.read_text() == "x", "prep is NEVER re-run"
    assert deploy_counter.read_text() == "x", "deploy ran exactly once, on the retry"
    assert _result_statuses(run_dir, "prep") == ["evidence_pending", "ok"]
    assert any(e["state"] == "SHIP_EVIDENCE_RESIGNED" for e in _journal_states(run_dir))
    final = json.loads((run_dir / "ship_result.json").read_text())
    assert final["outcome"] == df_ship.SHIPPED
    # The repaired evidence authenticates like any normal run.
    ok_a, why = supervisor._authenticate_ship_actions(cfg, str(cr), str(run_dir), rid)
    assert ok_a, why


@pytest.mark.skipif(not _CRYPTO, reason="cryptography not installed")
def test_auditor_repro_recovered_run_reaches_approval_not_exit_2(tmp_path, monkeypatch):
    # The auditor's EXACT flow: reversible prep (anchor fails) then an
    # irreversible deploy. Pre-M56b the retry permanently refused (exit 2);
    # now it repairs prep's evidence and reaches the NORMAL approval boundary.
    priv, pub = df_custody.generate_keypair()
    cr = tmp_path / "control"
    prep, prep_counter = _named_counter_action(tmp_path, "prep")
    deploy, deploy_counter = _named_counter_action(tmp_path, "deploy", reversible=False)
    ship = {"actions": [prep, deploy], "approval": {"approvers": [pub], "threshold": 1}}
    cfg, run_dir, oid, rid = build_sealed_run(
        tmp_path, cr, _base_config(tmp_path, "hardened", ship), {"app.txt": "v1"})

    restore = _fail_anchor_for(monkeypatch, "ship-action-ok", action_name="prep")
    rc = supervisor.ship_cmd(str(cr), str(run_dir))
    assert rc == supervisor.SHIP_EVIDENCE_PENDING_EXIT
    assert prep_counter.read_text() == "x" and not deploy_counter.exists()

    restore()
    rc2 = supervisor.ship_cmd(str(cr), str(run_dir), decision="repair-evidence")
    assert rc2 == 3, f"recovered retry must reach SHIP_APPROVAL_PENDING (3), got {rc2}"
    assert json.loads((run_dir / "ship_result.json").read_text())["outcome"] == \
        "SHIP_APPROVAL_PENDING"
    assert prep_counter.read_text() == "x", "prep never re-ran"
    assert not deploy_counter.exists(), "irreversible deploy stays gated on approval"


# ---------------------------------------------------------------------------
# Signer down BEFORE the spawn: nothing runs; the retry re-runs cleanly.
# ---------------------------------------------------------------------------

def test_intent_anchor_failure_halts_before_the_spawn(tmp_path, monkeypatch):
    cr = tmp_path / "control"
    deploy, counter = _counter_action(tmp_path)
    cfg, run_dir, oid, rid = build_sealed_run(
        tmp_path, cr, _base_config(tmp_path, "standard", {"actions": [deploy]}, signed=True),
        {"app.txt": "v1"})

    restore = _fail_anchor_for(monkeypatch, "ship-action-intent")
    rc = supervisor.ship_cmd(str(cr), str(run_dir))
    assert rc == supervisor.SHIP_EVIDENCE_PENDING_EXIT
    assert not counter.exists(), "the action must NOT run without a signed intent"
    assert _result_statuses(run_dir, "deploy") == ["not_run_evidence_halt"]

    restore()
    rc2 = supervisor.ship_cmd(str(cr), str(run_dir))
    assert rc2 == 0
    assert counter.read_text() == "x", "the never-run action re-runs exactly once"
    assert json.loads((run_dir / "ship_result.json").read_text())["outcome"] == df_ship.SHIPPED


# ---------------------------------------------------------------------------
# ATTACK: a planted intent + evidence_pending pair has no SIGNED intent token.
# ---------------------------------------------------------------------------

def test_planted_evidence_pending_pair_is_refused_not_resigned(tmp_path):
    cr = tmp_path / "control"
    deploy, counter = _counter_action(tmp_path)
    cfg, run_dir, oid, rid = build_sealed_run(
        tmp_path, cr, _base_config(tmp_path, "standard", {"actions": [deploy]}, signed=True),
        {"app.txt": "v1"})
    # Attacker plants a journal pair claiming `deploy` ran with pending evidence —
    # hoping the repair MINTS a signed ok-token for an action that never ran.
    idk = df_ship.idempotency_key(rid, "deploy", 0)
    lines = [
        {"ts": "2026-07-19T00:00:00Z", "state": "SHIP_ACTION_INTENT",
         "data": {"action": "deploy", "index": 0, "idempotency_key": idk,
                  "reversible": True, "approval_ref": None, "toolchain": None}},
        {"ts": "2026-07-19T00:00:01Z", "state": "SHIP_ACTION_RESULT",
         "data": {"action": "deploy", "index": 0, "idempotency_key": idk,
                  "exit": 0, "timed_out": False, "status": "evidence_pending",
                  "duration_s": 0.1}},
    ]
    (run_dir / "ship_journal.jsonl").write_text(
        "".join(json.dumps(l) + "\n" for l in lines), encoding="utf-8")

    rc = supervisor.ship_cmd(str(cr), str(run_dir), decision="repair-evidence")
    assert rc == 2, "a planted evidence_pending pair must be refused fail-closed"
    assert not counter.exists(), "and the real action must not have run"
    # No `ok` was appended and no completion token was minted for the plant.
    assert _result_statuses(run_dir, "deploy") == ["evidence_pending"]
    import df_audit_chain
    entries = df_audit_chain.read_chain(str(cr / "audit-chain.jsonl"))
    done_token = supervisor.sha256_str(supervisor._ship_action_commit_payload(
        rid, "deploy", idk, None, True, None))
    assert done_token not in {e.get("manifest_sha256") for e in entries}, \
        "the repair must never mint a completion token for a planted pair"


def test_flipped_failed_result_is_refused_even_with_consent(tmp_path, monkeypatch):
    # THE confused-deputy attack the consent gate + failed-line guard close: an
    # action really RAN AND FAILED (its intent token legitimately exists); a
    # journal writer flips nothing but APPENDS an evidence_pending line for the
    # same idempotency_key, hoping the key-holding operator retry mints a signed
    # ok-token for a FAILED action.
    cr = tmp_path / "control"
    cfg, run_dir, oid, rid = build_sealed_run(
        tmp_path, cr,
        _base_config(tmp_path, "standard", {"actions": [_failing_action(tmp_path)]},
                     signed=True),
        {"app.txt": "v1"})
    assert supervisor.ship_cmd(str(cr), str(run_dir)) == 3  # honest SHIP_FAILED
    (run_dir / "ship_result.json").unlink()  # attacker clears the terminal
    idk = df_ship.idempotency_key(rid, "deploy", 0)
    with open(run_dir / "ship_journal.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps({"ts": "2026-07-19T00:00:02Z", "state": "SHIP_ACTION_RESULT",
                            "data": {"action": "deploy", "index": 0,
                                     "idempotency_key": idk, "exit": 0,
                                     "timed_out": False, "status": "evidence_pending",
                                     "duration_s": 0.1}}) + "\n")

    rc = supervisor.ship_cmd(str(cr), str(run_dir), decision="repair-evidence")
    assert rc == 2, "a success claim coexisting with a journaled failure must refuse"


def _failing_action(tmp_path):
    script = tmp_path / "fail.py"
    script.write_text("import sys\nsys.exit(1)\n", encoding="utf-8")
    return {"name": "deploy", "run": [sys.executable, str(script)],
            "reversible": True, "timeout_s": 30}


# ---------------------------------------------------------------------------
# The auditor's repro 2: a SHIP_FAILED terminal sealed during a signer outage.
# ---------------------------------------------------------------------------

def test_terminal_anchor_failure_is_recoverable_and_stays_the_honest_terminal(
        tmp_path, monkeypatch):
    cr = tmp_path / "control"
    cfg, run_dir, oid, rid = build_sealed_run(
        tmp_path, cr,
        _base_config(tmp_path, "standard", {"actions": [_failing_action(tmp_path)]},
                     signed=True),
        {"app.txt": "v1"})
    key_path = cfg["_audit"]["key_path"]
    key_bak = key_path + ".bak"
    orig_run = df_ship.run_actions

    def _run_then_drop_key(*a, **k):
        res = orig_run(*a, **k)
        shutil.move(key_path, key_bak)
        return res

    monkeypatch.setattr(df_ship, "run_actions", _run_then_drop_key)
    rc = supervisor.ship_cmd(str(cr), str(run_dir))
    assert rc == 3, "the honest SHIP_FAILED terminal"
    monkeypatch.setattr(df_ship, "run_actions", orig_run)
    states = [e["state"] for e in _journal_states(run_dir)]
    assert "SHIP_TERMINAL_ANCHOR_PENDING" in states

    # Re-entry with the signer STILL down fail-closes upstream (_ship_eligible
    # cannot even authenticate the manifest without the key) — acceptable, and
    # NOT the brick: the moment the key returns, recovery below succeeds.
    rc2 = supervisor.ship_cmd(str(cr), str(run_dir))
    assert rc2 == 2, f"got {rc2}"

    # Signer recovers: the terminal re-anchors (evidence-bound) and STAYS the
    # honest SHIP_FAILED — never re-runs, never flips outcome. Pre-M56b THIS
    # was the permanent brick (exit 2 forever, even with the key back).
    shutil.move(key_bak, key_path)
    rc3 = supervisor.ship_cmd(str(cr), str(run_dir))
    assert rc3 == 3
    states = [e["state"] for e in _journal_states(run_dir)]
    assert "SHIP_TERMINAL_ANCHOR_RESOLVED" in states
    prior_text = (run_dir / "ship_result.json").read_text()
    ok_c, why = supervisor._authenticate_ship_chain(
        cfg, str(cr), rid, supervisor.sha256_str(prior_text), "ship")
    assert ok_c, why
    # And a further re-entry is the normal authenticated terminal short-circuit.
    assert supervisor.ship_cmd(str(cr), str(run_dir)) == 3


def test_forged_no_evidence_ship_failed_is_never_reanchored(tmp_path):
    # Opus-review HIGH: a forged EMPTY SHIP_FAILED (actions=[], failed_action=
    # None — the materialize-failure shape) + a planted anchor-pending marker
    # binds NOTHING checkable; re-anchoring it would be a signing oracle + a
    # permanent suppression of a shippable run. Must stay fail-closed exit 2.
    cr = tmp_path / "control"
    deploy, counter = _counter_action(tmp_path)
    cfg, run_dir, oid, rid = build_sealed_run(
        tmp_path, cr, _base_config(tmp_path, "standard", {"actions": [deploy]}, signed=True),
        {"app.txt": "v1"})
    forged = {"ship_version": "1", "outcome": "SHIP_FAILED", "actions": [],
              "rollbacks": [], "rollback_failed": False, "pending_action": None,
              "failed_action": None, "ship_workspace_object_id": oid,
              "ts": "2026-07-19T00:00:00Z"}
    forged_text = supervisor.canonical_json(forged)
    (run_dir / "ship_result.json").write_text(forged_text, encoding="utf-8")
    (run_dir / "ship_journal.jsonl").write_text(
        json.dumps({"ts": "2026-07-19T00:00:01Z",
                    "state": "SHIP_TERMINAL_ANCHOR_PENDING",
                    "data": {"outcome": "SHIP_FAILED",
                             "record_sha256": supervisor.sha256_str(forged_text)}}) + "\n",
        encoding="utf-8")

    rc = supervisor.ship_cmd(str(cr), str(run_dir))
    assert rc == 2, "a no-evidence terminal must never be re-anchored"
    assert not counter.exists(), "and no real action ran"
    ok_c, _why = supervisor._authenticate_ship_chain(
        cfg, str(cr), rid, supervisor.sha256_str(forged_text), "ship")
    assert not ok_c, "the forged bytes must NOT have been signed into the chain"


def test_consent_prompt_cannot_be_misdirected_by_a_renamed_result_line(tmp_path, monkeypatch):
    # Opus-review MEDIUM: the result line's `action` is attacker-writable while
    # the mint re-signs the INTENT's facts — a renamed result line would make
    # the operator verify the WRONG action. Any result/intent name or idk
    # inconsistency must refuse BEFORE the consent prompt and before any mint.
    cr = tmp_path / "control"
    prep, prep_counter = _named_counter_action(tmp_path, "prep")
    deploy, deploy_counter = _named_counter_action(tmp_path, "deploy")
    cfg, run_dir, oid, rid = build_sealed_run(
        tmp_path, cr,
        _base_config(tmp_path, "standard", {"actions": [prep, deploy]}, signed=True),
        {"app.txt": "v1"})
    restore = _fail_anchor_for(monkeypatch, "ship-action-ok", action_name="prep")
    assert supervisor.ship_cmd(str(cr), str(run_dir)) == \
        supervisor.SHIP_EVIDENCE_PENDING_EXIT
    restore()

    # Attacker renames the evidence_pending RESULT line to a benign-looking
    # action, hoping the prompt says "verify smoke-test" while prep is minted.
    jp = run_dir / "ship_journal.jsonl"
    out = []
    for ln in jp.read_text(encoding="utf-8").splitlines():
        e = json.loads(ln)
        if (e.get("state") == "SHIP_ACTION_RESULT"
                and e.get("data", {}).get("status") == "evidence_pending"):
            e["data"]["action"] = "smoke-test"
        out.append(json.dumps(e))
    jp.write_text("\n".join(out) + "\n", encoding="utf-8")

    for decision in ("continue", "repair-evidence"):
        rc = supervisor.ship_cmd(str(cr), str(run_dir), decision=decision)
        assert rc == 2, f"tampered result/intent naming must refuse (decision={decision})"
    assert _result_statuses(run_dir, "prep") == [], "no ok minted for prep"
    assert not deploy_counter.exists()


def test_forged_artifact_oid_on_a_real_failed_terminal_is_refused(tmp_path, monkeypatch):
    # Opus-review V-A4 hardening: a REAL failed run's record with only the
    # artifact oid forged must not be re-anchored with the forged oid.
    cr = tmp_path / "control"
    cfg, run_dir, oid, rid = build_sealed_run(
        tmp_path, cr,
        _base_config(tmp_path, "standard", {"actions": [_failing_action(tmp_path)]},
                     signed=True),
        {"app.txt": "v1"})
    key_path = cfg["_audit"]["key_path"]
    key_bak = key_path + ".bak"
    orig_run = df_ship.run_actions

    def _run_then_drop_key(*a, **k):
        res = orig_run(*a, **k)
        shutil.move(key_path, key_bak)
        return res

    monkeypatch.setattr(df_ship, "run_actions", _run_then_drop_key)
    assert supervisor.ship_cmd(str(cr), str(run_dir)) == 3
    monkeypatch.setattr(df_ship, "run_actions", orig_run)
    shutil.move(key_bak, key_path)

    # Forge ONLY the artifact id, re-derive the marker to match the forged bytes.
    rec = json.loads((run_dir / "ship_result.json").read_text())
    rec["ship_workspace_object_id"] = "FORGED-OID-" + "d" * 53
    forged_text = supervisor.canonical_json(rec)
    (run_dir / "ship_result.json").write_text(forged_text, encoding="utf-8")
    with open(run_dir / "ship_journal.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps({"ts": "2026-07-19T00:00:03Z",
                            "state": "SHIP_TERMINAL_ANCHOR_PENDING",
                            "data": {"outcome": "SHIP_FAILED",
                                     "record_sha256": supervisor.sha256_str(forged_text)}})
                + "\n")

    rc = supervisor.ship_cmd(str(cr), str(run_dir))
    assert rc == 2, "a forged artifact id must refuse the terminal re-anchor"
    ok_c, _why = supervisor._authenticate_ship_chain(
        cfg, str(cr), rid, supervisor.sha256_str(forged_text), "ship")
    assert not ok_c, "the forged bytes must NOT be in the signed chain"


def test_planted_terminal_plus_planted_marker_is_refused(tmp_path):
    # A control-root writer must not be able to LAUNDER a forged SHIP_FAILED into
    # the signed chain by also planting the anchor-pending marker.
    cr = tmp_path / "control"
    deploy, counter = _counter_action(tmp_path)
    cfg, run_dir, oid, rid = build_sealed_run(
        tmp_path, cr, _base_config(tmp_path, "standard", {"actions": [deploy]}, signed=True),
        {"app.txt": "v1"})
    assert supervisor.ship_cmd(str(cr), str(run_dir)) == 0  # legitimately SHIPPED

    forged = {"ship_version": "1", "outcome": "SHIP_FAILED",
              "actions": [{"name": "deploy", "reversible": True, "status": "failed",
                           "exit": 1, "approval_ref": None, "duration_s": 0.1}],
              "rollbacks": [], "rollback_failed": False, "pending_action": None,
              "failed_action": "deploy", "ship_workspace_object_id": oid,
              "ts": "2026-07-19T00:00:00Z"}
    forged_text = supervisor.canonical_json(forged)
    (run_dir / "ship_result.json").write_text(forged_text, encoding="utf-8")
    with open(run_dir / "ship_journal.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps({"ts": "2026-07-19T00:00:01Z",
                            "state": "SHIP_TERMINAL_ANCHOR_PENDING",
                            "data": {"outcome": "SHIP_FAILED",
                                     "record_sha256": supervisor.sha256_str(forged_text)}})
                + "\n")

    rc = supervisor.ship_cmd(str(cr), str(run_dir))
    assert rc == 2, "the forged terminal must be refused, never re-anchored"
    assert counter.read_text() == "x", "and nothing re-ran"
