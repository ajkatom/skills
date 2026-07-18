"""M41 Task 2/6: df_ship (the action runner) + supervisor ship-phase integration.

df_ship unit tests: ordered run; rollback-in-reverse on failure; the approval
gate; the reserve-before journal; brokered creds reach the child env but never
the journal/log. Supervisor integration (DETERMINISTIC — a hand-sealed qualified
run, stub actions, NO real infra/Docker): non-qualified never ships; a reversible
ship SHIPS; an irreversible action -> SHIP_APPROVAL_PENDING -> df-release attach
-> SHIPPED; a crash between INTENT and RESULT -> SHIP_UNKNOWN_OUTCOME until
reconcile."""
import datetime
import json
import os
import sys

import pytest

import df_audit
import df_custody
import df_release
import df_seal
import df_ship
import supervisor
from df_common import canonical_json

HERE = os.path.dirname(os.path.abspath(__file__))
STUB = os.path.join(HERE, "fixtures", "ship_stub.py")

_CRYPTO = df_custody._CRYPTOGRAPHY_IMPORT_ERROR is None


class FakeJournal:
    def __init__(self):
        self.events = []

    def write(self, state, **data):
        self.events.append({"state": state, "data": data})

    def states(self):
        return [e["state"] for e in self.events]


def _touch(name, marker, rollback_marker=None):
    a = {"name": name, "run": [sys.executable, STUB, "touch", str(marker)],
         "reversible": True, "timeout_s": 30, "cwd": None, "creds": {"env": []}}
    if rollback_marker is not None:
        a["rollback"] = [sys.executable, STUB, "remove", str(marker)]
    else:
        a["rollback"] = None
    return a


def _fail(name, own_rollback_marker=None):
    a = {"name": name, "run": [sys.executable, STUB, "fail"], "reversible": True,
         "timeout_s": 30, "cwd": None, "creds": {"env": []}}
    a["rollback"] = ([sys.executable, STUB, "touch", str(own_rollback_marker)]
                     if own_rollback_marker is not None else None)
    return a


def _no_creds(action):
    return {}


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


# --------------------------------------------------------------------------
# df_ship unit tests
# --------------------------------------------------------------------------
def test_ordered_run_all_succeed_ships(tmp_path):
    m1, m2 = tmp_path / "m1", tmp_path / "m2"
    ws = tmp_path / "ws"; ws.mkdir()
    j = FakeJournal()
    res = df_ship.run_actions(
        [_touch("a", m1), _touch("b", m2)], str(ws),
        approval_ctx=df_release.ApprovalContext(attestation=None, approvers=[], threshold=0,
                                                run_id="r", artifact_object_id="o"),
        journal=j, run_id="r", base_env=os.environ.copy(), base_secret_values=[],
        resolve_action_creds=_no_creds, now_fn=_now)
    assert res["outcome"] == df_ship.SHIPPED
    assert m1.exists() and m2.exists()
    assert [a["name"] for a in res["actions"]] == ["a", "b"]
    # reserve-before: every action journaled INTENT then RESULT with the same key
    intents = [e for e in j.events if e["state"] == "SHIP_ACTION_INTENT"]
    results = [e for e in j.events if e["state"] == "SHIP_ACTION_RESULT"]
    assert len(intents) == 2 and len(results) == 2
    assert j.states().index("SHIP_ACTION_INTENT") < j.states().index("SHIP_ACTION_RESULT")
    assert intents[0]["data"]["idempotency_key"] == results[0]["data"]["idempotency_key"]


def test_failure_rolls_back_in_reverse(tmp_path):
    m_a = tmp_path / "m_a"
    b_rb = tmp_path / "b_rollback_ran"
    ws = tmp_path / "ws"; ws.mkdir()
    j = FakeJournal()
    res = df_ship.run_actions(
        [_touch("a", m_a, rollback_marker=True), _fail("b", own_rollback_marker=b_rb)], str(ws),
        approval_ctx=df_release.ApprovalContext(attestation=None, approvers=[], threshold=0,
                                                run_id="r", artifact_object_id="o"),
        journal=j, run_id="r", base_env=os.environ.copy(), base_secret_values=[],
        resolve_action_creds=_no_creds, now_fn=_now)
    assert res["outcome"] == df_ship.SHIP_FAILED and res["failed_action"] == "b"
    assert not m_a.exists()   # a's rollback ran (marker removed)
    assert b_rb.exists()      # the FAILED action's OWN rollback ran first
    # order: b's rollback (own) THEN a's rollback (reverse of successes)
    rb = [e["data"]["action"] for e in j.events if e["state"] == "SHIP_ROLLED_BACK"]
    assert rb == ["b", "a"]
    assert res["rollback_failed"] is False


def test_irreversible_without_approval_is_pending(tmp_path):
    marker = tmp_path / "deployed"
    ws = tmp_path / "ws"; ws.mkdir()
    action = {"name": "deploy", "run": [sys.executable, STUB, "touch", str(marker)],
              "reversible": False, "rollback": None, "timeout_s": 30, "cwd": None,
              "creds": {"env": []}}
    j = FakeJournal()
    res = df_ship.run_actions(
        [action], str(ws),
        approval_ctx=df_release.ApprovalContext(attestation=None, approvers=["x"], threshold=1,
                                                run_id="r", artifact_object_id="o"),
        journal=j, run_id="r", base_env=os.environ.copy(), base_secret_values=[],
        resolve_action_creds=_no_creds, now_fn=_now)
    assert res["outcome"] == df_ship.SHIP_APPROVAL_PENDING
    assert res["pending_action"] == "deploy"
    assert not marker.exists()  # NEVER ran
    assert "SHIP_APPROVAL_PENDING" in j.states()
    assert "SHIP_ACTION_INTENT" not in j.states()  # never even reserved


def test_brokered_creds_reach_child_but_never_journal_or_log(tmp_path, monkeypatch):
    secret = "S3CR3T-shipping-value-0987654321"
    monkeypatch.setenv("SHIP_SECRET", secret)
    ws = tmp_path / "ws"; ws.mkdir()
    log_dir = tmp_path / "logs"
    action = {"name": "echo", "run": [sys.executable, STUB, "echo-secret"], "reversible": True,
              "rollback": None, "timeout_s": 30, "cwd": None, "creds": {"env": ["SHIP_SECRET"]}}
    j = FakeJournal()
    res = df_ship.run_actions(
        [action], str(ws),
        approval_ctx=df_release.ApprovalContext(attestation=None, approvers=[], threshold=0,
                                                run_id="r", artifact_object_id="o"),
        journal=j, run_id="r", base_env={"PATH": os.environ["PATH"]}, base_secret_values=[],
        resolve_action_creds=supervisor._resolve_ship_action_creds,
        log_dir=str(log_dir), now_fn=_now)
    assert res["outcome"] == df_ship.SHIPPED
    # the child SAW the value (it echoed it) — but the captured log is REDACTED
    log = (log_dir / "echo.stdout").read_text()
    assert secret not in log and "***REDACTED***" in log
    # and the raw value is NOWHERE in the journal events
    assert secret not in json.dumps(j.events)


def test_missing_cred_fails_closed(tmp_path, monkeypatch):
    monkeypatch.delenv("SHIP_MISSING", raising=False)
    ws = tmp_path / "ws"; ws.mkdir()
    action = {"name": "x", "run": [sys.executable, STUB, "touch", str(tmp_path / "m")],
              "reversible": True, "rollback": None, "timeout_s": 30, "cwd": None,
              "creds": {"env": ["SHIP_MISSING"]}}
    j = FakeJournal()
    res = df_ship.run_actions(
        [action], str(ws),
        approval_ctx=df_release.ApprovalContext(attestation=None, approvers=[], threshold=0,
                                                run_id="r", artifact_object_id="o"),
        journal=j, run_id="r", base_env=os.environ.copy(), base_secret_values=[],
        resolve_action_creds=supervisor._resolve_ship_action_creds, now_fn=_now)
    assert res["outcome"] == df_ship.SHIP_FAILED
    assert not (tmp_path / "m").exists()  # never ran
    assert "SHIP_CRED_FAILED" in j.states()


# --------------------------------------------------------------------------
# Supervisor integration (hand-sealed qualified run; deterministic; no Docker)
# --------------------------------------------------------------------------
def _base_config(tmp_path, tier, ship_block, *, signed=False):
    cfg = {
        "config_version": "0.1", "assurance": tier, "feedback": "ids",
        "max_iterations": 5, "workspace_root": str(tmp_path / "ws"),
        "roles": {"builder": {"adapter": sys.executable, "timeout_s": 60}},
        "budget": {"billing": "subscription"},
        "ship": ship_block,
    }
    if signed:
        # force signing ON (standard tier defaults it off unless a policy forces it)
        cfg["audit"] = {"signing": True, "key_path": str(tmp_path / "audit_keys" / "audit.key")}
    elif tier in ("hardened", "enterprise"):
        cfg["audit"] = {"key_path": str(tmp_path / "audit_keys" / "audit.key")}
    return cfg


def build_sealed_run(tmp_path, cr, config, artifact_files, *,
                     outcome="COMPLETE_QUALIFIED", qualified=True):
    """Materialize a SEALED, artifact-bound run_dir deterministically (no build
    loop, no sandbox, no Docker) so the ship phase can be driven directly. The
    manifest's config_sha256 is bound to the on-disk config exactly as a real
    run would seal it, so `ship`'s policy-binding check passes."""
    cr.mkdir(parents=True, exist_ok=True)
    (cr / "config.json").write_text(json.dumps(config))
    cfg = supervisor.load_config(str(cr))
    cfg["_control_root"] = str(cr)

    art = tmp_path / f"artifact_src_{cr.name}"
    art.mkdir()
    for name, content in artifact_files.items():
        (art / name).write_text(content)
    object_id = df_seal.freeze(str(art), supervisor._object_store_root(str(cr)))

    run_id = "20260717-120000-shiprun"
    run_dir = cr / "runs" / run_id
    run_dir.mkdir(parents=True)
    (run_dir / "journal.jsonl").write_text(
        '{"ts":"2026-07-17T00:00:00Z","state":"INIT","data":{}}\n', encoding="utf-8")

    audit_key = None
    if cfg["_audit"]["signing"]:
        audit_key = df_audit.load_or_create_key(cfg["_audit"]["key_path"])
    mf = {
        "invocation": run_id, "tier": config["assurance"],
        "config_sha256": cfg["_config_sha256"], "qualified": qualified, "outcome": outcome,
        "artifact": {"object_id": object_id, "file_count": len(artifact_files), "dir_count": 0},
        "iterations": 1, "regressions": [], "denial_probe_passed": qualified,
        "sandbox_backend": "test-sealed", "host_isolation": {"qualified": qualified},
        "app_security_qualified": qualified,
        "final_exam": {"ran": True, "passed": True, "count": 1},
        "security": {"checked": True, "failed": []},
    }
    supervisor.finalize_manifest(str(run_dir), mf, audit_key=audit_key)
    return cfg, run_dir, object_id, run_id


def _rev_ship(marker):
    return {"actions": [{"name": "merge", "run": [sys.executable, STUB, "touch", str(marker)],
                         "reversible": True, "timeout_s": 30}]}


def test_non_qualified_run_never_ships(tmp_path):
    cr = tmp_path / "control"
    marker = tmp_path / "SHOULD_NOT_EXIST"
    cfg, run_dir, _oid, _rid = build_sealed_run(
        tmp_path, cr, _base_config(tmp_path, "cooperative", _rev_ship(marker)),
        {"app.txt": "v1"}, outcome="COMPLETE_UNQUALIFIED", qualified=False)
    rc = supervisor.ship_cmd(str(cr), str(run_dir))
    assert rc == 2  # fail-closed refusal
    assert not marker.exists()
    assert not (run_dir / "ship_result.json").exists()


def test_reversible_ship_ships_on_sealed_bytes(tmp_path):
    cr = tmp_path / "control"
    marker = tmp_path / "merged"
    cfg, run_dir, object_id, _rid = build_sealed_run(
        tmp_path, cr, _base_config(tmp_path, "standard", _rev_ship(marker)), {"app.txt": "v1"})
    rc = supervisor.ship_cmd(str(cr), str(run_dir))
    assert rc == 0 and marker.exists()
    record = json.loads((run_dir / "ship_result.json").read_text())
    assert record["outcome"] == "SHIPPED"
    assert record["ship_workspace_object_id"] == object_id
    # manifest is untouched — qualified NOT re-opened by shipping
    manifest = json.loads((run_dir / "manifest.json").read_text())
    assert manifest["qualified"] is True and manifest["outcome"] == "COMPLETE_QUALIFIED"
    # idempotent: a second ship does not re-run
    marker.unlink()
    assert supervisor.ship_cmd(str(cr), str(run_dir)) == 0
    assert not marker.exists()  # not re-run


def test_ship_acts_on_sealed_object_not_drifted_workspace(tmp_path):
    # The action copies the artifact's app.txt into an out-of-tree marker so we
    # can prove the cwd was the MATERIALIZED sealed object, not some other tree.
    cr = tmp_path / "control"
    out = tmp_path / "captured.txt"
    copy_script = tmp_path / "copy.py"
    copy_script.write_text(
        "import sys,shutil; shutil.copy('app.txt', sys.argv[1])\n")
    ship = {"actions": [{"name": "capture",
                         "run": [sys.executable, str(copy_script), str(out)],
                         "reversible": True, "timeout_s": 30}]}
    cfg, run_dir, _oid, _rid = build_sealed_run(
        tmp_path, cr, _base_config(tmp_path, "standard", ship), {"app.txt": "SEALED-CONTENT-42"})
    assert supervisor.ship_cmd(str(cr), str(run_dir)) == 0
    assert out.read_text() == "SEALED-CONTENT-42"


@pytest.mark.skipif(not _CRYPTO, reason="cryptography not installed")
def test_irreversible_pending_then_release_attach_then_ships(tmp_path):
    priv, pub = df_custody.generate_keypair()
    cr = tmp_path / "control"
    marker = tmp_path / "deployed"
    ship = {
        "actions": [{"name": "deploy", "run": [sys.executable, STUB, "touch", str(marker)],
                     "reversible": False, "rollback": [sys.executable, STUB, "remove", str(marker)],
                     "timeout_s": 30}],
        "approval": {"approvers": [pub], "threshold": 1},
    }
    cfg, run_dir, object_id, run_id = build_sealed_run(
        tmp_path, cr, _base_config(tmp_path, "hardened", ship), {"app.txt": "v1"})

    # 1) ship with no approval -> SHIP_APPROVAL_PENDING; nothing ran.
    assert supervisor.ship_cmd(str(cr), str(run_dir)) == 3
    assert not marker.exists()
    assert json.loads((run_dir / "ship_result.json").read_text())["outcome"] == \
        "SHIP_APPROVAL_PENDING"

    # 2) df-release sign the claim bound to THIS run+artifact, scoped to `deploy`.
    manifest_path = str(run_dir / "manifest.json")
    manifest_obj = json.loads((run_dir / "manifest.json").read_text())
    claim = {
        "release_version": df_release.RELEASE_VERSION, "run_id": run_id,
        "artifact_object_id": object_id, "action_names": ["deploy"],
        "issued_at": "2026-07-17T00:00:00Z", "expires_at": "2099-01-01T00:00:00Z",
        "nonce": "ship-nonce-1",
    }
    sig = df_custody.sign_manifest(priv, df_release.release_signing_bytes(claim))
    (cr / supervisor.RELEASE_APPROVAL_FILE).write_text(
        json.dumps({"claim": claim, "signatures": [{"approver": pub, "sig": sig}]}))

    # 3) attach -> release_attestation.json + nonce ledger + audit anchor.
    assert supervisor.attach_release(str(cr), str(run_dir)) == 0
    assert (run_dir / supervisor.RELEASE_ATTESTATION_FILE).exists()
    assert "ship-nonce-1" in df_release.load_used_nonces(str(cr))

    # 4) ship again -> the irreversible action now runs -> SHIPPED.
    assert supervisor.ship_cmd(str(cr), str(run_dir)) == 0
    assert marker.exists()
    assert json.loads((run_dir / "ship_result.json").read_text())["outcome"] == "SHIPPED"


@pytest.mark.skipif(not _CRYPTO, reason="cryptography not installed")
def test_release_attach_rejects_wrong_artifact(tmp_path):
    priv, pub = df_custody.generate_keypair()
    cr = tmp_path / "control"
    ship = {"actions": [{"name": "deploy", "run": [sys.executable, STUB, "fail"],
                         "reversible": False, "timeout_s": 30}],
            "approval": {"approvers": [pub], "threshold": 1}}
    cfg, run_dir, object_id, run_id = build_sealed_run(
        tmp_path, cr, _base_config(tmp_path, "hardened", ship), {"app.txt": "v1"})
    claim = {
        "release_version": df_release.RELEASE_VERSION, "run_id": run_id,
        "artifact_object_id": "f" * 64,  # WRONG artifact
        "action_names": ["deploy"], "issued_at": "2026-07-17T00:00:00Z",
        "expires_at": "2099-01-01T00:00:00Z", "nonce": "n-wrong",
    }
    sig = df_custody.sign_manifest(priv, df_release.release_signing_bytes(claim))
    (cr / supervisor.RELEASE_APPROVAL_FILE).write_text(
        json.dumps({"claim": claim, "signatures": [{"approver": pub, "sig": sig}]}))
    assert supervisor.attach_release(str(cr), str(run_dir)) == 3  # PENDING, refused
    assert not (run_dir / supervisor.RELEASE_ATTESTATION_FILE).exists()


def test_crash_between_intent_and_result_is_unknown_until_reconcile(tmp_path):
    cr = tmp_path / "control"
    marker = tmp_path / "merged"
    cfg, run_dir, _oid, run_id = build_sealed_run(
        tmp_path, cr, _base_config(tmp_path, "standard", _rev_ship(marker)), {"app.txt": "v1"})
    # Simulate a crash: a SHIP_ACTION_INTENT fsync'd with NO matching RESULT.
    idk = df_ship.idempotency_key(run_id, "merge", 0)
    (run_dir / supervisor.SHIP_JOURNAL_FILE).write_text(
        json.dumps({"ts": "2026-07-17T00:00:00Z", "state": "SHIP_ACTION_INTENT",
                    "data": {"action": "merge", "index": 0, "idempotency_key": idk}}) + "\n")

    # plain continue -> refuse (exit 11), never a blind re-run.
    assert supervisor.ship_cmd(str(cr), str(run_dir), decision="continue") == \
        supervisor.UNKNOWN_OUTCOME
    assert not marker.exists()

    # reconcile -> operator consents; the action re-runs and ships.
    assert supervisor.ship_cmd(str(cr), str(run_dir), decision="reconcile") == 0
    assert marker.exists()


def test_unknown_outcome_abort_seals_ship_failed(tmp_path):
    cr = tmp_path / "control"
    marker = tmp_path / "merged"
    cfg, run_dir, _oid, run_id = build_sealed_run(
        tmp_path, cr, _base_config(tmp_path, "standard", _rev_ship(marker)), {"app.txt": "v1"})
    idk = df_ship.idempotency_key(run_id, "merge", 0)
    (run_dir / supervisor.SHIP_JOURNAL_FILE).write_text(
        json.dumps({"ts": "2026-07-17T00:00:00Z", "state": "SHIP_ACTION_INTENT",
                    "data": {"action": "merge", "index": 0, "idempotency_key": idk}}) + "\n")
    assert supervisor.ship_cmd(str(cr), str(run_dir), decision="abort") == 3
    assert not marker.exists()
    assert json.loads((run_dir / "ship_result.json").read_text())["outcome"] == "SHIP_FAILED"


@pytest.mark.skipif(not _CRYPTO, reason="cryptography not installed")
def test_swapped_approver_allowlist_with_stale_hmac_is_refused(tmp_path):
    """CRITICAL regression (M41 review): an attacker with ONLY control-root write
    + a fresh self-generated keypair (no legit approver key, no audit HMAC key)
    swaps ship.approval.approvers to their own pubkey, edits config_sha256 to
    match the new config, recomputes the PLAIN manifest.sha256, and leaves the
    HMAC stale. Both `df-release attach` AND `ship` must REFUSE (manifest
    authentication fails), and the irreversible action must NEVER spawn."""
    from df_common import canonical_json, sha256_str

    legit_priv, legit_pub = df_custody.generate_keypair()
    atk_priv, atk_pub = df_custody.generate_keypair()
    cr = tmp_path / "control"
    marker = tmp_path / "prod_deployed"
    ship = {
        "actions": [{"name": "deploy", "run": [sys.executable, STUB, "touch", str(marker)],
                     "reversible": False, "timeout_s": 30}],
        "approval": {"approvers": [legit_pub], "threshold": 1},
    }
    cfg, run_dir, object_id, run_id = build_sealed_run(
        tmp_path, cr, _base_config(tmp_path, "hardened", ship), {"app.txt": "v1"})

    # --- the attack: rewrite config.json to the attacker's allowlist ---
    raw = json.loads((cr / "config.json").read_text())
    raw["ship"]["approval"]["approvers"] = [atk_pub]
    (cr / "config.json").write_text(json.dumps(raw))
    new_config_sha = sha256_str(canonical_json(raw))
    # edit the sealed manifest's config_sha256 to match the NEW config + recompute
    # the PLAIN sha256 sidecar, leaving manifest.hmac (over the ORIGINAL bytes) stale.
    manifest = json.loads((run_dir / "manifest.json").read_text())
    manifest["config_sha256"] = new_config_sha
    tampered = canonical_json(manifest)
    (run_dir / "manifest.json").write_text(tampered)
    (run_dir / "manifest.sha256").write_text(sha256_str(tampered) + "\n")

    # attacker self-signs a release with their OWN key against the swapped allowlist
    claim = {
        "release_version": df_release.RELEASE_VERSION, "run_id": run_id,
        "artifact_object_id": object_id, "action_names": ["deploy"],
        "issued_at": "2026-07-17T00:00:00Z", "expires_at": "2099-01-01T00:00:00Z",
        "nonce": "atk-nonce",
    }
    sig = df_custody.sign_manifest(atk_priv, df_release.release_signing_bytes(claim))
    (cr / supervisor.RELEASE_APPROVAL_FILE).write_text(
        json.dumps({"claim": claim, "signatures": [{"approver": atk_pub, "sig": sig}]}))

    # attach must REFUSE: the manifest's HMAC (over the original bytes) no longer
    # matches the tampered manifest text -> TAMPERED -> fail-closed.
    assert supervisor.attach_release(str(cr), str(run_dir)) == 3
    assert not (run_dir / supervisor.RELEASE_ATTESTATION_FILE).exists()

    # even if the attacker forged an attestation file by hand, `ship` must ALSO
    # refuse at the manifest-authentication gate, before running anything.
    (run_dir / supervisor.RELEASE_ATTESTATION_FILE).write_text(
        json.dumps({"attestation_version": "1", "claim": claim,
                    "signatures": [{"approver": atk_pub, "sig": sig}],
                    "approvers_satisfied": [atk_pub], "qualified": True, "ts": "t"}))
    assert supervisor.ship_cmd(str(cr), str(run_dir)) == 2  # fail-closed refusal
    assert not marker.exists()  # the irreversible action NEVER spawned


def test_signed_unqualified_run_flipped_to_qualified_is_refused(tmp_path):
    """CRITICAL regression (M41 review): a SIGNED but UNqualified run whose
    manifest is edited to qualified:true + outcome COMPLETE_QUALIFIED (and the
    plain sha256 recomputed, HMAC left stale) must NOT be shippable — the HMAC
    authentication catches the flip (invariant #1)."""
    from df_common import canonical_json, sha256_str

    cr = tmp_path / "control"
    marker = tmp_path / "SHOULD_NOT_SHIP"
    # a signed run (force audit.signing via signed=True) that sealed UNQUALIFIED
    cfg, run_dir, _oid, _rid = build_sealed_run(
        tmp_path, cr,
        _base_config(tmp_path, "standard", _rev_ship(marker), signed=True),
        {"app.txt": "v1"}, outcome="SECURITY_GATE_FAILED", qualified=False)

    # legit state: refused because not qualified.
    assert supervisor.ship_cmd(str(cr), str(run_dir)) == 2
    assert not marker.exists()

    # --- the attack: flip qualified/outcome, recompute plain sha256, stale HMAC ---
    manifest = json.loads((run_dir / "manifest.json").read_text())
    manifest["qualified"] = True
    manifest["outcome"] = "COMPLETE_QUALIFIED"
    tampered = canonical_json(manifest)
    (run_dir / "manifest.json").write_text(tampered)
    (run_dir / "manifest.sha256").write_text(sha256_str(tampered) + "\n")

    # still refused: manifest.hmac (over the original bytes) fails -> TAMPERED.
    assert supervisor.ship_cmd(str(cr), str(run_dir)) == 2
    assert not marker.exists()


def test_failing_action_seals_ship_failed_but_stays_qualified(tmp_path):
    cr = tmp_path / "control"
    m_ok = tmp_path / "ok"
    ship = {"actions": [
        {"name": "step1", "run": [sys.executable, STUB, "touch", str(m_ok)],
         "reversible": True, "rollback": [sys.executable, STUB, "remove", str(m_ok)],
         "timeout_s": 30},
        {"name": "step2", "run": [sys.executable, STUB, "fail"], "reversible": True,
         "timeout_s": 30},
    ]}
    cfg, run_dir, _oid, _rid = build_sealed_run(
        tmp_path, cr, _base_config(tmp_path, "standard", ship), {"app.txt": "v1"})
    assert supervisor.ship_cmd(str(cr), str(run_dir)) == 3
    assert not m_ok.exists()  # step1 rolled back after step2 failed
    record = json.loads((run_dir / "ship_result.json").read_text())
    assert record["outcome"] == "SHIP_FAILED" and record["failed_action"] == "step2"
    # qualified NOT re-opened
    assert json.loads((run_dir / "manifest.json").read_text())["qualified"] is True
