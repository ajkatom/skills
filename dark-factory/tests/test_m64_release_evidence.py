"""M64 (Codex R6): DF-R6-08 crash-consistent release attach + DF-R6-07 evidence
bundle v2.

  * DF-R6-08 — `attach_release` recorded the one-time nonce FIRST and ignored the
    anchor result: a crash after nonce/before-attestation BURNED the approval,
    and an anchor failure printed RELEASE ATTESTED with no chain entry (which the
    ship path then rejected). The transaction is reordered so the nonce is
    consumed LAST, only after the attestation + receipt + a CHECKED signed anchor
    are durable — a crash at any earlier point leaves the nonce unconsumed and a
    plain re-run reattaches idempotently. A planted (unanchored) attestation is
    ignored at ship time.
  * DF-R6-07 — the evidence bundle must VERIFY, not summarize.
"""
import json
import os
import sys

import pytest

import df_custody
import df_release
import supervisor
from test_ship import build_sealed_run, _base_config

try:
    import cryptography  # noqa: F401
    _CRYPTO = True
except ImportError:
    _CRYPTO = False

STUB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "ship_stub.py")


def _hardened_release_run(tmp_path, marker):
    priv, pub = df_custody.generate_keypair()
    cr = tmp_path / "control"
    ship = {"actions": [{"name": "deploy", "run": [sys.executable, STUB, "touch", str(marker)],
                         "reversible": False,
                         "rollback": [sys.executable, STUB, "remove", str(marker)],
                         "timeout_s": 30}],
            "approval": {"approvers": [pub], "threshold": 1}}
    cfg, run_dir, object_id, run_id = build_sealed_run(
        tmp_path, cr, _base_config(tmp_path, "hardened", ship), {"app.txt": "v1"})
    claim = {
        "release_version": df_release.RELEASE_VERSION, "run_id": run_id,
        "artifact_object_id": object_id, "action_names": ["deploy"],
        "issued_at": "2026-07-17T00:00:00Z", "expires_at": "2099-01-01T00:00:00Z",
        "nonce": "ship-nonce-1",
    }
    sig = df_custody.sign_manifest(priv, df_release.release_signing_bytes(claim))
    (cr / supervisor.RELEASE_APPROVAL_FILE).write_text(
        json.dumps({"claim": claim, "signatures": [{"approver": pub, "sig": sig}]}))
    return cr, run_dir, object_id, run_id


@pytest.mark.skipif(not _CRYPTO, reason="cryptography not installed")
def test_crash_before_nonce_leaves_approval_reattachable(tmp_path, monkeypatch):
    marker = tmp_path / "deployed"
    cr, run_dir, oid, rid = _hardened_release_run(tmp_path, marker)

    # Simulate a crash AFTER the attestation/anchor but BEFORE nonce consumption.
    def _boom(*a, **k):
        raise KeyboardInterrupt("crash before nonce is recorded")
    monkeypatch.setattr(df_release, "record_nonce", _boom)
    with pytest.raises(KeyboardInterrupt):
        supervisor.attach_release(str(cr), str(run_dir))
    # The one-time approval was NOT burned.
    assert "ship-nonce-1" not in df_release.load_used_nonces(str(cr))

    # A plain re-run (same collected claim) reattaches idempotently — no new
    # approver signatures needed.
    monkeypatch.undo()
    assert supervisor.attach_release(str(cr), str(run_dir)) == 0
    assert "ship-nonce-1" in df_release.load_used_nonces(str(cr))
    assert supervisor.ship_cmd(str(cr), str(run_dir)) == 0
    assert marker.exists()


@pytest.mark.skipif(not _CRYPTO, reason="cryptography not installed")
def test_anchor_failure_is_evidence_pending_not_false_success(tmp_path, monkeypatch):
    marker = tmp_path / "deployed"
    cr, run_dir, oid, rid = _hardened_release_run(tmp_path, marker)

    real_anchor = supervisor._anchor_ship_local

    def _fail_release_anchor(cfg, control_root, run_id, text, kind):
        if kind == "release":
            return "anchor_failed"
        return real_anchor(cfg, control_root, run_id, text, kind)
    monkeypatch.setattr(supervisor, "_anchor_ship_local", _fail_release_anchor)

    rc = supervisor.attach_release(str(cr), str(run_dir))
    assert rc == supervisor.SHIP_EVIDENCE_PENDING_EXIT, "a failed anchor must NOT be a success"
    assert "ship-nonce-1" not in df_release.load_used_nonces(str(cr)), "nonce stays unconsumed"

    # Signer recovers -> a plain re-run finishes anchoring + consumes the nonce.
    monkeypatch.undo()
    assert supervisor.attach_release(str(cr), str(run_dir)) == 0
    assert "ship-nonce-1" in df_release.load_used_nonces(str(cr))


@pytest.mark.skipif(not _CRYPTO, reason="cryptography not installed")
def test_planted_unanchored_attestation_is_ignored_at_ship(tmp_path):
    marker = tmp_path / "deployed"
    cr, run_dir, oid, rid = _hardened_release_run(tmp_path, marker)
    # Attacker PLANTS a well-formed attestation (never went through attach, so it
    # is NOT in the signed chain) to try to authorize the irreversible action.
    forged = {"attestation_version": "1",
              "claim": json.loads((cr / supervisor.RELEASE_APPROVAL_FILE).read_text())["claim"],
              "signatures": [], "approvers_satisfied": [], "qualified": True,
              "ts": "2026-07-20T00:00:00Z"}
    (run_dir / supervisor.RELEASE_ATTESTATION_FILE).write_text(
        supervisor.canonical_json(forged), encoding="utf-8")

    # ship must NOT run the irreversible action — the attestation covers nothing.
    rc = supervisor.ship_cmd(str(cr), str(run_dir))
    assert rc == 3, "an unanchored planted attestation must not authorize the action"
    assert not marker.exists()


# ---------------------------------------------------------------------------
# DF-R6-07 — evidence bundle v2 VERIFIES, and production mode fails closed.
# ---------------------------------------------------------------------------

import df_evidence_bundle
from test_supervisor import FAKE, setup_control, stub_candidate_sandbox


def _standard_converged_run(tmp_path, monkeypatch):
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")
    cfg = json.loads((cr / "config.json").read_text())
    cfg["assurance"] = "standard"
    (cr / "config.json").write_text(json.dumps(cfg), encoding="utf-8")
    stub_candidate_sandbox(monkeypatch)
    monkeypatch.setattr(supervisor, "resolve_isolation",
                        lambda *a, **k: ("standard", [], "fake-standard-backend", True))
    assert supervisor.run(str(cr), None) == 0
    return cr, cr / "runs" / os.listdir(cr / "runs")[0]


def test_bundle_v2_seals_and_reports_source_identity(tmp_path, monkeypatch):
    cr, run_dir = _standard_converged_run(tmp_path, monkeypatch)
    mf = json.loads((run_dir / "manifest.json").read_text())
    # DF-R6-07: source identity is SEALED into the manifest (not a post-hoc
    # rev-parse); this repo is a git checkout, so a commit is present.
    assert "source_identity" in mf
    bundle, err = df_evidence_bundle.assemble(str(cr), str(run_dir))
    assert err is None
    assert bundle["source"]["sealed_commit"] == mf["source_identity"]["commit"]


def test_bundle_v2_verifies_the_manifest_not_just_hashes_it(tmp_path, monkeypatch):
    cr, run_dir = _standard_converged_run(tmp_path, monkeypatch)
    bundle, err = df_evidence_bundle.assemble(str(cr), str(run_dir))
    assert err is None
    # a standard (unsigned) run: manifest verify_status is a real status string.
    assert bundle["manifest"]["verify_status"] in ("OK", "UNVERIFIED") \
        or bundle["manifest"]["verify_status"].startswith(("OK", "UNBOUND"))
    assert "chain_member" in bundle["manifest"]


def test_bundle_v2_artifact_id_from_sealed_manifest(tmp_path, monkeypatch):
    cr, run_dir = _standard_converged_run(tmp_path, monkeypatch)
    mf = json.loads((run_dir / "manifest.json").read_text())
    bundle, err = df_evidence_bundle.assemble(str(cr), str(run_dir))
    # authoritative location — manifest.artifact.object_id, never ship-result.
    assert bundle["artifact_object_id"] == (mf.get("artifact") or {}).get("object_id")


def test_bundle_production_mode_fails_closed_on_an_incomplete_exercise(tmp_path, monkeypatch):
    # A cooperative (unqualified, no ship/custody) run can NEVER read as a
    # production-GO bundle.
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")
    assert supervisor.run(str(cr), None) == 0
    run_dir = cr / "runs" / os.listdir(cr / "runs")[0]
    bundle, err = df_evidence_bundle.assemble(
        str(cr), str(run_dir), require_production=True)
    assert err is None
    assert bundle["production_ready"] is False
    assert bundle["production_unmet"], "must enumerate what is missing"
