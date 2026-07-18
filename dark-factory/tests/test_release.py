"""M41 Task 4: df_release — signed K-of-N release approvals for irreversible
ship actions. Mirrors test_override/test_waiver: claim sign/verify, threshold,
expiry, replay ledger, wrong-artifact/run binding, action-name coverage."""
import datetime
import os

import pytest

import df_custody
import df_release

pytestmark = pytest.mark.skipif(
    df_custody._CRYPTOGRAPHY_IMPORT_ERROR is not None,
    reason="cryptography not installed")

NOW = datetime.datetime(2026, 7, 17, 12, 0, 0, tzinfo=datetime.timezone.utc)


def _kp():
    return df_custody.generate_keypair()  # (priv, pub)


def _claim(run_id="run-1", oid="a" * 64, actions=("deploy",), issued=None, expires=None,
           nonce="nonce-1"):
    return {
        "release_version": df_release.RELEASE_VERSION,
        "run_id": run_id,
        "artifact_object_id": oid,
        "action_names": list(actions) if actions != "*" else "*",
        "issued_at": issued or "2026-07-17T00:00:00Z",
        "expires_at": expires or "2026-07-18T00:00:00Z",
        "nonce": nonce,
    }


def _sign(claim, priv):
    return {"approver": df_custody.public_from_private(priv),
            "sig": df_custody.sign_manifest(priv, df_release.release_signing_bytes(claim))}


def test_valid_single_signer_verifies():
    priv, pub = _kp()
    claim = _claim()
    ok, reason, count, nonce = df_release.verify_release(
        claim=claim, signatures=[_sign(claim, priv)], approvers=[pub], threshold=1,
        run_id="run-1", artifact_object_id="a" * 64, now=NOW)
    assert ok and count == 1 and nonce == "nonce-1"


def test_threshold_needs_distinct_signers():
    p1, pub1 = _kp()
    p2, pub2 = _kp()
    claim = _claim()
    # two sigs from the SAME approver count once
    ok, *_ = df_release.verify_release(
        claim=claim, signatures=[_sign(claim, p1), _sign(claim, p1)],
        approvers=[pub1, pub2], threshold=2, run_id="run-1",
        artifact_object_id="a" * 64, now=NOW)
    assert not ok
    ok2, _r, count, _n = df_release.verify_release(
        claim=claim, signatures=[_sign(claim, p1), _sign(claim, p2)],
        approvers=[pub1, pub2], threshold=2, run_id="run-1",
        artifact_object_id="a" * 64, now=NOW)
    assert ok2 and count == 2


def test_zero_threshold_never_satisfiable():
    priv, pub = _kp()
    claim = _claim()
    ok, reason, *_ = df_release.verify_release(
        claim=claim, signatures=[_sign(claim, priv)], approvers=[pub], threshold=0,
        run_id="run-1", artifact_object_id="a" * 64, now=NOW)
    assert not ok and "no release-approval policy" in reason


def test_wrong_run_binding_rejected():
    priv, pub = _kp()
    claim = _claim(run_id="run-1")
    ok, reason, *_ = df_release.verify_release(
        claim=claim, signatures=[_sign(claim, priv)], approvers=[pub], threshold=1,
        run_id="run-OTHER", artifact_object_id="a" * 64, now=NOW)
    assert not ok and "run_id" in reason


def test_wrong_artifact_binding_rejected():
    priv, pub = _kp()
    claim = _claim(oid="a" * 64)
    ok, reason, *_ = df_release.verify_release(
        claim=claim, signatures=[_sign(claim, priv)], approvers=[pub], threshold=1,
        run_id="run-1", artifact_object_id="b" * 64, now=NOW)
    assert not ok and "artifact" in reason


def test_expiry_is_live_clock():
    priv, pub = _kp()
    claim = _claim(issued="2026-07-17T00:00:00Z", expires="2026-07-17T06:00:00Z")
    ok, reason, *_ = df_release.verify_release(
        claim=claim, signatures=[_sign(claim, priv)], approvers=[pub], threshold=1,
        run_id="run-1", artifact_object_id="a" * 64, now=NOW)  # NOW is 12:00, past 06:00
    assert not ok and "validity window" in reason


def test_schema_pin_rejects_other_version():
    priv, pub = _kp()
    claim = _claim()
    claim["release_version"] = "2"
    ok, reason, *_ = df_release.verify_release(
        claim=claim, signatures=[_sign(claim, priv)], approvers=[pub], threshold=1,
        run_id="run-1", artifact_object_id="a" * 64, now=NOW)
    assert not ok and "release_version" in reason


def test_nonce_replay_rejected_when_ledger_supplied():
    priv, pub = _kp()
    claim = _claim(nonce="used-nonce")
    ok, reason, *_ = df_release.verify_release(
        claim=claim, signatures=[_sign(claim, priv)], approvers=[pub], threshold=1,
        run_id="run-1", artifact_object_id="a" * 64, now=NOW,
        used_nonces={"used-nonce"})
    assert not ok and "replay" in reason
    # but with used_nonces=None (ship-time coverage re-check), it is allowed
    ok2, *_ = df_release.verify_release(
        claim=claim, signatures=[_sign(claim, priv)], approvers=[pub], threshold=1,
        run_id="run-1", artifact_object_id="a" * 64, now=NOW, used_nonces=None)
    assert ok2


def test_signature_over_tampered_scope_fails():
    priv, pub = _kp()
    claim = _claim(actions=("deploy",))
    entry = _sign(claim, priv)
    claim["action_names"] = ["deploy", "migrate"]  # widen scope AFTER signing
    ok, *_ = df_release.verify_release(
        claim=claim, signatures=[entry], approvers=[pub], threshold=1,
        run_id="run-1", artifact_object_id="a" * 64, now=NOW)
    assert not ok  # the signature no longer covers the widened claim


def test_nonce_ledger_roundtrip(tmp_path):
    cr = str(tmp_path)
    assert df_release.load_used_nonces(cr) == set()
    df_release.record_nonce(cr, "n1", run_id="r", artifact_object_id="o", applied_at="t")
    assert "n1" in df_release.load_used_nonces(cr)
    with pytest.raises(df_release.ReleaseError):
        df_release.record_nonce(cr, "n1", run_id="r", artifact_object_id="o", applied_at="t")


def test_corrupt_ledger_fails_closed(tmp_path):
    p = tmp_path / df_release.NONCE_LEDGER_FILE
    p.write_text("not json")
    with pytest.raises(df_release.ReleaseError):
        df_release.load_used_nonces(str(tmp_path))


def test_approval_context_covers_named_and_wildcard():
    priv, pub = _kp()
    claim = _claim(actions=("deploy",))
    att = {"claim": claim, "signatures": [_sign(claim, priv)]}
    ctx = df_release.ApprovalContext(attestation=att, approvers=[pub], threshold=1,
                                     run_id="run-1", artifact_object_id="a" * 64)
    assert ctx.covers("deploy", now=NOW)[0]
    assert not ctx.covers("migrate", now=NOW)[0]  # out of scope

    wclaim = _claim(actions="*", nonce="n2")
    watt = {"claim": wclaim, "signatures": [_sign(wclaim, priv)]}
    wctx = df_release.ApprovalContext(attestation=watt, approvers=[pub], threshold=1,
                                      run_id="run-1", artifact_object_id="a" * 64)
    assert wctx.covers("anything", now=NOW)[0]


def test_empty_context_covers_nothing():
    ctx = df_release.ApprovalContext(attestation=None, approvers=["x"], threshold=1,
                                     run_id="run-1", artifact_object_id="a" * 64)
    covered, reason = ctx.covers("deploy", now=NOW)
    assert not covered and "no release attestation" in reason


def test_context_expired_flips_to_gated():
    priv, pub = _kp()
    claim = _claim(actions=("deploy",), expires="2026-07-17T06:00:00Z")
    att = {"claim": claim, "signatures": [_sign(claim, priv)]}
    ctx = df_release.ApprovalContext(attestation=att, approvers=[pub], threshold=1,
                                     run_id="run-1", artifact_object_id="a" * 64)
    assert not ctx.covers("deploy", now=NOW)[0]  # NOW past expiry


def test_normalize_action_names_rejects_garbage():
    with pytest.raises(df_release.ReleaseError):
        df_release.normalize_action_names([])
    with pytest.raises(df_release.ReleaseError):
        df_release.normalize_action_names([1, 2])
    assert df_release.normalize_action_names("*") == "*"
    assert df_release.normalize_action_names(["b", "a", "a"]) == ("a", "b")
