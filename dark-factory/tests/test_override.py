"""M36b (Part A) unit tests for df_override — the signed resume-override
primitive. Exercises the canonical signing bytes, params validation, run
binding, expiry, replay via the nonce ledger, distinct-signer threshold
counting, and the fail-closed absent-policy default. Crypto is real ed25519 via
df_custody; skipped only if `cryptography` is not installed (same guard as the
split-custody/waiver tests)."""
import datetime
import json
import os

import pytest

import df_override
import supervisor
from test_supervisor import STUBBORN, setup_control

df_custody = pytest.importorskip("df_custody")
pytest.importorskip("cryptography")

UTC = datetime.timezone.utc
NOW = datetime.datetime(2027, 1, 1, tzinfo=UTC)


def _keypair():
    return df_custody.generate_keypair()  # (private_hex, public_hex)


def _make_override(priv, *, run_id="RUN-A", new_ceiling=50.0,
                   issued_at="2026-01-01T00:00:00Z", expires_at="2030-01-01T00:00:00Z",
                   nonce="nonce-1", override_type="budget_ceiling", params=None):
    claim = {
        "override_version": df_override.OVERRIDE_VERSION,
        "run_id": run_id,
        "override_type": override_type,
        "params": params if params is not None else {"new_usd_ceiling": new_ceiling},
        "issued_at": issued_at,
        "expires_at": expires_at,
        "nonce": nonce,
    }
    sig = df_custody.sign_manifest(priv, df_override.override_signing_bytes(claim))
    pub = df_custody.public_from_private(priv)
    return claim, {"approver": pub, "sig": sig}, pub


# --- signing bytes / params ------------------------------------------------


def test_signing_bytes_reject_missing_field():
    with pytest.raises(df_override.OverrideError):
        df_override.override_signing_bytes({"override_version": "1"})


def test_signing_bytes_exclude_extra_keys():
    base = {
        "override_version": "1", "run_id": "R", "override_type": "budget_ceiling",
        "params": {"new_usd_ceiling": 1.0}, "issued_at": "2026-01-01T00:00:00Z",
        "expires_at": "2030-01-01T00:00:00Z", "nonce": "n",
    }
    with_extra = dict(base, evil="smuggled")
    assert df_override.override_signing_bytes(base) == df_override.override_signing_bytes(with_extra)


@pytest.mark.parametrize("bad", [0, -1, "5", True, float("inf"), float("nan"), None])
def test_validate_params_rejects_bad_ceiling(bad):
    with pytest.raises(df_override.OverrideError):
        df_override.validate_params("budget_ceiling", {"new_usd_ceiling": bad})


def test_validate_params_rejects_unknown_type():
    with pytest.raises(df_override.OverrideError):
        df_override.validate_params("credential_refresh", {})


# --- verify_override happy path + each fail-closed gate ---------------------


def test_valid_override_accepted():
    priv = df_custody.generate_keypair()[0]
    claim, sig_entry, pub = _make_override(priv)
    ok, reason, count, nonce = df_override.verify_override(
        claim=claim, signatures=[sig_entry], approvers=[pub], threshold=1,
        run_id="RUN-A", now=NOW, used_nonces=set())
    assert ok is True and count == 1 and nonce == "nonce-1"


def test_wrong_run_id_rejected():
    priv = df_custody.generate_keypair()[0]
    claim, sig_entry, pub = _make_override(priv, run_id="RUN-A")
    ok, reason, _, _ = df_override.verify_override(
        claim=claim, signatures=[sig_entry], approvers=[pub], threshold=1,
        run_id="RUN-B", now=NOW, used_nonces=set())
    assert ok is False and "run_id" in reason


def test_replayed_nonce_rejected():
    priv = df_custody.generate_keypair()[0]
    claim, sig_entry, pub = _make_override(priv, nonce="used-nonce")
    ok, reason, _, _ = df_override.verify_override(
        claim=claim, signatures=[sig_entry], approvers=[pub], threshold=1,
        run_id="RUN-A", now=NOW, used_nonces={"used-nonce"})
    assert ok is False and "replay" in reason.lower()


def test_expired_override_rejected():
    priv = df_custody.generate_keypair()[0]
    claim, sig_entry, pub = _make_override(priv, expires_at="2026-06-01T00:00:00Z")
    ok, reason, _, _ = df_override.verify_override(
        claim=claim, signatures=[sig_entry], approvers=[pub], threshold=1,
        run_id="RUN-A", now=NOW, used_nonces=set())
    assert ok is False and "validity" in reason.lower()


def test_not_yet_valid_rejected():
    priv = df_custody.generate_keypair()[0]
    claim, sig_entry, pub = _make_override(priv, issued_at="2028-01-01T00:00:00Z")
    ok, _, _, _ = df_override.verify_override(
        claim=claim, signatures=[sig_entry], approvers=[pub], threshold=1,
        run_id="RUN-A", now=NOW, used_nonces=set())
    assert ok is False


def test_absent_policy_threshold_zero_never_accepts():
    priv = df_custody.generate_keypair()[0]
    claim, sig_entry, pub = _make_override(priv)
    ok, reason, _, _ = df_override.verify_override(
        claim=claim, signatures=[sig_entry], approvers=[], threshold=0,
        run_id="RUN-A", now=NOW, used_nonces=set())
    assert ok is False and "no resume-override policy" in reason


def test_non_allowlisted_signer_not_counted():
    priv_in = df_custody.generate_keypair()[0]
    priv_out = df_custody.generate_keypair()[0]
    claim, _, pub_in = _make_override(priv_in)
    # sign with an OUT-of-allowlist key; only pub_in is allowlisted
    sig_out = df_custody.sign_manifest(priv_out, df_override.override_signing_bytes(claim))
    ok, _, count, _ = df_override.verify_override(
        claim=claim, signatures=[{"approver": df_custody.public_from_private(priv_out), "sig": sig_out}],
        approvers=[pub_in], threshold=1, run_id="RUN-A", now=NOW, used_nonces=set())
    assert ok is False and count == 0


def test_distinct_signer_counting_two_of_two():
    p1 = df_custody.generate_keypair()[0]
    p2 = df_custody.generate_keypair()[0]
    pub1 = df_custody.public_from_private(p1)
    pub2 = df_custody.public_from_private(p2)
    claim, e1, _ = _make_override(p1)
    e2 = {"approver": pub2,
          "sig": df_custody.sign_manifest(p2, df_override.override_signing_bytes(claim))}
    # duplicate of e1 must not inflate the count
    ok, _, count, _ = df_override.verify_override(
        claim=claim, signatures=[e1, e1, e2], approvers=[pub1, pub2], threshold=2,
        run_id="RUN-A", now=NOW, used_nonces=set())
    assert ok is True and count == 2


def test_tampered_params_break_signature():
    priv = df_custody.generate_keypair()[0]
    claim, sig_entry, pub = _make_override(priv, new_ceiling=50.0)
    claim["params"] = {"new_usd_ceiling": 999999.0}  # tamper AFTER signing
    ok, _, count, _ = df_override.verify_override(
        claim=claim, signatures=[sig_entry], approvers=[pub], threshold=1,
        run_id="RUN-A", now=NOW, used_nonces=set())
    assert ok is False and count == 0


def test_version_pin_rejects_v2():
    priv = df_custody.generate_keypair()[0]
    claim, sig_entry, pub = _make_override(priv)
    claim2 = dict(claim, override_version="2")
    ok, reason, _, _ = df_override.verify_override(
        claim=claim2, signatures=[sig_entry], approvers=[pub], threshold=1,
        run_id="RUN-A", now=NOW, used_nonces=set())
    assert ok is False and "schema pin" in reason


# --- nonce ledger ----------------------------------------------------------


def test_nonce_ledger_roundtrip(tmp_path):
    cr = str(tmp_path)
    assert df_override.load_used_nonces(cr) == set()
    df_override.record_nonce(cr, "n1", run_id="R", override_type="budget_ceiling",
                             applied_at="2027-01-01T00:00:00Z")
    df_override.record_nonce(cr, "n2", run_id="R", override_type="budget_ceiling",
                             applied_at="2027-01-01T00:00:00Z")
    assert df_override.load_used_nonces(cr) == {"n1", "n2"}


def test_nonce_ledger_double_record_refused(tmp_path):
    cr = str(tmp_path)
    df_override.record_nonce(cr, "n1", run_id="R", override_type="budget_ceiling",
                             applied_at="t")
    with pytest.raises(df_override.OverrideError):
        df_override.record_nonce(cr, "n1", run_id="R", override_type="budget_ceiling",
                                 applied_at="t")


def test_corrupt_ledger_fails_closed(tmp_path):
    cr = str(tmp_path)
    (tmp_path / df_override.NONCE_LEDGER_FILE).write_text("{not json", encoding="utf-8")
    with pytest.raises(df_override.OverrideError):
        df_override.load_used_nonces(cr)


# --- resume --override integration (config policy + apply + replay) ---------


def _configure_override_policy(cr, tmp_path, approvers, threshold=1, budget=None):
    p = cr / "config.json"
    cfg = json.loads(p.read_text(encoding="utf-8"))
    cfg["resume_overrides"] = {"approvers": approvers, "threshold": threshold}
    # A non-empty override policy REQUIRES audit.signing; put the key OUTSIDE
    # both the control root and workspace_root (a disjoint sibling of tmp_path).
    cfg["audit"] = {"signing": True, "key_path": str(tmp_path / "keys" / "audit.key")}
    if budget is not None:
        cfg["budget"] = budget
    p.write_text(json.dumps(cfg), encoding="utf-8")


def _signed_override_file(tmp_path, priv, run_id, new_ceiling, name="override.json"):
    claim = {
        "override_version": df_override.OVERRIDE_VERSION,
        "run_id": run_id,
        "override_type": "budget_ceiling",
        "params": {"new_usd_ceiling": float(new_ceiling)},
        "issued_at": "2026-01-01T00:00:00Z",
        "expires_at": "2035-01-01T00:00:00Z",
        "nonce": "test-nonce-abc",
    }
    sig = df_custody.sign_manifest(priv, df_override.override_signing_bytes(claim))
    pub = df_custody.public_from_private(priv)
    path = tmp_path / name
    path.write_text(json.dumps({"claim": claim, "signatures": [{"approver": pub, "sig": sig}]}),
                    encoding="utf-8")
    return str(path)


def _journal(cr, run_id):
    return [json.loads(l) for l in
            (cr / "runs" / run_id / "journal.jsonl").read_text().splitlines()]


def test_resume_override_raises_ceiling_and_replay_refused(tmp_path):
    priv, pub = df_custody.generate_keypair()
    cr = setup_control(tmp_path, STUBBORN, max_iterations=6, checkpoint="auto")
    _configure_override_policy(
        cr, tmp_path, [pub], threshold=1,
        budget={"billing": "api", "per_call_usd": 1.0, "max_usd": 1.0})

    # STUBBORN never converges: call 1 admitted, call 2 admission pauses on $.
    assert supervisor.run(str(cr), None) == supervisor.PAUSED
    run_id = os.listdir(cr / "runs")[0]

    # Raise the ceiling 1 -> 2. STUBBORN keeps spending, so it re-pauses on $.
    ov = _signed_override_file(tmp_path, priv, run_id, 2.0)
    assert supervisor.resume(str(cr), "continue", override_file=ov) == supervisor.PAUSED

    states = [e["state"] for e in _journal(cr, run_id)]
    assert "OVERRIDE_APPLIED" in states
    applied = next(e for e in _journal(cr, run_id) if e["state"] == "OVERRIDE_APPLIED")
    assert applied["data"]["new_cap_usd"] == 2.0
    assert applied["data"]["distinct_signers"] == 1

    # The nonce is recorded in the append-only ledger.
    assert "test-nonce-abc" in df_override.load_used_nonces(str(cr))

    # Replay the SAME override on the (now re-paused) run -> refused, exit 2.
    assert supervisor.resume(str(cr), "continue", override_file=ov) == 2
    states = [e["state"] for e in _journal(cr, run_id)]
    assert "OVERRIDE_REJECTED" in states


def test_resume_override_wrong_run_id_rejected(tmp_path):
    priv, pub = df_custody.generate_keypair()
    cr = setup_control(tmp_path, STUBBORN, max_iterations=4, checkpoint="auto")
    _configure_override_policy(
        cr, tmp_path, [pub], threshold=1,
        budget={"billing": "api", "per_call_usd": 1.0, "max_usd": 1.0})
    assert supervisor.run(str(cr), None) == supervisor.PAUSED
    run_id = os.listdir(cr / "runs")[0]
    # Sign an override for a DIFFERENT run_id.
    ov = _signed_override_file(tmp_path, priv, "SOME-OTHER-RUN", 100.0)
    assert supervisor.resume(str(cr), "continue", override_file=ov) == 2
    states = [e["state"] for e in _journal(cr, run_id)]
    assert "OVERRIDE_REJECTED" in states
    assert "OVERRIDE_APPLIED" not in states


def test_absent_policy_rejects_any_override(tmp_path):
    # No resume_overrides configured -> threshold 0 -> any override refused.
    priv, pub = df_custody.generate_keypair()
    cr = setup_control(tmp_path, STUBBORN, max_iterations=4, checkpoint="auto")
    p = cr / "config.json"
    cfg = json.loads(p.read_text(encoding="utf-8"))
    cfg["budget"] = {"billing": "api", "per_call_usd": 1.0, "max_usd": 1.0}
    p.write_text(json.dumps(cfg), encoding="utf-8")
    assert supervisor.run(str(cr), None) == supervisor.PAUSED
    run_id = os.listdir(cr / "runs")[0]
    ov = _signed_override_file(tmp_path, priv, run_id, 100.0)
    assert supervisor.resume(str(cr), "continue", override_file=ov) == 2
    states = [e["state"] for e in _journal(cr, run_id)]
    assert "OVERRIDE_REJECTED" in states
