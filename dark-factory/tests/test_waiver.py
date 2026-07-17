"""M33a (DF-06) unit tests for df_waiver — the signed/scoped/expiring waiver
primitive. Exercises fingerprint stability, policy/report digest binding,
expiry, artifact binding, threshold + distinct-signer counting, and the
un-waivable (scanner-could-not-run) case. Crypto is real ed25519 via
df_custody; these tests are skipped only if `cryptography` is not installed
(the same guard the split-custody tests use).
"""
import datetime

import pytest

import df_waiver

df_custody = pytest.importorskip("df_custody")
pytest.importorskip("cryptography")


UTC = datetime.timezone.utc


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _keypair():
    return df_custody.generate_keypair()  # (private_hex, public_hex)


def _make_waiver(priv, pub, *, run_id, artifact, policy_digest, report_digest,
                 fingerprint, issued_at, expires_at, reason="accepted risk"):
    claim = {
        "waiver_version": df_waiver.WAIVER_VERSION,
        "run_id": run_id,
        "artifact_object_id": artifact,
        "gate_policy_digest": policy_digest,
        "gate_report_digest": report_digest,
        "finding_fingerprint": fingerprint,
        "reason": reason,
        "issued_at": issued_at,
        "expires_at": expires_at,
    }
    sig = df_custody.sign_manifest(priv, df_waiver.waiver_signing_bytes(claim))
    return {"claim": claim, "signer": pub, "sig": sig}


# --- finding_fingerprint --------------------------------------------------


def test_fingerprint_excludes_line_number():
    a = {"file": "config.py", "line": 3, "rule": "aws_access_key"}
    b = {"file": "config.py", "line": 99, "rule": "aws_access_key"}
    assert df_waiver.finding_fingerprint("secret_scan", a) == \
        df_waiver.finding_fingerprint("secret_scan", b)


def test_fingerprint_distinguishes_file_and_rule():
    base = {"file": "a.py", "line": 1, "rule": "aws_access_key"}
    other_file = {"file": "b.py", "line": 1, "rule": "aws_access_key"}
    other_rule = {"file": "a.py", "line": 1, "rule": "slack_token"}
    fp = df_waiver.finding_fingerprint("secret_scan", base)
    assert fp != df_waiver.finding_fingerprint("secret_scan", other_file)
    assert fp != df_waiver.finding_fingerprint("secret_scan", other_rule)


def test_fingerprint_gate_name_is_bound():
    f = {"file": "a.py", "line": 1, "rule": "eval_exec"}
    assert df_waiver.finding_fingerprint("secret_scan", f) != \
        df_waiver.finding_fingerprint("dangerous_scan", f)


def test_fingerprint_license_includes_package_excludes_license_string():
    a = {"file": "pyproject.toml", "package": "foo", "license": "GPL-3.0",
         "rule": "disallowed-license"}
    b = {"file": "pyproject.toml", "package": "foo", "license": "AGPL",
         "rule": "disallowed-license"}
    c = {"file": "pyproject.toml", "package": "bar", "license": "GPL-3.0",
         "rule": "disallowed-license"}
    # license STRING excluded (same package+file+rule = same finding), but
    # package IS part of identity.
    assert df_waiver.finding_fingerprint("license", a) == \
        df_waiver.finding_fingerprint("license", b)
    assert df_waiver.finding_fingerprint("license", a) != \
        df_waiver.finding_fingerprint("license", c)


def test_fingerprint_unknown_gate_uses_whole_finding():
    f1 = {"anything": 1, "else": 2}
    f2 = {"anything": 1, "else": 3}
    assert df_waiver.finding_fingerprint("bandit", f1) != \
        df_waiver.finding_fingerprint("bandit", f2)


def test_fingerprint_missing_expected_key_falls_back_to_whole():
    # A secret_scan-shaped finding missing "rule" must not crash and must be
    # bound over the whole object (fail toward specificity).
    weird = {"file": "a.py", "line": 2}
    fp = df_waiver.finding_fingerprint("secret_scan", weird)
    assert isinstance(fp, str) and len(fp) == 64


# --- policy / report digests ----------------------------------------------


def _sec_cfg(**over):
    base = {
        "enabled": True,
        "secret_scan": True,
        "dangerous_scan": True,
        "sbom": False,
        "external": [],
        "fail_on": ["secret_scan", "dangerous_scan"],
        "strict_unavailable": True,
        "license": {"enabled": False, "allowlist": [], "require_license": False},
        "dependency_audit": {"enabled": False},
    }
    base.update(over)
    return base


def test_policy_digest_changes_when_fail_on_changes():
    d1 = df_waiver.gate_policy_digest(_sec_cfg(fail_on=["secret_scan", "dangerous_scan"]))
    d2 = df_waiver.gate_policy_digest(_sec_cfg(fail_on=["secret_scan"]))
    assert d1 != d2


def test_policy_digest_order_independent_for_fail_on():
    d1 = df_waiver.gate_policy_digest(_sec_cfg(fail_on=["secret_scan", "dangerous_scan"]))
    d2 = df_waiver.gate_policy_digest(_sec_cfg(fail_on=["dangerous_scan", "secret_scan"]))
    assert d1 == d2


def test_report_digest_excludes_policy_and_waiver_keys():
    report = {"checked": True, "gates": {"secret_scan": {"status": "fail",
              "findings": [{"file": "a.py", "line": 1, "rule": "aws_access_key"}]}},
              "failed": ["secret_scan"]}
    bare = df_waiver.gate_report_digest(report)
    with_extra = df_waiver.gate_report_digest(
        dict(report, gate_policy_digest="deadbeef",
             waiver_policy={"signers": ["x"], "threshold": 1}))
    assert bare == with_extra


def test_report_digest_changes_with_findings():
    r1 = {"checked": True, "gates": {"secret_scan": {"status": "fail",
          "findings": [{"file": "a.py", "line": 1, "rule": "aws_access_key"}]}},
          "failed": ["secret_scan"]}
    r2 = {"checked": True, "gates": {"secret_scan": {"status": "fail",
          "findings": [{"file": "b.py", "line": 1, "rule": "aws_access_key"}]}},
          "failed": ["secret_scan"]}
    assert df_waiver.gate_report_digest(r1) != df_waiver.gate_report_digest(r2)


# --- waiver_signing_bytes -------------------------------------------------


def test_signing_bytes_reject_missing_field():
    with pytest.raises(df_waiver.WaiverError):
        df_waiver.waiver_signing_bytes({"run_id": "x"})


def test_signing_bytes_ignore_extra_fields():
    claim = {
        "waiver_version": "1", "run_id": "r", "artifact_object_id": "o",
        "gate_policy_digest": "p", "gate_report_digest": "rep",
        "finding_fingerprint": "fp", "reason": "x",
        "issued_at": "2026-01-01T00:00:00Z", "expires_at": "2026-02-01T00:00:00Z",
    }
    b1 = df_waiver.waiver_signing_bytes(claim)
    b2 = df_waiver.waiver_signing_bytes(dict(claim, sneaky="covert"))
    assert b1 == b2  # extra fields never enter the signed bytes


# --- verify_waiver_set ----------------------------------------------------


REPORT = {
    "checked": True,
    "gates": {
        "secret_scan": {
            "status": "fail",
            "findings": [{"file": "config.py", "line": 5, "rule": "aws_access_key"}],
        }
    },
    "failed": ["secret_scan"],
}
RUN_ID = "run-123"
ARTIFACT = "objabc"
POLICY = "policy-digest-xyz"


def _report_digest():
    return df_waiver.gate_report_digest(REPORT)


def _fp():
    return df_waiver.finding_fingerprint(
        "secret_scan", REPORT["gates"]["secret_scan"]["findings"][0])


def test_happy_path_single_signer():
    priv, pub = _keypair()
    now = datetime.datetime(2026, 1, 15, tzinfo=UTC)
    w = _make_waiver(priv, pub, run_id=RUN_ID, artifact=ARTIFACT, policy_digest=POLICY,
                     report_digest=_report_digest(), fingerprint=_fp(),
                     issued_at=_iso(now - datetime.timedelta(days=1)),
                     expires_at=_iso(now + datetime.timedelta(days=30)))
    satisfied, reason, covered, uncovered = df_waiver.verify_waiver_set(
        failing_findings=REPORT["failed"], gates=REPORT["gates"], waivers=[w],
        signers=[pub], threshold=1, run_id=RUN_ID, artifact_object_id=ARTIFACT,
        policy_digest=POLICY, report_digest=_report_digest(), now=now)
    assert satisfied is True, reason
    assert covered == [_fp()] and uncovered == []


def test_expired_waiver_not_counted():
    priv, pub = _keypair()
    now = datetime.datetime(2026, 6, 1, tzinfo=UTC)
    w = _make_waiver(priv, pub, run_id=RUN_ID, artifact=ARTIFACT, policy_digest=POLICY,
                     report_digest=_report_digest(), fingerprint=_fp(),
                     issued_at=_iso(datetime.datetime(2026, 1, 1, tzinfo=UTC)),
                     expires_at=_iso(datetime.datetime(2026, 2, 1, tzinfo=UTC)))
    satisfied, reason, covered, uncovered = df_waiver.verify_waiver_set(
        failing_findings=REPORT["failed"], gates=REPORT["gates"], waivers=[w],
        signers=[pub], threshold=1, run_id=RUN_ID, artifact_object_id=ARTIFACT,
        policy_digest=POLICY, report_digest=_report_digest(), now=now)
    assert satisfied is False
    assert uncovered == [_fp()]


def test_expiry_boundary_is_half_open():
    priv, pub = _keypair()
    expires = datetime.datetime(2026, 2, 1, tzinfo=UTC)
    w = _make_waiver(priv, pub, run_id=RUN_ID, artifact=ARTIFACT, policy_digest=POLICY,
                     report_digest=_report_digest(), fingerprint=_fp(),
                     issued_at=_iso(datetime.datetime(2026, 1, 1, tzinfo=UTC)),
                     expires_at=_iso(expires))
    # now == expires => expired (half-open [issued, expires))
    s_at, *_ = df_waiver.verify_waiver_set(
        failing_findings=REPORT["failed"], gates=REPORT["gates"], waivers=[w],
        signers=[pub], threshold=1, run_id=RUN_ID, artifact_object_id=ARTIFACT,
        policy_digest=POLICY, report_digest=_report_digest(), now=expires)
    assert s_at is False
    s_before, *_ = df_waiver.verify_waiver_set(
        failing_findings=REPORT["failed"], gates=REPORT["gates"], waivers=[w],
        signers=[pub], threshold=1, run_id=RUN_ID, artifact_object_id=ARTIFACT,
        policy_digest=POLICY, report_digest=_report_digest(),
        now=expires - datetime.timedelta(seconds=1))
    assert s_before is True


def test_wrong_artifact_not_counted():
    priv, pub = _keypair()
    now = datetime.datetime(2026, 1, 15, tzinfo=UTC)
    w = _make_waiver(priv, pub, run_id=RUN_ID, artifact="DIFFERENT-OBJECT",
                     policy_digest=POLICY, report_digest=_report_digest(), fingerprint=_fp(),
                     issued_at=_iso(now - datetime.timedelta(days=1)),
                     expires_at=_iso(now + datetime.timedelta(days=30)))
    satisfied, *_ = df_waiver.verify_waiver_set(
        failing_findings=REPORT["failed"], gates=REPORT["gates"], waivers=[w],
        signers=[pub], threshold=1, run_id=RUN_ID, artifact_object_id=ARTIFACT,
        policy_digest=POLICY, report_digest=_report_digest(), now=now)
    assert satisfied is False


def test_policy_or_report_drift_not_counted():
    priv, pub = _keypair()
    now = datetime.datetime(2026, 1, 15, tzinfo=UTC)
    w = _make_waiver(priv, pub, run_id=RUN_ID, artifact=ARTIFACT, policy_digest=POLICY,
                     report_digest=_report_digest(), fingerprint=_fp(),
                     issued_at=_iso(now - datetime.timedelta(days=1)),
                     expires_at=_iso(now + datetime.timedelta(days=30)))
    # Verify under a DIFFERENT policy digest (operator dropped a gate later).
    s_pol, *_ = df_waiver.verify_waiver_set(
        failing_findings=REPORT["failed"], gates=REPORT["gates"], waivers=[w],
        signers=[pub], threshold=1, run_id=RUN_ID, artifact_object_id=ARTIFACT,
        policy_digest="policy-CHANGED", report_digest=_report_digest(), now=now)
    assert s_pol is False
    # Verify under a DIFFERENT report digest (findings changed).
    s_rep, *_ = df_waiver.verify_waiver_set(
        failing_findings=REPORT["failed"], gates=REPORT["gates"], waivers=[w],
        signers=[pub], threshold=1, run_id=RUN_ID, artifact_object_id=ARTIFACT,
        policy_digest=POLICY, report_digest="report-CHANGED", now=now)
    assert s_rep is False


def test_below_threshold_uncovered():
    priv, pub = _keypair()
    now = datetime.datetime(2026, 1, 15, tzinfo=UTC)
    w = _make_waiver(priv, pub, run_id=RUN_ID, artifact=ARTIFACT, policy_digest=POLICY,
                     report_digest=_report_digest(), fingerprint=_fp(),
                     issued_at=_iso(now - datetime.timedelta(days=1)),
                     expires_at=_iso(now + datetime.timedelta(days=30)))
    priv2, pub2 = _keypair()
    satisfied, reason, covered, uncovered = df_waiver.verify_waiver_set(
        failing_findings=REPORT["failed"], gates=REPORT["gates"], waivers=[w],
        signers=[pub, pub2], threshold=2, run_id=RUN_ID, artifact_object_id=ARTIFACT,
        policy_digest=POLICY, report_digest=_report_digest(), now=now)
    assert satisfied is False
    assert uncovered == [_fp()]


def test_two_signatures_same_signer_count_once():
    priv, pub = _keypair()
    now = datetime.datetime(2026, 1, 15, tzinfo=UTC)
    w = _make_waiver(priv, pub, run_id=RUN_ID, artifact=ARTIFACT, policy_digest=POLICY,
                     report_digest=_report_digest(), fingerprint=_fp(),
                     issued_at=_iso(now - datetime.timedelta(days=1)),
                     expires_at=_iso(now + datetime.timedelta(days=30)))
    # Same signer twice (different reason -> different sig, still one signer).
    w2 = _make_waiver(priv, pub, run_id=RUN_ID, artifact=ARTIFACT, policy_digest=POLICY,
                      report_digest=_report_digest(), fingerprint=_fp(),
                      issued_at=_iso(now - datetime.timedelta(days=2)),
                      expires_at=_iso(now + datetime.timedelta(days=60)),
                      reason="second attempt")
    satisfied, *_ = df_waiver.verify_waiver_set(
        failing_findings=REPORT["failed"], gates=REPORT["gates"], waivers=[w, w2],
        signers=[pub], threshold=2, run_id=RUN_ID, artifact_object_id=ARTIFACT,
        policy_digest=POLICY, report_digest=_report_digest(), now=now)
    assert satisfied is False  # only 1 distinct signer, threshold 2


def test_two_distinct_signers_meet_threshold():
    priv1, pub1 = _keypair()
    priv2, pub2 = _keypair()
    now = datetime.datetime(2026, 1, 15, tzinfo=UTC)
    kw = dict(run_id=RUN_ID, artifact=ARTIFACT, policy_digest=POLICY,
              report_digest=_report_digest(), fingerprint=_fp(),
              issued_at=_iso(now - datetime.timedelta(days=1)),
              expires_at=_iso(now + datetime.timedelta(days=30)))
    w1 = _make_waiver(priv1, pub1, **kw)
    w2 = _make_waiver(priv2, pub2, **kw)
    satisfied, *_ = df_waiver.verify_waiver_set(
        failing_findings=REPORT["failed"], gates=REPORT["gates"], waivers=[w1, w2],
        signers=[pub1, pub2], threshold=2, run_id=RUN_ID, artifact_object_id=ARTIFACT,
        policy_digest=POLICY, report_digest=_report_digest(), now=now)
    assert satisfied is True


def test_non_allowlisted_signer_ignored():
    priv, pub = _keypair()
    now = datetime.datetime(2026, 1, 15, tzinfo=UTC)
    w = _make_waiver(priv, pub, run_id=RUN_ID, artifact=ARTIFACT, policy_digest=POLICY,
                     report_digest=_report_digest(), fingerprint=_fp(),
                     issued_at=_iso(now - datetime.timedelta(days=1)),
                     expires_at=_iso(now + datetime.timedelta(days=30)))
    _, other_pub = _keypair()
    satisfied, *_ = df_waiver.verify_waiver_set(
        failing_findings=REPORT["failed"], gates=REPORT["gates"], waivers=[w],
        signers=[other_pub], threshold=1, run_id=RUN_ID, artifact_object_id=ARTIFACT,
        policy_digest=POLICY, report_digest=_report_digest(), now=now)
    assert satisfied is False


def test_tampered_signature_ignored():
    priv, pub = _keypair()
    now = datetime.datetime(2026, 1, 15, tzinfo=UTC)
    w = _make_waiver(priv, pub, run_id=RUN_ID, artifact=ARTIFACT, policy_digest=POLICY,
                     report_digest=_report_digest(), fingerprint=_fp(),
                     issued_at=_iso(now - datetime.timedelta(days=1)),
                     expires_at=_iso(now + datetime.timedelta(days=30)))
    # Flip the signed reason WITHOUT re-signing -> signature no longer verifies.
    w["claim"]["reason"] = "totally different, unsigned"
    satisfied, *_ = df_waiver.verify_waiver_set(
        failing_findings=REPORT["failed"], gates=REPORT["gates"], waivers=[w],
        signers=[pub], threshold=1, run_id=RUN_ID, artifact_object_id=ARTIFACT,
        policy_digest=POLICY, report_digest=_report_digest(), now=now)
    assert satisfied is False


def test_threshold_zero_never_satisfiable():
    priv, pub = _keypair()
    now = datetime.datetime(2026, 1, 15, tzinfo=UTC)
    w = _make_waiver(priv, pub, run_id=RUN_ID, artifact=ARTIFACT, policy_digest=POLICY,
                     report_digest=_report_digest(), fingerprint=_fp(),
                     issued_at=_iso(now - datetime.timedelta(days=1)),
                     expires_at=_iso(now + datetime.timedelta(days=30)))
    satisfied, reason, *_ = df_waiver.verify_waiver_set(
        failing_findings=REPORT["failed"], gates=REPORT["gates"], waivers=[w],
        signers=[pub], threshold=0, run_id=RUN_ID, artifact_object_id=ARTIFACT,
        policy_digest=POLICY, report_digest=_report_digest(), now=now)
    assert satisfied is False


def test_unavailable_gate_is_unwaivable():
    # A failing gate with no enumerable findings (scanner could not run) cannot
    # be waived, even by an otherwise-valid signer set.
    report = {
        "checked": True,
        "gates": {"secret_scan": {"status": "unavailable", "detail": "gate not run"}},
        "failed": ["secret_scan"],
    }
    priv, pub = _keypair()
    now = datetime.datetime(2026, 1, 15, tzinfo=UTC)
    satisfied, reason, covered, uncovered = df_waiver.verify_waiver_set(
        failing_findings=report["failed"], gates=report["gates"], waivers=[],
        signers=[pub], threshold=1, run_id=RUN_ID, artifact_object_id=ARTIFACT,
        policy_digest=POLICY, report_digest=df_waiver.gate_report_digest(report), now=now)
    assert satisfied is False
    assert "un-waivable" in reason


def test_external_gate_without_findings_is_unwaivable():
    report = {
        "checked": True,
        "gates": {"bandit": {"status": "fail", "detail": "3 issues"}},
        "failed": ["bandit"],
    }
    _, pub = _keypair()
    now = datetime.datetime(2026, 1, 15, tzinfo=UTC)
    # Even with a real threshold-1 policy, a structureless external failure is
    # un-waivable (there are no enumerated findings to sign off on).
    satisfied, reason, *_ = df_waiver.verify_waiver_set(
        failing_findings=report["failed"], gates=report["gates"], waivers=[],
        signers=[pub], threshold=1, run_id=RUN_ID, artifact_object_id=ARTIFACT,
        policy_digest=POLICY, report_digest=df_waiver.gate_report_digest(report), now=now)
    assert satisfied is False
    assert "un-waivable" in reason


def test_empty_failing_set_fails_closed():
    # Finding 2: a degenerate empty failing set must NOT vacuously satisfy —
    # a security primitive fails closed on empty input.
    priv, pub = _keypair()
    now = datetime.datetime(2026, 1, 15, tzinfo=UTC)
    satisfied, reason, covered, uncovered = df_waiver.verify_waiver_set(
        failing_findings=[], gates={}, waivers=[], signers=[pub], threshold=1,
        run_id=RUN_ID, artifact_object_id=ARTIFACT, policy_digest=POLICY,
        report_digest="whatever", now=now)
    assert satisfied is False
    assert covered == [] and uncovered == []


def test_wrong_waiver_version_not_counted():
    # Finding 3: a validly-SIGNED claim carrying a non-v1 waiver_version is
    # dropped (a future v2 claim is never verified under v1 rules).
    priv, pub = _keypair()
    now = datetime.datetime(2026, 1, 15, tzinfo=UTC)
    claim = {
        "waiver_version": "2",  # future schema
        "run_id": RUN_ID,
        "artifact_object_id": ARTIFACT,
        "gate_policy_digest": POLICY,
        "gate_report_digest": _report_digest(),
        "finding_fingerprint": _fp(),
        "reason": "accepted",
        "issued_at": _iso(now - datetime.timedelta(days=1)),
        "expires_at": _iso(now + datetime.timedelta(days=30)),
    }
    # Sign the v2 claim honestly — the signature is valid, only the version is
    # wrong, so this proves the version check (not the signature check) drops it.
    sig = df_custody.sign_manifest(priv, df_waiver.waiver_signing_bytes(claim))
    w = {"claim": claim, "signer": pub, "sig": sig}
    satisfied, _reason, covered, uncovered = df_waiver.verify_waiver_set(
        failing_findings=REPORT["failed"], gates=REPORT["gates"], waivers=[w],
        signers=[pub], threshold=1, run_id=RUN_ID, artifact_object_id=ARTIFACT,
        policy_digest=POLICY, report_digest=_report_digest(), now=now)
    assert satisfied is False
    assert uncovered == [_fp()]


def test_multiple_findings_all_must_be_covered():
    report = {
        "checked": True,
        "gates": {"secret_scan": {"status": "fail", "findings": [
            {"file": "a.py", "line": 1, "rule": "aws_access_key"},
            {"file": "b.py", "line": 2, "rule": "slack_token"},
        ]}},
        "failed": ["secret_scan"],
    }
    rd = df_waiver.gate_report_digest(report)
    fp_a = df_waiver.finding_fingerprint("secret_scan", report["gates"]["secret_scan"]["findings"][0])
    priv, pub = _keypair()
    now = datetime.datetime(2026, 1, 15, tzinfo=UTC)
    # Waiver only for finding A -> B uncovered -> not satisfied.
    w = _make_waiver(priv, pub, run_id=RUN_ID, artifact=ARTIFACT, policy_digest=POLICY,
                     report_digest=rd, fingerprint=fp_a,
                     issued_at=_iso(now - datetime.timedelta(days=1)),
                     expires_at=_iso(now + datetime.timedelta(days=30)))
    satisfied, reason, covered, uncovered = df_waiver.verify_waiver_set(
        failing_findings=report["failed"], gates=report["gates"], waivers=[w],
        signers=[pub], threshold=1, run_id=RUN_ID, artifact_object_id=ARTIFACT,
        policy_digest=POLICY, report_digest=rd, now=now)
    assert satisfied is False
    assert covered == [fp_a]
    assert len(uncovered) == 1
