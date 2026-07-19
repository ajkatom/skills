"""M33a (DF-06) e2e: mandatory gates at standard+ fold into qualification
(Task 3), and the full df-waiver attach/verify lifecycle with verify-time
expiry re-check (Task 4).

The waiver-lifecycle tests run at COOPERATIVE tier: security gates and the
waiver machinery are tier-INDEPENDENT (a cooperative run with an enabled gate
still seals SECURITY_GATE_FAILED and a waiver_policy), so they exercise the
whole sign -> collect -> attach -> verify path without needing an OS sandbox.
Two standard-tier tests (guarded on sandbox availability) prove the
mandatory-gate + app_security_qualified wiring specifically.
"""
import datetime
import json
import os
import subprocess
import sys

import pytest

import df_custody
import df_sandbox
import df_waiver
import supervisor
from test_supervisor import FAKE, external_reachable, needs_network, setup_control

pytest.importorskip("cryptography")

HERE = os.path.dirname(os.path.abspath(__file__))
FAKE_SECRET = os.path.join(HERE, "fixtures", "fake_builder_secret")
SUP = os.path.join(HERE, "..", "scripts", "supervisor.py")
UTC = datetime.timezone.utc


def _run(cr, *args):
    return subprocess.run([sys.executable, SUP, *args, "--control-root", str(cr)],
                          capture_output=True, text=True, timeout=120)


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _set_gates(cr, gates):
    p = cr / "config.json"
    cfg = json.loads(p.read_text(encoding="utf-8"))
    cfg["security_gates"] = gates
    p.write_text(json.dumps(cfg), encoding="utf-8")


def _manifest(cr, run_id):
    return json.loads((cr / "runs" / run_id / "manifest.json").read_text(encoding="utf-8"))


def _failed_run_with_policy(tmp_path, signers, threshold):
    """A cooperative run that FAILS secret_scan and carries a waiver policy.
    Returns (cr, run_id, run_dir, manifest).

    M33a Finding 1: a non-empty waiver policy REQUIRES audit.signing: true, so
    the config carries an audit block with a tmp key_path (never the real
    ~/.dark-factory default), keeping the test hermetic."""
    cr = setup_control(tmp_path, FAKE_SECRET, checkpoint="auto")
    _set_gates(cr, {
        "enabled": True,
        "fail_on": ["secret_scan"],
        "waivers": {"signers": signers, "threshold": threshold},
    })
    p = cr / "config.json"
    cfg = json.loads(p.read_text(encoding="utf-8"))
    cfg["audit"] = {"signing": True, "key_path": str(tmp_path / "audit_keys" / "audit.key")}
    p.write_text(json.dumps(cfg), encoding="utf-8")
    proc = _run(cr, "run")
    assert proc.returncode == 3, proc.stderr
    run_id = os.listdir(cr / "runs")[0]
    return cr, run_id, cr / "runs" / run_id, _manifest(cr, run_id)


def _sign(manifest, priv, pub, *, fingerprint, issued_at, expires_at, reason="accepted"):
    security = manifest["security"]
    claim = {
        "waiver_version": df_waiver.WAIVER_VERSION,
        "run_id": manifest["invocation"],
        "artifact_object_id": manifest["artifact"]["object_id"],
        "gate_policy_digest": security["gate_policy_digest"],
        "gate_report_digest": df_waiver.gate_report_digest(security),
        "finding_fingerprint": fingerprint,
        "reason": reason,
        "issued_at": issued_at,
        "expires_at": expires_at,
    }
    sig = df_custody.sign_manifest(priv, df_waiver.waiver_signing_bytes(claim))
    return {"claim": claim, "signer": pub, "sig": sig}


def _the_fingerprint(manifest):
    finding = manifest["security"]["gates"]["secret_scan"]["findings"][0]
    return df_waiver.finding_fingerprint("secret_scan", finding)


def _write_sigs(cr, entries):
    (cr / "waiver-signatures.json").write_text(json.dumps(entries), encoding="utf-8")


# --- Task 3: mandatory gates at standard+ ---------------------------------


@needs_network
@pytest.mark.skipif(sys.platform not in ("darwin", "linux"), reason="needs a real sandbox backend")
def test_standard_clean_run_qualified_with_app_security(tmp_path):
    b = df_sandbox.current_backend()
    if not (b and b.available()):
        pytest.skip("no OS sandbox primitive")
    if not external_reachable():
        pytest.skip("no external reachability for the candidate egress-denial probe")
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")
    # NO security_gates block: standard tier must SYNTHESIZE the mandatory
    # minimum and still qualify a clean artifact. M47 RA-08(a): confine candidate
    # egress so the run QUALIFIES.
    p = cr / "config.json"
    cfg = json.loads(p.read_text()); cfg["assurance"] = "standard"
    cfg["candidate_network"] = "deny"; p.write_text(json.dumps(cfg))
    proc = _run(cr, "run")
    assert proc.returncode == 0, proc.stderr
    run_id = os.listdir(cr / "runs")[0]
    m = _manifest(cr, run_id)
    assert m["outcome"] == "COMPLETE_QUALIFIED"
    assert m["qualified"] is True
    assert m["app_security_qualified"] is True
    # Mandatory gates actually ran and were sealed with policy binding.
    assert m["security"]["checked"] is True
    assert m["security"]["failed"] == []
    assert isinstance(m["security"]["gate_policy_digest"], str)
    assert m["security"]["gates"]["secret_scan"]["status"] == "pass"
    assert m["security"]["gates"]["dangerous_scan"]["status"] == "pass"


@pytest.mark.skipif(sys.platform not in ("darwin", "linux"), reason="needs a real sandbox backend")
def test_standard_planted_secret_is_not_qualified(tmp_path):
    b = df_sandbox.current_backend()
    if not (b and b.available()):
        pytest.skip("no OS sandbox primitive")
    cr = setup_control(tmp_path, FAKE_SECRET, checkpoint="auto")
    p = cr / "config.json"
    cfg = json.loads(p.read_text()); cfg["assurance"] = "standard"; p.write_text(json.dumps(cfg))
    proc = _run(cr, "run")
    assert proc.returncode == 3, proc.stderr
    run_id = os.listdir(cr / "runs")[0]
    m = _manifest(cr, run_id)
    assert m["outcome"] == "SECURITY_GATE_FAILED"
    assert m["qualified"] is False
    assert m["app_security_qualified"] is False
    assert "secret_scan" in m["security"]["failed"]
    assert isinstance(m["security"]["gate_policy_digest"], str)


# --- Task 4: waiver lifecycle (cooperative tier) --------------------------


def test_failed_run_seals_waiver_policy(tmp_path):
    priv, pub = df_custody.generate_keypair()
    cr, run_id, run_dir, m = _failed_run_with_policy(tmp_path, [pub], 1)
    assert m["outcome"] == "SECURITY_GATE_FAILED"
    assert m["app_security_qualified"] is False
    # The signer allowlist + threshold are SEALED into the manifest (not just
    # config), so attach/verify can't be widened by a post-run config edit.
    assert m["security"]["waiver_policy"] == {"signers": [pub], "threshold": 1}
    assert isinstance(m["security"]["gate_policy_digest"], str)


def test_attach_happy_path_then_verify_qualified(tmp_path, capsys):
    priv, pub = df_custody.generate_keypair()
    cr, run_id, run_dir, m = _failed_run_with_policy(tmp_path, [pub], 1)
    now = datetime.datetime.now(UTC)
    entry = _sign(m, priv, pub, fingerprint=_the_fingerprint(m),
                  issued_at=_iso(now - datetime.timedelta(hours=1)),
                  expires_at=_iso(now + datetime.timedelta(days=30)))
    _write_sigs(cr, [entry])

    rc = supervisor.attach_waiver(str(cr), str(run_dir))
    assert rc == 0, capsys.readouterr()
    att = json.loads((run_dir / "waiver_attestation.json").read_text(encoding="utf-8"))
    assert att["satisfied"] is True
    assert att["covered_fingerprints"] == [_the_fingerprint(m)]

    rc_v = supervisor.verify_waiver_cmd(str(cr), str(run_dir))
    out = capsys.readouterr().out
    assert rc_v == 0
    assert "WAIVED_QUALIFIED" in out


def test_verify_expiry_flips_verdict(tmp_path, capsys, monkeypatch):
    priv, pub = df_custody.generate_keypair()
    cr, run_id, run_dir, m = _failed_run_with_policy(tmp_path, [pub], 1)
    now = datetime.datetime.now(UTC)
    # Valid NOW, expires soon. Attach at real now (inside window) succeeds.
    entry = _sign(m, priv, pub, fingerprint=_the_fingerprint(m),
                  issued_at=_iso(now - datetime.timedelta(hours=1)),
                  expires_at=_iso(now + datetime.timedelta(days=1)))
    _write_sigs(cr, [entry])
    assert supervisor.attach_waiver(str(cr), str(run_dir)) == 0
    capsys.readouterr()

    # Advance the verify clock past expiry -> the SAME attestation now flips to
    # WAIVER_EXPIRED (expiry is re-checked live, never a frozen boolean).
    future = now + datetime.timedelta(days=8)
    monkeypatch.setattr(supervisor, "_now_utc", lambda: future)
    rc = supervisor.verify_waiver_cmd(str(cr), str(run_dir))
    out = capsys.readouterr().out
    assert rc == supervisor._WAIVER_VERIFY_EXIT["WAIVER_EXPIRED"]
    assert "WAIVER_EXPIRED" in out


def test_expired_waiver_wont_attach(tmp_path, capsys):
    priv, pub = df_custody.generate_keypair()
    cr, run_id, run_dir, m = _failed_run_with_policy(tmp_path, [pub], 1)
    now = datetime.datetime.now(UTC)
    entry = _sign(m, priv, pub, fingerprint=_the_fingerprint(m),
                  issued_at=_iso(now - datetime.timedelta(days=10)),
                  expires_at=_iso(now - datetime.timedelta(days=1)))  # already expired
    _write_sigs(cr, [entry])
    rc = supervisor.attach_waiver(str(cr), str(run_dir))
    assert rc == 3
    assert not (run_dir / "waiver_attestation.json").exists()


def test_wrong_signer_refused(tmp_path):
    priv, pub = df_custody.generate_keypair()
    other_priv, other_pub = df_custody.generate_keypair()
    cr, run_id, run_dir, m = _failed_run_with_policy(tmp_path, [pub], 1)
    now = datetime.datetime.now(UTC)
    # Signed by a key NOT in the sealed allowlist.
    entry = _sign(m, other_priv, other_pub, fingerprint=_the_fingerprint(m),
                  issued_at=_iso(now - datetime.timedelta(hours=1)),
                  expires_at=_iso(now + datetime.timedelta(days=30)))
    _write_sigs(cr, [entry])
    assert supervisor.attach_waiver(str(cr), str(run_dir)) == 3
    assert not (run_dir / "waiver_attestation.json").exists()


def test_below_threshold_refused(tmp_path):
    priv1, pub1 = df_custody.generate_keypair()
    priv2, pub2 = df_custody.generate_keypair()
    cr, run_id, run_dir, m = _failed_run_with_policy(tmp_path, [pub1, pub2], 2)
    now = datetime.datetime.now(UTC)
    # Only ONE of the two required signers.
    entry = _sign(m, priv1, pub1, fingerprint=_the_fingerprint(m),
                  issued_at=_iso(now - datetime.timedelta(hours=1)),
                  expires_at=_iso(now + datetime.timedelta(days=30)))
    _write_sigs(cr, [entry])
    assert supervisor.attach_waiver(str(cr), str(run_dir)) == 3


def test_tampered_claim_refused(tmp_path):
    priv, pub = df_custody.generate_keypair()
    cr, run_id, run_dir, m = _failed_run_with_policy(tmp_path, [pub], 1)
    now = datetime.datetime.now(UTC)
    entry = _sign(m, priv, pub, fingerprint=_the_fingerprint(m),
                  issued_at=_iso(now - datetime.timedelta(hours=1)),
                  expires_at=_iso(now + datetime.timedelta(days=30)))
    # Mutate the signed reason WITHOUT re-signing.
    entry["claim"]["reason"] = "unsigned tampering"
    _write_sigs(cr, [entry])
    assert supervisor.attach_waiver(str(cr), str(run_dir)) == 3


def test_wrong_fingerprint_refused(tmp_path):
    priv, pub = df_custody.generate_keypair()
    cr, run_id, run_dir, m = _failed_run_with_policy(tmp_path, [pub], 1)
    now = datetime.datetime.now(UTC)
    entry = _sign(m, priv, pub, fingerprint="0" * 64,  # not a real finding fp
                  issued_at=_iso(now - datetime.timedelta(hours=1)),
                  expires_at=_iso(now + datetime.timedelta(days=30)))
    _write_sigs(cr, [entry])
    assert supervisor.attach_waiver(str(cr), str(run_dir)) == 3


def test_verify_without_attestation_not_waived(tmp_path, capsys):
    priv, pub = df_custody.generate_keypair()
    cr, run_id, run_dir, m = _failed_run_with_policy(tmp_path, [pub], 1)
    rc = supervisor.verify_waiver_cmd(str(cr), str(run_dir))
    out = capsys.readouterr().out
    assert rc == supervisor._WAIVER_VERIFY_EXIT["NOT_WAIVED"]
    assert "NOT_WAIVED" in out


def test_cli_findings_lists_the_fingerprint(tmp_path):
    priv, pub = df_custody.generate_keypair()
    cr, run_id, run_dir, m = _failed_run_with_policy(tmp_path, [pub], 1)
    proc = subprocess.run(
        [sys.executable, SUP, "df-waiver", "findings", "--manifest",
         str(run_dir / "manifest.json")],
        capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    out = json.loads(proc.stdout)
    assert _the_fingerprint(m) in out["waivable_fingerprints"]
    assert out["waiver_policy"] == {"signers": [pub], "threshold": 1}


def test_cli_sign_then_attach_end_to_end(tmp_path):
    """Drive the ACTUAL CLI (sign recomputes digests from the manifest), not
    the in-process _sign helper — proves the operator path works."""
    priv, pub = df_custody.generate_keypair()
    cr, run_id, run_dir, m = _failed_run_with_policy(tmp_path, [pub], 1)
    keyfile = cr / "signer.key"
    keyfile.write_text(priv + "\n", encoding="utf-8")
    expires = _iso(datetime.datetime.now(UTC) + datetime.timedelta(days=30))
    proc = subprocess.run(
        [sys.executable, SUP, "df-waiver", "sign",
         "--manifest", str(run_dir / "manifest.json"),
         "--fingerprint", _the_fingerprint(m),
         "--expires", expires, "--reason", "accepted risk",
         "--key-file", str(keyfile)],
        capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    entry = json.loads(proc.stdout)
    assert entry["signer"] == pub
    _write_sigs(cr, [entry])
    proc_a = subprocess.run(
        [sys.executable, SUP, "df-waiver", "attach", str(cr), "--run-dir", str(run_dir)],
        capture_output=True, text=True, timeout=60)
    assert proc_a.returncode == 0, proc_a.stderr
    assert "WAIVER ATTACHED" in proc_a.stdout
    proc_v = subprocess.run(
        [sys.executable, SUP, "df-waiver", "verify", str(cr), "--run-dir", str(run_dir)],
        capture_output=True, text=True, timeout=60)
    assert proc_v.returncode == 0
    assert "WAIVED_QUALIFIED" in proc_v.stdout
