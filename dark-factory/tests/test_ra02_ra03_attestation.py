"""M44 RA-02 / RA-03 regressions for the post-seal attestation paths.

RA-02 (a failed REQUIRED off-box sink must NOT leave a locally-qualified run):
  - custody attach against an unreachable REQUIRED sink returns nonzero AND
    leaves NO local custody_attestation.json / no chain link, and verify-custody
    reports NOT qualified (the pre-M44 bug wrote + anchored the attestation
    first, then returned 3, leaving a locally-QUALIFIED run).
  - verify-custody at a required-sink run with the receipt removed/corrupted is
    NOT qualified (SINK_RECEIPT_MISSING), never a silent QUALIFIED.

RA-03 (post-seal attestation must enforce manifest eligibility):
  - a SECURITY_GATE_FAILED enterprise manifest, even with valid K-of-N
    signatures, is REFUSED (never attested).
  - a HOST_ISOLATION_LIMITED CUSTODY_PENDING manifest, even with valid K-of-N,
    is REFUSED.
"""
import json
import os

import df_custody
import supervisor
from test_enterprise_config import (
    _approver, _enterprise_control, _fake_invoke, _patch_enterprise_probes,
    _sink_receiver, _FakeOSBackend,
)


GREET_PY = (
    "import sys\n"
    "if len(sys.argv) < 2:\n"
    "    print('usage: greet.py <name>', file=sys.stderr); sys.exit(2)\n"
    "print('Hello, ' + sys.argv[1] + '!')\n"
)


def _sign_kofn(cr, run_dir, priv_a, pub_a, priv_b, pub_b):
    manifest_bytes = (run_dir / "manifest.json").read_bytes()
    (cr / "custody-signatures.json").write_text(json.dumps([
        {"approver": pub_a, "sig": df_custody.sign_manifest(priv_a, manifest_bytes)},
        {"approver": pub_b, "sig": df_custody.sign_manifest(priv_b, manifest_bytes)},
    ]), encoding="utf-8")


# --- RA-02 ---------------------------------------------------------------

def test_ra02_required_sink_down_leaves_no_local_qualification(tmp_path, monkeypatch):
    priv_a, pub_a = _approver()
    priv_b, pub_b = _approver()
    _priv_c, pub_c = _approver()
    # A REQUIRED sink pointed at a port nothing listens on.
    cr = _enterprise_control(tmp_path, [pub_a, pub_b, pub_c], threshold=2,
                             sink_url="http://127.0.0.1:9")
    _patch_enterprise_probes(monkeypatch)
    monkeypatch.setattr(supervisor, "invoke_adapter", _fake_invoke)

    assert supervisor.run(str(cr), None) == 3
    run_id = os.listdir(cr / "runs")[0]
    run_dir = cr / "runs" / run_id
    _sign_kofn(cr, run_dir, priv_a, pub_a, priv_b, pub_b)

    chain_before = (cr / "audit-chain.jsonl").read_text().count("\n")
    # Custody IS satisfied by K-of-N, but the required sink push fails -> the
    # run must NOT be locally qualifiable.
    assert supervisor.attach_custody(str(cr), str(run_dir)) == 3
    # RA-02: no local attestation, no receipt, and no NEW chain link.
    assert not (run_dir / "custody_attestation.json").exists()
    assert not (run_dir / "custody_sink_receipt.json").exists()
    assert (cr / "audit-chain.jsonl").read_text().count("\n") == chain_before
    # And verify agrees: PENDING (no attestation), not a silent QUALIFIED.
    assert supervisor.verify_custody_cmd(str(cr), str(run_dir)) is False


def test_ra02_verify_requires_sink_receipt(tmp_path, monkeypatch):
    priv_a, pub_a = _approver()
    priv_b, pub_b = _approver()
    _priv_c, pub_c = _approver()
    with _sink_receiver(tmp_path) as (sink_url, _store):
        # M47 RA-08(a): confine candidate egress so the run is custody-qualifiable
        # (the enterprise probes are patched, so "deny" reaches no real network).
        cr = _enterprise_control(tmp_path, [pub_a, pub_b, pub_c], threshold=2,
                                 sink_url=sink_url, candidate_network="deny")
        _patch_enterprise_probes(monkeypatch)
        monkeypatch.setattr(supervisor, "invoke_adapter", _fake_invoke)

        assert supervisor.run(str(cr), None) == 3
        run_id = os.listdir(cr / "runs")[0]
        run_dir = cr / "runs" / run_id
        _sign_kofn(cr, run_dir, priv_a, pub_a, priv_b, pub_b)

        assert supervisor.attach_custody(str(cr), str(run_dir)) == 0
        receipt = run_dir / "custody_sink_receipt.json"
        assert receipt.exists()
        # Baseline: with the receipt present + bound, verify is QUALIFIED.
        assert supervisor.verify_custody_cmd(str(cr), str(run_dir)) is True

        # RA-02: remove the required-sink receipt -> NOT qualified.
        receipt.unlink()
        assert supervisor.verify_custody_cmd(str(cr), str(run_dir)) is False

        # A receipt that does not bind these attestation bytes -> NOT qualified.
        receipt.write_text(json.dumps({"kind": "http-append", "status": 200,
                                       "body_sha256": "0" * 64}), encoding="utf-8")
        assert supervisor.verify_custody_cmd(str(cr), str(run_dir)) is False


# --- RA-03 ---------------------------------------------------------------

def _secret_invoke(adapter, role, workdir, prompt_file, timeout_s,
                   exec_prefix=None, env_extra=None, env_full=None, confine=False):
    # A WORKING greet.py (every scenario passes) PLUS a planted secret, so the
    # run converges but the security gate rejects it: outcome SECURITY_GATE_FAILED.
    with open(os.path.join(workdir, "greet.py"), "w", encoding="utf-8") as f:
        f.write(GREET_PY)
    with open(os.path.join(workdir, "config.py"), "w", encoding="utf-8") as f:
        f.write('AWS_KEY = "AKIAABCDEFGHIJKLMNOP"\n')
    return {"adapter_protocol": "0.1", "status": "ok"}, None


def test_ra03_security_gate_failed_manifest_refused_despite_kofn(tmp_path, monkeypatch):
    priv_a, pub_a = _approver()
    priv_b, pub_b = _approver()
    _priv_c, pub_c = _approver()
    with _sink_receiver(tmp_path) as (sink_url, _store):
        cr = _enterprise_control(tmp_path, [pub_a, pub_b, pub_c], threshold=2,
                                 sink_url=sink_url)
        cfg = json.loads((cr / "config.json").read_text())
        cfg["security_gates"] = {"enabled": True, "fail_on": ["secret_scan"]}
        (cr / "config.json").write_text(json.dumps(cfg), encoding="utf-8")
        _patch_enterprise_probes(monkeypatch)
        monkeypatch.setattr(supervisor, "invoke_adapter", _secret_invoke)

        # The run seals SECURITY_GATE_FAILED (exit 3), NOT CUSTODY_PENDING.
        assert supervisor.run(str(cr), None) == 3
        run_id = os.listdir(cr / "runs")[0]
        run_dir = cr / "runs" / run_id
        m = json.loads((run_dir / "manifest.json").read_text())
        assert m["outcome"] == "SECURITY_GATE_FAILED"

        # Even a valid 2-of-3 signature set must NOT acquire a custody
        # qualification over an ineligible manifest.
        _sign_kofn(cr, run_dir, priv_a, pub_a, priv_b, pub_b)
        assert supervisor.attach_custody(str(cr), str(run_dir)) == 3
        assert not (run_dir / "custody_attestation.json").exists()
        assert supervisor.verify_custody_cmd(str(cr), str(run_dir)) is False


def test_ra03_host_isolation_limited_manifest_refused_despite_kofn(tmp_path, monkeypatch):
    """A CUSTODY_PENDING run whose candidate host-isolation is only legacy
    (allow_host_read) — host_isolation.qualified False — must be custody-refused
    even with valid K-of-N: a signature set cannot rescue a run that is
    genuinely less isolated than the tier promises."""
    priv_a, pub_a = _approver()
    priv_b, pub_b = _approver()
    _priv_c, pub_c = _approver()
    with _sink_receiver(tmp_path) as (sink_url, _store):
        cr = _enterprise_control(tmp_path, [pub_a, pub_b, pub_c], threshold=2,
                                 sink_url=sink_url)
        _patch_enterprise_probes(monkeypatch)

        # Downgrade the candidate backend to one WITHOUT default-deny support, so
        # host_isolation seals legacy_allow_host_read (qualified False) while the
        # run still converges CUSTODY_PENDING.
        class _LegacyBackend(_FakeOSBackend):
            supports_default_deny = False
        monkeypatch.setattr(supervisor.df_sandbox, "current_backend", lambda: _LegacyBackend())
        monkeypatch.setattr(supervisor, "invoke_adapter", _fake_invoke)

        assert supervisor.run(str(cr), None) == 3
        run_id = os.listdir(cr / "runs")[0]
        run_dir = cr / "runs" / run_id
        m = json.loads((run_dir / "manifest.json").read_text())
        assert m["outcome"] == "CUSTODY_PENDING"
        assert m["host_isolation"]["qualified"] is False

        _sign_kofn(cr, run_dir, priv_a, pub_a, priv_b, pub_b)
        assert supervisor.attach_custody(str(cr), str(run_dir)) == 3
        assert not (run_dir / "custody_attestation.json").exists()
        assert supervisor.verify_custody_cmd(str(cr), str(run_dir)) is False
