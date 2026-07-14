import json
import os

import df_audit
import supervisor
from test_supervisor import FAKE, setup_control


def _signed_control(tmp_path, key_path):
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")
    cfg = json.loads((cr / "config.json").read_text())
    cfg["audit"] = {"signing": True, "key_path": str(key_path)}
    (cr / "config.json").write_text(json.dumps(cfg))
    return cr


def test_signed_run_writes_hmac_and_verifies(tmp_path):
    kp = tmp_path / "keys" / "audit.key"
    cr = _signed_control(tmp_path, kp)
    assert supervisor.run(str(cr), None) == 0
    run_id = os.listdir(cr / "runs")[0]
    rd = cr / "runs" / run_id
    assert (rd / "manifest.hmac").exists()
    key = df_audit.load_or_create_key(str(kp))
    assert supervisor.verify_manifest(str(rd), key=key) is True


def test_tampered_signed_manifest_fails_without_key_forgery(tmp_path):
    kp = tmp_path / "keys" / "audit.key"
    cr = _signed_control(tmp_path, kp)
    supervisor.run(str(cr), None)
    rd = cr / "runs" / os.listdir(cr / "runs")[0]
    # attacker rewrites manifest.json AND recomputes manifest.sha256 (no key)
    m = json.loads((rd / "manifest.json").read_text())
    m["outcome"] = "COMPLETE_QUALIFIED"
    import df_common
    text = df_common.canonical_json(m)
    (rd / "manifest.json").write_text(text)
    (rd / "manifest.sha256").write_text(df_common.sha256_str(text) + "\n")
    key = df_audit.load_or_create_key(str(kp))
    assert supervisor.verify_manifest(str(rd), key=key) is False  # hmac catches it


def test_signed_manifest_unverified_without_key(tmp_path):
    kp = tmp_path / "keys" / "audit.key"
    cr = _signed_control(tmp_path, kp)
    supervisor.run(str(cr), None)
    rd = cr / "runs" / os.listdir(cr / "runs")[0]
    assert supervisor.verify_manifest(str(rd), key=None) is False  # fail-closed


def test_unsigned_run_unchanged(tmp_path):
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")  # no audit block
    assert supervisor.run(str(cr), None) == 0
    rd = cr / "runs" / os.listdir(cr / "runs")[0]
    assert not (rd / "manifest.hmac").exists()
    assert supervisor.verify_manifest(str(rd)) is True  # sha256 path unchanged
