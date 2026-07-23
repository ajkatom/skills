"""M85 (Codex R10): DF-R10-02 — `df-fork` combined signing-downgrade.

M80 keyed "was the parent signed?" on `cfg._audit.signing OR parent_manifest.
audit_signing` — BOTH same-user-writable. R10 defeated it by downgrading BOTH: set
current standard-tier config `audit.signing: false` AND the parent manifest
`audit_signing: false` + delete `manifest.hmac`. Standard tier permits signing off, so
neither writable signal remained true → vkey stayed None → the tampered, de-signed
parent (artifact repointed to a self-frozen malicious object) verified "clean" and the
fork seeded a child from attacker bytes with forged lineage.

Fix: the parent's HISTORICAL signing state is read from the SIGNED AUDIT CHAIN (its
`source-identity` anchor, which a keyless attacker cannot remove without breaking
verify_chain, and whose truncation is caught by the off-box sink), not from the
writable config/manifest. A parent that STARTED signed must authenticate under the
audit key AND its exact bytes must be a chain member — a signed parent cannot be
forked as unsigned.
"""
import json
import os

import df_seal
import supervisor
from test_m80_fork_auth import _signed_parent, _sha


def test_fork_refuses_combined_config_and_manifest_downgrade(tmp_path):
    cr, parent_dir = _signed_parent(tmp_path)
    store = supervisor._object_store_root(str(cr))
    mal = tmp_path / "mal"
    mal.mkdir()
    (mal / "evil.txt").write_text("pwned", encoding="utf-8")
    mal_oid = df_seal.freeze(str(mal), store)

    # downgrade BOTH writable signals + repoint the artifact + de-sign the manifest
    cfg = json.loads((cr / "config.json").read_text())
    cfg["audit"] = {"signing": False}
    (cr / "config.json").write_text(json.dumps(cfg), encoding="utf-8")

    m = json.loads((parent_dir / "manifest.json").read_text())
    m["artifact"]["object_id"] = mal_oid
    m["audit_signing"] = False
    raw = json.dumps(m).encode("utf-8")
    (parent_dir / "manifest.json").write_bytes(raw)
    (parent_dir / "manifest.sha256").write_text(_sha(raw) + "\n", encoding="utf-8")
    (parent_dir / "manifest.hmac").unlink()

    assert supervisor.fork_cmd(str(cr), str(parent_dir)) == 2
    assert len(os.listdir(cr / "runs")) == 1  # NO child seeded from the tampered parent


def test_fork_signed_parent_refused_when_config_downgraded_only(tmp_path):
    # Even downgrading ONLY the config (manifest left genuinely signed) is refused:
    # require_signed is True via the chain, and the downgraded config no longer provides
    # the key to authenticate the parent.
    cr, parent_dir = _signed_parent(tmp_path)
    cfg = json.loads((cr / "config.json").read_text())
    cfg["audit"] = {"signing": False}
    (cr / "config.json").write_text(json.dumps(cfg), encoding="utf-8")
    assert supervisor.fork_cmd(str(cr), str(parent_dir)) == 2


def test_fork_from_genuine_signed_parent_still_succeeds(tmp_path):
    # No false-refusal: a genuine signed parent under its real config still forks.
    cr, parent_dir = _signed_parent(tmp_path)
    assert supervisor.fork_cmd(str(cr), str(parent_dir)) == 0


def test_parent_started_signed_reads_from_chain(tmp_path):
    cr, parent_dir = _signed_parent(tmp_path)
    parent_id = os.path.basename(str(parent_dir))
    # the parent's signed source-identity anchor is the tamper-evident "started signed"
    # proof, read WITHOUT the key
    assert supervisor._run_started_signed(str(cr), parent_id) is True
