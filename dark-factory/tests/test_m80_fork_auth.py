"""M80 (found by the post-R9 proactive sweep, confirmed by opus repro): DF-R9-08 —
a keyless control-root attacker could DE-SIGN a genuinely-signed parent run and make
`df-fork` accept a TAMPERED parent as "verified clean".

`fork_cmd` loaded the audit verification key only `if parent_manifest.get(
"audit_signing")` — a SAME-USER-WRITABLE manifest field — instead of the config
signing anchor (`cfg._audit.signing`). And `_verify_manifest_status` enforces the
HMAC only when the `manifest.hmac` sidecar FILE exists. So an attacker (no audit key,
no approver key) could: repoint the parent manifest's `artifact.object_id` to a
self-frozen malicious object, set `audit_signing:false`, DELETE the `manifest.hmac`
sidecar, and recompute the plain `manifest.sha256` — then `fork_cmd` loaded vkey=None,
`_verify_manifest_status(key=None)` saw no hmac + expect_sig False → returned OK, and
the fork proceeded, seeding the child workspace from attacker bytes with forged
lineage. This is the recurring "gate on a writable field, not the crypto anchor"
class (M71/M76/M77/M79).

Fix: load vkey when `cfg._audit.signing` OR `parent_manifest.audit_signing`
(mirroring `_authenticate_manifest`'s `signed = cfg.signing OR manifest.audit_signing`).
On a signed control root the key is always loaded → expect_sig True → the deleted
HMAC yields UNVERIFIED → refuse.
"""
import hashlib
import json
import os

import df_seal
import supervisor
from test_supervisor import FAKE, setup_control


def _sha(b):
    return hashlib.sha256(b).hexdigest()


def _signed_parent(tmp_path):
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")
    cfg = json.loads((cr / "config.json").read_text())
    cfg["audit"] = {"signing": True, "key_path": str(tmp_path / "keys" / "audit.key")}
    (cr / "config.json").write_text(json.dumps(cfg), encoding="utf-8")
    assert supervisor.run(str(cr), None) == 0  # converges, signed manifest + bound artifact
    parent_id = os.listdir(cr / "runs")[0]
    parent_dir = cr / "runs" / parent_id
    assert (parent_dir / "manifest.hmac").exists()  # genuinely signed
    return cr, parent_dir


def test_fork_from_genuine_signed_parent_succeeds(tmp_path):
    # No false-refusal: a genuine signed parent still forks.
    cr, parent_dir = _signed_parent(tmp_path)
    assert supervisor.fork_cmd(str(cr), str(parent_dir)) == 0


def test_fork_refuses_designed_tampered_parent(tmp_path):
    cr, parent_dir = _signed_parent(tmp_path)
    store = supervisor._object_store_root(str(cr))

    # ATTACK: freeze an attacker-chosen malicious object (a legitimate keyless op),
    # repoint the parent manifest at it, DE-SIGN the manifest (audit_signing:false +
    # delete the manifest.hmac sidecar), and recompute the plain manifest.sha256.
    mal_src = tmp_path / "mal"
    mal_src.mkdir()
    (mal_src / "evil.txt").write_text("pwned", encoding="utf-8")
    mal_object_id = df_seal.freeze(str(mal_src), store)

    m = json.loads((parent_dir / "manifest.json").read_text())
    m["artifact"]["object_id"] = mal_object_id
    m["audit_signing"] = False
    mbytes = json.dumps(m).encode("utf-8")
    (parent_dir / "manifest.json").write_bytes(mbytes)
    (parent_dir / "manifest.sha256").write_text(_sha(mbytes) + "\n", encoding="utf-8")
    (parent_dir / "manifest.hmac").unlink()  # de-sign

    # The fix: the config signing anchor forces the key-load → the deleted HMAC is
    # detected (UNVERIFIED) → the fork refuses to start from the tampered parent.
    assert supervisor.fork_cmd(str(cr), str(parent_dir)) == 2
    # And no child run was seeded from the malicious object.
    assert len(os.listdir(cr / "runs")) == 1


def test_fork_refuses_tampered_signed_parent_with_hmac_kept(tmp_path):
    # The narrower variant: keep the (now stale) manifest.hmac but tamper the manifest
    # — the HMAC verify fails (TAMPERED) → refuse. (This was already caught pre-fix
    # for a signed parent, but assert it stays closed.)
    cr, parent_dir = _signed_parent(tmp_path)
    m = json.loads((parent_dir / "manifest.json").read_text())
    m["qualified"] = True
    mbytes = json.dumps(m).encode("utf-8")
    (parent_dir / "manifest.json").write_bytes(mbytes)
    (parent_dir / "manifest.sha256").write_text(_sha(mbytes) + "\n", encoding="utf-8")
    assert supervisor.fork_cmd(str(cr), str(parent_dir)) == 2
