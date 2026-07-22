"""M79 (found by an adversarial sweep of the trust surfaces the R1–R9 audits did not
visit): DF-R9-07 — the STANDALONE split-custody qualification verdict was forgeable by
a keyless control-root attacker.

`verify_custody_cmd` / `attach_custody` trusted the manifest's sealed `config_sha256`
(via `_custody_config_bound`) + K-of-N signatures over the manifest bytes, but NEVER
authenticated the manifest HMAC — the only thing binding config_sha256 to the audit
key the attacker lacks. So an attacker (no audit key, no approver key) could rewrite
config.json's custody block to their OWN 1-of-1 key, rewrite the manifest's
config_sha256 to match, recompute the PLAIN manifest.sha256 sidecar, self-sign the
manifest, and get QUALIFIED — defeating the single-operator-proof guarantee of
`df-custody verify` and the evidence bundle's `custody.verified` sub-fact. (The real
ship + the full evidence bundle independently re-authenticate the manifest, so no
unauthorized ship resulted — hence Medium.)

Fix: both custody paths now call `_authenticate_manifest` FIRST (mirroring
ship/release/waiver) — a rewritten manifest leaves the HMAC stale → TAMPERED →
refuse; AND df_config now REQUIRES audit.signing when a `custody` block is present
(mirroring waivers/overrides), so the HMAC always exists to authenticate.
"""
import hashlib
import json
import os

import pytest

import df_config
import df_custody
import supervisor
from test_enterprise_config import (
    _approver, _enterprise_control, _fake_invoke, _patch_enterprise_probes, _sink_receiver)


def _sha(b):
    return hashlib.sha256(b).hexdigest()


def _sign_over_manifest(cr, run_dir, pairs):
    mb = (run_dir / "manifest.json").read_bytes()
    (cr / "custody-signatures.json").write_text(json.dumps(
        [{"approver": pub, "sig": df_custody.sign_manifest(priv, mb)} for priv, pub in pairs]),
        encoding="utf-8")


def test_forged_custody_qualification_refused(tmp_path, monkeypatch):
    priv_a, pub_a = _approver()
    priv_b, pub_b = _approver()
    _pc, pub_c = _approver()
    with _sink_receiver(tmp_path) as (sink_url, _store):
        cr = _enterprise_control(tmp_path, [pub_a, pub_b, pub_c], threshold=2,
                                 sink_url=sink_url, candidate_network="deny")
        _patch_enterprise_probes(monkeypatch)
        monkeypatch.setattr(supervisor, "invoke_adapter", _fake_invoke)
        assert supervisor.run(str(cr), None) == 3  # CUSTODY_PENDING
        run_dir = cr / "runs" / os.listdir(cr / "runs")[0]

        # Baseline: a genuine 2-of-3 attach qualifies (the fix does not false-refuse).
        _sign_over_manifest(cr, run_dir, [(priv_a, pub_a), (priv_b, pub_b)])
        assert supervisor.attach_custody(str(cr), str(run_dir)) == 0
        assert supervisor.verify_custody_cmd(str(cr), str(run_dir)) is True

        # ATTACK (no audit key, no approver key): swap the config custody block to the
        # attacker's OWN 1-of-1 key, rewrite the manifest's config_sha256 to match the
        # new config, recompute the PLAIN manifest.sha256 sidecar, self-sign, and
        # hand-write the attestation + a locally-computed sink receipt.
        ka_priv, ka_pub = _approver()
        cfgj = json.loads((cr / "config.json").read_text())
        cfgj["custody"] = {"approvers": [ka_pub], "threshold": 1}
        (cr / "config.json").write_text(json.dumps(cfgj), encoding="utf-8")
        new_cfg_sha = supervisor.load_config(str(cr))["_config_sha256"]

        mobj = json.loads((run_dir / "manifest.json").read_text())
        mobj["config_sha256"] = new_cfg_sha  # manifest.hmac sidecar is now STALE
        mbytes = json.dumps(mobj).encode("utf-8")
        (run_dir / "manifest.json").write_bytes(mbytes)
        (run_dir / "manifest.sha256").write_text(_sha(mbytes) + "\n")  # attacker CAN redo this

        att_text = json.dumps({
            "manifest_sha256": _sha(mbytes),
            "signatures": [{"approver": ka_pub, "sig": df_custody.sign_manifest(ka_priv, mbytes)}],
        })
        (run_dir / "custody_attestation.json").write_text(att_text, encoding="utf-8")
        (run_dir / "custody_sink_receipt.json").write_text(json.dumps(
            {"kind": "http-append", "status": 200, "body_sha256": _sha(att_text.encode("utf-8"))}),
            encoding="utf-8")

        # The config_sha256 binding PASSES (the attacker matched it) and the K-of-N
        # signature over the rewritten manifest is valid against the attacker's own
        # allowlist — so the ONLY thing that can refuse is the manifest HMAC:
        bound, _s, _c = supervisor._custody_config_bound(supervisor.load_config(str(cr)), mbytes)
        assert bound is True
        satisfied, _r = df_custody.verify_custody(mbytes,
                                                  json.loads(att_text)["signatures"], [ka_pub], 1)
        assert satisfied is True

        # ... and the fix refuses the forged qualification on BOTH paths (stale HMAC).
        assert supervisor.verify_custody_cmd(str(cr), str(run_dir)) is False
        assert supervisor.attach_custody(str(cr), str(run_dir)) == 3


def test_custody_requires_signing(tmp_path):
    # DF-R9-07 part 2: a `custody` block at a non-enterprise tier (where signing is
    # NOT forced by the tier) must still require audit.signing — else the manifest is
    # unsigned and the HMAC authentication above has nothing to check.
    _pa, pub_a = _approver()
    cr = tmp_path / "control"
    (cr / "scenarios").mkdir(parents=True)
    (cr / "config.json").write_text(json.dumps({
        "config_version": "0.1", "assurance": "standard", "autonomy": 4,
        "feedback": "ids", "max_iterations": 3,
        "workspace_root": str(tmp_path / "ws"),
        "roles": {"builder": {"adapter": "fake", "timeout_s": 30}},
        "budget": {"billing": "subscription"},
        "custody": {"approvers": [pub_a], "threshold": 1},
        "audit": {"signing": False},
    }), encoding="utf-8")
    (cr / "spec.md").write_text("spec", encoding="utf-8")
    with pytest.raises(df_config.ConfigError, match="custody requires audit.signing"):
        supervisor.load_config(str(cr))
