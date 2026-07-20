"""M60 (Codex R5 arbitration §"Required evidence bundle"): assemble the
production-validation evidence bundle from a COMPLETED run.

Codex's arbitration (audit/10) splits acceptance into "code-complete" and
"production-validated release GO". The latter requires a representative live
hardened-H4 / enterprise exercise whose evidence is independently verifiable.
This module reads a finished control root + run dir and emits ONE JSON bundle
with exactly the fields the arbitration enumerates, pulled from the SEALED
artifacts (manifest, ship result, custody attestation, sink receipts, audit
chain) — never re-derived or re-run. It is a read-only reporter: it makes no
network calls and mutates nothing.

The bundle NEVER contains a credential value — it reports credential/env NAMES
and allowlists only (the same barrier the manifest itself keeps). A defensive
scrub pass drops any field whose key looks secret-bearing.

Run it AFTER a live exercise completes (see references/live-validation.md):

    supervisor.py evidence-bundle <control_root> --run-dir <run_dir> \\
        [--out bundle.json] [--key-path <audit_pub_or_priv_key>]

Exit 0 = a bundle was assembled (it may still show gaps the operator must read);
exit 2 = the run dir / manifest is missing or unreadable (nothing to report).
"""
import json
import os
import subprocess

import df_common


# Keys whose VALUES must never appear in the bundle (defense in depth; the
# source artifacts are already barrier-clean, this is a second gate).
_SECRET_KEY_HINTS = ("secret", "token", "password", "passwd", "privkey",
                     "private_key", "api_key", "apikey", "access_key",
                     "secret_key", "credential_value")


def _looks_secret(key):
    k = str(key).lower()
    return any(h in k for h in _SECRET_KEY_HINTS)


def _scrub(obj):
    """Recursively drop any mapping entry whose KEY looks secret-bearing,
    replacing its value with the marker '<omitted:secret-key>'. Lists/scalars
    pass through. This never inspects values (a value that merely looks like a
    token under a benign key is left — the source artifacts don't carry raw
    secret values, and guessing on values risks redacting real evidence like a
    sha256)."""
    if isinstance(obj, dict):
        return {k: ("<omitted:secret-key>" if _looks_secret(k) else _scrub(v))
                for k, v in obj.items()}
    if isinstance(obj, list):
        return [_scrub(v) for v in obj]
    return obj


def _read_json(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f), None
    except FileNotFoundError:
        return None, "absent"
    except (OSError, json.JSONDecodeError) as e:
        return None, f"unreadable ({e})"


def _source_commit(control_root):
    """The exact git commit of the SKILL source (this repo), or None. Best
    effort — a bundle from a non-git checkout just records None."""
    here = os.path.dirname(os.path.abspath(__file__))
    try:
        out = subprocess.run(["git", "-C", here, "rev-parse", "HEAD"],
                             capture_output=True, text=True, timeout=10)
        if out.returncode == 0:
            return out.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        pass
    return None


def _verify_chain_output(control_root, key):
    """Run the same signed-chain verification `verify-chain` does, capturing the
    (ok, message) as evidence — not just a boolean."""
    import df_audit_chain
    chain_path = os.path.join(control_root, "audit-chain.jsonl")
    try:
        entries = df_audit_chain.read_chain(chain_path)
    except df_audit_chain.ChainError as e:
        return {"present": False, "reason": str(e)}
    signed = any("sig" in e for e in entries)
    if signed and key is None:
        return {"present": True, "signed": True, "verified": None,
                "message": "UNVERIFIED (signed chain; supply --key-path)"}
    ok, msg = df_audit_chain.verify_chain(chain_path, audit_key=key)
    return {"present": True, "signed": signed, "verified": bool(ok), "message": msg}


def _verified_manifest(control_root, run_dir, key):
    """DF-R6-07: VERIFY the manifest, not just hash it. Runs the real
    _verify_manifest_status (HMAC + artifact-identity re-verification) AND proves
    the manifest's on-disk digest is a MEMBER of the verified chain — not merely
    that the chain verifies globally. Returns a dict of proven facts. Lazy import
    to avoid the supervisor<->bundle import cycle."""
    import supervisor
    import df_audit_chain
    mpath = os.path.join(run_dir, "manifest.json")
    raw_sha = df_common.sha256_file(mpath)
    out = {"manifest_sha256": raw_sha, "verify_status": None,
           "chain_member": None}
    try:
        out["verify_status"] = supervisor._verify_manifest_status(
            run_dir, key=key, object_store=os.path.join(control_root, "objects"))
    except Exception as e:  # a reporter must never crash the bundle
        out["verify_status"] = f"ERROR: {e.__class__.__name__}: {e}"
    # Chain membership: some signature-valid chain entry anchors this exact digest.
    try:
        chain_path = os.path.join(control_root, "audit-chain.jsonl")
        ok, _msg = df_audit_chain.verify_chain(chain_path, audit_key=key)
        entries = df_audit_chain.read_chain(chain_path)
        member = any(e.get("manifest_sha256") == raw_sha for e in entries)
        out["chain_member"] = bool(ok and member)
    except Exception as e:
        out["chain_member"] = f"ERROR: {e.__class__.__name__}: {e}"
    out["manifest_verified"] = (out["verify_status"] == "OK"
                                and out["chain_member"] is True)
    return out


def _verified_custody(control_root, run_dir, manifest, key):
    """DF-R6-07: CRYPTOGRAPHICALLY verify the custody attestation (K-of-N over the
    sealed manifest), not presence/count. Reuses the supervisor's own verifier."""
    import supervisor
    att, err = _read_json(os.path.join(run_dir, "custody_attestation.json"))
    if att is None:
        return {"present": False, "reason": err, "verified": None}
    try:
        verified = bool(supervisor.verify_custody_cmd(control_root, run_dir))
    except Exception as e:
        return {"present": True, "verified": f"ERROR: {e.__class__.__name__}: {e}"}
    return {"present": True, "verified": verified,
            "threshold": (manifest.get("custody") or {}).get("required_k"),
            "approvers_satisfied": att.get("approvers_satisfied")}


def _verified_release(control_root, run_dir, key):
    """DF-R6-07: verify the release attestation is chain-anchored (M64) and report
    its signed claim's scope/expiry — the release-approval RESULT the runbook
    promises, which the v1 bundle omitted entirely."""
    import supervisor
    att, err = _read_json(os.path.join(run_dir, "release_attestation.json"))
    if att is None:
        return {"present": False, "reason": err, "verified": None}
    att_bytes = None
    try:
        with open(os.path.join(run_dir, "release_attestation.json"), encoding="utf-8") as f:
            att_bytes = f.read()
    except OSError:
        pass
    anchored = None
    if att_bytes is not None:
        try:
            run_id = _run_id_of(run_dir)
            ok_c, _why = supervisor._authenticate_ship_chain(
                _cfg_of(control_root), control_root, run_id,
                df_common.sha256_str(att_bytes), "release")
            anchored = bool(ok_c)
        except Exception as e:
            anchored = f"ERROR: {e.__class__.__name__}: {e}"
    claim = att.get("claim") or {}
    return {"present": True, "chain_anchored": anchored,
            "verified": anchored is True,
            "action_names": claim.get("action_names"),
            "expires_at": claim.get("expires_at"),
            "approvers_satisfied": att.get("approvers_satisfied")}


def _run_id_of(run_dir):
    m, _ = _read_json(os.path.join(run_dir, "manifest.json"))
    return (m or {}).get("invocation") or os.path.basename(run_dir.rstrip(os.sep))


def _cfg_of(control_root):
    import supervisor
    from df_config import load_config
    cfg = load_config(control_root)
    cfg["_control_root"] = control_root
    return cfg


def _verified_receipt(control_root, run_dir, basename):
    """DF-R6-07: positively READ BACK + binding-check a sink receipt, not just copy
    its fields. Reuses supervisor._sink_readback (exact-version S3 / http-append)."""
    import supervisor
    receipt, err = _read_json(os.path.join(run_dir, basename))
    if receipt is None:
        return {"present": False, "reason": err, "verified": None}
    facts = {"present": True, "kind": receipt.get("kind"),
             "sink_key": receipt.get("sink_key"), "version_id": receipt.get("version_id"),
             "body_sha256": receipt.get("body_sha256"),
             "server_issued": receipt.get("server_issued")}
    # The bytes the receipt binds are the sealed record it accompanies.
    record_name = {"ship_sink_receipt.json": "ship_result.json"}.get(basename)
    att_text = None
    if record_name:
        try:
            with open(os.path.join(run_dir, record_name), encoding="utf-8") as f:
                att_text = f.read()
        except OSError:
            att_text = None
    try:
        cfg = _cfg_of(control_root)
        sink = cfg.get("_audit", {}).get("sink", {"kind": "none"})
        facts["readback"] = supervisor._sink_readback(sink, receipt, att_text or "")
    except Exception as e:
        facts["readback"] = f"ERROR: {e.__class__.__name__}: {e}"
    facts["verified"] = facts.get("readback") is True
    return facts


def _attempt_aware_reentry(control_root, run_dir):
    """DF-R6-07: re-entry proof from the M61 attempt-aware recovery state (never
    the raw journal): the currently-APPLIED action set + any unresolved
    forward/rollback intents (a real unknown must NOT read as 'no duplicates')."""
    import supervisor
    try:
        st = supervisor._ship_action_recovery_state(run_dir)
    except Exception as e:
        return {"available": False, "reason": f"{e.__class__.__name__}: {e}"}
    unresolved = (st.get("unresolved_forward") or st.get("unresolved_rollback")
                  or bool(st.get("unknown_effect")))
    return {"available": True,
            "applied_actions": sorted((st.get("applied") or {}).keys()),
            "unknown_effect": sorted(st.get("unknown_effect") or []),
            "has_unresolved": bool(unresolved),
            "no_duplicate_or_unknown_actions": not unresolved}


def assemble(control_root, run_dir, key=None, require_production=False):
    """Return (bundle_dict, error). error is a string only when the run is
    unreadable (no manifest). With require_production=True the bundle also carries
    a `production_ready` verdict that fails closed on ANY missing/unverified
    required section — so a partial or mock exercise can never read as production
    evidence (DF-R6-07)."""
    manifest, mf_err = _read_json(os.path.join(run_dir, "manifest.json"))
    if manifest is None:
        return None, f"manifest.json {mf_err} in {run_dir}"
    if not isinstance(manifest, dict):
        return None, f"manifest.json is not a JSON object in {run_dir}"

    container = manifest.get("container") or {}
    ship_result, _ = _read_json(os.path.join(run_dir, "ship_result.json"))
    # DF-R6-07: the SEALED source identity (bound to the run, HMAC-signed when the
    # run is signed) vs. the value git shows at assembly time — reported both so a
    # mismatch (a checkout moved after the run) is visible, and the SEALED value is
    # authoritative.
    sealed_src = manifest.get("source_identity") or {}
    live_commit = _source_commit(control_root)
    manifest_v = _verified_manifest(control_root, run_dir, key)

    bundle = {
        "bundle_version": "2",
        "control_root": os.path.abspath(control_root),
        "run_dir": os.path.abspath(run_dir),
        "source": {
            "sealed_commit": sealed_src.get("commit"),
            "sealed_dirty": sealed_src.get("dirty"),
            "assembly_time_commit": live_commit,
            "matches_sealed": (sealed_src.get("commit") is not None
                               and sealed_src.get("commit") == live_commit),
        },
        "config_sha256": manifest.get("config_sha256"),
        "spec_sha256": manifest.get("spec_sha256"),
        "scenario_set_sha256": manifest.get("scenario_set_sha256"),
        "requested_tier": manifest.get("requested_tier", manifest.get("tier")),
        "effective_tier": manifest.get("effective_tier", manifest.get("tier")),
        "qualified": manifest.get("qualified"),
        "outcome": manifest.get("outcome"),
        "image": {"pinned": container.get("image_pinned"),
                  "resolved_image_digest": container.get("resolved_image_digest"),
                  "image": container.get("image")},
        "host_isolation": manifest.get("host_isolation"),
        "denial_probe_passed": manifest.get("denial_probe_passed"),
        "sandbox_backend": manifest.get("sandbox_backend"),
        "builder_confinement": manifest.get("builder_confinement"),
        "seccomp": manifest.get("seccomp"),
        "enterprise_egress": manifest.get("enterprise_egress"),
        "adapter_sha256": manifest.get("adapter_sha256"),
        "builder_identity": manifest.get("builder_identity"),
        # VERIFIED manifest (HMAC + artifact + chain membership), not just a hash.
        "manifest": manifest_v,
        # artifact identity from the SEALED manifest.artifact.object_id (the
        # authoritative location) — never the writable ship-result fallback.
        "artifact_object_id": (manifest.get("artifact") or {}).get("object_id"),
        "audit_chain": _verify_chain_output(control_root, key),
        # CRYPTOGRAPHICALLY verified custody + release, not presence/count.
        "custody": _verified_custody(control_root, run_dir, manifest, key),
        "release": _verified_release(control_root, run_dir, key),
        # receipts: positively read back + binding-checked.
        "ship_sink_receipt": _verified_receipt(control_root, run_dir, "ship_sink_receipt.json"),
        "qualification_sink_receipt": _verified_receipt(
            control_root, run_dir, "qualification_sink_receipt.json"),
        "release_sink_receipt": _verified_receipt(
            control_root, run_dir, "release_sink_receipt.json"),
        "ship_result": {
            "present": ship_result is not None,
            "outcome": (ship_result or {}).get("outcome"),
            "actions": [{"name": a.get("name"), "status": a.get("status"),
                         "reversible": a.get("reversible")}
                        for a in (ship_result or {}).get("actions", [])],
        },
        # attempt-aware re-entry proof (M61), not the raw journal.
        "reentry": _attempt_aware_reentry(control_root, run_dir),
    }

    if require_production:
        # Production evidence fails CLOSED on any unmet requirement — a partial or
        # mock exercise can never masquerade as a production-GO bundle.
        unmet = []
        if not manifest_v.get("manifest_verified"):
            unmet.append("manifest not verified (HMAC/artifact/chain-membership)")
        if bundle["source"]["sealed_commit"] is None:
            unmet.append("no sealed source commit")
        if bundle["source"]["sealed_dirty"]:
            unmet.append("source tree was DIRTY at run start")
        if bundle["audit_chain"].get("verified") is not True:
            unmet.append("signed audit chain not verified")
        if bundle["effective_tier"] not in ("standard", "hardened", "enterprise"):
            unmet.append(f"effective tier {bundle['effective_tier']!r} is not qualifiable")
        if bundle["qualified"] is not True and bundle["effective_tier"] != "enterprise":
            unmet.append("run is not qualified")
        if bundle["effective_tier"] == "enterprise" and bundle["custody"].get("verified") is not True:
            unmet.append("enterprise custody not cryptographically verified")
        if bundle["ship_result"]["present"] and bundle["release"]["present"] \
                and bundle["release"].get("verified") is not True:
            unmet.append("release attestation not verified")
        if bundle["reentry"].get("no_duplicate_or_unknown_actions") is not True:
            unmet.append("re-entry shows an unresolved/unknown ship action")
        bundle["production_ready"] = not unmet
        bundle["production_unmet"] = unmet

    return _scrub(bundle), None
