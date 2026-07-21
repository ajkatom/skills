"""M60 (Codex R5 arbitration §"Required evidence bundle"): assemble the
production-validation evidence bundle from a COMPLETED run.

Codex's arbitration (audit/10) splits acceptance into "code-complete" and
"production-validated release GO". The latter requires a representative live
hardened-H4 / enterprise exercise whose evidence is independently verifiable.
This module reads a finished control root + run dir and emits ONE JSON bundle
with exactly the fields the arbitration enumerates, pulled from the SEALED
artifacts (manifest, ship result, custody attestation, sink receipts, audit
chain) — never re-derived or re-run. It MUTATES nothing. DF-R7-07: it is
read-only but NOT offline — verifying a required off-box sink receipt performs a
read-only HTTP GET (http-append) or a signed S3 GET (s3-objectlock) against the
remote sink, so bundle assembly needs network reachability and, for S3, usable
read credentials (DF_AUDIT_S3_ACCESS_KEY / DF_AUDIT_S3_SECRET_KEY). It never
writes to the sink and makes no OTHER network calls.

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


def _read_text(path):
    """The exact on-disk bytes as text, or None — for chain authentication /
    token binding that must hash the real record, never a re-serialization."""
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except OSError:
        return None


def _source_commit(control_root):
    """The exact git commit of the SKILL source (this repo), or None. Best
    effort — a bundle from a non-git checkout just records None."""
    return _live_source_identity(control_root).get("commit")


def _live_source_identity(control_root):
    """DF-R7-04: the SAME commit + tree/content digest the supervisor's
    _source_identity_field seals, recomputed at bundle-assembly time so the
    bundle can compare the assembly-time source to the sealed one. Reuses the
    supervisor's own function so the digest formula can never drift between the
    two."""
    try:
        import supervisor
        return supervisor._source_identity_field()
    except Exception:
        return {"commit": None, "tree_digest": None, "clean": None}


def _source_matches(sealed_src, live_src):
    """True iff the assembly-time source matches the sealed identity — on the
    full tree/content digest when the manifest sealed one (DF-R7-04), else on the
    commit (a pre-M67 manifest). None sealed commit → never a match."""
    if sealed_src.get("commit") is None:
        return False
    st = sealed_src.get("tree_digest")
    if st is not None:
        return st == live_src.get("tree_digest")
    return sealed_src.get("commit") == live_src.get("commit")


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
    run_id = _run_id_of(run_dir)
    if att_bytes is not None:
        try:
            ok_c, _why = supervisor._authenticate_ship_chain(
                _cfg_of(control_root), control_root, run_id,
                df_common.sha256_str(att_bytes), "release")
            anchored = bool(ok_c)
        except Exception as e:
            anchored = f"ERROR: {e.__class__.__name__}: {e}"
    claim = att.get("claim") or {}
    # DF-R7-03: CRYPTOGRAPHICALLY verify the release — the K-of-N signatures over
    # the sealed approver policy/threshold, bound to THIS run+artifact, in scope,
    # unexpired — via df_release.verify_release, not merely chain membership.
    sig_verified = None
    sig_reason = None
    try:
        import df_release
        import datetime
        cfg = _cfg_of(control_root)
        ship = cfg.get("_ship") or {}
        approval = ship.get("approval") or {}
        manifest, _ = _read_json(os.path.join(run_dir, "manifest.json"))
        artifact_object_id = ((manifest or {}).get("artifact") or {}).get("object_id")
        signatures = att.get("signatures") or []
        ok_s, sig_reason, _count, _nonce = df_release.verify_release(
            claim=claim, signatures=signatures,
            approvers=approval.get("approvers") or [],
            threshold=approval.get("threshold"),
            run_id=run_id, artifact_object_id=artifact_object_id,
            now=datetime.datetime.now(datetime.timezone.utc), used_nonces=set())
        sig_verified = bool(ok_s)
    except Exception as e:
        sig_verified = f"ERROR: {e.__class__.__name__}: {e}"
    return {"present": True, "chain_anchored": anchored,
            "signatures_verified": sig_verified, "signature_reason": sig_reason,
            "verified": (anchored is True and sig_verified is True),
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
    # DF-R8-03: bind the custody + release receipts too (the v2 map covered only
    # the ship receipt, so a custody/release receipt read back as "verified" from
    # readback alone without proving it accompanies THIS run's attestation bytes).
    record_name = {"ship_sink_receipt.json": "ship_result.json",
                   "custody_sink_receipt.json": "custody_attestation.json",
                   "release_sink_receipt.json": "release_attestation.json"}.get(basename)
    att_text = None
    if record_name:
        try:
            with open(os.path.join(run_dir, record_name), encoding="utf-8") as f:
                att_text = f.read()
        except OSError:
            att_text = None
    # DF-R7-03: BIND the receipt to the exact current record bytes BEFORE the
    # positive readback — a receipt whose body_sha256 does not match the record
    # it accompanies proves nothing about THIS run's evidence.
    bound = None
    if record_name:
        try:
            ok_b, _why = supervisor._sink_receipt_bound(
                run_dir, basename, att_text or "", require_server_issued=True,
                sink=_cfg_of(control_root).get("_audit", {}).get("sink"))
            bound = bool(ok_b)
        except Exception as e:
            bound = f"ERROR: {e.__class__.__name__}: {e}"
    facts["bound"] = bound
    try:
        cfg = _cfg_of(control_root)
        sink = cfg.get("_audit", {}).get("sink", {"kind": "none"})
        facts["readback"] = supervisor._sink_readback(sink, receipt, att_text or "")
    except Exception as e:
        facts["readback"] = f"ERROR: {e.__class__.__name__}: {e}"
    # Verified only when the receipt is bound to the current bytes AND positively
    # read back off-box.
    facts["verified"] = (facts.get("readback") is True
                         and (bound is True or record_name is None))
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
    # DF-R7-03: proof of no-duplicate re-entry requires that a ship actually
    # RAN AND completed (a final SHIPPED ship_result) — an UNSHIPPED run has no
    # re-entry to attest and must NOT read as "no duplicates".
    ship_result, _ = _read_json(os.path.join(run_dir, "ship_result.json"))
    shipped = (ship_result or {}).get("outcome") == "SHIPPED"
    started = sum(1 for e in _ship_journal_events_safe(run_dir)
                  if e.get("state") == "SHIP_STARTED")
    return {"available": True,
            "applied_actions": sorted((st.get("applied") or {}).keys()),
            "unknown_effect": sorted(st.get("unknown_effect") or []),
            "has_unresolved": bool(unresolved),
            "shipped": shipped,
            "ship_started_count": started,
            # a real idempotent-re-entry proof: a SHIPPED terminal, no unresolved
            # or unknown action, and (when observed) more than one SHIP_STARTED
            # with no duplicated applied effect.
            "no_duplicate_or_unknown_actions": (shipped and not unresolved)}


def _ship_journal_events_safe(run_dir):
    path = os.path.join(run_dir, "ship_journal.jsonl")
    out = []
    if not os.path.exists(path):
        return out
    with open(path, encoding="utf-8") as f:
        for line in f:
            try:
                out.append(json.loads(line))
            except ValueError:
                continue
    return out


def _ship_result_authenticated(control_root, run_id, ship_result_text):
    """DF-R8-02: verify the EXACT ship_result.json bytes are anchored in the signed
    chain under this run's `ship` namespace — not merely present in a writable file.
    None when there is no ship_result to authenticate."""
    if ship_result_text is None:
        return None
    import supervisor
    try:
        ok, _why = supervisor._authenticate_ship_chain(
            _cfg_of(control_root), control_root, run_id,
            df_common.sha256_str(ship_result_text), "ship")
        return bool(ok)
    except Exception as e:
        return f"ERROR: {e.__class__.__name__}: {e}"


def _reentry_verified(control_root, run_dir, run_id, ship_result_text):
    """DF-R8-02: True iff a signed SHIP_REENTRY_VERIFIED token exists — recomputed
    from a journaled event (nonce + ship_result_sha256) and ANCHORED in the signed
    chain — binding the sha256 of the EXACT current ship_result bytes. That is the
    positive proof the mandated idempotent re-entry ran against THIS terminal
    without redispatch (the emitting path returns before the action loop)."""
    if ship_result_text is None:
        return {"present": False, "verified": False, "reason": "no ship_result.json"}
    import supervisor
    import df_audit
    import df_audit_chain
    target_sha = df_common.sha256_str(ship_result_text)
    cfg = _cfg_of(control_root)
    try:
        key = df_audit.load_key(cfg.get("_audit", {}).get("key_path"))
    except Exception as e:
        return {"present": False, "verified": False, "reason": f"key: {e}"}
    chain_path = os.path.join(control_root, "audit-chain.jsonl")
    try:
        ok, why = df_audit_chain.verify_chain(chain_path, key)
        if not ok:
            return {"present": False, "verified": False, "reason": f"chain: {why}"}
        anchored = {e.get("manifest_sha256") for e in df_audit_chain.read_chain(chain_path)
                    if str(e.get("invocation", "")).startswith(f"{run_id}.ship-reentry.")}
    except Exception as e:
        return {"present": False, "verified": False, "reason": f"{e.__class__.__name__}: {e}"}
    events = [e for e in _ship_journal_events_safe(run_dir)
              if e.get("state") == "SHIP_REENTRY_VERIFIED"]
    for e in events:
        d = e.get("data", {})
        if d.get("ship_result_sha256") != target_sha:
            continue
        token = df_common.sha256_str(supervisor._ship_reentry_payload(
            run_id, target_sha, d.get("nonce")))
        if token in anchored:
            return {"present": True, "verified": True, "count": len(events)}
    return {"present": bool(events), "verified": False,
            "reason": "no anchored SHIP_REENTRY_VERIFIED binds the current ship_result bytes"}


def assemble(control_root, run_dir, key=None, require_production=False, profile=None):
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
    # DF-R8-02: the RAW ship_result bytes (for chain authentication + the re-entry
    # token binding), never a re-serialization.
    ship_result_text = _read_text(os.path.join(run_dir, "ship_result.json"))
    # DF-R6-07: the SEALED source identity (bound to the run, HMAC-signed when the
    # run is signed) vs. the value git shows at assembly time — reported both so a
    # mismatch (a checkout moved after the run) is visible, and the SEALED value is
    # authoritative.
    sealed_src = manifest.get("source_identity") or {}
    live_src = _live_source_identity(control_root)
    manifest_v = _verified_manifest(control_root, run_dir, key)

    bundle = {
        "bundle_version": "2",
        "control_root": os.path.abspath(control_root),
        "run_dir": os.path.abspath(run_dir),
        "source": {
            "sealed_commit": sealed_src.get("commit"),
            "sealed_clean": sealed_src.get("clean"),   # DF-R7-04 tri-state
            "sealed_dirty": sealed_src.get("dirty"),
            "sealed_tree_digest": sealed_src.get("tree_digest"),
            "assembly_time_commit": live_src.get("commit"),
            "assembly_time_tree_digest": live_src.get("tree_digest"),
            # DF-R7-04: match on the full tree/content digest (not just the
            # commit — two trees can share one commit), falling back to commit
            # for a pre-M67 manifest with no sealed tree_digest.
            "matches_sealed": _source_matches(sealed_src, live_src),
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
        # DF-R8-03: the supervisor seals the enterprise seccomp proof under
        # `enterprise_seccomp` (supervisor.py _finalize; NOT `seccomp`). The v2
        # bundle read the wrong key, so the enterprise profile could never see it.
        "enterprise_seccomp": manifest.get("enterprise_seccomp"),
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
        # DF-R8-03: custody attach writes/verifies `custody_sink_receipt.json`
        # (supervisor.py attach_custody); the v2 bundle looked for a nonexistent
        # `qualification_sink_receipt.json`, so the enterprise custody receipt was
        # always "absent". Read the real filename and bind it to its attestation.
        "custody_sink_receipt": _verified_receipt(
            control_root, run_dir, "custody_sink_receipt.json"),
        "release_sink_receipt": _verified_receipt(
            control_root, run_dir, "release_sink_receipt.json"),
        "ship_result": {
            "present": ship_result is not None,
            "outcome": (ship_result or {}).get("outcome"),
            "actions": [{"name": a.get("name"), "status": a.get("status"),
                         "reversible": a.get("reversible")}
                        for a in (ship_result or {}).get("actions", [])],
            # DF-R8-02: the EXACT ship_result bytes must be chain-anchored, not
            # merely present in the writable file.
            "authenticated": _ship_result_authenticated(
                control_root, _run_id_of(run_dir), ship_result_text),
        },
        # attempt-aware re-entry proof (M61), not the raw journal.
        "reentry": dict(_attempt_aware_reentry(control_root, run_dir),
                        # DF-R8-02: positive, chain-authenticated proof the mandated
                        # idempotent re-entry ran against THIS terminal.
                        reentry_verified=_reentry_verified(
                            control_root, run_dir, _run_id_of(run_dir),
                            ship_result_text)),
    }

    if require_production:
        bundle["production_profile"] = profile
        bundle["production_ready"], bundle["production_unmet"] = _production_verdict(
            bundle, manifest_v, manifest, profile)

    return _scrub(bundle), None


def _production_verdict(bundle, manifest_v, manifest, profile):
    """DF-R7-03: fail CLOSED unless EVERY fact a named production profile requires
    is present, non-null, bound, and cryptographically verified. A partial/mock
    exercise, an unshipped run, or an unrecognized/absent profile can never read
    as production-GO. Returns (ready: bool, unmet: [str])."""
    unmet = []
    if profile not in ("hardened-h4", "enterprise"):
        return (False, [f"no recognized production profile (got {profile!r}; "
                        "use --profile hardened-h4 | enterprise)"])

    src = bundle["source"]
    container = manifest.get("container") or {}

    # --- facts EVERY production profile requires ---
    if not manifest_v.get("manifest_verified"):
        unmet.append("manifest not verified (HMAC + artifact + chain membership)")
    if src["sealed_commit"] is None:
        unmet.append("no sealed source commit")
    if src.get("sealed_clean") is not True:      # DF-R7-04: clean must be EXPLICIT True
        unmet.append("source tree not explicitly clean at run start")
    # DF-R8-04 (opus review, M71 residual): a null sealed tree_digest makes
    # `matches_sealed` degrade to a COMMIT-ONLY comparison (the exact weakness the
    # R7-04 tree_digest exists to remove) — and `{clean:True, tree_digest:null}` is
    # an impossible honest combination (a forged/emptied anchor). Require a real
    # sealed tree digest for a production GO; a commit-only source binding is not
    # sufficient.
    if not src.get("sealed_tree_digest"):
        unmet.append("no sealed source-tree digest (a commit-only source binding is not "
                     "sufficient for production evidence — R7-04/R8-04)")
    if not src.get("matches_sealed"):
        unmet.append("assembly-time source does not match the sealed source identity")
    if bundle["audit_chain"].get("verified") is not True:
        unmet.append("signed audit chain not verified")
    if bundle["ship_result"]["outcome"] != "SHIPPED":
        unmet.append("no final SHIPPED ship_result")
    # DF-R8-02: the FINAL ship record itself must be authenticated against the
    # signed chain — not merely present with outcome "SHIPPED" in a writable file.
    if bundle["ship_result"].get("authenticated") is not True:
        unmet.append("the final ship_result.json is not anchored in the signed audit chain")
    if bundle["reentry"].get("no_duplicate_or_unknown_actions") is not True:
        unmet.append("no authenticated idempotent re-entry proof (unshipped or unresolved)")
    # DF-R8-02: require the POSITIVE, signed re-entry fact — a SHIP_REENTRY_VERIFIED
    # token binding the exact ship_result bytes — so the mandated 'ship again' proof
    # is present and no new action was dispatched on re-entry.
    if bundle["reentry"].get("reentry_verified", {}).get("verified") is not True:
        unmet.append("no signed SHIP_REENTRY_VERIFIED proof of an idempotent re-entry "
                     "against this exact terminal")
    # DF-R8-03: the sealed configuration policy must be bound. config_sha256 is
    # HMAC-covered by a verified manifest, so a non-null config_sha256 under a
    # verified manifest proves the run's config policy (approver allowlist, tier,
    # gates) is the sealed one. A null config binding is fail-closed.
    if not bundle.get("config_sha256"):
        unmet.append("no sealed config_sha256 (configuration policy not bound)")

    # DF-R7-03 (opus F2): an irreversible action's release must verify under EVERY
    # profile, not only enterprise. `reversible is True` counts an action as
    # reversible — a missing/None label is treated as irreversible (fail-closed).
    irr_actions = {a.get("name") for a in bundle["ship_result"].get("actions", [])
                   if a.get("reversible") is not True}
    irreversible = bool(irr_actions)
    if irreversible and bundle["release"].get("verified") is not True:
        unmet.append("an irreversible (or unlabeled) action shipped but the release "
                     "attestation is not cryptographically verified")
    # DF-R8-03: the release approval must COVER every irreversible shipped action —
    # a release scoped to a subset (or a removed release receipt) leaves an
    # irreversible effect unauthorized.
    if irreversible:
        covered = set(bundle["release"].get("action_names") or [])
        if not irr_actions.issubset(covered):
            unmet.append("the release attestation scope does not cover every irreversible "
                         f"shipped action (covered {sorted(covered)}, irreversible "
                         f"{sorted(irr_actions)})")

    def _image_digest_pinned():
        # DF-R8-03: a resolved digest is necessary but NOT sufficient — a mutable
        # `:latest` tag resolves to a digest at run time yet is not pinned. Accept
        # EITHER an @sha256-pinned configured image REFERENCE (a cryptographic pin
        # on its own — no resolved digest needed; opus review LOW: `resolve_image_
        # digest` fails open to None on a docker outage, which must not falsely fail
        # a genuinely-pinned run) OR image_pinned==true backed by a resolved digest.
        img = bundle["image"]
        if "@sha256:" in str(img.get("image") or ""):
            return True
        return img.get("pinned") is True and bool(img.get("resolved_image_digest"))

    if profile == "hardened-h4":
        if bundle["effective_tier"] != "hardened":
            unmet.append(f"effective tier is {bundle['effective_tier']!r}, not hardened")
        if bundle["qualified"] is not True:
            unmet.append("run is not qualified")
        if (manifest.get("intervention_mode") not in ("H4", "lights_out")):
            unmet.append("run was not H4 (lights-out)")
        if not _image_digest_pinned():
            unmet.append("container image is not digest-pinned "
                         "(need image_pinned or an @sha256-pinned image reference)")
        if bundle["denial_probe_passed"] is not True:
            unmet.append("denial/confinement probe did not pass")

    elif profile == "enterprise":
        if bundle["effective_tier"] != "enterprise":
            unmet.append(f"effective tier is {bundle['effective_tier']!r}, not enterprise")
        if bundle["custody"].get("verified") is not True:
            unmet.append("enterprise custody not cryptographically verified")
        if not _image_digest_pinned():
            unmet.append("container image is not digest-pinned "
                         "(need image_pinned or an @sha256-pinned image reference)")
        egress = bundle.get("enterprise_egress") or {}
        if not (egress.get("probed") and egress.get("passed")):
            unmet.append("enterprise egress probe did not pass")
        # DF-R8-03: the sealed enterprise seccomp proof (was read from the wrong
        # manifest key by the v2 bundle, so this was never checkable).
        sec = bundle.get("enterprise_seccomp") or {}
        if sec.get("probe") != "verified":
            unmet.append("enterprise seccomp proof not sealed/verified")
        # DF-R8-03: denial probe + builder confinement ACTUALLY applied.
        if bundle["denial_probe_passed"] is not True:
            unmet.append("denial/confinement probe did not pass")
        conf = bundle.get("builder_confinement") or {}
        if conf.get("enabled") is not True or conf.get("probe") == "unsupported":
            unmet.append("builder confinement was not applied (enabled/probe)")
        # a required S3 Object-Lock sink, server-issued + bound + read back:
        rcpt = bundle["ship_sink_receipt"]
        if not (rcpt.get("present") and rcpt.get("kind") == "s3-objectlock"
                and rcpt.get("server_issued") and rcpt.get("version_id")
                and rcpt.get("verified") is True):
            unmet.append("required s3-objectlock ship receipt not server-issued/bound/read-back")
        # DF-R8-03: the custody attestation's off-box receipt must be bound + read
        # back too (enterprise mandates the WORM sink for custody, not only ship).
        crcpt = bundle["custody_sink_receipt"]
        if not (crcpt.get("present") and crcpt.get("verified") is True):
            unmet.append("custody sink receipt not present/bound/read-back")
        # DF-R8-03: when an irreversible action shipped, its release attestation's
        # off-box receipt must be bound + read back (a removed release receipt after
        # shipping leaves the authorization unattested off-box).
        if irreversible:
            rrcpt = bundle["release_sink_receipt"]
            if not (rrcpt.get("present") and rrcpt.get("verified") is True):
                unmet.append("release sink receipt not present/bound/read-back for an "
                             "irreversible enterprise ship")

    return (not unmet, unmet)
