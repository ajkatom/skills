"""Post-seal attestation paths: split-custody (df-custody attach/verify) and signed security waivers (df-waiver attach/verify).

Extracted verbatim from supervisor.py (see supervisor.py for the CLI entry point and
the run/resume core). Every top-level name here is re-exported by supervisor.py, so
`supervisor.<name>` keeps working for tests and df_evidence_bundle.
"""
import datetime
import hashlib
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

import df_audit
import df_audit_chain
import df_audit_sink
import df_custody
import df_qualify
import df_seal
import df_waiver
from df_common import atomic_write, canonical_json, sha256_str
from df_config import (
    MANDATORY_TIERS,
    ConfigError,
)
from supervisor_audit import (
    CUSTODY_ATTESTATION_FILE,
    _authenticate_manifest,
    _custody_config_bound,
    _load_custody_signatures,
    _read_manifest_bytes,
    _satisfying_approvers,
)
from supervisor_core import (
    _ARTIFACT_OK,
    _QUALIFYING_TIERS,
    LockError,
    _candidate_egress_qualified,
    _now,
    _object_store_root,
    _sup,
    _verify_manifest_status,
    acquire_lock,
    release_lock,
)

# ---------------------------------------------------------------------------
# M44 RA-02/RA-03: the post-seal attestation paths (custody / waiver / release)
# must (1) require a successful REQUIRED off-box sink receipt BEFORE a run is
# locally qualifiable and roll back on failure, and (2) refuse to attest an
# INELIGIBLE manifest. The helpers below are shared by all three paths so the
# eligibility/receipt logic is defined once, not re-derived ad hoc.
# ---------------------------------------------------------------------------

def _effective_tier_of(manifest_obj: dict):
    """R5 DF-R5-04: the EFFECTIVE assurance tier the sealed run actually ran at —
    what every post-seal decision (qualification, custody, release, ship) MUST
    consume, so a permitted --allow-downgrade never yields a requested-vs-effective
    mismatch (e.g. an enterprise run downgraded to hardened that seals
    COMPLETE_QUALIFIED via the hardened branch but is then un-shippable because
    ship/custody read the configured `tier:"enterprise"` and demand a custody
    attestation that can never attach). Falls back to `tier` for pre-M57 manifests
    that sealed only the configured tier."""
    return manifest_obj.get("effective_tier", manifest_obj.get("tier"))


def _precustody_substates(manifest_obj: dict) -> dict:
    """RA-03: recompute the five qualification substates from a SEALED
    manifest's OWN fields via df_qualify.derive — never trust a stored
    `qualification.qualified` boolean (which a hand-edited manifest could
    lie about; the manifest's HMAC/sidecar is authenticated separately by
    the caller). Returns df_qualify.derive's `{qualified, substates, code}`.

    app_security mirrors the CONVERGED branch's own rule: vacuously true below
    a mandatory tier (gates optional there), otherwise "gates checked AND
    nothing failed". barrier/host_isolation/control_plane read the sealed
    tier / host_isolation.qualified / bound artifact object_id."""
    tier = _effective_tier_of(manifest_obj)  # R5 DF-R5-04: consume the EFFECTIVE tier
    hi = manifest_obj.get("host_isolation") or {}
    art = manifest_obj.get("artifact")
    sec = manifest_obj.get("security") or {}
    app_security = (tier not in MANDATORY_TIERS) or (
        bool(sec.get("checked")) and not sec.get("failed"))
    return df_qualify.derive(
        barrier=tier in _QUALIFYING_TIERS,
        host_isolation=bool(hi.get("qualified")),
        candidate_egress=_candidate_egress_qualified(manifest_obj.get("candidate_network")),
        control_plane=bool(isinstance(art, dict) and art.get("object_id")),
        app_security=bool(app_security),
        waiver_validity=True)


def _final_exam_ok(manifest_obj: dict) -> bool:
    """RA-03: the sealed final exam must have PASSED if it ran. A final cohort
    that never ran (no held-out scenarios existed) is allowed per policy."""
    fe = manifest_obj.get("final_exam") or {}
    if fe.get("ran"):
        return fe.get("passed") is True
    return True


def _push_qualification_offbox(cfg: dict, sink_key: str, att_text: str):
    """RA-02 (attach side): push a qualification attestation to the audit sink
    BEFORE it is treated as valid, so "enterprise qualification must leave the
    box" is actually enforced rather than best-effort-after-the-fact. Writes
    NOTHING to disk — the caller persists the attestation/chain/receipt ONLY
    after this returns a non-required-failure.

    Returns (status, receipt_or_None, detail):
      "skip"          no sink configured (kind==none) — nothing to push
      "ok"            pushed; receipt dict (augmented with body_sha256 +
                      sink_key so a later verify can bind it) to persist
      "optional_fail" push failed but the sink is NOT required — proceed, warn
      "required_fail" push failed AND the sink is required — the caller MUST
                      fail closed and roll back (no attestation, no chain link,
                      no receipt): the run must NOT be locally qualifiable."""
    sink = cfg.get("_audit", {}).get("sink", {"kind": "none", "required": False})
    if sink.get("kind", "none") == "none":
        return ("skip", None, "")
    try:
        receipt = df_audit_sink.push(sink, sink_key, att_text.encode("utf-8"))
    except df_audit_sink.SinkError as e:
        return (("required_fail" if sink.get("required") else "optional_fail"), None, str(e))
    # Bind the persisted receipt to the EXACT attestation bytes that were
    # pushed (independent of sink kind / server-chosen receipt string), so the
    # verify side can prove the receipt is for THIS attestation, not a stale one.
    receipt = dict(receipt, body_sha256=sha256_str(att_text), sink_key=sink_key)
    return ("ok", receipt, "")


def _sink_readback(sink: dict, receipt: dict, att_text: str):
    """DF-R4-04 best-effort READBACK: when the required sink is REACHABLE, confirm
    the object the receipt claims was pushed actually exists off-box with these
    exact bytes. Returns:
      True   — read back and the off-box bytes match (server-authentic)
      False  — read back and the object is ABSENT or its bytes DIFFER (a forged /
               never-pushed / tampered receipt) → the caller REJECTS
      None   — could not confirm (sink unreachable / kind unsupported). For a
               REQUIRED receipt the caller treats anything other than True as
               not-confirmed and REFUSES (M53/M56: a required sink demands
               POSITIVE off-box confirmation — inconclusive is not acceptance);
               an unreachable sink is thus a temporary refusal, retryable.
    This is what makes a purely-local http-append receipt non-forgeable: the
    fabricated object was never PUT, so a GET against the off-box trust domain
    404s."""
    kind = sink.get("kind", "none")
    if kind == "http-append":
        sink_key = receipt.get("sink_key")
        if not sink_key:
            return None
        url = sink["url"].rstrip("/") + f"/audit/{urllib.parse.quote(str(sink_key), safe='')}"
        try:
            with urllib.request.urlopen(url, timeout=10) as resp:
                if resp.status != 200:
                    return None
                body = resp.read()
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return False  # the receipt names an object that is NOT off-box
            return None
        except (urllib.error.URLError, TimeoutError, OSError):
            return None  # unreachable → inconclusive, not a rejection
        return hashlib.sha256(body).hexdigest() == receipt.get("body_sha256")
    if kind == "s3-objectlock":
        # R5 DF-R5-07: a signed S3 GET of the exact recorded object key makes an
        # S3-backed receipt idempotently re-verifiable (previously always None →
        # a completed S3 ship could never positively re-verify and every re-entry
        # re-pushed / flipped to audit-pending). 200 → compare bytes; 404 → absent
        # off-box (reject); unreachable/uncredentialed → inconclusive (None).
        sink_key = receipt.get("sink_key")
        if not sink_key:
            return None
        # M60 (R5 arbitration M56.6): read the EXACT recorded version, so a
        # versioned bucket's readback verifies the precise pushed bytes, not a
        # later version at the same key. Absent version_id (pre-M60 receipt) →
        # latest, as before.
        status, body = df_audit_sink.signed_s3_get(
            sink, str(sink_key), version_id=str(receipt.get("version_id") or ""))
        if status == 200 and body is not None:
            return hashlib.sha256(body).hexdigest() == receipt.get("body_sha256")
        if status == 404:
            return False
        return None
    # other kinds: no cheap stdlib readback here; inconclusive.
    return None


def _sink_receipt_bound(run_dir: str, receipt_basename: str, att_text: str, *,
                        require_server_issued: bool = False, sink: dict | None = None):
    """RA-02 (verify side): True iff `<run_dir>/<receipt_basename>` exists, is
    well-formed, and is BOUND to `att_text` (its recorded body_sha256 equals
    the sha256 of the current attestation bytes). Fail-closed: absent,
    unparseable, or mismatched → (False, reason). Only consulted when the
    sealed config's `audit.sink.required` is true.

    DF-R4-04: with `require_server_issued=True` (the ship-verify path for a
    REQUIRED sink) the body_sha256 bind is NECESSARY but no longer SUFFICIENT — it
    is locally computable. The `server_issued` flag is ALSO not sufficient on its
    own: it lives in the (same-user-writable) receipt file, so an attacker simply
    writes `server_issued: true`. The ONLY thing that binds the receipt to the
    off-box trust domain is a POSITIVE readback — a GET against the sink proving the
    anchored object exists with these exact bytes. So a required-server-issued check
    demands `server_issued: true` AND a readback that returns True. An absent /
    unreachable / inconclusive sink (readback None) or a byte mismatch (readback
    False) does NOT satisfy the check — a same-user attacker cannot make a dead or
    never-written off-box object read back positively (R4 re-audit: readback used to
    fail OPEN on None, which the audit-pending-sink-outage condition triggers). The
    legitimate finalize decision is made at push time (a reachable sink returning a
    server receipt), not here — this is the RE-ENTRY verification of an already
    -sealed SHIPPED record, and it is deliberately fail-closed when the sink cannot
    currently be confirmed (it triggers the idempotent retry, never a silent 0)."""
    path = os.path.join(run_dir, receipt_basename)
    if not os.path.exists(path):
        return (False, f"required off-box sink receipt {receipt_basename} is absent")
    try:
        with open(path, encoding="utf-8") as f:
            receipt = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        return (False, f"unreadable sink receipt {receipt_basename}: {e}")
    if not isinstance(receipt, dict):
        return (False, f"malformed sink receipt {receipt_basename}")
    if receipt.get("body_sha256") != sha256_str(att_text):
        return (False, f"sink receipt {receipt_basename} does not bind these attestation bytes")
    if require_server_issued:
        if receipt.get("server_issued") is not True:
            return (False, f"sink receipt {receipt_basename} carries no server-issued value "
                    "(a locally-computable receipt is not off-box evidence)")
        # server_issued is attacker-writable → require a POSITIVE off-box readback.
        confirmed = _sink_readback(sink, receipt, att_text) if sink is not None else None
        if confirmed is not True:
            return (False, f"sink receipt {receipt_basename} could not be POSITIVELY confirmed "
                    "off-box (the anchored object is absent, the sink is unreachable, or its "
                    "bytes differ) — a locally-written server_issued flag is not off-box evidence")
    return (True, "ok")


def _sink_required(cfg: dict) -> bool:
    """Whether the sealed config mandates an off-box audit sink (RA-02). The
    config is policy-bound to the run via config_sha256, so this reflects the
    sealed posture, not a post-run edit."""
    return bool(cfg.get("_audit", {}).get("sink", {}).get("required"))


def attach_custody(control_root: str, run_dir: str) -> int:
    """`df-custody attach` — PHASE 2 of the split-custody two-phase ship
    (references/enterprise.md). Reads the run's IMMUTABLE, already-sealed
    manifest.json (never rewrites it) and the collected approver signatures
    (`<control_root>/custody-signatures.json`), and verifies them via
    df_custody.verify_custody over the EXACT sealed manifest bytes against the
    config's approver allowlist + threshold.

    Satisfied (>=K distinct valid approver signatures): writes a SEPARATE
    `<run_dir>/custody_attestation.json` = {manifest_sha256, threshold,
    approvers_satisfied, signatures, qualified: true, ts} AND anchors it into
    the per-control-root hash chain (df_audit_chain -- tamper-evident, the
    same M13 chain), then returns 0. The manifest still reads
    outcome:CUSTODY_PENDING -- qualification lives in the attestation, never
    in a manifest rewrite (no single process/operator can self-ship).

    Not satisfied: prints PENDING with the distinct-count reason, writes NO
    attestation, and returns 3.

    DF-01/M28a Task 3: custody-by-object-id. A manifest whose `artifact` is
    null/absent PREDATES artifact binding (pre-M28a) and is refused outright
    -- split custody exists to attest a specific artifact, and there is
    nothing to bind to. When `artifact` IS present, its bound object_id must
    independently re-verify against the LIVE object store (df_seal.
    verify_object) before ANY attestation is written -- a mutated or
    unavailable object refuses exactly like an unsatisfied K-of-N, never a
    silent attest-over-drifted-bytes.
    """
    manifest_bytes, manifest_sha = _read_manifest_bytes(run_dir)
    if manifest_bytes is None:
        sys.stderr.write(f"dark-factory: no manifest.json in {run_dir}\n")
        return 3
    try:
        manifest_obj = json.loads(manifest_bytes)
    except json.JSONDecodeError as e:
        sys.stderr.write(f"dark-factory: manifest.json is not valid JSON: {e}\n")
        return 2
    artifact = manifest_obj.get("artifact")
    if not isinstance(artifact, dict) or not isinstance(artifact.get("object_id"), str):
        sys.stderr.write(
            "dark-factory: manifest predates artifact binding (no manifest[\"artifact\"]) — "
            "re-run under DF-01/M28a to get an object-bound manifest before requesting "
            "custody.\n")
        return 3
    object_id = artifact["object_id"]
    object_store = _object_store_root(control_root)
    if not df_seal.verify_object(object_store, object_id):
        sys.stderr.write(
            f"dark-factory: artifact object {object_id} failed identity re-verification "
            "against the live object store — refusing to attest a manifest whose bound "
            "artifact cannot be confirmed (mismatch or unavailable).\n")
        return 3

    try:
        cfg = _sup().load_config(control_root)
    except ConfigError as e:
        sys.stderr.write(f"dark-factory: config error: {e}\n")
        return 2
    if cfg["_custody"] is None:
        sys.stderr.write("dark-factory: control root has no `custody` block; nothing to attach\n")
        return 2

    # DF-R9-07 (M79): AUTHENTICATE the sealed manifest (HMAC) BEFORE trusting the
    # config_sha256 binding below — see verify_custody_cmd. A control-root writer who
    # rewrites config.json + the manifest's config_sha256 + the PLAIN manifest.sha256
    # and self-signs with their own approver key leaves the manifest HMAC STALE; this
    # returns TAMPERED and refuses, so custody cannot be self-qualified.
    ok_m, why_m = _authenticate_manifest(cfg, control_root, run_dir)
    if not ok_m:
        sys.stderr.write(
            f"dark-factory: custody attach refused — the sealed manifest failed authentication "
            f"({why_m}); refusing to attest an unauthenticated manifest (fail-closed).\n")
        return 3

    # Refuse if config.json changed since the run — the custody policy
    # (approvers/threshold) is bound to the manifest's sealed config_sha256,
    # so post-run threshold/approver tampering fails closed (see
    # _custody_config_bound).
    bound, sealed_sha, current_sha = _custody_config_bound(cfg, manifest_bytes)
    if not bound:
        sys.stderr.write(
            "dark-factory: config.json changed since this run (custody policy is bound to the "
            f"sealed config_sha256 {sealed_sha} != current {current_sha}); attestation refused "
            "— re-run under the intended config.\n")
        return 3

    approvers = cfg["_custody"]["approvers"]
    threshold = cfg["_custody"]["threshold"]
    signatures, load_reason = _load_custody_signatures(control_root)
    satisfied, reason = df_custody.verify_custody(manifest_bytes, signatures, approvers, threshold)
    if not satisfied:
        print(f"dark-factory: CUSTODY PENDING — not attached ({load_reason or reason}). "
              f"Collect >={threshold} distinct approver signatures over the sealed manifest, then "
              f"re-run df-custody attach.")
        return 3

    # M44 RA-03: K-of-N signatures alone must NOT qualify an INELIGIBLE
    # manifest. A custody attestation qualifies ONLY the enterprise pending
    # terminal whose pre-custody evidence all holds; a signed-but-ineligible
    # manifest (SECURITY_GATE_FAILED, HOST_ISOLATION_LIMITED, a failed final
    # exam, or any non-CUSTODY_PENDING outcome) is refused, never attested.
    if manifest_obj.get("outcome") != "CUSTODY_PENDING":
        sys.stderr.write(
            f"dark-factory: refusing custody attestation — run outcome is "
            f"{manifest_obj.get('outcome')!r}, not CUSTODY_PENDING (a custody sign-off "
            "qualifies only the enterprise pending terminal, never a run that failed a "
            "gate/exam).\n")
        return 3
    subs = _precustody_substates(manifest_obj)
    if not subs["qualified"] or not _final_exam_ok(manifest_obj):
        reasons = [k for k, v in subs["substates"].items() if not v]
        if not _final_exam_ok(manifest_obj):
            reasons.append("final_exam")
        sys.stderr.write(
            "dark-factory: refusing custody attestation — the run's pre-custody evidence "
            f"is not eligible (failing: {', '.join(reasons) or subs['code']}). A valid K-of-N "
            "cannot qualify a run that did not otherwise converge cleanly.\n")
        return 3

    satisfied_set = _satisfying_approvers(manifest_bytes, signatures, approvers)
    kept_sigs = [
        {"approver": e["approver"].lower(), "sig": e["sig"]}
        for e in signatures
        if isinstance(e, dict) and isinstance(e.get("approver"), str)
        and e["approver"].lower() in satisfied_set
        and isinstance(e.get("sig"), str)
    ]
    attestation = {
        "attestation_version": "0.1",
        "manifest_sha256": manifest_sha,
        "threshold": threshold,
        "approvers_satisfied": satisfied_set,
        "signatures": kept_sigs,
        "qualified": True,
        "ts": _now(),
    }

    # DF-01/M28a Task 3: writing the attestation + anchoring it into the hash
    # chain must not race a concurrent attach/run/resume over the same
    # control root (attach previously took no lock at all). Held for exactly
    # the write section below -- the reads/checks above are safe unlocked.
    try:
        lock = acquire_lock(control_root)
    except LockError as e:
        sys.stderr.write(f"dark-factory: {e}\n")
        return 2
    try:
        att_text = canonical_json(attestation)
        att_path = os.path.join(run_dir, CUSTODY_ATTESTATION_FILE)
        # The audit key is required at enterprise (audit.signing), so a
        # signed chain link binds this attestation off the manifest it
        # qualifies. Loaded up front so a key error fails BEFORE any off-box
        # push (nothing partially committed).
        audit_key = None
        if cfg.get("_audit", {}).get("signing"):
            try:
                audit_key = df_audit.load_or_create_key(cfg["_audit"]["key_path"])
            except df_audit.AuditKeyError as e:
                sys.stderr.write(f"dark-factory: audit key error: {e}\n")
                return 2
        # Dot-separated (not ':') so the same key is a valid http-append sink
        # key: the reference receiver's key regex is [A-Za-z0-9._-], and a
        # ':' would be percent-encoded to %3A and rejected.
        custody_key = os.path.basename(run_dir) + ".custody"

        # M44 RA-02: push the QUALIFICATION event off-box FIRST. Enterprise
        # MANDATES audit.sink.required:true, so a required-sink failure means
        # the run must NOT be locally qualifiable — we return BEFORE writing
        # the attestation OR anchoring the chain, so nothing on disk implies a
        # qualification that never left the box (the pre-M44 bug wrote + anchored
        # the attestation first, then returned 3 on push failure, leaving a
        # locally-QUALIFIED run). The pushed body is the attestation itself.
        push_status, receipt, detail = _push_qualification_offbox(cfg, custody_key, att_text)
        if push_status == "required_fail":
            sys.stderr.write(
                f"dark-factory: CUSTODY NOT ATTESTED — the REQUIRED audit sink push FAILED "
                f"({detail}); enterprise qualification must be recorded off-box. No local "
                f"attestation was written. Fix the sink and re-run df-custody attach.\n")
            return 3
        if push_status == "optional_fail":
            sys.stderr.write(f"dark-factory: audit sink push warning (not required): {detail}\n")

        # Off-box record is committed (or no/optional sink): now persist locally.
        atomic_write(att_path, att_text)
        chain_path = os.path.join(control_root, "audit-chain.jsonl")
        entry = df_audit_chain.append_entry(
            chain_path, custody_key, sha256_str(att_text), _now(), audit_key)
        # DF-R9-04: keep the off-box committed lengths DENSE — checkpoint this
        # custody anchor too (the required-sink record push above already fails closed
        # when the sink is down), else its length would be a HOLE an attacker could
        # truncate to undetected (opus review F1). DF-R12-01: a required-sink checkpoint
        # that does not land leaves this run not off-box-complete (the production
        # predicate requires the dense-baseline marker) — surfaced, not silent.
        if (not _sup()._checkpoint_chain_to_sink(cfg, control_root)
                and cfg.get("_audit", {}).get("sink", {}).get("required")):
            sys.stderr.write(
                "dark-factory: WARNING — the custody chain-length checkpoint did not land on "
                "the REQUIRED off-box sink; this run is NOT off-box-complete until the next "
                "checkpoint backfills the length.\n")
        if receipt is not None:
            atomic_write(os.path.join(run_dir, "custody_sink_receipt.json"),
                         canonical_json(receipt))

        print(f"dark-factory: CUSTODY ATTESTED — {reason}; qualified. "
              f"Attestation: {att_path}  Chain: {entry['chain_hash'][:16]}…")
        return 0
    finally:
        release_lock(lock)


def verify_custody_cmd(control_root: str, run_dir: str) -> bool:
    """CLI body for `verify-custody` — read-only confirmation that a run is
    QUALIFIED under split custody. Recomputes the CURRENT manifest.json
    sha256, loads `<run_dir>/custody_attestation.json`, checks the attestation
    binds THIS manifest (its manifest_sha256 must equal the current one -- a
    single-byte manifest edit breaks this), and RE-VERIFIES the attestation's
    recorded signatures still satisfy K-of-N over the current manifest bytes
    against the config's approver allowlist + threshold (so a forged
    attestation, or one carrying signatures over stale bytes, fails). Prints
    QUALIFIED (return True) / a PENDING-or-INVALID reason (return False).

    DF-01/M28a Task 3: custody-by-object-id. Before any of the above, the
    manifest must bind an artifact object (a null/absent `artifact` is a
    pre-M28a manifest -- UNBOUND, refused) AND that object_id must
    independently re-verify against the LIVE object store right now (a
    mutated or removed object since attach is ARTIFACT UNAVAILABLE/
    MISMATCH, refused) -- so a retroactively-corrupted object is caught even
    if the K-of-N attestation itself is still intact.
    """
    manifest_bytes, manifest_sha = _read_manifest_bytes(run_dir)
    if manifest_bytes is None:
        print(f"NOT FOUND ({os.path.join(run_dir, 'manifest.json')} does not exist)")
        return False

    try:
        manifest_obj = json.loads(manifest_bytes)
    except json.JSONDecodeError as e:
        print(f"INVALID (manifest.json is not valid JSON: {e})")
        return False
    artifact = manifest_obj.get("artifact")
    if not isinstance(artifact, dict) or not isinstance(artifact.get("object_id"), str):
        print("UNBOUND (manifest predates artifact binding — no manifest[\"artifact\"]; re-run "
              "under DF-01/M28a to bind an object before requesting custody)")
        return False
    object_id = artifact["object_id"]
    object_store = _object_store_root(control_root)
    if not df_seal.verify_object(object_store, object_id):
        print(f"ARTIFACT UNAVAILABLE (object {object_id} failed identity re-verification "
              "against the live object store)")
        return False

    try:
        cfg = _sup().load_config(control_root)
    except ConfigError as e:
        print(f"CONFIG ERROR ({e})")
        return False
    if cfg["_custody"] is None:
        print("NO CUSTODY CONFIGURED (control root has no `custody` block)")
        return False

    # DF-R9-07 (M79): AUTHENTICATE the sealed manifest (HMAC) BEFORE trusting ANY of
    # its fields — the config_sha256 binding below is only tamper-proof when the
    # manifest carrying it is HMAC-signed. Without this, a control-root writer (no
    # audit key, no approver key) rewrites config.json's custody block to their OWN
    # 1-of-1 key, rewrites the manifest's config_sha256 to match + recomputes the
    # PLAIN manifest.sha256, self-signs the manifest, and gets QUALIFIED — the exact
    # single-operator-proof bypass every sibling surface (ship/release/waiver) already
    # closes with _authenticate_manifest. A stale HMAC → TAMPERED → refuse. (The
    # config_sha256 check remains below as defense in depth against a signing-off /
    # legacy manifest and to surface an intended-config mismatch.)
    ok_m, why_m = _authenticate_manifest(cfg, control_root, run_dir)
    if not ok_m:
        print(f"INVALID (the sealed manifest failed authentication: {why_m})")
        return False

    # The custody policy is bound to the run's sealed config_sha256: a
    # config.json edited after the run (to lower the threshold or swap in a
    # rogue approver) fails closed here, even if an attestation exists.
    bound, sealed_sha, current_sha = _custody_config_bound(cfg, manifest_bytes)
    if not bound:
        print("INVALID (config.json changed since this run — custody policy is bound to the "
              f"sealed config_sha256 {sealed_sha} != current {current_sha}; re-run under the "
              "intended config)")
        return False

    att_path = os.path.join(run_dir, CUSTODY_ATTESTATION_FILE)
    if not os.path.exists(att_path):
        print(f"PENDING (no {CUSTODY_ATTESTATION_FILE}; run df-custody attach once "
              f">={cfg['_custody']['threshold']} approvers have signed)")
        return False
    try:
        with open(att_path, encoding="utf-8") as f:
            att_raw = f.read()
        attestation = json.loads(att_raw)
    except (OSError, json.JSONDecodeError) as e:
        print(f"INVALID (unreadable {CUSTODY_ATTESTATION_FILE}: {e})")
        return False

    if attestation.get("manifest_sha256") != manifest_sha:
        print("INVALID (attestation does not bind the current manifest bytes — "
              "manifest tampered or attestation stale)")
        return False

    sigs = attestation.get("signatures", [])
    if not isinstance(sigs, list):
        print(f"INVALID ({CUSTODY_ATTESTATION_FILE} signatures must be a list)")
        return False
    # Re-verify against the CONFIG's approvers + threshold (never the
    # attestation's own claimed values) so a forged attestation can neither
    # lower K nor introduce rogue approvers.
    satisfied, reason = df_custody.verify_custody(
        manifest_bytes, sigs, cfg["_custody"]["approvers"], cfg["_custody"]["threshold"])
    if not satisfied:
        print(f"INVALID (attestation signatures no longer satisfy K-of-N: {reason})")
        return False

    # M44 RA-03 (defense in depth): even a valid K-of-N attestation must bind an
    # ELIGIBLE manifest. attach refuses to write one over an ineligible run, but
    # a hand-planted attestation must not be honored either — recompute from the
    # sealed manifest fields.
    if manifest_obj.get("outcome") != "CUSTODY_PENDING" or \
            not _precustody_substates(manifest_obj)["qualified"] or \
            not _final_exam_ok(manifest_obj):
        print("INVALID (attestation binds an ineligible manifest — outcome is not "
              "CUSTODY_PENDING or its pre-custody evidence does not hold)")
        return False

    # M44 RA-02: at a run whose sealed config mandates a required off-box sink,
    # a QUALIFIED verdict REQUIRES the corresponding sink receipt (present, well-
    # formed, and bound to THESE attestation bytes). Its absence is a distinct
    # NOT-qualified status — enterprise qualification that never left the box
    # does not count — never a silent QUALIFIED.
    if _sink_required(cfg):
        ok_r, why_r = _sink_receipt_bound(run_dir, "custody_sink_receipt.json", att_raw)
        if not ok_r:
            print(f"SINK_RECEIPT_MISSING ({why_r}; a required off-box sink means qualification "
                  "must be recorded off-box — re-run df-custody attach against a reachable sink)")
            return False

    print(f"QUALIFIED ({reason}; attestation binds manifest {manifest_sha[:16]}…)")
    return True
    return False


# ---------------------------------------------------------------------------
# M33a (DF-06): the `df-waiver` operator CLI + attach + verify-time re-check.
#
# Structurally a mirror of split-custody (df-custody keygen/sign/attach +
# custody_attestation.json), but for security-gate findings: a
# SECURITY_GATE_FAILED run is re-qualified by a SEPARATE, signed
# `waiver_attestation.json` (never a manifest rewrite), and — crucially —
# every verify RE-CHECKS expiry against a LIVE clock, so an expired waiver
# flips the run back to not-qualified. All binding digests are recomputed
# FROM the sealed manifest; the signer allowlist + threshold are read from the
# manifest's SEALED waiver_policy (so no post-run config edit can widen who
# may waive).
# ---------------------------------------------------------------------------
WAIVER_SIGNATURES_FILE = "waiver-signatures.json"
WAIVER_ATTESTATION_FILE = "waiver_attestation.json"


def _now_utc():
    """The single live-clock source for waiver issue/expiry — an aware UTC
    datetime. Verify re-evaluates expiry against THIS every time (never a
    frozen boolean sealed at attach)."""
    return datetime.datetime.now(datetime.timezone.utc)


def _waiver_binding_from_manifest(manifest_obj):
    """Recompute a run's waiver binding tuple FROM its sealed manifest object.

    Returns `(binding, error)` where `binding` is a dict with `run_id`,
    `artifact_object_id`, `policy_digest`, `report_digest`, `security`,
    `signers`, `threshold` — every value derived from the (already
    byte-verified) manifest, NEVER from a mutable config — or `(None, reason)`
    fail-closed if the manifest lacks a usable, object-bound, gate-bearing
    security block. `report_digest` is recomputed via
    df_waiver.gate_report_digest over the sealed `security` object (excluding
    the policy/attestation keys), so it matches exactly what `sign`/`attach`/
    `verify` each compute.
    """
    if not isinstance(manifest_obj, dict):
        return None, "manifest is not a JSON object"
    run_id = manifest_obj.get("invocation")
    if not isinstance(run_id, str) or not run_id:
        return None, "manifest has no invocation (run_id)"
    artifact = manifest_obj.get("artifact")
    if not isinstance(artifact, dict) or not isinstance(artifact.get("object_id"), str):
        return None, "manifest predates artifact binding (no manifest['artifact'])"
    security = manifest_obj.get("security")
    if not isinstance(security, dict):
        return None, "manifest has no sealed security block"
    policy_digest = security.get("gate_policy_digest")
    if not isinstance(policy_digest, str) or not policy_digest:
        return None, "sealed security block has no gate_policy_digest (pre-M33a run)"
    waiver_policy = security.get("waiver_policy")
    if not isinstance(waiver_policy, dict):
        return None, "sealed security block has no waiver_policy"
    try:
        report_digest = df_waiver.gate_report_digest(security)
    except df_waiver.WaiverError as e:
        return None, f"cannot compute gate_report_digest: {e}"
    binding = {
        "run_id": run_id,
        "artifact_object_id": artifact["object_id"],
        "policy_digest": policy_digest,
        "report_digest": report_digest,
        "security": security,
        "signers": list(waiver_policy.get("signers", [])),
        "threshold": waiver_policy.get("threshold", 0),
    }
    return binding, None


def _load_waiver_signatures(control_root):
    """Load `<control_root>/waiver-signatures.json` — a JSON list of
    `{claim, signer, sig}` entries an operator collected. Returns
    `(list, None)` or `([], reason)` when absent/unreadable/wrong-shape.
    Never raises (mirrors _load_custody_signatures)."""
    sig_path = os.path.join(control_root, WAIVER_SIGNATURES_FILE)
    if not os.path.exists(sig_path):
        return [], f"{WAIVER_SIGNATURES_FILE} not found in the control root"
    try:
        with open(sig_path, encoding="utf-8") as f:
            loaded = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        return [], f"unreadable {WAIVER_SIGNATURES_FILE}: {e}"
    if not isinstance(loaded, list):
        return [], f"{WAIVER_SIGNATURES_FILE} must be a JSON list"
    return loaded, None


def _waiver_audit_key(cfg):
    """Load the run's audit key IF the control root configures audit signing —
    needed to byte-verify a SIGNED manifest (manifest.hmac) before trusting
    any binding read from it. Returns `(key_or_None, error_or_None)`. A
    control root with no audit signing returns (None, None) and its unsigned
    manifest is byte-verified by sha256 sidecar alone."""
    if not cfg.get("_audit", {}).get("signing"):
        return None, None
    try:
        return df_audit.load_key(cfg["_audit"]["key_path"]), None
    except df_audit.AuditKeyError as e:
        return None, str(e)


def _byte_verify_for_waiver(run_dir, cfg, control_root):
    """Byte-integrity + artifact-identity verify of the sealed manifest,
    reusing `_verify_manifest_status` (the same fail-closed path
    verify-manifest uses). Returns (ok, status). A signed manifest needs the
    audit key; we load it from config (the key PATH is config, but the
    allowlist that governs waivers is sealed in the manifest, not config)."""
    key, key_err = _waiver_audit_key(cfg)
    if key_err is not None:
        print(f"WAIVER_INVALID (audit key error: {key_err})")
        return False, "AUDIT_KEY_ERROR"
    status = _verify_manifest_status(
        run_dir, key=key, object_store=_object_store_root(control_root))
    return status == _ARTIFACT_OK, status


def attach_waiver(control_root: str, run_dir: str) -> int:
    """`df-waiver attach` — PHASE 2 of the two-phase waiver ship (mirrors
    attach_custody). Byte-verifies the sealed manifest, reads the collected
    `{claim,signer,sig}` entries from `<control_root>/waiver-signatures.json`,
    recomputes every binding digest FROM the manifest, and calls
    df_waiver.verify_waiver_set against the SEALED signer allowlist + threshold
    at `now = utcnow`.

    Satisfied → writes `<run_dir>/waiver_attestation.json` (never a manifest
    rewrite) and anchors it into the M13 hash chain, returns 0. Otherwise
    prints the fail-closed reason and returns 3. Precondition/usage errors
    (no manifest, unreadable config, run that didn't fail a gate) return 2.
    """
    manifest_bytes, manifest_sha = _read_manifest_bytes(run_dir)
    if manifest_bytes is None:
        sys.stderr.write(f"dark-factory: no manifest.json in {run_dir}\n")
        return 2
    try:
        manifest_obj = json.loads(manifest_bytes)
    except json.JSONDecodeError as e:
        sys.stderr.write(f"dark-factory: manifest.json is not valid JSON: {e}\n")
        return 2
    if manifest_obj.get("outcome") != "SECURITY_GATE_FAILED":
        sys.stderr.write(
            f"dark-factory: run outcome is {manifest_obj.get('outcome')!r}, not "
            "SECURITY_GATE_FAILED — waivers apply only to a run rejected by a "
            "security gate; nothing to attach.\n")
        return 2

    try:
        cfg = _sup().load_config(control_root)
    except ConfigError as e:
        sys.stderr.write(f"dark-factory: config error: {e}\n")
        return 2

    ok, status = _byte_verify_for_waiver(run_dir, cfg, control_root)
    if not ok:
        sys.stderr.write(
            f"dark-factory: sealed manifest failed verification ({status}) — refusing to "
            "attach a waiver over an unverifiable run.\n")
        return 3

    binding, berr = _waiver_binding_from_manifest(manifest_obj)
    if binding is None:
        sys.stderr.write(f"dark-factory: cannot bind waivers to this run: {berr}\n")
        return 2

    waivers, load_reason = _load_waiver_signatures(control_root)
    now = _sup()._now_utc()
    satisfied, reason, covered, _uncovered = df_waiver.verify_waiver_set(
        failing_findings=binding["security"].get("failed", []),
        gates=binding["security"].get("gates", {}),
        waivers=waivers,
        signers=binding["signers"],
        threshold=binding["threshold"],
        run_id=binding["run_id"],
        artifact_object_id=binding["artifact_object_id"],
        policy_digest=binding["policy_digest"],
        report_digest=binding["report_digest"],
        now=now,
    )
    if not satisfied:
        print(f"dark-factory: WAIVER NOT ATTACHED ({load_reason or reason}).")
        return 3

    # M44 RA-03: a waiver re-qualifies ONLY the app-security gate it covers; it
    # must NOT paper over a DIFFERENT per-run failure. The waiver machinery is
    # deliberately tier-INDEPENDENT (a cooperative run's security finding is
    # waivable), so tier posture (barrier / host_isolation) is NOT a waiver
    # eligibility condition — it is recorded honestly and consumed by the
    # qualification logic elsewhere. The one independent failure a security
    # waiver must never cover is a FAILED FINAL EXAM (a behaviorally-wrong
    # artifact). That is structurally excluded already (a failed final exam
    # seals FINAL_EXAM_FAILED, not SECURITY_GATE_FAILED, and is refused above),
    # but assert it explicitly so a hand-crafted manifest cannot slip through.
    if not _final_exam_ok(manifest_obj):
        print("dark-factory: WAIVER NOT ATTACHED — the sealed final exam did not pass; a "
              "security waiver cannot cover a behaviorally-rejected artifact.")
        return 3

    # Keep only the {claim,signer,sig} entries that actually contributed
    # (in-scope, valid, unexpired, allowlisted) — never echo unrelated
    # signature material into the attestation.
    kept = _kept_waiver_entries(waivers, binding, covered, now)
    attestation = {
        "attestation_version": "0.1",
        "manifest_sha256": manifest_sha,
        "run_id": binding["run_id"],
        "artifact_object_id": binding["artifact_object_id"],
        "gate_policy_digest": binding["policy_digest"],
        "gate_report_digest": binding["report_digest"],
        "threshold": binding["threshold"],
        "covered_fingerprints": covered,
        "waivers": kept,
        "satisfied": True,
        "attached_ts": _now(),
    }

    try:
        lock = acquire_lock(control_root)
    except LockError as e:
        sys.stderr.write(f"dark-factory: {e}\n")
        return 2
    try:
        att_text = canonical_json(attestation)
        att_path = os.path.join(run_dir, WAIVER_ATTESTATION_FILE)
        audit_key = None
        if cfg.get("_audit", {}).get("signing"):
            try:
                audit_key = df_audit.load_or_create_key(cfg["_audit"]["key_path"])
            except df_audit.AuditKeyError as e:
                sys.stderr.write(f"dark-factory: audit key error: {e}\n")
                return 2
        chain_path = os.path.join(control_root, "audit-chain.jsonl")
        waiver_chain_key = os.path.basename(run_dir) + ".waiver"

        # M44 RA-02: push the waiver off-box FIRST; a required-sink failure
        # leaves NO local attestation and NO chain link, so a waiver whose
        # off-box record never left the box is not locally waiver-qualifiable
        # (superset: a run without a required sink is unaffected).
        push_status, receipt, detail = _push_qualification_offbox(cfg, waiver_chain_key, att_text)
        if push_status == "required_fail":
            sys.stderr.write(
                f"dark-factory: WAIVER NOT ATTACHED — the REQUIRED audit sink push FAILED "
                f"({detail}); no local attestation was written. Fix the sink and re-run "
                f"df-waiver attach.\n")
            return 3
        if push_status == "optional_fail":
            sys.stderr.write(f"dark-factory: audit sink push warning (not required): {detail}\n")

        atomic_write(att_path, att_text)
        entry = df_audit_chain.append_entry(
            chain_path, waiver_chain_key, sha256_str(att_text), _now(), audit_key)
        # DF-R9-04: keep the off-box committed lengths DENSE (the required-sink record
        # push above already fails closed when down) — else this waiver anchor's length
        # is a HOLE (opus review F1). DF-R12-01: a required-sink checkpoint that does not
        # land leaves this run not off-box-complete (the production predicate requires the
        # dense-baseline marker) — surfaced, not silent.
        if (not _sup()._checkpoint_chain_to_sink(cfg, control_root)
                and cfg.get("_audit", {}).get("sink", {}).get("required")):
            sys.stderr.write(
                "dark-factory: WARNING — the waiver chain-length checkpoint did not land on "
                "the REQUIRED off-box sink; this run is NOT off-box-complete until the next "
                "checkpoint backfills the length.\n")
        if receipt is not None:
            atomic_write(os.path.join(run_dir, "waiver_sink_receipt.json"),
                         canonical_json(receipt))

        print(f"dark-factory: WAIVER ATTACHED — {reason}. "
              f"Attestation: {att_path}  Chain: {entry['chain_hash'][:16]}…  "
              f"NOTE: expiry is re-checked at every verify.")
        return 0
    finally:
        release_lock(lock)


def _kept_waiver_entries(waivers, binding, covered, now):
    """The subset of collected `{claim,signer,sig}` entries that are valid,
    in-scope, unexpired, allowlisted-signer, and cover one of the `covered`
    fingerprints — the exact entries that justified the attestation. Recorded
    so a later verify re-checks THESE (and their expiry) rather than trusting
    a bare boolean."""
    signer_set = {s.lower() for s in binding["signers"] if isinstance(s, str)}
    covered_set = set(covered)
    kept = []
    for w in waivers:
        if not isinstance(w, dict):
            continue
        claim = w.get("claim")
        signer = w.get("signer")
        sig = w.get("sig")
        if not (isinstance(claim, dict) and isinstance(signer, str) and isinstance(sig, str)):
            continue
        s = signer.lower()
        if s not in signer_set:
            continue
        if claim.get("run_id") != binding["run_id"]:
            continue
        if claim.get("artifact_object_id") != binding["artifact_object_id"]:
            continue
        if claim.get("gate_policy_digest") != binding["policy_digest"]:
            continue
        if claim.get("gate_report_digest") != binding["report_digest"]:
            continue
        if claim.get("finding_fingerprint") not in covered_set:
            continue
        if not df_waiver._claim_within_validity(claim, now):
            continue
        try:
            signed = df_waiver.waiver_signing_bytes(claim)
        except df_waiver.WaiverError:
            continue
        if not df_custody.verify_one(s, signed, sig):
            continue
        kept.append({"claim": claim, "signer": s, "sig": sig})
    return kept


# Distinct df-waiver verify statuses -> distinct exit codes.
_WAIVER_VERIFY_EXIT = {
    "WAIVED_QUALIFIED": 0,
    "NOT_WAIVED": 1,
    "WAIVER_EXPIRED": 7,
    "WAIVER_INVALID": 8,
    # M44 RA-02: a required off-box sink whose receipt is absent/unbound is a
    # DISTINCT not-qualified status (qualification never left the box), never a
    # silent WAIVED_QUALIFIED.
    "SINK_RECEIPT_MISSING": 9,
}


def verify_waiver_cmd(control_root: str, run_dir: str) -> int:
    """`df-waiver verify` — read-only re-evaluation of whether a
    SECURITY_GATE_FAILED run is CURRENTLY waiver-qualified.

    Byte-verifies the manifest, then (if a waiver_attestation.json exists)
    re-runs df_waiver.verify_waiver_set at `now = utcnow`. Expiry is therefore
    checked AT VERIFY TIME, never a frozen attach-time boolean: a waiver that
    was valid at attach but has since expired flips the verdict to
    WAIVER_EXPIRED. Prints a distinct status and returns its distinct exit
    code (see _WAIVER_VERIFY_EXIT).

    Expiry vs other invalidity is disambiguated by re-verifying the SAME
    recomputed-from-manifest binding at the attestation's `attached_ts` (a
    time it was, by construction, satisfied): satisfied-then-but-not-now ==
    the clock is the only thing that changed == EXPIRED; not-satisfied-even-
    then == tamper / drift / short count == INVALID.
    """
    manifest_bytes, manifest_sha = _read_manifest_bytes(run_dir)
    if manifest_bytes is None:
        print(f"WAIVER_INVALID (no manifest.json in {run_dir})")
        return _WAIVER_VERIFY_EXIT["WAIVER_INVALID"]
    try:
        manifest_obj = json.loads(manifest_bytes)
    except json.JSONDecodeError as e:
        print(f"WAIVER_INVALID (manifest.json is not valid JSON: {e})")
        return _WAIVER_VERIFY_EXIT["WAIVER_INVALID"]

    if manifest_obj.get("outcome") != "SECURITY_GATE_FAILED":
        # A run that never failed a gate isn't waiver-governed; report clearly
        # and don't pretend a waiver verdict applies.
        print(f"NOT_WAIVED (outcome {manifest_obj.get('outcome')!r}; waivers apply only to "
              "SECURITY_GATE_FAILED runs)")
        return _WAIVER_VERIFY_EXIT["NOT_WAIVED"]

    try:
        cfg = _sup().load_config(control_root)
    except ConfigError as e:
        print(f"WAIVER_INVALID (config error: {e})")
        return _WAIVER_VERIFY_EXIT["WAIVER_INVALID"]

    ok, status = _byte_verify_for_waiver(run_dir, cfg, control_root)
    if not ok:
        # _byte_verify_for_waiver / _verify_manifest_status already printed a
        # line; surface as INVALID (integrity is a precondition for any
        # waiver verdict).
        print(f"WAIVER_INVALID (sealed manifest failed verification: {status})")
        return _WAIVER_VERIFY_EXIT["WAIVER_INVALID"]

    binding, berr = _waiver_binding_from_manifest(manifest_obj)
    if binding is None:
        print(f"WAIVER_INVALID (cannot bind waivers to this run: {berr})")
        return _WAIVER_VERIFY_EXIT["WAIVER_INVALID"]

    att_path = os.path.join(run_dir, WAIVER_ATTESTATION_FILE)
    if not os.path.exists(att_path):
        print(f"NOT_WAIVED (no {WAIVER_ATTESTATION_FILE}; SECURITY_GATE_FAILED run stays "
              "not-qualified until waivers are attached)")
        return _WAIVER_VERIFY_EXIT["NOT_WAIVED"]
    try:
        with open(att_path, encoding="utf-8") as f:
            att_raw = f.read()
        attestation = json.loads(att_raw)
    except (OSError, json.JSONDecodeError) as e:
        print(f"WAIVER_INVALID (unreadable {WAIVER_ATTESTATION_FILE}: {e})")
        return _WAIVER_VERIFY_EXIT["WAIVER_INVALID"]

    # M44 RA-03 (defense in depth): a security waiver must not stand on a
    # behaviorally-rejected artifact (a failed final exam). Tier posture is NOT
    # a waiver condition (the waiver is tier-independent by design).
    if not _final_exam_ok(manifest_obj):
        print("WAIVER_INVALID (the sealed final exam did not pass — a security waiver cannot "
              "cover a behaviorally-rejected artifact)")
        return _WAIVER_VERIFY_EXIT["WAIVER_INVALID"]

    # The attestation must bind THESE manifest bytes (a single-byte manifest
    # edit that still passed byte-verify cannot happen — the sidecar/HMAC
    # guard it — but a STALE attestation from a different sealing must not be
    # honored).
    if attestation.get("manifest_sha256") != manifest_sha:
        print("WAIVER_INVALID (attestation does not bind the current manifest bytes)")
        return _WAIVER_VERIFY_EXIT["WAIVER_INVALID"]

    waivers = attestation.get("waivers", [])
    if not isinstance(waivers, list):
        print(f"WAIVER_INVALID ({WAIVER_ATTESTATION_FILE} waivers must be a list)")
        return _WAIVER_VERIFY_EXIT["WAIVER_INVALID"]

    def _eval(now):
        return df_waiver.verify_waiver_set(
            failing_findings=binding["security"].get("failed", []),
            gates=binding["security"].get("gates", {}),
            waivers=waivers,
            signers=binding["signers"],
            threshold=binding["threshold"],
            run_id=binding["run_id"],
            artifact_object_id=binding["artifact_object_id"],
            policy_digest=binding["policy_digest"],
            report_digest=binding["report_digest"],
            now=now,
        )

    now = _sup()._now_utc()
    satisfied_now, reason_now, _covered, _unc = _eval(now)
    if satisfied_now:
        # M44 RA-02: when the sealed config mandates a required off-box sink, a
        # WAIVED_QUALIFIED verdict REQUIRES the bound waiver sink receipt.
        if _sink_required(cfg):
            ok_r, why_r = _sink_receipt_bound(run_dir, "waiver_sink_receipt.json", att_raw)
            if not ok_r:
                print(f"SINK_RECEIPT_MISSING ({why_r}; a required off-box sink means the "
                      "waiver must be recorded off-box — re-attach against a reachable sink)")
                return _WAIVER_VERIFY_EXIT["SINK_RECEIPT_MISSING"]
        print(f"WAIVED_QUALIFIED ({reason_now}; expiry re-checked at {_now()})")
        return _WAIVER_VERIFY_EXIT["WAIVED_QUALIFIED"]

    # Not satisfied now. Was it satisfiable at attach time (with the SAME
    # manifest-derived binding)? If so, only the clock changed -> EXPIRED.
    attached_dt = df_waiver._parse_ts(attestation.get("attached_ts"))
    satisfied_at_attach = False
    if attached_dt is not None:
        satisfied_at_attach = _eval(attached_dt)[0]
    if satisfied_at_attach:
        print(f"WAIVER_EXPIRED (satisfied when attached, expired by {_now()}; "
              "re-issue with a later expiry and re-attach)")
        return _WAIVER_VERIFY_EXIT["WAIVER_EXPIRED"]
    print(f"WAIVER_INVALID ({reason_now})")
    return _WAIVER_VERIFY_EXIT["WAIVER_INVALID"]
