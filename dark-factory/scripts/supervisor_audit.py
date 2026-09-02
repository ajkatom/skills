"""Audit anchoring: security-gate dispatch, audit key loading, manifest finalization, the local hash chain, off-box chain checkpoints + completeness, verify-chain, manifest authentication.

Extracted verbatim from supervisor.py (see supervisor.py for the CLI entry point and
the run/resume core). Every top-level name here is re-exported by supervisor.py, so
`supervisor.<name>` keeps working for tests and df_evidence_bundle.
"""
import hashlib
import json
import os
import sys
import uuid

import df_audit
import df_audit_chain
import df_audit_sink
import df_custody
import df_qualify
import df_security
import df_waiver
from df_common import atomic_write, canonical_json, sha256_file, sha256_str
from supervisor_core import (
    _ARTIFACT_OK,
    _candidate_egress_qualified,
    _now,
    _object_store_root,
    _redacted_write,
    _sup,
    _verify_manifest_status,
)


def _run_security_gates(cfg, journal, run_dir, workspace, redactor=None):
    """Run mandatory security gates (M9) on the converged artifact, if enabled.

    Shared by BOTH the primary run() path and resume()'s continue path,
    since both funnel through _run_loop's CONVERGED branch — there is only
    one call site, so "gates run on resume exactly like the primary path"
    falls out for free rather than needing a second wiring.

    Disabled (default, back-compatible): returns {"checked": False} with no
    journal entry and no security_report.json written. Enabled: runs
    df_security.run_gates over the workspace, writes security_report.json
    into run_dir (control plane — the report is about the artifact, not
    holdout content), and journals SECURITY_GATES(checked=True, failed=...).
    """
    sec_cfg = cfg["_security"]
    if not sec_cfg.get("enabled"):
        return {"checked": False}
    sec_report = df_security.run_gates(workspace, sec_cfg)
    # M33a (DF-06): SEAL the waiver-binding metadata INTO the security report
    # so both the SECURITY_GATE_FAILED terminal and the CONVERGED terminal
    # carry it, and `df-waiver attach`/`verify` can recompute every binding
    # digest from the sealed manifest ALONE (never re-loading a mutable
    # config). `gate_policy_digest` fingerprints the effective gate policy;
    # `waiver_policy` is the SEALED signer allowlist + threshold — the
    # allowlist that governs a sealed run must itself be sealed, so it can't
    # be widened by editing config.json after the fact. `gate_report_digest`
    # is deliberately NOT stored here (it is always recomputed over this block
    # minus the excluded keys — see df_waiver._REPORT_DIGEST_EXCLUDE — which
    # avoids a digest-over-a-field-that-contains-itself recursion).
    sec_report["gate_policy_digest"] = df_waiver.gate_policy_digest(sec_cfg)
    waivers_cfg = sec_cfg.get("waivers", {"signers": [], "threshold": 0})
    sec_report["waiver_policy"] = {
        "signers": list(waivers_cfg.get("signers", [])),
        "threshold": waivers_cfg.get("threshold", 0),
    }
    _redacted_write(os.path.join(run_dir, "security_report.json"), sec_report, redactor)
    journal.write("SECURITY_GATES", checked=True, failed=sec_report["failed"])
    return sec_report


def _load_audit_key(cfg, journal):
    """Load the run's audit signing key once, if cfg["_audit"]["signing"].

    Returns (key_or_None, error_exit_code_or_None). On AuditKeyError this is a
    precondition failure — journal AUDIT_KEY_ERROR and return an exit code
    instead of silently proceeding unsigned.
    """
    audit_cfg = cfg.get("_audit", {"signing": False, "key_path": ""})
    if not audit_cfg.get("signing"):
        return None, None
    try:
        return df_audit.load_or_create_key(audit_cfg["key_path"]), None
    except df_audit.AuditKeyError as e:
        journal.write("AUDIT_KEY_ERROR", detail=str(e))
        sys.stderr.write(f"dark-factory: audit key error: {e}\n")
        return None, 2


def finalize_manifest(run_dir: str, extra: dict, audit_key: bytes = None, redactor=None) -> str:
    """Write manifest.json + manifest.sha256 sidecar.

    HONESTY (spec 7.5, cooperative/standard tier): a local process that can
    rewrite both files can defeat this. It detects accidental edits and
    casual tampering only; a signed chain / off-box anchor is hardened+.

    If `audit_key` is given, also write manifest.hmac (HMAC-SHA256 over the
    exact canonical manifest text, spec 7.5). The key itself is NEVER
    written to any run artifact.

    `redactor` (M11), if given, redacts credential VALUES out of the manifest
    before it is ever serialized — the digest and (if signed) the HMAC are
    computed over the redacted text, so verify-manifest's integrity checks
    stay consistent with the bytes actually on disk. `credentials` fields on
    the manifest are names/allowlist only and are never themselves subject to
    redaction (they contain no values).

    M17 note: the manifest this writes is the IMMUTABLE, signable artifact of
    an enterprise run — split-custody qualification is a SEPARATE attestation
    (custody_attestation.json, written later by `attach_custody` over these
    exact bytes), never a rewrite of this file. See references/enterprise.md.

    M13 note: finalize_manifest SEALS journal.jsonl — its whole-file hash goes
    into `journal_sha256` and NOTHING may append to journal.jsonl afterward.
    The audit-chain anchoring that runs right after this (`_anchor_audit`)
    happens AFTER the seal, so its events go to a SEPARATE, unhashed
    `audit_events.jsonl`, never back into journal.jsonl — keeping this
    whole-file seal (M5a) unweakened.
    """
    journal_path = os.path.join(run_dir, "journal.jsonl")
    manifest = dict(extra)
    manifest["manifest_version"] = "0.1"
    # M36a Task 2: EVERY terminal manifest carries the single qualification SM's
    # verdict. The three terminals that make a real ship decision (CONVERGED,
    # enterprise CUSTODY_PENDING, and H4 BUDGET_HALTED) set `qualification`
    # explicitly with their known effective tier; for every OTHER terminal we
    # derive an auditability record HERE from manifest fields alone. Barrier is
    # keyed off `denial_probe_passed` (probe-proven isolation THIS run) and
    # app_security defaults False when unknown, so this can never OVER-claim:
    # a non-converged terminal (which never set app_security_qualified=True)
    # always reads qualified=False, consistent with its top-level `qualified`.
    if "qualification" not in manifest:
        _art = manifest.get("artifact")
        manifest["qualification"] = df_qualify.derive(
            barrier=bool(manifest.get("denial_probe_passed")),
            host_isolation=bool((manifest.get("host_isolation") or {}).get("qualified")),
            candidate_egress=_candidate_egress_qualified(manifest.get("candidate_network")),
            control_plane=bool(isinstance(_art, dict) and _art.get("object_id")),
            app_security=bool(manifest.get("app_security_qualified", False)),
            waiver_validity=True)
    manifest["journal_sha256"] = sha256_file(journal_path)
    manifest["finished_ts"] = _now()
    if audit_key is not None:
        manifest["audit_signing"] = True
    text = _redacted_write(os.path.join(run_dir, "manifest.json"), manifest, redactor)
    digest = sha256_str(text)
    atomic_write(os.path.join(run_dir, "manifest.sha256"), digest + "\n")
    if audit_key is not None:
        sig = df_audit.sign(audit_key, text.encode("utf-8"))
        atomic_write(os.path.join(run_dir, "manifest.hmac"), sig + "\n")
    return digest


def _anchor_audit(cfg, control_root, run_dir, invocation, digest, audit_key, journal) -> int:
    """Anchor one finalized manifest into the per-control-root hash chain
    (M13), and — if a sink is configured — push the chain entry off-box.
    Called exactly once per terminal, immediately after `finalize_manifest`
    returns the manifest's digest.

    DESIGN (avoids binding-circularity): the chain entry binds `digest` —
    the manifest's ALREADY-finalized digest — so the chain/sink results
    cannot live inside that same manifest (embedding them would change the
    very digest the chain anchors). They are recorded as run_dir SIDECARS
    (`audit_chain.json`, and — only when a sink is configured —
    `audit_sink_receipt.json`). `finalize_manifest` is never called a
    second time.

    WHY A SEPARATE EVENT LOG: this runs AFTER `finalize_manifest` has already
    SEALED `journal.jsonl` (its whole-file hash is in the manifest, which the
    chain entry then binds). Writing these events back into `journal.jsonl`
    would either break that seal or force verify-manifest to hash less than
    the whole file — weakening a security primitive to fit a feature. So the
    audit-anchor events go to their OWN append log, `audit_events.jsonl`,
    which is NOT hashed into the manifest. It is a convenience/debugging
    trail; the AUTHORITATIVE, verifiable records are the chain file
    (`<control_root>/audit-chain.jsonl`, with signed links, checked by
    verify-chain) and the run_dir sidecars — NOT this event log.

    Returns 0 on the normal path: chain is always written (append-only,
    additive, cheap — unconditional even with no sink configured); a sink
    push that succeeds, or fails but isn't `required`, is still 0. Returns
    3 ONLY when `audit.sink.required` is true and the push failed — the
    manifest already on disk is untouched and correctly describes the run
    outcome; the caller folds this 3 into ITS OWN exit code (fail-closed)
    instead of the outcome's normal exit.
    """
    redactor = getattr(journal, "redactor", None)
    events_path = os.path.join(run_dir, "audit_events.jsonl")

    def _event(state, **data):
        # Same shape as a journal line, but to the UNHASHED audit_events log
        # (see docstring) -- never journal.jsonl, which is sealed by now.
        if redactor is not None:
            data = redactor.redact_obj(data)
        line = canonical_json({"ts": _now(), "state": state, "data": data})
        with open(events_path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
            f.flush()
            os.fsync(f.fileno())

    chain_path = os.path.join(control_root, "audit-chain.jsonl")
    entry = df_audit_chain.append_entry(chain_path, invocation, digest, _now(), audit_key)
    atomic_write(os.path.join(run_dir, "audit_chain.json"), canonical_json(entry))
    _event("AUDIT_CHAINED", chain_hash=entry["chain_hash"], prev=entry["prev_chain_hash"])

    sink = cfg.get("_audit", {}).get("sink", {"kind": "none", "required": False})
    if sink.get("kind", "none") == "none":
        return 0

    # DF-R9-04: commit THIS new chain length off-box BEFORE the (larger) audit-record
    # push, so the committed lengths stay DENSE (no HOLE the truncation probe could fall
    # into). DF-R12-01 fix #1: a REQUIRED sink that cannot confirm this checkpoint (and
    # its dense-baseline marker) is FAIL-CLOSED — returning 0 here would leave a run whose
    # tip length is uncheckpointed reading as a clean terminal, and a later same-user
    # truncation to the hole would pass the completeness probe. Fold it into the same
    # fatal exit (3) the required-record-push failure below uses; the next run's checkpoint
    # backfills the length once the sink recovers, and completeness stays not-confirmed
    # until then. (An OPTIONAL sink stays best-effort.)
    _checkpoint_ok = _sup()._checkpoint_chain_to_sink(cfg, control_root)
    if not _checkpoint_ok and sink.get("required"):
        _event("AUDIT_CHECKPOINT_FAILED", kind=sink["kind"], length=_chain_length(control_root))
        return 3

    try:
        receipt = df_audit_sink.push(sink, invocation, json.dumps(entry).encode("utf-8"))
    except df_audit_sink.SinkError as e:
        if sink.get("required"):
            _event("AUDIT_SINK_FAILED", kind=sink["kind"], error=str(e))
            return 3
        _event("AUDIT_SINK_WARN", kind=sink["kind"], error=str(e))
        return 0

    atomic_write(os.path.join(run_dir, "audit_sink_receipt.json"), canonical_json(receipt))
    _event("AUDIT_SINK_OK", kind=sink["kind"], receipt=receipt)
    return 0


CONTROL_ROOT_ID_FILE = ".dfchain_root_id"


def _key_fingerprint(key):
    kb = key if isinstance(key, (bytes, bytearray)) else str(key).encode("utf-8")
    return hashlib.sha256(b"dfroot-fp:" + bytes(kb)).hexdigest()[:24]


def _control_root_identity(cfg, control_root, allow_bootstrap=False):
    """DF-R10-01: a STABLE control-root identity for the off-box checkpoint namespace
    — relocation-invariant, truncation-surviving, per-root-unique, and (with a
    reachable sink) tamper-proof. Returns a hex id, or None (unsigned / no key).

    Pre-M83 the namespace bound `realpath(control_root)`, a MUTABLE deployment
    attribute: moving/copying a signed control root minted a NEW namespace, so the
    one-past probe queried an empty namespace, got 404, and read a tail-TRUNCATED
    local chain as complete (DF-R10-01) even with a required sink.

    The identity now lives in a local cache file (`.dfchain_root_id`, created once —
    it travels inside the control root, so it is relocation-invariant and survives
    truncation of the chain to empty), AUTHORITATIVELY confirmed off-box when a sink
    is reachable: `dfroot.<fp(key)>` is a WRITE-ONCE slot keyed by the audit-key
    FINGERPRINT — a same-user attacker who does NOT hold the key cannot compute that
    slot, so cannot read, forge, or overwrite it. Bootstrap registers the local id
    there once; later calls read the OFF-BOX id back as authoritative, so a control-
    root writer who edits the local `.dfchain_root_id` to mint a fresh (checkpoint-
    free) namespace is OVERRIDDEN when the sink is reachable. Sink unreachable →
    fall back to the local id (best-effort; detection-grade only anyway).

    Returns (identity, state) where state is one of:
      'confirmed'    — AUTHORITATIVE: the off-box `dfroot.<fp(key)>` slot returned the
                       id (200); or — ONLY on a WRITE path (allow_bootstrap) — we just
                       registered it write-once; or there is no off-box sink domain.
      'unregistered' — a REACHABLE sink returned 404 for `dfroot` on a VERIFY path: this
                       control root has committed NO authoritative off-box identity yet
                       (first run, or a required write that fails closed at write time),
                       so completeness is best-effort but there is nothing off-box to
                       miss — recovery proceeds; a production verdict is withheld.
      'unreachable'  — the sink could not be reached (status 0): a required sink fails
                       closed; an optional sink proceeds best-effort.

    Bootstrap (registering `dfroot` from the writable local file) happens ONLY on a
    write/append path (allow_bootstrap=True) — NEVER on a verify path. The M83 opus
    regression: with an ORPHANED `dfroot` (registration dropped), a verify-time
    bootstrap re-registered the ATTACKER's edited `.dfchain_root_id` as authoritative
    and re-namespaced the whole chain → a truncated chain read `confirmed_offbox`.
    Verify now treats an unconfirmed identity as fail-closed instead.

    Residual (documented, fail-SAFE): sharing ONE audit key across MANY control roots
    aliases the `dfroot.<fp(key)>` slot → the first root's id becomes authoritative
    for all → conservative FALSE-POSITIVE truncation refusals (never a bypass). Give
    each control root its own key. Cached (identity, confirmed) on cfg per invocation."""
    cached = cfg.get("_control_root_id")
    if cached is not None and cached[0] == control_root:  # bound to THIS control root
        return cached[1]
    audit = cfg.get("_audit", {})
    if not audit.get("signing"):
        return (None, "unreachable")
    try:
        key = df_audit.load_key(audit["key_path"])
    except (df_audit.AuditKeyError, KeyError, TypeError, OSError):
        return (None, "unreachable")

    def _decode(b, fallback):
        s = (b.decode("utf-8") if isinstance(b, (bytes, bytearray)) else str(b)).strip()
        return s or fallback

    id_path = os.path.join(control_root, CONTROL_ROOT_ID_FILE)
    local_id = None
    try:
        with open(id_path, encoding="utf-8") as f:
            local_id = f.read().strip() or None
    except OSError:
        local_id = None
    if local_id is None:
        local_id = uuid.uuid4().hex
        try:
            atomic_write(id_path, local_id)
        except OSError:
            pass
    sink = audit.get("sink", {"kind": "none"})
    if sink.get("kind", "none") == "none":
        result = (local_id, "confirmed")  # no off-box domain — local id IS the identity
    else:
        root_key = f"dfroot.{_key_fingerprint(key)}"
        try:
            status, body = df_audit_sink.probe(sink, root_key)
        except Exception:
            status, body = 0, None
        if status == 200 and body:
            ident = _decode(body, local_id)
            if ident != local_id:
                try:
                    atomic_write(id_path, ident)  # off-box id is authoritative
                except OSError:
                    pass
            result = (ident, "confirmed")
        elif status == 404 and allow_bootstrap:
            try:
                df_audit_sink.push(sink, root_key, local_id.encode("utf-8"))
                result = (local_id, "confirmed")
            except Exception:
                # concurrent bootstrap may have won the write-once race — re-read
                try:
                    st2, body2 = df_audit_sink.probe(sink, root_key)
                except Exception:
                    st2, body2 = 0, None
                result = ((_decode(body2, local_id), "confirmed") if st2 == 200 and body2
                          else (local_id, "unreachable"))
        elif status == 404:
            # VERIFY path, reachable sink, no dfroot yet: this control root has
            # registered NO off-box identity — nothing has been committed off-box
            # under an authoritative namespace (a required-sink write that could NOT
            # register dfroot fails closed at WRITE time — see _checkpoint_chain_to_sink
            # / R10-04 — so no orphaned checkpoints exist to miss). Proceed best-effort.
            result = (local_id, "unregistered")
        else:
            result = (local_id, "unreachable")  # sink unreachable (status 0)
    # Cache ONLY a CONFIRMED identity: an unconfirmed (unregistered / unreachable)
    # result must NOT be cached, or an early verify call would poison a later WRITE
    # path's bootstrap (which registers dfroot) in the same invocation.
    if result[1] == "confirmed":
        cfg["_control_root_id"] = (control_root, result)
    return result


def _chain_sink_namespace(cfg, control_root, allow_bootstrap=False):
    """DF-R9-04 + DF-R10-01: a STABLE, RELOCATION-INVARIANT namespace for the off-box
    chain-length checkpoints — sha256 of the audit key fingerprint (never the key)
    bound to the stable control-root IDENTITY (`_control_root_identity`), not the
    mutable `realpath(control_root)` M73 used. None when unsigned or no identity. Note
    the namespace is derived from the identity regardless of off-box confirmation; the
    CALLERS gate on the `confirmed` flag (verify fails closed when unconfirmed)."""
    audit = cfg.get("_audit", {})
    if not audit.get("signing"):
        return None
    try:
        key = df_audit.load_key(audit["key_path"])
    except (df_audit.AuditKeyError, KeyError, TypeError, OSError):
        return None
    ident, _confirmed = _control_root_identity(cfg, control_root, allow_bootstrap)
    if not ident:
        return None
    kb = key if isinstance(key, (bytes, bytearray)) else str(key).encode("utf-8")
    return hashlib.sha256(
        b"dfchain-ns:" + bytes(kb) + b"|" + ident.encode("utf-8")).hexdigest()[:24]


def _chain_length(control_root):
    """DF-R9-04: the number of entries in the local signed chain (0 if empty/
    unreadable — a truncation-to-empty reads as 0, which the checkpoint probe then
    catches against the off-box committed length)."""
    try:
        return len(df_audit_chain.read_chain(os.path.join(control_root, "audit-chain.jsonl")))
    except df_audit_chain.ChainError:
        return 0


def _chain_checkpoint_key(ns, length):
    return f"dfchain.{ns}.{length:08d}"


def _chain_dense_marker_key(ns, length):
    # DF-R12-01: a WRITE-ONCE off-box marker asserting "checkpoints 1..length are ALL
    # committed" (a versioned dense baseline). Written only after density through
    # `length` has actually been established (contiguous from a prior dense baseline,
    # or by a full verify+backfill on a legacy store). Same unforgeable namespace as
    # the checkpoints (sha256(key-fp+identity)), so a keyless attacker cannot mint one.
    return f"dfchain.{ns}.dense.{length:08d}"


def _checkpoint_chain_to_sink(cfg, control_root):
    """DF-R9-04: commit the current chain length to the off-box sink under a
    MONOTONIC WRITE-ONCE key (`dfchain.<ns>.<len>`), so a later tail-truncation of
    the local chain is detectable — the sink still holds a checkpoint for the longer
    length the local file no longer reaches. Returns True iff the current length is
    CONFIRMED committed off-box (freshly pushed OR already present — write-once).
    Returns False iff a sink is configured but the length could NOT be confirmed
    committed. Callers checkpoint at EVERY chain-append site so committed lengths
    stay DENSE (a missing checkpoint — a HOLE — at length h would let an attacker
    truncate to h-1 and pass the `local+1` probe; opus review F1). True when no
    sink / unsigned (nothing to commit).

    RESIDUAL (opus review, documented LOW): the push is best-effort here, so a
    TRANSIENT single-checkpoint drop — the sink up for the required record push but
    failing for exactly this one checkpoint PUT — leaves a hole a later truncation
    to length h-1 would pass. Under the stated threat model (control-root read/write
    only; every op holds acquire_lock) a pure control-root attacker CANNOT
    selectively fail one egress request, so this arises only from genuine sink
    flakiness; it escalates only if same-user network/egress interference is in
    scope. The committed-bool this returns lets a specific site (e.g. the ship
    completion anchor) be made fatal if that broader model must be covered — kept
    best-effort here to preserve the SHIPPED_AUDIT_PENDING crash-window recovery."""
    sink = cfg.get("_audit", {}).get("sink", {"kind": "none"})
    if sink.get("kind", "none") == "none":
        return True
    # DF-R10-01: establish the off-box control-root IDENTITY on this WRITE path
    # (allow_bootstrap) — registering `dfroot.<fp(key)>` write-once if absent. A
    # REQUIRED sink whose identity anchor could not be confirmed is a fail-closed
    # checkpoint (return False): checkpoints must never be committed under an
    # unanchored namespace a verify path would then be unable to trust.
    ident, state = _control_root_identity(cfg, control_root, allow_bootstrap=True)
    if ident is None:
        return True
    if state != "confirmed":
        # DF-R10-01 (2nd-round audit): NEVER commit a checkpoint under an UNANCHORED
        # namespace (dfroot unregistered/unreachable). A landed `dfchain.*` under an
        # unconfirmed identity is an orphan a same-user writer could re-namespace by
        # forging `dfroot` (under genuine sink flakiness) → a truncated chain reading
        # confirmed_offbox. So the checkpoint is NOT committed, and the committed-bool
        # is honestly False (nothing landed off-box). The caller decides severity — a
        # REQUIRED sink treats False as fail-closed; an OPTIONAL sink is best-effort.
        return False
    ns = _chain_sink_namespace(cfg, control_root)
    length = _chain_length(control_root)
    if ns is None or length == 0:
        return True

    def _probe_key(key):
        try:
            return df_audit_sink.probe(sink, key)[0]
        except Exception:
            return 0

    def _probe(n):
        return _probe_key(_chain_checkpoint_key(ns, n))

    def _commit_key(key, body):
        try:
            df_audit_sink.push(sink, key, body)
            return True
        except df_audit_sink.SinkError:
            return _probe_key(key) == 200  # write-once duplicate (already committed) = SUCCESS
        except Exception:
            return False

    def _commit(n):
        return _commit_key(_chain_checkpoint_key(ns, n),
                           canonical_json({"length": n}).encode("utf-8"))

    def _mark_dense(n):
        return _commit_key(_chain_dense_marker_key(ns, n),
                           canonical_json({"dense_through": n}).encode("utf-8"))

    # DF-R10-04 + DF-R12-01: keep the off-box checkpoints DENSE. A HOLE at length h (a
    # checkpoint that transiently failed, or a pre-sink/pre-M73 chain adopting a sink)
    # would let a same-user writer truncate to h-1 and pass the one-past `local+1`
    # probe. Maintain the invariant "1..L ALL committed" and record it with a WRITE-ONCE
    # DENSE-BASELINE marker `dfchain.<ns>.dense.<L>` — the completeness verifier requires
    # this marker (not the mere existence of the length-L checkpoint) as proof of
    # density. DF-R12-01: the pre-M89 shortcut "checkpoint L exists ⇒ 1..L dense" was
    # UNSOUND for a legacy/pre-M84 store that had L while an earlier checkpoint was
    # missing; the marker is written ONLY after density is actually established.
    if _probe_key(_chain_dense_marker_key(ns, length)) == 200:
        return True  # density through L already proven off-box (steady state: 1 probe)
    # Ensure the current tip checkpoint itself is committed (fail closed if it cannot be —
    # a required caller must treat this as a durable pending outcome; DF-R12-01 fix #1).
    if not _commit(length):
        return False
    # Contiguous case: density through L-1 already proven ⇒ committing L extends it.
    if length == 1 or _probe_key(_chain_dense_marker_key(ns, length - 1)) == 200:
        return _mark_dense(length)
    # Legacy/holey store (no dense baseline): the length-L checkpoint may sit ABOVE a
    # missing earlier checkpoint. VERIFY+BACKFILL every 1..L before marking dense — never
    # infer density from the tip alone. Bounded: reachable sink only (a down sink makes
    # _commit fail fast — no O(L)×timeout walk), and this full pass runs once per store
    # (subsequent runs hit the contiguous fast path above).
    for n in range(1, length + 1):
        if not _commit(n):
            return False  # could not establish density — fail closed, no dense marker
    return _mark_dense(length)


def _chain_completeness(cfg, control_root):
    """DF-R10-03: the OFF-BOX completeness ASSURANCE STATE of the local signed chain,
    as a tri(+)-state — NOT a lossy boolean — so a PRODUCTION verdict can require
    genuine off-box confirmation and never read sink-less 'best-effort' as complete
    (the R9/M70 boolean flattened `unconfirmed` into `untruncated:true`). Probes the
    monotonic checkpoint ONE PAST the local length; its existence off-box proves a
    longer chain was committed to the WORM/append-only trust domain, which a same-user
    writer cannot roll back (write-once keys). Returns (state, message):
      'confirmed_offbox' — a sink is configured + reachable and confirms the local
                           chain is NOT tail-truncated (no longer checkpoint exists).
      'unconfirmed'      — no sink configured (or unsigned): completeness is
                           detection-grade best-effort ONLY, never off-box-proven.
      'truncated'        — the sink holds a checkpoint for a LONGER chain than local
                           (the local chain was tail-truncated to erase evidence).
      'unreachable'      — a sink is configured but could not be reached to confirm."""
    sink = cfg.get("_audit", {}).get("sink", {"kind": "none"})
    if sink.get("kind", "none") == "none":
        return ("unconfirmed", "no off-box audit sink configured; local-chain completeness is "
                "detection-grade best-effort (sink-less tier)")
    # DF-R10-01: this is a VERIFY path — NEVER bootstrap the identity here (a verify-
    # time bootstrap from the writable local id was the M83 regression). If the
    # control-root identity cannot be AUTHORITATIVELY confirmed off-box (dfroot 404,
    # or the sink is unreachable), completeness is not off-box confirmed → fail closed.
    ident, state = _control_root_identity(cfg, control_root, allow_bootstrap=False)
    if ident is None:
        return ("unconfirmed", "unsigned run — no off-box chain trust boundary")
    if state == "unreachable":
        return ("unreachable", "the off-box audit sink is unreachable, so the control-root "
                "identity and local-chain completeness cannot be confirmed off-box")
    if state == "unregistered":
        # reachable sink, but this control root registered NO off-box identity yet —
        # nothing committed off-box under an authoritative namespace (a required-sink
        # write that could not register fails closed at write time), so completeness is
        # simply not off-box confirmed (best-effort); recovery proceeds, production not.
        return ("unconfirmed", "no off-box control-root identity registered — local-chain "
                "completeness is not off-box confirmed")
    ns = _chain_sink_namespace(cfg, control_root)
    if ns is None:
        return ("unconfirmed", "unsigned run — no off-box chain trust boundary")
    length = _chain_length(control_root)
    # Truncation check FIRST: a committed checkpoint for a LONGER chain than local means
    # the local chain was tail-truncated (write-once keys can't be rolled back).
    status_next, _b = df_audit_sink.probe(sink, _chain_checkpoint_key(ns, length + 1))
    if status_next == 200:
        return ("truncated", "the off-box audit sink records a LONGER signed chain than the "
                f"local audit-chain.jsonl (a committed checkpoint for length {length + 1} exists "
                f"off-box; the local chain has {length} entries) — the local chain was "
                "tail-truncated to erase audit evidence")
    if status_next not in (200, 404):
        return ("unreachable", "the off-box audit sink is unreachable, so local-chain "
                "completeness cannot be confirmed off-box")
    if length == 0:
        return ("confirmed_offbox", "the local chain is empty and no longer chain is committed "
                "off-box")
    # DF-R12-01: a 404 for length+1 is NOT completeness on its own. If a checkpoint UNDER the
    # tip is missing (a hole at h < length — a transiently-dropped checkpoint, or a pre-M84
    # legacy store), an attacker could truncate to h-1 and the one-past probe would 404 there
    # too. Require the WRITE-ONCE DENSE-BASELINE marker for the current length: it is written
    # (_checkpoint_chain_to_sink) ONLY after 1..length are all confirmed committed. Its
    # absence means the tip/range is not proven dense — NOT off-box confirmed (fail-closed for
    # a production verdict; recovery still proceeds best-effort, see _verify_chain_untruncated).
    status_dense, _b2 = df_audit_sink.probe(sink, _chain_dense_marker_key(ns, length))
    if status_dense == 200:
        return ("confirmed_offbox",
                f"off-box sink confirms the local chain (length {length}) is dense + untruncated")
    if status_dense == 404:
        return ("unconfirmed", f"the current chain tip (length {length}) has no off-box "
                "dense-baseline marker — its checkpoint range is not proven dense (a hole under "
                "the tip could hide a truncation); re-run to establish the dense baseline")
    return ("unreachable", "the off-box audit sink is unreachable, so local-chain completeness "
            "cannot be confirmed off-box")


def _verify_chain_untruncated(cfg, control_root):
    """DF-R9-04 recovery-path gate, derived from `_chain_completeness`. Returns
    (ok, reason) for the RECOVERY consumers (ship auth / source identity / resumable
    state / resume): ok=False ONLY when the chain is provably TRUNCATED, or a REQUIRED
    sink is unreachable (fail-closed). A sink-less 'unconfirmed' still PROCEEDS
    (detection-grade best-effort) — the PRODUCTION predicate separately requires
    completeness == 'confirmed_offbox' (df_evidence_bundle), which is the DF-R10-03
    fix: recovery stays available sink-less, but no production verdict claims off-box
    completeness it never obtained."""
    state, why = _chain_completeness(cfg, control_root)
    if state == "truncated":
        return (False, why)
    if state == "unreachable" and cfg.get("_audit", {}).get("sink", {}).get("required"):
        return (False, "the REQUIRED off-box audit sink is unreachable, so local-chain "
                "completeness cannot be confirmed — refusing (fail-closed)")
    return (True, why)


def verify_chain_cmd(control_root: str, key: bytes = None) -> bool:
    """CLI body for `verify-chain`. Mirrors verify_manifest's fail-closed
    semantics: a chain carrying ANY signed entry (an audit_key was
    configured when it was written) verified WITHOUT --key-path is never
    silently reported OK — the caller must prove the key to get a real
    signature check, exactly like a signed manifest with no --key-path.
    """
    chain_path = os.path.join(control_root, "audit-chain.jsonl")
    try:
        entries = df_audit_chain.read_chain(chain_path)
    except df_audit_chain.ChainError as e:
        print(str(e))
        return False
    signed = any("sig" in e for e in entries)
    if signed and key is None:
        print("UNVERIFIED (signed chain; supply --key-path)")
        return False
    ok, msg = df_audit_chain.verify_chain(chain_path, audit_key=key)
    print(msg)
    return ok


CUSTODY_SIGNATURES_FILE = "custody-signatures.json"
CUSTODY_ATTESTATION_FILE = "custody_attestation.json"


def _read_manifest_bytes(run_dir):
    """Read a run's SEALED manifest.json as raw bytes (exactly what an
    approver signs and what verification runs over) plus its sha256 (the
    same digest the manifest.sha256 sidecar carries). Returns (bytes, sha256)
    or (None, None) if the manifest is absent."""
    mp = os.path.join(run_dir, "manifest.json")
    if not os.path.exists(mp):
        return None, None
    with open(mp, "rb") as f:
        manifest_bytes = f.read()
    return manifest_bytes, sha256_str(manifest_bytes.decode("utf-8"))


def _load_custody_signatures(control_root):
    """Load <control_root>/custody-signatures.json (the collected approver
    signatures, a JSON list of {"approver", "sig"}). Returns (list, None) on
    success or ([], reason) when absent/unreadable/wrong-shape -- never
    raises."""
    sig_path = os.path.join(control_root, CUSTODY_SIGNATURES_FILE)
    if not os.path.exists(sig_path):
        return [], f"{CUSTODY_SIGNATURES_FILE} not found in the control root"
    try:
        with open(sig_path, encoding="utf-8") as f:
            loaded = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        return [], f"unreadable {CUSTODY_SIGNATURES_FILE}: {e}"
    if not isinstance(loaded, list):
        return [], f"{CUSTODY_SIGNATURES_FILE} must be a JSON list"
    return loaded, None


def _custody_config_bound(cfg, manifest_bytes):
    """Bind the custody POLICY to the exact run it gates.

    The approver allowlist + threshold are read fresh from config.json, but an
    operator who ran the build has control-root write access (they drop
    custody-signatures.json there) — so nothing stops them editing config.json's
    custody block to {approvers:[their_key], threshold:1} AFTER a legitimate
    threshold:2 run, self-signing, and self-qualifying, while manifest.json
    still records required_k:2. That would defeat single-operator-proof.

    Defense: every manifest (including the CUSTODY_PENDING one) already seals
    `config_sha256` = sha256 of the canonical config at run time (cfg[
    "_config_sha256"]). Require the CURRENT config's _config_sha256 to equal
    the sealed one; ANY edit to config.json (threshold, approvers, anything)
    changes _config_sha256 → mismatch → the caller refuses fail-closed.

    Returns (bound: bool, sealed_sha, current_sha)."""
    try:
        manifest = json.loads(manifest_bytes)
    except json.JSONDecodeError:
        return False, None, cfg.get("_config_sha256")
    sealed = manifest.get("config_sha256")
    return sealed == cfg["_config_sha256"], sealed, cfg["_config_sha256"]


def _satisfying_approvers(manifest_bytes, signatures, approvers):
    """The DISTINCT approver public keys (from `approvers`) that have a
    signature in `signatures` verifying over manifest_bytes -- the same
    distinct-count logic df_custody.verify_custody applies, surfaced here so
    the attestation can record WHICH approvers satisfied it (never a private
    key; public keys only)."""
    approver_set = {a.lower() for a in approvers if isinstance(a, str)}
    satisfied = []
    for a in sorted(approver_set):
        for entry in signatures:
            if not isinstance(entry, dict):
                continue
            ea, es = entry.get("approver"), entry.get("sig")
            if not isinstance(ea, str) or not isinstance(es, str):
                continue
            if ea.lower() == a and df_custody.verify_one(a, manifest_bytes, es):
                satisfied.append(a)
                break
    return satisfied


def _authenticate_manifest(cfg, control_root, run_dir):
    """Fail-closed: AUTHENTICATE the sealed manifest before ANY of its fields
    (config_sha256, qualified, outcome, artifact.object_id, the sealed ship
    policy) may be trusted by the ship phase or df-release attach.

    Runs the full `_verify_manifest_status` check — byte integrity + the HMAC
    signature (when the run is signed) + artifact-identity re-verification — and
    requires it to be exactly OK. This authenticates the manifest via the HMAC
    the whole design depends on (df_config forces audit.signing whenever a
    ship.approval policy exists, precisely so the sealed approver allowlist is
    HMAC-pinned): a control-root-write attacker who swaps
    ship.approval.approvers + edits config_sha256/qualified + recomputes the
    PLAIN manifest.sha256 leaves the HMAC stale, so this returns TAMPERED and we
    refuse — the irreversible-action signature gate cannot be bypassed, and an
    unqualified run cannot be flipped to qualified and shipped.

    Key handling: whenever the run is signed (`audit.signing`, or the manifest's
    own `audit_signing` flag), the audit key MUST be loadable — an absent/broken
    key is a fail-closed REFUSAL (never a silent proceed on an unverified
    manifest), and `_verify_manifest_status(key=None)` on a signed manifest
    returns UNVERIFIED, which is also refused. Returns (ok, reason)."""
    manifest_obj = None
    mp = os.path.join(run_dir, "manifest.json")
    if os.path.exists(mp):
        try:
            manifest_obj = json.loads(open(mp, encoding="utf-8").read())
        except (OSError, json.JSONDecodeError):
            manifest_obj = None
    signed = bool(cfg.get("_audit", {}).get("signing")) or bool(
        isinstance(manifest_obj, dict) and manifest_obj.get("audit_signing"))
    key = None
    if signed:
        # Use load_key (never create): a signed run's key MUST already exist to
        # authenticate; an absent/broken key is a fail-closed refusal, so an
        # approver-configured run can NEVER reach a ship/attach decision on an
        # unverified manifest.
        try:
            key = df_audit.load_key(cfg["_audit"]["key_path"])
        except df_audit.AuditKeyError as e:
            return (False, f"the audit signing key is required to authenticate this signed "
                    f"manifest but could not be loaded ({e}); refusing (fail-closed)")
    status = _verify_manifest_status(run_dir, key=key,
                                     object_store=_object_store_root(control_root))
    if status != _ARTIFACT_OK:
        return (False, f"manifest failed authentication/verification (verify-manifest: {status}); "
                "refusing to trust its fields (fail-closed)")
    return (True, "manifest authenticated")
