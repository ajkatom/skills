"""The governed ship phase (M41) and the df-release approval workflow.

Extracted verbatim from supervisor.py (see supervisor.py for the CLI entry point and
the run/resume core). Every top-level name here is re-exported by supervisor.py, so
`supervisor.<name>` keeps working for tests and df_evidence_bundle.
"""
import datetime
import json
import os
import shutil
import sys
import tempfile
import uuid

import df_audit
import df_audit_chain
import df_audit_sink
import df_creds
import df_custody
import df_release
import df_ship
from df_common import atomic_write, canonical_json, sha256_file, sha256_str
from df_config import (
    ConfigError,
)
from supervisor_audit import (
    _authenticate_manifest,
    _custody_config_bound,
    _read_manifest_bytes,
)
from supervisor_core import (
    SHIP_AUDIT_PENDING,
    SHIP_EVIDENCE_PENDING_EXIT,
    SHIP_STATE_UNAUTHENTICATED,
    UNKNOWN_OUTCOME,
    Journal,
    LockError,
    _now,
    _object_store_root,
    _resolve_credentials,
    _sup,
    acquire_lock,
    release_lock,
)
from supervisor_custody import (
    _effective_tier_of,
    _final_exam_ok,
    _precustody_substates,
    _push_qualification_offbox,
    _sink_receipt_bound,
    _sink_required,
    verify_custody_cmd,
)

# ---------------------------------------------------------------------------
# M41: the governed SHIP phase (references/ship.md).
#
# Runs ONLY after a run is QUALIFIED (invariant #1). Acts on a fresh workspace
# MATERIALIZED from the sealed artifact object, re-verified by identity
# (invariant #2). Irreversible actions require a valid, live, K-of-N SIGNED
# release approval (df_release) — absent/invalid ⇒ SHIP_APPROVAL_PENDING, never
# run, never block, in EVERY mode incl. H4 (invariant #3). Crash-safe via the
# M35 reserve-before pattern journaled to a SEPARATE ship_journal.jsonl
# (invariant #4: journal.jsonl is SEALED at finalize and must never be appended
# to). Rollback-in-reverse on failure (invariant #5). Brokered cred values reach
# only the child env; captured logs are redacted (invariant #6). The sealed
# ship record + the release attestation live in SEPARATE sidecars anchored into
# the tamper-evident audit chain — the immutable manifest is NEVER rewritten and
# `qualified` is NOT re-opened by shipping (a SHIP_FAILED run stays qualified).
# ---------------------------------------------------------------------------
SHIP_JOURNAL_FILE = "ship_journal.jsonl"
SHIP_RESULT_FILE = "ship_result.json"
RELEASE_APPROVAL_FILE = "release-approval.json"        # collected in the control root
RELEASE_ATTESTATION_FILE = "release_attestation.json"  # written per run_dir by attach


def _ship_journal_events(run_dir):
    """Read the ship crash-safety journal (SEPARATE from the sealed
    journal.jsonl). Returns a list of event dicts, or [] if absent. A malformed
    line raises (fail-closed: a corrupt ship journal must never read as 'no
    actions ran')."""
    path = os.path.join(run_dir, SHIP_JOURNAL_FILE)
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        raw = [ln.strip() for ln in f]
    nonempty = [(i, ln) for i, ln in enumerate(raw) if ln]
    out = []
    for pos, (idx, line) in enumerate(nonempty):
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            # R5 DF-R5-08: distinguish a torn TAIL from interior corruption, and
            # NEVER let a JSONDecodeError escape uncaught. The ship journal is
            # reserve-before: journal.write fsyncs a COMPLETE line BEFORE the
            # subprocess spawns. So a malformed FINAL line is a torn append (a crash
            # DURING the write, before its fsync returned) — the action it would have
            # announced never started, so it is SAFELY dropped. A malformed line that
            # is NOT last is real corruption of an already-durable record → a
            # controlled fail-closed refusal (df_ship.ShipError), never an uncaught
            # crash and never "no actions ran".
            if pos == len(nonempty) - 1:
                sys.stderr.write(
                    "dark-factory: WARNING — dropping a torn (incomplete) trailing line in the "
                    "ship journal; by reserve-before-fsync ordering the action it would announce "
                    "never spawned.\n")
                break
            raise df_ship.ShipError(
                f"ship journal is corrupt: a non-trailing line ({idx + 1}) is malformed JSON — "
                "refusing to trust the recovered ship state (fail-closed)")
    return out


def _resolution_key(data):
    """DF-R6-01: the token that binds a SHIP_ACTION_RESULT to the specific
    SHIP_ACTION_INTENT it resolves. The `attempt_id` (fresh per dispatch) when
    present; else the stable idempotency_key (a pre-M61 legacy journal, whose
    single-attempt semantics the key still matches correctly). (Forward result
    name/idk consistency is enforced separately by _repair_ship_evidence before
    any mint; see also _rollback_resolution_key for the rollback path.)"""
    aid = data.get("attempt_id")
    return aid if aid is not None else ("idk:" + str(data.get("idempotency_key")))


def _rollback_resolution_key(data):
    """DF-R8-01 (opus review F3): the (action, attempt) pair binding a
    SHIP_ROLLED_BACK / SHIP_ROLLBACK_FAILED to the SHIP_ROLLBACK_INTENT it
    resolves. Unlike forward results, SHIP_ROLLBACK_FAILED is unauthenticated and
    same-user-forgeable, and its `attempt_id` (which feeds resolution) is DECOUPLED
    from its `action` (which feeds applied.pop). Keying rollback resolution on
    attempt_id ALONE let a planted SHIP_ROLLBACK_FAILED for action B (with an
    attempt_id colliding a DIFFERENT action A's rollback intent) spoof resolution
    of A's dangling rollback intent — hiding it from the any-unresolved halt so a
    rolled-back A stayed in `applied` (the reorder-shadow's sibling). Binding the
    action forces the forged event to name A to resolve A's rollback intent — which
    then pops A from `applied` AND marks it unknown-effect (an operator halt),
    never a silent re-add."""
    aid = data.get("attempt_id")
    aid = aid if aid is not None else ("idk:" + str(data.get("idempotency_key")))
    return (data.get("action"), aid)


def _ship_action_recovery_state(run_dir):
    """DF-R6-01/02: the ONE ordered-pass recovery view of the ship journal.

    Walks events in order and returns a dict:
      - `applied`: {action -> latest-ok-result-data} for actions whose most
        recent forward `ok` result was NOT subsequently rolled back (the set a
        re-ship SKIPS — the currently-APPLIED effects);
      - `unresolved_forward`: the data of the latest SHIP_ACTION_INTENT whose
        attempt has NO matching SHIP_ACTION_RESULT (a crash left its real-world
        effect UNKNOWN), else None;
      - `unresolved_rollback`: the data of the latest SHIP_ROLLBACK_INTENT whose
        attempt has NO matching SHIP_ROLLED_BACK/SHIP_ROLLBACK_FAILED, else None.

    Matching is by attempt (see _resolution_key), so a reconciled RETRY — which
    reuses the stable idempotency_key — is a DISTINCT attempt: an old
    `reconciled_unknown` result can never resolve the retry's fresh intent, and a
    second crash re-surfaces the unknown outcome instead of silently re-firing."""
    forward_intents = {}       # attempt-key -> intent data (journal order)
    forward_resolved = set()   # attempt-keys with a result
    rollback_intents = {}      # attempt-key -> rollback intent data (journal order)
    rollback_resolved = set()
    applied = {}               # action -> latest ok result data (not yet rolled back)
    unknown_effect = set()     # actions whose rollback FAILED (real state unknown)
    for e in _ship_journal_events(run_dir):
        d = e.get("data", {})
        state = e.get("state")
        if state == "SHIP_ACTION_INTENT":
            forward_intents[_resolution_key(d)] = d
        elif state == "SHIP_ACTION_RESULT":
            forward_resolved.add(_resolution_key(d))
            if d.get("status") == "ok" and d.get("action") is not None:
                applied[d["action"]] = d
                # A fresh successful re-run resolves a prior unknown state.
                unknown_effect.discard(d["action"])
        elif state == "SHIP_ROLLBACK_INTENT":
            rollback_intents[_rollback_resolution_key(d)] = d
        elif state == "SHIP_ROLLED_BACK":
            rollback_resolved.add(_rollback_resolution_key(d))
            # A SUCCESSFUL rollback PROVES the effect is gone: drop it from
            # `applied` so the action re-runs before any SHIPPED (DF-R6-02).
            if d.get("action") is not None:
                applied.pop(d["action"], None)
                unknown_effect.discard(d["action"])
        elif state == "SHIP_ROLLBACK_FAILED":
            rollback_resolved.add(_rollback_resolution_key(d))
            # A FAILED rollback proves NOTHING about the real-world state: the
            # undo may have partially applied, or not at all (the effect may
            # still be fully present). Neither silently skipping (omission) nor
            # silently re-running (DUPLICATE of a possibly-still-applied,
            # possibly-non-idempotent action) is safe — so the action enters an
            # explicit UNKNOWN-effect set that forces an operator decision
            # (SHIP_UNKNOWN_OUTCOME) instead of either guess.
            if d.get("action") is not None:
                applied.pop(d["action"], None)
                unknown_effect.add(d["action"])
    # DF-R8-01 (opus review F2 — reorder-shadow): surface ANY unresolved intent,
    # not just the LATEST. The latest-only check was dodgeable: an attacker who
    # deletes a rollback's SHIP_ROLLED_BACK (to re-add the rolled-back action) but
    # KEEPS its SHIP_ROLLBACK_INTENT (so the intent-orphan check in
    # _authenticate_ship_actions still attributes the anchored token) could then
    # REORDER that dangling intent to sit BEHIND another, resolved rollback intent
    # — making `latest_rollback_intent` resolved and hiding the dangling one. With
    # every unresolved intent surfaced, the dangling rollback re-triggers the
    # SHIP_UNKNOWN_OUTCOME halt (which reconcile then pops → re-run, never a silent
    # re-add). Legit runs resolve EVERY intent, so this never false-positives; a
    # genuine crash leaves exactly one unresolved intent, still caught. The
    # last-journaled unresolved intent is reported (stable messaging). The same
    # symmetry closes the forward analogue (a hidden dangling forward intent whose
    # deleted result would otherwise let the action silently re-run as a DUPLICATE).
    unresolved_forward = None
    for _k, _d in forward_intents.items():
        if _k not in forward_resolved:
            unresolved_forward = _d
    unresolved_rollback = None
    for _k, _d in rollback_intents.items():
        if _k not in rollback_resolved:
            unresolved_rollback = _d
    return {"applied": applied,
            "unknown_effect": unknown_effect,
            "unresolved_forward": unresolved_forward,
            "unresolved_rollback": unresolved_rollback}


def _unresolved_ship_action(run_dir):
    """The M35 reserve-before check, for ship actions (DF-R6-01/02): the data
    dict of the latest unresolved FORWARD or ROLLBACK intent — a prior process
    crashed after journaling+fsyncing the intent but before its outcome resolved
    (real-world effect UNKNOWN) — else None. Never a blind re-run of a deploy."""
    st = _ship_action_recovery_state(run_dir)
    return st["unresolved_forward"] or st["unresolved_rollback"]


def _dangling_signed_dispatch(cfg, control_root, run_dir, run_id):
    """DF-R9-02: the intent-data of a SIGNED (anchored) forward dispatch whose
    real-world outcome is UNAUTHENTICATED — its attempt has NO anchored completion
    token AND no signed operator-reconcile token — else None (latest, mirroring
    `unresolved_forward`).

    The reserve-before check (`unresolved_forward`) only catches a dispatch with NO
    result. DF-R9-02: a same-user writer can instead PLANT an unsigned non-`ok`
    RESULT (failed/timed_out/reconciled_unknown) for a genuine dangling dispatch
    whose action ALREADY RAN — the recovery reducer marks the intent resolved by
    ANY status, so `unresolved_forward` goes None and the action RE-RUNS with no
    SHIP_UNKNOWN_OUTCOME consent gate (a duplicate). A dispatched action is only
    AUTHENTICALLY resolved by a signed COMPLETION (ran + exited 0) or a signed
    RECONCILE (operator consent); an unsigned result is forgeable and does not
    count. Fail-soft (None) on any key/chain error — the unconditional
    `_authenticate_ship_actions` under signing then fails closed before the action
    loop. Unsigned runs are detection-grade (no signed intents) → None."""
    if not bool(cfg.get("_audit", {}).get("signing")):
        return None
    try:
        key = df_audit.load_key(cfg.get("_audit", {}).get("key_path"))
    except (df_audit.AuditKeyError, KeyError, TypeError):
        return None
    chain_path = os.path.join(control_root, "audit-chain.jsonl")
    try:
        ok, _why = df_audit_chain.verify_chain(chain_path, key)
        if not ok:
            return None
        entries = df_audit_chain.read_chain(chain_path)
    except df_audit_chain.ChainError:
        return None

    def _anchored_under(kind):
        pre = f"{run_id}.{kind}."
        return {e.get("manifest_sha256") for e in entries
                if str(e.get("invocation", "")).startswith(pre)}

    anchored_intents = _anchored_under("ship-action-intent")
    anchored_completions = _anchored_under("ship-action")
    anchored_reconciled = _anchored_under("ship-action-reconciled")
    n = len(anchored_completions) + 2  # bounded seq search for a completion
    # M56b evidence-pending states (`evidence_pending` — the action RAN but its
    # completion anchor failed; `not_run_evidence_halt` — the intent could not be
    # signed pre-spawn so nothing ran) legitimately have a signed intent and NO
    # completion; they are handled by the authenticated `--decision repair-evidence`
    # flow (which never silently re-runs), NOT the unknown-outcome gate. Exclude
    # those attempts so this check does not double-flag them.
    m56b_attempts = {d.get("attempt_id") for e in _ship_journal_events(run_dir)
                     for d in [e.get("data", {})]
                     if e.get("state") == "SHIP_ACTION_RESULT"
                     and d.get("status") in ("evidence_pending", "not_run_evidence_halt")}
    dangling = None
    for e in _ship_journal_events(run_dir):
        if e.get("state") != "SHIP_ACTION_INTENT":
            continue
        d = e.get("data", {})
        att = d.get("attempt_id")
        if att in m56b_attempts:
            continue
        intent_token = sha256_str(_ship_action_intent_payload(
            run_id, d.get("action"), d.get("idempotency_key"), d.get("toolchain"),
            d.get("reversible"), d.get("approval_ref"), attempt_id=att))
        if intent_token not in anchored_intents:
            continue  # unsigned dispatch — out of the signed trust boundary
        has_completion = any(
            sha256_str(_ship_action_commit_payload(
                run_id, d.get("action"), d.get("idempotency_key"), d.get("toolchain"),
                d.get("reversible"), d.get("approval_ref"), attempt_id=att, seq=s))
            in anchored_completions for s in range(n))
        if has_completion:
            continue
        if sha256_str(_ship_reconciled_payload(run_id, d.get("action"), att)) in anchored_reconciled:
            continue  # operator-consented reconcile of this attempt
        dangling = d  # signed dispatch, no authenticated outcome → unknown
    return dangling


def _ship_completed_actions(run_dir):
    """Names of actions currently APPLIED (a prior attempt succeeded and was NOT
    later rolled back) — recovered so a re-ship SKIPS them, never re-runs a
    succeeded action, but ALSO never skips one whose effect was undone
    (DF-R6-02)."""
    return set(_ship_action_recovery_state(run_dir)["applied"].keys())


def _load_release_attestation(run_dir, cfg=None):
    """Load <run_dir>/release_attestation.json (df-release attach output), or
    None if absent/unreadable/wrong-shape (fail-closed: an unreadable attestation
    covers nothing, so an irreversible action stays gated).

    M44 RA-02: when `cfg` is provided AND its sealed config mandates a required
    off-box audit sink, the attestation is honored ONLY if the bound
    `release_sink_receipt.json` is present and binds these exact attestation
    bytes — an approval whose off-box record never left the box covers nothing,
    so the irreversible action stays gated (SHIP_APPROVAL_PENDING), never a
    silent authorization."""
    path = os.path.join(run_dir, RELEASE_ATTESTATION_FILE)
    if not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8") as f:
            att_raw = f.read()
        att = json.loads(att_raw)
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(att, dict):
        return None
    if cfg is not None and _sink_required(cfg):
        ok_r, _why = _sink_receipt_bound(run_dir, "release_sink_receipt.json", att_raw)
        if not ok_r:
            sys.stderr.write(
                "dark-factory: release approval ignored — required off-box sink receipt "
                f"missing/unbound ({_why}); the irreversible action stays gated.\n")
            return None
    # DF-R6-08: under signing, the attestation must be a MEMBER of the signed
    # audit chain — the M64 transaction anchors it (and refuses to consume the
    # nonce otherwise). A same-user writer who plants a release_attestation.json
    # (to authorize an irreversible action) cannot forge a signature-valid chain
    # entry over its bytes, so an unanchored attestation covers nothing.
    if cfg is not None and bool(cfg.get("_audit", {}).get("signing")):
        run_id = os.path.basename(run_dir.rstrip(os.sep))
        try:
            mp = os.path.join(run_dir, "manifest.json")
            run_id = json.loads(open(mp, encoding="utf-8").read()).get("invocation") or run_id
        except (OSError, json.JSONDecodeError, AttributeError):
            pass
        ok_c, why_c = _authenticate_ship_chain(
            cfg, os.path.dirname(os.path.dirname(run_dir)), run_id,
            sha256_str(att_raw), "release")
        if not ok_c:
            sys.stderr.write(
                "dark-factory: release approval ignored — the attestation is not anchored in "
                f"the signed audit chain ({why_c}); the irreversible action stays gated.\n")
            return None
    return att


def _ship_eligible(cfg, control_root, run_dir):
    """Invariant #1: decide whether a run's SEALED artifact may ship.

    Returns (ok, reason, artifact_object_id, run_id). Eligible iff: the manifest
    AUTHENTICATES (byte integrity + HMAC signature when signed + artifact identity,
    via _authenticate_manifest — so no manifest field can be trusted until its
    HMAC is verified); the sealed config_sha256 still equals the current config
    (policy binding, mirrors custody); AND the run is CLEANLY qualified —
    non-enterprise: outcome COMPLETE_QUALIFIED AND qualified:true; enterprise: a
    valid K-of-N custody attestation (verify_custody). A waived-but-limited /
    custody-pending-without-attestation / unqualified run is refused (never
    ships)."""
    manifest_bytes, _manifest_sha = _read_manifest_bytes(run_dir)
    if manifest_bytes is None:
        return (False, "no manifest.json (run has not sealed)", None, None)
    try:
        manifest_obj = json.loads(manifest_bytes)
    except json.JSONDecodeError as e:
        return (False, f"manifest.json is not valid JSON: {e}", None, None)

    # CRITICAL (M41 review fix): authenticate the manifest BEFORE trusting ANY
    # field of it. The whole irreversible-action gate + qualification precondition
    # rests on the sealed config_sha256 (approver allowlist) and the sealed
    # qualified/outcome — but those are only trustworthy once the manifest's HMAC
    # is verified. Without this, a control-root-write attacker could swap
    # ship.approval.approvers, edit config_sha256/qualified to match, recompute
    # the PLAIN manifest.sha256, leave the HMAC stale, and self-approve an
    # irreversible ship (or ship an unqualified artifact). This authenticates the
    # HMAC the design depends on and folds in the artifact-identity re-verify.
    ok, why = _authenticate_manifest(cfg, control_root, run_dir)
    if not ok:
        return (False, why, None, None)

    artifact = manifest_obj.get("artifact")
    if not isinstance(artifact, dict) or not isinstance(artifact.get("object_id"), str):
        return (False, "manifest binds no artifact object (nothing content-addressed to ship)",
                None, None)
    object_id = artifact["object_id"]

    bound, sealed_sha, current_sha = _custody_config_bound(cfg, manifest_bytes)
    if not bound:
        return (False, f"config.json changed since this run (sealed config_sha256 {sealed_sha} != "
                f"current {current_sha}); refusing to ship under a drifted policy", None, None)

    run_id = os.path.basename(os.path.abspath(run_dir).rstrip(os.sep))
    tier = _effective_tier_of(manifest_obj)  # R5 DF-R5-04: ship on the EFFECTIVE tier
    if tier == "enterprise":
        # Enterprise ships ONLY after df-custody attach qualifies it (invariant
        # #1). qualification lives in custody_attestation.json, never in the
        # CUSTODY_PENDING manifest itself.
        if not verify_custody_cmd(control_root, run_dir):
            return (False, "enterprise run is not custody-qualified — run df-custody attach "
                    "(>=K approvers) before shipping", None, None)
        return (True, "enterprise custody-qualified", object_id, run_id)

    if manifest_obj.get("outcome") == "COMPLETE_QUALIFIED" and manifest_obj.get("qualified") is True:
        return (True, "qualified", object_id, run_id)
    return (False,
            f"run outcome {manifest_obj.get('outcome')!r} (qualified="
            f"{manifest_obj.get('qualified')!r}) is not a clean qualified artifact — a "
            "waived/pending/unqualified run never ships", None, None)


def _resolve_ship_action_creds(action):
    """Resolve ONE ship action's `creds.env` NAMES to values, host-side, at
    action time, via the df_creds broker (source 'env' — the operator's launcher
    environment). Fail-closed: a missing/empty required var raises CredsError. An
    action with no creds returns {}. The VALUES returned reach ONLY the child
    subprocess env (df_ship._child_env) and the per-action Redactor — never the
    config, journal, manifest, or a captured log."""
    env_names = (action.get("creds") or {}).get("env") or []
    if not env_names:
        return {}
    return df_creds.load_credentials({"source": "env", "allowlist": list(env_names)})


def _anchor_ship_local(cfg, control_root, run_id, record_text, kind, key_suffix=None):
    """DF-R4-03 primitive #1 — the LOCAL signed anchor ONLY (no off-box push).
    Append one entry binding `record_text`'s digest into the tamper-evident
    per-control-root hash chain. `kind` is 'ship' / 'ship-action' / 'release' /
    'source-identity' / 'resumable-state'; the chain key is uniquified so repeated
    attempts (pending → attach → ship, plus the audit-only retry) each anchor
    without colliding. `key_suffix` (M77) overrides that random uniquifier with a
    DETERMINISTIC suffix (e.g. a monotonic `{seq:08d}`) so a later recovery can read
    the seq back out of the chain key and find the highest/matching anchor.

    Uses df_audit.load_key (NEVER load_or_create_key): an established signed run's
    audit key MUST already exist. A key that is missing/unloadable AFTER an action
    has run is a fail-closed PENDING state, never grounds to mint a REPLACEMENT key
    — a fresh key would FORK the chain (verify_chain then rejects every prior entry,
    breaking custody/qualification verify too) and would let a key-deletion attacker
    launder an unanchored ship as 'freshly signed'. Returns:
      "anchored"      the chain entry was committed (signed when signing is on)
      "anchor_failed" signing is on and the signed entry could NOT be committed (key
                      unloadable, or the append raised) — the caller must NOT
                      finalize an authoritative SHIPPED off this anchor.
    When signing is OFF the chain is unsigned and is NOT the trust boundary (the
    tier is detection-grade by construction); an append error is warned and still
    returns "anchored" (there is nothing to fail closed on). This split from the
    off-box push (see _push_ship_offbox) is what lets the ship seal push off-box
    FIRST and anchor/commit an authoritative SHIPPED only after the evidence lands."""
    chain_path = os.path.join(control_root, "audit-chain.jsonl")
    chain_key = f"{run_id}.{kind}.{key_suffix if key_suffix is not None else uuid.uuid4().hex[:8]}"
    if bool(cfg.get("_audit", {}).get("signing")):
        # CRITICAL (M49): never append an UNSIGNED entry to a SIGNED chain — it would
        # make verify_chain fail the ENTIRE control-root chain. A key that cannot be
        # loaded is surfaced as anchor_failed (fail-closed), never a silent proceed
        # and never a replacement key (DF-R4-03).
        try:
            audit_key = df_audit.load_key(cfg["_audit"]["key_path"])
        except df_audit.AuditKeyError as e:
            sys.stderr.write(
                f"dark-factory: WARNING — the audit signing key required to anchor the {kind} "
                f"record could not be loaded ({e}); REFUSING to mint a replacement key "
                f"(fail-closed) — the local signed anchor is PENDING.\n")
            return "anchor_failed"
        try:
            df_audit_chain.append_entry(chain_path, chain_key, sha256_str(record_text), _now(),
                                        audit_key)
        except (df_audit_chain.ChainError, OSError) as e:
            sys.stderr.write(
                f"dark-factory: WARNING — could not anchor the {kind} record into the signed "
                f"audit chain ({e}); the local signed anchor is PENDING.\n")
            return "anchor_failed"
        # DF-R9-04: commit this new chain length off-box so a later tail-truncation of
        # THIS just-anchored ship token is detectable on re-entry. Kept NON-fatal here
        # by design: a required sink that is DOWN is handled by the SEAL's required
        # off-box record push (SHIPPED_AUDIT_PENDING) and the production predicate
        # requires completeness == confirmed_offbox (DF-R12-01 fix #2 now requires the
        # dense-baseline marker, so a checkpoint that did NOT land leaves the run
        # not-confirmed → no production GO until the next run backfills it). Making it
        # fatal here would break the SHIPPED_AUDIT_PENDING crash-window recovery. We DO
        # surface a required-sink checkpoint miss so it is auditable, not silent.
        if not _sup()._checkpoint_chain_to_sink(cfg, control_root) \
                and cfg.get("_audit", {}).get("sink", {}).get("required"):
            sys.stderr.write(
                f"dark-factory: WARNING — the {kind} chain-length checkpoint did not land on "
                "the REQUIRED off-box sink; this run is NOT off-box-complete (no production "
                "verdict) until the next checkpoint backfills the length.\n")
        return "anchored"
    # signing off: best-effort unsigned chain (not a trust boundary).
    try:
        df_audit_chain.append_entry(chain_path, chain_key, sha256_str(record_text), _now(), None)
    except (df_audit_chain.ChainError, OSError) as e:
        sys.stderr.write(f"dark-factory: audit chain append warning ({kind}, unsigned): {e}\n")
    return "anchored"


def _push_ship_offbox(cfg, run_dir, run_id, record_text, kind):
    """DF-R4-04 primitive #2 — push `record_text` off-box to the configured audit
    sink and, on a SERVER-authentic receipt, persist a receipt BOUND to these exact
    bytes as <run_dir>/<kind>_sink_receipt.json. Called BEFORE any authoritative
    local SHIPPED is written/anchored (see _seal_ship_result / _ship_audit_retry),
    so a crash in the commit window can never leave a local SHIPPED without its
    off-box evidence. Returns:
      "skip"           no sink configured — nothing pushed
      "ok"             pushed AND (for a required sink) the SERVER returned an
                       authentic receipt — a receipt bound to these bytes persisted
      "optional_fail"  the sink is NOT required and the push FAILED — proceed, warn
      "required_fail"  the sink IS required and the push FAILED, OR returned no
                       server-authentic receipt — the caller must NOT finalize a
                       clean SHIPPED (the mandated off-box evidence never landed).

    A REQUIRED sink demands server_issued is True: a 2xx that carried only a
    locally-computable fallback receipt is treated as required_fail — detection
    grade rests on the off-box trust domain, so a purely-local receipt (which a
    same-user attacker can fabricate) cannot satisfy required:true. A sink kind that
    structurally cannot return a server-authentic receipt therefore cannot back a
    required sink, fail-closed. (For an OPTIONAL sink a successful push persists the
    bound receipt whether or not it is server-authentic — it is best-effort.)"""
    sink = cfg.get("_audit", {}).get("sink", {"kind": "none", "required": False})
    if sink.get("kind", "none") == "none":
        return "skip"
    required = bool(sink.get("required"))
    chain_key = f"{run_id}.{kind}.{uuid.uuid4().hex[:8]}"
    try:
        receipt = df_audit_sink.push(sink, chain_key, record_text.encode("utf-8"))
    except df_audit_sink.SinkError as e:
        if required:
            sys.stderr.write(
                f"dark-factory: WARNING — the REQUIRED audit sink push of the {kind} record "
                f"FAILED ({e}); the mandated off-box evidence did not leave the box.\n")
            return "required_fail"
        sys.stderr.write(f"dark-factory: audit sink push warning ({kind}, not required): {e}\n")
        return "optional_fail"
    if required and receipt.get("server_issued") is not True:
        # 2xx, but only a locally-computable fallback receipt — NOT off-box evidence
        # for a REQUIRED sink. Persist NOTHING (a non-authentic receipt must never
        # look like it satisfies the requirement) and fail closed.
        sys.stderr.write(
            f"dark-factory: WARNING — the REQUIRED audit sink accepted the {kind} record but "
            f"returned NO server-authentic receipt; a locally-computable receipt is not off-box "
            f"evidence (fail-closed).\n")
        return "required_fail"
    # Bind the persisted receipt to the EXACT bytes pushed (M44 _sink_receipt_bound
    # checks body_sha256), so the ship-verify path can prove the receipt is for THIS
    # sealed record — not a stale/forged one — and (required) that it is server-issued.
    receipt = dict(receipt, body_sha256=sha256_str(record_text), sink_key=chain_key)
    atomic_write(os.path.join(run_dir, f"{kind}_sink_receipt.json"), canonical_json(receipt))
    return "ok"


def _ship_toolchain_identity(actions):
    """M49 DF-R3-06 / DF-R4-08 FALLBACK ONLY: seal-time (post-hoc) resolution of
    each action's `run[0]` identity. Since M55 the AUTHORITATIVE toolchain is
    captured PRE-exec inside df_ship.run_actions (resolved against the action's
    cwd, hashed before the spawn) and threaded out on the run result; this
    seal-time resolver is used solely on the no-run SHIP_FAILED paths
    (materialize-failure / reconcile-abort) where no action executed, so its
    weaker semantics (supervisor cwd, post-run bytes) never describe a real run.
    Best-effort and HONEST: a PATH-resolved (or absolute) regular readable file
    gets a sha256; anything not resolvable/hashable is recorded as such (never a
    false claim). This does NOT make the external tool immutable — it stays
    operator-controlled (see references/ship.md)."""
    out = []
    for action in actions:
        argv = action.get("run") or []
        argv0 = argv[0] if argv else None
        entry = {"action": action.get("name"), "argv0": argv0,
                 "resolved_path": None, "sha256": None, "note": None}
        if not argv0:
            entry["note"] = "action has no run argv"
            out.append(entry)
            continue
        resolved = shutil.which(argv0)
        if resolved is None and os.path.isfile(argv0):
            resolved = os.path.abspath(argv0)
        if resolved is None:
            entry["note"] = "argv0 not resolvable to a file on PATH (operator-controlled)"
            out.append(entry)
            continue
        entry["resolved_path"] = resolved
        try:
            if os.path.isfile(resolved) and os.access(resolved, os.R_OK):
                entry["sha256"] = sha256_file(resolved)
            else:
                entry["note"] = "resolved path is not a regular readable file"
        except OSError as e:
            entry["note"] = f"unhashable ({e})"
        out.append(entry)
    return out


def _ship_action_commit_payload(run_id, action, idk, toolchain=None,
                                reversible=None, approval_ref=None, attempt_id=None,
                                seq=None):
    """The canonical bytes whose sha256 is a completed ship action's chain-anchored
    completion token (M49 DF-R3-03; R5 DF-R5-01). Binds the run, the action name,
    its idempotency_key, AND every per-action EVIDENCE field — the PRE-EXEC
    toolchain identity, the `reversible` classification, and the `approval_ref` that
    authorized it — so the token is reconstructible from the journal on re-entry yet
    unforgeable without the audit key (the signature over the chain entry is the
    real gate).

    DF-R5-01: binding these is what lets the final SHIPPED record be RECONSTRUCTED
    from authenticated facts — a control-root writer who edits the toolchain (which
    tool ran), the reversibility claim, or the approval that authorized an
    irreversible action in the writable pending record cannot make the
    reconstructed, chain-authenticated token match, so the forged value never
    reaches the signed/off-box final bytes. (An authenticated-`ok` action is exit-0
    by definition, and the shipped artifact id is reconstructed from the sealed
    manifest, so those two need no separate binding here; `duration_s` is genuinely
    cosmetic and is dropped by the reconstruction.)"""
    return canonical_json({"kind": "ship-action-ok", "run_id": run_id,
                           "action": action, "idempotency_key": idk,
                           "attempt_id": attempt_id, "seq": seq,
                           "toolchain": toolchain, "reversible": reversible,
                           "approval_ref": approval_ref})


def _ship_rollback_payload(run_id, action, attempt_id):
    """DF-R7-01: the canonical bytes whose sha256 is a SUCCESSFUL rollback's
    chain-anchored token. Signing rollbacks (not just forward completions) is
    what lets recovery derive the applied set from AUTHENTICATED transitions: a
    same-user writer who appends a bare `SHIP_ROLLED_BACK` for a real applied
    action — to force it to re-run and DUPLICATE — has no matching signed token,
    so the removal is refused. Bound to the rollback's own attempt_id.

    DF-R8-01: deliberately NOT `seq`-bound (unlike forward completions). The token
    is recomputable from the SHIP_ROLLBACK_INTENT alone (run_id + action +
    attempt_id — the intent is journaled+fsynced BEFORE the rollback runs), which
    is what lets recovery ATTRIBUTE every anchored rollback token to a surviving
    intent and so detect a DELETED rollback (opus review F1): an attacker who
    strips a rollback's journal lines to re-add a rolled-back action leaves an
    anchored token that maps to no surviving intent → refused. Rollback ORDERING
    is enforced separately, by the running-applied-set membership check in
    _verify_ship_transition_chain (a rollback for a not-currently-applied action is
    refused), so a seq is not needed here and would only break that attribution."""
    return canonical_json({"kind": "ship-rollback-ok", "run_id": run_id,
                           "action": action, "attempt_id": attempt_id})


def _ship_reconciled_payload(run_id, action, attempt_id):
    """DF-R9-02: the canonical bytes whose sha256 is a signed operator-RECONCILE
    token — the authenticated proof that the operator ran `--decision reconcile`
    for THIS dispatched action's unknown outcome. A dispatched (signed-intent)
    action is only AUTHENTICALLY resolved by a signed completion (it ran + exited
    0) or this signed reconcile (the operator consented to re-run, accepting a
    possible duplicate). An UNSIGNED non-`ok` RESULT (failed/timed_out/
    reconciled_unknown) a same-user writer can forge does NOT resolve a signed
    intent — a FORGED reconciled_unknown has no matching token, so recovery keeps
    the action UNKNOWN rather than silently re-running it. Bound to the attempt."""
    return canonical_json({"kind": "ship-action-reconciled", "run_id": run_id,
                           "action": action, "attempt_id": attempt_id})


def _ship_action_intent_payload(run_id, action, idk, toolchain=None,
                                reversible=None, approval_ref=None, attempt_id=None,
                                seq=None):
    """R5 DF-R5-02: the canonical bytes of a ship action's PRE-SPAWN intent token —
    the SAME evidence fields as the completion token, under a DISTINCT kind so the
    two can never collide. Signed BEFORE the action spawns, it is what makes the
    evidence-pending recovery authenticated: when the completion token later fails
    to sign (signer outage AFTER the real-world action ran), the retry may re-sign
    the completion from the journaled facts ONLY because those exact facts were
    already chain-bound while the signer was up. A same-user writer who plants an
    intent + evidence_pending journal pair for an action that never ran cannot
    produce the matching SIGNED intent token, so the retry refuses it."""
    return canonical_json({"kind": "ship-action-intent", "run_id": run_id,
                           "action": action, "idempotency_key": idk,
                           "attempt_id": attempt_id, "seq": seq,
                           "toolchain": toolchain, "reversible": reversible,
                           "approval_ref": approval_ref})


def _make_ship_action_committer(cfg, control_root, run_dir, run_id):
    """Return a `commit(action_name, idempotency_key)` hook passed into
    df_ship.run_actions. As EACH action succeeds — BEFORE its SHIP_ACTION_RESULT
    is journaled — this anchors that action's completion token into the signed
    chain (chain-only, never off-box). So every `already_done` entry recovered on
    re-entry is INDIVIDUALLY chain-backed: a legitimate crash-before-seal recovery
    still authenticates (each completed action has its own signed entry), while a
    planted/edited SHIP_ACTION_RESULT `ok` line has NO matching signed entry.

    This is why per-action anchoring (not one last-digest at seal) is required: a
    single last-digest cannot distinguish 'no anchor because a legit crash happened
    before the first seal' from 'anchor missing because tampered' — both look
    anchor-less. A per-action signed entry makes the two distinguishable.

    DF-R8-01: forward completions and successful rollbacks also draw a monotonic
    `seq` from ONE per-run counter (seeded from the journal so a resume/repair
    continues, never reuses, the sequence). The seq is bound into the signed token
    and returned so run_actions can journal it — this is what makes replay/reorder/
    deletion of otherwise-genuine signed transitions detectable on recovery. Intent
    tokens do NOT consume a seq (they don't determine the applied set)."""
    head = [_max_ship_seq(run_dir) + 1]

    def _commit(action_name, idk, toolchain=None, reversible=None, approval_ref=None,
                phase="done", attempt_id=None):
        # R5 DF-R5-02: phase "intent" signs the PRE-SPAWN intent token (distinct
        # payload kind); "done" signs the completion token; DF-R7-01: "rollback"
        # signs a SUCCESSFUL rollback's token. Every payload binds the dispatch's
        # `attempt_id`, so a signed token authenticates EXACTLY its own attempt
        # (an old attempt's token can no longer authenticate a planted new one).
        # All chain-only, never off-box.
        # DF-R8-05: anchor each token TYPE under a DISTINCT chain namespace so a
        # recovery query can tell an intent from a completion from a rollback.
        # (Before, all three shared `{run}.ship-action.`, so _is_no_action_terminal
        # wrongly treated a genuine pre-spawn INTENT — which every unresolved
        # action has — as proof the run shipped, and refused the governed abort
        # reseal.) Completions keep the `ship-action` namespace so the existing
        # completion authentication is byte-unchanged.
        # DF-R8-01: only forward COMPLETIONS draw the next monotonic seq (consumed
        # only if the anchor lands). Intents and rollbacks carry no seq — rollback
        # tokens are attributed by attempt_id (see _ship_rollback_payload) and their
        # ordering is checked by applied-set membership, not a seq.
        if phase == "intent":
            seq = None
            payload = _ship_action_intent_payload(run_id, action_name, idk, toolchain,
                                                  reversible, approval_ref, attempt_id)
            kind = "ship-action-intent"
        elif phase == "rollback":
            seq = None
            payload = _ship_rollback_payload(run_id, action_name, attempt_id)
            kind = "ship-rollback"
        else:
            seq = head[0]
            payload = _ship_action_commit_payload(run_id, action_name, idk, toolchain,
                                                  reversible, approval_ref, attempt_id,
                                                  seq=seq)
            kind = "ship-action"
        # DF-R5-01/R5-02: return the anchor status so run_actions can make an
        # anchor FAILURE a first-class result (do NOT journal `ok` for an action
        # whose completion token could not be signed — that would brick re-entry).
        status = _sup()._anchor_ship_local(cfg, control_root, run_id, payload, kind)
        # DF-R8-01: only advance the counter when the transition actually anchored,
        # so a failed anchor (evidence-pending) leaves the seq free for the retry —
        # the sequence stays gapless.
        if seq is not None and status == "anchored":
            head[0] += 1
        return (status, seq)
    return _commit


def _ship_completed_action_facts(run_dir):
    """(action, idempotency_key, toolchain) for every SHIP_ACTION_RESULT with status
    'ok' recovered from the ship journal — the exact set `already_done` skips, paired
    with the idempotency_key AND the PRE-EXEC toolchain each completion token binds
    (M49 DF-R3-03; R5 DF-R5-01). The toolchain is journaled on the matching
    SHIP_ACTION_INTENT (written before the spawn); it is recovered here so
    _authenticate_ship_actions can recompute the toolchain-bound signed token — a
    control-root writer who edits the toolchain cannot make the recomputed token
    match, so a forged toolchain is refused and never reconstructed into a signed
    final SHIPPED record."""
    # DF-R6-02: derive facts from the ordered-pass APPLIED set, so the
    # authenticated set == the skip set (`_ship_completed_actions`) exactly — a
    # rolled-back action is neither skipped nor authenticated-as-done. The
    # toolchain/reversible/approval_ref come from the intent of the SAME attempt
    # that produced the applied `ok` (matched by attempt_id, falling back to the
    # last intent for the idk on a legacy journal).
    applied = _ship_action_recovery_state(run_dir)["applied"]
    intents_by_key = {}
    intents_by_idk = {}
    for e in _ship_journal_events(run_dir):
        d = e.get("data", {})
        if e.get("state") == "SHIP_ACTION_INTENT":
            intents_by_key[_resolution_key(d)] = d
            if d.get("idempotency_key") is not None:
                intents_by_idk[d.get("idempotency_key")] = d
    facts = []
    for name, result in applied.items():
        intent = intents_by_key.get(_resolution_key(result)) \
            or intents_by_idk.get(result.get("idempotency_key")) or {}
        facts.append({"name": name, "idk": result.get("idempotency_key"),
                      # DF-R7-01: the applied attempt's own id, so the recomputed
                      # completion token authenticates EXACTLY that attempt — an
                      # earlier attempt's signed token no longer matches a planted
                      # later `ok` that shares the stable fields.
                      "attempt_id": result.get("attempt_id"),
                      # DF-R8-01: the applied completion's monotonic chain position,
                      # journaled on its SHIP_ACTION_RESULT — bound into the signed
                      # token so recovery recomputes it at the exact seq it was
                      # signed at (a tampered seq yields a token that was never
                      # anchored).
                      "seq": result.get("seq"),
                      "toolchain": intent.get("toolchain"),
                      "reversible": intent.get("reversible"),
                      "approval_ref": intent.get("approval_ref")})
    return facts


def _ship_reentry_payload(run_id, ship_result_sha256, nonce):
    """DF-R8-02: the canonical bytes whose sha256 is a SHIP_REENTRY_VERIFIED
    token. It binds the run, the sha256 of the EXACT authenticated ship_result.json
    the re-entry re-verified, and a fresh per-re-entry nonce. Anchored into the
    signed chain, it is the POSITIVE proof — recomputable from the journal — that
    the mandated 'ship again and prove idempotence' exercise actually ran against
    THIS terminal and dispatched no new action (the re-entry returns before the
    action loop; its very existence attests no redispatch)."""
    return canonical_json({"kind": "ship-reentry-verified", "run_id": run_id,
                           "ship_result_sha256": ship_result_sha256, "nonce": nonce})


def _record_ship_reentry_verified(cfg, control_root, run_dir, run_id, ship_journal,
                                  ship_result_sha256):
    """DF-R8-02: on an authenticated terminal-SHIPPED re-entry that runs NOTHING,
    anchor a signed SHIP_REENTRY_VERIFIED token (binding the authenticated
    ship_result bytes + a fresh nonce) and journal it, so the production evidence
    bundle has a positive, chain-authenticated re-entry fact. Fail-soft: if the
    anchor cannot commit (signer down), the event is journaled `anchored:false` and
    the bundle simply won't count it — never a brick of the idempotent re-entry."""
    nonce = uuid.uuid4().hex
    payload = _ship_reentry_payload(run_id, ship_result_sha256, nonce)
    status = _sup()._anchor_ship_local(cfg, control_root, run_id, payload, "ship-reentry")
    ship_journal.write("SHIP_REENTRY_VERIFIED", ship_result_sha256=ship_result_sha256,
                       nonce=nonce, anchored=(status == "anchored"))
    return status


def _authenticate_ship_chain(cfg, control_root, run_id, target_sha, kind):
    """M49 DF-R3-03 core (ship record): verify the signed audit chain and confirm
    ANY signature-valid chain entry for this run's `kind` ('ship') anchors
    `target_sha`. A planted/altered ship_result.json has no such entry. Fail-closed
    on ANY chain read/verify error or a missing key (never a silent proceed).
    Returns (ok, reason)."""
    audit = cfg.get("_audit", {})
    try:
        key = df_audit.load_key(audit["key_path"])
    except df_audit.AuditKeyError as e:
        return (False, f"the audit signing key required to authenticate the sealed ship "
                f"{kind} state could not be loaded ({e}); refusing (fail-closed)")
    chain_path = os.path.join(control_root, "audit-chain.jsonl")
    ok, why = df_audit_chain.verify_chain(chain_path, key)
    if not ok:
        return (False, f"the signed audit chain failed verification ({why}); refusing to trust "
                f"the local ship {kind} state (fail-closed)")
    try:
        entries = df_audit_chain.read_chain(chain_path)
    except df_audit_chain.ChainError as e:
        return (False, f"the audit chain is unreadable ({e}); refusing (fail-closed)")
    prefix = f"{run_id}.{kind}."
    for e in entries:
        if str(e.get("invocation", "")).startswith(prefix) and e.get("manifest_sha256") == target_sha:
            return (True, f"ship {kind} authenticated against the signed audit chain")
    return (False, f"no signature-valid audit-chain entry anchors this ship {kind}'s digest "
            "(a planted or altered local ship state)")


def _max_ship_seq(run_dir):
    """DF-R8-01: the highest monotonic `seq` journaled on any signed forward
    COMPLETION (a SHIP_ACTION_RESULT `ok`), or -1 if none. A fresh or RESUMED
    committer continues the contiguous completion chain at max+1, so a
    crash/resume/repair-evidence re-entry never reuses or gaps a seq that an
    earlier process already signed. (Rollbacks are attempt-attributed, not
    seq-bound — see _ship_rollback_payload — so they do not participate here.)"""
    hi = -1
    for e in _ship_journal_events(run_dir):
        d = e.get("data", {})
        seq = d.get("seq")
        if not isinstance(seq, int) or isinstance(seq, bool):
            continue
        if e.get("state") == "SHIP_ACTION_RESULT" and d.get("status") == "ok":
            hi = max(hi, seq)
    return hi


def _verify_ship_transition_chain(run_dir, run_id, anchored, anchored_rb):
    """DF-R8-01: verify the ORDERED chain of SIGNED ship transitions.

    FORWARD COMPLETIONS (SHIP_ACTION_RESULT `ok`) each bind a monotonic `seq` into
    their signed token. Walking the journal IN ORDER, these completion seqs MUST be
    contiguous and strictly increasing from 0 (0,1,...,N-1), each token recomputed
    WITH its journaled seq and anchored. This catches, for completions:
      * REPLAY — a genuine completion copied back in after its rollback repeats an
        already-seen seq (the applied-set reducer keys by action NAME, so the
        replay would otherwise silently re-add a rolled-back action with a single
        real anchored token the per-attempt duplicate guard cannot see);
      * REORDER — two completions swapped → seqs out of order;
      * INTERIOR DELETION — a dropped completion leaves a seq gap;
      * SEQ REWRITE — an edited seq yields a token that was never anchored.

    ROLLBACKS (SHIP_ROLLED_BACK) are NOT seq-bound; their tokens are attributed by
    attempt_id (see _ship_rollback_payload) and their ORDERING is enforced here by
    running-applied-set MEMBERSHIP: replaying the journal in order, a
    SHIP_ROLLED_BACK is valid only when its action is CURRENTLY applied. A rollback
    moved before the completion it removes (or planted for a never-applied action)
    fails membership → refused. Deleted rollbacks are caught by the chain→journal
    orphan check in _authenticate_ship_actions. Fail-closed. Returns (ok, reason)."""
    intents_by_attempt = {}
    for e in _ship_journal_events(run_dir):
        if e.get("state") == "SHIP_ACTION_INTENT":
            d = e.get("data", {})
            if d.get("attempt_id") is not None:
                intents_by_attempt[d.get("attempt_id")] = d
    expected = 0            # next completion seq required (contiguous from 0)
    applied_now = set()     # running applied set, in journal order
    saw_completion = False
    for e in _ship_journal_events(run_dir):
        st = e.get("state")
        d = e.get("data", {})
        if st == "SHIP_ACTION_RESULT" and d.get("status") == "ok":
            saw_completion = True
            seq = d.get("seq")
            label = f"completion of {d.get('action')!r}"
            if not isinstance(seq, int) or isinstance(seq, bool):
                return (False, f"signed ship transition ({label}) is missing its monotonic "
                        "`seq` (a pre-chain legacy or a stripped transition) — refusing "
                        "(fail-closed)")
            intent = intents_by_attempt.get(d.get("attempt_id"), {})
            token = sha256_str(_ship_action_commit_payload(
                run_id, d.get("action"), d.get("idempotency_key"),
                intent.get("toolchain"), intent.get("reversible"),
                intent.get("approval_ref"), attempt_id=d.get("attempt_id"),
                seq=seq))
            if token not in anchored:
                return (False, f"signed ship transition ({label}, seq {seq}) is not anchored in "
                        "the signed chain at its journaled sequence position (a rewritten `seq`, "
                        "a reordered, or an unsigned transition) — refusing (fail-closed)")
            if seq != expected:
                return (False, f"ship transition ({label}) is out of sequence: expected seq "
                        f"{expected}, found {seq} (a replayed, reordered, or deleted signed "
                        "completion) — refusing (fail-closed)")
            expected += 1
            applied_now.add(d.get("action"))
        elif st == "SHIP_ROLLED_BACK":
            action = d.get("action")
            # Ordering: a rollback is valid only for a CURRENTLY-applied action. A
            # rollback moved ahead of the completion it removes — or planted for an
            # action that never applied — fails here (the per-token anchor + orphan
            # checks handle authenticity/deletion separately).
            if action not in applied_now:
                return (False, f"rollback of ship action {action!r} appears before that action "
                        "is applied (a reordered or planted rollback) — refusing (fail-closed)")
            applied_now.discard(action)
    if not saw_completion:
        return (True, "no signed forward completions to order")
    return (True, f"ordered ship-transition chain verified ({expected} completions)")


def _authenticate_ship_actions(cfg, control_root, run_dir, run_id):
    """M49 DF-R3-03: before SKIPPING real actions on the strength of the ship
    journal's recovered `already_done`, authenticate each completed action against
    its own per-action signed chain entry (see _make_ship_action_committer).

    A legitimate crash-before-seal recovery authenticates (every completed action
    was anchored as it committed, before its RESULT was journaled); a planted or
    edited SHIP_ACTION_RESULT `ok` line for an action that never ran has no
    matching signed token → REFUSED. Fail-closed on any key/chain error. Returns
    (ok, reason)."""
    # DF-R9-04: before trusting ANY recovered ship state, refuse if the local
    # signed chain was TAIL-TRUNCATED (the off-box sink committed a longer chain
    # than the local file now holds). A truncation erases completion/rollback/
    # terminal tokens while the surviving prefix still passes verify_chain — so
    # this gate MUST run BEFORE the "nothing to authenticate" short-circuit below,
    # which a truncation could otherwise satisfy vacuously. No-op (best-effort)
    # when no sink is configured; fail-closed when a REQUIRED sink is unreachable.
    ok_tr, why_tr = _sup()._verify_chain_untruncated(cfg, control_root)
    if not ok_tr:
        return (False, why_tr)
    facts = _ship_completed_action_facts(run_dir)
    # DF-R7-01: a forged SHIP_ROLLED_BACK can EMPTY the applied set (so `facts` is
    # []) precisely to force a real action to re-run — so we must authenticate
    # the rollback transitions even when there are no completed actions left. Only
    # short-circuit when there is genuinely nothing to authenticate (no completed
    # actions AND no rollback events).
    rollback_events = [e for e in _ship_journal_events(run_dir)
                       if e.get("state") == "SHIP_ROLLED_BACK"]
    audit = cfg.get("_audit", {})
    try:
        key = df_audit.load_key(audit["key_path"])
    except df_audit.AuditKeyError as e:
        return (False, f"the audit signing key required to authenticate completed ship actions "
                f"could not be loaded ({e}); refusing (fail-closed)")
    chain_path = os.path.join(control_root, "audit-chain.jsonl")
    ok, why = df_audit_chain.verify_chain(chain_path, key)
    if not ok:
        return (False, f"the signed audit chain failed verification ({why}); refusing to trust "
                "the recovered already-completed ship actions (fail-closed)")
    try:
        entries = df_audit_chain.read_chain(chain_path)
    except df_audit_chain.ChainError as e:
        return (False, f"the audit chain is unreadable ({e}); refusing (fail-closed)")
    # DF-R8-05: token TYPES now live in distinct chain namespaces.
    def _anchored_under(kind):
        pre = f"{run_id}.{kind}."
        return {e.get("manifest_sha256") for e in entries
                if str(e.get("invocation", "")).startswith(pre)}
    anchored = _anchored_under("ship-action")            # completions
    anchored_rb = _anchored_under("ship-rollback")        # rollbacks
    anchored_intents = _anchored_under("ship-action-intent")  # pre-spawn intents
    # DF-R9-02 (opus review of M75): the SAME chain->journal reverse-completeness
    # for INTENTS. Reserve-before (df_ship) fsyncs the SHIP_ACTION_INTENT journal
    # line BEFORE it anchors the intent token, so a GENUINE anchored intent ALWAYS
    # has a surviving journal line — the reverse (anchored intent, no journal line)
    # happens ONLY under tampering. Deleting that line orphans a SIGNED dispatch
    # whose outcome is then invisible to BOTH journal-driven checks
    # (`unresolved_forward` AND `_dangling_signed_dispatch`, which iterate surviving
    # SHIP_ACTION_INTENT events): the action may have RUN with its completion never
    # anchored (the crash / M56b evidence-pending window) yet recovery sees nothing
    # and RE-RUNS it (a duplicate) with no SHIP_UNKNOWN_OUTCOME consent gate. This
    # runs BEFORE the short-circuit so an intent-ONLY orphan (no completion, no
    # rollback) cannot return "nothing to authenticate" vacuously. A planted decoy
    # intent recomputes to a DIFFERENT (unanchored) token and cannot mask a real
    # orphan; a legitimate crash BEFORE the intent anchored leaves the token
    # unanchored (not in anchored_intents), so this never false-refuses.
    journal_intent_tokens = set()
    for e in _ship_journal_events(run_dir):
        if e.get("state") == "SHIP_ACTION_INTENT":
            d = e.get("data", {})
            journal_intent_tokens.add(sha256_str(_ship_action_intent_payload(
                run_id, d.get("action"), d.get("idempotency_key"), d.get("toolchain"),
                d.get("reversible"), d.get("approval_ref"), attempt_id=d.get("attempt_id"))))
    orphan_intents = anchored_intents - journal_intent_tokens
    if orphan_intents:
        return (False, "an intent anchored in the signed audit chain is attributable to no "
                "surviving SHIP_ACTION_INTENT (its pre-spawn journal line was deleted to hide a "
                "signed dispatch whose action may have run — recovery would re-run it as a "
                "duplicate with no unknown-outcome gate) — refusing (fail-closed)")
    # DF-R9-01: short-circuit ONLY when there is genuinely nothing to authenticate
    # — no completed/rolled-back journal transitions AND no anchored completion/
    # rollback tokens in the signed chain. The pre-M74 short-circuit fired on empty
    # journal facts ALONE, so deleting a completed action's journal attribution
    # (SHIP_ACTION_INTENT + SHIP_ACTION_RESULT) while its genuine completion token
    # stayed anchored returned "nothing to authenticate" — and the action re-ran
    # (a duplicate). Now an orphaned anchored completion (below) is caught.
    if not facts and not rollback_events and not anchored and not anchored_rb:
        return (True, "no completed ship actions to authenticate")
    # DF-R8-01: verify the ORDERED, monotonic signed-transition sequence FIRST —
    # a genuine signed completion REPLAYED after its rollback (or any reorder /
    # deletion of a signed transition) is rejected here, before the applied set
    # is trusted, because each transition binds a `seq` that must form a
    # contiguous 0..N-1 with no gap and no duplicate.
    ok_seq, why_seq = _verify_ship_transition_chain(run_dir, run_id, anchored,
                                                    anchored_rb)
    if not ok_seq:
        return (False, why_seq)
    seen_fwd_attempts = set()
    for f in facts:
        # DF-R8-01: a forward completion attempt is single-use too (mirrors the
        # rollback replay guard). A replayed completion has a duplicate attempt.
        if f.get("attempt_id") in seen_fwd_attempts:
            return (False, f"completed ship action {f['name']!r} attempt "
                    f"{f.get('attempt_id')!r} appears more than once (a replayed completion)")
        seen_fwd_attempts.add(f.get("attempt_id"))
        token = sha256_str(_ship_action_commit_payload(
            run_id, f["name"], f["idk"], f["toolchain"], f["reversible"], f["approval_ref"],
            attempt_id=f.get("attempt_id"), seq=f.get("seq")))
        if token not in anchored:
            return (False, f"completed ship action {f['name']!r} is not individually anchored in "
                    "the signed audit chain (a planted or edited SHIP_ACTION_RESULT `ok`, a "
                    "tampered toolchain / reversibility / approval_ref, or an unsigned re-run "
                    "attempt claiming an earlier attempt's token)")
    # DF-R7-01: authenticate the ROLLBACK transitions too. A same-user writer who
    # appends a bare SHIP_ROLLED_BACK for a real applied action would make
    # recovery DROP it from `applied` and RE-RUN it (a duplicate). Every
    # SHIP_ROLLED_BACK under a signed run MUST carry its own signed rollback
    # token; a planted one has none → refuse (never silently re-run).
    seen_rb_attempts = set()
    for e in _ship_journal_events(run_dir):
        if e.get("state") != "SHIP_ROLLED_BACK":
            continue
        d = e.get("data", {})
        rb_attempt = d.get("attempt_id")
        # DF-R7-01 (mini-audit): a rollback attempt is single-use. A REPLAYED
        # SHIP_ROLLED_BACK (same real, signed attempt_id appended again — e.g.
        # AFTER the action was re-applied under a new forward attempt) would
        # otherwise pass the token check yet wrongly remove the re-applied
        # action from `applied`, forcing a duplicate re-run. Refuse a duplicate.
        if rb_attempt in seen_rb_attempts:
            return (False, f"rollback of ship action {d.get('action')!r} is REPLAYED "
                    f"(attempt {rb_attempt!r} appears more than once) — refusing")
        seen_rb_attempts.add(rb_attempt)
        rb_token = sha256_str(_ship_rollback_payload(
            run_id, d.get("action"), rb_attempt))
        if rb_token not in anchored_rb:
            return (False, f"rollback of ship action {d.get('action')!r} is not anchored in the "
                    "signed audit chain (a planted SHIP_ROLLED_BACK trying to force a "
                    "possibly-applied action to re-run) — refusing")
    # DF-R8-01 (opus review F1): the checks above are JOURNAL-driven — they verify
    # the SHIP_ROLLED_BACK lines PRESENT, but not that every SIGNED rollback still
    # HAS its journal lines. A same-user writer who DELETES a rollback's journal
    # lines (SHIP_ROLLBACK_INTENT + SHIP_ROLLED_BACK) leaves the rolled-back
    # action's genuine completion (seq 0) unpopped and the completion seqs still
    # contiguous — re-adding a rolled-back action to `applied` with its effect
    # actually GONE. Close the loop the other way: every rollback token anchored in
    # the signed chain MUST be ATTRIBUTABLE to a surviving SHIP_ROLLBACK_INTENT
    # (the intent is journaled+fsynced BEFORE the rollback runs, so a genuine
    # anchored rollback ALWAYS has one — a legit crash-window or reconcile keeps
    # the intent; only tampering removes it). Because the rollback token is NOT
    # seq-bound, it recomputes exactly from the intent's (action, attempt_id), so
    # this attribution is precise: a planted decoy intent recomputes to a DIFFERENT
    # (unanchored) token and cannot cover a real orphan. A deleted rollback leaves
    # an anchored token no surviving intent maps to → refuse.
    intent_rb_tokens = set()
    for e in _ship_journal_events(run_dir):
        if e.get("state") != "SHIP_ROLLBACK_INTENT":
            continue
        d = e.get("data", {})
        intent_rb_tokens.add(sha256_str(_ship_rollback_payload(
            run_id, d.get("action"), d.get("attempt_id"))))
    orphan_rb = anchored_rb - intent_rb_tokens
    if orphan_rb:
        return (False, "a rollback anchored in the signed audit chain is attributable to no "
                "surviving SHIP_ROLLBACK_INTENT (its rollback journal lines were deleted to "
                "re-add a rolled-back action to the applied set) — refusing (fail-closed)")
    # DF-R9-01: the SAME chain→journal reverse-completeness check for COMPLETIONS.
    # Every anchored `ship-action` completion token must be recomputable from a
    # SURVIVING SHIP_ACTION_RESULT `ok` (paired with its intent for the sealed
    # toolchain/reversible/approval_ref fields). Deleting a completed action's
    # journal lines (to make recovery re-run it — a duplicate) leaves an anchored
    # completion token that no surviving ok-result maps to → refuse. A LEGITIMATE
    # crash AFTER the completion anchor but BEFORE its RESULT is journaled leaves
    # the SHIP_ACTION_INTENT UNRESOLVED, which halts the ship at SHIP_UNKNOWN_OUTCOME
    # BEFORE this authentication runs — so this check never false-refuses that
    # window; only a deletion of BOTH the intent and the result reaches here.
    intents_by_attempt = {}
    for e in _ship_journal_events(run_dir):
        if e.get("state") == "SHIP_ACTION_INTENT":
            d = e.get("data", {})
            if d.get("attempt_id") is not None:
                intents_by_attempt[d.get("attempt_id")] = d
    journal_completion_tokens = set()
    for e in _ship_journal_events(run_dir):
        d = e.get("data", {})
        if e.get("state") == "SHIP_ACTION_RESULT" and d.get("status") == "ok":
            intent = intents_by_attempt.get(d.get("attempt_id"), {})
            journal_completion_tokens.add(sha256_str(_ship_action_commit_payload(
                run_id, d.get("action"), d.get("idempotency_key"),
                intent.get("toolchain"), intent.get("reversible"), intent.get("approval_ref"),
                attempt_id=d.get("attempt_id"), seq=d.get("seq"))))
    # DF-R9-01 (opus review F1): an anchored completion whose attempt was
    # operator-RECONCILED is NOT a deletion-orphan. A genuine crash AFTER the
    # completion anchor but BEFORE its RESULT leaves the intent UNRESOLVED; the
    # operator is told to run `--decision reconcile`/`abort`, which resolves the
    # intent to `reconciled_unknown` (accepting a possible duplicate re-run) and
    # then reaches this authenticator. The anchored completion has no `ok` RESULT
    # to recompute it, so — WITHOUT this — it would be a false orphan and PERMANENTLY
    # brick the run. The `reconciled_unknown` RESULT carries no seq, so recompute the
    # completion token from the SURVIVING intent across the seq range to cover it.
    # (An ATTACKER who PLANTS a `reconciled_unknown` to force a re-run is a DISTINCT
    # class — the non-ok resolution must itself be authenticated; DF-R9-02.)
    reconciled_attempts = {d.get("attempt_id") for e in _ship_journal_events(run_dir)
                           for d in [e.get("data", {})]
                           if e.get("state") == "SHIP_ACTION_RESULT"
                           and d.get("status") == "reconciled_unknown"}
    for _att in reconciled_attempts:
        _intent = intents_by_attempt.get(_att)
        if not _intent:
            continue
        for _seq in range(len(anchored) + 2):
            journal_completion_tokens.add(sha256_str(_ship_action_commit_payload(
                run_id, _intent.get("action"), _intent.get("idempotency_key"),
                _intent.get("toolchain"), _intent.get("reversible"), _intent.get("approval_ref"),
                attempt_id=_att, seq=_seq)))
    orphan_completions = anchored - journal_completion_tokens
    if orphan_completions:
        return (False, "a completion anchored in the signed audit chain has no surviving "
                "SHIP_ACTION_RESULT `ok` (its journal attribution was deleted to force a "
                "duplicate re-run of an already-completed action) — refusing (fail-closed)")
    return (True, "all completed ship actions + rollbacks authenticated against the signed chain")


def _terminal_anchor_pending_sha(run_dir):
    """R5 DF-R5-02: the record_sha256 of the LATEST journaled
    SHIP_TERMINAL_ANCHOR_PENDING (a terminal ship record sealed while the signer
    was down), or None. The marker alone authorizes NOTHING — re-anchoring also
    requires _failed_ship_record_bound to hold."""
    sha = None
    for e in _ship_journal_events(run_dir):
        if e.get("state") == "SHIP_TERMINAL_ANCHOR_PENDING":
            sha = e.get("data", {}).get("record_sha256")
    return sha


def _is_no_action_terminal(run_dir, run_id, prior, cfg=None, control_root=None):
    """DF-R7-05: True iff `prior` is a SHIP_FAILED terminal with NO successfully
    APPLIED action — a materialization failure (failed_action:null, nothing
    spawned) or a reconcile-abort (an action's effect is UNKNOWN, never a
    completed `ok`). Requires:
      * the record claims NO `ok` action, AND
      * the journal has NO SHIP_ACTION_RESULT with status 'ok' (no completed
        per-action evidence).
    Because NOTHING was successfully applied, re-sealing this as a no-action
    SHIP_FAILED is inert — it cannot launder to SHIPPED, cannot skip an applied
    effect, and no future ship reads this terminal for `already_done` (that comes
    from the signed journal tokens). A record with ANY completed action fails
    this and must go through the full _failed_ship_record_bound check."""
    if prior.get("outcome") != df_ship.SHIP_FAILED:
        return False
    if any(isinstance(a, dict) and a.get("status") == "ok"
           for a in (prior.get("actions") or [])):
        return False
    for e in _ship_journal_events(run_dir):
        if (e.get("state") == "SHIP_ACTION_RESULT"
                and e.get("data", {}).get("status") == "ok"):
            return False
    # DF-R7-05 (opus review F1): the journal is same-user writable, so re-root
    # the "nothing shipped" claim on the SIGNED CHAIN — the real M56b trust
    # boundary. If ANY signature-valid COMPLETION or ROLLBACK ship token exists,
    # the run DID apply (and maybe undo) something; it is NOT a no-action terminal
    # and must go through full evidence binding (never the reseal shortcut), even
    # if the journal was emptied to hide it. Fail-closed on any chain read/verify
    # error.
    # DF-R8-05: INTENT tokens now live in their OWN namespace (`ship-action-intent`)
    # and are DELIBERATELY not disqualifying — every dispatched action signs a
    # pre-spawn intent, so matching intents here (as the pre-split code did with a
    # shared `ship-action.` prefix) wrongly treated a genuine materialize-failure /
    # reconcile-abort as "shipped" and refused its governed reseal. Only a
    # COMPLETION (`ship-action.`) or a ROLLBACK (`ship-rollback.`) proves something
    # ran.
    if cfg is not None and bool(cfg.get("_audit", {}).get("signing")):
        try:
            key = df_audit.load_key(cfg["_audit"]["key_path"])
            chain_path = os.path.join(control_root, "audit-chain.jsonl")
            ok, _why = df_audit_chain.verify_chain(chain_path, key)
            if not ok:
                return False
            completion_pre = f"{run_id}.ship-action."
            rollback_pre = f"{run_id}.ship-rollback."
            for entry in df_audit_chain.read_chain(chain_path):
                inv = str(entry.get("invocation", ""))
                if inv.startswith((completion_pre, rollback_pre)):
                    return False
        except (df_audit.AuditKeyError, df_audit_chain.ChainError, OSError, KeyError):
            return False
    return True


def _failed_ship_record_bound(cfg, control_root, run_dir, run_id, prior,
                              artifact_object_id=None):
    """R5 DF-R5-02: bind an UNANCHORED SHIP_FAILED record to the run's signed +
    journaled evidence before it may be re-anchored (the signer-outage terminal
    recovery). The record file AND the pending marker are same-user writable, so
    neither is trusted alone; what must hold:

      * every claimed `ok` action authenticates against its own signed
        per-action completion token, and the claimed ok-SET equals the
        token-set EXACTLY (a laundered/edited action list is refused);
      * the claimed failed_action has a journaled SHIP_ACTION_INTENT and a
        journaled NON-ok SHIP_ACTION_RESULT (failed/timed_out) whose exit
        matches the record — and has NO ok-token (it really failed);
      * rollback records are carried journal-honestly (they are not signed;
        the terminal is FAILED either way — documented detection-grade
        residual, they never gate a skip or a SHIPPED).

    Returns (ok, reason)."""
    if prior.get("outcome") != df_ship.SHIP_FAILED:
        return (False, "terminal-anchor recovery only applies to SHIP_FAILED records")
    # Opus-review V-A4 hardening: the record's artifact id must be the
    # AUTHENTICATED one from the sealed manifest (_ship_eligible), so re-anchoring
    # can't sign a forged oid into the chain. Remaining unbound terminal metadata
    # (rollbacks/ts/durations) is inert + detection-grade by design: the outcome
    # stays SHIP_FAILED and can never launder to SHIPPED.
    if (artifact_object_id is not None
            and prior.get("ship_workspace_object_id") != artifact_object_id):
        return (False, "the record's ship_workspace_object_id does not match the sealed "
                "manifest's artifact_object_id (a forged artifact id)")
    facts = _ship_completed_action_facts(run_dir)
    if facts:
        ok_j, why_j = _authenticate_ship_actions(cfg, control_root, run_dir, run_id)
        if not ok_j:
            return (False, why_j)
    anchored_ok = {f["name"] for f in facts}
    claimed_ok = {a.get("name") for a in (prior.get("actions") or [])
                  if isinstance(a, dict) and a.get("status") == "ok"}
    if claimed_ok != anchored_ok:
        return (False, "the SHIP_FAILED record's claimed ok actions "
                f"{sorted(x for x in claimed_ok if x is not None)} do not match the signed "
                f"per-action evidence {sorted(anchored_ok)}")
    failed = prior.get("failed_action")
    # DF-R7-05 (opus review F2): a planted non-string failed_action (dict/list)
    # is unhashable and would crash the `failed in anchored_ok` test with an
    # uncaught TypeError — refuse it as a clean fail-closed, never a traceback.
    if not (failed is None or isinstance(failed, str)):
        return (False, "the record's failed_action is not a string/null (a tampered record)")
    # Opus-review HIGH: a record naming NO failed action binds nothing checkable
    # beyond the ok-set — an EMPTY one (the materialize-failure/reconcile-abort
    # shape, and equally a pure forgery) binds NOTHING at all, and a failed:None
    # record whose ok-set covers every token would sign away a SHIPPABLE run as
    # FAILED. Neither is distinguishable from a plant via the writable journal,
    # so re-anchoring would be a signing oracle + ship suppression. Fail-closed:
    # recovery requires a NAMED failed action with journal-bound failure
    # evidence. (The only legit victims — a materialize-failure or abort sealed
    # during a signer outage — ran NOTHING new; they stay the pre-M56b exit-2
    # refusal, recoverable by removing the unauthenticated record and
    # re-shipping.)
    if failed is None:
        return (False, "the record names no failed action, so it binds no failure "
                "evidence — indistinguishable from a forgery (fail-closed; if this was a "
                "genuine materialize-failure/abort sealed during a signer outage, nothing "
                "ran: remove the unauthenticated record and re-ship)")
    if failed is not None:
        if failed in anchored_ok:
            return (False, f"the record claims {failed!r} failed but a signed ok-token "
                    "exists for it")
        intents, results = {}, {}
        for e in _ship_journal_events(run_dir):
            d = e.get("data", {})
            if e.get("state") == "SHIP_ACTION_INTENT" and d.get("action") == failed:
                intents[d.get("idempotency_key")] = d
            elif e.get("state") == "SHIP_ACTION_RESULT" and d.get("action") == failed:
                results[d.get("idempotency_key")] = d
        failed_results = [r for k, r in results.items()
                          if k in intents and r.get("status") in ("failed", "timed_out")]
        if not failed_results:
            return (False, f"the record claims {failed!r} failed but the journal has no "
                    "matching intent + failed/timed_out result for it")
        rec_failed = [a for a in (prior.get("actions") or [])
                      if isinstance(a, dict) and a.get("name") == failed
                      and a.get("status") in ("failed", "timed_out")]
        if not rec_failed or all(r.get("exit") != rec_failed[0].get("exit")
                                 for r in failed_results):
            return (False, f"the record's failure evidence for {failed!r} does not match "
                    "the journaled result")
    return (True, "SHIP_FAILED record bound to the signed + journaled evidence")


def _ship_evidence_pending_entries(run_dir):
    """R5 DF-R5-02: the journal's UNREPAIRED evidence-pending completions — for each
    idempotency_key whose LATEST SHIP_ACTION_RESULT has status 'evidence_pending'
    (no later 'ok' appended by a completed repair), the pair (intent_data,
    result_data). Journal-driven on purpose: the recovery NEVER reads the same-user-
    writable ship_result.json blob (DF-R5-01 discipline)."""
    intents, latest = {}, {}
    for e in _ship_journal_events(run_dir):
        d = e.get("data", {})
        idk = d.get("idempotency_key")
        if idk is None:
            continue
        if e.get("state") == "SHIP_ACTION_INTENT":
            intents[idk] = d
        elif e.get("state") == "SHIP_ACTION_RESULT":
            latest[idk] = d
    return [(intents.get(idk), r) for idk, r in latest.items()
            if r.get("status") == "evidence_pending"]


def _repair_ship_evidence(cfg, control_root, run_dir, run_id, ship_journal,
                          decision="continue"):
    """R5 DF-R5-02: the AUTHENTICATED evidence-only repair, run on every ship
    re-entry BEFORE `already_done` is derived (idempotent no-op when nothing is
    pending). For each unrepaired evidence-pending completion:

      1. AUTHENTICATE: the signed chain must verify AND contain the action's
         SIGNED INTENT token over exactly the journaled facts (action/idk/
         toolchain/reversible/approval_ref). The intent was signed BEFORE the
         spawn, while the signer was up — a planted intent + evidence_pending
         journal pair has no matching signed token → fail-closed refusal, never
         a token minted for an action that cannot be proven to have been
         legitimately dispatched.
      2. RE-SIGN: anchor the completion token over those SAME intent-bound facts
         (the action is chain-authenticated-ok by construction: only a
         SUCCEEDED action ever journals evidence_pending). If the signer is
         still down → still pending, retry again later (never a brick).
      3. RECORD: append the normal SHIP_ACTION_RESULT `ok` (so `already_done`
         skips the action and _authenticate_ship_actions finds its token) plus
         an explicit SHIP_EVIDENCE_RESIGNED naming the outage window — the
         journal facts sat unauthenticated between the outage and this repair;
         binding-by-intent-token narrows that to the completion CLAIM only,
         and the resign event keeps the window visible to an auditor
         (detection-grade, like the rest of the same-user threat model).

    CONSENT (the confused-deputy guard): the SUCCESS claim itself — "this
    dispatched action exited 0" — sat in the same-user-writable journal during
    the signer outage and CANNOT be authenticated after the fact (the intent
    token proves WHAT was dispatched with WHICH facts, not that it succeeded; a
    journal writer could flip a real `failed` line to `evidence_pending` and let
    the operator's key-holding retry mint the ok-token FOR them). So the repair
    only runs under an EXPLICIT `--decision repair-evidence` — the operator is
    told exactly which action's success claim is being trusted and is expected
    to verify its real-world state first — mirroring the existing
    `--decision reconcile` consent for unknown outcomes. A plain `continue`
    re-entry reports and exits SHIP_EVIDENCE_PENDING, repairing nothing.

    The real-world action is NEVER re-run here. Returns (status, detail):
      "clean"    nothing was pending
      "consent"  pending exists but the operator has not consented
                 (caller exits SHIP_EVIDENCE_PENDING with instructions)
      "repaired" every pending completion re-signed
      "pending"  signer still unavailable (caller exits SHIP_EVIDENCE_PENDING)
      "refused"  authentication failed (caller exits fail-closed 2)."""
    pending = _ship_evidence_pending_entries(run_dir)
    if not pending:
        return ("clean", "")
    # KEY-FREE consistency checks FIRST — before the consent prompt, so the
    # prompt can never be misdirected (opus-review MEDIUM: the result line's
    # `action` is attacker-writable while the mint re-signs the INTENT's facts;
    # a renamed result line would make a diligent operator verify the WRONG
    # action's real-world state). The result line must agree with its intent on
    # the action name AND the idempotency_key must recompute from those exact
    # (run_id, action, index) facts — the same binding the intent token signs.
    all_results = {}
    for e in _ship_journal_events(run_dir):
        if e.get("state") == "SHIP_ACTION_RESULT":
            d = e.get("data", {})
            all_results.setdefault(d.get("idempotency_key"), []).append(d)
    for intent, result in pending:
        name = result.get("action")
        idk = result.get("idempotency_key")
        if intent is None:
            return ("refused", f"evidence-pending ship action {name!r} has no journaled "
                    "SHIP_ACTION_INTENT (a planted result line)")
        if intent.get("action") != name or intent.get("action") is None:
            return ("refused", f"evidence-pending result names action {name!r} but its "
                    f"intent (same idempotency_key) names {intent.get('action')!r} — a "
                    "tampered journal")
        if idk != df_ship.idempotency_key(run_id, intent.get("action"),
                                          intent.get("index")):
            return ("refused", f"evidence-pending ship action {name!r} has an "
                    "idempotency_key that does not recompute from its own "
                    "run/action/index facts — a tampered journal")
        # Defense in depth: an evidence_pending line only ever follows a SUCCESS
        # in run_actions; ANY failed/timed_out result for the same
        # idempotency_key (an attacker APPENDING evidence_pending after a real
        # failure) refuses.
        if any(r.get("status") in ("failed", "timed_out") for r in all_results.get(idk, [])):
            return ("refused", f"evidence-pending ship action {name!r} also has a journaled "
                    "failed/timed_out result — a success claim cannot coexist with a failure "
                    "(tampered journal)")
    if decision != "repair-evidence":
        # Consent prompt names come from the INTENT (now proven consistent with
        # the result line + idk above), never the raw result line.
        names = sorted({i.get("action") for i, _r in pending if i and i.get("action")})
        return ("consent", f"action(s) {names} completed but their evidence is unsigned")
    audit = cfg.get("_audit", {})
    try:
        key = df_audit.load_key(audit["key_path"])
    except df_audit.AuditKeyError as e:
        return ("pending", f"the audit signing key is still unavailable ({e}); the "
                "evidence-pending ship action(s) remain unrepaired")
    chain_path = os.path.join(control_root, "audit-chain.jsonl")
    ok, why = df_audit_chain.verify_chain(chain_path, key)
    if not ok:
        return ("refused", f"the signed audit chain failed verification ({why})")
    try:
        entries = df_audit_chain.read_chain(chain_path)
    except df_audit_chain.ChainError as e:
        return ("refused", f"the audit chain is unreadable ({e})")
    # DF-R8-05: the intent token now lives in its OWN chain namespace.
    prefix = f"{run_id}.ship-action-intent."
    anchored = {e.get("manifest_sha256") for e in entries
                if str(e.get("invocation", "")).startswith(prefix)}
    # DF-R8-01: the re-signed completion continues the monotonic transition chain
    # at max+1 (never reusing/gapping a seq an earlier process already signed).
    next_seq = _max_ship_seq(run_dir) + 1
    for intent, result in pending:
        name = intent.get("action")
        idk = result.get("idempotency_key")
        # DF-R7-01: bind the intent's attempt_id into both recomputed tokens, so
        # the re-signed completion authenticates EXACTLY this attempt.
        att = intent.get("attempt_id")
        intent_token = sha256_str(_ship_action_intent_payload(
            run_id, intent.get("action"), idk, intent.get("toolchain"),
            intent.get("reversible"), intent.get("approval_ref"), attempt_id=att))
        if intent_token not in anchored:
            return ("refused", f"evidence-pending ship action {name!r} has no SIGNED intent "
                    "token in the audit chain — its journaled facts cannot be authenticated "
                    "(a planted intent/evidence_pending pair, or a tampered intent)")
        done_payload = _ship_action_commit_payload(
            run_id, intent.get("action"), idk, intent.get("toolchain"),
            intent.get("reversible"), intent.get("approval_ref"), attempt_id=att,
            seq=next_seq)
        if _sup()._anchor_ship_local(cfg, control_root, run_id, done_payload,
                              "ship-action") != "anchored":
            return ("pending", f"the completion token for ship action {name!r} still could "
                    "not be signed; the evidence stays pending (retry later)")
        ship_journal.write("SHIP_ACTION_RESULT", action=intent.get("action"),
                           index=intent.get("index"), idempotency_key=idk,
                           attempt_id=att, exit=result.get("exit"), timed_out=False,
                           status="ok", duration_s=result.get("duration_s"),
                           seq=next_seq)
        next_seq += 1
        ship_journal.write("SHIP_EVIDENCE_RESIGNED", action=intent.get("action"),
                           idempotency_key=idk,
                           note="completion token re-signed on retry from the SIGNED "
                                "intent-token-bound facts; the real-world action was NOT re-run")
    return ("repaired", "")


def _pending_ship_authenticated(cfg, control_root, run_dir, run_id, prior, prior_text,
                                configured_action_names):
    """DF-R4-03 (+ R4 re-audit): authenticate a SHIPPED_AUDIT_PENDING record on
    re-entry. Unlike a FINAL SHIPPED (which must be anchored — see
    _authenticate_ship_chain), a pending record may LEGITIMATELY be unanchored: its
    own local signed anchor can be the very evidence still pending (the DF-R4-03
    anchor-failure pending). So accept EITHER:
      (a) the pending record IS anchored in the signed chain (the M49 sink-failure
          pending, whose local anchor succeeded), OR
      (b) it is not anchored, but it is BOUND to the signed per-action evidence of a
          run in which EVERY configured ship action SUCCEEDED.

    Branch (b) MUST bind the record to the chain — the record file is same-user
    writable, so authenticating on the mere existence of SOME anchored token would
    let a control-root writer LAUNDER a terminal SHIP_FAILED into SHIPPED by flipping
    the on-disk outcome (the ONE action that ran before the failure has a real
    ok-token). A genuine anchor/push-failure pending only arises AFTER run_actions
    returned SHIPPED — i.e. after ALL actions succeeded — so branch (b) requires:
      * every journal `ok` completion authenticates against its signed per-action
        token (_authenticate_ship_actions), AND
      * the set of actions with an anchored ok-token EXACTLY equals the set of ALL
        configured ship actions (a SHIP_FAILED run has NO ok-token for the failed
        action → refused: a pending never supersedes a non-complete/terminal run),
        AND
      * the record's OWN claimed `ok` action set equals that same anchored set (bind
        the attacker-writable record's action list to the signed evidence).
    A plant (unanchored record with no/partial anchored completions, or a laundered
    terminal) satisfies neither branch and is REFUSED. Returns (ok, reason)."""
    ok_c, _why_c = _authenticate_ship_chain(cfg, control_root, run_id,
                                            sha256_str(prior_text), "ship")
    if ok_c:
        return (True, "pending ship record anchored in the signed chain")
    # Branch (b): bind the UNANCHORED record to complete signed per-action evidence.
    facts = _ship_completed_action_facts(run_dir)
    if not facts:
        return (False, "unanchored SHIPPED_AUDIT_PENDING record with no anchored completed "
                "actions (a planted terminal ship state)")
    ok_j, why_j = _authenticate_ship_actions(cfg, control_root, run_dir, run_id)
    if not ok_j:
        return (False, why_j)
    anchored_ok = {f["name"] for f in facts}
    configured = {n for n in configured_action_names if n is not None}
    if anchored_ok != configured:
        # An ok-token is missing for some configured action → not all actions
        # succeeded (e.g. a laundered SHIP_FAILED, whose failed action never got a
        # token). A legitimate pending has an anchored ok-token for EVERY action.
        return (False, "unanchored SHIPPED_AUDIT_PENDING record does not show every configured "
                f"ship action succeeded (anchored ok-tokens {sorted(anchored_ok)} != configured "
                f"{sorted(configured)}) — refusing to supersede a non-complete run (a laundered "
                "SHIP_FAILED / partial ship)")
    claimed_ok = {a.get("name") for a in (prior.get("actions") or [])
                  if isinstance(a, dict) and a.get("status") == "ok"}
    if claimed_ok != anchored_ok:
        return (False, "the SHIPPED_AUDIT_PENDING record's claimed ok actions "
                f"{sorted(x for x in claimed_ok if x is not None)} do not match the signed "
                f"per-action evidence {sorted(anchored_ok)} (the record is not bound to the chain)")
    return (True, "unanchored pending ship record bound to complete signed per-action evidence")


def _ship_record_bytes(result, artifact_object_id, ship_actions, redactor):
    """Build the canonical ship record dict + its redacted on-disk/pushed bytes. The
    record is content-identical to the pre-M53 seal; returning the bytes WITHOUT
    writing them is what lets the SHIPPED seal push off-box FIRST and only then write
    the authoritative record (DF-R4-04 push-first)."""
    record = {
        "ship_version": "1",
        "outcome": result["outcome"],
        "actions": result.get("actions", []),
        "rollbacks": result.get("rollbacks", []),
        "rollback_failed": bool(result.get("rollback_failed")),
        "pending_action": result.get("pending_action"),
        "failed_action": result.get("failed_action"),
        "ship_workspace_object_id": artifact_object_id,
        "ts": _now(),
    }
    # DF-R4-08: the toolchain identity is the PRE-exec resolution captured by
    # df_ship.run_actions AS each action spawned (resolved against the action's
    # cwd, hashed before exec) — NOT a post-run re-read at seal time. Only the
    # no-run SHIP_FAILED paths (materialize-failure, reconcile-abort) carry no
    # per-action toolchain in `result`; there fall back to the seal-time resolver
    # (nothing ran, so it is purely informational).
    if "toolchain" in result:
        record["toolchain"] = result["toolchain"]
        if result.get("rollback_toolchain"):
            record["rollback_toolchain"] = result["rollback_toolchain"]
    elif ship_actions is not None:
        record["toolchain"] = _ship_toolchain_identity(ship_actions)
    obj = redactor.redact_obj(record) if redactor is not None else record
    return record, canonical_json(obj)


def _journal_ship_seal(ship_journal, result):
    ship_journal.write(result["outcome"],
                       actions=[a.get("name") for a in result.get("actions", [])],
                       rollback_failed=bool(result.get("rollback_failed")),
                       pending_action=result.get("pending_action"),
                       failed_action=result.get("failed_action"))


def _seal_ship_result(cfg, control_root, run_dir, run_id, ship_journal, result,
                      artifact_object_id, redactor, *, ship_actions=None,
                      push_offbox=True):
    """Write the SEPARATE, immutable ship record (ship_result.json), journal the
    terminal ship event, push it off-box, and anchor it into the signed chain. NEVER
    rewrites the manifest (qualified stays qualified). Returns
    `(record, sink_status, local_anchor_status)`.

    DF-R4-04/03 push-FIRST for an authoritative SHIPPED: a SHIPPED record must never
    touch disk (or the signed chain) before BOTH its REQUIRED off-box receipt AND
    (under signing) its local signed anchor exist. So for a SHIPPED outcome the FINAL
    bytes are pushed off-box, then anchored, and ONLY then is ship_result.json
    written — and if the required off-box receipt or the signed anchor is missing,
    NO authoritative SHIPPED is written at all (the returned statuses tell the caller
    to seal SHIPPED_AUDIT_PENDING instead). This closes the crash window in which a
    signature-valid local SHIPPED could exist with no successful sink.

    All OTHER outcomes (SHIP_FAILED / SHIP_APPROVAL_PENDING / the
    SHIPPED_AUDIT_PENDING re-seal) are not a clean exit-0 ship, so ordering is not
    security-critical: they are written, journaled, anchored, and (unless
    push_offbox=False) pushed best-effort. `push_offbox=False` suppresses the push
    (the SHIPPED_AUDIT_PENDING re-seal whose push already failed, or a caller that
    already pushed fail-closed).

    (The journal that feeds `already_done` is authenticated per-action, not by a
    seal-time journal digest — see _make_ship_action_committer.)"""
    record, text = _ship_record_bytes(result, artifact_object_id, ship_actions, redactor)
    result_path = os.path.join(run_dir, SHIP_RESULT_FILE)

    if result["outcome"] == df_ship.SHIPPED and push_offbox:
        signing = bool(cfg.get("_audit", {}).get("signing"))
        # 1) push the FINAL SHIPPED bytes off-box FIRST.
        sink_status = _push_ship_offbox(cfg, run_dir, run_id, text, "ship")
        if _sink_required(cfg) and sink_status != "ok":
            # No server-authentic off-box receipt → do NOT write/anchor an
            # authoritative local SHIPPED. Caller seals SHIPPED_AUDIT_PENDING.
            return record, sink_status, "unanchored_no_offbox"
        # 2) anchor those EXACT bytes into the local signed chain.
        anchor_status = _sup()._anchor_ship_local(cfg, control_root, run_id, text, "ship")
        if signing and anchor_status != "anchored":
            # No local signed anchor → do NOT write an authoritative local SHIPPED.
            return record, sink_status, anchor_status
        # 3) BOTH pieces of evidence exist → write the authoritative SHIPPED record.
        atomic_write(result_path, text)
        _journal_ship_seal(ship_journal, result)
        return record, sink_status, anchor_status

    # Non-authoritative seals: write, journal, anchor, push (order not critical).
    atomic_write(result_path, text)
    _journal_ship_seal(ship_journal, result)
    local_anchor_status = _sup()._anchor_ship_local(cfg, control_root, run_id, text, "ship")
    # R5 DF-R5-02: a TERMINAL record sealed while the signer is down would
    # otherwise brick re-entry forever (the record can never authenticate against
    # the chain). Journal the anchor failure as a first-class marker binding THIS
    # record's exact bytes; re-entry may then re-anchor the record — but ONLY
    # after re-verifying its evidence fields against the signed per-action
    # facts (_failed_ship_record_bound), so a planted terminal + planted marker
    # is still refused, never laundered into the signed chain.
    if (bool(cfg.get("_audit", {}).get("signing"))
            and local_anchor_status != "anchored"):
        ship_journal.write("SHIP_TERMINAL_ANCHOR_PENDING", outcome=result["outcome"],
                           record_sha256=sha256_str(text))
    sink_status = _push_ship_offbox(cfg, run_dir, run_id, text, "ship") if push_offbox else "skip"
    return record, sink_status, local_anchor_status


def _reconstruct_authenticated_ship_record(prior, artifact_object_id, facts, redactor):
    """R5 DF-R5-01: build the authoritative SHIPPED record + its bytes from ONLY
    AUTHENTICATED facts, never trusting the same-user-writable pending record's
    evidence fields.

    - `ship_workspace_object_id` = `artifact_object_id`, the id from the sealed
      (HMAC/hash-bound) manifest via _ship_eligible — NOT the pending record's
      (a forged `ffff…` object id in the pending file is discarded).
    - Each shipped action is `status:"ok"`, `exit:0` BY DEFINITION (it is chain-
      authenticated-ok) — a forged `exit:999` is discarded.
    - Each action's `toolchain` is the CHAIN-BOUND toolchain from `facts` (the
      signed per-action token binds it) — a forged `/evil` tool path is discarded.
    - Only cosmetic, non-evidence fields (reversible/approval_ref/duration_s) are
      carried from the prior record by action name, and never affect the signed
      claim about what shipped or what ran.

    `facts` is the chain-authenticated (name, idk, toolchain) list, in order."""
    actions, toolchain = [], []
    for f in facts:
        # EVERY per-action evidence field comes from the chain-authenticated token
        # (name/toolchain/reversible/approval_ref) or is true by definition
        # (status:ok, exit:0). NOTHING is taken from the writable pending record.
        actions.append({"name": f["name"], "reversible": bool(f["reversible"]),
                        "status": "ok", "exit": 0,
                        "approval_ref": f["approval_ref"], "duration_s": None})
        if f["toolchain"] is not None:
            toolchain.append(f["toolchain"])
    record = {"ship_version": "1", "outcome": df_ship.SHIPPED, "actions": actions,
              "rollbacks": [], "rollback_failed": False, "pending_action": None,
              "failed_action": None, "ship_workspace_object_id": artifact_object_id,
              "toolchain": toolchain, "ts": _now()}
    obj = redactor.redact_obj(record) if redactor is not None else record
    return record, canonical_json(obj)


def _ship_audit_retry(cfg, control_root, run_dir, run_id, ship_journal, prior_text,
                      redactor, artifact_object_id):
    """DF-R3-02 / DF-R4-03 / DF-R4-04 idempotent audit-only retry. The prior seal is
    SHIPPED_AUDIT_PENDING (or a SHIPPED whose REQUIRED off-box receipt is
    absent/unbound/non-authentic): the real-world actions ALREADY ran and are NEVER
    re-run. Re-attempt ONLY the evidence commit for the EXISTING sealed record.
    Finalize SHIPPED (exit 0) ONLY when BOTH the server-authentic off-box receipt
    AND (under signing) the local signed anchor land; otherwise stay
    SHIPPED_AUDIT_PENDING (exit 12).

    Push + anchor FIRST, flip on-disk LAST: the authoritative SHIPPED record is
    written only after both pieces of evidence exist, so a still-failing sink OR an
    unloadable audit key never leaves a SHIPPED record without its bound receipt +
    signed anchor."""
    try:
        prior = json.loads(prior_text)
    except json.JSONDecodeError as e:
        sys.stderr.write(f"dark-factory: ship refused — prior ship record is unreadable ({e}).\n")
        return 2
    signing = bool(cfg.get("_audit", {}).get("signing"))
    # R5 DF-R5-01: NEVER derive the final SHIPPED bytes by copying the writable
    # pending record. RECONSTRUCT from authenticated facts — the sealed manifest's
    # artifact id + the chain-authenticated per-action facts (name/ok/toolchain).
    # Under signing, re-authenticate the completed actions here (defense in depth)
    # so a forged pending field can never ride into the signed/off-box bytes.
    if signing:
        ok_a, why_a = _authenticate_ship_actions(cfg, control_root, run_dir, run_id)
        if not ok_a:
            sys.stderr.write(f"dark-factory: ship refused — completed ship actions could not be "
                             f"authenticated for the audit retry: {why_a}\n")
            return SHIP_STATE_UNAUTHENTICATED
        facts = _ship_completed_action_facts(run_dir)
        shipped, shipped_text = _reconstruct_authenticated_ship_record(
            prior, artifact_object_id, facts, redactor)
    else:
        # Detection-grade only (no signed chain to reconstruct from): keep the
        # prior record but pin the artifact id to the authenticated manifest.
        shipped = dict(prior)
        shipped["outcome"] = df_ship.SHIPPED
        shipped["ship_workspace_object_id"] = artifact_object_id
        shipped["ts"] = _now()
        shipped_obj = redactor.redact_obj(shipped) if redactor is not None else shipped
        shipped_text = canonical_json(shipped_obj)

    # 1) push the SHIPPED bytes off-box FIRST (a required sink demands a
    #    server-authentic receipt — a forged/local receipt is not evidence).
    sink_status = _push_ship_offbox(cfg, run_dir, run_id, shipped_text, "ship")
    if _sink_required(cfg) and sink_status != "ok":
        ship_journal.write("SHIP_AUDIT_RETRY_PENDING",
                           note="required off-box audit sink still unreachable or non-authentic")
        sys.stderr.write(
            "dark-factory: SHIP still AUDIT-PENDING — the REQUIRED off-box audit sink did not "
            "return a server-authentic receipt. The actions remain DONE and are NOT re-run; retry "
            "`ship` once the sink is reachable.\n")
        return SHIP_AUDIT_PENDING
    # 2) anchor those EXACT bytes into the local signed chain.
    anchor_status = _sup()._anchor_ship_local(cfg, control_root, run_id, shipped_text, "ship")
    if signing and anchor_status != "anchored":
        ship_journal.write("SHIP_AUDIT_RETRY_PENDING",
                           note="local signed anchor could not be committed (audit key)")
        sys.stderr.write(
            "dark-factory: SHIP still AUDIT-PENDING — the local signed audit anchor could not be "
            "committed (the audit key is required and was not loadable). The actions remain DONE "
            "and are NOT re-run; restore the audit key and retry `ship`.\n")
        return SHIP_AUDIT_PENDING
    # 3) BOTH pieces of evidence exist → flip the authoritative record to SHIPPED.
    atomic_write(os.path.join(run_dir, SHIP_RESULT_FILE), shipped_text)
    ship_journal.write(df_ship.SHIPPED,
                       note="audit-only retry: off-box receipt + local signed anchor committed")
    print("dark-factory: SHIPPED — off-box audit evidence + local signed anchor committed on "
          "retry (the actions were already done; not re-run).")
    return 0


def _ship_phase(cfg, control_root, run_dir, redactor, creds, decision="continue"):
    """Drive the ship phase for a qualified run_dir. Returns an exit code:
    0 SHIPPED · 3 SHIP_FAILED/SHIP_APPROVAL_PENDING · 11 SHIP_UNKNOWN_OUTCOME
    (needs --decision reconcile) · 2 fail-closed refusal. The caller holds the
    control-root lock. Absent ship policy is a caller error (never reached in
    normal flow)."""
    ship_cfg = cfg.get("_ship")
    if ship_cfg is None:
        sys.stderr.write("dark-factory: no `ship` block configured; nothing to ship\n")
        return 2

    ok, reason, artifact_object_id, run_id = _ship_eligible(cfg, control_root, run_dir)
    if not ok:
        sys.stderr.write(f"dark-factory: ship refused (fail-closed) — {reason}\n")
        return 2

    ship_journal = Journal(os.path.join(run_dir, SHIP_JOURNAL_FILE), redactor=redactor)
    signing_on = bool(cfg.get("_audit", {}).get("signing"))

    # DF-R9-04: refuse to ship (or re-ship) against a TAIL-TRUNCATED signed chain.
    # A same-user writer can truncate the local chain to a still-verifying prefix
    # (or to empty) to erase ship-action / terminal tokens AND their journal
    # attribution, then re-run a non-idempotent action — nothing survives for the
    # per-action authentication to catch. The off-box WORM/append sink still holds
    # a monotonic checkpoint for the longer length, so this UNCONDITIONAL gate
    # (before any `already_done` is derived) detects it. No-op when unsigned or
    # sink-less (detection-grade best-effort); fail-closed on a REQUIRED sink that
    # cannot confirm completeness.
    ok_tr, why_tr = _sup()._verify_chain_untruncated(cfg, control_root)
    if not ok_tr:
        ship_journal.write("SHIP_CHAIN_TRUNCATED_REFUSED", detail=why_tr)
        sys.stderr.write(f"dark-factory: ship refused (fail-closed) — {why_tr}\n")
        return SHIP_STATE_UNAUTHENTICATED

    # Idempotent terminal: a completed ship never re-ships. SHIP_APPROVAL_PENDING
    # is NOT terminal (an attach + re-`ship` resumes it), so it falls through.
    result_path = os.path.join(run_dir, SHIP_RESULT_FILE)
    prior, prior_text = None, None
    if os.path.exists(result_path):
        try:
            with open(result_path, encoding="utf-8") as f:
                prior_text = f.read()
            prior = json.loads(prior_text)
        except (OSError, json.JSONDecodeError):
            prior, prior_text = None, None
    if isinstance(prior, dict) and prior.get("outcome") in (
            df_ship.SHIPPED, df_ship.SHIP_FAILED, df_ship.SHIPPED_AUDIT_PENDING):
        prior_outcome = prior["outcome"]
        # DF-R3-03 / DF-R4-03: NEVER trust a planted/altered terminal ship_result on
        # re-entry. Under signing, a FINAL SHIPPED / SHIP_FAILED record MUST be
        # anchored in the signed chain (a control-root writer who plants one — to
        # suppress a real ship — cannot forge a signature-valid entry). A
        # SHIPPED_AUDIT_PENDING record MAY legitimately be UNANCHORED — its own local
        # anchor can be the very evidence that is pending (DF-R4-03) — so it is
        # authenticated via its per-action signed tokens instead (a genuine mid-ship
        # pending has anchored completions; a plant has none).
        if signing_on:
            if prior_outcome == df_ship.SHIPPED_AUDIT_PENDING:
                ok_a, why_a = _pending_ship_authenticated(
                    cfg, control_root, run_dir, run_id, prior, prior_text,
                    [a.get("name") for a in ship_cfg["actions"]])
            else:
                ok_a, why_a = _authenticate_ship_chain(
                    cfg, control_root, run_id, sha256_str(prior_text), "ship")
            if (not ok_a and prior_outcome == df_ship.SHIP_FAILED
                    and _terminal_anchor_pending_sha(run_dir) == sha256_str(prior_text)):
                # R5 DF-R5-02 terminal recovery: this SHIP_FAILED was sealed while
                # the signer was down (first-class journaled marker binding these
                # exact bytes). Re-anchor it — but ONLY after re-verifying the
                # record against the signed per-action + journaled evidence, so a
                # planted terminal + planted marker is still refused, never
                # laundered into the signed chain.
                ok_b, why_b = _failed_ship_record_bound(cfg, control_root, run_dir,
                                                        run_id, prior,
                                                        artifact_object_id=artifact_object_id)
                if not ok_b:
                    # DF-R7-05 (R6-10): a NO-ACTION terminal — a materialization
                    # failure (failed_action:null) or a reconcile-abort — sealed
                    # during a signer outage cannot self-authenticate (it bound no
                    # signed evidence, by construction it RAN NOTHING). M56b left
                    # it a fail-closed refusal recoverable only by MANUALLY
                    # deleting the record. Replace that state surgery with a
                    # GOVERNED, operator-consented reseal: under `--decision
                    # abort`, reconstruct a CLEAN no-action SHIP_FAILED from
                    # AUTHENTICATED facts (empty action set + the manifest's
                    # artifact id — never the writable prior blob) and anchor
                    # THOSE bytes. This is SAFE: it runs no action, cannot launder
                    # to SHIPPED (outcome stays SHIP_FAILED), cannot skip an
                    # action, and is gated on explicit operator consent — the M56b
                    # HIGH (SILENT re-anchor of a forged terminal) stays closed.
                    if _is_no_action_terminal(run_dir, run_id, prior, cfg=cfg,
                                              control_root=control_root):
                        if decision == "abort":
                            # DF-R7-05 (opus review F4): reconstruct from FACTS
                            # only — no field taken from the writable prior blob.
                            # The cause lives in the SHIP_TERMINAL_CAUSE_RESEALED
                            # journal event, so failed_action need not (and does
                            # not) carry the attacker-controlled prior value.
                            clean = {"outcome": df_ship.SHIP_FAILED, "actions": [],
                                     "pending_action": None, "failed_action": None,
                                     "rollbacks": [], "rollback_failed": False}
                            ship_journal.write("SHIP_TERMINAL_CAUSE_RESEALED",
                                               cause=("materialize_failure"
                                                      if prior.get("failed_action") is None
                                                      else "reconcile_abort"))
                            _rec2, _s, anchor2 = _sup()._seal_ship_result(
                                cfg, control_root, run_dir, run_id, ship_journal, clean,
                                artifact_object_id, redactor,
                                ship_actions=ship_cfg["actions"])
                            if signing_on and anchor2 != "anchored":
                                sys.stderr.write(
                                    "dark-factory: SHIP_EVIDENCE_PENDING — the no-action "
                                    "SHIP_FAILED was rebuilt from authenticated facts but its "
                                    "signed anchor still could not be committed; retry once the "
                                    "signer is available.\n")
                                return SHIP_EVIDENCE_PENDING_EXIT
                            print("dark-factory: no-action SHIP_FAILED terminal re-sealed from "
                                  "authenticated facts under operator consent (no action ran). "
                                  f"See {result_path}.")
                            return 3
                        sys.stderr.write(
                            "dark-factory: ship refused (fail-closed) — a no-action SHIP_FAILED "
                            "terminal (materialize-failure / reconcile-abort) was sealed during a "
                            "signer outage and cannot self-authenticate. It ran NOTHING; re-run "
                            "`ship --decision abort` to re-seal it from authenticated facts under "
                            "the now-available signer (no action runs).\n")
                        return SHIP_STATE_UNAUTHENTICATED
                    sys.stderr.write(f"dark-factory: ship refused (fail-closed) — the "
                                     f"unanchored SHIP_FAILED record could not be bound to "
                                     f"the run's evidence: {why_b}\n")
                    return SHIP_STATE_UNAUTHENTICATED
                if _sup()._anchor_ship_local(cfg, control_root, run_id, prior_text,
                                      "ship") != "anchored":
                    sys.stderr.write(
                        "dark-factory: SHIP_EVIDENCE_PENDING — the SHIP_FAILED terminal "
                        "record is evidence-bound but its signed anchor STILL could not be "
                        "committed (audit key/signer unavailable). Re-run `ship` once the "
                        "signer is available.\n")
                    return SHIP_EVIDENCE_PENDING_EXIT
                ship_journal.write("SHIP_TERMINAL_ANCHOR_RESOLVED",
                                   outcome=prior_outcome,
                                   record_sha256=sha256_str(prior_text))
                print(f"dark-factory: ship already terminal (SHIP_FAILED); its pending "
                      f"signed anchor was committed on retry (evidence-bound, no action "
                      f"re-ran); see {result_path}. Not re-shipping.")
                return 3
            if not ok_a:
                sys.stderr.write(f"dark-factory: ship refused (fail-closed) — the prior ship "
                                 f"result could not be authenticated: {why_a}\n")
                return SHIP_STATE_UNAUTHENTICATED
        if prior_outcome == df_ship.SHIP_FAILED:
            print(f"dark-factory: ship already terminal (SHIP_FAILED); see {result_path}. "
                  "Not re-shipping.")
            return 3
        # SHIPPED / SHIPPED_AUDIT_PENDING: fully attested only if the REQUIRED
        # off-box evidence is present, bound, AND server-authentic (DF-R3-02 +
        # DF-R4-04). SHIPPED_AUDIT_PENDING is by definition not-yet-final; a SHIPPED
        # whose required receipt is absent/unbound OR carries no server-issued value
        # (a locally-forged receipt with a correct body_sha256 is NOT off-box
        # evidence) is treated the same — never a silent fully-shipped — and triggers
        # the idempotent audit-only retry.
        needs_audit_retry = (prior_outcome == df_ship.SHIPPED_AUDIT_PENDING)
        if prior_outcome == df_ship.SHIPPED and _sink_required(cfg):
            ok_r, _why_r = _sink_receipt_bound(
                run_dir, "ship_sink_receipt.json", prior_text,
                require_server_issued=True, sink=cfg["_audit"]["sink"])
            if not ok_r:
                needs_audit_retry = True
        if not needs_audit_retry:
            # DF-R8-02: this re-entry AUTHENTICATED the existing terminal SHIPPED
            # (prior_text is chain-anchored under signing) and ran NOTHING — the
            # mandated idempotence exercise. Record a signed SHIP_REENTRY_VERIFIED
            # event binding these exact bytes so the production bundle has POSITIVE
            # proof the re-entry occurred without redispatch (the terminal auth
            # alone left no trace). Only under signing (else the chain is not a
            # trust boundary and the event would attest nothing).
            if signing_on:
                _record_ship_reentry_verified(cfg, control_root, run_dir, run_id,
                                              ship_journal, sha256_str(prior_text))
            print(f"dark-factory: ship already terminal (SHIPPED); see {result_path}. "
                  "Not re-shipping.")
            return 0
        # DF-R3-02 idempotent audit-only retry: re-anchor the off-box evidence for
        # the EXISTING sealed record; the actions are DONE and are NEVER re-run.
        return _ship_audit_retry(cfg, control_root, run_dir, run_id, ship_journal,
                                 prior_text, redactor, artifact_object_id)

    # Crash-safety (invariant #4): an INTENT with no RESULT is UNKNOWN. Refuse
    # (exit 11) under plain `continue`; `reconcile` consents to a possible
    # duplicate; `abort` seals SHIP_FAILED. DF-R6-02: a dangling ROLLBACK intent
    # is ALSO an unknown outcome (the undo may or may not have applied).
    _rec = _ship_action_recovery_state(run_dir)
    # DF-R9-02: a SIGNED dispatch with no authenticated outcome (no signed
    # completion, no signed reconcile) is unknown too — even if a forged unsigned
    # non-`ok` RESULT made the reducer mark its intent "resolved". Fold it into the
    # forward-unresolved set so the same SHIP_UNKNOWN_OUTCOME consent gate applies.
    unresolved_fwd = _rec["unresolved_forward"]
    if decision != "repair-evidence":
        # `repair-evidence` belongs to the M56b evidence-pending flow (below); a
        # dangling signed dispatch under that decision is re-checked AFTER the
        # repair (a repair that resolves nothing must not then silently re-run).
        unresolved_fwd = unresolved_fwd or \
            _dangling_signed_dispatch(cfg, control_root, run_dir, run_id)
    unresolved_rb = _rec["unresolved_rollback"]
    unknown_effect = sorted(_rec["unknown_effect"])
    unresolved = unresolved_fwd or unresolved_rb
    # DF-R6-02: an action whose ROLLBACK FAILED has an UNKNOWN real-world state —
    # the undo may have partly applied or not at all. Skipping it risks omitting a
    # required effect; re-running it risks DUPLICATING a possibly-still-applied,
    # possibly-non-idempotent production action. Neither guess is acceptable, so
    # this is an explicit unknown outcome requiring an operator decision — the
    # same gate a dangling intent gets.
    if unresolved is None and unknown_effect:
        if decision == "continue":
            ship_journal.write("SHIP_UNKNOWN_OUTCOME", actions=unknown_effect,
                               kind="failed_rollback")
            sys.stderr.write(
                f"dark-factory: ship action(s) {unknown_effect} had a FAILED rollback — the undo "
                "did not complete, so their real-world state is UNKNOWN (possibly still applied, "
                "possibly partial). Refusing to skip (would omit a required effect) or re-run "
                "(would duplicate a possibly-applied action). Inspect the target, then `ship "
                "--decision reconcile` (re-runs, accepting a possible duplicate) or `--decision "
                "abort` (seals SHIP_FAILED).\n")
            return UNKNOWN_OUTCOME
        if decision == "abort":
            ship_journal.write("SHIP_RECONCILE_ABORT", actions=unknown_effect,
                               kind="failed_rollback")
            result = {"outcome": df_ship.SHIP_FAILED, "actions": [], "pending_action": None,
                      "failed_action": unknown_effect[0], "rollbacks": [],
                      "rollback_failed": True}
            _sup()._seal_ship_result(cfg, control_root, run_dir, run_id, ship_journal, result,
                              artifact_object_id, redactor, ship_actions=ship_cfg["actions"])
            print("dark-factory: SHIP ABORTED at a failed-rollback unknown state "
                  "(sealed SHIP_FAILED).")
            return 3
        # reconcile: the operator inspected and consents to re-running the
        # unknown-state action(s) (accepting a possible duplicate). They are
        # already OUT of `applied`, so the normal loop re-runs them.
        ship_journal.write("SHIP_RECONCILED", actions=unknown_effect, kind="failed_rollback",
                           note="operator accepted possible duplicate; re-running")
        print(f"dark-factory: reconciling failed-rollback unknown state for "
              f"{unknown_effect} — re-running (possible duplicate).")
    if unresolved is not None:
        kind = "action" if unresolved_fwd is not None else "rollback"
        if decision == "continue":
            ship_journal.write("SHIP_UNKNOWN_OUTCOME", action=unresolved.get("action"),
                               idempotency_key=unresolved.get("idempotency_key"),
                               attempt_id=unresolved.get("attempt_id"), kind=kind)
            sys.stderr.write(
                f"dark-factory: ship {kind} {unresolved.get('action')!r} was reserved but did "
                "not resolve before a crash — its real-world effect is UNKNOWN. Refusing to "
                "re-run a possibly-applied action. Inspect the target, then `ship --decision "
                "reconcile` (re-runs, accepting a possible duplicate) or `--decision abort` "
                "(seals SHIP_FAILED).\n")
            return UNKNOWN_OUTCOME
        if decision == "abort":
            ship_journal.write("SHIP_RECONCILE_ABORT", action=unresolved.get("action"),
                               kind=kind)
            result = {"outcome": df_ship.SHIP_FAILED, "actions": [], "pending_action": None,
                      "failed_action": unresolved.get("action"), "rollbacks": [],
                      "rollback_failed": False}
            _sup()._seal_ship_result(cfg, control_root, run_dir, run_id, ship_journal, result,
                              artifact_object_id, redactor, ship_actions=ship_cfg["actions"])
            print("dark-factory: SHIP ABORTED at an unresolved action (sealed SHIP_FAILED).")
            return 3
        # reconcile: resolve the dangling intent so the re-scan is satisfied, then
        # re-run from a clean applied set (operator consents to a possible
        # duplicate). The result CARRIES the dangling intent's attempt_id, so it
        # resolves EXACTLY that attempt and can NEVER resolve a future retry's
        # fresh attempt (DF-R6-01).
        if unresolved_fwd is not None:
            # A dangling FORWARD action: record an explicit unknown forward RESULT
            # (status != ok, so it does not enter `already_done`; the action
            # re-runs).
            ship_journal.write("SHIP_ACTION_RESULT", action=unresolved.get("action"),
                               idempotency_key=unresolved.get("idempotency_key"),
                               attempt_id=unresolved.get("attempt_id"),
                               status="reconciled_unknown", exit=None, timed_out=False)
            # DF-R9-02: SIGN the operator-consented reconcile so recovery can tell
            # it apart from a FORGED reconciled_unknown (which has no such token) —
            # else the next re-entry would re-flag this attempt as unknown forever.
            _sup()._anchor_ship_local(cfg, control_root, run_id,
                               _ship_reconciled_payload(run_id, unresolved.get("action"),
                                                        unresolved.get("attempt_id")),
                               "ship-action-reconciled")
        else:
            # A dangling ROLLBACK: resolve it as an operator-consented unknown
            # failure AND drop the action from `applied` (its effect is now
            # unknown, so it must re-run before any SHIPPED).
            ship_journal.write("SHIP_ROLLBACK_FAILED", action=unresolved.get("action"),
                               attempt_id=unresolved.get("attempt_id"),
                               detail="operator-reconciled unknown rollback outcome")
        ship_journal.write("SHIP_RECONCILED", action=unresolved.get("action"), kind=kind,
                           note="operator accepted possible duplicate; re-running")
        print(f"dark-factory: reconciling unresolved ship {kind} "
              f"{unresolved.get('action')!r} — re-running (possible duplicate).")

    # R5 DF-R5-02: the AUTHENTICATED evidence-only repair runs BEFORE already_done
    # is derived, so a succeeded-but-unanchored action (journal status
    # `evidence_pending`, never `ok`) is re-signed from its intent-token-bound
    # facts and THEN skipped as done — the real-world action is never re-run and
    # never re-bricked. No-op when nothing is pending.
    repair_status, repair_detail = _repair_ship_evidence(
        cfg, control_root, run_dir, run_id, ship_journal, decision=decision)
    if repair_status == "refused":
        sys.stderr.write(f"dark-factory: ship refused (fail-closed) — the evidence-pending "
                         f"ship state could not be authenticated: {repair_detail}\n")
        return SHIP_STATE_UNAUTHENTICATED
    if repair_status == "consent":
        sys.stderr.write(
            f"dark-factory: SHIP_EVIDENCE_PENDING — {repair_detail} (a signer outage after the "
            "action ran). The success claim sat in the WRITABLE journal during the outage and "
            "cannot be authenticated after the fact — VERIFY the action's real-world state, "
            "then consent with `ship --decision repair-evidence` to re-sign its evidence from "
            "the signed intent facts and continue. Nothing was repaired or re-run.\n")
        return SHIP_EVIDENCE_PENDING_EXIT
    if repair_status == "pending":
        sys.stderr.write(f"dark-factory: SHIP_EVIDENCE_PENDING — {repair_detail}. The completed "
                         "action(s) are DONE and are NEVER re-run; re-run `ship --decision "
                         "repair-evidence` once the audit key/signer is available.\n")
        return SHIP_EVIDENCE_PENDING_EXIT
    if repair_status == "repaired":
        print("dark-factory: ship evidence repaired — the pending completion token(s) were "
              "re-signed from the intent-authenticated facts (no action re-ran); continuing.")

    # DF-R9-02: after evidence-repair, a SIGNED dispatch that STILL has no
    # authenticated outcome (no signed completion, no signed reconcile) must not be
    # silently re-run. This catches a forged non-`ok` result under `repair-evidence`
    # (where the dangling gate above is deferred so repair can run first) and any
    # dangling that survived the repair. Fail-closed: the operator must reconcile
    # (consent to a possible duplicate) or abort. A reconcile that reached here has
    # already signed its reconcile token, so it is no longer dangling and proceeds.
    _dangling = _dangling_signed_dispatch(cfg, control_root, run_dir, run_id)
    if _dangling is not None:
        ship_journal.write("SHIP_UNKNOWN_OUTCOME", action=_dangling.get("action"),
                           idempotency_key=_dangling.get("idempotency_key"),
                           attempt_id=_dangling.get("attempt_id"), kind="action")
        sys.stderr.write(
            f"dark-factory: ship action {_dangling.get('action')!r} has a SIGNED dispatch with "
            "no authenticated outcome — its real-world effect is UNKNOWN (an unsigned non-`ok` "
            "result does not resolve a signed intent). Refusing to re-run. Inspect the target, "
            "then `ship --decision reconcile` (re-run, accepting a possible duplicate) or "
            "`--decision abort` (seal SHIP_FAILED).\n")
        return UNKNOWN_OUTCOME

    already_done = _ship_completed_actions(run_dir)

    # DF-R3-03: before SKIPPING real actions on the strength of the ship journal's
    # recovered `already_done`, authenticate EACH completed action against its own
    # per-action signed chain entry (anchored as the action committed, before its
    # RESULT was journaled — see _make_ship_action_committer). A same-user
    # control-root writer who plants a fake SHIP_ACTION_RESULT `ok` (to skip a real
    # action) has no matching signed token → refused. Per-action anchoring (vs one
    # seal-time journal digest) is what lets an HONEST crash-before-seal recovery
    # still authenticate — every action that actually ran was individually
    # anchored, whereas a last-digest-at-seal scheme cannot tell a legit
    # crash-before-first-seal (no anchor yet) from a tampered journal (both look
    # anchor-less), and so would brick crash recovery. Reconcile's own journal
    # lines (status `reconciled_unknown`, not `ok`) do not enter `already_done`, so
    # this stays correct after the reconcile writes above.
    # DF-R7-01 (M66 opus review): authenticate whenever there is ANYTHING to
    # authenticate — NOT only when `already_done` is non-empty. A planted bare
    # SHIP_ROLLED_BACK pops the (only) applied action, EMPTYING already_done; if
    # the guard were `and already_done`, authentication would be skipped in
    # exactly the scenario it exists for and the action would re-run (a
    # duplicate). Trigger it when there is a completed action OR any rollback
    # event; the authenticator handles the empty-facts+rollback case.
    # DF-R9-01: authenticate UNCONDITIONALLY under signing — NOT only when
    # `already_done`/rollback events are present. Deleting a completed action's
    # journal lines empties both (the attacker's goal: re-run the action), so a
    # guard keyed on them would skip authentication in exactly the scenario it
    # exists for. The authenticator short-circuits cheaply when there is genuinely
    # nothing anchored, and refuses an orphaned anchored completion otherwise.
    if signing_on:
        ok_j, why_j = _authenticate_ship_actions(cfg, control_root, run_dir, run_id)
        if not ok_j:
            sys.stderr.write(f"dark-factory: ship refused (fail-closed) — the ship journal that "
                             f"records already-completed actions could not be authenticated: "
                             f"{why_j}\n")
            return SHIP_STATE_UNAUTHENTICATED

    # The live approval view (invariant #3): the SEALED policy from config + the
    # attached attestation (or none). covers() RE-VERIFIES every call.
    approval_ctx = df_release.ApprovalContext(
        attestation=_load_release_attestation(run_dir, cfg),
        approvers=ship_cfg["approval"]["approvers"],
        threshold=ship_cfg["approval"]["threshold"],
        run_id=run_id, artifact_object_id=artifact_object_id)

    # Materialize a FRESH workspace from the SEALED bytes (invariant #2). DF-R3-06:
    # a try/finally guarantees this fresh copy of the sealed artifact is REMOVED on
    # EVERY exit path (success, fail, approval-pending, exception) — it used to leak
    # a full copy of the sealed bytes into temp on every ship.
    ship_ws = tempfile.mkdtemp(prefix="df-ship-ws-")
    try:
        try:
            df_ship.materialize_ship_workspace(_object_store_root(control_root),
                                               artifact_object_id, ship_ws)
        except df_ship.ShipError as e:
            ship_journal.write("SHIP_MATERIALIZE_FAILED", artifact_object_id=artifact_object_id,
                               detail=str(e))
            result = {"outcome": df_ship.SHIP_FAILED, "actions": [], "pending_action": None,
                      "failed_action": None, "rollbacks": [], "rollback_failed": False}
            _sup()._seal_ship_result(cfg, control_root, run_dir, run_id, ship_journal, result,
                              artifact_object_id, redactor, ship_actions=ship_cfg["actions"])
            sys.stderr.write(f"dark-factory: ship failed — {e}\n")
            return 3

        ship_journal.write("SHIP_STARTED", artifact_object_id=artifact_object_id,
                           action_count=len(ship_cfg["actions"]),
                           already_done=sorted(already_done))
        base_secret_values = list(creds.values()) if creds else []
        # DF-R3-03: under signing, anchor each action's completion into the signed
        # chain AS it commits (before its RESULT is journaled), so `already_done`
        # is individually chain-backed on re-entry (crash-recovery authenticates;
        # a planted RESULT does not). No committer when signing is off (nothing to
        # authenticate against — the residual is documented, detection-grade).
        commit_action = (_make_ship_action_committer(cfg, control_root, run_dir, run_id)
                         if signing_on else None)
        result = df_ship.run_actions(
            ship_cfg["actions"], ship_ws,
            approval_ctx=approval_ctx, journal=ship_journal, run_id=run_id,
            base_env=os.environ.copy(), base_secret_values=base_secret_values,
            resolve_action_creds=_resolve_ship_action_creds,
            already_done=already_done, commit_action=commit_action,
            log_dir=os.path.join(run_dir, "ship_logs"),
            now_fn=lambda: datetime.datetime.now(datetime.timezone.utc))

        record, sink_status, anchor_status = _sup()._seal_ship_result(
            cfg, control_root, run_dir, run_id, ship_journal, result,
            artifact_object_id, redactor, ship_actions=ship_cfg["actions"])

        if result["outcome"] == df_ship.SHIP_EVIDENCE_PENDING:
            # R5 DF-R5-02: a per-action token could not be signed. The loop already
            # STOPPED (no later action ran). The RECOVERABLE pending record was
            # ALREADY sealed by the unconditional _seal_ship_result above — its own
            # anchor will typically fail too (same signer); that is fine: re-entry
            # is journal+chain-driven and never trusts this blob.
            # DF-R6-09: do NOT seal a second time. The duplicate seal wrote two
            # terminal records, two journal events, two chain anchors and two
            # off-box versions for ONE event, leaving a needlessly contradictory
            # WORM history.
            ran = result.get("evidence_pending_action")
            halted = result.get("pending_action")
            gap = (f"action {ran!r} RAN but its completion token could not be signed"
                   if ran is not None else
                   f"action {halted!r} did NOT run (its intent token could not be signed "
                   "before the spawn)")
            fix = ("verify the action's real-world state, then re-run `ship --decision "
                   "repair-evidence` once the signer is available (the retry re-signs its "
                   "evidence from the SIGNED intent facts and continues)"
                   if ran is not None else
                   "re-run `ship` once the signer is available (the action re-runs normally)")
            sys.stderr.write(
                f"dark-factory: SHIP_EVIDENCE_PENDING — {gap} (a transient audit-key/signer "
                f"failure). No further action ran. Completed actions are DONE and are NEVER "
                f"re-run. To recover: {fix}.\n")
            return SHIP_EVIDENCE_PENDING_EXIT
        if result["outcome"] == df_ship.SHIPPED:
            # DF-R4-04/03: a SHIPPED is FINAL only when the REQUIRED off-box evidence
            # landed server-authentic AND (under signing) the local signed anchor
            # committed. _seal_ship_result already pushed + anchored the FINAL bytes
            # BEFORE writing ship_result.json and did NOT write an authoritative
            # SHIPPED when either piece was missing — so here we either confirm
            # SHIPPED or seal the DISTINCT SHIPPED_AUDIT_PENDING (the real-world
            # actions RAN and are NEVER re-run) with a distinct exit so automation
            # does NOT read exit 0. Re-`ship` runs the idempotent audit-only retry.
            required_ok = (not _sink_required(cfg)) or (sink_status == "ok")
            anchor_ok = (not signing_on) or (anchor_status == "anchored")
            if required_ok and anchor_ok:
                print(f"dark-factory: SHIPPED — {len(result['actions'])} action(s) ran on the "
                      f"sealed artifact {artifact_object_id[:16]}…. Record: {result_path}")
                return 0
            pending = dict(result, outcome=df_ship.SHIPPED_AUDIT_PENDING)
            _sup()._seal_ship_result(cfg, control_root, run_dir, run_id, ship_journal, pending,
                              artifact_object_id, redactor, ship_actions=ship_cfg["actions"],
                              push_offbox=False)
            gap = ("the REQUIRED off-box audit sink did not return a server-authentic receipt"
                   if not required_ok else
                   "the local signed audit anchor could not be committed (audit key)")
            sys.stderr.write(
                f"dark-factory: SHIPPED_AUDIT_PENDING — {len(result['actions'])} action(s) ran "
                f"on the sealed artifact {artifact_object_id[:16]}…, but {gap}, so the mandated "
                f"audit evidence is not yet complete. No authoritative local SHIPPED was written "
                f"or anchored. The actions are DONE and are NEVER re-run. Re-run `ship` to "
                f"complete the evidence and finalize SHIPPED. Record: {result_path}\n")
            return SHIP_AUDIT_PENDING
        if result["outcome"] == df_ship.SHIP_APPROVAL_PENDING:
            pol = ship_cfg["approval"]
            manifest_path = os.path.join(run_dir, "manifest.json")
            print(
                f"dark-factory: SHIP APPROVAL PENDING — the irreversible action "
                f"{result['pending_action']!r} needs a signed K-of-N release approval "
                f"({pol['threshold']} of {len(pol['approvers'])}). The run STAYS qualified; no "
                f"irreversible action ran. To authorize:\n"
                f"  supervisor.py df-release sign --manifest {manifest_path} "
                f"--actions {result['pending_action']} --expires <ISO8601Z> --key-file <privkey>\n"
                f"collect the {{claim,signatures}} into "
                f"{os.path.join(control_root, RELEASE_APPROVAL_FILE)} (merge signatures for K>1), "
                f"then:\n"
                f"  supervisor.py df-release attach {control_root} --run-dir {run_dir}\n"
                f"  supervisor.py ship {control_root} --run-dir {run_dir}")
            return 3
        # SHIP_FAILED
        if record.get("rollback_failed"):
            sys.stderr.write(
                "dark-factory: SHIP FAILED and a ROLLBACK ITSELF FAILED — infrastructure may be "
                f"in an inconsistent state. Inspect {os.path.join(run_dir, 'ship_logs')} and the "
                "ship journal, then intervene MANUALLY.\n")
        print(f"dark-factory: SHIP FAILED at action {result.get('failed_action')!r} "
              f"(rollback ran in reverse). The run stays qualified. Record: {result_path}")
        return 3
    finally:
        # DF-R3-06: never leak the materialized sealed-artifact copy, on ANY path.
        shutil.rmtree(ship_ws, ignore_errors=True)


def ship_cmd(control_root, run_dir, decision="continue"):
    """`ship` subcommand: run/resume the governed ship phase against a QUALIFIED
    run as a deliberate, separate step (the ONLY path for an enterprise run,
    which ships only after df-custody attach; also the resume path for a
    SHIP_APPROVAL_PENDING or SHIP_UNKNOWN_OUTCOME run)."""
    control_root = os.path.abspath(control_root)
    try:
        cfg = _sup().load_config(control_root)
    except ConfigError as e:
        sys.stderr.write(f"dark-factory: config error: {e}\n")
        return 2
    cfg["_control_root"] = control_root
    if cfg.get("_ship") is None:
        sys.stderr.write("dark-factory: control root has no `ship` block; nothing to ship\n")
        return 2
    run_dir = os.path.abspath(run_dir)
    if not os.path.isdir(run_dir):
        sys.stderr.write(f"dark-factory: run-dir not found: {run_dir}\n")
        return 2

    creds, redactor, creds_err = _resolve_credentials(cfg)
    if creds_err is not None:
        sys.stderr.write(f"dark-factory: credentials: {creds_err}\n")
        return 2

    try:
        lock = acquire_lock(control_root)
    except LockError as e:
        sys.stderr.write(f"dark-factory: {e}\n")
        return 2
    try:
        return _ship_phase(cfg, control_root, run_dir, redactor, creds, decision=decision)
    except df_ship.ShipError as e:
        # R5 DF-R5-08: a corrupt/torn ship journal (or other controlled ship-state
        # error) is a fail-closed REFUSAL with a diagnostic, never an uncaught crash.
        sys.stderr.write(f"dark-factory: ship refused (fail-closed) — {e}\n")
        return 2
    finally:
        release_lock(lock)


def attach_release(control_root, run_dir):
    """`df-release attach` — verify the collected {claim, signatures} in
    <control_root>/release-approval.json against the run's SEALED manifest +
    SEALED ship.approval policy, and on success write <run_dir>/release_attestation.json
    (+ record the nonce, + anchor it). Mirrors attach_custody's two-phase shape.
    Fail-closed on every drift: unqualified run, wrong-artifact/run binding,
    expired, replayed nonce, config changed, or < threshold distinct approvers."""
    control_root = os.path.abspath(control_root)
    run_dir = os.path.abspath(run_dir)
    manifest_bytes, _manifest_sha = _read_manifest_bytes(run_dir)
    if manifest_bytes is None:
        sys.stderr.write(f"dark-factory: no manifest.json in {run_dir}\n")
        return 3
    try:
        manifest_obj = json.loads(manifest_bytes)
    except json.JSONDecodeError as e:
        sys.stderr.write(f"dark-factory: manifest.json is not valid JSON: {e}\n")
        return 2

    try:
        cfg = _sup().load_config(control_root)
    except ConfigError as e:
        sys.stderr.write(f"dark-factory: config error: {e}\n")
        return 2
    cfg["_control_root"] = control_root
    ship_cfg = cfg.get("_ship")
    if ship_cfg is None or ship_cfg["approval"]["threshold"] < 1:
        sys.stderr.write("dark-factory: no `ship.approval` policy (threshold>=1) configured; "
                         "nothing to attach\n")
        return 2

    # CRITICAL (M41 review fix): authenticate the manifest via its HMAC BEFORE
    # trusting config_sha256 / artifact / run_id / the sealed policy. An
    # approver-configured run FORCES audit.signing (df_config), so this always
    # verifies the HMAC that pins the sealed approver allowlist — a swapped
    # config.json + re-sha256'd manifest with a stale HMAC is TAMPERED and refused,
    # so an attacker cannot self-approve an irreversible ship with their own key.
    ok, why = _authenticate_manifest(cfg, control_root, run_dir)
    if not ok:
        sys.stderr.write(f"dark-factory: release attach refused (fail-closed) — {why}\n")
        return 3

    artifact = manifest_obj.get("artifact")
    if not isinstance(artifact, dict) or not isinstance(artifact.get("object_id"), str):
        sys.stderr.write("dark-factory: manifest binds no artifact object — nothing to approve\n")
        return 3
    object_id = artifact["object_id"]  # artifact identity re-verified in _authenticate_manifest

    # Policy binding: the approver allowlist is sealed via config_sha256 — a
    # post-run config edit fails closed (mirrors custody).
    bound, sealed_sha, current_sha = _custody_config_bound(cfg, manifest_bytes)
    if not bound:
        sys.stderr.write(f"dark-factory: config.json changed since this run (sealed "
                         f"config_sha256 {sealed_sha} != current {current_sha}); approval "
                         "refused — re-run under the intended config\n")
        return 3

    # M44 RA-03: a release approval authorizes irreversible ship ACTIONS for a
    # QUALIFIED run only — it must never stand on a run that failed a gate/exam.
    # Mirror _ship_eligible's qualification requirement (the ship phase also
    # enforces it) so an ineligible run cannot even collect an approval that
    # would imply it is a ship candidate.
    _rtier = _effective_tier_of(manifest_obj)  # R5 DF-R5-04: EFFECTIVE tier
    if _rtier == "enterprise":
        _release_eligible = (manifest_obj.get("outcome") == "CUSTODY_PENDING"
                             and _precustody_substates(manifest_obj)["qualified"]
                             and _final_exam_ok(manifest_obj))
    else:
        _release_eligible = (manifest_obj.get("outcome") == "COMPLETE_QUALIFIED"
                             and manifest_obj.get("qualified") is True)
    if not _release_eligible:
        sys.stderr.write(
            f"dark-factory: release attach refused — run is not a qualified ship candidate "
            f"(outcome {manifest_obj.get('outcome')!r}, qualified="
            f"{manifest_obj.get('qualified')!r}); a release approval cannot qualify a run "
            "that failed a gate/exam.\n")
        return 3

    approval_path = os.path.join(control_root, RELEASE_APPROVAL_FILE)
    if not os.path.exists(approval_path):
        sys.stderr.write(f"dark-factory: {RELEASE_APPROVAL_FILE} not found in the control root — "
                         "collect a signed {claim, signatures} there first (df-release sign)\n")
        return 3
    try:
        with open(approval_path, encoding="utf-8") as f:
            collected = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        sys.stderr.write(f"dark-factory: unreadable {RELEASE_APPROVAL_FILE}: {e}\n")
        return 2
    claim = collected.get("claim") if isinstance(collected, dict) else None
    signatures = collected.get("signatures") if isinstance(collected, dict) else None
    if not isinstance(claim, dict) or not isinstance(signatures, list):
        sys.stderr.write(f"dark-factory: {RELEASE_APPROVAL_FILE} must be "
                         "{{\"claim\":{{...}},\"signatures\":[...]}}\n")
        return 2

    run_id = manifest_obj.get("invocation") or os.path.basename(run_dir.rstrip(os.sep))
    approvers = ship_cfg["approval"]["approvers"]
    threshold = ship_cfg["approval"]["threshold"]
    now = datetime.datetime.now(datetime.timezone.utc)

    try:
        lock = acquire_lock(control_root)
    except LockError as e:
        sys.stderr.write(f"dark-factory: {e}\n")
        return 2
    try:
        try:
            used = df_release.load_used_nonces(control_root)
        except df_release.ReleaseError as e:
            sys.stderr.write(f"dark-factory: {e}\n")
            return 2
        satisfied, reason, _count, nonce = df_release.verify_release(
            claim=claim, signatures=signatures, approvers=approvers, threshold=threshold,
            run_id=run_id, artifact_object_id=object_id, now=now, used_nonces=used)
        if not satisfied:
            print(f"dark-factory: RELEASE PENDING — not attached ({reason}). Collect "
                  f">={threshold} distinct approver signatures over the SAME claim, then re-run "
                  "df-release attach.")
            return 3

        # Keep only the entries that actually verify against an allowlisted
        # approver (never a private key; public keys + sigs only).
        try:
            signed = df_release.release_signing_bytes(claim)
        except df_release.ReleaseError as e:
            sys.stderr.write(f"dark-factory: {e}\n")
            return 2
        approver_set = {a.lower() for a in approvers}
        kept, satisfied_set = [], []
        for entry in signatures:
            if not isinstance(entry, dict):
                continue
            a, s = entry.get("approver"), entry.get("sig")
            if not isinstance(a, str) or not isinstance(s, str):
                continue
            al = a.lower()
            if al in approver_set and df_custody.verify_one(al, signed, s):
                kept.append({"approver": al, "sig": s})
                if al not in satisfied_set:
                    satisfied_set.append(al)

        attestation = {
            "attestation_version": "1",
            "claim": claim,
            "signatures": kept,
            "approvers_satisfied": sorted(satisfied_set),
            "qualified": True,
            "ts": _now(),
        }
        att_text = canonical_json(attestation)

        # M44 RA-02: push the release approval off-box FIRST. On a REQUIRED sink
        # failure, roll back fail-closed — do NOT record the one-time nonce or
        # write the attestation, so an approval whose off-box record never left
        # the box cannot authorize an irreversible ship (and its nonce stays
        # unconsumed for a retry once the sink is reachable). No sink / optional
        # sink is byte-compatible with the pre-M44 flow.
        release_chain_key = f"{run_id}.release"
        push_status, receipt, detail = _push_qualification_offbox(
            cfg, release_chain_key, att_text)
        if push_status == "required_fail":
            sys.stderr.write(
                f"dark-factory: RELEASE NOT ATTESTED — the REQUIRED audit sink push FAILED "
                f"({detail}); no attestation written and the approval nonce was not consumed. "
                f"Fix the sink and re-run df-release attach.\n")
            return 3
        if push_status == "optional_fail":
            sys.stderr.write(f"dark-factory: audit sink push warning (not required): {detail}\n")

        # DF-R6-08: a REPLAY-SAFE release-evidence transaction. The one-time
        # nonce is consumed LAST, only after every piece of evidence is durable,
        # so a crash at ANY earlier point leaves the nonce UNCONSUMED and a plain
        # re-run of `df-release attach` (same collected claim) redoes all of this
        # idempotently — recovery never needs fresh approver signatures.
        # Previously the nonce was recorded FIRST and the anchor result was
        # ignored: a crash after nonce/before-attestation burned the approval,
        # and an anchor failure still printed RELEASE ATTESTED with no chain
        # entry (so ship-time `_load_release_attestation` then rejected it).
        # 1) attestation bytes (idempotent atomic write).
        atomic_write(os.path.join(run_dir, RELEASE_ATTESTATION_FILE), att_text)
        # 2) the off-box receipt (if any) — bound to those exact bytes.
        if receipt is not None:
            atomic_write(os.path.join(run_dir, "release_sink_receipt.json"),
                         canonical_json(receipt))
        # 3) anchor into the tamper-evident chain and CHECK the result. Under
        #    signing, a failed anchor means the attestation is NOT chain-backed;
        #    do NOT consume the nonce — report evidence-pending so a retry
        #    (once the audit key is available) re-anchors and then consumes it.
        anchor_status = _sup()._anchor_ship_local(cfg, control_root, run_id, att_text, "release")
        if bool(cfg.get("_audit", {}).get("signing")) and anchor_status != "anchored":
            sys.stderr.write(
                "dark-factory: RELEASE EVIDENCE PENDING — the attestation was written and "
                "pushed off-box, but its local signed anchor could not be committed (audit "
                "key). The approval nonce was NOT consumed; re-run `df-release attach` once "
                "the signer is available to finish anchoring.\n")
            return SHIP_EVIDENCE_PENDING_EXIT
        # 4) consume the one-time nonce LAST — the transaction is now durable.
        df_release.record_nonce(control_root, nonce, run_id=run_id,
                                artifact_object_id=object_id, applied_at=_now())
        scope = claim.get("action_names")
        print(f"dark-factory: RELEASE ATTESTED — {reason}; scope="
              f"{scope!r}; nonce recorded. Now ship:\n"
              f"  supervisor.py ship {control_root} --run-dir {run_dir}")
        return 0
    except df_release.ReleaseError as e:
        sys.stderr.write(f"dark-factory: {e}\n")
        return 3
    finally:
        release_lock(lock)


def _df_release_cli(args):
    """Dispatch for `df-release` (keygen / sign / attach). keygen delegates to
    df_custody (an approver key IS an ed25519 keypair). sign recomputes run_id +
    artifact_object_id FROM the SEALED manifest (never operator-supplied), so an
    approver can only sign for the exact run+artifact the manifest binds."""
    if args.release_cmd == "keygen":
        try:
            priv, pub = df_custody.generate_keypair()
        except df_custody.CustodyError as e:
            sys.stderr.write(f"dark-factory: {e}\n")
            return 2
        if args.out_prefix:
            atomic_write(args.out_prefix + ".key", priv + "\n")
            os.chmod(args.out_prefix + ".key", 0o600)
            atomic_write(args.out_prefix + ".pub", pub + "\n")
            print(f"dark-factory: wrote {args.out_prefix}.key (private, 0600) + "
                  f"{args.out_prefix}.pub (public: {pub})")
        else:
            print(json.dumps({"private": priv, "public": pub}))
        return 0

    if args.release_cmd == "attach":
        return attach_release(args.control_root, args.run_dir)

    if args.release_cmd == "sign":
        if not os.path.exists(args.manifest):
            sys.stderr.write(f"dark-factory: manifest not found: {args.manifest}\n")
            return 2
        try:
            with open(args.manifest, "rb") as f:
                manifest_obj = json.loads(f.read())
        except (OSError, json.JSONDecodeError) as e:
            sys.stderr.write(f"dark-factory: cannot read manifest: {e}\n")
            return 2
        run_id = manifest_obj.get("invocation")
        artifact = manifest_obj.get("artifact")
        object_id = artifact.get("object_id") if isinstance(artifact, dict) else None
        if not isinstance(run_id, str) or not isinstance(object_id, str):
            sys.stderr.write("dark-factory: manifest lacks invocation/artifact.object_id — a "
                             "release can only be signed against a sealed, artifact-bound run\n")
            return 2
        try:
            with open(args.key_file, encoding="utf-8") as f:
                private_hex = f.read().strip()
        except OSError as e:
            sys.stderr.write(f"dark-factory: cannot read key file: {e}\n")
            return 2

        if args.claim_file is not None:
            # Additional approver: sign the SAME claim (identical nonce/bytes).
            try:
                with open(args.claim_file, encoding="utf-8") as f:
                    loaded = json.load(f)
            except (OSError, ValueError) as e:
                sys.stderr.write(f"dark-factory: cannot read --claim file: {e}\n")
                return 2
            claim = loaded.get("claim") if isinstance(loaded, dict) and "claim" in loaded else loaded
            if not isinstance(claim, dict):
                sys.stderr.write("dark-factory: --claim file has no signable claim object\n")
                return 2
            if claim.get("run_id") != run_id or claim.get("artifact_object_id") != object_id:
                sys.stderr.write("dark-factory: --claim run_id/artifact does not match this "
                                 "manifest's sealed run+artifact\n")
                return 2
        else:
            expires_dt = df_release._parse_ts(args.expires)
            if expires_dt is None:
                sys.stderr.write(f"dark-factory: --expires is not a valid ISO-8601 UTC "
                                 f"timestamp: {args.expires!r}\n")
                return 2
            issued_at = _now()
            if not (df_release._parse_ts(issued_at) < expires_dt):
                sys.stderr.write(f"dark-factory: --expires {args.expires!r} is not after the "
                                 f"issue time {issued_at!r}; the approval would be dead on "
                                 "arrival\n")
                return 2
            if args.all_actions:
                action_names = df_release.ACTION_WILDCARD
            else:
                action_names = [n.strip() for n in (args.actions or "").split(",") if n.strip()]
            try:
                df_release.normalize_action_names(action_names)
            except df_release.ReleaseError as e:
                sys.stderr.write(f"dark-factory: {e} (use --actions a,b or --all)\n")
                return 2
            claim = {
                "release_version": df_release.RELEASE_VERSION,
                "run_id": run_id,
                "artifact_object_id": object_id,
                "action_names": action_names,
                "issued_at": issued_at,
                "expires_at": args.expires,
                "nonce": uuid.uuid4().hex,
            }
        try:
            signed = df_release.release_signing_bytes(claim)
            sig = df_custody.sign_manifest(private_hex, signed)
            approver = df_custody.public_from_private(private_hex)
        except (df_custody.CustodyError, df_release.ReleaseError) as e:
            sys.stderr.write(f"dark-factory: {e}\n")
            return 2
        print(json.dumps({"claim": claim, "signatures": [{"approver": approver, "sig": sig}]},
                         indent=2, sort_keys=True))
        return 0

    return 2
