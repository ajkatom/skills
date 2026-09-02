"""dark-factory supervisor: the sole state-changing entry point (spec 7.7).

M1 walking skeleton, cooperative tier only. FSM:
  INIT -> SNAPSHOT -> [BUILD -> VERIFY -> (FEEDBACK ->)]* ->
  CONVERGED -> COMPLETE_UNQUALIFIED | CAP_REACHED | ABORTED_BUILD_ERROR
"""
import argparse
import datetime
import json
import os
import secrets
import subprocess
import sys
import tempfile
import uuid

# DF-R6-06: the codebase uses PEP 604 (`X | None`) runtime annotations, which
# require Python >= 3.10. Enforce the floor HERE — before the df_* imports that
# would otherwise crash at import time with an opaque
# `TypeError: unsupported operand type(s) for |` on 3.9 — so an operator on an
# old interpreter gets an actionable message instead. (README/runbooks now name
# the supported interpreter; this is the fail-closed backstop.)
if sys.version_info < (3, 10):
    sys.stderr.write(
        "dark-factory requires Python 3.10 or newer (found "
        f"{sys.version_info.major}.{sys.version_info.minor}). Re-run with a 3.10+ "
        "interpreter, e.g. the repo virtualenv: `.venv/bin/python "
        "dark-factory/scripts/supervisor.py ...`.\n")
    raise SystemExit(2)

import df_audit
import df_audit_chain
import df_brownfield
import df_confine
import df_container
import df_creds
import df_custody
import df_evidence_bundle
import df_gates
import df_init
import df_modes
import df_notify
import df_override
import df_proxy
import df_qualify
import df_sandbox
import df_seal
import df_twins
import df_waiver
import snapshot_source
from df_common import atomic_write, canonical_json, sha256_file, sha256_str
from df_config import (
    _PROXY_PROVIDER_RULES,
    MANDATORY_TIERS,
    ConfigError,
    _adapter_provider,
    _disjoint,
    load_config,
)
from id_feedback import project_feedback
from run_scenarios import (
    OracleError,
    ScenarioBundleDrift,
    deny_network_incompatible_ids,
    load_scenarios,
    run_all,
)
from snapshot_source import SnapshotError, snapshot

# Facade re-exports. supervisor.py is the sole CLI entry point and the module the
# test-suite (and df_evidence_bundle) address by name — `supervisor.<name>` — so
# every top-level name that moved into a supervisor_* module is re-exported here.
# The suite also monkeypatches a fixed set of these names on THIS module (see
# supervisor_core._sup); that only works because the moved code calls them back
# through this namespace.
from supervisor_audit import (  # noqa: F401  (facade re-export, see above)
    CONTROL_ROOT_ID_FILE,
    CUSTODY_ATTESTATION_FILE,
    CUSTODY_SIGNATURES_FILE,
    _anchor_audit,
    _authenticate_manifest,
    _chain_checkpoint_key,
    _chain_completeness,
    _chain_dense_marker_key,
    _chain_length,
    _chain_sink_namespace,
    _checkpoint_chain_to_sink,
    _control_root_identity,
    _custody_config_bound,
    _key_fingerprint,
    _load_audit_key,
    _load_custody_signatures,
    _read_manifest_bytes,
    _run_security_gates,
    _satisfying_approvers,
    _verify_chain_untruncated,
    finalize_manifest,
    verify_chain_cmd,
)
from supervisor_core import (  # noqa: F401  (facade re-export, see above)
    _ARTIFACT_MISMATCH,
    _ARTIFACT_OK,
    _ARTIFACT_UNAVAILABLE,
    _ARTIFACT_UNBOUND,
    _CONFINED_CANDIDATE_NETWORK,
    _CONTAINER_TIERS,
    _ENTERPRISE_PROXY_HOST,
    _QUALIFYING_TIERS,
    BUILDER_RULES,
    FSM_CHAIN_FILE,
    PAUSED,
    SHIP_AUDIT_PENDING,
    SHIP_EVIDENCE_PENDING_EXIT,
    SHIP_STATE_UNAUTHENTICATED,
    SOURCE_IDENTITY_FILE,
    STATE_VERSION,
    SUPERSEDED_BY_FILE,
    UNKNOWN_OUTCOME,
    Journal,
    LockError,
    _adequacy_manifest_field,
    _budget_enforced,
    _budget_manifest_field,
    _candidate_egress_qualified,
    _chain_scenario_set_sha256,
    _check_manifest_artifact,
    _confine_manifest_field,
    _control_root_from_run_dir,
    _discard_validation_root,
    _dispatch_idempotency_key,
    _effective_image,
    _enforce_adapter_digests,
    _finalize_container_manifest,
    _fsm_chain_append,
    _fsm_chain_head,
    _fsm_chain_lines,
    _fsm_entry_hash,
    _image_resolved_from_journal,
    _init_scenario_set_sha256_from_journal,
    _journal_property_violations,
    _kb_writeback,
    _materialize_validation_root,
    _mode_from_journal,
    _notify_budget,
    _notify_spool_dir,
    _now,
    _object_store_root,
    _pin_effective_image,
    _property_manifest_field,
    _qualification_field,
    _read_critic_review,
    _redacted_write,
    _resolve_credentials,
    _resolved_dispatch_result,
    _resumable_state_seqs,
    _seal_workspace_artifact,
    _snapshot_sha256_from_journal,
    _state_integrity_payload,
    _unresolved_dispatch_intent,
    _usage_manifest_field,
    _validate_fsm_chain,
    _verify_manifest_status,
    acquire_lock,
    latest_paused_run,
    load_state,
    object_referenced,
    release_lock,
    save_state,
    verify_manifest,
    write_build_checkpoint_report,
    write_checkpoint_report,
    write_ship_checkpoint_report,
)
from supervisor_custody import (  # noqa: F401  (facade re-export, see above)
    _WAIVER_VERIFY_EXIT,
    WAIVER_ATTESTATION_FILE,
    WAIVER_SIGNATURES_FILE,
    _byte_verify_for_waiver,
    _effective_tier_of,
    _final_exam_ok,
    _kept_waiver_entries,
    _load_waiver_signatures,
    _now_utc,
    _precustody_substates,
    _push_qualification_offbox,
    _sink_readback,
    _sink_receipt_bound,
    _sink_required,
    _waiver_audit_key,
    _waiver_binding_from_manifest,
    attach_custody,
    attach_waiver,
    verify_custody_cmd,
    verify_waiver_cmd,
)
from supervisor_init import (  # noqa: F401  (facade re-export, see above)
    _author_once,
    _author_review_confirm,
    _critic_once,
    _empty_author_report,
    _init_prerequisite_lines,
    _init_report_lines,
    _install_authored_scenarios,
    author_scenarios_cmd,
    init_cmd,
)
from supervisor_isolation import (  # noqa: F401  (facade re-export, see above)
    _EGRESS_PROBE_DENIED_HOST,
    _HOST_ISOLATION_SOFT_RESIDUALS,
    _annotate_process_containment,
    _candidate_prefix_for_twins,
    _egress_probe_stub_handler,
    _host_isolation_preliminary,
    _host_isolation_qualified,
    _reserve_service_ports,
    _resolve_candidate_network_prefix,
    _seccomp_profile_ok,
    _service_ports_env,
    _stamp_loopback_outbound,
    _start_egress_probe_stub,
    _verify_enterprise_egress,
    resolve_candidate_prefix,
    resolve_isolation,
)
from supervisor_ship import (  # noqa: F401  (facade re-export, see above)
    RELEASE_APPROVAL_FILE,
    RELEASE_ATTESTATION_FILE,
    SHIP_JOURNAL_FILE,
    SHIP_RESULT_FILE,
    _anchor_ship_local,
    _authenticate_ship_actions,
    _authenticate_ship_chain,
    _dangling_signed_dispatch,
    _df_release_cli,
    _failed_ship_record_bound,
    _is_no_action_terminal,
    _journal_ship_seal,
    _load_release_attestation,
    _make_ship_action_committer,
    _max_ship_seq,
    _pending_ship_authenticated,
    _push_ship_offbox,
    _reconstruct_authenticated_ship_record,
    _record_ship_reentry_verified,
    _repair_ship_evidence,
    _resolution_key,
    _resolve_ship_action_creds,
    _rollback_resolution_key,
    _seal_ship_result,
    _ship_action_commit_payload,
    _ship_action_intent_payload,
    _ship_action_recovery_state,
    _ship_audit_retry,
    _ship_completed_action_facts,
    _ship_completed_actions,
    _ship_eligible,
    _ship_evidence_pending_entries,
    _ship_journal_events,
    _ship_phase,
    _ship_reconciled_payload,
    _ship_record_bytes,
    _ship_reentry_payload,
    _ship_rollback_payload,
    _ship_toolchain_identity,
    _terminal_anchor_pending_sha,
    _unresolved_ship_action,
    _verify_ship_transition_chain,
    attach_release,
    ship_cmd,
)

# Register this module under the name `supervisor` even when executed as a script
# (`python supervisor.py ...` runs it as `__main__`): the supervisor_* modules and
# df_evidence_bundle resolve the live supervisor namespace at call time via
# `import supervisor`, and this makes that the SAME module object rather than a
# second copy.
sys.modules.setdefault("supervisor", sys.modules[__name__])


def _supersede_parent(control_root, parent_run_id, child_run_id, redactor):
    """Mark a parent run superseded by a child spec-fork.

    Writes `<parent_run_dir>/superseded_by.json = {child_run_id, ts}` and appends
    a SUPERSEDED event to the parent's UNHASHED post-seal `audit_events.jsonl`
    (NEVER its sealed `journal.jsonl` — the parent's journal_sha256 is frozen in
    its manifest, so an append there would break the parent's verify-manifest).
    Supersession is provenance, not tampering: the parent still verifies clean
    (verify-manifest surfaces the supersession as a printed line, never a
    failure). Idempotent-ish: re-superseding overwrites the sidecar with the
    latest child (single-parent, single-supersessor model — the newest fork
    wins; the audit_events log keeps every SUPERSEDED for the full trail)."""
    parent_run_dir = os.path.join(control_root, "runs", parent_run_id)
    ts = _now()
    _redacted_write(os.path.join(parent_run_dir, SUPERSEDED_BY_FILE),
                    {"child_run_id": child_run_id, "ts": ts}, redactor)
    events_path = os.path.join(parent_run_dir, "audit_events.jsonl")
    data = {"child_run_id": child_run_id}
    if redactor is not None:
        data = redactor.redact_obj(data)
    line = canonical_json({"ts": ts, "state": "SUPERSEDED", "data": data})
    with open(events_path, "a", encoding="utf-8") as f:
        f.write(line + "\n")
        f.flush()
        os.fsync(f.fileno())


def fork_cmd(control_root: str, parent_run: str, allow_downgrade: bool = False) -> int:
    """`df-fork` — start a NEW run seeded FROM a PARENT run's sealed artifact
    object (M36b Part B), rather than an empty/greenfield workspace.

    Validate-before-materialize, fail-closed:
      - the parent must live under THIS control root's runs/ (its object lives in
        this control root's object store);
      - the parent's manifest must verify clean (`_verify_manifest_status` == OK
        — byte-integrity AND a bound artifact object that re-verifies by
        identity); a superseded parent still verifies OK, so a parent can be
        re-forked, but a tampered/unbound one is refused;
      - the parent must bind an artifact `object_id`.
    On success it records lineage on the child's manifest and marks the parent
    superseded (both handled inside the normal run path via `fork_seed`)."""
    control_root = os.path.abspath(control_root)
    try:
        cfg = load_config(control_root)
    except ConfigError as e:
        sys.stderr.write(f"dark-factory: config error: {e}\n")
        return 2
    cfg["_control_root"] = control_root

    parent_run_dir = os.path.abspath(parent_run)
    # The parent MUST be a run under this control root (its frozen object is in
    # this control root's object store; a cross-root fork has no object to
    # materialize). Enforce the <control_root>/runs/<id> layout.
    expected_parent = os.path.abspath(_control_root_from_run_dir(parent_run_dir) or "")
    if expected_parent != control_root:
        sys.stderr.write(
            f"dark-factory: --parent-run must be a run under {control_root}/runs "
            f"(got {parent_run_dir})\n")
        return 2
    parent_run_id = os.path.basename(parent_run_dir.rstrip(os.sep))

    mp = os.path.join(parent_run_dir, "manifest.json")
    if not os.path.isfile(mp):
        sys.stderr.write(f"dark-factory: parent run has no sealed manifest: {mp}\n")
        return 2
    try:
        with open(mp, encoding="utf-8") as f:
            parent_manifest = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        sys.stderr.write(f"dark-factory: cannot read parent manifest: {e}\n")
        return 2

    # Verify the parent clean. Load the audit key so verification is a real HMAC
    # signature check (not UNVERIFIED). Object store is this control root's.
    # DF-R9-08 (M80): the "is this signed?" decision MUST come from the config-signing
    # ANCHOR (`cfg._audit.signing`), NOT from the same-user-writable parent
    # `audit_signing` field alone — mirroring `_authenticate_manifest`'s
    # `signed = cfg.signing OR manifest.audit_signing`. Gating on the writable field
    # let a keyless control-root attacker DE-SIGN a genuinely-signed parent (flip
    # audit_signing:false + DELETE the manifest.hmac sidecar + recompute the plain
    # manifest.sha256) so vkey stayed None and _verify_manifest_status(key=None) read
    # the now-hmac-less manifest as OK — accepting a TAMPERED parent (e.g. artifact
    # repointed to a self-frozen malicious object) as "verified clean", forging
    # lineage and seeding the child from attacker bytes. With the config anchor, a
    # signed control root always loads the key → expect_sig True → the deleted/stale
    # HMAC yields UNVERIFIED/TAMPERED → refuse.
    # DF-R10-02 (M85): "was the parent signed?" must NOT be inferred from the two
    # SAME-USER-WRITABLE signals M80 used (cfg._audit.signing AND parent
    # manifest.audit_signing) — R10 defeated M80 by downgrading BOTH (standard tier
    # permits signing off). The historical signing state is read from the SIGNED AUDIT
    # CHAIN instead: a run that ran signed anchored a `source-identity` token for its
    # run_id (M76). If the chain proves the parent STARTED SIGNED, the fork REQUIRES the
    # parent manifest to authenticate under the audit key AND its exact bytes to be a
    # chain MEMBER, whatever the current config or writable manifest field now claim: a
    # signed parent cannot be forked as unsigned.
    #
    # TAMPER-EVIDENCE OF THE ANCHOR (accurate scope): df_audit_chain's linkage hash is
    # UNKEYED (only the per-entry `sig` is HMAC-bound), so a keyless same-user attacker
    # CAN excise the source-identity line and re-link the chain — `_run_started_signed`
    # (presence, key-free) would then read 'unsigned'. But excision SHORTENS the chain,
    # so the off-box sink's length checkpoint catches it: `_verify_chain_untruncated`
    # (step 1) refuses when the sink holds a longer committed length. The guarantee is
    # therefore SINK-CONDITIONAL, exactly like ship/source/state truncation detection
    # (M73/M76/M77): with a required, reachable sink the excision is caught; a sink-less
    # signed control root retains the documented detection-grade-best-effort residual
    # (enterprise mandates a required sink). M85 strictly NARROWS M80, which accepted
    # the chain-INTACT combined downgrade even with a sink.
    ok_tr, why_tr = _verify_chain_untruncated(cfg, control_root)
    if not ok_tr:
        sys.stderr.write(f"dark-factory: refusing to fork — the control root's signed audit "
                         f"chain could not be confirmed complete ({why_tr}); a truncation could "
                         "hide the parent's signing history.\n")
        return 2
    require_signed = (_run_started_signed(control_root, parent_run_id)
                      or bool(cfg.get("_audit", {}).get("signing"))
                      or parent_manifest.get("audit_signing"))
    vkey = None
    if require_signed:
        try:
            vkey = df_audit.load_key(cfg["_audit"].get("key_path"))
        except (df_audit.AuditKeyError, KeyError, TypeError) as e:
            sys.stderr.write(
                "dark-factory: refusing to fork — the parent run STARTED SIGNED (it holds "
                "signed anchors in the audit chain), but its audit key could not be loaded to "
                f"authenticate it ({e}). A signed parent cannot be forked as unsigned; restore "
                "audit.signing + key_path to fork it.\n")
            return 2
    status = _verify_manifest_status(
        parent_run_dir, key=vkey, object_store=_object_store_root(control_root))
    if status != _ARTIFACT_OK:
        sys.stderr.write(
            f"dark-factory: refusing to fork — parent run does not verify clean "
            f"(status: {status}). A fork must start from a verified parent artifact.\n")
        return 2
    if require_signed:
        # DF-R10-02: the exact parent-manifest bytes must be ANCHORED in the signed
        # chain — a genuine-but-de-signed or foreign manifest that somehow verified is
        # refused unless its digest is a chain member of THIS control root.
        _pm_bytes, _pm_sha = _read_manifest_bytes(parent_run_dir)
        try:
            _entries = df_audit_chain.read_chain(os.path.join(control_root, "audit-chain.jsonl"))
        except (df_audit_chain.ChainError, OSError):
            _entries = []
        if not any(e.get("manifest_sha256") == _pm_sha for e in _entries):
            sys.stderr.write(
                "dark-factory: refusing to fork — the parent manifest is not anchored in this "
                "control root's signed audit chain (its terminal anchor is absent or the "
                "manifest was replaced); a signed parent's manifest must be a chain member.\n")
            return 2

    artifact = parent_manifest.get("artifact")
    if not isinstance(artifact, dict) or not isinstance(artifact.get("object_id"), str):
        sys.stderr.write(
            "dark-factory: refusing to fork — parent manifest binds no artifact object_id "
            "(nothing to materialize).\n")
        return 2

    _pm_bytes, parent_manifest_sha256 = _read_manifest_bytes(parent_run_dir)
    fork_seed = {
        "parent_run_id": parent_run_id,
        "parent_artifact_object_id": artifact["object_id"],
        "parent_manifest_sha256": parent_manifest_sha256,
        "forked_at": _now(),
    }
    print(f"dark-factory: forking from parent {parent_run_id} "
          f"(artifact {artifact['object_id'][:12]}…); starting child run.")
    # A fork is a fresh run with a seeded workspace + recorded lineage; reuse the
    # whole normal run path (gates, isolation, build/verify loop). project_src is
    # None: the workspace comes from the parent object, not a source tree.
    return run(control_root, None, allow_downgrade=allow_downgrade, fork_seed=fork_seed)


def compose_prompt(spec_text: str, feedback) -> str:
    fb_block = (
        json.dumps(feedback, indent=2, sort_keys=True)
        if feedback is not None
        else "none — first iteration"
    )
    return (
        f"{BUILDER_RULES}\n## Specification\n{spec_text}\n"
        f"\n## Verification feedback (previous round; behavior IDs + taxonomy only)\n"
        f"{fb_block}\n"
    )


def invoke_adapter(adapter: str, role: str, workdir: str, prompt_file: str, timeout_s: int,
                   exec_prefix=None, env_extra=None, env_full=None, confine=False):
    """`env_full`, if given, is used INSTEAD of the inherit+merge below — it is
    the exact env dict the subprocess gets (e.g. df_creds.launcher_scoped_env's
    output, which STRIPS vars from os.environ; env_extra's dict(os.environ,
    **env_extra) merge can only add, never remove, so it cannot express a
    strip). `env_extra` behavior is unchanged when `env_full` is None (the
    verifier/twins path never sets env_full).

    `confine` (M14) is threaded into the request JSON as `confine`; adapters
    honor `req.get("confine")` (Task 1). Defaults False, so every pre-M14
    caller (and every test that monkeypatches this function with a
    pre-M14 signature and never sees the kwarg — the builder call site
    below only ever passes `confine=True` explicitly) is byte-identical."""
    req = {
        "adapter_protocol": "0.1",
        "role": role,
        "workdir": workdir,
        "prompt_file": prompt_file,
        "timeout_s": timeout_s,
        "confine": bool(confine),
    }
    argv = (list(exec_prefix) if exec_prefix else []) + [adapter]
    if env_full is not None:
        env = dict(env_full)
    else:
        env = dict(os.environ, **env_extra) if env_extra else None
    try:
        proc = subprocess.run(
            argv, input=json.dumps(req), capture_output=True, text=True,
            timeout=timeout_s + 60, env=env,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError, OSError) as e:
        return None, f"adapter spawn failed: {e}"
    if proc.returncode != 0:
        return None, f"adapter exited {proc.returncode}: {proc.stderr[-500:]}"
    try:
        resp = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None, f"adapter wrote unparseable stdout: {proc.stdout[-500:]}"
    if resp.get("adapter_protocol") != "0.1":
        return None, "adapter protocol mismatch"
    return resp, None


def _scenario_set_hash(scenarios_dir: str) -> str:
    # M91: enumerate EXACTLY the set `run_scenarios.load_scenarios` loads and executes —
    # `glob("*.json")`, which (unlike os.listdir+endswith) excludes leading-dot names — so
    # the run-start seal and the verifier's load-time digest can never diverge on a stray
    # dotfile and spuriously fail-closed (independent-audit LOW). "Seal exactly what you run."
    files = {
        name: sha256_file(os.path.join(scenarios_dir, name))
        for name in sorted(os.listdir(scenarios_dir))
        if name.endswith(".json") and not name.startswith(".")
    }
    return sha256_str(canonical_json(files))


def run(control_root: str, project_src, allow_downgrade: bool = False,
        fork_seed=None) -> int:
    control_root = os.path.abspath(control_root)
    try:
        cfg = load_config(control_root)
    except ConfigError as e:
        sys.stderr.write(f"dark-factory: config error: {e}\n")
        return 2
    cfg["_control_root"] = control_root

    # M40: a control root scaffolded pending an agent author has no scenarios
    # yet -- fail closed BEFORE touching the lock/run_dir. The barrier makes a
    # scenario-less run meaningless (nothing to verify against), so this is a
    # clean refusal naming the exact next step, not a silent no-op.
    if df_init.is_scenarios_pending(control_root):
        sys.stderr.write(
            "dark-factory: no scenarios; run author-scenarios first "
            f"(scenarios pending an author for {control_root})\n")
        return 2

    try:
        lock = acquire_lock(control_root)
    except LockError as e:
        sys.stderr.write(f"dark-factory: {e}\n")
        return 2
    try:
        return _run_locked(control_root, project_src, cfg, allow_downgrade, fork_seed=fork_seed)
    finally:
        release_lock(lock)


def _twin_manifest_field(cfg, scenarios):
    """Compute the additive `twin_evidence` manifest field (M12), or None if
    twins aren't enabled. Loads twin defs FRESH (cheap, pure, read-only) so
    `variants` reflects whatever is on disk right now; raises
    df_twins.TwinError if twins are enabled but the defs don't load -- the
    caller decides how to abort (mirrors the existing twin-precondition
    failure handling, `_twin_error_abort`).

    `observed_assertions` counts scenarios (either cohort) whose `then`
    carries a twin-evidence assertion key -- purely a property of the
    already-validated scenario set, independent of any twin ever starting.
    """
    if not cfg["_twins"]["enabled"]:
        return None
    defs = df_twins.load_defs(os.path.join(cfg["_control_root"], "twins"))
    observed_assertions = sum(
        1 for sc in scenarios
        if "twin_observed" in sc["then"] or "stdout_echoes_twin" in sc["then"]
    )
    return {
        "variants": any(d.get("supports_variants") for d in defs),
        "observed_assertions": observed_assertions,
    }


def _twins_manifest_field(cfg):
    """Compute the additive `twins` manifest field (M21), or None if twins
    aren't enabled. Loads twin defs FRESH (cheap, pure, read-only) --
    same "fresh + resume, every terminal" threading as `twin_evidence`
    (M12): computed right alongside it into manifest_base on both the
    fresh-run and resume paths, so it rides every subsequent
    `dict(mb_clean/manifest_base, ...)` terminal for free. Raises
    df_twins.TwinError exactly like `_twin_manifest_field` if twins are
    enabled but the defs don't load -- the caller handles it the same way
    (the existing twin-precondition abort).

    Each entry is `{"name", "fidelity", "verify_only_impl", "supports_variants"}`,
    sorted by name -- names/labels/flags only, straight from the def files;
    no twin response data (the barrier: twin behavior/responses never reach
    the builder, but names/labels/flags are plain audit metadata on the
    control-plane manifest).
    """
    if not cfg["_twins"]["enabled"]:
        return None
    defs = df_twins.load_defs(os.path.join(cfg["_control_root"], "twins"))
    return sorted(
        (
            {
                "name": d["name"],
                "fidelity": d.get("fidelity") or "",
                "verify_only_impl": bool(d.get("verify_launch")),
                "supports_variants": bool(d.get("supports_variants")),
            }
            for d in defs
        ),
        key=lambda t: t["name"],
    )


def _variant_seed_extra(twin_defs):
    """A fresh per-pass DF_TWIN_VARIANT_SEED extra_env dict, ONLY when at
    least one twin def declares supports_variants -- else None, which makes
    the caller's ts.reset(..., extra_env=None) byte-identical to the
    pre-M12 reset call. Build-phase ts.start is NEVER passed this (the
    builder must never see a seed); only the verifier's reset calls are."""
    if any(d.get("supports_variants") for d in (twin_defs or [])):
        return {"DF_TWIN_VARIANT_SEED": uuid.uuid4().hex}
    return None


def _source_identity_field():
    """DF-R6-07: the SKILL source revision, sealed into the terminal manifest so
    the production-evidence bundle can report a value BOUND to the run (HMAC-
    signed when the run is signed), never a `git rev-parse` performed at bundle
    assembly time (which reflects whatever the checkout is THEN, not what ran).

    Records the skill repo's HEAD commit, a DETERMINISTIC source-tree/content
    digest (DF-R7-04 — the commit alone does not identify uncommitted bytes, and
    two different working trees can share one commit), and a TRI-STATE
    cleanliness (`clean`: True / False / None-unknown). The `tree_digest` binds
    HEAD + the full uncommitted diff of tracked files + the untracked-file
    listing, so a resume under different bytes (even at the same commit) is
    detectable. Best-effort: a non-git checkout seals nulls, still an honest
    sealed statement. `clean` is None (UNKNOWN), never a false `True`/`False`,
    when a git command fails after rev-parse — the production gate treats
    unknown-cleanliness as not-production-ready. Never raises."""
    skill_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    commit, clean, tree_digest = None, None, None

    def _git(*args):
        return subprocess.run(["git", "-C", skill_dir, *args],
                              capture_output=True, text=True, timeout=15)
    try:
        r = _git("rev-parse", "HEAD")
        if r.returncode == 0:
            commit = r.stdout.strip()
            status = _git("status", "--porcelain")
            diff = _git("diff", "HEAD")            # tracked-file content changes
            if status.returncode == 0 and diff.returncode == 0:
                porcelain = status.stdout
                clean = not porcelain.strip()
                # DF-R7-04 (opus F3): `git diff HEAD` + `status --porcelain`
                # capture committed state + tracked-file content changes, but
                # UNTRACKED files appear by NAME only — their CONTENT is not
                # bound. Hash each untracked file's bytes so a new/changed
                # untracked source file changes the digest (the "identify all
                # code used" claim needs content, not just names).
                untracked = _git("ls-files", "--others", "--exclude-standard", "-z")
                untracked_digests = {}
                if untracked.returncode == 0 and untracked.stdout:
                    for rel in untracked.stdout.split("\0"):
                        if not rel:
                            continue
                        ap = os.path.join(skill_dir, rel)
                        untracked_digests[rel] = sha256_file(ap) if os.path.isfile(ap) else None
                tree_digest = sha256_str(
                    canonical_json({"commit": commit,
                                    "diff": diff.stdout,
                                    "status": porcelain,
                                    "untracked": untracked_digests}))
            # else: clean stays None (UNKNOWN) — a git failure is not "clean".
    except (OSError, subprocess.SubprocessError):
        pass
    # `dirty` kept for back-compat readers (== not clean); None-safe.
    dirty = (not clean) if clean is not None else None
    return {"commit": commit, "clean": clean, "dirty": dirty,
            "tree_digest": tree_digest}


def _source_identity_stable(cfg):
    """DF-R8-04: the CURRENT skill source identity, recomputed NOW, must be
    non-null AND equal to this run's sealed anchor (`cfg["_source_identity"]`,
    set at first dispatch and re-sealed on resume). Returns (ok, reason, si_now).

    This is the per-dispatch guard: the pre-M71 code computed the source identity
    ONCE at run setup and never re-checked it before each builder dispatch, so the
    control-plane/support bytes could change (or become unknown) between dispatches
    within one logical run and be restored before the final evidence seal. A git
    failure that makes the current digest UNKNOWN fails CLOSED here (never a silent
    proceed). A run that sealed NO tree digest (pre-M67 / non-git) has nothing to
    enforce — it is stable by definition (there is no anchor to drift from).

    DEPLOYMENT CONSTRAINT (opus review F3): the tree_digest hashes every
    non-gitignored UNTRACKED file under the skill checkout, so the `control_root`
    (whose run artifacts grow during the run) MUST live OUTSIDE the skill's git
    working tree, or be gitignored — otherwise the run's own writes register as
    source churn between dispatches and this guard seals a spurious SOURCE_DRIFT
    (fail-closed, never unsafe). The runbook + examples already place the control
    root outside the checkout."""
    anchor = cfg.get("_source_identity") or {}
    od = anchor.get("tree_digest")
    if od is None:
        return (True, "no sealed source-tree digest to enforce (legacy/non-git run)", None)
    si_now = _source_identity_field()
    nd = si_now.get("tree_digest")
    if nd is None:
        return (False, "the current skill source-tree digest is UNKNOWN (a git failure "
                "must fail closed, never dispatch)", si_now)
    if nd != od:
        return (False, "the skill SOURCE changed mid-run (sealed tree/content digest != "
                "current) — a logical run must execute under ONE source identity", si_now)
    return (True, "source identity stable", si_now)


def _source_identity_payload(run_id, si):
    """DF-R9-03: the canonical bytes whose sha256 is anchored as this run's SIGNED
    source-identity token at first dispatch. Binds the run_id + the FULL identity
    (commit / clean / dirty / tree_digest — the exact fields journaled as the
    SOURCE_IDENTITY event) so a resume can AUTHENTICATE the recovered journal event
    against the chain: a deleted or replaced event recomputes to a token that was
    never anchored."""
    return canonical_json({"kind": "source-identity", "run_id": run_id,
                           "commit": si.get("commit"), "clean": si.get("clean"),
                           "dirty": si.get("dirty"), "tree_digest": si.get("tree_digest")})


def _authenticated_source_identity(cfg, control_root, run_dir, run_id):
    """DF-R9-03: recover this run's ORIGINAL source identity AUTHENTICATED against
    the SIGNED audit chain. Returns (status, si_orig):

      "authenticated" — a source-identity token is anchored in the chain AND a
                        surviving journal SOURCE_IDENTITY event recomputes to it
                        (si_orig = that event's data);
      "tampered"      — signing is ON but authentication fails: a source token is
                        anchored with NO surviving journal event that recomputes to
                        it (DELETED/REPLACED event); OR the chain failed verification
                        / could not be confirmed untruncated; OR the chain holds NO
                        source token at all (the anchor — or the whole chain — was
                        deleted; a signed run always anchors at first dispatch or
                        fails closed there, so on RESUME an empty set is tampering)
                        → the caller FAILS CLOSED;
      "unanchored"    — signing is OFF or the key is unloadable: an unsigned / no-key
                        tier with no detection-grade guarantee → the caller uses the
                        tier-independent source_identity.json cross-check (best-effort,
                        unchanged for those runs).

    M71 recovered the original identity from the ordinary journal SOURCE_IDENTITY
    event ALONE. That event is same-user writable, so DELETING it made the resume
    drift-check no-op and DOWNGRADE to the legacy (no-enforcement) path under a
    drifted identity (DF-R9-03). The identity is now ALSO anchored into the signed
    chain at first dispatch; the chain is hash-linked + HMAC-signed, so an interior
    deletion of the anchor breaks verify_chain and a tail-truncation is caught by
    the off-box checkpoint probe — either way this returns "tampered", never
    "unanchored". Never raises."""
    if not bool(cfg.get("_audit", {}).get("signing")):
        return ("unanchored", None)
    try:
        key = df_audit.load_key(cfg.get("_audit", {}).get("key_path"))
    except (df_audit.AuditKeyError, KeyError, TypeError):
        return ("unanchored", None)  # no key → no detection-grade guarantee; legacy
    # DF-R9-04: a tail-truncation could have erased the source anchor while the
    # surviving prefix still verifies — treat an unconfirmed-untruncated REQUIRED
    # chain as tampered rather than reading a short chain as "unanchored" and
    # silently downgrading. No-op (ok) when no sink is configured.
    ok_tr, _why_tr = _verify_chain_untruncated(cfg, control_root)
    if not ok_tr:
        return ("tampered", None)
    chain_path = os.path.join(control_root, "audit-chain.jsonl")
    try:
        ok, _why = df_audit_chain.verify_chain(chain_path, key)
        if not ok:
            return ("tampered", None)
        entries = df_audit_chain.read_chain(chain_path)
    except df_audit_chain.ChainError:
        return ("tampered", None)
    pre = f"{run_id}.source-identity."
    anchored = {e.get("manifest_sha256") for e in entries
                if str(e.get("invocation", "")).startswith(pre)}
    if not anchored:
        # DF-R9-03 (opus re-review): verify_chain accepts a 0-entry chain as valid
        # ("OK: 0 entries"), so a signed run whose ENTIRE audit-chain.jsonl was
        # DELETED (not just truncated) reads with an empty anchor set — and an
        # earlier journal-event backstop was defeatable (the attacker strips the
        # SNAPSHOT/SOURCE_IDENTITY lines while leaving the rest, so the journal still
        # shows dispatch). This function is reached ONLY on RESUME (a paused run), and
        # a SIGNED run FAILS CLOSED at first dispatch if it cannot anchor its source
        # identity (SOURCE_ANCHOR_FAILED, _run_locked) — so EVERY paused signed run
        # provably HAS the anchor. An empty set on a signed run therefore means the
        # anchor — or the whole chain — was DELETED: fail closed, unconditionally, off
        # the chain (which the attacker cannot forge) rather than any strippable local
        # dispatch evidence. (A PRE-M76 signed run has no anchor either and also fails
        # closed on its first post-upgrade resume — an accepted one-time migration:
        # restart it under M76. The sink-configured case is already caught earlier by
        # _verify_chain_untruncated; this is the sink-less backstop.)
        return ("tampered", None)
    try:
        with open(os.path.join(run_dir, "journal.jsonl"), encoding="utf-8") as jf:
            for line in jf:
                try:
                    e = json.loads(line)
                except ValueError:
                    continue
                if e.get("state") == "SOURCE_IDENTITY":
                    data = e.get("data", {})
                    if sha256_str(_source_identity_payload(run_id, data)) in anchored:
                        return ("authenticated", data)
    except OSError:
        pass
    return ("tampered", None)


def _run_started_signed(control_root, run_id):
    """DF-R9-05 (M77): True iff this run anchored a source-identity token in the
    per-control-root audit chain — the tamper-evident proof that the run STARTED with
    `audit.signing` ON. Every SIGNED run anchors exactly this token at first dispatch
    (or FAILS CLOSED there — see _run_locked / SOURCE_ANCHOR_FAILED); a genuinely
    UNSIGNED run NEVER writes a `source-identity` entry (that anchor is gated on
    `audit.signing` at first dispatch — the ONLY writer of the `source-identity` kind),
    so the mere PRESENCE of a `{run_id}.source-identity.` entry is a reliable
    "started signed" signal.

    Keyed on PRESENCE, not on the `sig` field: `sig` is NOT part of `chain_hash`
    (df_audit_chain hashes only invocation/manifest_sha256/ts), so a control-root
    attacker could BLANK an honest anchor's `sig` — a write that does NOT break chain
    linkage — and a `sig`-based check would then read the run as unsigned and let the
    downgrade through. Presence-keying closes that: blanking `sig` leaves the entry
    present (still detected); to evade detection the attacker must DELETE the anchor
    line, which breaks the hash chain and (deleting the WHOLE chain) is the documented
    construction limit — a required off-box sink makes even that independently
    detectable. The attacker holds control-root read/write but NOT the HMAC key; a
    FORGED unsigned `source-identity` entry only causes a (safe) refuse of an unsigned
    resume, never a bypass.

    Read WITHOUT the audit key, straight off the raw chain lines (not read_chain): a
    malformed/corrupted OTHER line must not blind the detector to a present anchor, and
    a partly-corrupted chain that read_chain would reject entirely must still surface
    the anchor if it is there."""
    pre = f"{run_id}.source-identity."
    chain_path = os.path.join(control_root, "audit-chain.jsonl")
    try:
        with open(chain_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except ValueError:
                    continue
                if isinstance(e, dict) and str(e.get("invocation", "")).startswith(pre):
                    return True
    except OSError:
        pass
    return False


def _authenticate_resumable_state(cfg, control_root, run_dir, run_id, state):
    """DF-R9 (M77): AUTHENTICATE the loaded resumable checkpoint (state.json) against
    the SIGNED audit chain before resume trusts ANY of its control-plane decisions.
    Returns (ok, reason). SIGNED runs only — the caller gates on signing.

    The M36a FSM chain (fsm_chain.jsonl) is an UNSIGNED sha256 chain: a same-user
    writer (no audit key) can rewrite it wholesale AND set state.json's recorded head
    to match, so it detects accidental corruption, not tampering. And the security-
    critical fields it never bound — `build_approved_through` (forge it high to skip
    the before-build approval pause) and `builder_calls`/`estimated_usd` (forge them
    low to defeat the budget ceiling) — are trusted raw. Each state.json write now
    also anchors a SIGNED token binding its EXACT bytes at a monotonic seq; here we
    require the loaded checkpoint to BE that latest signed state:
      * the run has ≥1 anchored resumable-state token (else the anchor / whole audit
        chain was deleted, or the run predates M77 — fail closed, mirroring M76);
      * the loaded `state_seq` is the HIGHEST anchored seq (no replay of an older,
        lower-budget / lower-approval checkpoint);
      * the token for (run_id, state_seq, sha256(state.json now)) is anchored — any
        edited field changes the digest → no match → fail closed.

    RESIDUAL (opus M77 review; the inherited DF-R9-04/M73 truncatability, NOT new to
    this mechanism): anti-replay keys on the HIGHEST seq in the LOCAL chain, and a
    same-owner local chain is truncatable to any prefix that still verifies. So on a
    signed run WITHOUT a REQUIRED off-box sink, a same-user attacker can snapshot an
    early checkpoint (state.json + fsm_chain.jsonl + audit-chain.jsonl), let the run
    advance, then roll ALL of them back to that snapshot: the truncated chain's tip
    IS the restored state_seq and its digest matches, so resume authenticates a stale
    checkpoint — reverting the budget counters (repeatable → defeats the ceiling).
    build_approved_through can only be reverted to an OLDER (lower, safe-direction)
    value, so this is a BUDGET-integrity residual, not an approval-skip. It is CLOSED
    by a required, reachable off-box sink: _checkpoint_chain_to_sink keeps committed
    lengths dense, so `_verify_chain_untruncated` below probes length local+1, gets
    200, and fails closed on the truncation. This is the SAME sink-conditional
    boundary as ship-completion and source-identity truncation detection (M73/M76);
    the cross-pause budget-ceiling guarantee is therefore sink-conditional on a
    signed run, robust against in-place forgery + same-chain replay unconditionally.
    Never raises."""
    try:
        key = df_audit.load_key(cfg.get("_audit", {}).get("key_path"))
    except (df_audit.AuditKeyError, KeyError, TypeError):
        return (False, "the audit signing key required to authenticate the resumable "
                "checkpoint could not be loaded; refusing to resume (fail-closed)")
    # DF-R9-04 / M73: a tail-truncation could have erased the tip state anchor (or
    # rolled the whole chain back to an earlier prefix — the truncation-replay
    # residual above) while the surviving prefix still verifies — treat an
    # unconfirmed-untruncated REQUIRED chain as fail-closed. This is what makes the
    # cross-pause budget guarantee hold on a sink-backed signed run. No-op (ok) when
    # no sink is configured (the documented sink-conditional residual).
    ok_tr, why_tr = _verify_chain_untruncated(cfg, control_root)
    if not ok_tr:
        return (False, why_tr)
    chain_path = os.path.join(control_root, "audit-chain.jsonl")
    try:
        ok, why = df_audit_chain.verify_chain(chain_path, key)
        if not ok:
            return (False, f"the signed audit chain failed verification ({why}); refusing "
                    "to resume the recorded checkpoint (fail-closed)")
        entries = df_audit_chain.read_chain(chain_path)
    except df_audit_chain.ChainError as e:
        return (False, f"the audit chain is unreadable ({e}); refusing (fail-closed)")
    pre = f"{run_id}.resumable-state."
    anchored = {}  # seq -> anchored token digest
    for e in entries:
        inv = str(e.get("invocation", ""))
        if inv.startswith(pre) and inv[len(pre):].isdigit():
            anchored[int(inv[len(pre):])] = e.get("manifest_sha256")
    if not anchored:
        return (False, "this SIGNED run has NO anchored resumable-state token — the "
                "checkpoint integrity anchor (or the whole audit chain) was deleted, or the "
                "run predates M77; refusing to resume (fail-closed)")
    state_seq = state.get("state_seq")
    if not isinstance(state_seq, int) or isinstance(state_seq, bool):
        return (False, "the resumable checkpoint carries no integrity seq on a signed run "
                "(a forged or pre-M77 state.json); refusing to resume (fail-closed)")
    max_seq = max(anchored)
    if state_seq != max_seq:
        return (False, f"the resumable checkpoint is not the latest signed state (seq "
                f"{state_seq} != highest anchored {max_seq}) — an older checkpoint was "
                "replayed to revert budget/approval state; refusing to resume (fail-closed)")
    digest = sha256_file(os.path.join(run_dir, "state.json"))
    token = sha256_str(_state_integrity_payload(run_id, state_seq, digest))
    if token != anchored[max_seq]:
        return (False, "the resumable checkpoint's bytes do not match their SIGNED integrity "
                "anchor — state.json was edited after the pause (a forged build_approved_through, "
                "budget counter, FSM head, or phase); refusing to resume (fail-closed)")
    return (True, "resumable state authenticated against the signed chain")


def _builder_identity_field(cfg):
    """The sealed `builder_identity` manifest field (or None). Carries the
    operator-ASSERTED model_identity (DF-R4-09) AND — new for the R5 arbitration
    (DF-R5-03 class) — the DIGEST of every builder support file.

    A support file (e.g. df_confine.py, which the shipped CLI adapters import and
    EXECUTE in-container) contributes to the adapter's actual behavior, so an
    adapter's structural 'no agentic tool surface' guarantee is only as strong as
    those bytes. Sealing `{path, sha256}` for each into the terminal manifest makes
    the exact mounted support bytes auditable and bound to the run — a substituted
    support file changes the manifest. (Content pinning/refusal is a separate,
    optional control; this is the always-on evidence seal the arbitration requires:
    'every support file contributing to adapter behavior must be digest-bound and
    sealed'.) None when there is neither a model_identity nor any support file, so
    a control root with neither is byte-identical to pre-M60."""
    support = [
        {"path": sf, "sha256": (sha256_file(sf) if os.path.exists(sf) else None)}
        for sf in (cfg.get("_support_files") or [])
    ]
    model_identity = cfg.get("_builder_model_identity")
    if not support and not model_identity:
        return None
    field = {}
    if model_identity:
        field["model_identity"] = model_identity
    if support:
        field["support_files"] = support
    return field


def _is_sha256_hex(v):
    """True iff `v` is a 64-character hex sha256 string (DF-R7-02)."""
    return (isinstance(v, str) and len(v) == 64
            and all(c in "0123456789abcdefABCDEF" for c in v))


def _verify_support_files_at_dispatch(cfg, manifest_base, journal):
    """DF-R6-04: re-resolve and re-hash EVERY builder support file at the moment
    of dispatch, and refuse on any drift from the digest sealed into the manifest.

    M60 hashed the support files ONCE, when the manifest base was assembled —
    time-of-CHECK. The mount loops then re-checked only path disjointness, so a
    support file could change between the snapshot and the builder importing it
    (or between iterations): the sealed manifest would attest bytes that were
    NOT the bytes the builder executed. Because the shipped CLI adapters IMPORT
    these files in-container, that is an execution-path integrity gap, not just
    an evidence one.

    Fail-closed on drift, on a vanished/unreadable file, and on a type change
    (a path swapped to a directory hashes to None — the M60 seal recorded that
    honestly, but dispatching against it is refused here). Returns None when
    every file matches, else an error string; the caller raises SandboxError.
    """
    sealed = ((manifest_base.get("builder_identity") or {}).get("support_files") or [])
    # DF-R7-02: index by path AND count occurrences — a configured support file
    # must have EXACTLY ONE sealed entry (a duplicate or a missing entry is a
    # tampered/ambiguous seal, not a match).
    sealed_by_path = {}
    seal_count = {}
    for e in sealed:
        p = e.get("path")
        sealed_by_path[p] = e.get("sha256")
        seal_count[p] = seal_count.get(p, 0) + 1
    for sf in (cfg.get("_support_files") or []):
        expected = sealed_by_path.get(sf)
        # DF-R7-02: a null / missing / non-64-hex sealed digest is NOT a
        # "match anything" wildcard. The M60 seal records `sha256: null` for a
        # file that was a directory / unreadable at snapshot; dispatching a
        # builder against bytes the manifest does not actually attest is exactly
        # the bytes-used gap R6-04 set out to close. Require a real sealed
        # digest, exactly one entry, and actual == expected.
        if seal_count.get(sf, 0) != 1:
            journal.write("SUPPORT_FILE_SEAL_AMBIGUOUS_AT_DISPATCH", path=sf,
                          entries=seal_count.get(sf, 0))
            return (f"builder support file {sf} does not have exactly one sealed manifest "
                    f"entry ({seal_count.get(sf, 0)} found) — refusing to dispatch against "
                    "an ambiguous/missing seal")
        if not _is_sha256_hex(expected):
            journal.write("SUPPORT_FILE_SEAL_UNDIGESTED_AT_DISPATCH", path=sf,
                          sealed_sha256=expected)
            return (f"builder support file {sf} has no valid sealed sha256 "
                    f"(sealed {expected!r}) — the manifest attests no bytes for it; "
                    "refusing to mount bytes that cannot be verified")
        actual = sha256_file(sf) if os.path.isfile(sf) else None
        if actual is None:
            journal.write("SUPPORT_FILE_UNREADABLE_AT_DISPATCH", path=sf,
                          sealed_sha256=expected)
            return (f"builder support file {sf} is missing, unreadable, or no longer a "
                    "regular file at dispatch — refusing to mount bytes that cannot be "
                    "verified against the sealed manifest digest")
        if actual != expected:
            journal.write("SUPPORT_FILE_DRIFT_AT_DISPATCH", path=sf,
                          sealed_sha256=expected, actual_sha256=actual)
            return (f"builder support file {sf} CHANGED after it was sealed into the "
                    f"manifest (sealed {expected[:16]}…, now {actual[:16]}…) — refusing "
                    "to dispatch a builder that would import bytes the manifest does not "
                    "attest")
    return None


def _run_locked(control_root: str, project_src, cfg, allow_downgrade: bool = False,
                fork_seed=None) -> int:
    creds, redactor, creds_err = _resolve_credentials(cfg)
    if creds_err is not None:
        sys.stderr.write(f"dark-factory: credentials: {creds_err}\n")
        return 2

    invocation = _now().replace(":", "").replace("-", "") + "-" + uuid.uuid4().hex[:8]
    run_dir = os.path.join(control_root, "runs", invocation)
    os.makedirs(run_dir, exist_ok=True)
    journal = Journal(os.path.join(run_dir, "journal.jsonl"), redactor=redactor)

    # DF-R7-04: compute the source identity ONCE at run start, stash it on cfg
    # (so the fresh manifest seals it), persist it as the run-state anchor, AND
    # journal it. The JOURNAL (always present for any dispatched run, unlike the
    # per-pause manifest) is the reliable "this run tracked source identity"
    # signal + the original value the resume drift-check compares against.
    cfg["_source_identity"] = _source_identity_field()
    atomic_write(os.path.join(run_dir, SOURCE_IDENTITY_FILE),
                 canonical_json(cfg["_source_identity"]))
    # (the SOURCE_IDENTITY journal event is written after SNAPSHOT below, so the
    #  documented INIT -> GATE_PASSED -> SNAPSHOT journal prefix is preserved.)

    audit_key, audit_err = _load_audit_key(cfg, journal)
    if audit_err is not None:
        return audit_err

    spec_path = os.path.join(control_root, "spec.md")
    if not os.path.exists(spec_path):
        sys.stderr.write(f"dark-factory: missing spec: {spec_path}\n")
        return 2
    spec_text = open(spec_path, encoding="utf-8").read()
    scenarios_dir = os.path.join(control_root, "scenarios")
    if not os.path.isdir(scenarios_dir) or not any(
        n.endswith(".json") for n in os.listdir(scenarios_dir)
    ):
        sys.stderr.write(f"dark-factory: no scenarios in {scenarios_dir}\n")
        return 2
    adapter = cfg["roles"]["builder"]["adapter"]
    timeout_s = cfg["roles"]["builder"].get("timeout_s", 600)
    cli = os.path.basename(adapter)

    # M47 condition #7: authenticate every pinned adapter by CONTENT before the
    # run touches it -- fail closed on any mismatch (or missing file).
    _digest_err = _enforce_adapter_digests(cfg, journal)
    if _digest_err is not None:
        sys.stderr.write(f"dark-factory: {_digest_err}\n")
        return 2

    journal.write(
        "INIT",
        invocation=invocation,
        tier=cfg["assurance"],
        qualified=cfg["_qualified"],
        config_sha256=cfg["_config_sha256"],
        spec_sha256=sha256_str(spec_text),
        scenario_set_sha256=_scenario_set_hash(scenarios_dir),
        adapter=adapter,
        adapter_sha256=sha256_file(adapter) if os.path.exists(adapter) else None,
    )

    # M22 Task 2: at run start, flush any events a PRIOR run spooled (durable
    # notification only — absent notification_durable this is a no-op branch,
    # byte-identical to pre-M22). Fail-soft like everything else in
    # df_notify: flush_spool never raises, an unreachable sink just leaves
    # the counts where they were and the run proceeds unaffected either way.
    _budget_cfg = cfg["_budget"]
    if _budget_cfg.get("notification_durable") and _budget_cfg["notification_sink"]:
        _flush_result = df_notify.flush_spool(
            _budget_cfg["notification_sink"], _notify_spool_dir(cfg), redactor=redactor,
        )
        journal.write(
            "NOTIFY_FLUSH",
            flushed=_flush_result["flushed"],
            remaining=_flush_result["remaining"],
        )

    manifest_base = {
        "invocation": invocation,
        "tier": cfg["assurance"],
        # Additive (M27 Task 2, spec §7.4): config-time-known, so it's on
        # every terminal manifest including every pre-build abort branch —
        # same "additive, present as soon as it's knowable" pattern as
        # `credentials`/`mode`/`builder_confinement`.
        "candidate_network": cfg["candidate_network"],
        # Additive (M29b, DF-02 host-read half): seeded with the config-known
        # preliminary (probed=False) so every terminal manifest carries it;
        # replaced with the live-probed truth right after
        # resolve_candidate_prefix below.
        "host_isolation": _host_isolation_preliminary(cfg),
        "qualified": cfg["_qualified"],
        "config_sha256": cfg["_config_sha256"],
        "spec_sha256": sha256_str(spec_text),
        "scenario_set_sha256": _scenario_set_hash(scenarios_dir),
        "adapter_sha256": sha256_file(adapter) if os.path.exists(adapter) else None,
        # Additive (M11), names/allowlist only — NEVER values — on every
        # terminal manifest since manifest_base feeds every `dict(manifest_base,
        # outcome=...)` branch below, including the pre-build gate aborts.
        "credentials": ({"source": cfg["_credentials"]["source"],
                        "allowlist": list(cfg["_credentials"]["allowlist"])}
                       if cfg["_credentials"] else None),
        # Additive (M15): seeded here — like `credentials` — so EVERY terminal
        # manifest carries mode/characterization, including the five pre-build
        # abort branches below (they finalize BEFORE detection runs). Detection
        # hasn't happened yet, so the honest seed is "unknown"; the real values
        # overwrite these once detect_mode + characterize complete (after
        # isolation is resolved). `probes` is knowable now (config-time), the
        # rest is not until we snapshot + detect.
        "mode": "unknown",
        "characterization": {
            "probes": len(cfg["_brownfield"]["probes"]),
            "generated": 0,
            "note": "not yet characterized (aborted before build)",
            "legacy_ignored": False,
        },
        # Additive (M14): seeded here — like `credentials` — so EVERY terminal
        # manifest carries builder_confinement, including every pre-build
        # abort branch below. Unlike `mode`, this is fully knowable at
        # config-load time (cfg["_confine"] + the adapter's cli basename),
        # no "unknown" placeholder needed; a required+unsupported refusal or
        # a not-required WARN fallback overrides it later via mb_clean once
        # the builder is actually invoked (_run_loop). DF-R3-05: pass the
        # resolved builder adapter path + its optional pinned digest so a
        # structural api_* claim is bound to the shipped-adapter identity.
        "builder_confinement": _confine_manifest_field(
            cfg["_confine"], cli, adapter, cfg["_adapter_digests"]["builder"]),
        # Additive (M17 Task 3): seeded None here — like `credentials`/`mode`/
        # `builder_confinement` — so EVERY terminal manifest carries
        # custody/proxy/enterprise_egress, including every pre-build abort
        # branch below (all enterprise-only concepts; None at every
        # non-enterprise tier, and at enterprise for any terminal reached
        # before the proxy has even started). `proxy`/`enterprise_egress`
        # are overridden by _run_loop's CONVERGED branch (probe passed) AND
        # (DF-05/M32) by the EGRESS_PROBE_FAILED terminal — the one other
        # place a real (failing) probe result exists to report; `custody`
        # stays CONVERGED-only (custody is never evaluated before that gate).
        "custody": None,
        "proxy": None,
        "enterprise_egress": None,
        # Additive (M22 Task 1): same "None unless CONVERGED at enterprise"
        # threading as enterprise_egress — overridden below only once the
        # enterprise resolve's LIVE seccomp probe has actually verified True
        # (resolve_isolation never returns "enterprise" otherwise).
        "enterprise_seccomp": None,
        # Additive (DF-01/M28a Task 2): same "None unless overridden"
        # threading as custody/proxy/enterprise_egress — seeded here so
        # EVERY terminal manifest carries `artifact`, including every
        # pre-workspace abort branch below (mirrors how `snapshot_sha256`
        # is seeded None until a workspace actually exists). Only
        # overridden, in `_run_loop`, on the terminals reached AFTER the
        # converged workspace has been successfully frozen into the
        # content-addressed object store (CONVERGED, FINAL_EXAM_FAILED,
        # SECURITY_GATE_FAILED) — never on ARTIFACT_UNHASHABLE or any
        # earlier terminal, where no trustworthy object_id exists yet.
        "artifact": None,
        # Additive (M36b Part B): spec-fork lineage. None for an ordinary
        # (non-forked) run; set below from `fork_seed` to
        # {parent_run_id, parent_artifact_object_id, parent_manifest_sha256,
        # forked_at} so EVERY terminal manifest of a forked child records its
        # provenance.
        "lineage": fork_seed if fork_seed else None,
        # Additive (M40): if the hidden scenarios were written by an AGENT
        # author (roles.author configured), record WHICH independent adapter and
        # whether the distinct-adapter-identity guarantee was waived -- so an
        # audit shows the scenarios were agent-written, by which adapter, and
        # (fail-open on snooping only under an explicit ack) the same_model_ack.
        # None for a human-authored control root (no roles.author) -- byte-
        # identical to pre-M40 on every terminal manifest, including pre-build
        # aborts. Config-known, so seeded here alongside credentials/mode/custody.
        # DF-R3-04 (M50): `model_identity` (or None) is the operator-ASSERTED,
        # NOT system-verified model string, sealed VERBATIM for an auditor.
        "authored_by": (
            {"adapter": cfg["_author"]["adapter"],
             "adapter_sha256": (sha256_file(cfg["_author"]["adapter"])
                                if os.path.exists(cfg["_author"]["adapter"]) else None),
             "same_model_ack": cfg["_author"]["same_model_ack"],
             "model_identity": cfg["_author"]["model_identity"]}
            if cfg.get("_author") else None
        ),
        # Additive (M42): the decorrelated CRITIC role (or None), sealed exactly
        # like authored_by -- which independent adapter reviewed the authored
        # scenarios and whether the two distinct-adapter-identity inequalities
        # were waived. None for a control root with no roles.critic (byte-
        # identical to pre-M42 on every terminal manifest). DF-R3-04 (M50):
        # `model_identity` is operator-ASSERTED, not system-verified.
        "critic": (
            {"adapter": cfg["_critic"]["adapter"],
             "adapter_sha256": (sha256_file(cfg["_critic"]["adapter"])
                                if os.path.exists(cfg["_critic"]["adapter"]) else None),
             "same_model_ack": cfg["_critic"]["same_model_ack"],
             "model_identity": cfg["_critic"]["model_identity"]}
            if cfg.get("_critic") else None
        ),
        # DF-R4-09 (M55): the BUILDER's operator-ASSERTED model_identity (or None),
        # sealed VERBATIM so an auditor can compare all three roles' declared
        # identities from the terminal manifest. Operator-ASSERTED, NOT system-
        # verified (a black-box API key can reach any model — same caveat as
        # authored_by/critic model_identity). Absent -> None -> byte-identical
        # manifest to pre-M55.
        "builder_identity": _builder_identity_field(cfg),
        # DF-R6-07: the SKILL source revision, sealed so the evidence bundle
        # reports a value BOUND to the run, not a post-hoc rev-parse.
        "source_identity": cfg.get("_source_identity") or _source_identity_field(),
    }

    # --- Pre-build gate (M7): mutation validation + coverage traceability,
    # entirely control-plane, BEFORE any builder invocation — a gate failure
    # journals + finalizes a GATE_FAILED manifest and returns 2 with no build
    # ever run. Fresh run ONLY: a resumed run already passed this gate once;
    # resume() recomputes the same deterministic coverage/oracle fields for
    # its manifests instead of re-running (and re-failing) the gate.
    try:
        scenarios = load_scenarios(scenarios_dir)
    except OracleError as e:
        journal.write("ABORTED_BUILD_ERROR", iteration=0, detail=f"invalid scenarios: {e}")
        mf = dict(manifest_base, outcome="ABORTED_BUILD_ERROR", iterations=0, qualified=False,
                  sandbox_backend=None, denial_probe_passed=False, snapshot_sha256=None,
                  final_exam={"ran": False, "passed": None, "count": 0}, regressions=[],
                  security={"checked": False}, container=None,
                  budget=_budget_manifest_field(cfg["_budget"], 0, 0.0),
                  usage=_usage_manifest_field(cfg["_budget"], False, 0, 0))
        digest = finalize_manifest(run_dir, mf, audit_key=audit_key, redactor=redactor)
        anchor_exit = _anchor_audit(cfg, cfg["_control_root"], run_dir, mf["invocation"],
                                    digest, audit_key, journal)
        _kb_writeback(cfg, journal, mf, [])
        sys.stderr.write(f"dark-factory: {e}\n")
        return anchor_exit or 2

    # M27 Task 2 (spec §7.4): candidate_network=="deny" would make the
    # candidate's OWN http server unreachable to the verifier -- an http
    # scenario polls the candidate over 127.0.0.1, which "deny" blocks too
    # (only "loopback" keeps 127.0.0.1 reachable). Refuse before any build
    # ever runs, naming every offending scenario id. This is a pure
    # scenario-content check, so it belongs here (where scenarios are
    # already loaded) rather than at config-load time (df_config never
    # reads scenarios).
    if cfg["candidate_network"] == "deny":
        # DF-R5-05: the deny-vs-http rule is the SHARED validator in
        # run_scenarios (df_init.validate_scaffold runs the same call), so a
        # scaffold that init blessed can never fail THIS gate.
        http_scenario_ids = deny_network_incompatible_ids(scenarios)
        if http_scenario_ids:
            journal.write("CANDIDATE_NETWORK_GATE_FAILED", scenarios=http_scenario_ids)
            mf = dict(manifest_base, outcome="GATE_FAILED", iterations=0, qualified=False,
                      sandbox_backend=None, denial_probe_passed=False, snapshot_sha256=None,
                      final_exam={"ran": False, "passed": None, "count": 0}, regressions=[],
                      security={"checked": False}, container=None,
                      budget=_budget_manifest_field(cfg["_budget"], 0, 0.0),
                      usage=_usage_manifest_field(cfg["_budget"], False, 0, 0))
            digest = finalize_manifest(run_dir, mf, audit_key=audit_key, redactor=redactor)
            anchor_exit = _anchor_audit(cfg, cfg["_control_root"], run_dir, mf["invocation"],
                                        digest, audit_key, journal)
            _kb_writeback(cfg, journal, mf, [])
            sys.stderr.write(
                f"dark-factory: pre-build gate FAILED — candidate_network 'deny' would make "
                f"http scenario(s) unreachable, no build was run: "
                f"{', '.join(http_scenario_ids)}\n"
            )
            return anchor_exit or 2

    # Mutation validation first (order matters: an inert oracle is a more
    # fundamental defect than a coverage gap, and coverage hasn't been
    # computed yet, so its manifest field is honestly {"checked": False}).
    inert = df_gates.validate_oracle(scenarios)
    if inert:
        journal.write("ORACLE_GATE_FAILED", inert=inert)
        mf = dict(manifest_base, outcome="GATE_FAILED", iterations=0, qualified=False,
                  sandbox_backend=None, denial_probe_passed=False, snapshot_sha256=None,
                  final_exam={"ran": False, "passed": None, "count": 0}, regressions=[],
                  oracle={"mutation_validated": False, "inert": inert},
                  coverage={"checked": False},
                  security={"checked": False}, container=None,
                  budget=_budget_manifest_field(cfg["_budget"], 0, 0.0),
                  usage=_usage_manifest_field(cfg["_budget"], False, 0, 0))
        digest = finalize_manifest(run_dir, mf, audit_key=audit_key, redactor=redactor)
        anchor_exit = _anchor_audit(cfg, cfg["_control_root"], run_dir, mf["invocation"],
                                    digest, audit_key, journal)
        _kb_writeback(cfg, journal, mf, [])
        sys.stderr.write(
            f"dark-factory: pre-build gate FAILED — {len(inert)} inert (non-discriminating) "
            f"scenario oracle(s), no build was run: {', '.join(inert)}\n"
        )
        return anchor_exit or 2

    try:
        behaviors = df_gates.load_behaviors(control_root)
    except df_gates.GateError as e:
        journal.write("GATE_ERROR", detail=str(e))
        sys.stderr.write(f"dark-factory: behaviors.json error: {e}\n")
        return 2

    if behaviors is not None:
        cov = df_gates.check_coverage(behaviors, scenarios)
        if cov["uncovered_dev"] or cov["orphan_scenarios"]:
            journal.write("COVERAGE_GATE_FAILED", uncovered=cov["uncovered_dev"],
                          orphans=cov["orphan_scenarios"])
            mf = dict(manifest_base, outcome="GATE_FAILED", iterations=0, qualified=False,
                      sandbox_backend=None, denial_probe_passed=False, snapshot_sha256=None,
                      final_exam={"ran": False, "passed": None, "count": 0}, regressions=[],
                      oracle={"mutation_validated": True, "inert": []}, coverage=cov,
                      security={"checked": False}, container=None,
                      budget=_budget_manifest_field(cfg["_budget"], 0, 0.0),
                      usage=_usage_manifest_field(cfg["_budget"], False, 0, 0))
            digest = finalize_manifest(run_dir, mf, audit_key=audit_key, redactor=redactor)
            anchor_exit = _anchor_audit(cfg, cfg["_control_root"], run_dir, mf["invocation"],
                                        digest, audit_key, journal)
            _kb_writeback(cfg, journal, mf, [])
            sys.stderr.write(
                f"dark-factory: pre-build gate FAILED — coverage gap, no build was run: "
                f"uncovered_dev={cov['uncovered_dev']} orphan_scenarios={cov['orphan_scenarios']}\n"
            )
            return anchor_exit or 2
    else:
        cov = {"checked": False}

    # --- Adequacy gate (M42): class-typed coverage per the resolved policy,
    # for BOTH human- and agent-authored scenarios. Runs HERE in the M7 slot
    # (before any build), after coverage (a class gap is a finer defect than a
    # missing behavior). Needs behaviors.json to key per-behavior classes on;
    # absent -> honest {"checked": False} and no gate (the default happy-only
    # policy is satisfied by every scenario anyway). The sharpness battery
    # already ran as the oracle gate above (validate_oracle is now battery-
    # backed); the adequacy manifest field records both.
    policy = cfg["_adequacy"]
    if behaviors is not None:
        adq = df_gates.check_adequacy(behaviors, scenarios, policy)
        if adq["under_covered"]:
            journal.write("ADEQUACY_GATE_FAILED",
                          required_classes=policy["required_classes"],
                          under_covered=adq["under_covered"])
            mf = dict(manifest_base, outcome="GATE_FAILED", iterations=0, qualified=False,
                      sandbox_backend=None, denial_probe_passed=False, snapshot_sha256=None,
                      final_exam={"ran": False, "passed": None, "count": 0}, regressions=[],
                      oracle={"mutation_validated": True, "inert": []}, coverage=cov,
                      adequacy=_adequacy_manifest_field(cfg, behaviors, scenarios),
                      security={"checked": False}, container=None,
                      budget=_budget_manifest_field(cfg["_budget"], 0, 0.0),
                      usage=_usage_manifest_field(cfg["_budget"], False, 0, 0))
            digest = finalize_manifest(run_dir, mf, audit_key=audit_key, redactor=redactor)
            anchor_exit = _anchor_audit(cfg, cfg["_control_root"], run_dir, mf["invocation"],
                                        digest, audit_key, journal)
            _kb_writeback(cfg, journal, mf, [])
            sys.stderr.write(
                f"dark-factory: pre-build gate FAILED — scenario adequacy gap "
                f"(required classes {policy['required_classes']}), no build was run: "
                f"{adq['under_covered']}\n"
            )
            return anchor_exit or 2

    journal.write("GATE_PASSED", coverage_checked=cov["checked"], scenarios=len(scenarios))
    manifest_base["coverage"] = cov
    manifest_base["oracle"] = {"mutation_validated": True, "inert": []}
    # M42: the auditable adequacy record (class coverage + sharpness battery +
    # decorrelated-critic outcome), threaded onto every terminal from here on.
    manifest_base["adequacy"] = _adequacy_manifest_field(cfg, behaviors, scenarios)
    # M43a: per-property-scenario {cases, seed, invariant} (reproducibility)
    # plus the shared in-place `violations` audit list -- see
    # _property_manifest_field. Empty-but-present when no property scenarios
    # exist (additive; run/http-only control roots gain a benign field).
    manifest_base["property"] = _property_manifest_field(scenarios)
    # M9 default: {"checked": False} threads into every terminal manifest via
    # mb_clean unless the CONVERGED path overrides it with the real gate
    # report (gates only run after dev converges + final exam passes).
    manifest_base["security"] = {"checked": False}

    # M12: twin_evidence manifest field, computed here (scenarios validated,
    # nothing built yet) so it's on every terminal manifest from this point
    # on -- the same "additive, present as soon as it's knowable" pattern as
    # `credentials` (M11). A load failure here is a twin precondition
    # failure exactly like the one _twin_error_abort handles inside the
    # build/verify loop, just caught before any build is attempted.
    try:
        manifest_base["twin_evidence"] = _twin_manifest_field(cfg, scenarios)
        # M21: `twins` (name/fidelity/verify_only_impl/supports_variants)
        # computed alongside `twin_evidence`, same fail-closed handling below.
        manifest_base["twins"] = _twins_manifest_field(cfg)
    except df_twins.TwinError as e:
        journal.write("TWIN_ERROR", iteration=0, detail=str(e))
        mf = dict(manifest_base, outcome="ABORTED_BUILD_ERROR", iterations=0, qualified=False,
                  sandbox_backend=None, denial_probe_passed=False, snapshot_sha256=None,
                  final_exam={"ran": False, "passed": None, "count": 0}, regressions=[],
                  container=None, twin_evidence=None, twins=None,
                  budget=_budget_manifest_field(cfg["_budget"], 0, 0.0),
                  usage=_usage_manifest_field(cfg["_budget"], False, 0, 0))
        digest = finalize_manifest(run_dir, mf, audit_key=audit_key, redactor=redactor)
        anchor_exit = _anchor_audit(cfg, cfg["_control_root"], run_dir, mf["invocation"],
                                    digest, audit_key, journal)
        _kb_writeback(cfg, journal, mf, [])
        sys.stderr.write(f"dark-factory: twin precondition failed: {e}\n")
        return anchor_exit or 2

    workspace = os.path.join(cfg["workspace_root"], invocation)
    if fork_seed:
        # M36b Part B: a spec-fork seeds the child workspace FROM the parent's
        # frozen, content-addressed artifact object (validate-before-materialize
        # inside df_seal.materialize_object: it re-verifies the object against
        # its sidecar and refuses on any drift). The parent was already verified
        # clean by fork_cmd BEFORE the lock; this re-verify is the fail-closed
        # net for any drift since. `snapshot_sha256` is computed over the
        # materialized tree so the child's provenance is auditable. Parent
        # supersession is recorded only AFTER a successful materialize (the fork
        # genuinely happened) — into the parent's UNHASHED post-seal event log +
        # a sidecar, never its sealed journal.jsonl (which would break the
        # parent's verify-manifest).
        os.makedirs(workspace, exist_ok=True)
        try:
            df_seal.materialize_object(
                _object_store_root(control_root),
                fork_seed["parent_artifact_object_id"], workspace)
            manifest = snapshot_source.build_manifest(workspace)
            snap_hash = sha256_str(canonical_json(manifest))
        except (df_seal.SealError, SnapshotError) as e:
            journal.write("FORK_MATERIALIZE_FAILED", detail=str(e),
                          parent_run_id=fork_seed.get("parent_run_id"))
            mf = dict(manifest_base, outcome="ABORTED_BUILD_ERROR", iterations=0,
                      snapshot_sha256=None, qualified=False,
                      sandbox_backend=None, denial_probe_passed=False,
                      final_exam={"ran": False, "passed": None, "count": 0},
                      regressions=[], container=None,
                      budget=_budget_manifest_field(cfg["_budget"], 0, 0.0),
                      usage=_usage_manifest_field(cfg["_budget"], False, 0, 0))
            digest = finalize_manifest(run_dir, mf, audit_key=audit_key, redactor=redactor)
            anchor_exit = _anchor_audit(cfg, cfg["_control_root"], run_dir, mf["invocation"],
                                        digest, audit_key, journal)
            _kb_writeback(cfg, journal, mf, [])
            sys.stderr.write(f"dark-factory: fork materialize failed: {e}\n")
            return anchor_exit or 2
        _supersede_parent(control_root, fork_seed["parent_run_id"], invocation, redactor)
        journal.write("FORKED", parent_run_id=fork_seed["parent_run_id"],
                      parent_artifact_object_id=fork_seed["parent_artifact_object_id"],
                      parent_manifest_sha256=fork_seed["parent_manifest_sha256"])
    elif project_src:
        try:
            manifest, snap_hash = snapshot(project_src, workspace)
        except SnapshotError as e:
            journal.write("ABORTED_BUILD_ERROR", iteration=0, detail=f"snapshot failed: {e}")
            mf = dict(manifest_base, outcome="ABORTED_BUILD_ERROR", iterations=0,
                      snapshot_sha256=None, qualified=False,
                      sandbox_backend=None, denial_probe_passed=False,
                      final_exam={"ran": False, "passed": None, "count": 0},
                      regressions=[], container=None,
                      budget=_budget_manifest_field(cfg["_budget"], 0, 0.0),
                      usage=_usage_manifest_field(cfg["_budget"], False, 0, 0))
            digest = finalize_manifest(run_dir, mf, audit_key=audit_key, redactor=redactor)
            anchor_exit = _anchor_audit(cfg, cfg["_control_root"], run_dir, mf["invocation"],
                                        digest, audit_key, journal)
            _kb_writeback(cfg, journal, mf, [])
            sys.stderr.write(f"dark-factory: {e}\n")
            return anchor_exit or 2
    else:
        os.makedirs(workspace, exist_ok=True)
        manifest, snap_hash = {"manifest_version": "0.1", "files": []}, sha256_str(
            canonical_json({"manifest_version": "0.1", "files": []})
        )
    atomic_write(os.path.join(workspace, "spec.md"), spec_text)
    journal.write("SNAPSHOT", workspace=workspace, snapshot_sha256=snap_hash,
                  file_count=len(manifest["files"]))
    # DF-R7-04: journal the source identity (pre-dispatch, after SNAPSHOT so the
    # INIT->GATE_PASSED->SNAPSHOT prefix is preserved). The resume drift-check
    # reads this event; its presence marks an M67-era source-tracked run.
    journal.write("SOURCE_IDENTITY", **cfg["_source_identity"])
    # DF-R9-03: on a SIGNED run, ALSO anchor the source identity into the signed
    # audit chain so a resume AUTHENTICATES it (see _authenticated_source_identity).
    # The journal event alone is same-user writable — deleting/replacing it
    # downgraded resume to the legacy no-enforcement path; the chain anchor makes
    # that fail closed even if source_identity.json is also deleted. Only when
    # signing is ON: the chain is a trust boundary only when signed, and an unsigned
    # run's chain must not be polluted with an unauthenticated marker (unsigned tiers
    # rely on the source_identity.json cross-check in resume).
    #
    # DF-R9-03 (opus re-review): this anchor is a signed run's authenticator-of-
    # record for its source identity across EVERY resume. So if it cannot be
    # committed, FAIL CLOSED HERE at first dispatch (before any builder work) — do
    # NOT proceed to a paused state a later resume could not tell apart from a
    # DELETED-anchor tamper (a signed run with no anchor is, at resume, exactly the
    # tamper signature). Failing closed here means every paused/resumable signed run
    # provably HAS the anchor, so resume can treat "signed run, no source token" as
    # tampering with no benign exception. The key/chain is broken (append or key-load
    # failed); fix it and start a fresh run — no builder work has run yet.
    if bool(cfg.get("_audit", {}).get("signing")):
        _src_anchor = _anchor_ship_local(
            cfg, control_root, invocation,
            _source_identity_payload(invocation, cfg["_source_identity"]),
            "source-identity")
        if _src_anchor != "anchored":
            journal.write("SOURCE_ANCHOR_FAILED",
                          commit=cfg["_source_identity"].get("commit"))
            sys.stderr.write(
                "dark-factory: refusing to proceed (fail-closed) — this SIGNED run could not "
                "anchor its source identity into the audit chain at first dispatch (the signing "
                "key or a chain append failed), so the run could never be authenticated on "
                "resume. Fix the audit key/chain and start a fresh run (no builder work has "
                "run).\n")
            return 2
    manifest_base["snapshot_sha256"] = snap_hash

    # DF-R5-09: pin the image identity BEFORE resolve_isolation — its container
    # probes are the FIRST _effective_image consumers, so the pin must already
    # be seeded (fresh: resolve+journal; nothing yet to reuse) or the probe and
    # the later dispatch could disagree on which image bytes they exercised.
    _pin_effective_image(cfg, run_dir, journal)
    try:
        eff_tier, exec_prefix, backend_name, probe_passed = resolve_isolation(
            cfg, control_root, workspace, journal, allow_downgrade)
    except df_sandbox.SandboxError as e:
        sys.stderr.write(f"dark-factory: {e}\n")
        return 2
    manifest_base["qualified"] = eff_tier in _QUALIFYING_TIERS
    manifest_base["sandbox_backend"] = backend_name
    manifest_base["denial_probe_passed"] = probe_passed
    manifest_base["container"] = _finalize_container_manifest(cfg, eff_tier)
    manifest_base["_effective_tier"] = eff_tier   # internal; stripped before finalize
    # cooperative banner only when the EFFECTIVE tier is cooperative:
    if eff_tier not in _QUALIFYING_TIERS:
        sys.stderr.write("dark-factory: COOPERATIVE MODE — unqualified: no probe-proven "
                         "isolation; outcome can never be a qualified ship-candidate.\n")

    # M27 Task 2 (spec §7.4) + M29b: the CANDIDATE-only wrapper. `exec_prefix`
    # (above) is untouched and stays what the builder uses; `candidate_prefix`
    # is what every run_all(...)/characterize() call below uses instead. A
    # failed live probe (network OR default-deny confinement) fails closed
    # here, before any build, exactly like a failed isolation probe.
    try:
        candidate_prefix, host_isolation = resolve_candidate_prefix(
            cfg, control_root, workspace, exec_prefix, eff_tier, journal,
            allow_downgrade=allow_downgrade)
    except df_sandbox.SandboxError as e:
        sys.stderr.write(f"dark-factory: {e}\n")
        return 2
    manifest_base["host_isolation"] = host_isolation
    journal.write("HOST_ISOLATION", **host_isolation)

    # M15: brownfield detection + characterization. Runs HERE -- after
    # isolation is resolved (characterization probes execute under the same
    # exec_wrapper the verifier uses, per the barrier: a probe can read the
    # snapshot copy but the control root stays denied, same as any scenario
    # run) and BEFORE the build loop, so any generated regression scenario is
    # in place for the very first dev-cohort verify pass. `manifest` here is
    # already snapshot_source.build_manifest(project_src)'s output (snapshot()
    # returns it) when project_src was given -- no need to rebuild it.
    snap_manifest = manifest if project_src else None
    try:
        mode = df_brownfield.detect_mode(cfg["_brownfield"]["mode"], project_src, snap_manifest)
    except df_brownfield.BrownfieldError as e:
        sys.stderr.write(f"dark-factory: brownfield: {e}\n")
        return 2
    legacy_ignored = bool(mode == "greenfield" and snap_manifest and snap_manifest["files"])
    journal.write("MODE_DETECTED", mode=mode, legacy_ignored=legacy_ignored)

    generated = []
    gen_dir = None
    # Only actually characterize when there are probes to run. `mode` can be
    # "brownfield" via AUTO-DETECTION (any project_src with >=1 file, fail-safe
    # toward brownfield per df_brownfield.detect_mode) with ZERO probes
    # configured -- e.g. every pre-M15 project-src run, which never configured
    # a `brownfield` block at all. That combination must stay a back-compat
    # no-op (honest mode="brownfield", zero guards), not a BrownfieldError:
    # df_config already refuses an EXPLICIT `mode: "brownfield"` with empty
    # probes at load time (nothing to characterize is a ConfigError there),
    # so this branch only ever sees probes==[] via auto-detection.
    if mode == "brownfield" and cfg["_brownfield"]["probes"]:
        # M29b: characterize snapshots the source into a mkdtemp OUTSIDE the
        # workspace and runs probes there; under the default-deny candidate
        # profile that copy would be unreadable. Pre-create the copy dir and
        # hand it to a characterize-specific wrapper as a scratch dir -- the
        # SAME probe-proven profile shape, with exactly one extra
        # read+write+exec subpath (the throwaway copy). Every other mode
        # keeps the resolved candidate_prefix untouched.
        char_tmp = tempfile.mkdtemp(prefix="df-brownfield-")
        char_prefix = candidate_prefix
        if host_isolation.get("mode") == "default_deny":
            _lo = cfg.get("candidate_loopback_outbound", "pinned")
            _lo_extra = {} if _lo == "pinned" else {"loopback_outbound": _lo}
            char_prefix = df_sandbox.current_backend().wrap_candidate_prefix(
                control_root, workspace, network=cfg["candidate_network"],
                scratch_dirs=(char_tmp,), **_lo_extra)
        try:
            generated = df_brownfield.characterize(
                project_src, cfg["_brownfield"]["probes"], exec_wrapper=char_prefix,
                tmp_dir=char_tmp)
        except df_brownfield.BrownfieldError as e:
            sys.stderr.write(f"dark-factory: brownfield characterization failed: {e}\n")
            return 2
        gen_dir = os.path.join(run_dir, "generated-scenarios")
        os.makedirs(gen_dir, exist_ok=True)
        for sc in generated:
            atomic_write(os.path.join(gen_dir, sc["id"] + ".json"), canonical_json(sc))
        journal.write("CHARACTERIZED", mode=mode, generated=len(generated),
                      behavior_ids=[sc["behavior_id"] for sc in generated])
    elif mode == "brownfield":
        # Auto-detected brownfield with ZERO probes: a valid no-op, but a
        # SILENT one would let a manifest read as "regressions checked" when
        # nothing was guarded. Make the gap loud (stderr WARN + a distinct
        # journal entry) and unambiguous in the manifest (note below), so an
        # auditor can tell "brownfield, nothing guarded" from "guards passed".
        sys.stderr.write(
            "dark-factory: brownfield detected but no probes configured — NO regression "
            "guards were captured; add brownfield.probes to guard existing behavior.\n")
        journal.write("BROWNFIELD_UNGUARDED", reason="brownfield detected, zero probes")

    manifest_base["mode"] = mode
    if mode == "brownfield":
        # generated>0: real snapshot captured. generated==0: the unguarded
        # no-op above — the note must NOT read as if a snapshot happened.
        char_note = (
            "behavioral snapshot at probe points; unprobed behavior may regress"
            if generated
            else "NO regression guards captured (no probes configured); unguarded"
        )
        manifest_base["characterization"] = {
            "probes": len(cfg["_brownfield"]["probes"]),
            "generated": len(generated),
            "note": char_note,
            "legacy_ignored": bool(legacy_ignored),
        }
    elif legacy_ignored:
        manifest_base["characterization"] = {
            "probes": len(cfg["_brownfield"]["probes"]),
            "generated": len(generated),
            "note": "behavioral snapshot at probe points; unprobed behavior may regress",
            "legacy_ignored": True,
        }
    else:
        manifest_base["characterization"] = {"probes": 0, "generated": 0}

    try:
        return _run_loop(cfg, journal, run_dir, manifest_base, spec_text, scenarios_dir,
                         adapter, timeout_s, workspace, start_iter=1, feedback=None,
                         exec_prefix=exec_prefix, candidate_prefix=candidate_prefix,
                         audit_key=audit_key,
                         creds=creds, redactor=redactor, extra_scenarios_dir=gen_dir)
    except df_sandbox.SandboxError as e:
        # In-loop fail-closed guards (e.g. the hardened adapter-mount re-check)
        # must exit 2 like every other refusal, not escape as a traceback.
        sys.stderr.write(f"dark-factory: {e}\n")
        return 2


def _run_loop(cfg, journal, run_dir, manifest_base, spec_text, scenarios_dir,
              adapter, timeout_s, workspace, start_iter, feedback, exec_prefix=None,
              candidate_prefix=None,
              audit_key=None, prev_dev_status=None, regressions=None,
              builder_calls=0, estimated_usd=0.0, budget_alerted=False,
              creds=None, redactor=None, extra_scenarios_dir=None,
              builder_input_tokens=0, builder_output_tokens=0, usage_known=False,
              build_approved_through=0, resume_ship=False, ship_meta=None):
    exec_prefix = exec_prefix or []
    # M27 Task 2: candidate_prefix is the CANDIDATE/verifier-only wrapper
    # (run_all below); exec_prefix above stays the builder's. A caller that
    # doesn't pass candidate_prefix (e.g. candidate_network=="unrestricted",
    # or a pre-M27 test that predates this param) gets exec_prefix itself --
    # byte-identical to before this task.
    candidate_prefix = candidate_prefix if candidate_prefix is not None else exec_prefix
    effective = manifest_base.get("_effective_tier", "cooperative")
    mb_clean = {k: v for k, v in manifest_base.items() if k != "_effective_tier"}
    # R5 DF-R5-04: seal BOTH the requested and the EFFECTIVE assurance tier on
    # every terminal. `tier` continues to echo the CONFIGURED tier (back-compat +
    # docs), but `requested_tier`/`effective_tier` make an --allow-downgrade
    # explicit in the sealed evidence, and every downstream decision
    # (qualification, custody, release, ship) consumes `effective_tier` so a
    # downgraded run can never seal COMPLETE_QUALIFIED via one branch while
    # shipping/custody demand the other (the enterprise-downgrade dead-end).
    mb_clean["requested_tier"] = mb_clean.get("tier")
    mb_clean["effective_tier"] = effective
    # M36a: the resolved intervention mode drives WHICH transitions pause. It's
    # recorded on every terminal manifest (auditability) and journaled at loop
    # entry (fresh run AND every resume, so a paused-then-resumed run's mode is
    # visible in the journal on both segments).
    mode = cfg.get("_intervention_mode", "H2")
    mb_clean["intervention_mode"] = mode
    scenario_set_sha256 = mb_clean.get("scenario_set_sha256")
    # M86 (post-R10 audit): hash of the brownfield-GENERATED regression cohort
    # (created after the run-start seal, so not covered by scenario_set_sha256). Sealed
    # into state.json at each pause so a same-user edit of a generated BHV-REGRESS
    # scenario across a pause is detected on resume. None when there is no cohort.
    generated_set_sha256 = (_scenario_set_hash(extra_scenarios_dir)
                            if extra_scenarios_dir and os.path.isdir(extra_scenarios_dir)
                            else None)
    journal.write("MODE", mode=mode, source=cfg.get("_intervention_source", "default"),
                  start_iter=start_iter)
    # DF-R5-09: pin the container image identity for the WHOLE logical run —
    # first segment resolves + journals it, every resume segment reuses the
    # journaled pin instead of re-resolving a possibly-moved mutable tag.
    _pin_effective_image(cfg, run_dir, journal)
    # H4 (lights-out) MUST never take a pause transition. This is asserted at
    # each would-be pause point below; if the invariant is ever violated the
    # run fails closed (a real raise, not a bare assert -- the suite runs under
    # python -O) rather than silently PAUSING a lights-out run.
    _lights_out = df_modes.is_lights_out(mode)
    # M29b: in default-deny mode the loopback allowlist must pin THIS pass's
    # twin ports (fresh ephemeral ports on every twin reset), so the wrapper
    # is re-derived per verify/final pass from the same probe-proven profile
    # shape. host_isolation rides in manifest_base, so a caller that never
    # went through resolve_candidate_prefix (pre-M29b tests, cooperative
    # runs) has no "default_deny" mode and gets candidate_prefix untouched.
    host_isolation = mb_clean.get("host_isolation") or {}
    # M14: a per-run-loop copy of cfg["_confine"] — NOT cfg["_confine"] itself
    # — so a required=False CONFINEMENT_WARN fallback (below) can flip
    # `enabled` to False for the REST of this loop without mutating cfg
    # (which could otherwise leak the downgrade across unrelated callers
    # sharing the same cfg object).
    confine_state = dict(cfg["_confine"])
    cli = os.path.basename(adapter)
    # Regression tracking (green->red on dev, spec §6/§15.3): prev_dev_status maps
    # behavior_id -> did every dev scenario of that behavior pass LAST iteration.
    # regressed accumulates behavior-IDs that ever flip True->False across the run.
    # Barrier-safe: only ever behavior-IDs, never scenario content.
    prev_dev_status = dict(prev_dev_status or {})
    regressed = set(regressions or [])
    # Budget accounting (M8): builder_calls/estimated_usd/budget_alerted thread
    # through resume via state.json — reassigned as plain locals below (no
    # mutable-container aliasing concern, unlike prev_dev_status/regressed).
    budget_downgrade_noted = False

    def _clear_state():
        p = os.path.join(run_dir, "state.json")
        if os.path.exists(p):
            os.unlink(p)

    def _seal_terminal(mf, msg, code=2, stdout=False, failing=None):
        # AUTO-RESEARCH M92: the byte-identical fail-closed terminal seal that 13 abort
        # paths in this loop performed inline. Extracted VERBATIM -- the ORDER IS
        # LOAD-BEARING: finalize seals the manifest, the chain anchor binds that sealed
        # digest, state is cleared only AFTER the seal, and the exit stays
        # `anchor_exit or code` so an anchor failure still dominates the outcome.
        # NOT exhaustive: 3 further terminals in `_finalize_converged` still seal inline
        # (one canonical -- the "mandatory security gates did not run" refusal -- and two
        # with extra trailing waiver/custody logic). A security fix applied HERE must be
        # applied there too; do not assume this helper covers every abort path.
        digest = finalize_manifest(run_dir, mf, audit_key=audit_key, redactor=redactor)
        anchor_exit = _anchor_audit(cfg, cfg["_control_root"], run_dir, mf["invocation"],
                                    digest, audit_key, journal)
        _clear_state()
        _kb_writeback(cfg, journal, mf, [] if failing is None else failing)
        if stdout:
            print(msg)
        else:
            sys.stderr.write(msg)
        return anchor_exit or code
    def _twin_error_abort(iteration, e):
        journal.write("TWIN_ERROR", iteration=iteration, detail=str(e))
        mf = dict(mb_clean, outcome="ABORTED_BUILD_ERROR", iterations=iteration, qualified=False,
                  final_exam={"ran": False, "passed": None, "count": 0},
                  regressions=sorted(regressed),
                  budget=_budget_manifest_field(cfg["_budget"], builder_calls, estimated_usd),
                  usage=_usage_manifest_field(cfg["_budget"], usage_known,
                                              builder_input_tokens, builder_output_tokens))
        return _seal_terminal(mf, f"dark-factory: twin precondition failed at iteration {iteration}: {e}\n", code=2)

    def _artifact_unhashable_abort(iteration, detail, fe=None, sec_report=None):
        # DF-01/M28a: fail-closed terminal for a converged workspace that
        # could not be trusted as a content-addressed artifact — either
        # `df_seal.freeze()` itself refused it (hostile/unhashable content:
        # symlink, special file, setuid/setgid/world-writable entry, ...),
        # or a post-final-exam `verify_object` re-check found the already-
        # frozen object no longer matches its own sidecar (integrity drift
        # in the object store between freeze and manifest write). Either
        # way: NEVER a qualified/CONVERGED manifest, and `artifact` stays
        # None — there is no object_id trustworthy enough to bind.
        journal.write("ARTIFACT_UNHASHABLE", iteration=iteration, detail=detail)
        mf = dict(mb_clean, outcome="ARTIFACT_UNHASHABLE", iterations=iteration, qualified=False,
                  final_exam=fe or {"ran": False, "passed": None, "count": 0},
                  regressions=sorted(regressed), artifact=None,
                  security=sec_report if sec_report is not None else {"checked": False},
                  budget=_budget_manifest_field(cfg["_budget"], builder_calls, estimated_usd),
                  usage=_usage_manifest_field(cfg["_budget"], usage_known,
                                              builder_input_tokens, builder_output_tokens))
        return _seal_terminal(mf, f"dark-factory: ARTIFACT UNHASHABLE (artifact rejected, not qualified): "
            f"{detail}. Run: {run_dir}", code=3, stdout=True)

    def _scenario_drift_abort(iteration, sealed_hash, live_hash, kind="SCENARIO"):
        # M45 RA-05 + M88 (DF-R12-03): the run-start scenario bundle was sealed at
        # run start (manifest_base["scenario_set_sha256"] + the FSM-chain genesis;
        # the brownfield-generated cohort by `generated_set_sha256` in state.json,
        # M86). Resume already refuses a bundle that drifted across a pause; this
        # seals the SAME-PROCESS window the auditor names ("acceptance criteria can
        # change during a run") — an operator (or a process) that edits the live
        # scenarios dir OR the generated-cohort dir between the run-start gate and
        # ANY verifier load (dev verify AND the sealed final exam) must NEVER have
        # the verifier grade the artifact against altered criteria. `kind` selects
        # the acceptance ("SCENARIO") vs generated ("GENERATED") cohort. Fail-closed,
        # barrier-safe (only 12-char hash prefixes ever surface — never scenario bytes).
        outcome = "SCENARIO_BUNDLE_DRIFT" if kind == "SCENARIO" else "GENERATED_BUNDLE_DRIFT"
        _what = ("acceptance scenarios" if kind == "SCENARIO"
                 else "brownfield-generated regression guards")
        journal.write(outcome, iteration=iteration,
                      sealed=sealed_hash[:12], live=live_hash[:12])
        mf = dict(mb_clean, outcome=outcome, iterations=iteration, qualified=False,
                  final_exam={"ran": False, "passed": None, "count": 0},
                  regressions=sorted(regressed), artifact=None,
                  budget=_budget_manifest_field(cfg["_budget"], builder_calls, estimated_usd),
                  usage=_usage_manifest_field(cfg["_budget"], usage_known,
                                              builder_input_tokens, builder_output_tokens))
        return _seal_terminal(mf, f"dark-factory: {outcome} — the {_what} changed mid-run "
            f"(run-start {sealed_hash[:12]} != live {live_hash[:12]}); refusing to "
            f"grade the artifact against altered criteria. Run: {run_dir}\n", code=2)

    def _scenario_immutability_drift():
        # M88 (DF-R12-03) + generalization: recompute BOTH sealed scenario digests
        # against the LIVE control-root dirs, immediately before a verifier load.
        # Returns (kind, sealed, live) on drift else None — pure check, no side
        # effects, so the caller can discard any throwaway validation roots before
        # taking the fail-closed terminal. Covers the acceptance set (the reported
        # finding only re-checked it before the FINAL exam, not the dev verify) AND
        # the generated cohort (M86 sealed it but only re-checked it on resume).
        _sealed = manifest_base.get("scenario_set_sha256")
        if _sealed is not None:
            _live = _scenario_set_hash(scenarios_dir)
            if _live != _sealed:
                return ("SCENARIO", _sealed, _live)
        if (generated_set_sha256 is not None and extra_scenarios_dir
                and os.path.isdir(extra_scenarios_dir)):
            _live_gen = _scenario_set_hash(extra_scenarios_dir)
            if _live_gen != generated_set_sha256:
                return ("GENERATED", generated_set_sha256, _live_gen)
        return None

    def _finalize_converged(i, object_id, artifact_field, fe, gate_target, allow_pause):
        """M36b Part C: the post-final-exam SEAL tail, shared by the straight-
        through convergence AND the AWAIT_SHIP seal-reentry resume.

        Runs mandatory security gates over `gate_target` (the live `workspace`
        on the straight path; the frozen object dir on ship-resume), re-verifies
        the frozen object by identity, folds the five substates through the SAME
        `df_qualify.derive`, and seals. When `allow_pause` and the mode pauses
        before ship (H1/H2) at a non-enterprise tier, it persists an AWAIT_SHIP
        checkpoint and returns PAUSED INSTEAD of sealing — the ONLY new pause
        point. Reads builder_calls/estimated_usd/etc. from the enclosing scope
        (their post-convergence values on the straight path; the resumed state's
        values on ship-resume), so NO builder dispatch happens on ship-resume."""
        # Mandatory security gates (M9) on the converged/frozen artifact,
        # independent of scenario pass — a clean scenario run with a planted
        # secret still must not ship. Re-run (not trusted from the pause) on
        # ship-resume: the artifact is immutable so the verdict is stable, but
        # re-running is the honest fail-closed choice.
        sec_report = _run_security_gates(cfg, journal, run_dir, gate_target, redactor=redactor)
        if sec_report.get("failed"):
            journal.write("SECURITY_GATE_FAILED", failed=sec_report["failed"])
            # A SECURITY_GATE_FAILED run becomes shippable ONLY via a SEPARATE,
            # signed df-waiver attestation (never a manifest rewrite). The sealed
            # security block carries gate_policy_digest + waiver_policy so attach
            # can recompute every binding digest from these bytes alone.
            mf = dict(mb_clean, outcome="SECURITY_GATE_FAILED", iterations=i,
                      qualified=False, app_security_qualified=False,
                      final_exam=fe, regressions=sorted(regressed),
                      security=sec_report, artifact=artifact_field,
                      budget=_budget_manifest_field(cfg["_budget"], builder_calls, estimated_usd),
                      usage=_usage_manifest_field(cfg["_budget"], usage_known,
                                                  builder_input_tokens, builder_output_tokens))
            digest = finalize_manifest(run_dir, mf, audit_key=audit_key, redactor=redactor)
            anchor_exit = _anchor_audit(cfg, cfg["_control_root"], run_dir, mf["invocation"],
                                        digest, audit_key, journal)
            _clear_state()
            _kb_writeback(cfg, journal, mf, [])
            print(f"dark-factory: security gate failed (artifact rejected): "
                  f"{', '.join(sec_report['failed'])}. Run: {run_dir}")
            _wpol = sec_report.get("waiver_policy", {"threshold": 0})
            if _wpol.get("threshold", 0) >= 1:
                manifest_path = os.path.join(run_dir, "manifest.json")
                print(
                    f"dark-factory: a waiver policy is configured "
                    f"({_wpol['threshold']} of {len(_wpol.get('signers', []))} signers). "
                    f"To accept a specific finding: list them with\n"
                    f"  supervisor.py df-waiver findings --manifest {manifest_path}\n"
                    f"have signers sign each with `df-waiver sign`, collect the entries "
                    f"into {os.path.join(cfg['_control_root'], 'waiver-signatures.json')}, "
                    f"then:\n"
                    f"  supervisor.py df-waiver attach {cfg['_control_root']} --run-dir {run_dir}"
                )
            return anchor_exit or 3

        # DF-01/M28a belt-and-suspenders: re-verify the frozen object still
        # matches its own sidecar (object-store integrity drift -> fail closed,
        # never seal a drifted object). This is also the ship-resume drift net.
        if not df_seal.verify_object(_object_store_root(cfg["_control_root"]), object_id):
            return _artifact_unhashable_abort(
                i, f"frozen object {object_id} failed post-final-exam re-verification "
                   "(object store integrity drift)", fe=fe, sec_report=sec_report)

        eff = effective

        # M33a fail-closed: at a mandatory tier the gates MUST have run.
        if eff in MANDATORY_TIERS and not sec_report.get("checked"):
            journal.write("SECURITY_GATES_MISSING", tier=eff)
            mf = dict(mb_clean, outcome="SECURITY_GATES_MISSING", iterations=i,
                      qualified=False, app_security_qualified=False,
                      final_exam=fe, regressions=sorted(regressed),
                      security=sec_report, artifact=artifact_field,
                      budget=_budget_manifest_field(cfg["_budget"], builder_calls, estimated_usd),
                      usage=_usage_manifest_field(cfg["_budget"], usage_known,
                                                  builder_input_tokens, builder_output_tokens))
            digest = finalize_manifest(run_dir, mf, audit_key=audit_key, redactor=redactor)
            anchor_exit = _anchor_audit(cfg, cfg["_control_root"], run_dir, mf["invocation"],
                                        digest, audit_key, journal)
            _clear_state()
            _kb_writeback(cfg, journal, mf, [])
            print(f"dark-factory: mandatory security gates did not run at tier {eff} "
                  f"(fail-closed, not qualified). Run: {run_dir}")
            return anchor_exit or 3

        app_security_qualified = (eff not in MANDATORY_TIERS) or (
            bool(sec_report.get("checked")) and not sec_report.get("failed"))

        # M36b Part C: the before-ship approval pause. Fires only on the
        # straight-through path (allow_pause), at a non-enterprise tier (an
        # enterprise run's ship gate is the SEPARATE K-of-N custody attestation,
        # not a human pause), when the mode pauses before ship (H1/H2). The
        # frozen artifact + final-exam result are persisted so resume seals
        # WITHOUT rebuilding. H4 can never reach here (it never pauses), but the
        # lights-out invariant is asserted for defense in depth.
        if allow_pause and eff != "enterprise" and df_modes.pauses_before_ship(mode):
            if _lights_out:
                raise df_sandbox.SandboxError(
                    "H4 lights-out invariant violated: before-ship pause reached")
            write_ship_checkpoint_report(run_dir, i, fe, sec_report, object_id, redactor=redactor)
            save_state(run_dir, next_iter=i, feedback=feedback, workspace=workspace,
                       dev_status=prev_dev_status, regressions=regressed,
                       builder_calls=builder_calls, estimated_usd=estimated_usd,
                       budget_alerted=budget_alerted, reason="ship",
                       phase="AWAIT_SHIP", chain_append=True,
                       scenario_set_sha256=scenario_set_sha256,
                       generated_set_sha256=generated_set_sha256,
                       artifact_object_id=object_id,
                       build_approved_through=build_approved_through, redactor=redactor, cfg=cfg,
                       builder_input_tokens=builder_input_tokens,
                       builder_output_tokens=builder_output_tokens,
                       usage_known=usage_known,
                       ship_meta={"object_id": object_id, "artifact_field": artifact_field,
                                  "final_exam": fe, "converged_iteration": i})
            journal.write("CHECKPOINT", iteration=i, phase="AWAIT_SHIP",
                          artifact_object_id=object_id)
            print(f"dark-factory: PAUSED before ship (iteration {i}). Review "
                  f"{run_dir}/checkpoint_ship.md, then `supervisor.py resume --control-root "
                  f"{cfg.get('_control_root', '<CR>')} --decision continue` to SEAL (no rebuild) "
                  f"or `--decision abort` to decline (SHIP_DECLINED).")
            return PAUSED

        custody_field = None
        proxy_field = None
        egress_field = None
        seccomp_field = None

        if eff == "enterprise":
            # M17: an enterprise run with required custody ALWAYS seals
            # CUSTODY_PENDING (qualified False) — the signable artifact must
            # never self-qualify; shipping needs the SEPARATE K-of-N custody
            # attestation. (Enterprise never reaches the before-ship pause
            # above, so this path is unchanged from M36a.)
            outcome, qualified = "CUSTODY_PENDING", False
            qualification = _qualification_field(
                mb_clean, eff, app_security=app_security_qualified,
                waiver_validity=True, artifact_field=artifact_field)
            proxy_field = {"enabled": True, "allowlist": list(cfg["_proxy"]["allowlist"])}
            egress_field = enterprise_egress_result
            seccomp_field = {
                "profile": os.path.basename(cfg["_enterprise"]["seccomp"]),
                "probe": "verified",
            }
            custody_field = {
                "required_k": cfg["_custody"]["threshold"],
                "approvers": len(cfg["_custody"]["approvers"]),
                "satisfied": False,
                "note": "enterprise run sealed CUSTODY_PENDING; qualification requires a "
                        "valid K-of-N custody_attestation.json over these exact manifest "
                        "bytes (df-custody attach)",
            }
            journal.write("CUSTODY_PENDING", iteration=i,
                          required_k=cfg["_custody"]["threshold"],
                          approvers=len(cfg["_custody"]["approvers"]))
        else:
            journal.write("CONVERGED", iteration=i)
            # M36a Task 2: the SINGLE qualification SM — barrier ∧ host_isolation
            # ∧ control_plane ∧ app_security ∧ waiver_validity. Unchanged by
            # M36b; the ship pause simply gates WHEN this runs on H1/H2.
            qualification = df_qualify.derive(
                barrier=eff in _QUALIFYING_TIERS,
                host_isolation=bool((mb_clean.get("host_isolation") or {}).get("qualified")),
                candidate_egress=_candidate_egress_qualified(cfg["candidate_network"]),
                control_plane=bool(isinstance(artifact_field, dict)
                                   and artifact_field.get("object_id")),
                app_security=app_security_qualified,
                waiver_validity=True)
            qualified = qualification["qualified"]
            if qualified:
                outcome = "COMPLETE_QUALIFIED"
            elif eff not in _QUALIFYING_TIERS:
                outcome = "COMPLETE_UNQUALIFIED"
            else:
                outcome = qualification["code"]

        mf = dict(mb_clean, outcome=outcome, iterations=i, final_exam=fe,
                  regressions=sorted(regressed), security=sec_report, qualified=qualified,
                  app_security_qualified=app_security_qualified,
                  qualification=qualification,
                  artifact=artifact_field,
                  budget=_budget_manifest_field(cfg["_budget"], builder_calls, estimated_usd),
                  usage=_usage_manifest_field(cfg["_budget"], usage_known,
                                              builder_input_tokens, builder_output_tokens),
                  custody=custody_field, proxy=proxy_field, enterprise_egress=egress_field,
                  enterprise_seccomp=seccomp_field)
        digest = finalize_manifest(run_dir, mf, audit_key=audit_key, redactor=redactor)
        anchor_exit = _anchor_audit(cfg, cfg["_control_root"], run_dir, mf["invocation"],
                                    digest, audit_key, journal)
        _clear_state()
        _kb_writeback(cfg, journal, mf, [])

        if outcome == "CUSTODY_PENDING":
            manifest_path = os.path.join(run_dir, "manifest.json")
            print(
                f"dark-factory: CUSTODY PENDING — build converged, but shipping requires "
                f"K-of-N split-custody sign-off ({custody_field['required_k']} of "
                f"{custody_field['approvers']} approvers). The sealed manifest is the "
                f"signable artifact:\n"
                f"  manifest: {manifest_path}\n"
                f"  sha256:   {digest}\n"
                f"Have K-of-N approvers sign these exact bytes:\n"
                f"  supervisor.py df-custody sign --manifest {manifest_path} --key-file <privkey>\n"
                f"collect the {{approver,sig}} entries into "
                f"{os.path.join(cfg['_control_root'], 'custody-signatures.json')}, then attach:\n"
                f"  supervisor.py df-custody attach {cfg['_control_root']} --run-dir {run_dir}"
            )
            return anchor_exit or 3

        note = "" if fe.get("ran") else " [no sealed final exam administered]"
        print(f"dark-factory: CONVERGED "
              f"({'qualified, ' + eff if qualified else 'unqualified, ' + eff} tier). "
              f"Workspace: {workspace}  Run: {run_dir}{note}")
        # M41: auto-enter the governed ship phase after a CLEAN qualified seal
        # (invariant #1: only COMPLETE_QUALIFIED + qualified ships here;
        # enterprise seals CUSTODY_PENDING and never reaches this branch — it
        # ships via the `ship` subcommand after df-custody attach). Only when the
        # audit anchor already succeeded (a run that couldn't record its own
        # qualification off-box must not go on to ship). In H4 lights-out this
        # runs unattended; the irreversible-action signature gate still holds.
        if (not anchor_exit and outcome == "COMPLETE_QUALIFIED" and qualified
                and cfg.get("_ship") is not None):
            return _ship_phase(cfg, cfg["_control_root"], run_dir, redactor, creds,
                               decision="continue")
        return anchor_exit or 0

    def _resume_ship_seal():
        """M36b Part C seal-reentry: resume from an AWAIT_SHIP pause and SEAL
        WITHOUT re-dispatching a builder. Re-verify the frozen object matches
        its sidecar (fail-closed on drift), then run gates over the frozen
        object + seal via the SAME `_finalize_converged` path. The build
        for-loop below is NEVER entered on this path, so `builder_calls` is
        provably unchanged across the ship-resume."""
        meta = ship_meta or {}
        object_id = meta.get("object_id")
        artifact_field = meta.get("artifact_field")
        fe = meta.get("final_exam") or {"ran": False, "passed": None, "count": 0}
        ci = meta.get("converged_iteration", start_iter)
        object_store = _object_store_root(cfg["_control_root"])
        journal.write("SHIP_RESUME", converged_iteration=ci, artifact_object_id=object_id)
        # M36b hardening: `ship_meta` rides in state.json (not the FSM chain), so
        # a hand-edited state.json could point the seal at a DIFFERENT,
        # individually-valid object than the one this pause committed to. The
        # AWAIT_SHIP transition already bound the object_id into the hash chain's
        # head `bound_ids` (resume() re-validated the whole chain above), so
        # cross-check them and REFUSE fail-closed on any disagreement — the
        # chain-bound id is the authoritative one. Raising SandboxError routes to
        # resume()'s exit-2 refusal (never a silent seal), mirroring
        # FSM_CHAIN_CORRUPT: the run stays paused for the operator to reconcile.
        chain_lines = _fsm_chain_lines(run_dir)
        chain_bound_id = (chain_lines[-1].get("bound_ids", {}).get("artifact_object_id")
                          if chain_lines else None)
        if object_id != chain_bound_id:
            journal.write("SHIP_META_MISMATCH", ship_object_id=object_id,
                          chain_object_id=chain_bound_id)
            raise df_sandbox.SandboxError(
                "ship-resume: ship_meta.object_id "
                f"{object_id!r} disagrees with the AWAIT_SHIP chain-bound "
                f"artifact_object_id {chain_bound_id!r} (state.json tampered/corrupt); "
                "refusing to seal (fail-closed)")
        if not object_id or not df_seal.verify_object(object_store, object_id):
            return _artifact_unhashable_abort(
                ci, f"ship-resume: frozen object {object_id} failed re-verification "
                    "(drift since the AWAIT_SHIP pause)", fe=fe)
        object_dir = os.path.join(object_store, "objects", object_id)
        return _finalize_converged(ci, object_id, artifact_field, fe, object_dir,
                                   allow_pause=False)

    twins_enabled = cfg["_twins"]["enabled"]
    ts = df_twins.TwinSet() if twins_enabled else None
    # M17 Task 3: the host-side credential proxy + the rendered egress-lock
    # entrypoint script — enterprise-only, started ONCE per _run_loop
    # invocation (not per iteration: the proxy's allowlist is static config,
    # and re-rendering the entrypoint per iteration would be pure churn) and
    # reaped in the SAME finally that reaps twins below — no orphaned
    # listener on any terminal or exception, mirroring the twin lifecycle
    # discipline this module already follows.
    proxy_httpd = None
    proxy_endpoint = None
    entrypoint_path = None
    pcfg = None
    # M30/DF-03 supervisor-wiring (M32): a per-run capability token + (when
    # the builder is one of the two API adapters) the provider name that ARMS
    # df_proxy's method/path injection lock. `enterprise_provider` is None
    # for CLI builder adapters (claude/codex/gemini) -- they don't read
    # DF_PROXY_DESCRIPTOR at all, so there is no provider to lock to and
    # their enterprise behavior is unchanged (no descriptor, env=None plus
    # only the dep-cache vars, exactly pre-M32).
    enterprise_provider = None
    enterprise_capability_token = None
    if effective == "enterprise":
        pcfg = cfg["_proxy"]
        enterprise_provider = _adapter_provider(adapter)
        enterprise_capability_token = secrets.token_urlsafe(32)
        proxy_httpd, proxy_port = df_proxy.serve(
            pcfg["allowlist"], pcfg["token_env"], header=pcfg["header"],
            capability_token=enterprise_capability_token, provider=enterprise_provider)
        proxy_endpoint = f"{_ENTERPRISE_PROXY_HOST}:{proxy_port}"
        entrypoint_path = os.path.join(run_dir, "enterprise-entrypoint.sh")
        df_container.write_enterprise_entrypoint(entrypoint_path, proxy_endpoint)
        # Never the capability token value -- only that a token now gates
        # this proxy and (if set) which provider's method/path it is locked to.
        journal.write("PROXY_STARTED", port=proxy_port, allowlist=pcfg["allowlist"],
                      capability_token_set=True, provider=enterprise_provider)
    # Twins are SHARED/dev (not holdout): reaping them is non-negotiable — this
    # try/finally must wrap the WHOLE loop so every terminal (return) and any
    # exception still stops the twin processes (and, at enterprise, the proxy
    # started above). No orphans, ever.
    try:
        twin_defs = None
        twin_timeout = None
        twins_started = False
        if twins_enabled:
            control_root = cfg["_control_root"]
            twin_timeout = cfg["_twins"]["startup_timeout_s"]
            try:
                twin_defs = df_twins.load_defs(os.path.join(control_root, "twins"))
            except df_twins.TwinError as e:
                return _twin_error_abort(start_iter, e)

        # DF-05/M32: the mandatory per-run egress probe resolve_isolation
        # deliberately skipped (the proxy wasn't running yet there -- it is
        # now). Runs exactly ONCE per _run_loop invocation (fresh run OR
        # resume -- both start a fresh proxy above), BEFORE the first
        # builder invoke_adapter, inside this try/finally so an early
        # refusal here still reaps the proxy/twins via the finally below.
        # Fail-closed (Global Constraint, spec-equivalent to M14's
        # confinement-required posture): an enterprise run whose egress
        # cannot be empirically proven THIS run is not enterprise -- there
        # is no downgrade here, only refusal. See _verify_enterprise_egress's
        # docstring for exactly what the probe does and does not prove.
        enterprise_egress_result = None
        if effective == "enterprise":
            egress_ok, egress_detail, policy_digest = _verify_enterprise_egress(
                cfg, pcfg, proxy_endpoint)
            enterprise_egress_result = {
                "probed": True,
                "passed": bool(egress_ok),
                "policy_digest": policy_digest,
                "checked_at": _now(),
            }
            if not egress_ok:
                journal.write("EGRESS_PROBE_FAILED", detail=egress_detail,
                              policy_digest=policy_digest)
                mf = dict(mb_clean, outcome="EGRESS_PROBE_FAILED", iterations=start_iter,
                          qualified=False,
                          final_exam={"ran": False, "passed": None, "count": 0},
                          regressions=sorted(regressed),
                          proxy={"enabled": True, "allowlist": list(pcfg["allowlist"])},
                          enterprise_egress=enterprise_egress_result,
                          budget=_budget_manifest_field(cfg["_budget"], builder_calls, estimated_usd),
                          usage=_usage_manifest_field(cfg["_budget"], usage_known,
                                                      builder_input_tokens, builder_output_tokens))
                return _seal_terminal(mf, "dark-factory: enterprise egress probe FAILED — the transport/lock could "
                    "not be empirically verified this run (fail-closed; the builder was never "
                    f"invoked). detail: {egress_detail}\n", code=2)
            journal.write("EGRESS_PROBE_PASSED", policy_digest=policy_digest)

        # --- DF-R4-02 (M52): PRE-DISPATCH identity-aware confinement gate. ----
        # The post-dispatch refusal below (M14, in the build loop) only fires
        # when the ADAPTER self-reports status:"error" + "confinement
        # unsupported". An arbitrary executable named `api_anthropic` (a
        # STRUCTURAL profile) that IGNORES the confine arg and returns success
        # would otherwise run the builder UNCONFINED while `required:true` — the
        # security control is fail-OPEN at dispatch. M50 made
        # df_confine.profile_for identity-aware (a structural api_* claim is
        # bound to the shipped-adapter realpath OR a pinned content digest,
        # never the bare basename) and recorded an impostor as
        # probe:"unsupported" in the manifest, but never used that as a GATE.
        # This IS that gate: computed ONCE here (the builder adapter identity is
        # constant across every iteration), BEFORE any invoke_adapter builder
        # spawn, on the fresh-run AND the resume path (both reach the build loop
        # only through this function, and both re-run this preflight). A
        # `required`-confinement adapter whose identity-aware profile is NOT
        # supported is REFUSED here — the builder is never spawned at all —
        # rather than trusted to self-report. The existing post-dispatch
        # self-report refusal is KEPT (defense in depth for a supported adapter
        # that dynamically reports unsupported at runtime); this gate is
        # ADDITIVE and fires first. Back-compat: a live-probed CLI (claude —
        # profile_for ignores adapter_path for non-structural profiles) and a
        # shipped api_anthropic at its trusted path (or a digest-pinned copy)
        # stay `supported` and dispatch normally; a disabled/absent confine
        # (confine_state["enabled"] False) or a not-required confine skips this
        # entirely (a not-required impostor still runs unconfined, with the
        # manifest honestly recording probe:"unsupported" via M50 — unchanged).
        # DF-R4-06 (R4 re-audit): H4 (lights-out) is permitted at config load
        # ONLY for a hardened/enterprise CONFIGURED tier. But resolve_isolation
        # can DOWNGRADE the EFFECTIVE tier under --allow-downgrade (e.g. docker
        # unavailable -> standard/cooperative). A lights-out run must never
        # silently proceed unattended under weaker isolation than the mode
        # requires: re-check the invariant against the EFFECTIVE tier here,
        # before any builder spawn, on the fresh-run AND resume path. Changing
        # the mode is an operator decision, not an implicit side effect of
        # --allow-downgrade, so this fails CLOSED (a distinct terminal, builder
        # never invoked) rather than demoting the mode silently.
        if _lights_out and effective not in ("hardened", "enterprise"):
            journal.write("H4_TIER_DOWNGRADED", effective=effective,
                          configured=cfg["assurance"])
            mf = dict(mb_clean, outcome="MODE_TIER_UNAVAILABLE", iterations=start_iter,
                      qualified=False,
                      final_exam={"ran": False, "passed": None, "count": 0},
                      regressions=sorted(regressed),
                      budget=_budget_manifest_field(cfg["_budget"], builder_calls,
                                                    estimated_usd),
                      usage=_usage_manifest_field(cfg["_budget"], usage_known,
                                                  builder_input_tokens,
                                                  builder_output_tokens))
            return _seal_terminal(mf, f"dark-factory: intervention_mode H4 (lights-out) requires an EFFECTIVE "
                f"hardened/enterprise tier, but isolation resolved to {effective!r} "
                f"(configured {cfg['assurance']!r}, downgraded). Refusing to run "
                f"lights-out under weaker-than-selected isolation — reconfigure the "
                f"mode or restore the required infrastructure. The builder was never "
                f"spawned.\n", code=2)

        if confine_state["enabled"] and cfg["_confine"]["required"]:
            _resolved_adapter_path = os.path.realpath(os.path.expanduser(adapter))
            _confine_profile = df_confine.profile_for(
                cli, _resolved_adapter_path, cfg["_adapter_digests"]["builder"])
            if not _confine_profile.get("supported"):
                _reason = _confine_profile.get(
                    "reason", f"no confinement profile for {cli}")
                journal.write("CONFINEMENT_UNSUPPORTED", iteration=start_iter,
                              detail=_reason)
                mf = dict(mb_clean, outcome="CONFINEMENT_REFUSED", iterations=start_iter,
                          qualified=False,
                          final_exam={"ran": False, "passed": None, "count": 0},
                          regressions=sorted(regressed),
                          budget=_budget_manifest_field(cfg["_budget"], builder_calls,
                                                        estimated_usd),
                          usage=_usage_manifest_field(cfg["_budget"], usage_known,
                                                      builder_input_tokens,
                                                      builder_output_tokens))
                return _seal_terminal(mf, "dark-factory: confinement REQUIRED but the builder adapter's "
                    f"identity-aware profile is UNSUPPORTED ({_reason}) — refusing "
                    "BEFORE dispatch (fail-closed); the builder was never spawned.\n", code=2)

        # M36b Part C: an AWAIT_SHIP resume seals the ALREADY-frozen artifact
        # here and returns BEFORE the build for-loop — the loop is the only
        # place a builder is dispatched, so this reentry provably makes zero
        # builder calls (asserted by the ship-pause e2e's builder_calls check).
        if resume_ship:
            return _resume_ship_seal()

        last_report = None
        for i in range(start_iter, cfg["max_iterations"] + 1):
            # M36a before-build gate (H1/directed only): pause BEFORE rebuilding
            # iteration i (i>=2) so a human can approve/edit-spec/abort before
            # another builder call is spent. This fits the EXISTING pause
            # mechanism cleanly: no dispatch has happened yet this iteration, so
            # resume simply rebuilds i exactly once (no duplicate spend). The
            # `build_approved_through` cursor is the one-shot: a resume from a
            # "build" pause carries build_approved_through=i, so the very next
            # entry here does NOT re-pause the build it just approved.
            if df_modes.pauses_before_build(mode, i) and i > build_approved_through:
                if _lights_out:
                    raise df_sandbox.SandboxError(
                        "H4 lights-out invariant violated: before-build pause reached")
                write_build_checkpoint_report(run_dir, i, feedback, redactor=redactor)
                save_state(run_dir, next_iter=i, feedback=feedback, workspace=workspace,
                          dev_status=prev_dev_status, regressions=regressed,
                          builder_calls=builder_calls, estimated_usd=estimated_usd,
                          budget_alerted=budget_alerted, reason="build",
                          phase=f"AWAIT_BUILD_{i}", chain_append=True,
                          scenario_set_sha256=scenario_set_sha256,
                       generated_set_sha256=generated_set_sha256,
                          build_approved_through=build_approved_through, redactor=redactor, cfg=cfg,
                          builder_input_tokens=builder_input_tokens,
                          builder_output_tokens=builder_output_tokens, usage_known=usage_known)
                journal.write("CHECKPOINT", iteration=i, phase=f"AWAIT_BUILD_{i}",
                              failing=[f["behavior_id"] for f in feedback["failures"]]
                              if feedback else [])
                print(f"dark-factory: PAUSED before build (iteration {i}, directed mode). "
                      f"Review {run_dir}/checkpoint_build_{i}.md, then "
                      f"`supervisor.py resume --control-root {cfg.get('_control_root', '<CR>')}`.")
                return PAUSED
            build_env_extra = None
            if twins_enabled:
                if not twins_started:
                    try:
                        build_env_extra = ts.start(twin_defs, run_dir, twin_timeout, phase="build")
                        twins_started = True
                    except df_twins.TwinError as e:
                        return _twin_error_abort(i, e)
                else:
                    build_env_extra = ts.env

            prompt = compose_prompt(spec_text, feedback)
            # Audit copy on the control plane (barrier tests assert MARKER-absence here).
            audit_prompt_file = os.path.join(run_dir, f"prompt_iter_{i}.md")
            atomic_write(audit_prompt_file, prompt)
            # Working copy the adapter actually reads: under standard tier, control_root
            # is OS-denied to the wrapped builder, so prompt_file must live in the
            # workspace instead (readable) or every standard build aborts with
            # PermissionError. This is barrier-safe: prompt content is compose_prompt's
            # output (spec + ID/taxonomy feedback only, no scenario content), and the
            # spec is already present in the workspace as spec.md — no holdout leak.
            prompt_file = os.path.join(workspace, "DARK_FACTORY_PROMPT.md")
            atomic_write(prompt_file, prompt)

            # RA-06/M46: idempotent dispatch replay. Before dispatching
            # iteration i's PAID builder call, check whether it already
            # resolved successfully in a prior (crashed) process. A crash
            # that landed AFTER DISPATCH_RESULT ok was journaled (the call
            # completed and wrote the workspace) but BEFORE the iteration
            # finalized and next_iter advanced leaves state.json still at
            # iteration i; `_unresolved_dispatch_intent` sees the intent
            # RESOLVED and would let plain `continue` re-enter and re-pay.
            # _resolved_dispatch_result closes that window: a successful
            # result means the output is already in the persisted workspace,
            # so SKIP the whole admission+dispatch block below (no second
            # paid call, and no re-committing the reservation -- it was
            # committed at intent time in M35 and reloaded into
            # builder_calls/estimated_usd, so re-running admission would
            # double-count) and fall straight through to verifying the
            # already-persisted workspace with the recorded ok result.
            replay_result = _resolved_dispatch_result(run_dir, mb_clean["invocation"], i)
            if replay_result is None:
                # --- Budget admission control (M8): reserve BEFORE the builder call,
                # regardless of checkpoint mode (even auto/L5) — a cost overrun pauses
                # here rather than proceeding unattended. billing=="subscription" can't
                # meter dollars (alert-only, milestone-only); max_calls is exact and
                # enforced under any billing. api+max_usd without per_call_usd has no
                # estimate to reserve against, so the $ cap downgrades to alert-only
                # (still counted, never pauses on $).
                b = cfg["_budget"]
                calls_after = builder_calls + 1
                est_after = estimated_usd + (b["per_call_usd"] or 0.0)
                dollar_enforced, calls_enforced = _budget_enforced(b)

                if (b["billing"] == "api" and b["max_usd"] is not None
                        and b["per_call_usd"] is None and not budget_downgrade_noted):
                    journal.write(
                        "BUDGET_DOWNGRADE",
                        reason="max_usd set without per_call_usd; no estimate to reserve "
                               "against — $ cap downgraded to alert-only",
                    )
                    budget_downgrade_noted = True

                if not budget_alerted:
                    hit_dollar = dollar_enforced and estimated_usd >= b["alert_at"] * b["max_usd"]
                    hit_calls = calls_enforced and builder_calls >= b["alert_at"] * b["max_calls"]
                    if hit_dollar or hit_calls:
                        journal.write("BUDGET_ALERT", estimated_usd=estimated_usd,
                                      builder_calls=builder_calls, cap_usd=b["max_usd"],
                                      max_calls=b["max_calls"])
                        sys.stderr.write(
                            f"dark-factory: BUDGET ALERT — {b['alert_at']:.0%} of budget cap "
                            f"reached (estimated_usd={estimated_usd}, builder_calls={builder_calls}).\n")
                        _notify_budget(cfg, journal, redactor, manifest_base["invocation"],
                                       "BUDGET_ALERT", estimated_usd, builder_calls)
                        budget_alerted = True

                if (b["billing"] == "subscription" and not dollar_enforced and not calls_enforced
                        and calls_after % 5 == 0):
                    journal.write("BUDGET_ALERT", milestone=True, builder_calls=calls_after,
                                  estimated_usd=est_after)
                    sys.stderr.write(
                        f"dark-factory: budget milestone — {calls_after} builder calls "
                        f"(subscription billing; informational only).\n")

                budget_pause = ((calls_enforced and calls_after > b["max_calls"]) or
                                (dollar_enforced and est_after > b["max_usd"]))
                if budget_pause and _lights_out:
                    # M36a H4 (lights-out) fail-closed contract: a budget guard that
                    # PAUSES in H1/H2/H3 becomes a deterministic TERMINAL under
                    # lights-out. Never a silent proceed past a human-needed
                    # decision (raise-the-cap), never an indefinite block. This is
                    # the ONLY safe meaning of "unattended": the run halts, sealed,
                    # rather than waiting forever for a human who isn't watching.
                    journal.write("BUDGET_HALTED", estimated_usd=estimated_usd,
                                  builder_calls=builder_calls, cap_usd=b["max_usd"],
                                  max_calls=b["max_calls"], mode=mode)
                    _notify_budget(cfg, journal, redactor, manifest_base["invocation"],
                                   "BUDGET_HALTED", estimated_usd, builder_calls)
                    mf = dict(mb_clean, outcome="BUDGET_HALTED", iterations=i, qualified=False,
                              final_exam={"ran": False, "passed": None, "count": 0},
                              regressions=sorted(regressed),
                              qualification=_qualification_field(mb_clean, effective),
                              budget=_budget_manifest_field(cfg["_budget"], builder_calls, estimated_usd),
                              usage=_usage_manifest_field(cfg["_budget"], usage_known,
                                                          builder_input_tokens, builder_output_tokens))
                    return _seal_terminal(mf, f"dark-factory: BUDGET HALTED (lights-out) — budget cap reached "
                        f"(estimated_usd={estimated_usd}, builder_calls={builder_calls}); "
                        f"a lights-out run fails closed instead of pausing. Run: {run_dir}", code=3, stdout=True)
                if budget_pause:
                    journal.write("BUDGET_PAUSE", estimated_usd=estimated_usd,
                                  builder_calls=builder_calls, cap_usd=b["max_usd"],
                                  max_calls=b["max_calls"])
                    _notify_budget(cfg, journal, redactor, manifest_base["invocation"],
                                   "BUDGET_PAUSE", estimated_usd, builder_calls)
                    save_state(run_dir, next_iter=i, feedback=feedback, workspace=workspace,
                              dev_status=prev_dev_status, regressions=regressed,
                              builder_calls=builder_calls, estimated_usd=estimated_usd,
                              budget_alerted=budget_alerted, reason="budget",
                              phase=f"AWAIT_BUDGET_{i}", chain_append=True,
                              scenario_set_sha256=scenario_set_sha256,
                       generated_set_sha256=generated_set_sha256,
                              build_approved_through=build_approved_through, redactor=redactor, cfg=cfg,
                              builder_input_tokens=builder_input_tokens,
                              builder_output_tokens=builder_output_tokens,
                              usage_known=usage_known)
                    print(f"dark-factory: PAUSED — budget cap reached (estimated_usd={estimated_usd}, "
                          f"builder_calls={builder_calls}). Raise budget.max_usd (or max_calls) in "
                          f"config.json and run: supervisor.py resume --control-root "
                          f"{cfg.get('_control_root', '<cr>')} --decision continue")
                    return PAUSED

                # Builder isolation: at effective "hardened" the builder runs inside a
                # Docker container (control root never mounted — barrier by
                # construction), built fresh per call; the OS-sandbox exec_prefix
                # returned by resolve_isolation is reserved for the VERIFIER only
                # (run_all below), unchanged. Builder-side twin env cannot cross the
                # container boundary in M10 (journaled, not silently dropped) — the
                # container always gets a clean env regardless of twins, PLUS
                # (M11) the configured credential allowlist via `-e` container env.
                builder_env_full = None
                if effective == "hardened":
                    c = cfg["_container"]
                    # RA-07/M46: mount the adapter EXECUTABLE FILE, not its parent
                    # directory. Mounting os.path.dirname(...) ro-exposed EVERY
                    # sibling of the adapter to the builder — an adapter placed in
                    # a broad dir (~/bin, a repo root, a dir also holding keys)
                    # would leak all of it. Docker supports a single-file bind
                    # mount, and df_container.build_argv binds any path as
                    # `-v {p}:{p}:ro`, so the in-container adapter path (and the
                    # invocation) are unchanged — only the exposed surface shrinks
                    # from the whole directory to the one file. The shipped
                    # in-container adapters (api_anthropic/api_openai) are
                    # stdlib-only single files (no sibling import), so a file mount
                    # is sufficient; a multi-file adapter must declare its extras
                    # (see references/hardened.md) rather than get its dir mounted.
                    adapter_ro_file = os.path.realpath(adapter)
                    # Belt-and-suspenders (defense in depth against config drift /
                    # TOCTOU): df_config already rejects a hardened adapter whose
                    # directory overlaps the control root, but this file is about to
                    # be bind-mounted into the builder container — re-verify at the
                    # moment of use rather than trusting the load-time check.
                    if not _disjoint(adapter_ro_file, cfg["_control_root"]):
                        raise df_sandbox.SandboxError(
                            "hardened: refusing to mount the adapter executable — it "
                            f"overlaps the control root ({adapter_ro_file}); the "
                            "holdout barrier would be breached by construction")
                    # (M11) Credential values enter the container ONLY as `-e` argv
                    # baked into the docker invocation by build_argv — never via the
                    # docker CLIENT process's own env. This is the sole channel any
                    # env reaches the hardened builder; `-e K=V` is visible to local
                    # `ps` (documented residual, see references/credentials.md).
                    # (§7.3 Task 3) hardened.dep_cache_dir, when configured, is a
                    # SECOND ro_mount — a pre-provisioned read-only pip/npm cache
                    # so a hardened builder can pip/npm install pinned deps
                    # without live network access. Same TOCTOU re-check
                    # discipline as the adapter mount above: config-load already
                    # validated the dir exists, but this is the moment it's about
                    # to be bind-mounted into the container.
                    ro_mounts = [adapter_ro_file]
                    # DF-R6-04: bytes-at-DISPATCH, not bytes-at-snapshot.
                    _sf_err = _verify_support_files_at_dispatch(cfg, mb_clean, journal)
                    if _sf_err is not None:
                        raise df_sandbox.SandboxError(f"hardened: {_sf_err}")
                    # DF-R4-07: the builder adapter's declared support files
                    # (e.g. df_confine.py, which the shipped CLI adapters import)
                    # ro-mounted alongside the adapter. df_container mounts each
                    # at its own host realpath, so a shipped CLI adapter's
                    # `sys.path.insert(dirname(dirname(__file__)))` + `import
                    # df_confine` resolves in-container. Same fail-closed TOCTOU
                    # disjointness re-check as the adapter/dep-cache mounts;
                    # config-load already validated absolute/existing/disjoint,
                    # but re-check at the moment of mount.
                    for sf in cfg.get("_support_files", []):
                        if not _disjoint(sf, cfg["_control_root"]):
                            raise df_sandbox.SandboxError(
                                "hardened: refusing to mount builder support file — it "
                                f"overlaps the control root ({sf}); the holdout barrier "
                                "would be breached by construction")
                        ro_mounts.append(sf)
                    dep_cache_env = None
                    dep_cache_dir = c.get("dep_cache_dir")
                    if dep_cache_dir:
                        if not _disjoint(dep_cache_dir, cfg["_control_root"]):
                            raise df_sandbox.SandboxError(
                                "hardened: refusing to mount dep_cache_dir — it "
                                f"overlaps the control root ({dep_cache_dir}); the "
                                "holdout barrier would be breached by construction")
                        ro_mounts.append(dep_cache_dir)
                        dep_cache_env = {
                            "PIP_NO_INDEX": "1",
                            "PIP_FIND_LINKS": os.path.join(dep_cache_dir, "pypi"),
                            "npm_config_cache": os.path.join(dep_cache_dir, "npm-cache"),
                            "npm_config_offline": "true",
                        }
                    merged_env = dict(creds) if creds else {}
                    if dep_cache_env:
                        merged_env.update(dep_cache_env)
                    builder_prefix = df_container.build_argv(
                        _effective_image(cfg), workspace,
                        ro_mounts=ro_mounts,
                        network=c["network"], memory=c["memory"], pids=c["pids"],
                        env=merged_env if merged_env else None)
                    if build_env_extra:
                        journal.write("TWIN_ENV_SKIPPED", tier="hardened",
                                      reason="builder-side twin env not forwarded into "
                                             "container (M12)")
                    builder_env = creds
                elif effective == "enterprise":
                    # M17 Task 3: the hardened container path PLUS the egress
                    # lock + seccomp. RA-07/M46 (same fix as hardened above):
                    # mount the adapter EXECUTABLE FILE, not its parent directory,
                    # so an adapter in a broad dir cannot leak its siblings into
                    # the builder. Same single-file bind + TOCTOU re-check as
                    # hardened; the shipped in-container API adapters are
                    # stdlib-only single files, so a file mount suffices.
                    c = cfg["_container"]
                    adapter_ro_file = os.path.realpath(adapter)
                    if not _disjoint(adapter_ro_file, cfg["_control_root"]):
                        raise df_sandbox.SandboxError(
                            "enterprise: refusing to mount the adapter executable — it "
                            f"overlaps the control root ({adapter_ro_file}); the "
                            "holdout barrier would be breached by construction")
                    # Enterprise passes NO PROVIDER credential env into the
                    # container (the credential_proxy is the SOLE provider-
                    # credential path: the raw provider token is read host-side
                    # by the proxy and injected on the proxy->provider leg,
                    # never baked into the container as a `-e` var — df_config
                    # additionally refuses a config where credential_proxy.
                    # token_env also appears in credentials.allowlist, so the
                    # two channels can't collide). (§7.3 Task 3) dep_cache_dir
                    # carries the SAME ro_mount + env wiring as hardened above —
                    # it is not a credential either.
                    #
                    # M30/DF-03 supervisor-wiring (M32, Part 1): when the
                    # builder IS an API adapter (api_anthropic/api_openai --
                    # enterprise_provider is set above), also thread in
                    # DF_PROXY_DESCRIPTOR: {endpoint, provider, target_base_url,
                    # capability_token} as a plain env var. This is NOT the
                    # provider secret -- it is a LOCAL workload capability token
                    # (proves to the proxy which process may use it) plus
                    # non-secret routing (where the proxy listens, which
                    # provider/base-URL to address). The adapter uses it to
                    # speak PLAINTEXT to the local proxy (see api_anthropic/
                    # api_openai's _parse_proxy_descriptor); the proxy is what
                    # opens the real TLS leg and injects the REAL key, host-side,
                    # exactly as before. CLI builder adapters never read this
                    # var (enterprise_provider is None for them) — unchanged
                    # behavior, no descriptor, same as pre-M32.
                    ro_mounts_ent = [adapter_ro_file]
                    # DF-R6-04: bytes-at-DISPATCH, not bytes-at-snapshot.
                    _sf_err = _verify_support_files_at_dispatch(cfg, mb_clean, journal)
                    if _sf_err is not None:
                        raise df_sandbox.SandboxError(f"enterprise: {_sf_err}")
                    # DF-R4-07: builder adapter support files (e.g. df_confine.py)
                    # ro-mounted alongside the adapter, same as hardened — a
                    # multi-file CLI adapter's sibling import resolves in-container.
                    for sf in cfg.get("_support_files", []):
                        if not _disjoint(sf, cfg["_control_root"]):
                            raise df_sandbox.SandboxError(
                                "enterprise: refusing to mount builder support file — it "
                                f"overlaps the control root ({sf}); the holdout barrier "
                                "would be breached by construction")
                        ro_mounts_ent.append(sf)
                    enterprise_env = {}
                    dep_cache_dir = c.get("dep_cache_dir")
                    if dep_cache_dir:
                        if not _disjoint(dep_cache_dir, cfg["_control_root"]):
                            raise df_sandbox.SandboxError(
                                "enterprise: refusing to mount dep_cache_dir — it "
                                f"overlaps the control root ({dep_cache_dir}); the "
                                "holdout barrier would be breached by construction")
                        ro_mounts_ent.append(dep_cache_dir)
                        enterprise_env.update({
                            "PIP_NO_INDEX": "1",
                            "PIP_FIND_LINKS": os.path.join(dep_cache_dir, "pypi"),
                            "npm_config_cache": os.path.join(dep_cache_dir, "npm-cache"),
                            "npm_config_offline": "true",
                        })
                    if enterprise_provider is not None:
                        target_base_url = f"https://{_PROXY_PROVIDER_RULES[enterprise_provider]['host']}"
                        descriptor = {
                            "endpoint": f"http://{proxy_endpoint}",
                            "provider": enterprise_provider,
                            "target_base_url": target_base_url,
                            "capability_token": enterprise_capability_token,
                        }
                        enterprise_env["DF_PROXY_DESCRIPTOR"] = canonical_json(descriptor)
                        # Descriptor WIRED — never the token value.
                        journal.write("PROXY_DESCRIPTOR_WIRED", iteration=i,
                                      provider=enterprise_provider,
                                      endpoint=descriptor["endpoint"],
                                      target_base_url=target_base_url)
                    builder_prefix = df_container.build_enterprise_argv(
                        _effective_image(cfg), workspace,
                        ro_mounts=ro_mounts_ent,
                        proxy_endpoint=proxy_endpoint,
                        seccomp_profile_path=cfg["_enterprise"]["seccomp"],
                        entrypoint_path=entrypoint_path,
                        memory=c["memory"], pids=c["pids"],
                        env=enterprise_env if enterprise_env else None)
                    if build_env_extra:
                        journal.write("TWIN_ENV_SKIPPED", tier="enterprise",
                                      reason="builder-side twin env not forwarded into "
                                             "container (M12)")
                    builder_env = None
                else:
                    builder_prefix = exec_prefix
                    if creds:
                        # Strip credential-shaped launcher vars that aren't
                        # allowlisted, then merge the resolved creds in — a full
                        # env REPLACEMENT (env_full), since env_extra's
                        # dict(os.environ, **env_extra) merge can only add, never
                        # strip. Twin env (build_env_extra: DF_TWIN_* endpoints)
                        # is NOT a credential and keeps flowing to non-hardened
                        # builders exactly as pre-M11 — merged over the scoped
                        # env so twins+credentials compose instead of silently
                        # dropping the twin endpoints.
                        builder_env = None
                        builder_env_full = df_creds.launcher_scoped_env(
                            os.environ, cfg["_credentials"]["allowlist"], creds)
                        builder_env_full.update(build_env_extra or {})
                    else:
                        builder_env = build_env_extra

                # env_full is only ever passed when actually set (M11 credentials
                # configured at standard/cooperative): existing invoke_adapter
                # call sites/tests that predate env_full and don't accept it as a
                # kwarg keep working unchanged when no credentials are configured.
                _invoke_kwargs = {"exec_prefix": builder_prefix, "env_extra": builder_env}
                if builder_env_full is not None:
                    _invoke_kwargs["env_full"] = builder_env_full
                # confine is only ever passed when actually enabled (M14) — same
                # back-compat reason as env_full above: existing invoke_adapter
                # callers/tests that predate `confine` and don't accept it as a
                # kwarg keep working unchanged when builder_confinement is
                # absent/disabled.
                _confined_kwargs = dict(_invoke_kwargs)
                if confine_state["enabled"]:
                    _confined_kwargs["confine"] = True

                # DF-R8-04: recompute the skill SOURCE identity immediately before
                # EVERY builder dispatch and refuse if it is unknown or drifted from
                # the run's sealed anchor. The pre-M71 code sealed the source ONCE
                # at run setup and never re-checked it, so the control-plane/support
                # bytes could change between dispatches within one logical run (then
                # be restored before the final evidence seal). Refuse BEFORE the
                # dispatch intent / budget reservation, so a drift neither spends nor
                # leaves a dangling intent. (Adapter + support-file identity is
                # separately re-verified per dispatch — M62 _enforce_adapter_digests
                # / _verify_support_files_at_dispatch.)
                _src_ok, _src_why, _src_now = _source_identity_stable(cfg)
                if not _src_ok:
                    journal.write(
                        "SOURCE_DRIFT_REFUSED", iteration=i,
                        sealed_commit=(cfg.get("_source_identity") or {}).get("commit"),
                        current_commit=(_src_now or {}).get("commit"),
                        current_digest_known=((_src_now or {}).get("tree_digest") is not None),
                        phase=f"dispatch_{i}")
                    mf = dict(mb_clean, outcome="SOURCE_DRIFT", iterations=i, qualified=False,
                             final_exam={"ran": False, "passed": None, "count": 0},
                             regressions=sorted(regressed),
                             budget=_budget_manifest_field(cfg["_budget"], builder_calls,
                                                           estimated_usd),
                             usage=_usage_manifest_field(cfg["_budget"], usage_known,
                                                         builder_input_tokens,
                                                         builder_output_tokens))
                    return _seal_terminal(mf, f"dark-factory: builder dispatch refused (fail-closed) at iteration {i} — "
                        f"{_src_why}. No builder ran; start a fresh run under the current source.\n", code=2)

                # --- DF-08/M35: crash-safe dispatch. Journal INTENT to dispatch
                # a paid builder call, and COMMIT the reservation computed above
                # (calls_after/est_after) to durable state, BOTH before the call
                # is made -- so if this process is killed anywhere between here
                # and the matching DISPATCH_RESULT below (including mid-
                # subprocess, after a real provider request has already gone
                # out), the spend is never understated and a resume never
                # silently re-dispatches: `_unresolved_dispatch_intent` (used by
                # resume()) finds this INTENT with no matching RESULT and stops,
                # fail-closed, at UNKNOWN_OUTCOME instead of guessing. This
                # replaces the old post-call `builder_calls = calls_after;
                # estimated_usd = est_after` commit (moved here, before the
                # call) -- a normal, non-crashing run ends with the identical
                # final numbers, just committed earlier.
                dispatch_key = _dispatch_idempotency_key(mb_clean["invocation"], i)
                journal.write("DISPATCH_INTENT", iteration=i, idempotency_key=dispatch_key,
                              reserved_calls=calls_after, reserved_usd=est_after)
                builder_calls = calls_after
                estimated_usd = est_after
                save_state(run_dir, next_iter=i, feedback=feedback, workspace=workspace,
                          dev_status=prev_dev_status, regressions=regressed,
                          builder_calls=builder_calls, estimated_usd=estimated_usd,
                          budget_alerted=budget_alerted, reason="dispatch",
                          phase=f"DISPATCH_{i}", chain_append=False,
                          build_approved_through=build_approved_through, redactor=redactor, cfg=cfg,
                          scenario_set_sha256=scenario_set_sha256,
                          generated_set_sha256=generated_set_sha256,
                          builder_input_tokens=builder_input_tokens,
                          builder_output_tokens=builder_output_tokens,
                          usage_known=usage_known)

                resp, err = invoke_adapter(adapter, "builder", workspace, prompt_file, timeout_s,
                                           **_confined_kwargs)

                if (confine_state["enabled"] and err is None and resp is not None
                        and resp.get("status") == "error"
                        and "confinement unsupported" in (resp.get("detail") or "")):
                    if cfg["_confine"]["required"]:
                        # Fail-closed (M14 Global Constraint): a tier that
                        # REQUIRES confinement must NEVER run the builder
                        # unconfined — refuse here, before any unconfined build
                        # happens (this iteration's builder call already did
                        # nothing but report the refusal; no artifact written).
                        journal.write("DISPATCH_RESULT", iteration=i, idempotency_key=dispatch_key,
                                     status="error")
                        journal.write("CONFINEMENT_UNSUPPORTED", iteration=i,
                                     detail=resp.get("detail", ""))
                        mf = dict(mb_clean, outcome="CONFINEMENT_REFUSED", iterations=i,
                                 qualified=False,
                                 final_exam={"ran": False, "passed": None, "count": 0},
                                 regressions=sorted(regressed),
                                 budget=_budget_manifest_field(cfg["_budget"], builder_calls,
                                                               estimated_usd),
                                 usage=_usage_manifest_field(cfg["_budget"], usage_known,
                                                             builder_input_tokens, builder_output_tokens))
                        return _seal_terminal(mf, f"dark-factory: confinement required but unsupported for this "
                            f"builder adapter at iteration {i} — refusing (fail-closed); "
                            f"the builder was never run unconfined\n", code=2)
                    # Not required: warn + fall back to an UNCONFINED call for
                    # the rest of this run (retrying confine=True every
                    # iteration would just keep re-hitting the same
                    # unsupported CLI — the result is deterministic).
                    journal.write("CONFINEMENT_WARN", iteration=i, detail=resp.get("detail", ""))
                    confine_state["enabled"] = False
                    mb_clean["builder_confinement"] = _confine_manifest_field(
                        confine_state, cli, adapter, cfg["_adapter_digests"]["builder"])
                    resp, err = invoke_adapter(adapter, "builder", workspace, prompt_file, timeout_s,
                                               **_invoke_kwargs)

                # DF-08/M35: durable marker that iteration i's dispatch RESOLVED
                # (the adapter call returned -- no crash) -- whichever of the
                # one or two invoke_adapter attempts above actually produced the
                # resp/err this iteration lands on. Written unconditionally,
                # before the ok/error branch, so both outcomes are bracketed.
                journal.write("DISPATCH_RESULT", iteration=i, idempotency_key=dispatch_key,
                              status="error" if err else ("ok" if resp.get("status") == "ok" else "error"))
            else:
                # Replay path. On the happy path (no crash) replay_result is
                # always None, so this branch is inert -- the normal run is
                # unchanged. Here the builder already ran and wrote the
                # workspace, which persists across the crash. Fail CLOSED if it
                # is somehow gone: a resolved-ok result with a missing workspace
                # is an inconsistent state we must never paper over by verifying
                # an empty tree (which could spuriously 'converge' on nothing).
                if not os.path.isdir(workspace):
                    raise df_sandbox.SandboxError(
                        f"RA-06 replay: iteration {i} recorded a successful "
                        f"DISPATCH_RESULT but its workspace is missing "
                        f"({workspace}) -- refusing to verify an inconsistent "
                        "state (fail-closed)")
                journal.write("DISPATCH_REPLAYED", iteration=i,
                              idempotency_key=_dispatch_idempotency_key(
                                  mb_clean["invocation"], i))
                # Reconstruct the minimal ok result the ok-branch below needs.
                # No usage is replayed (value-free): M25 token accounting for
                # this already-paid call is a soft, fail-soft estimate, simply
                # not re-accrued on replay -- the paid-spend budget
                # (builder_calls/estimated_usd) is what M35 durably preserved.
                resp, err = {"status": "ok"}, None

            if err or resp.get("status") != "ok":
                journal.write("ABORTED_BUILD_ERROR", iteration=i, detail=err or resp.get("detail", ""))
                mf = dict(mb_clean, outcome="ABORTED_BUILD_ERROR", iterations=i, qualified=False,
                          final_exam={"ran": False, "passed": None, "count": 0},
                          regressions=sorted(regressed),
                          budget=_budget_manifest_field(cfg["_budget"], builder_calls, estimated_usd),
                          usage=_usage_manifest_field(cfg["_budget"], usage_known,
                                                      builder_input_tokens, builder_output_tokens))
                return _seal_terminal(mf, f"dark-factory: build error at iteration {i}\n", code=2)
            # DF-08/M35: builder_calls/estimated_usd were already committed
            # BEFORE the call, right after DISPATCH_INTENT above -- nothing
            # to do here. (Historically this is where the M8 post-call
            # commit lived; moving it earlier is what makes a crash mid-call
            # never understate spend.)
            # M25 Task 1: authoritative token accounting, additive alongside
            # the M8 estimate above -- reads resp["usage"] (an adapter that
            # can report real Messages-API token counts, e.g. api_anthropic)
            # and accumulates RUN totals. Fail-soft by construction: any
            # shape other than {"known": True, "input_tokens": <int-able>,
            # "output_tokens": <int-able>} — absent, {"known": False}, or a
            # malformed "known": True block — leaves the totals untouched and
            # NEVER raises; it never affects estimated_usd or the admission/
            # alert/pause path above, which already ran and decided on the
            # pre-call estimate alone.
            usage = resp.get("usage")
            if isinstance(usage, dict) and usage.get("known") is True:
                try:
                    call_input_tokens = int(usage["input_tokens"])
                    call_output_tokens = int(usage["output_tokens"])
                except (KeyError, TypeError, ValueError):
                    pass
                else:
                    builder_input_tokens += call_input_tokens
                    builder_output_tokens += call_output_tokens
                    usage_known = True
            journal.write("BUILD", iteration=i, usage_known=usage_known,
                          builder_input_tokens=builder_input_tokens,
                          builder_output_tokens=builder_output_tokens)

            # M12: the dev-cohort verify pass gets a FRESH twin reset with a
            # fresh per-pass seed (only when a twin def supports_variants --
            # else extra_env=None, exactly today's reset). The seed lives
            # ONLY in this local var, fed to run_all (the scenario/candidate
            # env) below -- it never touches build_env_extra/builder_env, so
            # it cannot reach the builder (see the barrier note above
            # invoke_adapter's env_extra/env_full handling).
            verify_env_extra = None
            if twins_enabled:
                try:
                    verify_env_extra = ts.reset(twin_defs, run_dir, twin_timeout,
                                                 extra_env=_variant_seed_extra(twin_defs),
                                                 phase="verify")
                except df_twins.TwinError as e:
                    return _twin_error_abort(i, e)
            # M93: reserve THIS pass's candidate-service ports and expose
            # them to scenario commands (DF_SERVICE_PORTS) -- they are
            # pinned into the wrapper below exactly like twin ports, and
            # journaled so the widened-authority scope is auditable per pass.
            verify_env_extra = _service_ports_env(cfg, verify_env_extra)
            if verify_env_extra and "DF_SERVICE_PORTS" in verify_env_extra:
                journal.write("SERVICE_PORTS", iteration=i, cohort="dev",
                              ports=verify_env_extra["DF_SERVICE_PORTS"])
            # M29b: pin THIS pass's twin ports into the candidate wrapper
            # (no-op outside default-deny mode).
            pass_candidate_prefix = _candidate_prefix_for_twins(
                cfg, host_isolation, workspace, candidate_prefix, verify_env_extra)

            # M88 (DF-R12-03): re-verify the sealed scenario digests immediately
            # before the DEV verify loads them — the builder just ran and a
            # same-user control-root writer could have weakened a hidden guard
            # (generated BHV-REGRESS-* or a hand-authored dev scenario) in the
            # no-pause window between dispatch and this load. Resume-only / final-
            # exam-only checking left this uninterrupted (H3/H4) window open.
            _drift = _scenario_immutability_drift()
            if _drift is not None:
                return _scenario_drift_abort(i, _drift[1], _drift[2], kind=_drift[0])

            try:
                # M15: extra_scenarios_dir merges the brownfield-generated
                # BHV-REGRESS-* guards into the DEV cohort here at verify time.
                # They are deliberately NOT in the M7 pre-build coverage/mutation
                # gate above (which loads only the control scenarios/ dir): each
                # generated `then` is already proven discriminating by
                # characterize() itself, and folding them into check_coverage
                # would flag every BHV-REGRESS-* as an orphan_scenario (no
                # matching behaviors.json entry) and spuriously fail any
                # brownfield+coverage run. See references/brownfield.md.
                report = run_all(scenarios_dir, workspace, exec_wrapper=pass_candidate_prefix,
                                  env_extra=verify_env_extra, cohort="dev",
                                  observer_files=ts.observer_files if ts else None,
                                  extra_scenarios_dir=extra_scenarios_dir,
                                  verify_digests={"scenarios": manifest_base.get("scenario_set_sha256"),
                                                  "generated": generated_set_sha256})
            except ScenarioBundleDrift as e:
                # M91: the bundle changed between the M88 pre-check above and this LOAD
                # (the residual TOCTOU micro-window) — the verifier hashed the exact bytes
                # it read and they no longer match the run-start seal. Fail closed.
                _k = "SCENARIO" if e.kind == "scenarios" else "GENERATED"
                return _scenario_drift_abort(i, e.expected, e.actual, kind=_k)
            except OracleError as e:
                journal.write("ABORTED_BUILD_ERROR", iteration=i, detail=f"invalid scenarios: {e}")
                mf = dict(mb_clean, outcome="ABORTED_BUILD_ERROR", iterations=i, qualified=False,
                          final_exam={"ran": False, "passed": None, "count": 0},
                          regressions=sorted(regressed),
                          budget=_budget_manifest_field(cfg["_budget"], builder_calls, estimated_usd),
                          usage=_usage_manifest_field(cfg["_budget"], usage_known,
                                                      builder_input_tokens, builder_output_tokens))
                return _seal_terminal(mf, f"dark-factory: {e}\n", code=2)
            last_report = report
            # verifier_report_iter_*.json carries raw builder-produced observed
            # stdout/stderr (spec: run_all's `observed` dict) — a real smuggle
            # channel, not merely defensive — so it goes through the redactor.
            _redacted_write(os.path.join(run_dir, f"verifier_report_iter_{i}.json"), report, redactor)
            passing = sum(1 for r in report["results"] if r["pass"])
            journal.write("VERIFY", iteration=i, passing=passing, total=len(report["results"]))
            # M43a: journal PROPERTY_VIOLATED (behavior-id + invariant name +
            # case index ONLY -- value-free) for each failed property scenario
            # and mirror it into the shared manifest property.violations list.
            # The counterexample content stays in verifier_report_iter_*.json
            # (control-plane); the builder feedback below carries only the
            # "property_violated" taxonomy.
            _journal_property_violations(journal, mb_clean, report["results"],
                                         cohort="dev", iteration=i)

            # Regression tracking (green->red on dev): a behavior passes this
            # iteration iff EVERY one of its dev scenarios passed. Any behavior
            # that was True last iteration and is False now regressed — journal
            # the behavior-ID only (barrier-safe), then roll prev_dev_status
            # forward. Informational + auditable; does not change control flow
            # (a regressed behavior is failing, so the loop already won't
            # converge on it).
            cur_dev_status = {}
            for r in report["results"]:
                bid = r["behavior_id"]
                cur_dev_status[bid] = cur_dev_status.get(bid, True) and bool(r["pass"])
            for bid, ok in cur_dev_status.items():
                if prev_dev_status.get(bid) is True and not ok:
                    journal.write("REGRESSION", iteration=i, behavior_id=bid)
                    regressed.add(bid)
            prev_dev_status = cur_dev_status

            if report["all_pass"]:
                # DF-01/M28a (seal-first): freeze the converged workspace into
                # a content-addressed object BEFORE the final exam runs, so
                # the identity bound into the manifest is provably what dev
                # converged on -- not a workspace that could still be swapped
                # after the fact and before the final exam/gates/manifest
                # write. Fail-closed on hostile/unhashable content: this run
                # NEVER reaches CONVERGED/qualified without a trustworthy
                # object_id. See _seal_workspace_artifact + the module-level
                # ARTIFACT_UNHASHABLE terminal (_artifact_unhashable_abort).
                #
                # ENGINEERING NOTE — where the final exam + gates run (M44
                # RA-01 fix; supersedes the old "M29d deferred" note):
                # validation now examines the SEALED object, not the mutable
                # `workspace`. AFTER the freeze below yields `object_id`, we
                # materialize the sealed object into TWO fresh throwaway roots
                # (siblings of `workspace`, so they live OUTSIDE the control
                # root and stay reachable under candidate confinement, which
                # denies the control root): `R_gates` for the security gates
                # and `R_exam` (cwd for the final cohort). Each materialize
                # re-verifies object identity (df_seal.materialize_object) and
                # refuses a non-empty dest, so a drifted/absent object fails
                # closed into `_artifact_unhashable_abort` rather than seeding
                # validation from untrustworthy bytes. Because both roots are
                # copies of the SEALED bytes, a final-cohort scenario side
                # effect (or a hostile candidate) that scrubs `workspace`
                # AFTER the freeze — the reproduced RA-01 attack — is INERT:
                # the gates scan `R_gates` (still holds the planted secret) and
                # the exam runs in the discardable `R_exam`, never the shipped
                # object dir itself (pointing a candidate command's cwd at the
                # live object store risks a same-privilege write silently
                # corrupting the very object we just bound — df_seal's
                # documented residual — so we validate a COPY and discard it).
                # The dev-loop verify above stays on `workspace`: pre-seal
                # there is no sealed object, and its results only drive
                # ID+taxonomy feedback, never qualification.
                #
                # DOCUMENTED RESIDUAL (narrowed from the old M29d): M44 closes
                # the shipped-vs-validated-bytes gap (gates + exam both derive
                # from the sealed object). Per-SCENARIO copy-on-run WITHIN the
                # final cohort (a fresh copy per final scenario, so one final
                # scenario can't mutate state a later one in the SAME cohort
                # observes) is a further hardening still deferred as full M29d.
                try:
                    object_id, artifact_field = _seal_workspace_artifact(
                        cfg["_control_root"], workspace)
                except df_seal.SealError as e:
                    return _artifact_unhashable_abort(i, str(e))

                # M44 RA-01: materialize pristine copies of the SEALED object
                # for the gates (R_gates) and the final exam (R_exam). Siblings
                # of `workspace` (workspace_root is disjoint from the control
                # root — enforced by df_config — so these are reachable by the
                # confined candidate, whereas a dir under run_dir would be
                # denied). A materialize failure is object-store drift → the
                # fail-closed ARTIFACT_UNHASHABLE terminal (never validate, let
                # alone qualify, off untrustworthy bytes).
                _object_store = _object_store_root(cfg["_control_root"])
                r_gates = workspace + "__m44_gates"
                r_exam = workspace + "__m44_exam"
                try:
                    _materialize_validation_root(_object_store, object_id, r_gates)
                    _materialize_validation_root(_object_store, object_id, r_exam)
                except df_seal.SealError as e:
                    _discard_validation_root(r_gates)
                    _discard_validation_root(r_exam)
                    return _artifact_unhashable_abort(
                        i, f"could not materialize the sealed object {object_id} for "
                           f"validation-on-sealed-bytes: {e}")

                # DEV converged. The sealed FINAL exam runs exactly ONCE, here, and its
                # results are NEVER fed back: project_feedback is never called on it,
                # nothing from it is written to `workspace`, and only final
                # behavior-IDs (never title/given/when/then/observed) reach the
                # journal/manifest. M12: when a twin supports_variants, the
                # final exam gets its OWN fresh twin reset with a fresh seed
                # (distinct from dev-verify's) -- a builder that hardcoded
                # dev-verify's served token cannot rely on seeing it again at
                # final exam. When NO twin supports_variants, a reset would be
                # pure churn (kill+relaunch+readiness-wait) with no variant to
                # serve, so we reuse dev-verify's already-running twins --
                # byte-identical to the pre-M12 final-exam path (zero restart).
                # M45 RA-05 + M88: the sealed final exam below re-reads the LIVE
                # `scenarios_dir` from the control root. Re-hash BOTH sealed cohorts
                # NOW and refuse if either drifted from the run-start seal — closing
                # the same-process edit window (resume already covers the across-
                # pause window; M88 also added this check before the dev verify).
                # Fail-closed; discards the validation roots first.
                _drift = _scenario_immutability_drift()
                if _drift is not None:
                    _discard_validation_root(r_gates)
                    _discard_validation_root(r_exam)
                    return _scenario_drift_abort(i, _drift[1], _drift[2], kind=_drift[0])

                final_env_extra = verify_env_extra
                # M44 RA-01: the throwaway sealed-object copies (R_gates/R_exam)
                # are discarded no matter which terminal this block reaches.
                try:
                    if twins_enabled:
                        seed_extra = _variant_seed_extra(twin_defs)
                        if seed_extra is not None:
                            try:
                                final_env_extra = ts.reset(twin_defs, run_dir, twin_timeout,
                                                            extra_env=seed_extra, phase="verify")
                            except df_twins.TwinError as e:
                                return _twin_error_abort(i, e)
                    # M29b: the final exam pins ITS pass's twin ports too. When no
                    # twin supports variants there was no reset above, so
                    # final_env_extra is dev-verify's endpoints and this re-derives
                    # a wrapper with the same (still-live) ports. M44 RA-01: the
                    # wrapper is rebuilt around `r_exam` (the exam's cwd), so
                    # default-deny confinement allowlists the materialized root
                    # and denies the control root exactly as it did for
                    # `workspace`; twin ports still flow through unchanged.
                    # M93: the sealed exam gets its OWN fresh service-port
                    # reservation (overwriting any dev-pass DF_SERVICE_PORTS
                    # riding in final_env_extra), pinned by the same wrapper
                    # rebuild below and journaled like the dev passes.
                    final_env_extra = _service_ports_env(cfg, final_env_extra)
                    if final_env_extra and "DF_SERVICE_PORTS" in final_env_extra:
                        journal.write("SERVICE_PORTS", iteration=i, cohort="final",
                                      ports=final_env_extra["DF_SERVICE_PORTS"])
                    final_candidate_prefix = _candidate_prefix_for_twins(
                        cfg, host_isolation, r_exam, candidate_prefix, final_env_extra)
                    final = run_all(scenarios_dir, r_exam, exec_wrapper=final_candidate_prefix,
                                     env_extra=final_env_extra, cohort="final",
                                     observer_files=ts.observer_files if ts else None,
                                     verify_digests={"scenarios": manifest_base.get("scenario_set_sha256")})
                    _redacted_write(os.path.join(run_dir, "final_exam_report.json"), final, redactor)
                    final_ran = final["count"] > 0
                    journal.write("FINAL_EXAM", ran=final_ran,
                                  passing=sum(1 for r in final["results"] if r["pass"]),
                                  total=final["count"])
                    # M43a: same value-free property-violation audit record for the
                    # sealed final cohort (behavior-id + invariant + case index --
                    # consistent with FINAL_EXAM_FAILED's behavior-id-only
                    # discipline; final results are still NEVER fed back).
                    _journal_property_violations(journal, mb_clean, final["results"],
                                                 cohort="final", iteration=i)
                    fe = {"ran": final_ran, "passed": bool(final["all_pass"]) if final_ran else None,
                          "count": final["count"]}

                    if final_ran and not final["all_pass"]:
                        journal.write("FINAL_EXAM_FAILED",
                                      failing=sorted({r["behavior_id"] for r in final["results"]
                                                      if not r["pass"]}))
                        mf = dict(mb_clean, outcome="FINAL_EXAM_FAILED", iterations=i,
                                  qualified=False, final_exam=fe, regressions=sorted(regressed),
                                  artifact=artifact_field,
                                  budget=_budget_manifest_field(cfg["_budget"], builder_calls, estimated_usd),
                                  usage=_usage_manifest_field(cfg["_budget"], usage_known,
                                                              builder_input_tokens, builder_output_tokens))
                        return _seal_terminal(mf, f"dark-factory: FINAL-EXAM FAILED (artifact rejected; held-out "
                            f"scenarios not disclosed). Run: {run_dir}", code=3, stdout=True)

                    # M36b Part C: the whole post-final-exam SEAL tail (mandatory
                    # gates -> object re-verify -> before-ship pause -> seal) lives
                    # in `_finalize_converged` so the AWAIT_SHIP seal-reentry resume
                    # can reuse the IDENTICAL df_qualify.derive path with NO builder
                    # dispatch. M44 RA-01: the straight-through path runs gates over
                    # `r_gates` (a pristine copy of the sealed object), not the
                    # mutable `workspace`; the ship-resume path runs them over the
                    # frozen object dir. Either way the gates certify the shipped
                    # bytes. It still allows the before-ship pause.
                    return _finalize_converged(i, object_id, artifact_field, fe,
                                               r_gates, allow_pause=True)
                except ScenarioBundleDrift as e:
                    # M91: the acceptance bundle changed between the M88 pre-check and this
                    # final-exam LOAD (the residual TOCTOU micro-window). The finally below
                    # discards the throwaway validation roots; fail closed.
                    _k = "SCENARIO" if e.kind == "scenarios" else "GENERATED"
                    return _scenario_drift_abort(i, e.expected, e.actual, kind=_k)
                finally:
                    _discard_validation_root(r_exam)
                    _discard_validation_root(r_gates)

            feedback = project_feedback(report)
            # feedback_iter/*.json and workspace/feedback.json are structurally
            # guaranteed value-free (validate_feedback's ALLOWED_TOP/ALLOWED_FAILURE
            # keysets — behavior_id/taxonomy only), so redaction is a defensive
            # no-op here rather than a load-bearing choke point.
            _redacted_write(os.path.join(run_dir, f"feedback_iter_{i}.json"), feedback, redactor)
            atomic_write(os.path.join(workspace, "feedback.json"), canonical_json(feedback))
            journal.write("FEEDBACK", iteration=i, failing=[f["behavior_id"] for f in feedback["failures"]])

            # M36a after-verify gate: pauses under H1/H2 (== legacy
            # `checkpoint:"pause"`), runs straight through under H3/H4 (== legacy
            # `auto`). This is the byte-for-byte replacement of the old
            # `cfg["_checkpoint"] == "pause"` gate: H1/H2 both map back to a
            # `pause` checkpoint, so the default (H2) reproduces today exactly.
            if df_modes.pauses_after_verify(mode) and i < cfg["max_iterations"]:
                if _lights_out:
                    raise df_sandbox.SandboxError(
                        "H4 lights-out invariant violated: after-verify pause reached")
                write_checkpoint_report(run_dir, i, report, redactor=redactor)
                save_state(run_dir, next_iter=i + 1, feedback=feedback, workspace=workspace,
                          dev_status=prev_dev_status, regressions=regressed,
                          builder_calls=builder_calls, estimated_usd=estimated_usd,
                          budget_alerted=budget_alerted, reason="checkpoint",
                          phase=f"AWAIT_VERIFY_{i}", chain_append=True,
                          scenario_set_sha256=scenario_set_sha256,
                       generated_set_sha256=generated_set_sha256,
                          build_approved_through=build_approved_through, redactor=redactor, cfg=cfg,
                          builder_input_tokens=builder_input_tokens,
                          builder_output_tokens=builder_output_tokens,
                          usage_known=usage_known)
                journal.write("CHECKPOINT", iteration=i, phase=f"AWAIT_VERIFY_{i}",
                              failing=[f["behavior_id"] for f in feedback["failures"]])
                print(f"dark-factory: PAUSED at checkpoint (iteration {i}). "
                      f"Review {run_dir}/checkpoint_iter_{i}.md, then "
                      f"`supervisor.py resume --control-root {cfg.get('_control_root', '<CR>')}`.")
                return PAUSED

        failing = sorted({r["behavior_id"] for r in last_report["results"] if not r["pass"]})
        journal.write("CAP_REACHED", failing_behaviors=failing,
                      note="likely spec ambiguity — human decision needed")
        mf = dict(mb_clean, outcome="CAP_REACHED", iterations=cfg["max_iterations"], qualified=False,
                  final_exam={"ran": False, "passed": None, "count": 0},
                  regressions=sorted(regressed),
                  budget=_budget_manifest_field(cfg["_budget"], builder_calls, estimated_usd),
                  usage=_usage_manifest_field(cfg["_budget"], usage_known,
                                              builder_input_tokens, builder_output_tokens))
        return _seal_terminal(mf, f"dark-factory: CAP REACHED after {cfg['max_iterations']} iterations. "
            f"Still failing: {', '.join(failing)}. Run: {run_dir}", code=3, stdout=True, failing=failing)
    finally:
        if ts is not None:
            ts.stop()
        if proxy_httpd is not None:
            proxy_httpd.shutdown()
            proxy_httpd.server_close()


def _apply_resume_override(cfg, run_dir, journal, override_file):
    """M36b (Part A): verify a signed resume override and, if valid, APPLY it —
    raising THIS resume's effective budget hard ceiling in `cfg["_budget"]`.

    Runs in `resume` BEFORE any builder call (before _run_loop). Returns
    `(applied: bool, exit_code)`: on a valid override, `(True, None)` after
    journaling OVERRIDE_APPLIED + recording the nonce; on ANY failure
    (unreadable file, absent/short policy, wrong run, expired, replayed,
    threshold-short), `(False, 2)` after journaling OVERRIDE_REJECTED — never a
    silent proceed. The nonce is recorded to the append-only ledger the MOMENT
    the override is accepted (before the loop re-enters), so an override
    authorizes EXACTLY ONE resume even if that resume later fails.
    """
    run_id = os.path.basename(run_dir.rstrip(os.sep))
    control_root = cfg["_control_root"]
    policy = cfg.get("_resume_overrides", {"approvers": [], "threshold": 0})

    if not os.path.exists(override_file):
        journal.write("OVERRIDE_REJECTED", reason="override file not found", path=override_file)
        sys.stderr.write(f"dark-factory: override file not found: {override_file}\n")
        return False, 2
    try:
        with open(override_file, encoding="utf-8") as f:
            doc = json.load(f)
    except (OSError, ValueError) as e:
        journal.write("OVERRIDE_REJECTED", reason=f"unreadable override file: {e}")
        sys.stderr.write(f"dark-factory: cannot read override file: {e}\n")
        return False, 2
    if not isinstance(doc, dict):
        journal.write("OVERRIDE_REJECTED", reason="override file is not a JSON object")
        sys.stderr.write("dark-factory: override file must be a JSON object "
                         "{claim, signatures:[{approver,sig}]}\n")
        return False, 2
    claim = doc.get("claim")
    signatures = doc.get("signatures")
    if not isinstance(signatures, list):
        journal.write("OVERRIDE_REJECTED", reason="override file has no signatures list")
        sys.stderr.write("dark-factory: override file must carry a 'signatures' list\n")
        return False, 2

    # Replay-protection store is fail-closed: a corrupt ledger refuses, never
    # "assume no nonces used".
    try:
        used = df_override.load_used_nonces(control_root)
    except df_override.OverrideError as e:
        journal.write("OVERRIDE_REJECTED", reason=str(e))
        sys.stderr.write(f"dark-factory: {e}\n")
        return False, 2

    satisfied, reason, count, nonce = df_override.verify_override(
        claim=claim, signatures=signatures,
        approvers=policy.get("approvers", []), threshold=policy.get("threshold", 0),
        run_id=run_id,
        now=datetime.datetime.now(datetime.timezone.utc),
        used_nonces=used,
    )
    if not satisfied:
        journal.write("OVERRIDE_REJECTED", reason=reason, run_id=run_id,
                      distinct_signers=count)
        sys.stderr.write(f"dark-factory: resume override REJECTED — {reason}\n")
        return False, 2

    # Accepted. Record the nonce FIRST (the point of no return for replay
    # protection), then apply. A record failure fails the override closed.
    override_type = claim.get("override_type")
    params = claim.get("params", {})
    try:
        df_override.record_nonce(control_root, nonce, run_id=run_id,
                                 override_type=override_type, applied_at=_now())
    except df_override.OverrideError as e:
        journal.write("OVERRIDE_REJECTED", reason=f"nonce record failed: {e}", run_id=run_id)
        sys.stderr.write(f"dark-factory: {e}\n")
        return False, 2

    # Apply: raise this resume's effective budget hard ceiling. The change is
    # in-memory only (cfg is per-invocation); config.json on disk is untouched,
    # so a FRESH run re-reads the original cap. The budget admission loop reads
    # cfg["_budget"]["max_usd"] each iteration, so lifting it here lets the
    # paused run clear the cap it stalled on.
    new_ceiling = float(params["new_usd_ceiling"])
    prev_ceiling = cfg["_budget"].get("max_usd")
    cfg["_budget"]["max_usd"] = new_ceiling
    journal.write("OVERRIDE_APPLIED", override_type=override_type, params=params,
                  distinct_signers=count, nonce=nonce, run_id=run_id,
                  prev_cap_usd=prev_ceiling, new_cap_usd=new_ceiling)
    print(f"dark-factory: resume override APPLIED — budget ceiling raised "
          f"{prev_ceiling} -> {new_ceiling} USD ({count} distinct approver signature(s)).")
    return True, None


def resume(control_root, decision="continue", allow_downgrade: bool = False,
           override_file=None):
    control_root = os.path.abspath(control_root)
    try:
        cfg = load_config(control_root)
    except ConfigError as e:
        sys.stderr.write(f"dark-factory: config error: {e}\n")
        return 2
    cfg["_control_root"] = control_root

    run_dir = latest_paused_run(control_root)
    if run_dir is None:
        sys.stderr.write("dark-factory: no paused run to resume\n")
        return 2

    # Isolation cannot be trusted across a pause, and neither can credentials:
    # re-resolve them every resume (env-file/keychain contents may have
    # changed, or the operator may be fixing a prior refusal) — fail-closed,
    # exit 2, BEFORE any builder call, exactly like the fresh-run path.
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
        state = load_state(run_dir)
        journal = Journal(os.path.join(run_dir, "journal.jsonl"), redactor=redactor)
        run_id = os.path.basename(run_dir.rstrip(os.sep))  # == first-dispatch invocation

        # DF-R9-05 (M77): audit signing is STICKY across a resume. `audit.signing` is
        # re-derived fresh from the same-user-writable config.json on EVERY resume, so
        # a control-root attacker (who does NOT hold the HMAC key) could flip it
        # true->false and resume — the resumed run would then take the UNSIGNED /
        # no-enforcement path for EVERYTHING (source-identity AND ship-completion
        # authentication, chain verification), silently bypassing the detection-grade
        # signed model and reaching the DF-R9-03 downgrade M76 otherwise closes (this
        # is BROADER than source identity, so it is gated FIRST, before that block). A
        # run that anchored a SIGNED source-identity token at first dispatch (every
        # signed run does, or fails closed there) provably STARTED signed; if the
        # freshly loaded config now says signing is OFF, REFUSE (fail closed) — a run
        # cannot switch signed->unsigned across a resume. The anchor is detected WITHOUT
        # the key, so the attacker cannot forge it away undetectably. ON->ON / OFF->OFF
        # / genuine unsigned runs are unaffected (no signed anchor, or signing still
        # on); OFF->ON is already caught downstream (an unsigned run has no signed
        # anchor -> _authenticated_source_identity reads it as tampered).
        if (not bool(cfg.get("_audit", {}).get("signing"))
                and _run_started_signed(control_root, run_id)):
            journal.write("AUDIT_SIGNING_DOWNGRADE_REFUSED", run_id=run_id)
            sys.stderr.write(
                "dark-factory: resume refused (fail-closed) — this run STARTED with audit "
                "signing ON (it holds a signed source-identity anchor in the audit chain) but "
                "config.json now sets audit.signing: false. A run cannot be downgraded from "
                "signed to unsigned across a resume: the unsigned path disables source-identity "
                "and ship-completion authentication and chain verification for the remainder of "
                "the run. Restore audit.signing: true (and key_path) to resume this run, or start "
                "a fresh run under the new config.\n")
            release_lock(lock)
            return 2

        # DF-R7-04: refuse SOURCE DRIFT. The first dispatch persisted its source
        # identity (commit + tree/content digest); if the checkout has since
        # moved — even to a different working tree at the same commit — the
        # logical run would seal an artifact partly built under DIFFERENT
        # supervisor/control-plane bytes than it started with. Compare the
        # persisted anchor to a fresh computation; a mismatch is a fail-closed
        # refusal (exit 2). The resume then re-seals the ORIGINAL sealed source
        # identity (they match), so the manifest stays run-stable.
        # DF-R7-04 (opus F1): the ORIGINAL source identity comes from the JOURNAL
        # (SOURCE_IDENTITY, written at first dispatch — always present for an
        # M67-era run, unlike the per-pause manifest). The PRESENCE of the event is
        # the reliable "this run tracked source identity" signal:
        #   * present (M67+ run): recompute and REFUSE on any drift (below) — a
        #     resume under different source bytes (even same commit) fails closed.
        #   * absent (pre-M67 run): resume through the legacy path unchanged.
        # DF-R8-04 (opus review F1): enforcement now triggers on the EVENT's
        # presence, NOT on `tree_digest is not None`. The journal is same-user
        # writable (no per-line HMAC), so gating on a non-null digest let an
        # attacker NULL the journaled tree_digest to skip both this check AND the
        # per-dispatch guard (which no-ops when `cfg["_source_identity"]` is unset).
        # A nulled anchor is distinguished from a genuine non-git run by the CURRENT
        # checkout: a real git repo recomputes a non-null digest now (see below).
        # DF-R9-03: the journal event is same-user writable, so DELETING it (M71's
        # blind spot) made this whole block no-op and DOWNGRADED resume to the legacy
        # path under a drifted identity. Recover the original identity AUTHENTICATED
        # against the SIGNED audit chain (the identity is also anchored at first
        # dispatch): a source token anchored with no surviving journal event that
        # recomputes to it — or a chain that failed verification / could not be
        # confirmed untruncated — FAILS CLOSED here, and can no longer downgrade.
        _src_status, si_orig = _authenticated_source_identity(
            cfg, control_root, run_dir, run_id)
        if _src_status == "tampered":
            journal.write("SOURCE_DRIFT_REFUSED",
                          sealed_commit=None,
                          current_commit=_source_identity_field().get("commit"),
                          reason="source-anchor-unauthenticated")
            sys.stderr.write(
                "dark-factory: resume refused (fail-closed) — this run's SIGNED source-identity "
                "anchor could not be authenticated against the audit chain (the SOURCE_IDENTITY "
                "record or the audit chain was deleted/replaced, the signed chain failed "
                "verification, or a REQUIRED off-box audit sink is unreachable so a truncation "
                "could not be ruled out). A logical run must execute under ONE authenticated "
                "source identity; start a fresh run under the current source instead of "
                "resuming.\n")
            release_lock(lock)
            return 2
        if _src_status == "unanchored":
            # A pre-M76 or unsigned run has no chain anchor — fall back to the M71
            # journal-presence path (unchanged for those runs).
            si_orig = None
            try:
                with open(os.path.join(run_dir, "journal.jsonl"), encoding="utf-8") as _jf:
                    for _line in _jf:
                        try:
                            _e = json.loads(_line)
                        except ValueError:
                            continue
                        if _e.get("state") == "SOURCE_IDENTITY":
                            si_orig = _e.get("data", {})
                            break
            except OSError:
                si_orig = None
            # DF-R9-03 (tier-independent fallback): source_identity.json is written
            # at first dispatch for EVERY run (see _run_locked), with byte-identical
            # content to the journal SOURCE_IDENTITY event. If the FILE is present
            # (this run tracked source identity) but the journal event is now MISSING
            # or ALTERED, the event was deleted/replaced to dodge the drift check —
            # fail closed. This catches the deletion on UNSIGNED tiers too, where no
            # chain anchor exists. It is best-effort there: an attacker who ALSO
            # deletes source_identity.json leaves nothing to cross-check — that tier
            # is not detection-grade by construction; the signed chain anchor above
            # is the robust guarantee. A pre-M67 run has NEITHER file (no false
            # refusal). Reads that fail leave _si_file None (no cross-check).
            _si_file = None
            try:
                with open(os.path.join(run_dir, SOURCE_IDENTITY_FILE), encoding="utf-8") as _sf:
                    _si_file = json.load(_sf)
            except (OSError, ValueError):
                _si_file = None
            if isinstance(_si_file, dict) and si_orig != _si_file:
                journal.write("SOURCE_DRIFT_REFUSED",
                              sealed_commit=_si_file.get("commit"),
                              current_commit=_source_identity_field().get("commit"),
                              reason="source-journal-event-deleted-or-replaced")
                sys.stderr.write(
                    "dark-factory: resume refused (fail-closed) — this run recorded a source "
                    "identity at first dispatch (source_identity.json) but its journal "
                    "SOURCE_IDENTITY event is now missing or altered (deleted/replaced to dodge "
                    "the resume drift check). A logical run must execute under ONE source "
                    "identity; start a fresh run under the current source instead of resuming.\n")
                release_lock(lock)
                return 2
        if isinstance(si_orig, dict):
            si_now = _source_identity_field()
            od, nd = si_orig.get("tree_digest"), si_now.get("tree_digest")
            # DF-R8-04: fail CLOSED unless the CURRENT source is confirmed identical
            # to the sealed anchor.
            #   * anchor HAS a digest (normal git run): the current digest must be
            #     non-null AND equal — an UNKNOWN current digest (a git failure) must
            #     never resume-proceed (the pre-M71 `nd is not None and od != nd`
            #     let it through).
            #   * anchor digest is NULL: this is HONEST only when the digest was
            #     genuinely unknowable at seal — in which case `clean` is ALSO None
            #     (both are computed together in _source_identity_field; a null
            #     tree_digest never coexists with a definite clean). So a null anchor
            #     with `clean` still True/False is a FORGED/emptied anchor: an
            #     attacker nulled the journaled tree_digest (or forged clean=True) to
            #     dodge this check AND make the bundle's matches_sealed degrade to a
            #     commit-only comparison (opus review F1 + its residual). Refuse on
            #     the impossible (clean, tree_digest) combination — this also catches
            #     the attacker who additionally suppresses the CURRENT git digest
            #     (nd None), which an nd-based check would miss. A genuinely
            #     unknown-source run (clean None) has nothing to enforce and proceeds
            #     (matching pre-M71, no new false refusal).
            if od is not None:
                drift = (nd is None or nd != od)
            else:
                drift = (si_orig.get("clean") is not None)
            if drift:
                journal.write("SOURCE_DRIFT_REFUSED",
                              sealed_commit=si_orig.get("commit"),
                              current_commit=si_now.get("commit"),
                              sealed_digest_known=(od is not None),
                              current_digest_known=(nd is not None))
                if od is None:
                    _reason = ("this run's sealed source anchor is INTERNALLY INCONSISTENT "
                               "(a null tree-digest paired with a definite cleanliness) — an "
                               "emptied/forged source anchor")
                elif nd is None:
                    _reason = ("the current skill source-tree digest is UNKNOWN (a git failure "
                               "must never resume-proceed)")
                else:
                    _reason = "the tree/content digest differs"
                sys.stderr.write(
                    "dark-factory: resume refused (fail-closed) — the skill SOURCE could not be "
                    f"confirmed identical to this run's first dispatch ({_reason}; original commit "
                    f"{si_orig.get('commit')}, now {si_now.get('commit')}). A logical run must "
                    "execute under ONE source identity; start a fresh run under the current "
                    "source instead of resuming.\n")
                release_lock(lock)
                return 2
            cfg["_source_identity"] = si_orig  # re-seal the ORIGINAL on resume

        # M36a Task 3: validate the phase-aware FSM hash chain BEFORE doing any
        # work. A 0.2 state records a head into a per-run fsm_chain.jsonl; recompute
        # the whole chain + verify head-of-chain. ANY mismatch -> refuse,
        # fail-closed (FSM_CHAIN_CORRUPT, exit 2). A pre-M36a 0.1 state has no
        # chain (the field defaults to None on load) -- resume it through the
        # documented back-compat path, journaling FSM_CHAIN_ABSENT_LEGACY so the
        # skip is auditable rather than silent.
        if state.get("state_version") == STATE_VERSION:
            ok, detail = _validate_fsm_chain(run_dir, state.get("fsm_chain_head"))
            if not ok:
                journal.write("FSM_CHAIN_CORRUPT", detail=detail)
                sys.stderr.write(
                    f"dark-factory: FSM_CHAIN_CORRUPT — the resumable checkpoint's "
                    f"transition chain failed integrity validation ({detail}); refusing "
                    f"to resume (fail-closed). This detects accidental corruption of "
                    f"{FSM_CHAIN_FILE}/state.json across the pause.\n")
                return 2
            journal.write("FSM_CHAIN_VERIFIED", head=state.get("fsm_chain_head"),
                          phase=state.get("phase"))
        else:
            journal.write("FSM_CHAIN_ABSENT_LEGACY", state_version=state.get("state_version"))

        # DF-R9 (M77): the FSM chain above is UNSIGNED (sha256) — it detects
        # accidental corruption, but a same-user writer (no audit key) can rewrite it
        # + state.json's head consistently, and it never bound build_approved_through
        # or the budget counters. On a SIGNED run, additionally AUTHENTICATE the
        # loaded checkpoint against the signed audit chain (each state.json write
        # anchored its exact bytes at a monotonic seq): a forged field or a replayed
        # older checkpoint fails closed here, BEFORE any resume override, budget
        # admission, or approval-cursor decision reads the state.
        if bool(cfg.get("_audit", {}).get("signing")):
            ok_st, why_st = _authenticate_resumable_state(
                cfg, control_root, run_dir, run_id, state)
            if not ok_st:
                journal.write("STATE_INTEGRITY_REFUSED", detail=why_st)
                sys.stderr.write(f"dark-factory: resume refused (fail-closed) — {why_st}\n")
                release_lock(lock)
                return 2
            journal.write("STATE_INTEGRITY_VERIFIED", state_seq=state.get("state_seq"))

        audit_key, audit_err = _load_audit_key(cfg, journal)
        if audit_err is not None:
            return audit_err

        # M36b (Part A): a signed resume override is verified + applied BEFORE
        # any builder call. On success it raises this resume's effective budget
        # ceiling (cfg["_budget"]) so a BUDGET-PAUSE'd run can clear the cap it
        # stalled on; on ANY failure the run REFUSES (exit 2), never a silent
        # proceed. Applied only on the loop-re-entering decisions; abort/accept
        # seal a terminal without building, so an override there is meaningless.
        if override_file is not None and decision in ("continue", "reconcile"):
            _applied, _ov_exit = _apply_resume_override(cfg, run_dir, journal, override_file)
            if _ov_exit is not None:
                return _ov_exit

        spec_text = open(os.path.join(control_root, "spec.md"), encoding="utf-8").read()
        scenarios_dir = os.path.join(control_root, "scenarios")

        # RA-05/M45: SEAL enforcement. The hidden acceptance scenarios live in
        # the LIVE control root; without this, a resume re-hashes them and uses
        # the value as-is, so an operator could EDIT the criteria between pause
        # and resume and qualify the builder against a different scenario set
        # than the run started with. Enforce immutability, fail-closed.
        #
        # The sealed run-start hash is looked up from THREE independent
        # run-start records, in order (R1): (1) the FSM chain's genesis entry
        # (authoritative + tamper-evident: the chain was integrity-validated
        # just above); (2) the additive state.json field (covers a no-chain
        # state); (3) the journal's INIT event (a THIRD record, so the
        # unenforced legacy path below is only reachable when NONE of the three
        # carries a run-start hash). `_scenario_set_hash(scenarios_dir)` here is
        # computed IDENTICALLY to run start (same control_root/scenarios dir,
        # same function, and the run-start seal predates the generated-scenarios
        # dir so neither side hashes gen_dir) — an UNCHANGED bundle always
        # matches and resumes byte-compatibly; only a genuine edit diverges.
        sealed_hash = None
        if state.get("state_version") == STATE_VERSION:
            sealed_hash = _chain_scenario_set_sha256(run_dir)
        if sealed_hash is None:
            sealed_hash = state.get("scenario_set_sha256")
        if sealed_hash is None:
            sealed_hash = _init_scenario_set_sha256_from_journal(run_dir)
        if sealed_hash is None:
            # No run-start hash in the chain genesis, the state.json field, OR
            # the journal INIT event, so there is nothing to enforce against.
            # Reachable for a genuinely pre-seal (pre-M45) run, OR if a same-
            # user actor stripped EVERY run-start hash record (downgraded
            # state.json to 0.1, deleted fsm_chain.jsonl and the state field,
            # and stripped the unauthenticated journal INIT record). Journal it
            # (auditable, not silent) and proceed — we cannot enforce an
            # immutability that was never established. The residual is the same
            # same-user, detection-grade scope as the FSM chain itself (a
            # process that can rewrite all three records could equally rewrite
            # a chain + its recorded head together).
            journal.write("SCENARIO_BUNDLE_UNSEALED_LEGACY",
                          state_version=state.get("state_version"))
        else:
            current_hash = _scenario_set_hash(scenarios_dir)
            if current_hash != sealed_hash:
                journal.write("SCENARIO_BUNDLE_CHANGED",
                              sealed=sealed_hash, current=current_hash)
                sys.stderr.write(
                    "dark-factory: SCENARIO_BUNDLE_CHANGED — the acceptance "
                    "scenario set changed since this run started "
                    f"(sealed {sealed_hash[:12]}…, live {current_hash[:12]}…); "
                    "refusing to resume (fail-closed). The hidden acceptance "
                    "criteria are sealed at run start and must not be edited "
                    "across a pause.\n")
                return 2
            journal.write("SCENARIO_BUNDLE_VERIFIED", sealed=sealed_hash)

        # M86 (post-R10 audit): RA-05 immutability EXTENDED to the brownfield-GENERATED
        # regression cohort (run_dir/generated-scenarios/*.json), which is created after
        # the run-start seal so `scenario_set_sha256` never covered it. Its hash is
        # sealed into state.json (M77-anchored into the signed chain) at each pause; a
        # same-user writer who WEAKENS or DELETES a generated BHV-REGRESS scenario across
        # a pause (to make a build that broke original behavior converge) is caught here.
        # Only enforced when a seal exists (a run that produced a cohort) — a run with no
        # generated cohort has None on both sides.
        sealed_gen = state.get("generated_set_sha256")
        _gd = os.path.join(run_dir, "generated-scenarios")
        _has_gen = os.path.isdir(_gd) and any(n.endswith(".json") for n in os.listdir(_gd))
        if sealed_gen is None and _has_gen:
            # A generated cohort exists but carries NO seal — a genuinely pre-M86 paused
            # run (every M86+ pause, including the dispatch crash-safe save, seals it).
            # Journal it (auditable, not a silent skip) and proceed; we cannot enforce an
            # immutability that was never established — same posture as
            # SCENARIO_BUNDLE_UNSEALED_LEGACY.
            journal.write("GENERATED_BUNDLE_UNSEALED_LEGACY",
                          state_version=state.get("state_version"))
        if sealed_gen is not None:
            current_gen = (_scenario_set_hash(_gd) if os.path.isdir(_gd) else None)
            if current_gen != sealed_gen:
                journal.write("GENERATED_BUNDLE_CHANGED", sealed=sealed_gen, current=current_gen)
                sys.stderr.write(
                    "dark-factory: GENERATED_BUNDLE_CHANGED — the brownfield-generated "
                    "regression cohort (generated-scenarios/) changed since this run started "
                    f"(sealed {sealed_gen[:12]}…, live "
                    f"{(current_gen or 'absent')[:12] if current_gen else 'absent'}…); refusing "
                    "to resume (fail-closed). The generated regression guard is sealed at run "
                    "start and must not be edited or deleted across a pause.\n")
                return 2
            journal.write("GENERATED_BUNDLE_VERIFIED", sealed=sealed_gen)

        adapter = cfg["roles"]["builder"]["adapter"]
        timeout_s = cfg["roles"]["builder"].get("timeout_s", 600)
        cli = os.path.basename(adapter)
        manifest_base = {
            "invocation": os.path.basename(run_dir),
            "tier": cfg["assurance"],
            # Additive (M27 Task 2): same "fresh + resume" threading as
            # `credentials`/`mode`/`builder_confinement`.
            "candidate_network": cfg["candidate_network"],
            # Additive (M29b): preliminary seed; replaced with the re-probed
            # truth after resolve_candidate_prefix below (isolation cannot be
            # trusted across a pause, and neither can host isolation).
            "host_isolation": _host_isolation_preliminary(cfg),
            "qualified": cfg["_qualified"],
            "config_sha256": cfg["_config_sha256"],
            "spec_sha256": sha256_str(spec_text),
            "scenario_set_sha256": _scenario_set_hash(scenarios_dir),
            "adapter_sha256": sha256_file(adapter) if os.path.exists(adapter) else None,
            "snapshot_sha256": _snapshot_sha256_from_journal(run_dir),
            "credentials": ({"source": cfg["_credentials"]["source"],
                            "allowlist": list(cfg["_credentials"]["allowlist"])}
                           if cfg["_credentials"] else None),
            # Additive (M14), same "fresh + resume" threading as `credentials`
            # (M11) / `mode`+`characterization` (M15). NOTE: a mid-run
            # required=False CONFINEMENT_WARN downgrade from BEFORE the pause
            # is not recovered here (not persisted in state.json) — a resumed
            # run re-attempts confine=True once more on its first iteration if
            # cfg["_confine"]["enabled"] is still True, exactly like isolation
            # being re-probed on every resume rather than trusted across a
            # pause. Deterministic (same adapter => same unsupported result),
            # so this just re-derives the same WARN, never silently skips it.
            # DF-R3-05: same identity binding as the fresh-run path.
            "builder_confinement": _confine_manifest_field(
                cfg["_confine"], cli, adapter, cfg["_adapter_digests"]["builder"]),
            # Additive (M17 Task 3), same "fresh + resume" threading as
            # `credentials`/`builder_confinement`: None here, overridden only
            # by _run_loop's CONVERGED branch when the effective tier is
            # enterprise.
            "custody": None,
            "proxy": None,
            "enterprise_egress": None,
            # Additive (M22 Task 1): see the matching seed in the fresh-run
            # manifest_base above.
            "enterprise_seccomp": None,
            # Additive (DF-01/M28a Task 2): see the matching seed + comment
            # in the fresh-run manifest_base above.
            "artifact": None,
            # Additive (M40): same config-known "fresh + resume" threading as
            # credentials -- a resumed run of an agent-authored control root
            # still records WHICH independent model wrote the scenarios.
            "authored_by": (
                {"adapter": cfg["_author"]["adapter"],
                 "adapter_sha256": (sha256_file(cfg["_author"]["adapter"])
                                    if os.path.exists(cfg["_author"]["adapter"]) else None),
                 "same_model_ack": cfg["_author"]["same_model_ack"],
                 "model_identity": cfg["_author"]["model_identity"]}
                if cfg.get("_author") else None
            ),
            # Additive (M42): same fresh+resume threading as authored_by.
            # DF-R3-04 (M50): model_identity sealed on resume too.
            "critic": (
                {"adapter": cfg["_critic"]["adapter"],
                 "adapter_sha256": (sha256_file(cfg["_critic"]["adapter"])
                                    if os.path.exists(cfg["_critic"]["adapter"]) else None),
                 "same_model_ack": cfg["_critic"]["same_model_ack"],
                 "model_identity": cfg["_critic"]["model_identity"]}
                if cfg.get("_critic") else None
            ),
            # DF-R4-09 (M55) + M60 (R5 arbitration): same fresh+resume threading —
            # the builder's model_identity AND every support-file digest, sealed
            # on resume too.
            "builder_identity": _builder_identity_field(cfg),
            "source_identity": cfg.get("_source_identity") or _source_identity_field(),  # DF-R6-07 / DF-R7-04
        }

        # M7: coverage/oracle are deterministic from the control root +
        # scenarios, so resume() recomputes them (cheaply) instead of
        # re-running the fail-closed gate — a resumed run already passed the
        # gate once, on the initial `run`; re-gating here could spuriously
        # fail an already-approved run. If scenarios no longer load cleanly
        # (control root edited mid-run — not the gate's contract to police
        # here), fall back to honest "unknown" fields; a genuine oracle
        # problem still surfaces normally when `continue` re-enters the loop
        # and run_all() re-loads the scenarios itself.
        gate_scenarios = None
        try:
            gate_scenarios = load_scenarios(scenarios_dir)
            gate_inert = df_gates.validate_oracle(gate_scenarios)
            oracle = {"mutation_validated": not gate_inert, "inert": gate_inert}
            try:
                gate_behaviors = df_gates.load_behaviors(control_root)
                cov = (df_gates.check_coverage(gate_behaviors, gate_scenarios)
                       if gate_behaviors is not None else {"checked": False})
            except df_gates.GateError:
                gate_behaviors = None
                cov = {"checked": False}
        except OracleError:
            gate_behaviors, gate_scenarios = None, None
            cov, oracle = {"checked": False}, {"mutation_validated": False, "inert": []}
        manifest_base["coverage"] = cov
        manifest_base["oracle"] = oracle
        # M42: recompute the adequacy record (deterministic from the control
        # root + scenarios) for the resumed run's manifests -- same "resume
        # recomputes rather than re-gates" discipline as coverage/oracle. If
        # scenarios no longer load, fall back to the policy-only record.
        if gate_scenarios is not None:
            manifest_base["adequacy"] = _adequacy_manifest_field(
                cfg, gate_behaviors, gate_scenarios)
        else:
            manifest_base["adequacy"] = {
                "checked": False,
                "required_classes": cfg["_adequacy"]["required_classes"],
                "min_per_class": cfg["_adequacy"]["min_per_class"],
                "sharpness": {"scenarios": 0, "min_killed": 0, "weakest": []},
                "critic": None,
            }
        # M43a: recompute the property record on resume too (deterministic
        # from the scenarios, same discipline as coverage/adequacy above).
        # Violations recorded before the pause live in the PARENT segment's
        # journal/manifest; this segment's list starts empty.
        manifest_base["property"] = (
            _property_manifest_field(gate_scenarios) if gate_scenarios is not None
            else {"scenarios": {}, "violations": []})
        # M9 default (same reasoning as _run_locked): overridden on a
        # resumed-converge by _run_loop's CONVERGED branch, which is the
        # SAME code both run() and resume() funnel through.
        manifest_base["security"] = {"checked": False}

        # M15: brownfield mode/characterization -- NOT re-detected or
        # re-characterized on resume (project_src isn't even passed to
        # resume(), and re-observing a possibly-changed source would defeat
        # the sealed dev cohort the first `run` already froze). Reuse the
        # ORIGINAL run's <run_dir>/generated-scenarios/ (if any) and recover
        # `mode`/`legacy_ignored` from the MODE_DETECTED journal entry the
        # fresh-run path always writes; `probes` is deterministic from cfg
        # (same as a fresh run), `generated` is the actual sealed file count.
        gen_dir = os.path.join(run_dir, "generated-scenarios")
        extra_scenarios_dir = gen_dir if os.path.isdir(gen_dir) else None
        resumed_mode, resumed_legacy_ignored = _mode_from_journal(run_dir)
        generated_count = (
            len([n for n in os.listdir(gen_dir) if n.endswith(".json")])
            if extra_scenarios_dir else 0
        )
        manifest_base["mode"] = resumed_mode
        manifest_base["characterization"] = (
            {"probes": len(cfg["_brownfield"]["probes"]), "generated": generated_count,
             "note": "behavioral snapshot at probe points; unprobed behavior may regress",
             "legacy_ignored": bool(resumed_legacy_ignored)}
            if resumed_mode == "brownfield" or resumed_legacy_ignored
            else {"probes": 0, "generated": 0}
        )

        # M12: twin_evidence, recomputed fresh on every resume (deterministic
        # from cfg + the control root's twins/*.json + scenarios) -- same
        # "fresh + resume" threading as `credentials`. gate_scenarios may be
        # None if scenarios failed to reload above; observed_assertions then
        # honestly falls back to 0 rather than raising here too.
        try:
            manifest_base["twin_evidence"] = _twin_manifest_field(cfg, gate_scenarios or [])
            # M21: `twins`, recomputed fresh on every resume, same as
            # `twin_evidence` -- deterministic from cfg + the control root's
            # twins/*.json.
            manifest_base["twins"] = _twins_manifest_field(cfg)
        except df_twins.TwinError as e:
            journal.write("TWIN_ERROR", detail=str(e))
            mf = dict(manifest_base, outcome="ABORTED_BUILD_ERROR",
                      iterations=state["next_iter"] - 1, qualified=False,
                      sandbox_backend=None, denial_probe_passed=False, container=None,
                      final_exam={"ran": False, "passed": None, "count": 0},
                      regressions=sorted(state.get("regressions", [])),
                      twin_evidence=None, twins=None,
                      budget=_budget_manifest_field(
                          cfg["_budget"], state.get("builder_calls", 0),
                          state.get("estimated_usd", 0.0)),
                      usage=_usage_manifest_field(
                          cfg["_budget"], state.get("usage_known", False),
                          state.get("builder_input_tokens", 0),
                          state.get("builder_output_tokens", 0)))
            digest = finalize_manifest(run_dir, mf, audit_key=audit_key, redactor=redactor)
            anchor_exit = _anchor_audit(cfg, cfg["_control_root"], run_dir, mf["invocation"],
                                        digest, audit_key, journal)
            os.unlink(os.path.join(run_dir, "state.json"))
            _kb_writeback(cfg, journal, mf, [])
            sys.stderr.write(f"dark-factory: twin precondition failed: {e}\n")
            return anchor_exit or 2

        if decision == "abort":
            # M36b Part C: aborting from an AWAIT_SHIP pause is a SHIP DECLINE,
            # not a generic human abort — the artifact converged and froze; the
            # human chose not to ship it. Seal a distinct SHIP_DECLINED terminal
            # (qualified False) that BINDS the frozen artifact object (so the
            # declined candidate is auditable), rather than ABORTED_BY_HUMAN.
            ship_meta = state.get("ship_meta")
            if state.get("phase") == "AWAIT_SHIP" and isinstance(ship_meta, dict):
                journal.write("SHIP_DECLINED",
                              converged_iteration=ship_meta.get("converged_iteration"),
                              artifact_object_id=(ship_meta.get("artifact_field") or {}).get("object_id"))
                mf = dict(manifest_base, outcome="SHIP_DECLINED",
                          iterations=ship_meta.get("converged_iteration",
                                                   state["next_iter"] - 1),
                          qualified=False,
                          sandbox_backend=None, denial_probe_passed=False, container=None,
                          final_exam=ship_meta.get("final_exam")
                          or {"ran": False, "passed": None, "count": 0},
                          artifact=ship_meta.get("artifact_field"),
                          regressions=sorted(state.get("regressions", [])),
                          budget=_budget_manifest_field(
                              cfg["_budget"], state.get("builder_calls", 0),
                              state.get("estimated_usd", 0.0)),
                          usage=_usage_manifest_field(
                              cfg["_budget"], state.get("usage_known", False),
                              state.get("builder_input_tokens", 0),
                              state.get("builder_output_tokens", 0)))
                digest = finalize_manifest(run_dir, mf, audit_key=audit_key, redactor=redactor)
                anchor_exit = _anchor_audit(cfg, cfg["_control_root"], run_dir, mf["invocation"],
                                            digest, audit_key, journal)
                os.unlink(os.path.join(run_dir, "state.json"))
                _kb_writeback(cfg, journal, mf, [])
                print("dark-factory: SHIP DECLINED — converged artifact not shipped "
                      "(sealed SHIP_DECLINED, not qualified).")
                return anchor_exit or 2
            journal.write("ABORTED_BY_HUMAN")
            mf = dict(manifest_base, outcome="ABORTED_BY_HUMAN",
                      iterations=state["next_iter"] - 1,
                      qualified=False,
                      sandbox_backend=None, denial_probe_passed=False, container=None,
                      final_exam={"ran": False, "passed": None, "count": 0},
                      regressions=sorted(state.get("regressions", [])),
                      budget=_budget_manifest_field(
                          cfg["_budget"], state.get("builder_calls", 0),
                          state.get("estimated_usd", 0.0)),
                      usage=_usage_manifest_field(
                          cfg["_budget"], state.get("usage_known", False),
                          state.get("builder_input_tokens", 0),
                          state.get("builder_output_tokens", 0)))
            digest = finalize_manifest(run_dir, mf, audit_key=audit_key, redactor=redactor)
            anchor_exit = _anchor_audit(cfg, cfg["_control_root"], run_dir, mf["invocation"],
                                        digest, audit_key, journal)
            os.unlink(os.path.join(run_dir, "state.json"))
            _kb_writeback(cfg, journal, mf, [])
            print("dark-factory: ABORTED by human.")
            return anchor_exit or 2
        if decision == "accept":
            journal.write("ACCEPTED_BY_HUMAN",
                          note="human accepted a non-passing build — waived/unverified")
            mf = dict(manifest_base, outcome="ACCEPTED_WAIVED",
                      qualified=False,
                      sandbox_backend=None, denial_probe_passed=False, container=None,
                      iterations=state["next_iter"] - 1,
                      final_exam={"ran": False, "passed": None, "count": 0},
                      regressions=sorted(state.get("regressions", [])),
                      budget=_budget_manifest_field(
                          cfg["_budget"], state.get("builder_calls", 0),
                          state.get("estimated_usd", 0.0)),
                      usage=_usage_manifest_field(
                          cfg["_budget"], state.get("usage_known", False),
                          state.get("builder_input_tokens", 0),
                          state.get("builder_output_tokens", 0)))
            digest = finalize_manifest(run_dir, mf, audit_key=audit_key, redactor=redactor)
            anchor_exit = _anchor_audit(cfg, cfg["_control_root"], run_dir, mf["invocation"],
                                        digest, audit_key, journal)
            os.unlink(os.path.join(run_dir, "state.json"))
            _kb_writeback(cfg, journal, mf, [])
            print("dark-factory: ACCEPTED (waived/unverified — not a qualified ship-candidate).")
            return anchor_exit or 0

        # DF-08/M35: decision in {"continue", "reconcile"} both re-enter the
        # loop below, but "continue" must NEVER silently re-dispatch a
        # builder call whose outcome is unknown (a prior process crashed
        # after committing the reserved spend but before the call
        # resolved) -- fail-closed by default. Only "reconcile" (explicit
        # operator consent to possible duplicate spend) clears the way.
        unresolved = _unresolved_dispatch_intent(run_dir) if decision in ("continue", "reconcile") else None
        if unresolved is not None:
            if decision == "continue":
                journal.write("UNKNOWN_OUTCOME", iteration=unresolved.get("iteration"),
                              idempotency_key=unresolved.get("idempotency_key"),
                              reserved_calls=unresolved.get("reserved_calls"),
                              reserved_usd=unresolved.get("reserved_usd"))
                sys.stderr.write(
                    f"dark-factory: a model dispatch at iteration {unresolved.get('iteration')} "
                    "did not resolve before a crash; its outcome is unknown — reconcile before "
                    "continuing. The reserved spend has been counted. To proceed, "
                    "`resume --decision reconcile` (re-dispatches, accepting possible duplicate "
                    "spend) or `--decision abort`.\n")
                return UNKNOWN_OUTCOME
            # decision == "reconcile": operator consents to possibly
            # re-sending a builder call whose earlier outcome is unknown.
            # The reserved spend from the crashed attempt is NOT reversed
            # (never understate — see DISPATCH_INTENT above); _run_loop
            # re-entering at the same iteration will reserve+commit AGAIN
            # for the retry, so a reconciled iteration's budget numbers
            # honestly reflect up to two attempted calls.
            journal.write("DISPATCH_RECONCILED", iteration=unresolved.get("iteration"),
                          idempotency_key=unresolved.get("idempotency_key"),
                          note="operator accepted possible duplicate spend; re-dispatching")
            print(f"dark-factory: reconciling unresolved dispatch at iteration "
                  f"{unresolved.get('iteration')} — re-dispatching (possible duplicate spend).")

        # decision == "continue" (or "reconcile", now cleared) — isolation
        # cannot be trusted across a pause; re-probe (and re-wrap) before
        # re-entering the loop.
        # DF-R5-09: seed the run's PINNED image identity from the journal
        # BEFORE the re-probe, so the resume-segment probes exercise the SAME
        # image bytes every dispatch of this logical run uses — never a
        # re-resolved (possibly moved) tag.
        _pin_effective_image(cfg, run_dir, journal)
        try:
            eff_tier, exec_prefix, backend_name, probe_passed = resolve_isolation(
                cfg, control_root, state["workspace"], journal, allow_downgrade)
        except df_sandbox.SandboxError as e:
            sys.stderr.write(f"dark-factory: {e}\n")
            return 2
        manifest_base["qualified"] = eff_tier in _QUALIFYING_TIERS
        manifest_base["sandbox_backend"] = backend_name
        manifest_base["denial_probe_passed"] = probe_passed
        manifest_base["container"] = _finalize_container_manifest(cfg, eff_tier)
        manifest_base["_effective_tier"] = eff_tier
        if eff_tier not in _QUALIFYING_TIERS:
            sys.stderr.write("dark-factory: COOPERATIVE MODE — unqualified: no probe-proven "
                             "isolation; outcome can never be a qualified ship-candidate.\n")
        # M27 Task 2 + M29b: re-derive the candidate-only wrapper (and
        # re-prove default-deny confinement) on every resume too — isolation
        # cannot be trusted across a pause, and neither can a network
        # restriction or a host-read denial built on top of it.
        try:
            candidate_prefix, host_isolation = resolve_candidate_prefix(
                cfg, control_root, state["workspace"], exec_prefix, eff_tier, journal,
                allow_downgrade=allow_downgrade)
        except df_sandbox.SandboxError as e:
            sys.stderr.write(f"dark-factory: {e}\n")
            return 2
        manifest_base["host_isolation"] = host_isolation
        journal.write("HOST_ISOLATION", **host_isolation)
        try:
            return _run_loop(
                cfg, journal, run_dir, manifest_base, spec_text, scenarios_dir,
                adapter, timeout_s, state["workspace"],
                start_iter=state["next_iter"], feedback=state["feedback"],
                exec_prefix=exec_prefix, candidate_prefix=candidate_prefix,
                audit_key=audit_key,
                prev_dev_status=state.get("dev_status", {}),
                regressions=state.get("regressions", []),
                builder_calls=state.get("builder_calls", 0),
                estimated_usd=state.get("estimated_usd", 0.0),
                budget_alerted=state.get("budget_alerted", False),
                creds=creds, redactor=redactor, extra_scenarios_dir=extra_scenarios_dir,
                builder_input_tokens=state.get("builder_input_tokens", 0),
                builder_output_tokens=state.get("builder_output_tokens", 0),
                usage_known=state.get("usage_known", False),
                # M36a: the before-build (H1/directed) one-shot cursor. Resuming
                # FROM a "build" pause means the human APPROVED building this
                # iteration -- carry the cursor up to it so the loop does NOT
                # re-pause the build it just approved. Every other resume simply
                # threads the persisted cursor forward.
                # DF-R9 (M77): this cursor is ADVANCE-ONLY — it is only ever set to
                # `next_iter` (the approved iteration) or threaded forward unchanged,
                # NEVER lowered by any legitimate path. That is what makes the M77
                # truncation-replay residual a BUDGET-only concern: replaying an
                # OLDER signed checkpoint yields a LOWER cursor → MORE approval pauses
                # (the safe direction), never an approval-skip. Keep it advance-only.
                build_approved_through=(
                    state["next_iter"] if state.get("reason") == "build"
                    else state.get("build_approved_through", 0)),
                # M36b Part C: resuming FROM an AWAIT_SHIP pause seals the frozen
                # artifact WITHOUT re-entering the build loop (no builder call).
                resume_ship=(state.get("phase") == "AWAIT_SHIP"),
                ship_meta=state.get("ship_meta"),
            )
        except df_sandbox.SandboxError as e:
            # In-loop fail-closed guards exit 2, not an unhandled traceback.
            sys.stderr.write(f"dark-factory: {e}\n")
            return 2
    finally:
        release_lock(lock)


def migrate_config_cmd(control_root) -> int:
    """M36a Task 5: rewrite a legacy (autonomy, checkpoint) config to the
    equivalent `intervention_mode`. Validate-before-commit (the rewritten config
    must load cleanly), atomic, idempotent (already-migrated -> no-op), refuses
    a dual-field config (hand-edit to resolve), and leaves a config.json.bak."""
    control_root = os.path.abspath(control_root)
    cfg_path = os.path.join(control_root, "config.json")
    if not os.path.exists(cfg_path):
        sys.stderr.write(f"dark-factory: no config.json under {control_root}\n")
        return 2
    try:
        original_text = open(cfg_path, encoding="utf-8").read()
        raw = json.loads(original_text)
    except (OSError, json.JSONDecodeError) as e:
        sys.stderr.write(f"dark-factory: cannot read config.json: {e}\n")
        return 2
    if not isinstance(raw, dict):
        sys.stderr.write("dark-factory: config.json is not a JSON object\n")
        return 2

    has_mode = "intervention_mode" in raw
    has_legacy = ("autonomy" in raw) or ("checkpoint" in raw)
    if has_mode and has_legacy:
        sys.stderr.write(
            "dark-factory: config has BOTH intervention_mode and legacy "
            "autonomy/checkpoint — resolve by hand (remove one); refusing to guess.\n")
        return 2
    if has_mode:
        print(f"dark-factory: already migrated (intervention_mode="
              f"{raw['intervention_mode']!r}); no change.")
        return 0

    # Map legacy (or the all-defaults case) to a mode. Mirrors df_config's
    # legacy defaulting exactly so the mapped mode matches what the config
    # loads as today.
    autonomy = raw.get("autonomy", 4)
    checkpoint = raw.get("checkpoint")
    if checkpoint is None:
        checkpoint = "pause" if autonomy == 4 else "auto"
    try:
        mode = df_modes.legacy_mode(autonomy, checkpoint)
    except df_modes.ModeError as e:
        sys.stderr.write(f"dark-factory: cannot migrate this config: {e}\n")
        return 2

    new_raw = {k: v for k, v in raw.items() if k not in ("autonomy", "checkpoint")}
    new_raw["intervention_mode"] = mode
    new_text = canonical_json(new_raw)

    # Validate-before-commit: write the candidate, confirm load_config accepts
    # it, and roll back to the original bytes on any ConfigError so a failed
    # migration never leaves a broken config on disk.
    atomic_write(cfg_path, new_text)
    try:
        load_config(control_root)
    except ConfigError as e:
        atomic_write(cfg_path, original_text)
        sys.stderr.write(
            f"dark-factory: migrated config failed validation ({e}); "
            f"rolled back, no change.\n")
        return 2

    atomic_write(cfg_path + ".bak", original_text)
    src = "defaults" if not has_legacy else f"autonomy={autonomy}, checkpoint={checkpoint!r}"
    print(f"dark-factory: migrated {cfg_path}\n"
          f"  {src}  ->  intervention_mode={mode!r}\n"
          f"  (removed legacy autonomy/checkpoint; original saved as config.json.bak)")
    return 0


def main():
    ap = argparse.ArgumentParser(prog="dark-factory supervisor")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p_init = sub.add_parser(
        "init", help="scaffold + validate a ready-to-run control root from an answers file")
    p_init.add_argument("--control-root", required=True)
    p_init.add_argument("--answers", required=True,
                        help="path to an answers JSON file, or '-' to read from stdin")
    p_init.add_argument("--force", action="store_true",
                        help="overwrite a non-empty --control-root")
    p_init.add_argument("--force-keep", action="store_true",
                        help="on a failed validation, keep the scaffolded tree for inspection "
                             "instead of removing it")
    p_run = sub.add_parser("run", help="execute the build/verify loop")
    p_run.add_argument("--control-root", required=True)
    p_run.add_argument("--project-src", default=None)
    p_run.add_argument("--allow-downgrade", action="store_true",
                       help="if standard tier is unavailable/probe fails, downgrade to "
                            "cooperative (unqualified) instead of failing closed")
    p_author = sub.add_parser(
        "author-scenarios",
        help="M40: have the configured roles.author agent (a DIFFERENT model than "
             "the builder) write the hidden scenarios into a scenarios-pending "
             "control root")
    p_author.add_argument("--control-root", required=True)
    p_author.add_argument("--attempts", type=int, default=3,
                          help="max author invocations (bounded retry on impoverished, "
                               "barrier-safe feedback); default 3")
    p_author.add_argument("--review", action="store_true",
                          help="print each generated scenario and require interactive "
                               "confirmation before install (off by default)")
    p_ver = sub.add_parser("verify-manifest", help="check a run's audit manifest")
    p_ver.add_argument("--run-dir", required=True)
    p_ver.add_argument("--key-path", default=None,
                       help="path to the audit signing key; required to verify a "
                            "signed (manifest.hmac) run")
    p_ver.add_argument("--object-store", default=None,
                       help="DF-01/M28a: path to the content-addressed object store "
                            "(default <control_root>/objects, derived from --run-dir)")
    p_vc = sub.add_parser("verify-chain", help="check a control root's hash-chained audit log")
    p_vc.add_argument("control_root")
    p_vc.add_argument("--key-path", default=None,
                      help="path to the audit signing key; required to verify a "
                           "signed (any entry carrying 'sig') chain")
    p_eb = sub.add_parser(
        "evidence-bundle",
        help="assemble the production-validation evidence bundle from a completed "
             "run (read-only; see references/live-validation.md)")
    p_eb.add_argument("control_root")
    p_eb.add_argument("--run-dir", required=True,
                      help="the completed run_dir to report on (under <control_root>/runs)")
    p_eb.add_argument("--out", default=None,
                      help="write the JSON bundle here (default: stdout)")
    p_eb.add_argument("--key-path", default=None,
                      help="path to the audit key; supply it to record a real signed-chain "
                           "verification result in the bundle (else it records UNVERIFIED)")
    p_eb.add_argument("--require-production", action="store_true",
                      help="DF-R6-07/R7-03: add a production_ready verdict that fails closed "
                           "(exit 3) unless EVERY fact the named --profile requires is present, "
                           "bound, and cryptographically verified — a partial or mock exercise "
                           "can never read as production-GO evidence")
    p_eb.add_argument("--profile", choices=["hardened-h4", "enterprise"], default=None,
                      help="DF-R7-03: the production evidence profile to enforce with "
                           "--require-production (hardened-h4 = Exercise A, enterprise = "
                           "Exercise B)")
    p_res = sub.add_parser("resume", help="resume a paused run")
    p_res.add_argument("--control-root", required=True)
    p_res.add_argument("--decision", choices=["continue", "accept", "abort", "reconcile"],
                       default="continue")
    p_res.add_argument("--allow-downgrade", action="store_true",
                       help="if standard tier is unavailable/probe fails on re-probe, "
                            "downgrade to cooperative (unqualified) instead of failing closed")
    p_res.add_argument("--override", default=None, dest="override_file",
                       help="M36b: path to a signed resume-override file "
                            "{claim, signatures:[{approver,sig}]} (df-override sign) — "
                            "raises this resume's budget ceiling before any builder call")
    p_fork = sub.add_parser(
        "df-fork",
        help="M36b: start a NEW run seeded from a PARENT run's sealed artifact object "
             "(records lineage; marks the parent superseded)")
    p_fork.add_argument("control_root")
    p_fork.add_argument("--parent-run", required=True,
                        help="the parent run_dir (under <control_root>/runs) whose verified, "
                             "artifact-bound sealed manifest the child forks from")
    p_fork.add_argument("--allow-downgrade", action="store_true",
                        help="if standard tier is unavailable/probe fails, downgrade to "
                             "cooperative (unqualified) instead of failing closed")
    p_mig = sub.add_parser(
        "df-migrate-config",
        help="rewrite a legacy autonomy/checkpoint config.json to the equivalent "
             "intervention_mode (idempotent; leaves a .bak)")
    p_mig.add_argument("control_root")
    p_vcu = sub.add_parser(
        "verify-custody",
        help="confirm an enterprise run is QUALIFIED under split custody "
             "(a valid K-of-N custody_attestation.json binds its sealed manifest)")
    p_vcu.add_argument("control_root")
    p_vcu.add_argument("--run-dir", required=True)

    # `df-custody` — the split-custody operator CLI (M17 two-phase ship):
    #   keygen  -> a fresh approver ed25519 keypair
    #   sign    -> an approver signs a run's sealed manifest bytes
    #   attach  -> PHASE 2: verify collected sigs + write custody_attestation.json
    p_dc = sub.add_parser("df-custody", help="split-custody keygen / sign / attach (enterprise)")
    dc_sub = p_dc.add_subparsers(dest="custody_cmd", required=True)
    dc_keygen = dc_sub.add_parser("keygen", help="generate a fresh approver ed25519 keypair")
    dc_keygen.add_argument("--out-prefix", default=None,
                           help="if given, write <prefix>.key (private) + <prefix>.pub (public); "
                                "otherwise print both to stdout")
    dc_sign = dc_sub.add_parser(
        "sign", help="sign a run's sealed manifest bytes; prints a {approver,sig} JSON entry")
    dc_sign.add_argument("--manifest", required=True, help="path to the run's manifest.json")
    dc_sign.add_argument("--key-file", required=True,
                         help="path to the approver's private key (raw-32-byte hex)")
    dc_attach = dc_sub.add_parser(
        "attach", help="PHASE 2: verify collected approver signatures over the sealed manifest "
                       "and, if K-of-N satisfied, write custody_attestation.json + anchor it")
    dc_attach.add_argument("control_root")
    dc_attach.add_argument("--run-dir", required=True)

    # `df-waiver` — the M33a (DF-06) waiver operator CLI, structurally a mirror
    # of df-custody but for security-gate findings on a SECURITY_GATE_FAILED
    # run: findings -> sign -> collect -> attach -> verify (expiry re-checked
    # at every verify). See references/security-gates.md.
    p_dw = sub.add_parser("df-waiver",
                          help="signed/scoped/expiring security-gate waivers "
                               "(keygen / findings / sign / attach / verify)")
    dw_sub = p_dw.add_subparsers(dest="waiver_cmd", required=True)
    dw_keygen = dw_sub.add_parser("keygen", help="generate a fresh waiver-signer ed25519 keypair")
    dw_keygen.add_argument("--out-prefix", default=None,
                           help="if given, write <prefix>.key (private) + <prefix>.pub (public); "
                                "otherwise print both to stdout")
    dw_findings = dw_sub.add_parser(
        "findings", help="list a failed run's WAIVABLE finding fingerprints (+ un-waivable gates) "
                         "so an operator knows what to sign")
    dw_findings.add_argument("--manifest", required=True, help="path to the run's manifest.json")
    dw_sign = dw_sub.add_parser(
        "sign", help="sign ONE finding fingerprint for a run; prints a {claim,signer,sig} entry "
                     "(all binding digests recomputed FROM the sealed manifest)")
    dw_sign.add_argument("--manifest", required=True, help="path to the run's manifest.json")
    dw_sign.add_argument("--fingerprint", required=True,
                         help="the finding fingerprint to waive (from `df-waiver findings`)")
    dw_sign.add_argument("--expires", required=True,
                         help="ISO-8601 UTC expiry, e.g. 2026-09-01T00:00:00Z (waiver is void "
                              "at/after this instant; re-checked at every verify)")
    dw_sign.add_argument("--reason", required=True, help="human-readable acceptance rationale")
    dw_sign.add_argument("--key-file", required=True,
                         help="path to the signer's private key (raw-32-byte hex)")
    dw_attach = dw_sub.add_parser(
        "attach", help="PHASE 2: verify collected waiver signatures against the SEALED policy and, "
                       "if satisfied, write waiver_attestation.json + anchor it")
    dw_attach.add_argument("control_root")
    dw_attach.add_argument("--run-dir", required=True)
    dw_verify = dw_sub.add_parser(
        "verify", help="re-evaluate a failed run's waiver qualification NOW (expiry re-checked "
                       "against a live clock): WAIVED_QUALIFIED / WAIVER_EXPIRED / WAIVER_INVALID")
    dw_verify.add_argument("control_root")
    dw_verify.add_argument("--run-dir", required=True)

    # `df-override` — the M36b (Part A) signed resume-override operator CLI,
    # structurally a mirror of df-waiver but for RAISING a BUDGET-PAUSE'd run's
    # budget ceiling at resume. keygen -> sign -> (collect for K>1) -> the file
    # is passed to `resume --override`. See references/budget.md.
    p_do = sub.add_parser("df-override",
                          help="signed resume budget-ceiling overrides (keygen / sign)")
    do_sub = p_do.add_subparsers(dest="override_cmd", required=True)
    do_keygen = do_sub.add_parser("keygen",
                                  help="generate a fresh override-approver ed25519 keypair")
    do_keygen.add_argument("--out-prefix", default=None,
                           help="if given, write <prefix>.key (private) + <prefix>.pub (public); "
                                "otherwise print both to stdout")
    do_sign = do_sub.add_parser(
        "sign", help="build + sign a resume-override claim for a paused run; prints a ready "
                     "{claim, signatures:[{approver,sig}]} file (merge signatures for K>1)")
    do_sign.add_argument("--run-dir", required=True,
                         help="the PAUSED run's run_dir; run_id is recomputed from its basename")
    do_sign.add_argument("--type", default="budget_ceiling", dest="override_type",
                         choices=list(df_override.OVERRIDE_TYPES),
                         help="override type (M36b: budget_ceiling only)")
    do_sign.add_argument("--new-usd-ceiling", type=float, default=None,
                         help="budget_ceiling: the new max_usd ceiling to authorize (> 0)")
    do_sign.add_argument("--expires", required=True,
                         help="ISO-8601 UTC expiry, e.g. 2026-09-01T00:00:00Z (override is void "
                              "at/after this instant; re-checked at resume against a live clock)")
    do_sign.add_argument("--key-file", required=True,
                         help="path to the approver's private key (raw-32-byte hex)")
    do_sign.add_argument("--claim", default=None, dest="claim_file",
                         help="for K>1: sign an EXISTING claim (a prior sign's output or a bare "
                              "claim) instead of minting a new one, so every approver signs the "
                              "identical nonce/bytes; merge the resulting signatures lists")

    # `ship` — M41: run/resume the governed ship phase against a QUALIFIED run.
    p_ship = sub.add_parser(
        "ship",
        help="run/resume the governed ship phase (operator ship actions) against a "
             "qualified run; irreversible actions require a signed df-release approval")
    p_ship.add_argument("control_root")
    p_ship.add_argument("--run-dir", required=True,
                        help="the qualified run_dir to ship (under <control_root>/runs)")
    p_ship.add_argument("--decision",
                        choices=["continue", "reconcile", "abort", "repair-evidence"],
                        default="continue",
                        help="continue (default) · reconcile (accept a possible duplicate after "
                             "SHIP_UNKNOWN_OUTCOME) · abort (seal SHIP_FAILED at an unresolved "
                             "action) · repair-evidence (after SHIP_EVIDENCE_PENDING: consent to "
                             "re-sign a completed action's evidence from its signed intent facts "
                             "— verify the action's real-world state first)")

    # `df-release` — M41: the signed release-approval operator CLI (mirror of
    # df-custody/df-waiver), gating IRREVERSIBLE ship actions. keygen -> sign
    # -> (collect for K>1 into <control_root>/release-approval.json) -> attach.
    p_dr = sub.add_parser("df-release",
                          help="signed K-of-N release approvals for irreversible ship actions "
                               "(keygen / sign / attach)")
    dr_sub = p_dr.add_subparsers(dest="release_cmd", required=True)
    dr_keygen = dr_sub.add_parser("keygen", help="generate a fresh release-approver ed25519 keypair")
    dr_keygen.add_argument("--out-prefix", default=None,
                           help="if given, write <prefix>.key (private) + <prefix>.pub (public); "
                                "otherwise print both to stdout")
    dr_sign = dr_sub.add_parser(
        "sign", help="build + sign a release-approval claim bound to a run's SEALED "
                     "run_id+artifact; prints a {claim, signatures:[{approver,sig}]} file")
    dr_sign.add_argument("--manifest", required=True, help="path to the run's manifest.json")
    dr_sign.add_argument("--actions", default=None,
                         help="comma-separated ship action NAMES this approval covers")
    dr_sign.add_argument("--all", action="store_true", dest="all_actions",
                         help="cover EVERY ship action (wildcard scope) instead of --actions")
    dr_sign.add_argument("--expires", required=True,
                         help="ISO-8601 UTC expiry, e.g. 2026-09-01T00:00:00Z (approval is void "
                              "at/after this instant; re-checked at every ship attempt)")
    dr_sign.add_argument("--key-file", required=True,
                         help="path to the approver's private key (raw-32-byte hex)")
    dr_sign.add_argument("--claim", default=None, dest="claim_file",
                         help="for K>1: sign an EXISTING claim (a prior sign's output) so every "
                              "approver signs the identical nonce/bytes; merge the signatures lists")
    dr_attach = dr_sub.add_parser(
        "attach", help="verify the collected release-approval.json against the sealed run + "
                       "sealed ship.approval policy and, if satisfied, write release_attestation.json")
    dr_attach.add_argument("control_root")
    dr_attach.add_argument("--run-dir", required=True)

    args = ap.parse_args()
    if args.cmd == "init":
        sys.exit(init_cmd(args.control_root, args.answers, force=args.force,
                          force_keep=args.force_keep))
    elif args.cmd == "author-scenarios":
        sys.exit(author_scenarios_cmd(args.control_root, attempts=args.attempts,
                                      review=args.review))
    elif args.cmd == "run":
        sys.exit(run(args.control_root, args.project_src, allow_downgrade=args.allow_downgrade))
    elif args.cmd == "verify-manifest":
        vkey = None
        if args.key_path:
            try:
                vkey = df_audit.load_key(args.key_path)
            except df_audit.AuditKeyError as e:
                sys.stderr.write(f"dark-factory: audit key error: {e}\n")
                sys.exit(2)
        status = _verify_manifest_status(args.run_dir, key=vkey, object_store=args.object_store)
        # DF-01/M28a Task 3: distinct exit codes so a caller can tell "byte
        # integrity failed" (4, unchanged from pre-M28a) apart from "the
        # bound artifact object failed identity re-verification" (5) apart
        # from "this manifest never bound an object at all" (6) -- an
        # UNBOUND (pre-M28a) manifest is a DISTINCT non-success, never
        # conflated with either a clean pass or a MISMATCH/UNAVAILABLE drift.
        exit_codes = {
            "OK": 0,
            "TAMPERED": 4,
            "UNVERIFIED": 4,
            _ARTIFACT_MISMATCH: 5,
            _ARTIFACT_UNAVAILABLE: 5,
            _ARTIFACT_UNBOUND: 6,
        }
        sys.exit(exit_codes.get(status, 4))
    elif args.cmd == "verify-chain":
        vkey = None
        if args.key_path:
            try:
                vkey = df_audit.load_key(args.key_path)
            except df_audit.AuditKeyError as e:
                sys.stderr.write(f"dark-factory: audit key error: {e}\n")
                sys.exit(2)
        sys.exit(0 if verify_chain_cmd(args.control_root, key=vkey) else 1)
    elif args.cmd == "evidence-bundle":
        ekey = None
        if args.key_path:
            try:
                ekey = df_audit.load_key(args.key_path)
            except df_audit.AuditKeyError as e:
                sys.stderr.write(f"dark-factory: audit key error: {e}\n")
                sys.exit(2)
        bundle, err = df_evidence_bundle.assemble(
            args.control_root, args.run_dir, key=ekey,
            require_production=args.require_production, profile=args.profile)
        if err is not None:
            sys.stderr.write(f"dark-factory: {err}\n")
            sys.exit(2)
        text = json.dumps(bundle, indent=2, sort_keys=True)
        if args.out:
            atomic_write(args.out, text + "\n")
            print(f"dark-factory: evidence bundle written to {args.out}")
        else:
            print(text)
        # DF-R6-07: in production mode, a bundle with any unmet requirement exits
        # nonzero so automation cannot read a partial exercise as production-GO.
        if args.require_production and not bundle.get("production_ready"):
            # DF-R12-02: distinguish "mechanism sound, live remote/WORM sink not proven"
            # from a genuinely broken run, so a same-host/mock exercise is reported
            # honestly rather than as either a pass or an opaque failure.
            if bundle.get("mechanism_ready"):
                sys.stderr.write(
                    "dark-factory: MECHANISM-READY but NOT production-validated — the run "
                    "meets every production requirement except machine-verifiable remote/WORM "
                    f"sink provenance: {bundle.get('production_unmet')}\n")
            else:
                sys.stderr.write(
                    "dark-factory: production evidence INCOMPLETE — "
                    f"{bundle.get('production_unmet')}\n")
            sys.exit(3)
        sys.exit(0)
    elif args.cmd == "resume":
        sys.exit(resume(args.control_root, args.decision, allow_downgrade=args.allow_downgrade,
                        override_file=args.override_file))
    elif args.cmd == "df-fork":
        sys.exit(fork_cmd(args.control_root, args.parent_run,
                          allow_downgrade=args.allow_downgrade))
    elif args.cmd == "df-migrate-config":
        sys.exit(migrate_config_cmd(args.control_root))
    elif args.cmd == "verify-custody":
        # exit 0 = QUALIFIED, 1 = PENDING/INVALID (mirrors verify-chain).
        sys.exit(0 if verify_custody_cmd(args.control_root, args.run_dir) else 1)
    elif args.cmd == "df-custody":
        sys.exit(_df_custody_cli(args))
    elif args.cmd == "df-waiver":
        sys.exit(_df_waiver_cli(args))
    elif args.cmd == "df-override":
        sys.exit(_df_override_cli(args))
    elif args.cmd == "ship":
        sys.exit(ship_cmd(args.control_root, args.run_dir, decision=args.decision))
    elif args.cmd == "df-release":
        sys.exit(_df_release_cli(args))


def _df_override_cli(args) -> int:
    """Dispatch for the `df-override` operator CLI (keygen / sign). keygen
    delegates to df_custody (an approver key IS an ed25519 keypair). sign
    recomputes run_id FROM the paused run's run_dir basename (never a
    user-supplied run_id) and either mints a fresh claim (with a random nonce)
    or signs an EXISTING claim (--claim, for K>1 so every approver signs the
    identical nonce/bytes)."""
    if args.override_cmd == "keygen":
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

    if args.override_cmd == "sign":
        run_dir = os.path.abspath(args.run_dir)
        run_id = os.path.basename(run_dir.rstrip(os.sep))
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
            if claim.get("run_id") != run_id:
                sys.stderr.write(
                    f"dark-factory: --claim run_id {claim.get('run_id')!r} does not match this "
                    f"run_dir's run_id {run_id!r}\n")
                return 2
        else:
            # First approver: mint the claim (validate expiry + params here so a
            # dead-on-arrival or malformed override is caught at sign time).
            expires_dt = df_override._parse_ts(args.expires)
            if expires_dt is None:
                sys.stderr.write(
                    f"dark-factory: --expires is not a valid ISO-8601 UTC timestamp: "
                    f"{args.expires!r}\n")
                return 2
            issued_at = _now()
            issued_dt = df_override._parse_ts(issued_at)
            if not (issued_dt < expires_dt):
                sys.stderr.write(
                    f"dark-factory: --expires {args.expires!r} is not after the issue time "
                    f"{issued_at!r}; the override would be dead on arrival.\n")
                return 2
            if args.override_type == "budget_ceiling" and args.new_usd_ceiling is None:
                sys.stderr.write(
                    "dark-factory: budget_ceiling requires --new-usd-ceiling\n")
                return 2
            params = {"new_usd_ceiling": args.new_usd_ceiling}
            try:
                df_override.validate_params(args.override_type, params)
            except df_override.OverrideError as e:
                sys.stderr.write(f"dark-factory: {e}\n")
                return 2
            claim = {
                "override_version": df_override.OVERRIDE_VERSION,
                "run_id": run_id,
                "override_type": args.override_type,
                "params": params,
                "issued_at": issued_at,
                "expires_at": args.expires,
                "nonce": uuid.uuid4().hex,
            }

        try:
            signed = df_override.override_signing_bytes(claim)
            sig = df_custody.sign_manifest(private_hex, signed)
            approver = df_custody.public_from_private(private_hex)
        except (df_custody.CustodyError, df_override.OverrideError) as e:
            sys.stderr.write(f"dark-factory: {e}\n")
            return 2
        # Print a ready-to-use single-signer override file. For K>1, each
        # approver runs `sign --claim <this>` and the operator merges the
        # `signatures` lists (the claim is byte-identical across them).
        print(json.dumps({"claim": claim, "signatures": [{"approver": approver, "sig": sig}]},
                         indent=2, sort_keys=True))
        return 0

    return 2


def _df_waiver_cli(args) -> int:
    """Dispatch for the `df-waiver` operator CLI (keygen/findings/sign/attach/
    verify). keygen delegates to df_custody (a waiver-signer key IS an ed25519
    keypair); findings/sign recompute every binding digest FROM the sealed
    manifest so an operator can never sign against operator-supplied copies of
    run_id/artifact/policy/report."""
    if args.waiver_cmd == "keygen":
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

    if args.waiver_cmd == "attach":
        return attach_waiver(args.control_root, args.run_dir)
    if args.waiver_cmd == "verify":
        return verify_waiver_cmd(args.control_root, args.run_dir)

    # findings / sign both read + bind FROM the sealed manifest.
    if args.waiver_cmd in ("findings", "sign"):
        if not os.path.exists(args.manifest):
            sys.stderr.write(f"dark-factory: manifest not found: {args.manifest}\n")
            return 2
        try:
            with open(args.manifest, "rb") as f:
                manifest_obj = json.loads(f.read())
        except (OSError, json.JSONDecodeError) as e:
            sys.stderr.write(f"dark-factory: cannot read manifest: {e}\n")
            return 2
        binding, berr = _waiver_binding_from_manifest(manifest_obj)
        if binding is None:
            sys.stderr.write(f"dark-factory: {berr}\n")
            return 2

        if args.waiver_cmd == "findings":
            security = binding["security"]
            waivable, unwaivable = df_waiver.required_fingerprints(
                security.get("failed", []), security.get("gates", {}))
            # Re-attach each fingerprint to its gate+finding so the operator
            # can SEE what they'd be signing (never just an opaque hash).
            detail = []
            gates = security.get("gates", {})
            for name in security.get("failed", []):
                gate = gates.get(name) if isinstance(gates, dict) else None
                findings = gate.get("findings") if isinstance(gate, dict) else None
                if not isinstance(findings, list):
                    continue
                for finding in findings:
                    detail.append({
                        "gate": name,
                        "fingerprint": df_waiver.finding_fingerprint(name, finding),
                        "finding": finding,
                    })
            out = {
                "run_id": binding["run_id"],
                "artifact_object_id": binding["artifact_object_id"],
                "gate_policy_digest": binding["policy_digest"],
                "gate_report_digest": binding["report_digest"],
                "waivable_fingerprints": waivable,
                "findings": detail,
                "unwaivable_gates": unwaivable,
                "waiver_policy": {"signers": binding["signers"], "threshold": binding["threshold"]},
            }
            print(json.dumps(out, indent=2, sort_keys=True))
            return 0

        # sign: build + sign ONE scoped, expiring claim.
        expires_dt = df_waiver._parse_ts(args.expires)
        if expires_dt is None:
            sys.stderr.write(
                f"dark-factory: --expires is not a valid ISO-8601 UTC timestamp: {args.expires!r}\n")
            return 2
        issued_at = _now()
        issued_dt = df_waiver._parse_ts(issued_at)
        if not (issued_dt < expires_dt):
            sys.stderr.write(
                f"dark-factory: --expires {args.expires!r} is not after the issue time "
                f"{issued_at!r}; the waiver would be dead on arrival.\n")
            return 2
        try:
            with open(args.key_file, encoding="utf-8") as f:
                private_hex = f.read().strip()
        except OSError as e:
            sys.stderr.write(f"dark-factory: cannot read key file: {e}\n")
            return 2
        claim = {
            "waiver_version": df_waiver.WAIVER_VERSION,
            "run_id": binding["run_id"],
            "artifact_object_id": binding["artifact_object_id"],
            "gate_policy_digest": binding["policy_digest"],
            "gate_report_digest": binding["report_digest"],
            "finding_fingerprint": args.fingerprint,
            "reason": args.reason,
            "issued_at": issued_at,
            "expires_at": args.expires,
        }
        try:
            signed = df_waiver.waiver_signing_bytes(claim)
            sig = df_custody.sign_manifest(private_hex, signed)
            signer = df_custody.public_from_private(private_hex)
        except (df_custody.CustodyError, df_waiver.WaiverError) as e:
            sys.stderr.write(f"dark-factory: {e}\n")
            return 2
        print(json.dumps({"claim": claim, "signer": signer, "sig": sig}))
        return 0

    return 2


def _df_custody_cli(args) -> int:
    """Dispatch for the `df-custody` operator CLI (keygen/sign/attach)."""
    if args.custody_cmd == "keygen":
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

    if args.custody_cmd == "sign":
        if not os.path.exists(args.manifest):
            sys.stderr.write(f"dark-factory: manifest not found: {args.manifest}\n")
            return 2
        with open(args.manifest, "rb") as f:
            manifest_bytes = f.read()
        try:
            with open(args.key_file, encoding="utf-8") as f:
                private_hex = f.read().strip()
        except OSError as e:
            sys.stderr.write(f"dark-factory: cannot read key file: {e}\n")
            return 2
        try:
            sig = df_custody.sign_manifest(private_hex, manifest_bytes)
            approver = df_custody.public_from_private(private_hex)
        except df_custody.CustodyError as e:
            sys.stderr.write(f"dark-factory: {e}\n")
            return 2
        # Self-describing entry ready to drop into custody-signatures.json.
        print(json.dumps({"approver": approver, "sig": sig}))
        return 0

    if args.custody_cmd == "attach":
        return attach_custody(args.control_root, args.run_dir)
    return 2


if __name__ == "__main__":
    main()
