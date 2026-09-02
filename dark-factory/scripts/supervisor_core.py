"""Shared supervisor primitives: constants, the hash-chained FSM checkpoint, run lock, Journal, resumable state, checkpoint reports, manifest sub-fields, the artifact object store, manifest verification.

Extracted verbatim from supervisor.py (see supervisor.py for the CLI entry point and
the run/resume core). Every top-level name here is re-exported by supervisor.py, so
`supervisor.<name>` keeps working for tests and df_evidence_bundle.
"""
import datetime
import json
import os
import shutil
import sys

import df_audit
import df_audit_chain
import df_confine
import df_container
import df_creds
import df_gates
import df_kb
import df_notify
import df_qualify
import df_seal
from df_common import atomic_write, canonical_json, sha256_file, sha256_str
from df_config import (
    MANDATORY_TIERS,
)

# The names the test-suite monkeypatches ON the `supervisor` module. Code that lives
# in a supervisor_* module must call these THROUGH `_sup()` so a patch installed on
# `supervisor` still takes effect; tests/test_supervisor_seams.py enforces both halves
# (every patched name is either defined in supervisor.py or listed here, and no
# supervisor_* module calls a listed name directly).
SUPERVISOR_SEAMS = frozenset({
    "invoke_adapter", "_source_identity_field", "resolve_isolation", "run_all",
    "_verify_chain_untruncated", "_anchor_ship_local", "load_config",
    "_seal_ship_result", "_run_security_gates", "_now_utc", "_checkpoint_chain_to_sink",
})


def _sup():
    """The `supervisor` module namespace, resolved at CALL time (see SUPERVISOR_SEAMS).

    supervisor.py registers itself under the name `supervisor` even when run as
    `__main__`, so this is always the one live module object."""
    import supervisor
    return supervisor

# M17 Task 3: the hostname the enterprise builder container uses to reach the
# host-side credential proxy. "host.docker.internal" is a Docker Desktop
# convenience (macOS/Windows) that routes to services bound on the HOST,
# including 127.0.0.1-bound listeners like df_proxy.serve() -- documented
# Docker-Desktop assumption (see references/enterprise.md); a native-Linux
# Docker Engine deployment would need `--add-host=host.docker.internal:
# host-gateway` wired in here too (a named, deliberate deferral -- M16
# already established Docker Desktop's Linux VM as this project's live-test
# target).
_ENTERPRISE_PROXY_HOST = "host.docker.internal"

# Tiers whose manifests read "qualified" (probe-proven isolation) — every
# tier at or above "standard". Enterprise is a superset of hardened's
# guarantees, so it belongs here too; kept as one tuple so the three call
# sites that used to hardcode ("standard", "hardened") can't drift apart.
_QUALIFYING_TIERS = ("standard", "hardened", "enterprise")
# Tiers whose builder runs inside a Docker container (so `container` is
# non-None on the manifest, and the builder-isolation branch below builds a
# docker argv instead of using the OS-sandbox exec_prefix).
_CONTAINER_TIERS = ("hardened", "enterprise")


def _finalize_container_manifest(cfg, eff_tier):
    """Build the manifest `container` field (None outside a container tier),
    enriched with the M51/DF-R3-08 reproducibility ADVISORY fields:

      - `image_pinned` (bool): does the effective image carry an `@sha256:`
        content digest (reproducible) vs. a mutable tag? Recorded honestly.
      - `resolved_image_digest` (str|None): the digest Docker ACTUALLY used,
        resolved ONCE here (the container probe in resolve_isolation has already
        passed, so docker is up) — best-effort, None on any error. So even a
        tag-based run's manifest says which image bytes ran.

    When the image is an unpinned tag at hardened/enterprise, emits a ONE-LINE
    stderr WARNING recommending a digest pin. This is FAIL-OPEN: a tag is
    legitimate in dev, so it is an advisory, NOT a ConfigError — the run
    continues either way (contrast the fail-CLOSED isolation probes). Called at
    both the fresh-run and resume manifest-seal sites so they can't drift."""
    if eff_tier not in _CONTAINER_TIERS:
        return None
    c = dict(cfg["_container"])
    # Internal, run-time cache keys (DF-R4-10) never belong on the manifest.
    c.pop("_effective_image", None)
    c.pop("_resolved_image_digest", None)
    image = c["image"]
    # A digest pin is an `@sha256:` reference; anything else is a mutable tag
    # whose bytes can change under you as upstream republishes it.
    pinned = "@sha256:" in image
    c["image_pinned"] = pinned
    if not pinned:
        sys.stderr.write(
            f"dark-factory: WARNING container image {image!r} is an unpinned tag; "
            "pin a digest (hardened.image: ...@sha256:...) for a reproducible "
            "build environment (advisory only — the run continues, and the "
            "manifest records the resolved digest either way).\n"
        )
    # DF-R4-10: report the SAME digest EVERY dispatch/probe in this run used. If a
    # dispatch already resolved it (cached by _effective_image on first use), reuse
    # that EXACT value so the manifest cannot disagree with what actually ran; on a
    # no-dispatch path (e.g. this called before any container op) resolve once here.
    # Best-effort, fail-open: resolve_image_digest returns None on any error and
    # never raises, so a missing digest / unreachable docker cannot block a run.
    cc = cfg["_container"]
    if "_resolved_image_digest" in cc:
        c["resolved_image_digest"] = cc["_resolved_image_digest"]
    else:
        c["resolved_image_digest"] = df_container.resolve_image_digest(image)
    return c


def _effective_image(cfg):
    """DF-R4-10: the SINGLE, digest-pinned image reference used for EVERY container
    dispatch + probe in a run — resolved ONCE and cached on cfg["_container"].

    A mutable tag can move between digest-inspection and dispatch (or between the
    probe and the real builder run, or between iterations). Resolving the digest
    once here and threading THIS reference to build_argv/build_enterprise_argv and
    every probe guarantees the manifest's recorded digest == the bytes that ran.

      - config already pinned (`@sha256:` present) -> dispatched verbatim;
      - otherwise resolve the digest once: a RepoDigest ('repo@sha256:...') or a
        local image id ('sha256:...') is dispatched as the pinned reference and
        recorded on the manifest;
      - unresolvable (offline / never-pulled) -> fall back to the mutable tag
        (fail-OPEN, back-compat) and the manifest stays honest (resolved digest
        null); WHEN a digest is available, though, ALL dispatches use it.

    resolve_image_digest is fail-open (returns None, never raises) so this cannot
    block a run even with docker down."""
    c = cfg["_container"]
    if "_effective_image" in c:
        return c["_effective_image"]
    image = c["image"]
    # Resolve once (verbatim-pinned config still records its digest for the
    # manifest). None on any failure -> keep the operator's reference as-is.
    digest = df_container.resolve_image_digest(image)
    if "@sha256:" in image:
        c["_effective_image"] = image
    else:
        c["_effective_image"] = digest if digest else image
    c["_resolved_image_digest"] = digest
    return c["_effective_image"]


def _image_resolved_from_journal(run_dir):
    """DF-R5-09: the FIRST journaled IMAGE_RESOLVED event of this run, or None.
    Scans forward and returns the first (the pin), mirroring
    _snapshot_sha256_from_journal's tolerance model: the journal is this run's
    append-only record; a torn/absent file just means no pin yet."""
    path = os.path.join(run_dir, "journal.jsonl")
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as f:
        for line in f:
            try:
                e = json.loads(line)
            except ValueError:
                continue
            if e.get("state") == "IMAGE_RESOLVED":
                return e.get("data", {})
    return None


def _pin_effective_image(cfg, run_dir, journal):
    """DF-R5-09: ONE logical run = ONE container image identity, across process
    resume. `_effective_image` caches the resolved digest only on the in-memory
    cfg, so a pause/crash/restart reloaded config.json and re-resolved a mutable
    tag — earlier iterations could build under digest A, the resume under digest
    B, and the manifest sealed only B. Called at `_run_loop` entry (fresh run
    AND every resume enter there):

      - a prior IMAGE_RESOLVED journal event -> pre-seed the in-memory cache
        from it VERBATIM (no re-resolution; every dispatch/probe this segment
        uses the run's original pinned reference);
      - no prior event (fresh run, or a pre-M58 paused run) -> resolve once via
        _effective_image and journal IMAGE_RESOLVED so every LATER segment
        reuses it.

    No-op for tiers without a container. Same-user tampering of the journal is
    detection-grade like the rest of the run evidence (see references/audit.md)."""
    cc = cfg.get("_container")
    if not cc:
        return
    prior = _image_resolved_from_journal(run_dir)
    if prior and prior.get("effective_image"):
        # The pin WINS over a config.json image edited across a pause — one
        # logical run, one image (an operator who wants different bytes starts
        # a new run) — but the override is journaled, never silent.
        if prior.get("config_image") is not None and cc["image"] != prior["config_image"]:
            journal.write("IMAGE_PIN_KEPT", pinned=prior["effective_image"],
                          original_config_image=prior["config_image"],
                          edited_config_image=cc["image"])
        cc["_effective_image"] = prior["effective_image"]
        cc["_resolved_image_digest"] = prior.get("resolved_image_digest")
        return
    eff = _effective_image(cfg)
    journal.write("IMAGE_RESOLVED", effective_image=eff, config_image=cc["image"],
                  resolved_image_digest=cc.get("_resolved_image_digest"))


BUILDER_RULES = """## Builder rules
- You are the BUILDER in a dark-factory run. Implement the specification below
  in the current working directory.
- Work ONLY inside this directory.
- Hidden acceptance scenarios exist; they are NOT visible to you. Do not try to
  find or read them. Verification feedback arrives only as behavior IDs plus a
  coarse failure taxonomy.
"""


class LockError(RuntimeError):
    pass


PAUSED = 10
# DF-08/M35: a prior process crashed mid-dispatch — after a DISPATCH_INTENT
# was journaled (and its reserved spend committed to state.json) but before
# the matching DISPATCH_RESULT resolved. Distinct from PAUSED: the run is
# NOT simply waiting on a human checkpoint/budget decision, it needs
# reconciliation (`resume --decision reconcile` or `--decision abort`)
# because the outcome of an already-sent builder call is unknown. Fail-closed
# default: plain `resume --decision continue` refuses to re-enter the loop
# while this is set, so a crash never causes a silent duplicate dispatch.
UNKNOWN_OUTCOME = 11

# M49 DF-R3-02: the ship actions ran (SHIPPED) but a REQUIRED off-box audit sink
# push FAILED — the mandated off-box evidence is missing, so the run sealed the
# DISTINCT outcome SHIPPED_AUDIT_PENDING (never SHIPPED). A distinct nonzero exit
# so automation does NOT read this as a clean exit-0 ship; an idempotent
# audit-only retry (`ship` re-entry) re-anchors off-box and flips it to 0.
SHIP_AUDIT_PENDING = 12

# R5 DF-R5-02: a ship action's per-action evidence could not be signed (a
# transient audit-key/signer failure) — either its completion token after the
# real-world action RAN (that action is DONE and is NEVER re-run), or its intent
# token BEFORE the spawn (nothing ran; the retry re-runs it). The run sealed the
# DISTINCT, RECOVERABLE outcome SHIP_EVIDENCE_PENDING (never SHIPPED, never an
# unbacked journal `ok`). A distinct nonzero exit; `ship` re-entry runs the
# AUTHENTICATED evidence-only repair (re-sign from intent-token-bound facts) and
# then continues the remaining actions normally. Same code as SHIP_AUDIT_PENDING
# family: 13.
SHIP_EVIDENCE_PENDING_EXIT = 13

# DF-R7-04: the run-state anchor for the source identity computed at the first
# dispatch — the resume drift-check compares a fresh computation against this.
SOURCE_IDENTITY_FILE = "source_identity.json"

# M49 DF-R3-03: on re-entry a prior ship_result.json (or the ship journal that
# feeds `already_done`) could not be AUTHENTICATED against the signed audit chain
# (missing/mismatched/tampered) while audit.signing is on — a same-user
# control-root writer may have planted a terminal SHIPPED or edited the journal.
# Fail-closed refusal (exit 2), NEVER trusting the unauthenticated local state.
SHIP_STATE_UNAUTHENTICATED = 2

# M36a Task 3: the versioned, phase-aware, hash-chained FSM checkpoint. A 0.2
# state records `phase` + the head of a per-run transition chain
# (fsm_chain.jsonl). Pre-M36a states are 0.1 (no phase, no chain) and resume
# through a back-compat path. This chain is CORRUPTION-DETECTION (an in-model
# integrity check that catches an accidental truncation/edit of the transition
# log across a pause/resume); it is explicitly NOT forgery-resistance against a
# same-user process that can rewrite both the chain and the recorded head
# together -- that is the same detection-grade scope as finalize_manifest's
# sha256 sidecar (a signed/off-box anchor is the hardened+ story). Documented
# in references/audit.md.
STATE_VERSION = "0.2"
FSM_CHAIN_FILE = "fsm_chain.jsonl"


def _fsm_chain_lines(run_dir):
    path = os.path.join(run_dir, FSM_CHAIN_FILE)
    if not os.path.exists(path):
        return []
    out = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def _fsm_entry_hash(seq, phase, ts, prev_chain, bound_ids):
    # The hash binds the transition's ordinal, its phase, its timestamp, its
    # predecessor's hash (the chain linkage), AND the run-identifying bound_ids
    # (artifact object_id once sealed + the scenario-set hash) so a chain
    # can't be spliced from a different run's transitions without detection.
    return sha256_str(canonical_json({
        "seq": seq, "phase": phase, "ts": ts,
        "prev_chain": prev_chain, "bound_ids": bound_ids,
    }))


def _fsm_chain_head(run_dir):
    lines = _fsm_chain_lines(run_dir)
    return lines[-1]["entry_hash"] if lines else None


def _fsm_chain_append(run_dir, phase, scenario_set_sha256, artifact_object_id, redactor=None):
    """Append one transition to fsm_chain.jsonl (atomic whole-file rewrite via
    the same redaction choke point as every other artifact) and return the new
    head entry_hash. bound_ids are value-free control-plane identifiers."""
    lines = _fsm_chain_lines(run_dir)
    seq = len(lines)
    prev_chain = lines[-1]["entry_hash"] if lines else None
    ts = _now()
    bound_ids = {"artifact_object_id": artifact_object_id,
                 "scenario_set_sha256": scenario_set_sha256}
    entry_hash = _fsm_entry_hash(seq, phase, ts, prev_chain, bound_ids)
    entry = {"seq": seq, "phase": phase, "ts": ts, "prev_chain": prev_chain,
             "bound_ids": bound_ids, "entry_hash": entry_hash}
    text = "".join(canonical_json(e) + "\n" for e in (lines + [entry]))
    _redacted_write(os.path.join(run_dir, FSM_CHAIN_FILE), text, redactor)
    return entry_hash


def _validate_fsm_chain(run_dir, expected_head):
    """Recompute + verify the whole FSM chain and that its head matches the
    resumed state's recorded head. Returns (ok, detail). ANY mismatch -> not ok
    (the caller refuses, fail-closed). An EMPTY/absent chain with a None
    expected_head is a legacy (0.1) resume, handled by the caller BEFORE this
    is even reached -- here an absent chain with a non-None expected_head is
    corruption (the recorded head claims a chain that is gone)."""
    try:
        # A truncated/malformed line (the most likely accidental corruption --
        # a crash or disk-full mid-append) must route to FSM_CHAIN_CORRUPT/
        # exit 2 like any other integrity failure, NOT escape as an uncaught
        # JSONDecodeError (the resume try only catches SandboxError, so it
        # would otherwise traceback + exit 1, violating the fail-closed
        # contract).
        lines = _fsm_chain_lines(run_dir)
    except json.JSONDecodeError:
        return False, "unparseable chain line (truncated/corrupt JSON)"
    if not lines:
        if expected_head is None:
            return True, "empty"
        return False, "recorded FSM head references a chain that is absent/empty"
    prev = None
    for idx, e in enumerate(lines):
        if e.get("seq") != idx:
            return False, f"seq out of order at line {idx} (got {e.get('seq')})"
        if e.get("prev_chain") != prev:
            return False, f"broken prev_chain linkage at seq {idx}"
        recomputed = _fsm_entry_hash(e.get("seq"), e.get("phase"), e.get("ts"),
                                     e.get("prev_chain"), e.get("bound_ids"))
        if recomputed != e.get("entry_hash"):
            return False, f"entry_hash mismatch at seq {idx} (tampered/corrupt)"
        prev = e["entry_hash"]
    if prev != expected_head:
        return False, "chain head does not match the recorded state head"
    return True, "ok"


def _chain_scenario_set_sha256(run_dir):
    """RA-05: return the run-start scenario-set hash SEALED into the FSM chain's
    genesis (seq 0) entry, or None if the chain is empty/absent (a legacy 0.1
    run). Every chain entry binds `bound_ids.scenario_set_sha256` (M36a), and
    the first entry is written at run start from `_scenario_set_hash(scenarios_dir)`
    — so the genesis value IS the run-start bundle. This is only trusted AFTER
    `_validate_fsm_chain` has passed (the chain's integrity is proven, so the
    bound hash is tamper-evident), which is why resume calls it exactly there."""
    try:
        lines = _fsm_chain_lines(run_dir)
    except json.JSONDecodeError:
        return None
    if not lines:
        return None
    return lines[0].get("bound_ids", {}).get("scenario_set_sha256")


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def acquire_lock(control_root: str) -> str:
    path = os.path.join(control_root, ".lock")
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError:
        try:
            pid = int(open(path, encoding="utf-8").read().strip())
            os.kill(pid, 0)  # raises if dead
        except (ValueError, ProcessLookupError):
            sys.stderr.write(f"dark-factory: removing stale lock {path}\n")
            os.unlink(path)
            return acquire_lock(control_root)
        except PermissionError:
            raise LockError(f"another invocation holds {path} (pid {pid}, live)")
        raise LockError(f"another invocation holds {path} (pid {pid})")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(str(os.getpid()))
    return path


def release_lock(lock_path: str) -> None:
    if os.path.exists(lock_path):
        os.unlink(lock_path)


class Journal:
    def __init__(self, path: str, redactor=None):
        self.path = path
        self.redactor = redactor
        os.makedirs(os.path.dirname(path), exist_ok=True)

    def write(self, state: str, **data) -> None:
        if self.redactor is not None:
            data = self.redactor.redact_obj(data)
        line = canonical_json({"ts": _now(), "state": state, "data": data})
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
            f.flush()
            os.fsync(f.fileno())


def _redacted_write(path: str, payload, redactor) -> str:
    """The single choke point every persisted run artifact goes through.

    `payload` is either a str (already-serialized text, e.g. the checkpoint
    markdown) or a JSON-able dict/list (canonical_json'd here). `redactor`'s
    redact/redact_obj runs immediately before the bytes hit disk via
    atomic_write. redactor=None (no credentials configured) is a strict
    no-op: the exact bytes that would have been written pre-M11. Returns the
    text actually written (callers that need to hash/sign it use this, never
    a pre-redaction copy).
    """
    if isinstance(payload, str):
        text = redactor.redact(payload) if redactor is not None else payload
    else:
        obj = redactor.redact_obj(payload) if redactor is not None else payload
        text = canonical_json(obj)
    atomic_write(path, text)
    return text


def _state_integrity_payload(run_id, seq, state_sha256):
    """DF-R9 (M77): the canonical bytes whose sha256 is anchored as a SIGNED
    resumable-state token every time state.json is written. Binds run_id + a
    monotonic seq + the sha256 of the EXACT state.json bytes, so a resume can
    AUTHENTICATE the checkpoint it is about to trust: any same-user edit of
    state.json (a forged build_approved_through, budget counter, FSM head, or phase)
    changes the digest and no longer matches the signed anchor, and an OLDER
    checkpoint cannot be replayed because seq must be the HIGHEST anchored."""
    return canonical_json({"kind": "resumable-state", "run_id": run_id,
                           "seq": seq, "state_sha256": state_sha256})


def _resumable_state_seqs(control_root, run_id):
    """The set of monotonic seqs for which a resumable-state token is anchored for
    `run_id` — parsed from the deterministic chain key `{run_id}.resumable-state.
    {seq:08d}`. Empty on any chain/read error (the caller treats that as none)."""
    seqs = set()
    pre = f"{run_id}.resumable-state."
    try:
        for e in df_audit_chain.read_chain(os.path.join(control_root, "audit-chain.jsonl")):
            inv = str(e.get("invocation", ""))
            if inv.startswith(pre) and inv[len(pre):].isdigit():
                seqs.add(int(inv[len(pre):]))
    except (df_audit_chain.ChainError, OSError):
        pass
    return seqs


def save_state(run_dir, next_iter, feedback, workspace, dev_status=None, regressions=None,
              builder_calls=0, estimated_usd=0.0, budget_alerted=False, reason="checkpoint",
              redactor=None, builder_input_tokens=0, builder_output_tokens=0,
              usage_known=False, phase=None, chain_append=False,
              scenario_set_sha256=None, artifact_object_id=None,
              build_approved_through=0, ship_meta=None, cfg=None,
              generated_set_sha256=None):
    # M36a Task 3: state_version 0.2 additionally records the FSM `phase` and
    # the head of the per-run hash chain. Genuine resumable pause transitions
    # (chain_append=True: the checkpoint / budget / before-build pauses) append
    # a new chain entry; the crash-safe per-dispatch save (chain_append=False)
    # records the CURRENT head without growing the chain, so state.json's
    # recorded head always equals the last fsm_chain.jsonl entry and resume can
    # verify head-of-chain either way. phase defaults to the reason when a
    # caller doesn't pass a richer AWAIT_* label.
    phase = phase or reason
    if chain_append:
        chain_head = _fsm_chain_append(run_dir, phase, scenario_set_sha256,
                                       artifact_object_id, redactor=redactor)
    else:
        chain_head = _fsm_chain_head(run_dir)
    # DF-R9 (M77): on a SIGNED run, every state.json write is bound to the SIGNED
    # audit chain (the FSM chain above is an UNSIGNED sha256 chain a same-user writer
    # can rewrite wholesale, and build_approved_through / budget counters are not
    # bound by it at all). Compute the monotonic seq for THIS write now (highest
    # anchored + 1); it is sealed INTO state.json below, then the written bytes are
    # digested and anchored. Unsigned tiers keep state_seq None and are not anchored.
    _signing = bool((cfg or {}).get("_audit", {}).get("signing"))
    _control_root = (cfg or {}).get("_control_root")
    _run_id = os.path.basename(run_dir.rstrip(os.sep))
    state_seq = None
    if _signing and _control_root:
        _existing = _resumable_state_seqs(_control_root, _run_id)
        state_seq = (max(_existing) + 1) if _existing else 0
    # state.json must NEVER carry a credential value: it holds only control-
    # plane bookkeeping (iteration counters, ID/taxonomy feedback, paths), but
    # it goes through the same redaction choke point as every other artifact
    # for defense in depth (redactor=None is a strict no-op).
    _redacted_write(
        os.path.join(run_dir, "state.json"),
        {
            "state_version": STATE_VERSION,
            # DF-R9 (M77): the monotonic integrity seq sealed into these very bytes;
            # the SIGNED resumable-state anchor below binds sha256(state.json) at this
            # seq. None on unsigned tiers (no detection-grade guarantee to offer).
            "state_seq": state_seq,
            "next_iter": next_iter,
            "feedback": feedback,
            "workspace": workspace,
            "run_dir": run_dir,
            "dev_status": dev_status or {},
            "regressions": sorted(regressions) if regressions else [],
            "builder_calls": builder_calls,
            "estimated_usd": estimated_usd,
            "budget_alerted": budget_alerted,
            "reason": reason,
            # M36a: FSM phase + hash-chain head + the before-build approval
            # cursor (so a directed/H1 resume doesn't re-pause a build it
            # already approved). Additive; a 0.1 state defaults them on load.
            "phase": phase,
            "fsm_chain_head": chain_head,
            # RA-05/M45: seal the run-start scenario-set hash into state.json
            # too (additive). The FSM chain's genesis entry is the AUTHORITATIVE
            # sealed value on a 0.2 resume, but persisting it here is belt-and-
            # suspenders: a run that somehow lacks a chain (or a future no-chain
            # path) still carries the sealed hash so resume can enforce bundle
            # immutability. A pre-M45 0.1 state.json has neither this field nor
            # a chain -> resume journals SCENARIO_BUNDLE_UNSEALED_LEGACY.
            "scenario_set_sha256": scenario_set_sha256,
            # M86 (post-R10 audit): the brownfield-GENERATED regression cohort
            # (run_dir/generated-scenarios/*.json, created after the run-start seal so
            # it is NOT in scenario_set_sha256) is sealed HERE — state.json is
            # M77-anchored into the signed chain, so a same-user edit of a generated
            # BHV-REGRESS scenario across a pause is tamper-evident (RA-05's
            # immutability, extended to the generated guard cohort). None when there
            # is no generated cohort.
            "generated_set_sha256": generated_set_sha256,
            "build_approved_through": build_approved_through,
            # M36b Part C: the post-convergence data an AWAIT_SHIP pause needs to
            # SEAL on resume WITHOUT rebuilding — the frozen artifact object_id +
            # its manifest field, the sealed final-exam result, and the converged
            # iteration. None for every other pause (which resumes by rebuilding).
            "ship_meta": ship_meta,
            # M25 Task 1: authoritative token totals, additive alongside the
            # M8 estimated_usd/builder_calls fields above -- never read by the
            # estimated_usd admission/alert/pause path, only accumulated and
            # carried across a pause/resume like the rest of this state.
            "builder_input_tokens": builder_input_tokens,
            "builder_output_tokens": builder_output_tokens,
            "usage_known": usage_known,
        },
        redactor,
    )
    # DF-R9 (M77): anchor the SIGNED resumable-state token binding the EXACT written
    # bytes at this seq, under the deterministic key `{run_id}.resumable-state.
    # {seq:08d}` so resume can find the highest/matching anchor. Best-effort: a
    # failed anchor leaves state_seq unmatched at resume, which fails closed — the
    # safe outcome for a checkpoint whose integrity could not be committed.
    if _signing and _control_root and state_seq is not None:
        _digest = sha256_file(os.path.join(run_dir, "state.json"))
        _sup()._anchor_ship_local(cfg, _control_root, _run_id,
                           _state_integrity_payload(_run_id, state_seq, _digest),
                           "resumable-state", key_suffix=f"{state_seq:08d}")


def load_state(run_dir):
    with open(os.path.join(run_dir, "state.json"), encoding="utf-8") as f:
        state = json.load(f)
    # Additive fields (M8): default them when absent so a pre-M8 state.json
    # (or an old checkpoint-pause save) resumes cleanly with a fresh budget.
    state.setdefault("builder_calls", 0)
    state.setdefault("estimated_usd", 0.0)
    state.setdefault("budget_alerted", False)
    state.setdefault("reason", "checkpoint")
    # Additive (M25 Task 1): default 0/0/False for a pre-M25 state.json so an
    # old paused run resumes cleanly with a fresh (zeroed) token count --
    # never double-counted, never backfilled from thin air.
    state.setdefault("builder_input_tokens", 0)
    state.setdefault("builder_output_tokens", 0)
    state.setdefault("usage_known", False)
    # M36a Task 3: additive FSM fields. A pre-M36a (0.1) state has none of
    # these -- default them so a legacy paused run resumes cleanly through the
    # no-chain back-compat path (state_version stays "0.1", so resume can tell
    # it apart and journal FSM_CHAIN_ABSENT_LEGACY instead of validating a
    # chain that never existed).
    state.setdefault("state_version", "0.1")
    state.setdefault("phase", None)
    state.setdefault("fsm_chain_head", None)
    # DF-R9 (M77): the SIGNED resumable-state integrity seq. Absent on a pre-M77
    # state.json (→ None); on a signed run that is a fail-closed refusal at resume
    # (an unauthenticatable checkpoint), on an unsigned run it is simply unused.
    state.setdefault("state_seq", None)
    # RA-05/M45: additive. A pre-M45 state.json (0.1 legacy OR a 0.2 state
    # written before this field existed) defaults to None -> the sealed hash
    # comes from the FSM chain genesis when available, else the run is treated
    # as unsealed-legacy (journaled, proceeds) rather than false-refused.
    state.setdefault("scenario_set_sha256", None)
    state.setdefault("generated_set_sha256", None)  # M86: brownfield generated cohort seal
    state.setdefault("build_approved_through", 0)
    # M36b Part C: only an AWAIT_SHIP pause records this; every other state has
    # None (they resume by rebuilding, not sealing).
    state.setdefault("ship_meta", None)
    return state


def _snapshot_sha256_from_journal(run_dir):
    path = os.path.join(run_dir, "journal.jsonl")
    with open(path, encoding="utf-8") as f:
        for line in f:
            e = json.loads(line)
            if e.get("state") == "SNAPSHOT":
                return e.get("data", {}).get("snapshot_sha256")
    return None


def _init_scenario_set_sha256_from_journal(run_dir):
    """RA-05/M45 (R1): the run-start scenario-set hash as recorded in the
    journal's INIT event (supervisor.run writes it at run start). This is a
    THIRD independent run-start record — alongside the FSM chain genesis and
    the state.json field — so the SCENARIO_BUNDLE_UNSEALED_LEGACY (unenforced)
    fallback is only reached when a run-start hash exists in NONE of the three.
    A same-user actor who downgrades state.json to 0.1, deletes fsm_chain.jsonl,
    and strips the state.json field must ALSO strip/rewrite the journal INIT
    record to force the unenforced path. HONEST SCOPE: journal.jsonl is plain,
    UNAUTHENTICATED JSONL (no per-entry hash chain) and resume does not
    integrity-check it — so this third record raises the AVAILABILITY bar for
    legacy compat, not the adversarial bar (a determined same-user actor can
    forge/strip it, the same detection-grade residual the FSM chain already
    carries). It is a defence-in-depth breadcrumb, not a cryptographic anchor.
    A missing/unreadable INIT record -> None ("no fallback available"), never a
    silent pass."""
    path = os.path.join(run_dir, "journal.jsonl")
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                e = json.loads(line)
                if e.get("state") == "INIT":
                    return e.get("data", {}).get("scenario_set_sha256")
    except (OSError, json.JSONDecodeError):
        return None
    return None


def _mode_from_journal(run_dir):
    """Recover the ORIGINAL run's brownfield mode + legacy_ignored flag from
    its journal (M15). Resume must NOT re-run detect_mode (project_src isn't
    even passed to resume(), and re-detecting against a possibly-changed
    source would be exactly the re-observation the sealed cohort must avoid)
    -- the fresh-run path always writes MODE_DETECTED unconditionally, so a
    resumed run's manifest reports the same mode it converged/paused under.
    """
    path = os.path.join(run_dir, "journal.jsonl")
    with open(path, encoding="utf-8") as f:
        for line in f:
            e = json.loads(line)
            if e.get("state") == "MODE_DETECTED":
                data = e.get("data", {})
                return data.get("mode", "greenfield"), bool(data.get("legacy_ignored", False))
    return "greenfield", False


def _dispatch_idempotency_key(invocation: str, iteration: int) -> str:
    """Deterministic per-(run, iteration) key (DF-08/M35). Stable across a
    crash + resume/reconcile: the SAME iteration always derives the SAME
    key, so re-entering iteration i after a crash re-uses it rather than
    minting a new one -- resolution-matching (see
    `_unresolved_dispatch_intent`) works by exact key equality."""
    return sha256_str(f"{invocation}:{iteration}")


def _unresolved_dispatch_intent(run_dir):
    """Scan run_dir/journal.jsonl for the LATEST DISPATCH_INTENT event and
    report whether it has a matching DISPATCH_RESULT (same idempotency_key)
    anywhere later in the journal.

    Returns the intent's data dict (iteration/idempotency_key/reserved_calls/
    reserved_usd) if unresolved -- meaning a prior process crashed after
    committing a builder call's reserved spend but before the call resolved
    -- else None.

    A journal with no DISPATCH_INTENT at all (every pre-M35 run) returns
    None: absence is "no unresolved intent", never a false positive, so an
    old state.json resumes exactly as before this task.
    """
    path = os.path.join(run_dir, "journal.jsonl")
    if not os.path.exists(path):
        return None
    latest_intent = None
    resolved_keys = set()
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            e = json.loads(line)
            data = e.get("data", {})
            state = e.get("state")
            if state == "DISPATCH_INTENT":
                latest_intent = data
            elif state == "DISPATCH_RESULT":
                resolved_keys.add(data.get("idempotency_key"))
    if latest_intent is not None and latest_intent.get("idempotency_key") not in resolved_keys:
        return latest_intent
    return None


def _resolved_dispatch_result(run_dir, invocation, iteration):
    """RA-06/M46: return the recorded DISPATCH_RESULT data dict for iteration
    `iteration`'s dispatch key IFF that dispatch already resolved
    SUCCESSFULLY (status "ok"), else None.

    This is the RESOLVED counterpart to `_unresolved_dispatch_intent`, and the
    two are deliberately disjoint. M35 made the intent->result interval
    crash-safe: an UNRESOLVED intent (crash BETWEEN intent and result) stops
    resume at UNKNOWN_OUTCOME / reconcile. But a crash landing AFTER
    DISPATCH_RESULT ok was journaled (the paid builder call COMPLETED and its
    output was written into the persisted workspace) yet BEFORE the iteration
    finalized and `next_iter` advanced leaves state.json still at this same
    iteration `i`. On `resume --decision continue`, `_unresolved_dispatch_intent`
    returns None (the intent IS resolved), so without this check the loop would
    re-enter iteration `i` and re-dispatch -- a SECOND PAID model request for
    work already done. When this returns non-None the caller SKIPS
    invoke_adapter and instead verifies the already-persisted workspace,
    journaling a value-free DISPATCH_REPLAYED. The reservation was already
    committed to durable state at intent time (M35) and reloaded into
    builder_calls/estimated_usd on resume, so replaying does NOT double-count
    spend -- the caller must NOT re-commit it.

    Only a SUCCESSFUL result triggers the replay: an errored DISPATCH_RESULT
    means the dispatch already terminated the run (ABORTED_BUILD_ERROR /
    CONFINEMENT_REFUSED cleared state.json), so it is never resumed into a
    re-dispatch in the first place. Absence of any matching result returns None,
    leaving the M35 unresolved-intent -> reconcile / UNKNOWN_OUTCOME path (and
    every pre-M35 journal) untouched -- fail-closed by omission.
    """
    path = os.path.join(run_dir, "journal.jsonl")
    if not os.path.exists(path):
        return None
    key = _dispatch_idempotency_key(invocation, iteration)
    resolved = None
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            e = json.loads(line)
            if e.get("state") != "DISPATCH_RESULT":
                continue
            data = e.get("data", {})
            if data.get("idempotency_key") == key and data.get("status") == "ok":
                resolved = data
    return resolved


def latest_paused_run(control_root):
    runs_dir = os.path.join(control_root, "runs")
    if not os.path.isdir(runs_dir):
        return None
    paused = [
        os.path.join(runs_dir, name)
        for name in sorted(os.listdir(runs_dir), reverse=True)
        if os.path.exists(os.path.join(runs_dir, name, "state.json"))
    ]
    return paused[0] if paused else None


def write_checkpoint_report(run_dir, iteration, report, redactor=None):
    passing = sum(1 for r in report["results"] if r["pass"])
    total = len(report["results"])
    lines = [
        f"# Checkpoint — iteration {iteration}",
        "",
        f"Passing: **{passing}/{total}**  (twin-observed, cooperative tier — unqualified)",
        "",
        "| behavior | scenario | pass | taxonomy | exit |",
        "|---|---|:--:|---|--:|",
    ]
    for r in report["results"]:
        mark = "✅" if r["pass"] else "❌"
        tax = r["taxonomy"] or ""
        code = r["observed"].get("exit_code")
        lines.append(f"| {r['behavior_id']} | {r['id']} | {mark} | {tax} | {code} |")
    lines += [
        "",
        "Decide: `resume --decision continue` (build again) · edit `spec.md` then "
        "`resume --decision continue` (adjust) · `resume --decision accept` (stop, "
        "waived/unverified) · `resume --decision abort`.",
        "",
    ]
    path = os.path.join(run_dir, f"checkpoint_iter_{iteration}.md")
    _redacted_write(path, "\n".join(lines), redactor)
    return path


def write_build_checkpoint_report(run_dir, iteration, feedback, redactor=None):
    """M36a: the human-review surface for a DIRECTED (H1) before-build pause.
    At this point iteration `iteration` has NOT been built yet -- the human is
    reviewing the PRIOR iteration's ID/taxonomy feedback (barrier-safe: behavior
    IDs + coarse taxonomy only, never scenario content) before approving the
    next builder call. Distinct filename from the after-verify checkpoint so an
    H1 run's two pauses per cycle don't overwrite each other."""
    failures = (feedback or {}).get("failures", [])
    lines = [
        f"# Before-build checkpoint — iteration {iteration} (directed mode)",
        "",
        f"About to spend another builder call to (re)build iteration {iteration}.",
        f"Still-failing behaviors from the last verify: **{len(failures)}**",
        "",
        "| behavior | taxonomy |",
        "|---|---|",
    ]
    for f in failures:
        tax = ", ".join(f.get("taxonomy", [])) if isinstance(f.get("taxonomy"), list) else ""
        lines.append(f"| {f.get('behavior_id', '')} | {tax} |")
    lines += [
        "",
        "Decide: `resume --decision continue` (approve this build) · edit `spec.md` "
        "then `resume --decision continue` (adjust) · `resume --decision accept` "
        "(stop, waived/unverified) · `resume --decision abort`.",
        "",
    ]
    path = os.path.join(run_dir, f"checkpoint_build_{iteration}.md")
    _redacted_write(path, "\n".join(lines), redactor)
    return path


def write_ship_checkpoint_report(run_dir, iteration, fe, sec_report, object_id, redactor=None):
    """M36b Part C: the human-review surface for a BEFORE-SHIP (H1/H2) pause.

    At this point dev converged, the sealed final exam PASSED, the security
    gates PASSED, and the artifact was frozen (object_id) — the run is one
    approval away from sealing COMPLETE_QUALIFIED. Barrier-safe: only pass/fail
    counts + the content-addressed object_id reach this surface, never scenario
    content. `continue` seals (no rebuild); `abort` seals SHIP_DECLINED."""
    passed = fe.get("passed")
    fe_line = (f"**{'PASS' if passed else 'FAIL'}** ({fe.get('count', 0)} held-out scenarios)"
               if fe.get("ran") else "not administered")
    failed_gates = (sec_report or {}).get("failed") or []
    lines = [
        f"# Before-ship checkpoint — iteration {iteration}",
        "",
        "Dev converged and the artifact is frozen. This is the final human gate "
        "before it seals as a qualified ship-candidate.",
        "",
        f"- Final exam: {fe_line}",
        f"- Security gates: **{'PASS' if not failed_gates else 'FAIL: ' + ', '.join(failed_gates)}**",
        f"- Frozen artifact object_id: `{object_id}`",
        "",
        "Decide: `resume --decision continue` (approve the ship — seals without "
        "rebuilding) · `resume --decision abort` (decline — seals SHIP_DECLINED, "
        "not shipped).",
        "",
    ]
    path = os.path.join(run_dir, "checkpoint_ship.md")
    _redacted_write(path, "\n".join(lines), redactor)
    return path


# M47 RA-08(a): the candidate_network modes that CONFINE the built app's egress.
# `unrestricted` (the config default, kept for back-compat and the only value a
# cooperative tier accepts) leaves the shipped artifact's network wide open and
# is DISQUALIFYING at a qualifying tier -- df_qualify folds this into the single
# qualification AND as the `candidate_egress` sub-state (code CANDIDATE_EGRESS_OPEN).
_CONFINED_CANDIDATE_NETWORK = ("deny", "loopback")


def _candidate_egress_qualified(candidate_network) -> bool:
    """True iff the candidate's egress is OS-confined to deny/loopback. An
    `unrestricted` candidate is False -> the candidate_egress sub-state is
    False -> at a qualifying tier (where barrier is True) the run is NOT
    qualified, sealing CANDIDATE_EGRESS_OPEN. At a non-qualifying tier barrier
    already fails first by precedence, so this value can never newly PASS a run
    -- only the fail-closed direction df_qualify's superset invariant guarantees."""
    return candidate_network in _CONFINED_CANDIDATE_NETWORK


def _qualification_field(mb_clean, effective, app_security=None, waiver_validity=True,
                         artifact_field=None):
    """M36a Task 2: the sealed `qualification` object for a terminal manifest,
    computed by the SINGLE qualification SM (df_qualify.derive). At the
    CONVERGED terminal the caller passes the exact booleans it decided; every
    OTHER terminal (which keeps qualified=False for its own reason) calls this
    with best-effort values so the manifest still carries an auditable
    substate breakdown. Conservative on the two dimensions a failed/early
    terminal can't have fully established: `app_security` defaults to
    False at a mandatory tier (gates may not have run) so this auxiliary field
    never OVER-claims qualification, and `control_plane` is True only when a
    real artifact object_id is bound. Because barrier ∧ ... precedence puts
    tier first, a cooperative terminal reads BARRIER_UNQUALIFIED regardless."""
    hi = (mb_clean.get("host_isolation") or {})
    if app_security is None:
        app_security = effective not in MANDATORY_TIERS
    art = artifact_field if artifact_field is not None else mb_clean.get("artifact")
    control_plane = bool(isinstance(art, dict) and art.get("object_id"))
    return df_qualify.derive(
        barrier=effective in _QUALIFYING_TIERS,
        host_isolation=bool(hi.get("qualified")),
        candidate_egress=_candidate_egress_qualified(mb_clean.get("candidate_network")),
        control_plane=control_plane,
        app_security=bool(app_security),
        waiver_validity=bool(waiver_validity))


def _budget_enforced(b):
    """Which caps are actively enforced (can trigger a BUDGET_PAUSE).

    Returns (dollar_enforced, calls_enforced). A $ cap requires billing=="api"
    AND max_usd AND per_call_usd (no per_call_usd => no estimate to reserve
    against => downgraded to alert-only, spec M8). max_calls is exact and
    enforced under any billing.
    """
    dollar_enforced = (b["billing"] == "api" and b["max_usd"] is not None
                       and b["per_call_usd"] is not None)
    calls_enforced = b["max_calls"] is not None
    return dollar_enforced, calls_enforced


def _budget_manifest_field(b, builder_calls, estimated_usd):
    dollar_enforced, calls_enforced = _budget_enforced(b)
    return {
        "billing": b["billing"],
        "builder_calls": builder_calls,
        "estimated_usd": estimated_usd,
        "cap_usd": b["max_usd"],
        "max_calls": b["max_calls"],
        "enforced": bool(dollar_enforced or calls_enforced),
        "estimate_caveat": "estimated from per_call_usd; not metered usage",
    }


def _read_critic_review(control_root):
    """The last CRITIC_REVIEW event recorded in <control_root>/authored.jsonl
    (M42), or None. This is the author-time record of the decorrelated critic
    loop -- the run-time manifest reads it back (read-only) so the auditable
    `adequacy.critic` field carries {rounds, blocking_resolved, advisories}
    without the supervisor re-running the critic at build time (the critic is
    an author-time concern; the gate at build time is adequacy + sharpness)."""
    path = os.path.join(control_root, "authored.jsonl")
    if not os.path.exists(path):
        return None
    result = None
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if e.get("state") == "CRITIC_REVIEW":
                    d = e.get("data", {})
                    result = {
                        "rounds": d.get("rounds"),
                        "blocking_resolved": d.get("blocking_resolved"),
                        "advisories": d.get("advisories"),
                        "same_model_ack": d.get("same_model_ack"),
                    }
    except OSError:
        return None
    return result


def _adequacy_manifest_field(cfg, behaviors, scenarios):
    """The auditable "how thorough were the tests" record (M42), sealed on
    every terminal that ran the pre-build gate. Combines: the class-coverage
    report (per-behavior, against the policy), the sharpness battery summary
    (scenario count + weakest kill count), and the decorrelated-critic record
    (read back from authored.jsonl). `checked` is False iff there is no
    behaviors.json to key class coverage on (mirrors `coverage`)."""
    policy = cfg["_adequacy"]
    field = {
        "required_classes": policy["required_classes"],
        "min_per_class": policy["min_per_class"],
        "sharpness": df_gates.sharpness_manifest(scenarios),
    }
    if behaviors is not None:
        adq = df_gates.check_adequacy(behaviors, scenarios, policy)
        field["checked"] = True
        field["per_behavior_class_coverage"] = adq["per_behavior_class_coverage"]
        field["under_covered"] = adq["under_covered"]
    else:
        field["checked"] = False
    # The critic is an author-time step; record its outcome (or that it was
    # configured but hasn't run) for the audit trail.
    if cfg.get("_critic") is not None:
        review = _read_critic_review(cfg["_control_root"])
        field["critic"] = {
            "enabled": policy["critic"]["enabled"],
            "review": review,
        }
    else:
        field["critic"] = None
    return field


def _property_manifest_field(scenarios):
    """M43a: the reproducibility + audit record for property scenarios.

    `scenarios` maps each property scenario id to {cases, seed, invariant} --
    with the seed recorded, a property run (and any counterexample) is
    replayable bit-for-bit (df_generate is a pure function of seed+spec).
    `violations` starts empty and is appended IN PLACE by the run loop when a
    property fails: the inner dict is SHARED (shallow-copied) into every
    terminal manifest via mb_clean/dict(mb_clean, ...), so a violation
    recorded mid-loop lands on whatever terminal the run reaches -- without
    threading a new argument through every terminal branch. Entries are
    VALUE-FREE (behavior-id + invariant name + case index +
    counterexample_recorded flag); the counterexample CONTENT lives only in
    the control-plane verifier report (run_dir), never here, never in
    feedback."""
    props = {}
    for sc in scenarios:
        prop = sc.get("when", {}).get("property")
        if prop:
            entry = {
                "cases": prop["generate"]["cases"],
                "seed": prop["generate"]["seed"],
                "invariant": sc["then"]["invariant"]["name"],
            }
            # M43b: a concurrency property records workers x attempts so the
            # PROBABILISTIC detection strength is auditable (a PASS is absence
            # of an observed race over cases x attempts x workers, not proof of
            # race-freedom — the honest framing, quantified here).
            conc = prop.get("concurrency")
            if conc:
                entry["workers"] = conc["workers"]
                entry["attempts"] = conc["attempts"]
            props[sc["id"]] = entry
    return {"scenarios": props, "violations": []}


def _journal_property_violations(journal, mb, results, *, cohort, iteration):
    """M43a: journal PROPERTY_VIOLATED (VALUE-FREE: behavior-id + invariant
    name + case index -- never the generated input) for each failed property
    scenario in `results`, and mirror the same value-free record into the
    shared manifest `property.violations` list (see _property_manifest_field
    for why in-place append reaches every terminal manifest)."""
    violations = mb.setdefault("property", {"scenarios": {}, "violations": []})["violations"]
    for r in results:
        pinfo = (r.get("observed") or {}).get("property")
        if not pinfo or r.get("taxonomy") != "property_violated":
            continue
        cx = pinfo.get("counterexample") or {}
        entry = {
            "cohort": cohort,
            "iteration": iteration,
            "behavior_id": r["behavior_id"],
            "invariant": pinfo.get("invariant"),
            "case_index": cx.get("case_index"),
            # The counterexample EXISTS (auditors: look in the run report);
            # its content is deliberately not reproduced here.
            "counterexample_recorded": cx != {},
        }
        # M43b: a concurrency violation also records WHICH interleaving attempt
        # struck (value-free — an int index, never a generated input). Only
        # present for concurrency scenarios, so M43a's exact value-free key set
        # is unchanged for sequential property violations.
        if "attempt_index" in cx:
            entry["attempt_index"] = cx["attempt_index"]
        journal.write("PROPERTY_VIOLATED", **entry)
        violations.append(entry)


def _usage_manifest_field(b, usage_known, input_tokens, output_tokens):
    """M25 Task 2: authoritative usage (known/input_tokens/output_tokens --
    accumulated in _run_loop from adapter-reported `resp["usage"]`, e.g.
    api_anthropic) plus an OPERATOR-priced `actual_usd`, threaded onto every
    terminal manifest exactly like `_budget_manifest_field` (fresh + resume,
    every outcome branch).

    `actual_usd` is computed ONLY when usage_known AND `budget.token_pricing`
    carries a "default" entry -- the run's builder model name isn't visible
    to the supervisor (DF_API_MODEL is adapter-side env, never returned in
    the protocol response), so per-model pricing keys are accepted and
    validated by df_config for forward-compat/documentation but selection is
    default-entry-only today (see references/budget.md). Absent pricing or
    unknown usage -> actual_usd is None; tokens are still recorded honestly
    (0/False when never reported). This is RECORDED truth, never admission-
    gating -- estimated_usd (above) alone drives the M8 admission/alert/
    pause path, unchanged.
    """
    pricing = (b.get("token_pricing") or {}).get("default")
    actual_usd = None
    if usage_known and pricing is not None:
        actual_usd = (input_tokens / 1e6 * pricing["input_per_mtok"]
                      + output_tokens / 1e6 * pricing["output_per_mtok"])
    return {
        "known": bool(usage_known),
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "actual_usd": actual_usd,
    }


def _notify_spool_dir(cfg):
    return os.path.join(cfg["_control_root"], ".notify-spool")


def _notify_budget(cfg, journal, redactor, invocation, trigger, estimated_usd,
                    builder_calls):
    """M18: best-effort delivery of a BUDGET_ALERT/BUDGET_PAUSE event to
    `budget.notification_sink`, when one is configured. FAIL-SOFT by
    construction — df_notify.deliver() never raises, and this function never
    affects control flow either way: a down alert channel journals
    NOTIFY_FAILED and the run proceeds exactly as it would have with no sink
    configured at all. Absent notification_sink, deliver() is never called
    (byte-identical to pre-M18 behavior).

    M22 Task 2: when `budget.notification_durable` is set, the SAME event
    goes through `df_notify.deliver_durable` instead — still fail-soft (the
    run's exit/outcome never changes either way) but at-least-once: a final
    failure after `notification_attempts` retries spools the (already
    redacted) event to `<control_root>/.notify-spool/pending.ndjson` and
    journals NOTIFY_SPOOLED rather than NOTIFY_FAILED. Absent
    notification_durable (default False), this branch is never taken —
    byte-identical to the M18 best-effort path above."""
    b = cfg["_budget"]
    sink = b["notification_sink"]
    if not sink:
        return
    event = {
        "event": trigger,
        "invocation": invocation,
        "estimated_usd": estimated_usd,
        "builder_calls": builder_calls,
        "cap": {"max_usd": b["max_usd"], "max_calls": b["max_calls"]},
        "ts": _now(),
    }
    if b.get("notification_durable"):
        ok, reason = df_notify.deliver_durable(
            sink, event, _notify_spool_dir(cfg),
            attempts=b["notification_attempts"], redactor=redactor,
        )
        if ok:
            journal.write("NOTIFY_SENT", event=trigger)
        elif reason == "spooled":
            journal.write("NOTIFY_SPOOLED", event=trigger)
        else:
            journal.write("NOTIFY_FAILED", event=trigger, reason=reason)
        return
    ok, reason = df_notify.deliver(sink, event, redactor=redactor)
    if ok:
        journal.write("NOTIFY_SENT", event=trigger)
    else:
        journal.write("NOTIFY_FAILED", event=trigger, reason=reason)


def _confine_manifest_field(confine_cfg, cli, adapter_path=None, expected_sha256=None):
    """builder_confinement manifest field (M14) for the CURRENT confine
    state. `confine_cfg["enabled"]` reflects whether confinement is
    ACTUALLY being applied to the builder for this manifest -- it can
    differ from the configured value after a `required: false`
    CONFINEMENT_WARN fallback flips it to False mid-run (never claim a
    profile's properties were applied when they weren't). `mcp_disabled`/
    `tool_allowlist` come from `df_confine.profile_for(cli, ...)` only when
    enabled; `probe` is `"unverified"` when enabled (M17 wires a real
    startup probe) or `"n/a"` when not.

    DF-R3-05 (M50): `adapter_path` + `expected_sha256` (the builder adapter's
    resolved path + its optional M47 `adapter_sha256`) are threaded into
    `profile_for` so the STRUCTURAL api_* profiles' `supported: True` is bound
    to a trusted adapter IDENTITY, not the bare basename. If confinement is
    enabled but the resolved profile is an UNSUPPORTED structural one (an
    impostor renamed `api_anthropic`, or a relocated copy with no digest pin),
    the field HONESTLY records that the no-tool-surface claim was NOT granted
    (`mcp_disabled: False`, empty `tool_allowlist`, `probe: "unsupported"`) —
    never a false structural claim earned by name alone.
    """
    if not confine_cfg["enabled"]:
        return {
            "enabled": False,
            "profile": confine_cfg["profile"],
            "mcp_disabled": False,
            "tool_allowlist": [],
            "probe": "n/a",
        }
    profile = df_confine.profile_for(cli, adapter_path, expected_sha256)
    if profile.get("structural") and not profile.get("supported"):
        # DF-R3-05 fail-closed: a structural profile whose adapter identity did
        # not match the shipped adapter (nor a pinned digest). Claim nothing.
        return {
            "enabled": True,
            "profile": confine_cfg["profile"],
            "mcp_disabled": False,
            "tool_allowlist": [],
            "probe": "unsupported",
        }
    return {
        "enabled": True,
        "profile": confine_cfg["profile"],
        "mcp_disabled": bool(profile.get("mcp_disabled", False)),
        "tool_allowlist": list(profile.get("tool_allowlist", [])),
        "probe": "unverified",
    }


def _object_store_root(control_root: str) -> str:
    """Where DF-01/M28a's content-addressed object store lives for this
    control root: `<control_root>/objects`. This is the `object_store`
    argument passed to every `df_seal.freeze`/`df_seal.verify_object` call
    in this module — the actual per-object directories/sidecars therefore
    live at `<control_root>/objects/objects/<object_id>[.json]` (df_seal's
    own `object_store/objects/...` convention layered under this module's
    `objects` dir). A later `verify` (Task 3) derives the SAME path from
    just the control root, so nothing about the object store's location
    needs to be recorded anywhere else.
    """
    return os.path.join(control_root, "objects")


def _seal_workspace_artifact(control_root: str, workspace: str):
    """Freeze `workspace` into the content-addressed object store (DF-01/
    M28a seal-first fix) and return `(object_id, artifact_field)`, where
    `artifact_field` is exactly what belongs at `manifest["artifact"]`.

    Raises `df_seal.SealError` on any hostile/unhashable workspace content
    (symlink, special file, setuid/setgid/world-writable entry, ...) — the
    caller MUST treat that as a fail-closed, non-qualified terminal
    (`ARTIFACT_UNHASHABLE`), never let a qualified/CONVERGED manifest out
    the door whose artifact couldn't actually be frozen.

    Reads the sidecar `df_seal.freeze()` already wrote back off disk
    (rather than re-scanning `workspace` a second time) so `file_count`/
    `dir_count` are exactly what was published — no second read of a
    workspace that could, in principle, differ from what was just hashed.
    """
    object_store = _object_store_root(control_root)
    object_id = df_seal.freeze(workspace, object_store)
    sidecar_path = os.path.join(object_store, "objects", object_id + ".json")
    with open(sidecar_path, "r", encoding="utf-8") as f:
        sidecar = json.load(f)
    artifact_field = {
        "object_id": object_id,
        "seal_version": sidecar["seal_version"],
        "file_count": len(sidecar["files"]),
        "dir_count": len(sidecar["dirs"]),
    }
    return object_id, artifact_field


def _materialize_validation_root(object_store: str, object_id: str, dest_dir: str) -> None:
    """M44 RA-01: create `dest_dir` empty and materialize the SEALED object
    into it so validation (security gates / final exam) can run against a
    PRISTINE copy of the exact bytes that will ship — never the mutable
    `workspace`, which a post-freeze side effect (a final-cohort scenario, a
    hostile candidate) can scrub to look clean AFTER the object is frozen.

    `df_seal.materialize_object` re-verifies object identity against its own
    sidecar FIRST (and refuses a non-empty dest), so a drifted/absent object
    raises `df_seal.SealError` here rather than seeding a validation root from
    untrustworthy bytes — the caller MUST turn that into the fail-closed
    ARTIFACT_UNHASHABLE terminal (never qualify). A stale copy from a crashed
    prior attempt is cleared first so the empty-dest precondition holds on a
    re-converge (resume re-enters this branch under the same workspace path)."""
    _discard_validation_root(dest_dir)
    os.makedirs(dest_dir)
    df_seal.materialize_object(object_store, object_id, dest_dir)


def _discard_validation_root(path: str) -> None:
    """Best-effort teardown of an M44 throwaway validation root (`R_gates` /
    `R_exam`). They hold only a copy of bytes the object store already holds,
    so a failed delete is not fatal and never raises — the object whose
    identity was bound into the manifest is the object store's, not this copy."""
    shutil.rmtree(path, ignore_errors=True)


# ---------------------------------------------------------------------------
# DF-01/M28a Task 3: verify-by-identity + custody-by-object-id + retention.
#
# Task 2 bound `manifest["artifact"] = {object_id, ...}` into the signed
# manifest. That binding is worthless as an enforcement mechanism unless
# something actually re-derives the object's identity from the live object
# store at verify/custody time and refuses on any drift -- that is what the
# helpers below do. All fail closed: an object that is missing, mutated, or
# was never bound in the first place is NEVER treated as a pass.
# ---------------------------------------------------------------------------

_ARTIFACT_OK = "OK"
_ARTIFACT_UNBOUND = "UNBOUND"
_ARTIFACT_MISMATCH = "ARTIFACT_MISMATCH"
_ARTIFACT_UNAVAILABLE = "ARTIFACT_UNAVAILABLE"


def _control_root_from_run_dir(run_dir: str):
    """Best-effort recovery of a run's control root from just its run_dir,
    for callers (verify-manifest) that historically were only ever given
    run_dir. Layout is always `<control_root>/runs/<invocation>` (see
    `run()`/`resume()`), so control_root is exactly two path components up.
    Returns None -- never raises -- if that doesn't hold (e.g. a relocated
    or hand-built run_dir); callers must treat None as "no derivable object
    store", not silently skip the artifact check.
    """
    runs_dir = os.path.dirname(os.path.abspath(run_dir))
    if os.path.basename(runs_dir) != "runs":
        return None
    control_root = os.path.dirname(runs_dir)
    return control_root if os.path.isdir(control_root) else None


def _check_manifest_artifact(manifest: dict, object_store: str) -> str:
    """The verify-by-identity check itself: recompute the bound object's
    sidecar (via df_seal.verify_object) and require it still matches.
    PRINTS the human-readable line for whichever status is returned --
    callers (verify_manifest / the CLI / custody) use the return value to
    pick a distinct exit code / bool, never re-deriving the message.

    manifest["artifact"] absent or null means the manifest never bound an
    object at all (pre-M28a, or a pre-workspace terminal like GATE_FAILED /
    ARTIFACT_UNHASHABLE) -- that is NOT a clean pass, it is UNBOUND: the
    caller must never treat "nothing to check" as "checked and fine".
    """
    artifact = manifest.get("artifact")
    if not isinstance(artifact, dict) or not isinstance(artifact.get("object_id"), str):
        print("UNBOUND: manifest does not bind an artifact object (pre-M28a manifest, or a "
              "pre-workspace terminal) -- integrity checks passed but artifact identity was "
              "never established")
        return _ARTIFACT_UNBOUND

    object_id = artifact["object_id"]
    if df_seal.verify_object(object_store, object_id):
        return _ARTIFACT_OK

    obj_path = os.path.join(object_store, "objects", object_id)
    if os.path.islink(obj_path) or not os.path.isdir(obj_path):
        print(f"ARTIFACT UNAVAILABLE (object {object_id} not found under {object_store})")
        return _ARTIFACT_UNAVAILABLE
    print(f"ARTIFACT MISMATCH (object {object_id} failed identity re-verification -- content, "
          "mode, or a filename drifted since it was sealed)")
    return _ARTIFACT_MISMATCH


def object_referenced(control_root: str, object_id: str) -> bool:
    """Retention guard: True iff ANY run manifest under control_root binds
    `object_id` as its artifact. dark-factory ships no prune/GC subsystem
    today (deliberately -- see task-3-report.md), but any future prune
    tooling, or an operator's own cleanup script, MUST consult this before
    removing an object directory. Never raises: an unreadable/malformed
    manifest is skipped, not fatal to the scan.
    """
    runs_dir = os.path.join(control_root, "runs")
    if not os.path.isdir(runs_dir):
        return False
    for name in os.listdir(runs_dir):
        mp = os.path.join(runs_dir, name, "manifest.json")
        if not os.path.isfile(mp):
            continue
        try:
            with open(mp, encoding="utf-8") as f:
                manifest = json.load(f)
        except (OSError, json.JSONDecodeError):
            continue
        artifact = manifest.get("artifact")
        if isinstance(artifact, dict) and artifact.get("object_id") == object_id:
            return True
    return False


def _kb_writeback(cfg, journal, manifest_dict, failing):
    """Opt-in KB write-back after a terminal manifest is finalized.

    Side-effect only: never raises, never affects control flow or exit codes.

    REDACTION COUPLING (M11): call sites pass the PRE-redaction manifest
    object. That is safe today ONLY because df_kb.build_summary hard-
    allowlists {finished_ts, invocation, outcome, tier, qualified,
    iterations} and never touches e.g. manifest["security"] (whose
    external-gate `detail` can embed a matched secret from tools like
    trufflehog). Any widening of build_summary's field allowlist MUST route
    the manifest through the run's Redactor (redact_obj) first.
    """
    kb = cfg.get("_kb", {"kind": "none"})
    if kb.get("kind") != "wiki" or not kb.get("write_back"):
        return
    try:
        path = df_kb.write_run_summary(kb, manifest_dict, failing)
        if path:
            journal.write("KB_WRITEBACK", path=path)
    except Exception as e:
        journal.write("KB_WRITEBACK_ERROR", detail=str(e))


def _verify_manifest_status(run_dir: str, key: bytes = None, object_store: str = None) -> str:
    """The full body of `verify-manifest`: byte-integrity checks (unchanged
    from pre-M28a) followed by DF-01/M28a Task 3's verify-by-identity check
    of the manifest's bound artifact object. Returns one of "OK" / "TAMPERED"
    / "UNVERIFIED" / _ARTIFACT_MISMATCH / _ARTIFACT_UNAVAILABLE /
    _ARTIFACT_UNBOUND, and PRINTS the corresponding human-readable line --
    `verify_manifest` (bool) and the CLI (exit code) both derive from this
    single source of truth so the printed line and the returned status can
    never disagree.

    object_store defaults to `_object_store_root(control_root)` where
    control_root is recovered from run_dir's `<control_root>/runs/<id>`
    layout (`_control_root_from_run_dir`); pass explicitly (the CLI's
    --object-store) when run_dir doesn't follow that layout.
    """
    mp = os.path.join(run_dir, "manifest.json")
    sp = os.path.join(run_dir, "manifest.sha256")
    jp = os.path.join(run_dir, "journal.jsonl")
    if not (os.path.exists(mp) and os.path.exists(sp) and os.path.exists(jp)):
        print("TAMPERED (missing manifest, sidecar, or journal)")
        return "TAMPERED"
    text = open(mp, encoding="utf-8").read()
    if sha256_str(text) != open(sp, encoding="utf-8").read().strip():
        print("TAMPERED (manifest.json does not match manifest.sha256)")
        return "TAMPERED"
    manifest = json.loads(text)
    if sha256_file(jp) != manifest.get("journal_sha256"):
        print("TAMPERED (journal.jsonl does not match manifest)")
        return "TAMPERED"
    hp = os.path.join(run_dir, "manifest.hmac")
    expect_sig = (key is not None) or bool(manifest.get("audit_signing"))
    if os.path.exists(hp):
        if key is None:
            print("UNVERIFIED (signed manifest; supply --key-path)")
            return "UNVERIFIED"
        sig = open(hp, encoding="utf-8").read().strip()
        if not df_audit.verify(key, text.encode("utf-8"), sig):
            print("TAMPERED (bad signature)")
            return "TAMPERED"
    elif expect_sig:
        print("UNVERIFIED (expected a signed manifest; manifest.hmac is missing)")
        return "UNVERIFIED"

    # Byte-integrity holds. DF-01/M28a Task 3: that only proves manifest.json
    # itself is untampered -- it says nothing about whether the artifact
    # object it REFERENCES still matches what was sealed. Verify by
    # identity, fail-closed.
    store = object_store
    if store is None:
        control_root = _control_root_from_run_dir(run_dir)
        store = _object_store_root(control_root) if control_root else None
    if store is None:
        print("ARTIFACT UNAVAILABLE (control root could not be derived from run_dir; pass "
              "--object-store explicitly)")
        return _ARTIFACT_UNAVAILABLE
    status = _check_manifest_artifact(manifest, store)
    if status == _ARTIFACT_OK:
        print("OK")
        # M36b Part B: a superseded parent STILL verifies OK (supersession is
        # provenance, not tampering), but surface it so a stale artifact is not
        # shipped unknowingly. Printed after OK, never changing the status.
        sb_path = os.path.join(run_dir, SUPERSEDED_BY_FILE)
        if os.path.isfile(sb_path):
            try:
                with open(sb_path, encoding="utf-8") as f:
                    sb = json.load(f)
                print(f"SUPERSEDED by child run {sb.get('child_run_id')} "
                      f"(at {sb.get('ts')}) — this artifact was forked; a newer child "
                      "run exists.")
            except (OSError, json.JSONDecodeError):
                print("SUPERSEDED (superseded_by.json present but unreadable)")
    return status


def verify_manifest(run_dir: str, key: bytes = None, object_store: str = None) -> bool:
    return _verify_manifest_status(run_dir, key=key, object_store=object_store) == _ARTIFACT_OK


# ---------------------------------------------------------------------------
# M36b Part B: spec-fork lineage + parent supersession.
# ---------------------------------------------------------------------------

SUPERSEDED_BY_FILE = "superseded_by.json"


def _resolve_credentials(cfg):
    """Resolve cfg["_credentials"] (if configured) into (creds, redactor).

    Fail-closed at run start (spec: "ConfigError-style refusal at run start,
    exit 2, never a silent empty value"): a CredsError here writes only to
    stderr — no run_dir, no journal entry, nothing on disk — and the caller
    must return 2 before touching anything else. Absent block -> (None, None):
    exactly today's behavior, no builder env change, no writer touched.
    """
    if not cfg["_credentials"]:
        return None, None, None
    try:
        creds = df_creds.load_credentials(cfg["_credentials"])
    except df_creds.CredsError as e:
        return None, None, e
    return creds, df_creds.Redactor(creds.values()), None


def _enforce_adapter_digests(cfg, journal):
    """M47 condition #7: if a role pinned `adapter_sha256`, the adapter FILE's
    actual content sha256 must match at run start, else REFUSE (fail-closed).
    Returns None when every pin matches (or none are set), otherwise an error
    string; the caller journals ADAPTER_DIGEST_MISMATCH (done here) and exits 2.

    An absent/unreadable file counts as a mismatch (actual=None != expected):
    pinning a digest means the exact bytes MUST be present, so a substituted or
    tampered adapter -- or a missing one -- can never run under the pin."""
    digests = cfg.get("_adapter_digests") or {}
    roles = cfg.get("roles") or {}
    checks = []
    if digests.get("builder"):
        checks.append(("builder", (roles.get("builder") or {}).get("adapter"),
                       digests["builder"]))
    if digests.get("author") and cfg.get("_author"):
        checks.append(("author", cfg["_author"]["adapter"], digests["author"]))
    if digests.get("critic") and cfg.get("_critic"):
        checks.append(("critic", cfg["_critic"]["adapter"], digests["critic"]))
    for role, path, expected in checks:
        actual = sha256_file(path) if (path and os.path.exists(path)) else None
        if actual != expected:
            journal.write("ADAPTER_DIGEST_MISMATCH", role=role, expected=expected,
                          actual=actual, adapter=path)
            return (f"roles.{role}.adapter_sha256 pin does not match the adapter "
                    f"file content (expected {expected}, actual {actual}) -- "
                    "refusing to run a substituted or tampered adapter")
    return None
