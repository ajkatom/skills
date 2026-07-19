"""dark-factory supervisor: the sole state-changing entry point (spec 7.7).

M1 walking skeleton, cooperative tier only. FSM:
  INIT -> SNAPSHOT -> [BUILD -> VERIFY -> (FEEDBACK ->)]* ->
  CONVERGED -> COMPLETE_UNQUALIFIED | CAP_REACHED | ABORTED_BUILD_ERROR
"""
import argparse
import datetime
import http.server
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import threading
import uuid

import df_audit
import df_audit_chain
import df_audit_sink
import df_author
import df_brownfield
import df_confine
import df_container
import df_creds
import df_critic
import df_custody
import df_gates
import df_init
import df_kb
import df_modes
import df_notify
import df_override
import df_proxy
import df_qualify
import df_release
import df_sandbox
import df_seal
import df_ship
import df_security
import df_twins
import df_waiver
from df_common import atomic_write, canonical_json, sha256_file, sha256_str
from df_config import (
    ConfigError,
    MANDATORY_TIERS,
    _adapter_provider,
    _disjoint,
    _PROXY_PROVIDER_RULES,
    load_config,
)
from id_feedback import project_feedback
from run_scenarios import OracleError, load_scenarios, run_all
import snapshot_source
from snapshot_source import SnapshotError, snapshot

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


def save_state(run_dir, next_iter, feedback, workspace, dev_status=None, regressions=None,
              builder_calls=0, estimated_usd=0.0, budget_alerted=False, reason="checkpoint",
              redactor=None, builder_input_tokens=0, builder_output_tokens=0,
              usage_known=False, phase=None, chain_append=False,
              scenario_set_sha256=None, artifact_object_id=None,
              build_approved_through=0, ship_meta=None):
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
    # state.json must NEVER carry a credential value: it holds only control-
    # plane bookkeeping (iteration counters, ID/taxonomy feedback, paths), but
    # it goes through the same redaction choke point as every other artifact
    # for defense in depth (redactor=None is a strict no-op).
    _redacted_write(
        os.path.join(run_dir, "state.json"),
        {
            "state_version": STATE_VERSION,
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
    # RA-05/M45: additive. A pre-M45 state.json (0.1 legacy OR a 0.2 state
    # written before this field existed) defaults to None -> the sealed hash
    # comes from the FSM chain genesis when available, else the run is treated
    # as unsealed-legacy (journaled, proceeds) rather than false-refused.
    state.setdefault("scenario_set_sha256", None)
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


# ---------------------------------------------------------------------------
# M44 RA-02/RA-03: the post-seal attestation paths (custody / waiver / release)
# must (1) require a successful REQUIRED off-box sink receipt BEFORE a run is
# locally qualifiable and roll back on failure, and (2) refuse to attest an
# INELIGIBLE manifest. The helpers below are shared by all three paths so the
# eligibility/receipt logic is defined once, not re-derived ad hoc.
# ---------------------------------------------------------------------------

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
    tier = manifest_obj.get("tier")
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


def _sink_receipt_bound(run_dir: str, receipt_basename: str, att_text: str):
    """RA-02 (verify side): True iff `<run_dir>/<receipt_basename>` exists, is
    well-formed, and is BOUND to `att_text` (its recorded body_sha256 equals
    the sha256 of the current attestation bytes). Fail-closed: absent,
    unparseable, or mismatched → (False, reason). Only consulted when the
    sealed config's `audit.sink.required` is true."""
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
        cfg = load_config(control_root)
    except ConfigError as e:
        sys.stderr.write(f"dark-factory: config error: {e}\n")
        return 2
    if cfg["_custody"] is None:
        sys.stderr.write("dark-factory: control root has no `custody` block; nothing to attach\n")
        return 2

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
        cfg = load_config(control_root)
    except ConfigError as e:
        print(f"CONFIG ERROR ({e})")
        return False
    if cfg["_custody"] is None:
        print("NO CUSTODY CONFIGURED (control root has no `custody` block)")
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
        cfg = load_config(control_root)
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
    now = _now_utc()
    satisfied, reason, covered, uncovered = df_waiver.verify_waiver_set(
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
        cfg = load_config(control_root)
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

    now = _now_utc()
    satisfied_now, reason_now, covered, _unc = _eval(now)
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

    # Verify the parent clean. If the parent's manifest is signed, load the audit
    # key so verification is a real signature check (not UNVERIFIED). Object
    # store is this control root's.
    vkey = None
    if parent_manifest.get("audit_signing"):
        try:
            vkey = df_audit.load_key(cfg["_audit"]["key_path"])
        except df_audit.AuditKeyError as e:
            sys.stderr.write(
                f"dark-factory: parent manifest is signed but its audit key could not be "
                f"loaded to verify it: {e}\n")
            return 2
    status = _verify_manifest_status(
        parent_run_dir, key=vkey, object_store=_object_store_root(control_root))
    if status != _ARTIFACT_OK:
        sys.stderr.write(
            f"dark-factory: refusing to fork — parent run does not verify clean "
            f"(status: {status}). A fork must start from a verified parent artifact.\n")
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
    files = {
        name: sha256_file(os.path.join(scenarios_dir, name))
        for name in sorted(os.listdir(scenarios_dir))
        if name.endswith(".json")
    }
    return sha256_str(canonical_json(files))


def _seccomp_profile_ok(path):
    """Fast, deterministic, offline sanity check that the enterprise seccomp
    profile at `path` exists and parses as a plausible Docker seccomp JSON
    document (has "defaultAction" + "syscalls"). This is NOT the live proof
    that the egress lock actually holds on a real kernel — that is
    df_container.probe_enterprise_egress, which needs a running proxy and
    specific allowed/denied hosts. (DF-05/M32: the live probe now DOES run
    once per enterprise run, via `_verify_enterprise_egress` below — against
    a throwaway stub target, not the real provider/allowlist — see that
    function's docstring for the honest scope split.) Any error (missing
    file, invalid JSON, wrong shape) → False, never a silent pass."""
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return False
    return isinstance(data, dict) and "defaultAction" in data and "syscalls" in data


# ---------------------------------------------------------------------------
# DF-05/M32: mandatory per-run egress verification.
#
# resolve_isolation's enterprise probe deliberately skips
# df_container.probe_enterprise_egress (needs a running proxy, which isn't up
# yet at resolve time — see _seccomp_profile_ok's docstring). Once the real
# credential proxy for THIS run is started (_run_loop, effective=="enterprise"),
# _verify_enterprise_egress runs the deferred probe exactly once, before the
# first builder call, and the run refuses (fail-closed) if it doesn't verify.
# ---------------------------------------------------------------------------

_EGRESS_PROBE_DENIED_HOST = "1.1.1.1"


def _egress_probe_stub_handler():
    class _StubHandler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            body = b"df-egress-probe-ok"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
            self.close_connection = True

        def log_message(self, format, *args):  # noqa: A002 (stdlib signature)
            pass

    return _StubHandler


def _start_egress_probe_stub():
    """Start a throwaway loopback HTTP stub (always 200 OK) — the mandatory
    per-run egress probe's "allowed" leg (see _verify_enterprise_egress).
    Never a real provider. Caller owns shutdown: httpd.shutdown();
    httpd.server_close()."""
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _egress_probe_stub_handler())
    httpd.daemon_threads = True
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    return httpd, httpd.server_address[1]


def _verify_enterprise_egress(cfg, pcfg, proxy_endpoint):
    """DF-05/M32 mandatory per-run egress verification. Called ONCE per
    enterprise `_run_loop` invocation (fresh run or resume — both restart the
    proxy), before the first builder call, from inside the same try/finally
    that already owns proxy_httpd/twin cleanup.

    HONEST SCOPE — what this DOES prove: using the SAME container image and
    seccomp profile this run will use for the builder, wired through a real
    (Docker) instance of the SAME enterprise entrypoint/iptables lockdown
    machinery (df_container.build_enterprise_argv +
    df_container.probe_enterprise_egress), it proves live that (a) an
    allowlisted-via-proxy origin is reachable and (b) a direct connection to
    a denied host is blocked and the probed child cannot re-add an iptables
    ACCEPT rule (NET_ADMIN was dropped).

    What this does NOT prove: it deliberately does NOT exercise the run's
    REAL credential_proxy process/allowlist/provider (the one started in
    _run_loop for the actual builder call) — the "allowed" leg here is a
    local, always-200 stub server this function starts and tears down
    itself, fronted by a distinct, throwaway proxy + capability token. This
    is a deliberate choice, not an oversight: when the builder is an API
    adapter, the run's REAL proxy has the M30 provider method/path
    injection lock ARMED (see df_proxy._PROVIDER_METHOD_PATH / Part 1's
    `provider=` wiring below) — a generic probe request against it would
    either be refused (method/path mismatch) or, worse, if it happened to
    match the locked method+path with no client auth header, actually
    trigger a REAL credential injection and a real (paid) provider call.
    Neither is acceptable for a MANDATORY, every-run, no-cost probe. Proving
    the run's real proxy+allowlist+injection+provider-lock end to end needs
    a real provider round trip — that is a SEPARATE, OPTIONAL, operator-
    invoked, paid check (see test_enterprise_config.py's
    test_probe_enterprise_egress_live and references/enterprise.md), not run
    automatically here.

    Returns (ok: bool, detail: dict [diagnostic only, never a secret/token],
    policy_digest: str [a STABLE sha256 over the allowlist/header/image/seccomp
    that define this run's egress policy — excludes the ephemeral proxy port
    so it is comparable across runs to detect policy drift]). Never raises: any failure to even set
    up the probe (stub server, throwaway proxy, docker) resolves to
    ok=False with a diagnostic detail — fail-closed, like
    df_container.probe_enterprise_egress's own contract.
    """
    # A STABLE, cross-run-comparable fingerprint of the egress-relevant
    # policy: the allowlist + injection header + the container image + the
    # seccomp profile that together define what egress is permitted. It
    # deliberately EXCLUDES the ephemeral proxy_endpoint (its port is
    # OS-assigned and random every run, which would make the digest differ
    # run-to-run even under an identical policy and defeat drift detection).
    # An operator can diff this digest across two runs to see whether the
    # egress policy actually changed.
    policy_digest = sha256_str(canonical_json({
        "allowlist": sorted(pcfg["allowlist"]),
        "header": pcfg["header"],
        "image": cfg["_container"]["image"],
        "seccomp_profile": cfg["_enterprise"]["seccomp"],
    }))
    stub_httpd = None
    probe_proxy_httpd = None
    # A per-call, randomly-named env var carries the probe's OWN throwaway
    # "provider" token for its OWN throwaway stub -- never a real credential,
    # never a name that could collide with an operator-configured env var,
    # and always removed in the finally below regardless of outcome.
    token_env_name = f"_DF_EGRESS_PROBE_TOKEN_{uuid.uuid4().hex}"
    try:
        stub_httpd, stub_port = _start_egress_probe_stub()
        os.environ[token_env_name] = secrets.token_urlsafe(16)
        probe_cap_token = secrets.token_urlsafe(32)
        probe_proxy_httpd, probe_proxy_port = df_proxy.serve(
            [f"127.0.0.1:{stub_port}"], token_env_name,
            capability_token=probe_cap_token)
        probe_proxy_endpoint = f"{_ENTERPRISE_PROXY_HOST}:{probe_proxy_port}"
        ok, detail = df_container.probe_enterprise_egress(
            cfg["_container"]["image"], probe_proxy_endpoint,
            f"http://127.0.0.1:{stub_port}/", _EGRESS_PROBE_DENIED_HOST,
            seccomp_profile_path=cfg["_enterprise"]["seccomp"],
            capability_token=probe_cap_token)
        return bool(ok), detail, policy_digest
    except Exception as e:
        return (False, {"error": f"egress probe setup failed: {e.__class__.__name__}: {e}"},
                policy_digest)
    finally:
        os.environ.pop(token_env_name, None)
        if probe_proxy_httpd is not None:
            probe_proxy_httpd.shutdown()
            probe_proxy_httpd.server_close()
        if stub_httpd is not None:
            stub_httpd.shutdown()
            stub_httpd.server_close()


def resolve_isolation(cfg, control_root, workspace, journal, allow_downgrade):
    if cfg["assurance"] == "enterprise":
        os_backend = df_sandbox.current_backend()
        os_name = os_backend.name if os_backend is not None else None
        os_ok = os_backend is not None and os_backend.available() and df_sandbox.probe_denial(
            os_backend, control_root, workspace)
        c = cfg["_container"]
        dk_ok = df_container.docker_available() and df_container.probe_container(
            c["image"], control_root, workspace)
        seccomp_path = cfg["_enterprise"]["seccomp"]
        # M22 Task 1: the offline shape-check (_seccomp_profile_ok) is a
        # fast, no-docker-needed rejection of a missing/malformed profile
        # (mirrors df_config's own load-time validation); the LIVE probe
        # (df_container.probe_seccomp) is the actual proof the profile
        # DENIES what it claims to on a real kernel -- run it only once the
        # offline check and the container probe both already passed (no
        # point spending a docker run on a profile path that's already known
        # bad, or when docker itself isn't even up). Same fail-closed
        # discipline as the egress probe: any doubt -> seccomp_ok False.
        seccomp_ok = (
            _seccomp_profile_ok(seccomp_path)
            and dk_ok
            and df_container.probe_seccomp(c["image"], seccomp_path)
        )
        if os_ok and dk_ok and seccomp_ok:
            return ("enterprise", os_backend.wrap_prefix(control_root, workspace),
                    df_container.ENTERPRISE_BACKEND_NAME, True)
        failed = []
        if not dk_ok:
            failed.append("docker")
        if not os_ok:
            failed.append("os_sandbox")
        if not seccomp_ok:
            failed.append("seccomp_profile")
        reason = f"enterprise probe failed: {', '.join(failed)}"
        if allow_downgrade:
            # Enterprise ⊇ hardened: a failed enterprise probe with a
            # WORKING hardened path (os+docker both ok, only the seccomp
            # profile is the problem) downgrades one step to hardened —
            # still container-barrier-qualified, just without the egress
            # lock/seccomp — before falling further to standard/cooperative.
            if os_ok and dk_ok:
                journal.write("DOWNGRADE", requested="enterprise", effective="hardened",
                              reason=reason)
                sys.stderr.write("dark-factory: enterprise tier UNavailable — DOWNGRADED to "
                                 "hardened (qualified, no egress lock/split-custody) by "
                                 "--allow-downgrade.\n")
                return ("hardened", os_backend.wrap_prefix(control_root, workspace),
                        df_container.BACKEND_NAME, True)
            if os_ok:
                journal.write("DOWNGRADE", requested="enterprise", effective="standard",
                              reason=reason)
                sys.stderr.write("dark-factory: enterprise tier UNavailable — DOWNGRADED to "
                                 "standard (qualified) by --allow-downgrade.\n")
                return ("standard", os_backend.wrap_prefix(control_root, workspace), os_name, True)
            journal.write("DOWNGRADE", requested="enterprise", effective="cooperative",
                          reason=reason)
            sys.stderr.write("dark-factory: enterprise tier UNavailable — DOWNGRADED to "
                             "cooperative (unqualified) by --allow-downgrade.\n")
            return ("cooperative", [], os_name, False)
        journal.write("PROBE_FAILED", requested="enterprise", reason=reason)
        raise df_sandbox.SandboxError(
            "enterprise tier requires a running Docker daemon + passing container probe "
            "+ a valid seccomp profile (and a working OS sandbox for the verifier); "
            f"none available ({reason}). Fix docker/the sandbox/seccomp profile, or set "
            "assurance=hardened/standard/cooperative (or pass --allow-downgrade).")
    if cfg["assurance"] == "hardened":
        os_backend = df_sandbox.current_backend()
        os_name = os_backend.name if os_backend is not None else None
        os_ok = os_backend is not None and os_backend.available() and df_sandbox.probe_denial(
            os_backend, control_root, workspace)
        c = cfg["_container"]
        dk_ok = df_container.docker_available() and df_container.probe_container(
            c["image"], control_root, workspace)
        if os_ok and dk_ok:
            return ("hardened", os_backend.wrap_prefix(control_root, workspace),
                    df_container.BACKEND_NAME, True)
        failed = []
        if not dk_ok:
            failed.append("docker")
        if not os_ok:
            failed.append("os_sandbox")
        reason = f"hardened probe failed: {', '.join(failed)}"
        if allow_downgrade:
            if os_ok:
                journal.write("DOWNGRADE", requested="hardened", effective="standard",
                              reason=reason)
                sys.stderr.write("dark-factory: hardened tier UNavailable — DOWNGRADED to "
                                 "standard (qualified) by --allow-downgrade.\n")
                return ("standard", os_backend.wrap_prefix(control_root, workspace), os_name, True)
            journal.write("DOWNGRADE", requested="hardened", effective="cooperative",
                          reason=reason)
            sys.stderr.write("dark-factory: hardened tier UNavailable — DOWNGRADED to "
                             "cooperative (unqualified) by --allow-downgrade.\n")
            # Intentionally (os_name, False), NOT (None, None) like a
            # configured-cooperative run: here the backend was probed and
            # FAILED, vs never probed at all — manifests keep that distinction.
            return ("cooperative", [], os_name, False)
        journal.write("PROBE_FAILED", requested="hardened", reason=reason)
        raise df_sandbox.SandboxError(
            "hardened tier requires a running Docker daemon + passing container probe "
            "(and a working OS sandbox for the verifier); none available "
            f"({reason}). Fix the sandbox/docker or set assurance=standard/cooperative "
            "(or pass --allow-downgrade).")
    if cfg["assurance"] != "standard":
        return "cooperative", [], None, None
    backend = df_sandbox.current_backend()
    name = backend.name if backend is not None else None
    ok = backend is not None and backend.available() and df_sandbox.probe_denial(
        backend, control_root, workspace)
    if ok:
        return "standard", backend.wrap_prefix(control_root, workspace), name, True
    if allow_downgrade:
        journal.write("DOWNGRADE", requested="standard", effective="cooperative",
                      reason="sandbox unavailable or denial probe failed")
        sys.stderr.write("dark-factory: standard tier UNavailable/probe failed — "
                         "DOWNGRADED to cooperative (unqualified) by --allow-downgrade.\n")
        return "cooperative", [], name, False
    journal.write("PROBE_FAILED", requested="standard",
                  reason="sandbox unavailable or denial probe failed")
    raise df_sandbox.SandboxError(
        "standard tier requires a working OS sandbox + passing denial probe; "
        "none available. Fix the sandbox or set assurance=cooperative "
        "(or pass --allow-downgrade).")


def _resolve_candidate_network_prefix(cfg, control_root, workspace, exec_prefix, eff_tier, journal):
    """M27 Task 2 (spec §7.4): builds the CANDIDATE/verifier-only exec wrapper
    used by every run_all(...) call (and brownfield characterize()), kept
    strictly separate from `exec_prefix` -- which stays exactly what
    resolve_isolation returned and is what the BUILDER uses at every tier
    (see _run_loop's builder_prefix handling, unchanged by this function). A
    network restriction on the candidate must never reach the builder.

    cfg["candidate_network"] == "unrestricted" (the default, and the ONLY
    legal value df_config accepts at a configured cooperative tier) is a
    total no-op: returns `exec_prefix` unchanged, byte-identical to pre-M27
    behavior -- nothing new is ever built or probed.

    Otherwise the EFFECTIVE tier must actually carry an OS sandbox backend
    (standard/hardened/enterprise -- the same tiers resolve_isolation ever
    calls `os_backend.wrap_prefix()` for; see _QUALIFYING_TIERS). A
    --allow-downgrade run can still resolve to "cooperative" at RUNTIME even
    though df_config only ever accepted candidate_network != "unrestricted"
    for a CONFIGURED standard-or-above tier -- in that case there is no
    sandbox left to enforce the restriction, so this fails closed exactly
    like a failed isolation probe: journals PROBE_FAILED and raises
    SandboxError, which every existing call site already catches and turns
    into a clean exit 2 (never a traceback).

    When a backend IS available, `wrap_prefix(..., network=mode)` builds the
    candidate-only wrapper and `probe_network_denial` LIVE-proves it before
    anything relies on it -- the same fail-closed discipline as the base
    denial probe. A SandboxError raised by wrap_prefix itself (e.g. Linux +
    "loopback", which bwrap cannot support) surfaces the same clean way.
    """
    mode = cfg["candidate_network"]
    if mode == "unrestricted":
        return exec_prefix
    if eff_tier not in _QUALIFYING_TIERS:
        reason = (f"effective isolation tier is {eff_tier!r} -- no OS sandbox "
                  "backend is available to enforce it")
        journal.write("PROBE_FAILED", requested=f"candidate_network:{mode}", reason=reason)
        raise df_sandbox.SandboxError(
            f"candidate_network {mode!r} requires a working OS sandbox backend, but "
            f"{reason}. Fix the sandbox or set candidate_network=unrestricted.")
    os_backend = df_sandbox.current_backend()
    try:
        candidate_prefix = os_backend.wrap_prefix(control_root, workspace, network=mode)
    except df_sandbox.SandboxError as e:
        journal.write("PROBE_FAILED", requested=f"candidate_network:{mode}", reason=str(e))
        raise
    ok, reason = df_sandbox.probe_network_denial(os_backend, control_root, workspace, mode)
    if not ok:
        journal.write("PROBE_FAILED", requested=f"candidate_network:{mode}", reason=reason)
        raise df_sandbox.SandboxError(
            f"candidate_network {mode!r} live network-denial probe failed -- refusing "
            f"to run the candidate with an unproven network restriction: {reason}")
    return candidate_prefix


# host_isolation residuals that DISQUALIFY (manifest host_isolation.qualified
# False when any is present). RESIDUAL_METADATA (stat/existence visibility
# outside $HOME, structural to the profile's measured-required broad
# file-read-metadata allow) and RESIDUAL_NET_UNRESTRICTED (egress open because
# candidate_network was CONFIGURED unrestricted -- that axis' own choice, not
# a host-read defect) are the two non-disqualifying ones; everything else --
# host reads open, keychain reachable, resolver reachable at a denying network
# mode -- defeats the point of host isolation. M36's qualification FSM folds
# this field into the overall `qualified` boolean; M29b only computes and
# seals it honestly.
_HOST_ISOLATION_SOFT_RESIDUALS = frozenset({
    df_sandbox.RESIDUAL_METADATA,
    df_sandbox.RESIDUAL_NET_UNRESTRICTED,
    # M47 RA-08(b): a host backend's process-group escape is NAMED honestly as a
    # residual but does NOT disqualify -- host_isolation already gates on host
    # READ containment; the process-group best-effort is a separately-documented
    # residual (references/isolation.md) that a namespace backend closes.
    df_sandbox.RESIDUAL_PROCESS_GROUP_ESCAPE,
})


def _host_isolation_qualified(mode, passed, residuals):
    return bool(
        mode == "default_deny"
        and passed
        and not [r for r in residuals if r not in _HOST_ISOLATION_SOFT_RESIDUALS]
    )


def _annotate_process_containment(hi, backend=None):
    """M47 RA-08(b): stamp the honest `process_containment` label onto a
    host_isolation dict, and for a best-effort (host) backend append the (soft)
    process_group_escape residual so the residual is auditable.

    A candidate that ACTUALLY ran default-deny on a PID-namespace backend (Linux
    --unshare-pid netns; a hardened/enterprise container's own PID namespace)
    has every descendant -- setsid()/double-fork included -- reaped by
    construction: "namespace". Every other case (macOS sandbox-exec, the
    standard-tier host path, an allow-host-read opt-out, cooperative's unwrapped
    candidate) can only best-effort killpg the process group, which a deliberate
    setsid()/double-fork escapes: "process_group_besteffort" (+ the residual).
    "none" only when there is no OS sandbox backend at all. Conservative by
    design -- it never OVER-claims "namespace" (the fail-closed direction).
    Idempotent (dedups the residual). Returns the same dict for convenience."""
    if backend is None:
        backend = df_sandbox.current_backend()
    if backend is None:
        hi["process_containment"] = "none"
        return hi
    namespace = (getattr(backend, "provides_pid_namespace", False)
                 and hi.get("mode") == "default_deny")
    if namespace:
        hi["process_containment"] = "namespace"
        return hi
    hi["process_containment"] = "process_group_besteffort"
    residuals = hi.setdefault("residuals", [])
    if df_sandbox.RESIDUAL_PROCESS_GROUP_ESCAPE not in residuals:
        residuals.append(df_sandbox.RESIDUAL_PROCESS_GROUP_ESCAPE)
    return hi


def _host_isolation_preliminary(cfg):
    """Config-time-known seed for the manifest `host_isolation` field, so
    EVERY terminal manifest carries it (including pre-probe abort branches,
    same additive pattern as `candidate_network`). probed=False /
    qualified=False until resolve_candidate_prefix replaces it with the
    live-probed truth."""
    if cfg.get("candidate_host_read") == "default_deny":
        mode = "default_deny"
    elif cfg.get("assurance") in ("standard", "hardened", "enterprise"):
        mode = "allow_host_read_optout"
    else:
        mode = "none"
    residuals = [] if mode == "default_deny" else [df_sandbox.RESIDUAL_HOST_READ_OPEN]
    return _annotate_process_containment(
        {"mode": mode, "probed": False, "passed": None,
         "residuals": residuals, "qualified": False})


def resolve_candidate_prefix(cfg, control_root, workspace, exec_prefix, eff_tier,
                             journal, allow_downgrade=False):
    """M29b (DF-02 host-read half): resolves the CANDIDATE/verifier-only exec
    wrapper AND the manifest `host_isolation` field -- returns
    (candidate_prefix, host_isolation). The builder's `exec_prefix` is never
    touched (CLI builders legitimately need HOME/keychain/DNS; their
    isolation story is the hardened/enterprise container).

    Paths, in order:
    - cfg["candidate_host_read"] != "default_deny" (explicit opt-out at
      standard+, or the cooperative-tier default): the prefix is EXACTLY the
      M27 `_resolve_candidate_network_prefix` result -- byte-identical
      behavior -- and host_isolation says so honestly
      (mode="allow_host_read_optout"/"none", RESIDUAL_HOST_READ_OPEN,
      qualified False).
    - default_deny + effective tier downgraded to cooperative (only
      reachable via --allow-downgrade, which already sanctioned running
      unqualified): no backend is left to enforce anything; journal the
      DOWNGRADE and return the (empty) exec_prefix with mode="none". A
      restricted candidate_network still fails closed here exactly as M27
      (delegated below).
    - default_deny + backend WITHOUT `supports_default_deny` (Linux bwrap
      until M29c, plus any test double): the legacy candidate wrapper +
      legacy probes, reported as mode="legacy_allow_host_read" -- flagged,
      never a fake default-deny claim.
    - default_deny + macOS: `probe_candidate_confinement` live-proves the
      profile fail-closed BEFORE any build. Probe failure refuses the run
      (journal CANDIDATE_CONFINEMENT_PROBE_FAILED, SandboxError -> the
      existing clean exit 2), unless --allow-downgrade, which falls back to
      the legacy wrapper as mode="allow_host_read_downgrade" (journaled,
      unqualified) -- mirroring the isolation-probe downgrade UX. On
      success the returned prefix pins NO loopback ports yet (twins are not
      started); _run_loop rebuilds the same proven profile shape per verify
      pass with that pass's twin ports via _candidate_prefix_for_twins.
    """
    host_read = cfg.get("candidate_host_read", "allow_host_read")
    net_mode = cfg["candidate_network"]

    if host_read != "default_deny" or eff_tier not in _QUALIFYING_TIERS:
        # Both the explicit opt-out and the sanctioned runtime downgrade land
        # on the M27 resolver, which itself fails closed on a restricted
        # candidate_network with no backend to enforce it.
        prefix = _resolve_candidate_network_prefix(
            cfg, control_root, workspace, exec_prefix, eff_tier, journal)
        if eff_tier not in _QUALIFYING_TIERS:
            if host_read == "default_deny":
                # Configured default_deny but the run was explicitly
                # downgraded to cooperative -- record that the host-read
                # protection went with the sandbox it rides on.
                journal.write("DOWNGRADE", requested="candidate_host_read:default_deny",
                              effective="none",
                              reason="effective tier is cooperative -- no OS sandbox backend")
                sys.stderr.write(
                    "dark-factory: candidate_host_read default_deny DOWNGRADED to none "
                    "(cooperative tier has no sandbox) -- host_isolation unqualified.\n")
            hi = {"mode": "none", "probed": False, "passed": None,
                  "residuals": [df_sandbox.RESIDUAL_HOST_READ_OPEN], "qualified": False}
        else:
            hi = {"mode": "allow_host_read_optout", "probed": False, "passed": None,
                  "residuals": [df_sandbox.RESIDUAL_HOST_READ_OPEN], "qualified": False}
        # M47 RA-08(b): neither branch runs the candidate in a PID namespace
        # (opt-out / cooperative-downgrade), so process containment is
        # best-effort -- labelled honestly with the process_group_escape residual.
        return prefix, _annotate_process_containment(hi)

    os_backend = df_sandbox.current_backend()
    if os_backend is None:
        # eff_tier is qualifying, so resolve_isolation just used a live
        # backend; it vanishing between the two calls is a broken
        # environment, not a policy choice -- fail closed.
        reason = "no OS sandbox backend available for the candidate wrapper"
        journal.write("CANDIDATE_CONFINEMENT_PROBE_FAILED",
                      requested="candidate_host_read:default_deny", reason=reason)
        raise df_sandbox.SandboxError(
            f"candidate_host_read 'default_deny': {reason}")

    if not getattr(os_backend, "supports_default_deny", False):
        # Backend without a default-deny profile (Linux bwrap until M29c,
        # plus any test double): take the EXACT M27 path -- same wrapper,
        # same probes, same journal events (a network-probe failure still
        # surfaces as PROBE_FAILED, not as a confinement failure it isn't)
        # -- and label the result honestly: host reads are OPEN here.
        # probed/passed refer to the legacy guarantees that were actually
        # proven for this run (resolve_isolation's control-root denial
        # probe at every qualifying tier, plus the M27 network probe when
        # candidate_network is restricted), never to a default-deny claim.
        prefix = _resolve_candidate_network_prefix(
            cfg, control_root, workspace, exec_prefix, eff_tier, journal)
        hi = {"mode": "legacy_allow_host_read", "probed": True, "passed": True,
              "residuals": [df_sandbox.RESIDUAL_HOST_READ_OPEN], "qualified": False}
        return prefix, _annotate_process_containment(hi, os_backend)

    ok, report = df_sandbox.probe_candidate_confinement(
        os_backend, control_root, workspace, net_mode)
    if not ok:
        reason = report.get("detail", "confinement probe failed")
        journal.write("CANDIDATE_CONFINEMENT_PROBE_FAILED",
                      requested="candidate_host_read:default_deny", reason=reason)
        if allow_downgrade:
            journal.write("DOWNGRADE", requested="candidate_host_read:default_deny",
                          effective="allow_host_read", reason=reason)
            sys.stderr.write(
                "dark-factory: candidate default-deny confinement probe FAILED; "
                "DOWNGRADED to allow_host_read (unqualified host_isolation) by "
                "--allow-downgrade.\n")
            prefix = _resolve_candidate_network_prefix(
                cfg, control_root, workspace, exec_prefix, eff_tier, journal)
            hi = {"mode": "allow_host_read_downgrade", "probed": True, "passed": False,
                  "residuals": [df_sandbox.RESIDUAL_HOST_READ_OPEN], "qualified": False}
            return prefix, _annotate_process_containment(hi, os_backend)
        raise df_sandbox.SandboxError(
            "candidate_host_read 'default_deny' live confinement probe failed -- "
            f"refusing to run the candidate with unproven host isolation: {reason} "
            "(fix the sandbox, set candidate_host_read=allow_host_read, or pass "
            "--allow-downgrade)")

    try:
        prefix = os_backend.wrap_candidate_prefix(
            control_root, workspace, network=net_mode)
    except df_sandbox.SandboxError as e:
        journal.write("CANDIDATE_CONFINEMENT_PROBE_FAILED",
                      requested="candidate_host_read:default_deny", reason=str(e))
        raise
    mode = report.get("mode", "default_deny")
    residuals = list(report.get("residuals", []))
    hi = {"mode": mode, "probed": True, "passed": True, "residuals": residuals,
          "qualified": _host_isolation_qualified(mode, True, residuals)}
    # M47 RA-08(b): on a namespace backend (Linux --unshare-pid) this stamps
    # "namespace"; on macOS sandbox-exec (a host backend) "process_group_
    # besteffort" + the soft process_group_escape residual. qualified was
    # computed above and the residual is SOFT, so labelling never flips it.
    return prefix, _annotate_process_containment(hi, os_backend)


def _candidate_prefix_for_twins(cfg, host_isolation, workspace, base_prefix, twin_env):
    """Per-verify-pass candidate wrapper (M29b): when the run is in
    default-deny mode, rebuild the SAME probe-proven profile shape with THIS
    pass's twin ports pinned (twins bind fresh ephemeral ports on every
    reset, so a run-start wrapper cannot know them). Ports are data flowing
    into an already-live-proven profile shape -- no re-probe per pass. Any
    other mode (opt-out, downgrade, legacy, cooperative) returns the
    resolved base prefix untouched, so this can never silently re-tighten a
    sanctioned downgrade or loosen anything.

    A twin endpoint whose port cannot be parsed is SKIPPED, never widened:
    the candidate then simply cannot reach that twin and the scenario fails
    visibly -- fail closed, not open."""
    if not host_isolation or host_isolation.get("mode") != "default_deny":
        return base_prefix
    backend = df_sandbox.current_backend()
    if backend is None or not getattr(backend, "supports_default_deny", False):
        # resolve_candidate_prefix proved a default-deny-capable backend at
        # run start; it disappearing mid-run is a broken environment.
        raise df_sandbox.SandboxError(
            "candidate default-deny wrapper: sandbox backend disappeared mid-run")
    ports = set()
    for value in (twin_env or {}).values():
        try:
            ports.add(int(str(value).rsplit(":", 1)[1]))
        except (IndexError, ValueError):
            continue
    return backend.wrap_candidate_prefix(
        cfg["_control_root"], workspace, network=cfg["candidate_network"],
        allowed_loopback_ports=sorted(ports))


def _init_report_lines(report: dict) -> list:
    """Human-readable failure lines for a not-ok df_init.validate_scaffold
    report -- covers every branch that report shape can take (config,
    scenario-load, behaviors-load, inert, coverage, spec_leak)."""
    lines = []
    if not report.get("config_ok"):
        lines.append(f"  config.json: FAILED ({report.get('config_error', 'did not load')})")
        return lines
    if "scenarios_error" in report:
        lines.append(f"  scenarios/: FAILED to load ({report['scenarios_error']})")
        return lines
    if "behaviors_error" in report:
        lines.append(f"  behaviors.json: FAILED to load ({report['behaviors_error']})")
        return lines
    if report.get("inert"):
        lines.append(f"  inert (non-discriminating) scenarios: {report['inert']}")
    coverage = report.get("coverage", {})
    if coverage.get("uncovered_dev"):
        lines.append(f"  behaviors with no dev-cohort scenario: {coverage['uncovered_dev']}")
    if coverage.get("orphan_scenarios"):
        lines.append(f"  scenarios referencing an undeclared behavior_id: {coverage['orphan_scenarios']}")
    if report.get("spec_leak"):
        ids = sorted({leak["scenario_id"] for leak in report["spec_leak"]})
        lines.append(
            f"  spec_leak: scenario(s) {ids} have a `then` value appearing verbatim in "
            "spec.md (the builder-visible spec would leak the holdout answer)"
        )
    if not lines:
        lines.append("  (validate_scaffold reported not-ok with no specific failure recorded)")
    return lines


def _init_prerequisite_lines(cfg: dict) -> list:
    """Run-time prerequisites for the scaffolded control root's assurance
    tier -- printed, never checked here (init never runs a build; `run`
    fails closed on its own if these aren't actually met)."""
    adapter = cfg.get("roles", {}).get("builder", {}).get("adapter", "<unset>")
    lines = [f"  - the builder CLI/adapter must be installed and executable: {adapter}"]
    assurance = cfg.get("assurance")
    if assurance in ("hardened", "enterprise"):
        lines.append(f"  - a running Docker daemon (assurance: {assurance})")
        lines.append("  - a working OS sandbox backend for the verifier (macOS sandbox-exec / Linux bwrap)")
    elif assurance == "standard":
        lines.append("  - a working OS sandbox backend (macOS sandbox-exec / Linux bwrap) + a passing denial probe")
    if assurance == "enterprise":
        lines.append(
            "  - approver PRIVATE keys distributed to the operators named by "
            "custody.approvers (generated off-host, e.g. `supervisor.py "
            "df-custody keygen`; init never generates or sees a private key) "
            "-- a run stays CUSTODY_PENDING until >=threshold approvers sign "
            "via `df-custody sign` + `attach` (see references/enterprise.md)"
        )
        lines.append(
            "  - the configured audit sink must be REACHABLE and its WORM/"
            "retention (Object Lock) config ACTIVE -- init only checked the "
            "sink config's SHAPE, never reached it; verify this by hand "
            "(see references/enterprise.md, 'Manual WORM-readback preflight')"
        )
    if cfg.get("enterprise_downgrade_note"):
        lines.append(f"  - NOTE: {cfg['enterprise_downgrade_note']}")
    return lines


def init_cmd(control_root: str, answers_path: str, force: bool = False, force_keep: bool = False) -> int:
    """CLI body for `init`: df_init.scaffold(control_root, answers) then
    df_init.validate_scaffold(control_root) -- init BLESSES a control root
    only when the real validators (df_config.load_config, oracle
    discrimination, coverage, the spec_leak barrier check) all pass, exactly
    what `run` would independently accept. Never runs a build.

    ok -> prints the scaffolded tree summary + the exact `run` command + the
    tier's run-time prerequisites, returns 0.
    not ok -> prints the report's specific failures, removes the scaffolded
    tree (unless `force_keep`), returns 2.
    An InitError raised by scaffold() itself (a pure-answers violation, or a
    non-empty control_root refused without `force`) means NOTHING was ever
    written -- printed to stderr, returns 2, no cleanup needed.
    """
    control_root = os.path.abspath(control_root)
    try:
        if answers_path == "-":
            answers_text = sys.stdin.read()
        else:
            with open(answers_path, encoding="utf-8") as f:
                answers_text = f.read()
    except OSError as e:
        sys.stderr.write(f"dark-factory: init: cannot read answers ({e})\n")
        return 2

    try:
        answers = json.loads(answers_text)
    except json.JSONDecodeError as e:
        sys.stderr.write(f"dark-factory: init: answers is not valid JSON ({e})\n")
        return 2
    if not isinstance(answers, dict):
        sys.stderr.write("dark-factory: init: answers must be a JSON object\n")
        return 2

    # --control-root is the single source of truth for WHERE the scaffold is
    # written; overwrite whatever (likely placeholder) control_root the
    # answers carry so df_init's disjointness check (build_config) runs
    # against the ACTUAL write target, never a stale path from the file.
    answers = dict(answers)
    answers["control_root"] = control_root
    if force:
        answers["force"] = True

    try:
        df_init.scaffold(control_root, answers)
    except df_init.InitError as e:
        sys.stderr.write(f"dark-factory: init: {e}\n")
        return 2

    ok, report = df_init.validate_scaffold(control_root)
    if not ok:
        sys.stderr.write(f"dark-factory: init: scaffolded control root FAILED validation ({control_root}):\n")
        for line in _init_report_lines(report):
            sys.stderr.write(line + "\n")
        if force_keep:
            sys.stderr.write(
                f"dark-factory: init: --force-keep set -- leaving the invalid tree at {control_root}\n")
        else:
            shutil.rmtree(control_root, ignore_errors=True)
            sys.stderr.write(f"dark-factory: init: removed the invalid control root {control_root}\n")
        return 2

    cfg = load_config(control_root)
    behaviors = df_gates.load_behaviors(control_root) or []
    # M40: a scenarios-pending-author scaffold validated as structurally OK
    # (validate_scaffold set scenarios_pending) but has NO scenario files yet.
    # Print the pending summary + the author-scenarios next step instead of
    # loading a scenario set that doesn't exist.
    pending = report.get("scenarios_pending")
    if not pending:
        scenarios = load_scenarios(os.path.join(control_root, "scenarios"))
        dev_n = sum(1 for s in scenarios if s.get("cohort", "dev") == "dev")
        final_n = sum(1 for s in scenarios if s.get("cohort") == "final")

    print(f"dark-factory: init OK -- control root {control_root}")
    print(f"  config.json     assurance={cfg['assurance']}  autonomy={cfg['autonomy']}")
    if cfg.get("enterprise_downgrade_note"):
        print(f"  ** NOT enterprise-qualified ** {cfg['enterprise_downgrade_note']}")
    print("  spec.md         (builder-visible; no scenario content)")
    print(f"  behaviors.json  {len(behaviors)} behavior(s): {', '.join(b['id'] for b in behaviors)}")
    if pending:
        author_adapter = cfg.get("roles", {}).get("author", {}).get("adapter", "<unset>")
        print("  scenarios/      PENDING -- an agent author will write them "
              "(scenarios_pending_author marker present)")
        print("Next: have the author agent write the hidden scenarios:")
        print(f"  python3 {os.path.abspath(__file__)} author-scenarios --control-root {control_root}")
        print(f"  (author adapter, a DIFFERENT model than the builder: {author_adapter})")
        print("Then, after reviewing scenarios/*.json:")
        print(f"  python3 {os.path.abspath(__file__)} run --control-root {control_root}")
    else:
        print(f"  scenarios/      {len(scenarios)} scenario(s) ({dev_n} dev, {final_n} final/sealed)")
        print("Run:")
        print(f"  python3 {os.path.abspath(__file__)} run --control-root {control_root}")
    print("Prerequisites:")
    for line in _init_prerequisite_lines(cfg):
        print(line)
    return 0


def _author_review_confirm(normalized: list) -> bool:
    """--review gate: print every generated scenario (id/behavior/cohort/title
    + the literal run/then, control-plane only -- these never reach the
    builder) and require an interactive 'yes' before install. Honors the
    documented "human review is RECOMMENDED" limitation without forcing it
    (off by default). A non-tty stdin or anything but an explicit yes is a
    fail-closed decline -- authoring never installs an unreviewed set under
    --review."""
    print("dark-factory: author-scenarios --review -- generated scenarios "
          "(NOT yet installed):")
    for sc in normalized:
        print(f"  [{sc['id']}] behavior={sc['behavior_id']} cohort={sc['cohort']} "
              f"title={sc.get('title', '')!r}")
        print(f"      run:  {sc['when']['run']}")
        print(f"      then: {json.dumps(sc['then'], sort_keys=True)}")
    try:
        answer = input("Install these scenarios? [y/N] ").strip().lower()
    except EOFError:
        answer = ""
    return answer in ("y", "yes")


def _author_once(adapter, spec_text, behaviors, policy, timeout_s, *,
                 attempt_feedback, critic_feedback):
    """One author invocation in a FRESH scratch workdir (torn down here -- a
    pre-run artifact that must never persist or reach the builder). Returns
    (status, payload):
      ("adapter_error", detail)          -- transport/env failure (deterministic)
      ("parse_error", report)            -- unusable scenarios.json (retryable)
      ("invalid", report)                -- failed a gate (retryable)
      ("ok", (report, normalized))       -- a validated, installable set
    `policy` (M42) is threaded into BOTH the prompt (so the author knows the
    required classes) and validate_authored (so the adequacy gate uses it).
    `critic_feedback`, when set, carries a prior critic's BLOCKING findings for
    the author to address in this revision (barrier-safe: verifier-side text)."""
    workdir = tempfile.mkdtemp(prefix="df-author-")
    try:
        prompt = df_author.compose_author_prompt(
            spec_text, behaviors, policy=policy,
            attempt_feedback=attempt_feedback, critic_feedback=critic_feedback)
        prompt_file = os.path.join(workdir, "AUTHOR_PROMPT.md")
        atomic_write(prompt_file, prompt)
        resp, err = invoke_adapter(adapter, "author", workdir, prompt_file, timeout_s)
        if err or resp.get("status") != "ok":
            return "adapter_error", (err or resp.get("detail", ""))
        try:
            scenarios_raw = df_author.parse_author_output(workdir)
        except df_author.AuthorError as e:
            report = _empty_author_report()
            report["schema_errors"] = [str(e)]
            return "parse_error", report
        ok, report, normalized = df_author.validate_authored(
            scenarios_raw, spec_text, behaviors, policy)
        if not ok:
            return "invalid", report
        return "ok", (report, normalized)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def _critic_once(critic_adapter, spec_text, behaviors, normalized, policy,
                 timeout_s, declared_ids):
    """One critic invocation in a FRESH scratch workdir (torn down here -- its
    output is control-plane and MUST NEVER reach the builder workspace).
    Returns (status, payload):
      ("adapter_error", detail)              -- transport/env failure
      ("parse_error", detail)                -- unparseable/wrong-shape verdict
      ("ok", (blocking, advisories))         -- normalized findings
    The critic sees the AUTHORED scenarios (verifier side); its verdict never
    crosses the barrier."""
    workdir = tempfile.mkdtemp(prefix="df-critic-")
    try:
        prompt = df_critic.compose_critic_prompt(spec_text, behaviors, normalized, policy=policy)
        prompt_file = os.path.join(workdir, "CRITIC_PROMPT.md")
        atomic_write(prompt_file, prompt)
        resp, err = invoke_adapter(critic_adapter, "critic", workdir, prompt_file, timeout_s)
        if err or resp.get("status") != "ok":
            return "adapter_error", (err or resp.get("detail", ""))
        try:
            verdict = df_critic.parse_critic_output(workdir)
            blocking, advisories = df_critic.validate_critic_verdict(verdict, declared_ids)
        except df_critic.CriticError as e:
            return "parse_error", str(e)
        return "ok", (blocking, advisories)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def author_scenarios_cmd(control_root: str, attempts: int = 3, review: bool = False) -> int:
    """CLI body for `author-scenarios` (M40): an AGENT author (a different
    model than the builder, enforced at config load) writes the hidden
    scenarios into a scaffolded, scenarios-pending control root.

    Flow: load config (must have roles.author) -> load spec.md + behaviors.json
    -> invoke the author adapter in a FRESH scratch workdir (role="author") ->
    parse its scenarios.json -> validate through the IDENTICAL init gates
    (discrimination/coverage/spec-leak/shape). On a validation failure, re-invoke
    with impoverished, barrier-safe feedback up to `attempts` times. On success,
    ATOMICALLY install one file per scenario into <control_root>/scenarios/ (the
    same layout df_init.scaffold produces), clear the pending marker LAST (the
    commit point -- a crash before it leaves `run` still fail-closed), and journal
    an AUTHORED_SCENARIOS control-plane event (adapter/attempts/counts -- NEVER
    scenario content). Exhausted attempts => exit 2, control root left with NO
    scenarios (never a bad partial set). The barrier is byte-for-byte unchanged:
    scenarios seal via the existing path and `run` is untouched.
    """
    control_root = os.path.abspath(control_root)
    try:
        cfg = load_config(control_root)
    except ConfigError as e:
        sys.stderr.write(f"dark-factory: author-scenarios: config error: {e}\n")
        return 2

    author = cfg.get("_author")
    if author is None:
        sys.stderr.write(
            "dark-factory: author-scenarios: no roles.author configured in "
            f"{control_root}/config.json -- add a roles.author block (a DIFFERENT "
            "adapter than roles.builder) and re-run\n")
        return 2

    scenarios_dir = os.path.join(control_root, "scenarios")
    existing = (
        [n for n in os.listdir(scenarios_dir) if n.endswith(".json")]
        if os.path.isdir(scenarios_dir) else []
    )
    if existing:
        # Never clobber an already-populated scenarios/ -- whether human- or a
        # prior author-written. Re-authoring is an explicit, destructive act the
        # operator must do by clearing scenarios/ (and restoring the pending
        # marker) themselves; this command only FILLS an empty set.
        sys.stderr.write(
            "dark-factory: author-scenarios: control root already has "
            f"{len(existing)} scenario file(s) -- refusing to overwrite. Clear "
            "scenarios/ (and re-scaffold pending) to re-author.\n")
        return 2

    spec_path = os.path.join(control_root, "spec.md")
    if not os.path.exists(spec_path):
        sys.stderr.write(f"dark-factory: author-scenarios: missing spec: {spec_path}\n")
        return 2
    spec_text = open(spec_path, encoding="utf-8").read()

    try:
        behaviors = df_gates.load_behaviors(control_root)
    except df_gates.GateError as e:
        sys.stderr.write(f"dark-factory: author-scenarios: behaviors.json error: {e}\n")
        return 2
    if not behaviors:
        sys.stderr.write(
            "dark-factory: author-scenarios: behaviors.json declares no behaviors "
            "-- there is nothing for an author to write scenarios for\n")
        return 2

    adapter = author["adapter"]
    timeout_s = author["timeout_s"]
    if attempts < 1:
        attempts = 1

    # M42: the adequacy policy (required classes + min_per_class) the authored
    # set must satisfy, and the decorrelated critic loop toggle. cfg["_adequacy"]
    # is resolved by df_config (agent-authored -> happy+boundary+failure, critic
    # on iff roles.critic set, unless overridden).
    policy = cfg["_adequacy"]
    critic = cfg.get("_critic")
    critic_enabled = policy["critic"]["enabled"] and critic is not None
    max_rounds = policy["critic"]["max_rounds"]
    declared_ids = {b["id"] for b in behaviors}

    journal = Journal(os.path.join(control_root, "authored.jsonl"))

    # M47 condition #7 (review fix): enforce any pinned adapter digest BEFORE the
    # author/critic adapters are ever invoked. The builder-run path enforces this
    # at run start, but author-scenarios is a SEPARATE command that executes the
    # author (and critic) adapters here — an operator who pins
    # roles.author.adapter_sha256 to bind "only these exact bytes may author my
    # hidden scenarios" must be protected AT authoring time, not only at a later
    # `run` (a swap-then-swap-back would otherwise author the barrier scenarios
    # with a substituted model undetected). Fail-closed, exit 2.
    _digest_err = _enforce_adapter_digests(cfg, journal)
    if _digest_err is not None:
        sys.stderr.write(f"dark-factory: author-scenarios: {_digest_err}\n")
        return 2

    critic_round = 0            # completed author<->critic revision cycles
    critic_feedback = None      # blocking findings the author must address
    total_blocking_raised = 0   # cumulative blocking findings across rounds
    last_advisories = []        # advisories from the FINAL critic pass
    validated = None            # (report, normalized) once a set passes the gates

    # Outer loop: one iteration == "obtain a validated set, then (if enabled)
    # critique it". Bounded: the inner author loop is capped at `attempts`
    # invocations; the critic revision count is capped at max_rounds. Every
    # exit is fail-closed (install-and-return, or return 2 with NOTHING
    # installed and the pending marker retained).
    while True:
        # Inner: reach a validated set within `attempts` author invocations.
        # Validation feedback resets each critic round (the previous set was
        # valid -- this round the author is addressing critic blocking, not a
        # validation defect); critic_feedback persists across the inner tries.
        validated = None
        attempt_feedback = None
        for attempt in range(1, attempts + 1):
            status, payload = _author_once(
                adapter, spec_text, behaviors, policy, timeout_s,
                attempt_feedback=attempt_feedback, critic_feedback=critic_feedback)
            if status == "adapter_error":
                # Deterministic transport/env failure -- retrying re-hits the
                # same wall. Fail closed immediately.
                journal.write("AUTHORED_SCENARIOS_ABORTED", adapter=adapter,
                              attempt=attempt, reason="adapter_error",
                              detail=str(payload)[:500])
                sys.stderr.write(
                    f"dark-factory: author-scenarios: author adapter failed on attempt "
                    f"{attempt}: {payload}\n")
                return 2
            if status == "parse_error":
                attempt_feedback = payload
                journal.write("AUTHORED_SCENARIOS_ATTEMPT", adapter=adapter,
                              attempt=attempt, ok=False, reason="parse_error")
                sys.stderr.write(
                    f"dark-factory: author-scenarios: attempt {attempt} produced "
                    f"unusable output\n")
                continue
            if status == "invalid":
                attempt_feedback = payload
                journal.write("AUTHORED_SCENARIOS_ATTEMPT", adapter=adapter,
                              attempt=attempt, ok=False, counts=payload["counts"])
                sys.stderr.write(
                    f"dark-factory: author-scenarios: attempt {attempt} FAILED validation:\n")
                for line in df_author._feedback_lines(payload):
                    sys.stderr.write(f"  - {line}\n")
                continue
            # status == "ok"
            report, normalized = payload
            journal.write("AUTHORED_SCENARIOS_ATTEMPT", adapter=adapter,
                          attempt=attempt, ok=True, counts=report["counts"])
            validated = (report, normalized)
            break

        if validated is None:
            sys.stderr.write(
                f"dark-factory: author-scenarios: exhausted {attempts} attempt(s) without "
                "a valid scenario set -- fail-closed, NO scenarios installed (control root "
                "still pending)\n")
            return 2
        report, normalized = validated

        if not critic_enabled:
            break  # no decorrelated review -> straight to install

        # Decorrelated critic pass on the validated set.
        cstatus, cpayload = _critic_once(
            critic["adapter"], spec_text, behaviors, normalized, policy,
            critic["timeout_s"], declared_ids)
        if cstatus in ("adapter_error", "parse_error"):
            # A critic that can't run or can't emit a valid verdict is a
            # transport/config problem, not something the author can fix. Fail
            # closed (NOTHING installed) rather than silently skipping the
            # decorrelated review the operator asked for.
            journal.write("CRITIC_ABORTED", adapter=critic["adapter"],
                          round=critic_round, reason=cstatus, detail=str(cpayload)[:500])
            sys.stderr.write(
                f"dark-factory: author-scenarios: critic {cstatus} "
                f"({cpayload}) -- fail-closed, NO scenarios installed\n")
            return 2
        blocking, last_advisories = cpayload
        journal.write("CRITIC_ATTEMPT", adapter=critic["adapter"], round=critic_round,
                      blocking=len(blocking), advisories=len(last_advisories))

        if not blocking:
            break  # converged: the second mind found no blocking gap -> install

        total_blocking_raised += len(blocking)
        if critic_round >= max_rounds:
            # The author and critic did not converge within the bound. Fail
            # closed -- a persistently-contested set is NOT sealed.
            journal.write("CRITIC_UNRESOLVED", adapter=critic["adapter"],
                          rounds=critic_round, blocking=len(blocking))
            sys.stderr.write(
                f"dark-factory: author-scenarios: critic still reports {len(blocking)} "
                f"blocking gap(s) after {max_rounds} revision round(s) -- fail-closed, "
                "NO scenarios installed (control root still pending)\n")
            return 2
        critic_round += 1
        critic_feedback = blocking  # next author cycle must address these
        # loop back: re-author addressing the blocking findings.

    # ---- install path (validated, and critic-clean if enabled) ----
    if review and not _author_review_confirm(normalized):
        journal.write("AUTHORED_SCENARIOS_DECLINED", adapter=adapter,
                      counts=report["counts"])
        sys.stderr.write(
            "dark-factory: author-scenarios: review declined -- NO scenarios "
            "installed (control root still pending)\n")
        return 2

    _install_authored_scenarios(control_root, scenarios_dir, normalized)

    if critic_enabled:
        # scenario_review.md is CONTROL-PLANE ONLY (never installed into the
        # builder workspace). It records the blocking loop summary + the
        # advisories -- likely-missing REQUIREMENTS surfaced to the operator,
        # NEVER auto-applied. The journal events are content-free (counts only).
        review_md = df_critic.render_scenario_review(
            last_advisories, rounds=critic_round, blocking_resolved=total_blocking_raised)
        atomic_write(os.path.join(control_root, "scenario_review.md"), review_md)
        journal.write("CRITIC_REVIEW", adapter=critic["adapter"],
                      adapter_sha256=(sha256_file(critic["adapter"])
                                      if os.path.exists(critic["adapter"]) else None),
                      same_model_ack=critic["same_model_ack"],
                      rounds=critic_round, blocking_resolved=total_blocking_raised,
                      advisories=len(last_advisories))
        if last_advisories:
            journal.write("CRITIC_ADVISORY", count=len(last_advisories))

    journal.write("AUTHORED_SCENARIOS", adapter=adapter,
                  adapter_sha256=(sha256_file(adapter)
                                  if os.path.exists(adapter) else None),
                  same_model_ack=author["same_model_ack"],
                  counts=report["counts"])
    print(f"dark-factory: author-scenarios OK -- {report['counts']['scenarios']} "
          f"scenario(s) ({report['counts']['dev']} dev, "
          f"{report['counts']['final']} final) installed into {scenarios_dir}")
    print(f"  authored by (independent model): {adapter}"
          + ("  [same-model ack]" if author["same_model_ack"] else ""))
    if critic_enabled:
        print(f"  reviewed by (decorrelated critic): {critic['adapter']} "
              f"-- {critic_round} revision round(s), {len(last_advisories)} advisory(ies) "
              f"in scenario_review.md")
    print("Review the generated scenarios/*.json, then run:")
    print(f"  python3 {os.path.abspath(__file__)} run --control-root {control_root}")
    return 0


def _empty_author_report() -> dict:
    """A zero-valued validate_authored-shaped report, for the parse-error retry
    path (which has no normalized scenarios to report counts over)."""
    return {
        "schema_errors": [],
        "non_discriminating_titles": [],
        "non_sharp_survivors": {},
        "uncovered_behaviors": [],
        "under_covered_classes": [],
        "orphan_titles": [],
        "spec_leak_values": [],
        "counts": {"scenarios": 0, "dev": 0, "final": 0},
    }


def _install_authored_scenarios(control_root: str, scenarios_dir: str, normalized: list) -> None:
    """Atomically install a VALIDATED author scenario set into `scenarios_dir`
    (same one-file-per-scenario layout df_init.scaffold produces), then clear
    the pending marker LAST. Staging + per-file os.replace + marker-removal-last
    means a crash mid-install never yields a bad PARTIAL set that `run` would
    accept: the pending marker stays until every file has landed, so `run`
    keeps fail-closing until the install fully commits."""
    os.makedirs(scenarios_dir, exist_ok=True)
    staging = tempfile.mkdtemp(prefix=".df-author-stage-", dir=control_root)
    try:
        for sc in normalized:
            staged = os.path.join(staging, f"{sc['id']}.json")
            with open(staged, "w", encoding="utf-8") as f:
                json.dump(sc, f, indent=2)
                f.write("\n")
        for sc in normalized:
            os.replace(os.path.join(staging, f"{sc['id']}.json"),
                       os.path.join(scenarios_dir, f"{sc['id']}.json"))
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    # Commit point: with every scenario file now in place, drop the marker so a
    # subsequent `run` proceeds. Removed last, on purpose (see docstring).
    marker = os.path.join(control_root, df_init.PENDING_MARKER)
    if os.path.exists(marker):
        os.remove(marker)


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
        # M43a: a property scenario whose STEPS include an http action needs
        # loopback for exactly the same reason as a when.http scenario.
        http_scenario_ids = [
            sc["id"] for sc in scenarios
            if "http" in sc["when"]
            or ("property" in sc["when"]
                and any("http" in step for step in sc["when"]["property"]["steps"]))
        ]
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
    manifest_base["snapshot_sha256"] = snap_hash

    try:
        eff_tier, exec_prefix, backend_name, probe_passed = resolve_isolation(
            cfg, control_root, workspace, journal, allow_downgrade)
    except df_sandbox.SandboxError as e:
        sys.stderr.write(f"dark-factory: {e}\n")
        return 2
    manifest_base["qualified"] = eff_tier in _QUALIFYING_TIERS
    manifest_base["sandbox_backend"] = backend_name
    manifest_base["denial_probe_passed"] = probe_passed
    manifest_base["container"] = dict(cfg["_container"]) if eff_tier in _CONTAINER_TIERS else None
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
            char_prefix = df_sandbox.current_backend().wrap_candidate_prefix(
                control_root, workspace, network=cfg["candidate_network"],
                scratch_dirs=(char_tmp,))
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
    # M36a: the resolved intervention mode drives WHICH transitions pause. It's
    # recorded on every terminal manifest (auditability) and journaled at loop
    # entry (fresh run AND every resume, so a paused-then-resumed run's mode is
    # visible in the journal on both segments).
    mode = cfg.get("_intervention_mode", "H2")
    mb_clean["intervention_mode"] = mode
    scenario_set_sha256 = mb_clean.get("scenario_set_sha256")
    journal.write("MODE", mode=mode, source=cfg.get("_intervention_source", "default"),
                  start_iter=start_iter)
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

    def _twin_error_abort(iteration, e):
        journal.write("TWIN_ERROR", iteration=iteration, detail=str(e))
        mf = dict(mb_clean, outcome="ABORTED_BUILD_ERROR", iterations=iteration, qualified=False,
                  final_exam={"ran": False, "passed": None, "count": 0},
                  regressions=sorted(regressed),
                  budget=_budget_manifest_field(cfg["_budget"], builder_calls, estimated_usd),
                  usage=_usage_manifest_field(cfg["_budget"], usage_known,
                                              builder_input_tokens, builder_output_tokens))
        digest = finalize_manifest(run_dir, mf, audit_key=audit_key, redactor=redactor)
        anchor_exit = _anchor_audit(cfg, cfg["_control_root"], run_dir, mf["invocation"],
                                    digest, audit_key, journal)
        _clear_state()
        _kb_writeback(cfg, journal, mf, [])
        sys.stderr.write(f"dark-factory: twin precondition failed at iteration {iteration}: {e}\n")
        return anchor_exit or 2

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
        digest = finalize_manifest(run_dir, mf, audit_key=audit_key, redactor=redactor)
        anchor_exit = _anchor_audit(cfg, cfg["_control_root"], run_dir, mf["invocation"],
                                    digest, audit_key, journal)
        _clear_state()
        _kb_writeback(cfg, journal, mf, [])
        print(f"dark-factory: ARTIFACT UNHASHABLE (artifact rejected, not qualified): "
              f"{detail}. Run: {run_dir}")
        return anchor_exit or 3

    def _scenario_drift_abort(iteration, sealed_hash, live_hash):
        # M45 RA-05 (fresh-run in-process window): the run-start scenario
        # bundle was sealed at run start (manifest_base["scenario_set_sha256"]
        # + the FSM-chain genesis). Resume already refuses a bundle that drifted
        # across a pause; this seals the SAME-PROCESS window the auditor's RA-05
        # names ("acceptance criteria can change during a run") — an operator (or
        # a process) that edits the live scenarios dir between the run-start gate
        # and the sealed final exam must NEVER have the exam grade the artifact
        # against altered criteria. Fail-closed, barrier-safe (only 12-char hash
        # prefixes ever surface — never scenario bytes).
        journal.write("SCENARIO_BUNDLE_DRIFT", iteration=iteration,
                      sealed=sealed_hash[:12], live=live_hash[:12])
        mf = dict(mb_clean, outcome="SCENARIO_BUNDLE_DRIFT", iterations=iteration, qualified=False,
                  final_exam={"ran": False, "passed": None, "count": 0},
                  regressions=sorted(regressed), artifact=None,
                  budget=_budget_manifest_field(cfg["_budget"], builder_calls, estimated_usd),
                  usage=_usage_manifest_field(cfg["_budget"], usage_known,
                                              builder_input_tokens, builder_output_tokens))
        digest = finalize_manifest(run_dir, mf, audit_key=audit_key, redactor=redactor)
        anchor_exit = _anchor_audit(cfg, cfg["_control_root"], run_dir, mf["invocation"],
                                    digest, audit_key, journal)
        _clear_state()
        _kb_writeback(cfg, journal, mf, [])
        sys.stderr.write(
            f"dark-factory: SCENARIO BUNDLE DRIFT — the acceptance scenarios changed "
            f"mid-run (run-start {sealed_hash[:12]} != live {live_hash[:12]}); refusing to "
            f"grade the sealed final exam against altered criteria. Run: {run_dir}\n")
        return anchor_exit or 2

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
                       artifact_object_id=object_id,
                       build_approved_through=build_approved_through, redactor=redactor,
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
                digest = finalize_manifest(run_dir, mf, audit_key=audit_key, redactor=redactor)
                anchor_exit = _anchor_audit(cfg, cfg["_control_root"], run_dir, mf["invocation"],
                                            digest, audit_key, journal)
                _clear_state()
                _kb_writeback(cfg, journal, mf, [])
                sys.stderr.write(
                    "dark-factory: enterprise egress probe FAILED — the transport/lock could "
                    "not be empirically verified this run (fail-closed; the builder was never "
                    f"invoked). detail: {egress_detail}\n")
                return anchor_exit or 2
            journal.write("EGRESS_PROBE_PASSED", policy_digest=policy_digest)

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
                          build_approved_through=build_approved_through, redactor=redactor,
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
                    digest = finalize_manifest(run_dir, mf, audit_key=audit_key, redactor=redactor)
                    anchor_exit = _anchor_audit(cfg, cfg["_control_root"], run_dir, mf["invocation"],
                                                digest, audit_key, journal)
                    _clear_state()
                    _kb_writeback(cfg, journal, mf, [])
                    print(f"dark-factory: BUDGET HALTED (lights-out) — budget cap reached "
                          f"(estimated_usd={estimated_usd}, builder_calls={builder_calls}); "
                          f"a lights-out run fails closed instead of pausing. Run: {run_dir}")
                    return anchor_exit or 3
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
                              build_approved_through=build_approved_through, redactor=redactor,
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
                        c["image"], workspace,
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
                        c["image"], workspace,
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
                          build_approved_through=build_approved_through, redactor=redactor,
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
                        digest = finalize_manifest(run_dir, mf, audit_key=audit_key, redactor=redactor)
                        anchor_exit = _anchor_audit(cfg, cfg["_control_root"], run_dir, mf["invocation"],
                                                    digest, audit_key, journal)
                        _clear_state()
                        _kb_writeback(cfg, journal, mf, [])
                        sys.stderr.write(
                            f"dark-factory: confinement required but unsupported for this "
                            f"builder adapter at iteration {i} — refusing (fail-closed); "
                            f"the builder was never run unconfined\n")
                        return anchor_exit or 2
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
                digest = finalize_manifest(run_dir, mf, audit_key=audit_key, redactor=redactor)
                anchor_exit = _anchor_audit(cfg, cfg["_control_root"], run_dir, mf["invocation"],
                                            digest, audit_key, journal)
                _clear_state()
                _kb_writeback(cfg, journal, mf, [])
                sys.stderr.write(f"dark-factory: build error at iteration {i}\n")
                return anchor_exit or 2
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
            # M29b: pin THIS pass's twin ports into the candidate wrapper
            # (no-op outside default-deny mode).
            pass_candidate_prefix = _candidate_prefix_for_twins(
                cfg, host_isolation, workspace, candidate_prefix, verify_env_extra)

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
                                  extra_scenarios_dir=extra_scenarios_dir)
            except OracleError as e:
                journal.write("ABORTED_BUILD_ERROR", iteration=i, detail=f"invalid scenarios: {e}")
                mf = dict(mb_clean, outcome="ABORTED_BUILD_ERROR", iterations=i, qualified=False,
                          final_exam={"ran": False, "passed": None, "count": 0},
                          regressions=sorted(regressed),
                          budget=_budget_manifest_field(cfg["_budget"], builder_calls, estimated_usd),
                          usage=_usage_manifest_field(cfg["_budget"], usage_known,
                                                      builder_input_tokens, builder_output_tokens))
                digest = finalize_manifest(run_dir, mf, audit_key=audit_key, redactor=redactor)
                anchor_exit = _anchor_audit(cfg, cfg["_control_root"], run_dir, mf["invocation"],
                                            digest, audit_key, journal)
                _clear_state()
                _kb_writeback(cfg, journal, mf, [])
                sys.stderr.write(f"dark-factory: {e}\n")
                return anchor_exit or 2
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
                # M45 RA-05 (fresh-run in-process): the sealed final exam below
                # re-reads the LIVE `scenarios_dir` from the control root. Re-hash
                # it NOW and refuse if it drifted from the run-start seal — closing
                # the same-process edit window (resume already covers the across-
                # pause window). Fail-closed; discards the validation roots first.
                _sealed_bundle = manifest_base.get("scenario_set_sha256")
                _live_bundle = _scenario_set_hash(scenarios_dir)
                if _sealed_bundle is not None and _live_bundle != _sealed_bundle:
                    _discard_validation_root(r_gates)
                    _discard_validation_root(r_exam)
                    return _scenario_drift_abort(i, _sealed_bundle, _live_bundle)

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
                    final_candidate_prefix = _candidate_prefix_for_twins(
                        cfg, host_isolation, r_exam, candidate_prefix, final_env_extra)
                    final = run_all(scenarios_dir, r_exam, exec_wrapper=final_candidate_prefix,
                                     env_extra=final_env_extra, cohort="final",
                                     observer_files=ts.observer_files if ts else None)
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
                        digest = finalize_manifest(run_dir, mf, audit_key=audit_key, redactor=redactor)
                        anchor_exit = _anchor_audit(cfg, cfg["_control_root"], run_dir, mf["invocation"],
                                                    digest, audit_key, journal)
                        _clear_state()
                        _kb_writeback(cfg, journal, mf, [])
                        print(f"dark-factory: FINAL-EXAM FAILED (artifact rejected; held-out "
                              f"scenarios not disclosed). Run: {run_dir}")
                        return anchor_exit or 3

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
                          build_approved_through=build_approved_through, redactor=redactor,
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
        digest = finalize_manifest(run_dir, mf, audit_key=audit_key, redactor=redactor)
        anchor_exit = _anchor_audit(cfg, cfg["_control_root"], run_dir, mf["invocation"],
                                    digest, audit_key, journal)
        _clear_state()
        _kb_writeback(cfg, journal, mf, failing)
        print(f"dark-factory: CAP REACHED after {cfg['max_iterations']} iterations. "
              f"Still failing: {', '.join(failing)}. Run: {run_dir}")
        return anchor_exit or 3
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
        try:
            eff_tier, exec_prefix, backend_name, probe_passed = resolve_isolation(
                cfg, control_root, state["workspace"], journal, allow_downgrade)
        except df_sandbox.SandboxError as e:
            sys.stderr.write(f"dark-factory: {e}\n")
            return 2
        manifest_base["qualified"] = eff_tier in _QUALIFYING_TIERS
        manifest_base["sandbox_backend"] = backend_name
        manifest_base["denial_probe_passed"] = probe_passed
        manifest_base["container"] = dict(cfg["_container"]) if eff_tier in _CONTAINER_TIERS else None
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
    out = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def _unresolved_ship_action(run_dir):
    """The M35 reserve-before check, for ship actions. Returns the data dict of
    the LATEST SHIP_ACTION_INTENT that has NO matching SHIP_ACTION_RESULT (same
    idempotency_key) — meaning a prior process crashed after journaling+fsyncing
    the intent but before the action's outcome resolved (its real-world effect
    is UNKNOWN) — else None. Never a blind re-run of a deploy."""
    latest_intent = None
    resolved = set()
    for e in _ship_journal_events(run_dir):
        data = e.get("data", {})
        state = e.get("state")
        if state == "SHIP_ACTION_INTENT":
            latest_intent = data
        elif state == "SHIP_ACTION_RESULT":
            resolved.add(data.get("idempotency_key"))
    if latest_intent is not None and latest_intent.get("idempotency_key") not in resolved:
        return latest_intent
    return None


def _ship_completed_actions(run_dir):
    """Names of actions with a recorded SHIP_ACTION_RESULT status 'ok' (a prior
    ship attempt succeeded on them) — recovered so a re-ship SKIPS them, never
    re-runs a succeeded action."""
    done = set()
    for e in _ship_journal_events(run_dir):
        if e.get("state") == "SHIP_ACTION_RESULT" and e.get("data", {}).get("status") == "ok":
            done.add(e["data"].get("action"))
    done.discard(None)
    return done


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
    return att


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
    manifest_bytes, manifest_sha = _read_manifest_bytes(run_dir)
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
    tier = manifest_obj.get("tier")
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


def _anchor_ship_record(cfg, control_root, run_dir, run_id, record_text, kind,
                        push_offbox=True):
    """Anchor a ship-phase record (the ship record, a per-action completion token,
    or the release attestation) into the tamper-evident per-control-root hash chain,
    and push it off-box if a REQUIRED/optional audit sink is configured — mirroring
    attach_custody. `kind` is 'ship' / 'ship-action' / 'release'; the chain key is
    uniquified so repeated ship attempts (pending → attach → ship, plus the M49
    audit-only retry) each anchor without colliding. Best-effort on the audit key
    and the local chain append (ship actions may have ALREADY run — never crash
    after the fact); a required off-box sink failure is SURFACED (M49 DF-R3-02)
    instead of swallowed, so `_seal_ship_result` can seal SHIPPED_AUDIT_PENDING.

    Returns a status string (M49 DF-R3-02):
      "skip"           no sink configured / push suppressed — nothing pushed
      "ok"             pushed; a receipt BOUND to record_text (body_sha256) was
                       written to <run_dir>/<kind>_sink_receipt.json
      "optional_fail"  push failed, sink NOT required — proceed, warn
      "required_fail"  push failed AND the sink is required — the caller must NOT
                       report a clean ship (a production action's mandated off-box
                       evidence never left the box)

    `push_offbox=False` (M44 RA-02 / M49 per-action commit): the caller either
    ALREADY performed the required off-box push fail-closed (attach_release) or is
    anchoring a per-action completion token into the local signed chain only, so
    this anchors the local chain and does NOT push (a second push to the same
    append-only key would 409); it returns "skip"."""
    signing = bool(cfg.get("_audit", {}).get("signing"))
    audit_key = None
    if signing:
        try:
            audit_key = df_audit.load_or_create_key(cfg["_audit"]["key_path"])
        except df_audit.AuditKeyError as e:
            sys.stderr.write(f"dark-factory: WARNING — could not load audit key to anchor the "
                             f"{kind} record ({e}); the local sidecar stands unanchored.\n")
    chain_path = os.path.join(control_root, "audit-chain.jsonl")
    chain_key = f"{run_id}.{kind}.{uuid.uuid4().hex[:8]}"
    # CRITICAL (M49 re-audit fix): NEVER append an UNSIGNED entry to a SIGNED
    # chain. If signing is on but the key could not be loaded, appending with
    # audit_key=None would make verify_chain fail the ENTIRE control-root chain
    # (breaking custody/qualification verify too), not just this record. Skip the
    # local anchor and surface the failure honestly — a signed run whose key is
    # gone fails re-entry authentication anyway (fail-closed).
    if not (signing and audit_key is None):
        try:
            df_audit_chain.append_entry(chain_path, chain_key, sha256_str(record_text), _now(),
                                        audit_key)
        except (df_audit_chain.ChainError, OSError) as e:
            sys.stderr.write(f"dark-factory: WARNING — could not anchor the {kind} record into "
                             f"the audit chain ({e}).\n")
    if not push_offbox:
        return "skip"
    sink = cfg.get("_audit", {}).get("sink", {"kind": "none", "required": False})
    if sink.get("kind", "none") == "none":
        return "skip"
    try:
        receipt = df_audit_sink.push(sink, chain_key, record_text.encode("utf-8"))
    except df_audit_sink.SinkError as e:
        if sink.get("required"):
            sys.stderr.write(f"dark-factory: WARNING — the REQUIRED audit sink push of the "
                             f"{kind} record FAILED ({e}); record it off-box manually.\n")
            return "required_fail"
        sys.stderr.write(f"dark-factory: audit sink push warning ({kind}, not required): {e}\n")
        return "optional_fail"
    # Bind the persisted receipt to the EXACT record bytes that were pushed (M44
    # _sink_receipt_bound checks body_sha256), so the ship-verify path can prove
    # the receipt is for THIS sealed ship record, not a stale one.
    receipt = dict(receipt, body_sha256=sha256_str(record_text), sink_key=chain_key)
    atomic_write(os.path.join(run_dir, f"{kind}_sink_receipt.json"), canonical_json(receipt))
    return "ok"


def _ship_toolchain_identity(actions):
    """M49 DF-R3-06: record WHAT ran per action for the audit trail — the resolved
    executable identity of each action's `run[0]`. Best-effort and HONEST: a
    PATH-resolved (or absolute) regular readable file gets a sha256; anything not
    resolvable/hashable is recorded as such (never a false claim). This does NOT
    make the external tool immutable — it stays operator-controlled; this records
    its identity at ship time, nothing more (see references/ship.md)."""
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


def _ship_action_commit_payload(run_id, action, idk):
    """The canonical bytes whose sha256 is a completed ship action's chain-anchored
    completion token (M49 DF-R3-03). Binds the run, the action name, and its
    idempotency_key, so the token is reconstructible from the journal's
    SHIP_ACTION_RESULT `ok` event on re-entry yet unforgeable without the audit
    key (the signature over the chain entry is the real gate)."""
    return canonical_json({"kind": "ship-action-ok", "run_id": run_id,
                           "action": action, "idempotency_key": idk})


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
    anchor-less. A per-action signed entry makes the two distinguishable."""
    def _commit(action_name, idk):
        payload = _ship_action_commit_payload(run_id, action_name, idk)
        _anchor_ship_record(cfg, control_root, run_dir, run_id, payload, "ship-action",
                            push_offbox=False)
    return _commit


def _ship_completed_action_facts(run_dir):
    """(action, idempotency_key) for every SHIP_ACTION_RESULT with status 'ok'
    recovered from the ship journal — the exact set `already_done` skips, paired
    with the idempotency_key each completion token binds (M49 DF-R3-03)."""
    facts = []
    for e in _ship_journal_events(run_dir):
        d = e.get("data", {})
        if e.get("state") == "SHIP_ACTION_RESULT" and d.get("status") == "ok":
            if d.get("action") is not None:
                facts.append((d.get("action"), d.get("idempotency_key")))
    return facts


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


def _authenticate_ship_actions(cfg, control_root, run_dir, run_id):
    """M49 DF-R3-03: before SKIPPING real actions on the strength of the ship
    journal's recovered `already_done`, authenticate each completed action against
    its own per-action signed chain entry (see _make_ship_action_committer).

    A legitimate crash-before-seal recovery authenticates (every completed action
    was anchored as it committed, before its RESULT was journaled); a planted or
    edited SHIP_ACTION_RESULT `ok` line for an action that never ran has no
    matching signed token → REFUSED. Fail-closed on any key/chain error. Returns
    (ok, reason)."""
    facts = _ship_completed_action_facts(run_dir)
    if not facts:
        return (True, "no completed ship actions to authenticate")
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
    prefix = f"{run_id}.ship-action."
    anchored = {e.get("manifest_sha256") for e in entries
                if str(e.get("invocation", "")).startswith(prefix)}
    for action, idk in facts:
        token = sha256_str(_ship_action_commit_payload(run_id, action, idk))
        if token not in anchored:
            return (False, f"completed ship action {action!r} is not individually anchored in "
                    "the signed audit chain (a planted or edited SHIP_ACTION_RESULT `ok`)")
    return (True, "all completed ship actions authenticated against the signed audit chain")


def _seal_ship_result(cfg, control_root, run_dir, run_id, ship_journal, result,
                      artifact_object_id, redactor, *, ship_actions=None,
                      push_offbox=True):
    """Write the SEPARATE, immutable ship record (ship_result.json), journal the
    terminal ship event, anchor the record into the signed chain, and push it
    off-box. NEVER rewrites the manifest (qualified stays qualified). Returns
    `(record, anchor_status)` — the M49 DF-R3-02 off-box status so the caller can
    escalate a SHIPPED result to SHIPPED_AUDIT_PENDING when a REQUIRED sink push
    failed. `push_offbox=False` anchors + writes locally without re-pushing (used
    by the SHIPPED_AUDIT_PENDING re-seal, whose push already failed).

    (The journal that feeds `already_done` is authenticated per-action, not by a
    seal-time journal digest — see _make_ship_action_committer.)"""
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
    if ship_actions is not None:
        record["toolchain"] = _ship_toolchain_identity(ship_actions)
    text = _redacted_write(os.path.join(run_dir, SHIP_RESULT_FILE), record, redactor)
    ship_journal.write(result["outcome"],
                       actions=[a.get("name") for a in result.get("actions", [])],
                       rollback_failed=bool(result.get("rollback_failed")),
                       pending_action=result.get("pending_action"),
                       failed_action=result.get("failed_action"))
    anchor_status = _anchor_ship_record(cfg, control_root, run_dir, run_id, text, "ship",
                                        push_offbox=push_offbox)
    return record, anchor_status


def _ship_audit_retry(cfg, control_root, run_dir, run_id, ship_journal, prior_text,
                      redactor):
    """M49 DF-R3-02 idempotent audit-only retry. The prior seal is
    SHIPPED_AUDIT_PENDING (the real-world actions ALREADY ran) but the REQUIRED
    off-box audit sink push failed. Re-run ONLY the off-box anchoring for the
    EXISTING sealed record — NEVER the actions. On success flip the sealed record
    to SHIPPED (exit 0); still failing → stay SHIPPED_AUDIT_PENDING (exit 12).

    Push-FIRST (not write-first): the SHIPPED bytes are pushed off-box before the
    on-disk record is flipped, so a still-failing sink never leaves a SHIPPED
    record without its bound receipt."""
    try:
        prior = json.loads(prior_text)
    except json.JSONDecodeError as e:
        sys.stderr.write(f"dark-factory: ship refused — prior ship record is unreadable ({e}).\n")
        return 2
    shipped = dict(prior)
    shipped["outcome"] = df_ship.SHIPPED
    shipped["ts"] = _now()
    shipped_obj = redactor.redact_obj(shipped) if redactor is not None else shipped
    shipped_text = canonical_json(shipped_obj)
    # Push the EXISTING sealed record off-box (+ chain-anchor + bound receipt).
    status = _anchor_ship_record(cfg, control_root, run_dir, run_id, shipped_text, "ship")
    if status == "required_fail":
        ship_journal.write("SHIP_AUDIT_RETRY_PENDING",
                           note="required off-box audit sink still unreachable")
        sys.stderr.write(
            "dark-factory: SHIP still AUDIT-PENDING — the REQUIRED off-box audit sink is still "
            "unreachable. The actions remain DONE and are NOT re-run; retry `ship` once the sink "
            "is reachable.\n")
        return SHIP_AUDIT_PENDING
    # Off-box attested now → flip the sealed record to SHIPPED (never re-run actions).
    atomic_write(os.path.join(run_dir, SHIP_RESULT_FILE), shipped_text)
    ship_journal.write(df_ship.SHIPPED, note="audit-only retry: off-box evidence anchored")
    print("dark-factory: SHIPPED — off-box audit evidence anchored on retry (the actions were "
          "already done; not re-run).")
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
        # DF-R3-03: NEVER trust a planted/altered terminal ship_result on re-entry.
        # When signing is on, the sealed result MUST be anchored in the signed
        # chain (a control-root-write attacker who plants a SHIPPED result — to
        # suppress a real ship — cannot forge a signature-valid chain entry).
        if signing_on:
            ok_a, why_a = _authenticate_ship_chain(
                cfg, control_root, run_id, sha256_str(prior_text), "ship")
            if not ok_a:
                sys.stderr.write(f"dark-factory: ship refused (fail-closed) — the prior ship "
                                 f"result could not be authenticated: {why_a}\n")
                return SHIP_STATE_UNAUTHENTICATED
        if prior_outcome == df_ship.SHIP_FAILED:
            print(f"dark-factory: ship already terminal (SHIP_FAILED); see {result_path}. "
                  "Not re-shipping.")
            return 3
        # SHIPPED / SHIPPED_AUDIT_PENDING: fully attested only if the REQUIRED
        # off-box evidence is present + bound (DF-R3-02). SHIPPED_AUDIT_PENDING is
        # by definition not-yet-attested; a SHIPPED whose required receipt is
        # absent/unbound is treated the same (fail-closed — never a silent
        # fully-shipped) and triggers the idempotent audit-only retry.
        needs_audit_retry = (prior_outcome == df_ship.SHIPPED_AUDIT_PENDING)
        if prior_outcome == df_ship.SHIPPED and _sink_required(cfg):
            ok_r, _why_r = _sink_receipt_bound(run_dir, "ship_sink_receipt.json", prior_text)
            if not ok_r:
                needs_audit_retry = True
        if not needs_audit_retry:
            print(f"dark-factory: ship already terminal (SHIPPED); see {result_path}. "
                  "Not re-shipping.")
            return 0
        # DF-R3-02 idempotent audit-only retry: re-anchor the off-box evidence for
        # the EXISTING sealed record; the actions are DONE and are NEVER re-run.
        return _ship_audit_retry(cfg, control_root, run_dir, run_id, ship_journal,
                                 prior_text, redactor)

    # Crash-safety (invariant #4): an INTENT with no RESULT is UNKNOWN. Refuse
    # (exit 11) under plain `continue`; `reconcile` consents to a possible
    # duplicate; `abort` seals SHIP_FAILED.
    unresolved = _unresolved_ship_action(run_dir)
    if unresolved is not None:
        if decision == "continue":
            ship_journal.write("SHIP_UNKNOWN_OUTCOME", action=unresolved.get("action"),
                               idempotency_key=unresolved.get("idempotency_key"))
            sys.stderr.write(
                f"dark-factory: ship action {unresolved.get('action')!r} was reserved but did "
                "not resolve before a crash — its real-world effect is UNKNOWN. Refusing to "
                "re-run a possibly-applied action. Inspect the target, then `ship --decision "
                "reconcile` (re-runs, accepting a possible duplicate) or `--decision abort` "
                "(seals SHIP_FAILED).\n")
            return UNKNOWN_OUTCOME
        if decision == "abort":
            ship_journal.write("SHIP_RECONCILE_ABORT", action=unresolved.get("action"))
            result = {"outcome": df_ship.SHIP_FAILED, "actions": [], "pending_action": None,
                      "failed_action": unresolved.get("action"), "rollbacks": [],
                      "rollback_failed": False}
            _seal_ship_result(cfg, control_root, run_dir, run_id, ship_journal, result,
                              artifact_object_id, redactor, ship_actions=ship_cfg["actions"])
            print("dark-factory: SHIP ABORTED at an unresolved action (sealed SHIP_FAILED).")
            return 3
        # reconcile: clear the dangling intent by recording an explicit unknown
        # RESULT (so the re-scan is satisfied and the action re-runs — it is NOT
        # in `already_done`), operator consenting to a possible duplicate.
        ship_journal.write("SHIP_ACTION_RESULT", action=unresolved.get("action"),
                           idempotency_key=unresolved.get("idempotency_key"),
                           status="reconciled_unknown", exit=None, timed_out=False)
        ship_journal.write("SHIP_RECONCILED", action=unresolved.get("action"),
                           note="operator accepted possible duplicate; re-running")
        print(f"dark-factory: reconciling unresolved ship action "
              f"{unresolved.get('action')!r} — re-running (possible duplicate).")

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
    if signing_on and already_done:
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
            _seal_ship_result(cfg, control_root, run_dir, run_id, ship_journal, result,
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

        record, anchor_status = _seal_ship_result(
            cfg, control_root, run_dir, run_id, ship_journal, result,
            artifact_object_id, redactor, ship_actions=ship_cfg["actions"])

        if result["outcome"] == df_ship.SHIPPED and anchor_status == "required_fail":
            # DF-R3-02: the real-world actions RAN, but the REQUIRED off-box audit
            # sink push FAILED — the mandated evidence is missing. Seal a DISTINCT
            # outcome (never re-run the actions) + a distinct exit so automation
            # does NOT read exit 0. Re-`ship` runs the idempotent audit-only retry.
            pending = dict(result, outcome=df_ship.SHIPPED_AUDIT_PENDING)
            _seal_ship_result(cfg, control_root, run_dir, run_id, ship_journal, pending,
                              artifact_object_id, redactor, ship_actions=ship_cfg["actions"],
                              push_offbox=False)
            sys.stderr.write(
                f"dark-factory: SHIPPED_AUDIT_PENDING — {len(result['actions'])} action(s) ran "
                f"on the sealed artifact {artifact_object_id[:16]}…, but the REQUIRED off-box "
                f"audit sink push FAILED, so the mandated off-box evidence is not yet anchored. "
                f"The actions are DONE and are NEVER re-run. Re-run `ship` once the sink is "
                f"reachable to anchor the evidence and finalize SHIPPED. Record: {result_path}\n")
            return SHIP_AUDIT_PENDING
        if result["outcome"] == df_ship.SHIPPED:
            print(f"dark-factory: SHIPPED — {len(result['actions'])} action(s) ran on the sealed "
                  f"artifact {artifact_object_id[:16]}…. Record: {result_path}")
            return 0
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
        cfg = load_config(control_root)
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
        cfg = load_config(control_root)
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
    _rtier = manifest_obj.get("tier")
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
        satisfied, reason, count, nonce = df_release.verify_release(
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

        df_release.record_nonce(control_root, nonce, run_id=run_id,
                                artifact_object_id=object_id, applied_at=_now())
        atomic_write(os.path.join(run_dir, RELEASE_ATTESTATION_FILE), att_text)
        # Anchor into the tamper-evident chain; the off-box push (if any) already
        # happened above, so do NOT push again (append-only key would 409).
        _anchor_ship_record(cfg, control_root, run_dir, run_id, att_text, "release",
                            push_offbox=False)
        if receipt is not None:
            atomic_write(os.path.join(run_dir, "release_sink_receipt.json"),
                         canonical_json(receipt))
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
    p_ship.add_argument("--decision", choices=["continue", "reconcile", "abort"],
                        default="continue",
                        help="continue (default) · reconcile (accept a possible duplicate after "
                             "SHIP_UNKNOWN_OUTCOME) · abort (seal SHIP_FAILED at an unresolved action)")

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
