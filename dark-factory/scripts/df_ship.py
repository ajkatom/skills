"""M41: the governed SHIP-ACTION RUNNER. Pure orchestration — it executes
operator-supplied argv (git/kubectl/deploy scripts) as an ordered, audited,
gated, crash-safe, rollback-capable phase. It is a governed RUNNER, not a
deploy engine: all crypto/gate logic lives in df_release; all qualification /
materialization / sealing wiring lives in supervisor. This module is the
subprocess loop with the hard safety behaviors:

  - order: actions run in configured order; an already-succeeded action (from a
    prior ship attempt, recovered by the caller into `already_done`) is skipped,
    never re-run.
  - the reversibility gate: a `reversible:false` action runs ONLY if
    `approval_ctx.covers(name)` returns True (a valid, live, in-scope release
    approval — df_release). Absent/invalid ⇒ STOP with SHIP_APPROVAL_PENDING;
    never run, never block. This holds in every mode incl. H4.
  - crash-safety (reserve-before): the caller's `journal.write` for
    SHIP_ACTION_INTENT fsyncs BEFORE the subprocess is spawned; SHIP_ACTION_RESULT
    is journaled after. On resume the caller detects an INTENT with no RESULT and
    refuses (SHIP_UNKNOWN_OUTCOME) rather than blindly re-running a deploy.
  - rollback: on a nonzero exit or a timeout, the failed action's OWN rollback
    (if any) runs first, then each already-succeeded prior action's rollback in
    REVERSE order; a rollback that itself fails is journaled SHIP_ROLLBACK_FAILED
    and surfaced loudly (`rollback_failed=True` on the result), never swallowed.
  - secrets: brokered credential VALUES (resolved per-action, host-side, by the
    caller's `resolve_action_creds`) reach ONLY the child subprocess env; captured
    stdout/stderr are routed through a per-action Redactor before hitting disk, so
    a value never enters a captured log (and the caller never journals values).

HONEST SCOPE (documented, not hidden): ship actions legitimately need real
network + credentials — that is the point — so they are NOT network-sandboxed.
The protection is the qualification precondition + the signature gate + the
audit trail, NOT confinement. A ship action runs as a normal host subprocess.
See references/ship.md.
"""
import os
import shutil
import subprocess
import time

import df_common
import df_creds
import df_seal


class ShipError(RuntimeError):
    pass


def toolchain_identity(action_name, argv0, cwd, child_env=None):
    """DF-R4-08: resolve + hash an executable's identity as it is ABOUT to run.

    Records WHAT is spawning, resolved EXACTLY as the OS will resolve argv[0] for
    a child launched with cwd=`cwd`:
      - a name WITH a path separator is relative to the ACTION's cwd (the ship
        workspace), NOT the supervisor cwd — matching execve semantics;
      - a bare command is looked up on PATH (the child inherits it) with every
        relative/empty PATH entry resolved against the ACTION cwd, exactly as
        the child's post-chdir execvpe will (DF-R5-10).
    The sha256 is the PRE-exec bytes, so a self-modifying deploy tool that rewrites
    its own bytes AFTER running cannot make the manifest record the post-run image.
    HONEST: a non-resolvable / non-regular / unreadable target is recorded with a
    `note` and a null sha256, never a false claim. This does NOT make the external
    tool immutable — it records its identity at spawn time, nothing more (the tool
    stays operator-controlled; see references/ship.md)."""
    entry = {"action": action_name, "argv0": argv0,
             "resolved_path": None, "sha256": None, "note": None}
    if not argv0:
        entry["note"] = "action has no run argv"
        return entry
    has_sep = (os.sep in argv0) or (os.altsep is not None and os.altsep in argv0)
    if os.path.isabs(argv0):
        resolved = os.path.realpath(argv0) if os.path.exists(argv0) else None
        miss = "absolute argv0 does not exist (operator-controlled)"
    elif has_sep:
        # A relative path WITH a separator: the OS resolves it against the child's
        # cwd (the action ship workspace), so resolve it the same way here — NOT
        # against the supervisor cwd (the pre-M55 bug).
        candidate = os.path.realpath(os.path.join(cwd, argv0))
        resolved = candidate if os.path.exists(candidate) else None
        miss = "relative argv0 not found under the action cwd (operator-controlled)"
    else:
        # A bare command: the child searches PATH (inherited) — but only AFTER
        # chdir to the action cwd (subprocess chdirs in the child before exec),
        # so a RELATIVE or empty PATH entry resolves against the ACTION cwd,
        # not the supervisor cwd (DF-R5-10: with PATH="." the child finds a
        # tool in the action directory that a supervisor-cwd which() missed —
        # the evidence recorded a null hash for a command that actually ran).
        # Mirror execvpe-after-chdir exactly: absolutize every non-absolute
        # PATH entry against the action cwd before the lookup — using the
        # CHILD's env when given (a resolved credential could shadow PATH;
        # the child would search THAT one, so the evidence must too).
        env_for_path = child_env if child_env is not None else os.environ
        path_env = env_for_path.get("PATH", os.defpath)
        abs_path = os.pathsep.join(
            entry if os.path.isabs(entry)
            else os.path.normpath(os.path.join(cwd, entry or "."))
            for entry in path_env.split(os.pathsep))
        which_hit = shutil.which(argv0, path=abs_path)
        resolved = os.path.realpath(which_hit) if which_hit else None
        miss = "argv0 not resolvable to a file on PATH (operator-controlled)"
    if resolved is None:
        entry["note"] = miss
        return entry
    entry["resolved_path"] = resolved
    try:
        if os.path.isfile(resolved) and os.access(resolved, os.R_OK):
            entry["sha256"] = df_common.sha256_file(resolved)
        else:
            entry["note"] = "resolved path is not a regular readable file"
    except OSError as e:
        entry["note"] = f"unhashable ({e})"
    return entry


# Terminal ship outcomes (also the sealed ship-record `outcome` values).
SHIPPED = "SHIPPED"
SHIP_FAILED = "SHIP_FAILED"
SHIP_APPROVAL_PENDING = "SHIP_APPROVAL_PENDING"
# M49 DF-R3-02: the real-world actions DID run (SHIPPED), but a REQUIRED off-box
# audit sink push FAILED, so the mandated off-box evidence is not yet anchored.
# A DISTINCT sealed outcome (never SHIPPED) so automation cannot read exit 0 with
# the required attestation missing. The actions are done and are NEVER re-run;
# an idempotent audit-only retry re-anchors off-box and flips this to SHIPPED.
SHIPPED_AUDIT_PENDING = "SHIPPED_AUDIT_PENDING"
# R5 DF-R5-02: a real action ran successfully, but its per-action completion
# token could not be signed/anchored into the local chain (a transient audit-key
# failure). A DISTINCT, RECOVERABLE sealed outcome: the loop stops (no further
# actions run), and an authenticated evidence-only retry re-anchors the completed
# actions' tokens and continues — never a silent journal `ok` with no signed
# token (which would make re-entry authentication refuse and BRICK recovery).
SHIP_EVIDENCE_PENDING = "SHIP_EVIDENCE_PENDING"


def idempotency_key(run_id, action_name, index):
    """Deterministic per-(run, action, position) key. Stable across a crash +
    resume so the caller's INTENT/RESULT matching works by exact equality."""
    from df_common import sha256_str
    return sha256_str(f"ship:{run_id}:{index}:{action_name}")


def materialize_ship_workspace(object_store, artifact_object_id, dest_dir):
    """Materialize the SEALED artifact object into `dest_dir` as the action cwd.

    Fail-closed: `df_seal.materialize_object` re-verifies the object against its
    own sidecar FIRST and refuses on any drift (never ship a drifted/tampered/
    absent artifact), and refuses a non-empty `dest_dir` (a fresh workspace,
    never a drifted post-build one). Returns `dest_dir`. Translates SealError to
    ShipError so the ship phase has one error type."""
    try:
        df_seal.materialize_object(object_store, artifact_object_id, dest_dir)
    except df_seal.SealError as e:
        raise ShipError(
            f"cannot materialize the sealed artifact {artifact_object_id} for shipping "
            f"(fail-closed): {e}") from e
    return dest_dir


def _resolve_cwd(ship_ws, rel_cwd):
    """Resolve an action's optional relative cwd inside the ship workspace,
    re-checking containment (belt-and-suspenders; df_config already rejected
    abs/`..`/`~`). Any escape is a ShipError, never a silent run outside the
    materialized artifact."""
    if not rel_cwd:
        return ship_ws
    ws_abs = os.path.realpath(ship_ws)
    target = os.path.realpath(os.path.join(ws_abs, rel_cwd))
    if target != ws_abs and not target.startswith(ws_abs + os.sep):
        raise ShipError(
            f"action cwd {rel_cwd!r} escapes the ship workspace (refused, fail-closed)")
    if not os.path.isdir(target):
        raise ShipError(f"action cwd {rel_cwd!r} is not a directory in the ship workspace")
    return target


def _run_one(argv, *, cwd, child_env, timeout_s):
    """Run one argv, capturing stdout/stderr. Returns
    (exit_code, timed_out, stdout, stderr). exit_code is None on timeout. A
    launch failure (OSError, e.g. ENOENT on the argv[0]) surfaces as exit code
    127 with the error text on stderr — a fail-closed nonzero, never a crash."""
    started = time.monotonic()
    try:
        proc = subprocess.run(
            list(argv), cwd=cwd, env=child_env, capture_output=True, text=True,
            timeout=timeout_s)
        return proc.returncode, False, (proc.stdout or ""), (proc.stderr or ""), \
            time.monotonic() - started
    except subprocess.TimeoutExpired as e:
        out = e.stdout or ""
        err = e.stderr or ""
        if isinstance(out, bytes):
            out = out.decode("utf-8", "replace")
        if isinstance(err, bytes):
            err = err.decode("utf-8", "replace")
        return None, True, out, err, time.monotonic() - started
    except OSError as e:
        # ENOENT / EACCES launching the argv: a nonzero fail-closed result, not
        # an escaped exception (the ship loop must roll back + seal SHIP_FAILED).
        return 127, False, "", f"failed to launch {argv[0]!r}: {e}", time.monotonic() - started


def _write_logs(log_dir, action_name, suffix, stdout, stderr, redactor):
    """Write REDACTED stdout/stderr for one (roll)action to run_dir. The redactor
    is built from the run's + this action's resolved secret values, so a brokered
    credential value is scrubbed before the bytes touch disk (invariant #6)."""
    if log_dir is None:
        return
    os.makedirs(log_dir, exist_ok=True)
    for stream, text in (("stdout", stdout), ("stderr", stderr)):
        red = redactor.redact(text) if redactor is not None else text
        path = os.path.join(log_dir, f"{action_name}{suffix}.{stream}")
        with open(path, "w", encoding="utf-8") as f:
            f.write(red)


def _child_env(base_env, cred_values):
    """The child subprocess env: the host base env plus this action's resolved
    credential VALUES. The values live ONLY here (never in config/journal/
    manifest/log). base_env is the caller's os.environ snapshot so the action's
    argv resolves normally (PATH/HOME/git config)."""
    env = dict(base_env or {})
    env.update(cred_values or {})
    return env


def run_actions(actions, ship_ws, *, approval_ctx, journal, run_id,
                base_env, base_secret_values, resolve_action_creds,
                already_done=None, log_dir=None, now_fn=None, commit_action=None):
    """Run the ship actions in order. Returns a ShipResult dict:

        {"outcome": SHIPPED|SHIP_FAILED|SHIP_APPROVAL_PENDING,
         "actions": [{"name","reversible","status","exit","approval_ref",
                      "duration_s"} ...],
         "pending_action": <name|None>,   # SHIP_APPROVAL_PENDING
         "failed_action":  <name|None>,   # SHIP_FAILED
         "rollbacks": [{"name","status","exit"} ...],
         "rollback_failed": bool,
         "ship_workspace_object_id": <set by caller>}

    Contract with the caller (supervisor):
      - `approval_ctx.covers(name, now=...)` is the ONLY authority for an
        irreversible action; this loop never inspects signatures itself.
      - `journal.write(state, **data)` fsyncs — so a SHIP_ACTION_INTENT write is
        the durable "reserved before spawn" record (invariant #4).
      - `resolve_action_creds(action) -> {NAME: value}` resolves ONE action's
        creds host-side at action time, fail-closed (raises on missing/empty). A
        resolution failure is treated as an action FAILURE (rollback + SHIP_FAILED),
        never a silent skip.
      - `already_done` names actions a prior attempt completed OK (recovered from
        the ship journal) — skipped here, but still placed on the rollback stack
        (an already-succeeded prior action is rolled back in reverse on a later
        failure, invariant #5).
      - `commit_action(action_name, idempotency_key)` (M49 DF-R3-03), if given, is
        called for each SUCCEEDED action BEFORE its SHIP_ACTION_RESULT is journaled,
        so the caller can anchor that action's completion into the signed audit
        chain. Ordering is deliberate: anchor-before-journal guarantees every
        `already_done` entry recovered on re-entry is individually chain-backed
        (a crash between anchor and the RESULT write leaves an unresolved INTENT —
        handled by the exit-11 reconcile path — never an un-anchored `already_done`
        entry). It is best-effort (must not raise); a real-world action has run.
    """
    now_fn = now_fn or _utcnow
    already = set(already_done or ())
    records = []
    # DF-R4-08: the per-action executable identity, resolved + hashed BEFORE each
    # spawn (never re-resolved after the fact at seal time). One entry per action
    # actually reached this attempt, in order; the caller seals this list as the
    # ship record's `toolchain`.
    toolchain = []
    # Actions that have SUCCEEDED (this attempt or a prior one) AND define a
    # rollback — the reverse-order rollback stack for invariant #5.
    rollback_stack = []

    for index, action in enumerate(actions):
        name = action["name"]
        reversible = action["reversible"]
        argv0 = (action.get("run") or [None])[0]

        if name in already:
            records.append({"name": name, "reversible": reversible,
                            "status": "already_done", "exit": 0, "approval_ref": None,
                            "duration_s": None})
            # HONEST: this action ran in a PRIOR attempt; its PRE-exec bytes are
            # not re-derivable now, so record the identity slot with a note rather
            # than a misleading post-hoc re-resolution.
            toolchain.append({"action": name, "argv0": argv0, "resolved_path": None,
                              "sha256": None,
                              "note": "action completed in a prior attempt; "
                                      "toolchain not re-resolved this attempt"})
            if action.get("rollback"):
                rollback_stack.append(action)
            continue

        # The reversibility gate (invariant #3): an irreversible action runs
        # ONLY under a valid, live, in-scope release approval. Absent/invalid ⇒
        # SHIP_APPROVAL_PENDING — STOP, never run, never block. Reversible
        # actions already run needn't be rolled back (they stay applied; the
        # operator attaches an approval and re-runs `ship`).
        approval_ref = None
        if not reversible:
            covered, why = approval_ctx.covers(name, now=now_fn())
            if not covered:
                journal.write("SHIP_APPROVAL_PENDING", action=name, index=index, reason=why)
                records.append({"name": name, "reversible": False,
                                "status": "approval_pending", "exit": None,
                                "approval_ref": None, "duration_s": None})
                return {"outcome": SHIP_APPROVAL_PENDING, "actions": records,
                        "pending_action": name, "failed_action": None,
                        "rollbacks": [], "rollback_failed": False,
                        "toolchain": toolchain, "rollback_toolchain": []}
            approval_ref = _approval_ref(approval_ctx)

        # Resolve THIS action's creds host-side, at action time, fail-closed. A
        # missing/empty required secret is an action FAILURE (rollback + fail),
        # never a run with a half-populated env.
        try:
            cred_values = resolve_action_creds(action)
        except (df_creds.CredsError, ShipError) as e:
            journal.write("SHIP_CRED_FAILED", action=name, index=index, detail=str(e))
            records.append({"name": name, "reversible": reversible, "status": "cred_failed",
                            "exit": None, "approval_ref": approval_ref, "duration_s": None})
            rb = _rollback(action_has_own=action, stack=rollback_stack, journal=journal,
                           ship_ws=ship_ws, base_env=base_env,
                           base_secret_values=base_secret_values,
                           resolve_action_creds=resolve_action_creds, log_dir=log_dir)
            return {"outcome": SHIP_FAILED, "actions": records, "pending_action": None,
                    "failed_action": name, "rollbacks": rb["records"],
                    "rollback_failed": rb["failed"],
                    "toolchain": toolchain, "rollback_toolchain": rb["toolchain"]}

        redactor = df_creds.Redactor(list(base_secret_values or []) + list(cred_values.values()))

        try:
            cwd = _resolve_cwd(ship_ws, action.get("cwd"))
        except ShipError as e:
            journal.write("SHIP_CWD_INVALID", action=name, index=index, detail=str(e))
            records.append({"name": name, "reversible": reversible, "status": "cwd_invalid",
                            "exit": None, "approval_ref": approval_ref, "duration_s": None})
            rb = _rollback(action_has_own=action, stack=rollback_stack, journal=journal,
                           ship_ws=ship_ws, base_env=base_env,
                           base_secret_values=base_secret_values,
                           resolve_action_creds=resolve_action_creds, log_dir=log_dir)
            return {"outcome": SHIP_FAILED, "actions": records, "pending_action": None,
                    "failed_action": name, "rollbacks": rb["records"],
                    "rollback_failed": rb["failed"],
                    "toolchain": toolchain, "rollback_toolchain": rb["toolchain"]}

        # DF-R4-08: resolve + hash argv[0] NOW — against the action's cwd, and
        # BEFORE the spawn — so a self-modifying tool's recorded sha256 is the
        # bytes that actually started this action, not a post-run re-read.
        tc_entry = toolchain_identity(name, argv0, cwd,
                                      child_env=_child_env(base_env, cred_values))
        toolchain.append(tc_entry)

        idk = idempotency_key(run_id, name, index)
        # RESERVE-BEFORE (invariant #4): journal the intent (fsync'd) BEFORE the
        # subprocess is spawned. On a crash between here and the RESULT, resume
        # sees an unresolved intent and refuses (SHIP_UNKNOWN_OUTCOME).
        journal.write("SHIP_ACTION_INTENT", action=name, index=index, idempotency_key=idk,
                      reversible=reversible, approval_ref=approval_ref, toolchain=tc_entry)

        exit_code, timed_out, out, err, dur = _run_one(
            action["run"], cwd=cwd, child_env=_child_env(base_env, cred_values),
            timeout_s=action["timeout_s"])
        _write_logs(log_dir, name, "", out, err, redactor)

        success = (exit_code == 0) and not timed_out
        status = "ok" if success else ("timed_out" if timed_out else "failed")
        # M49 DF-R3-03 / R5 DF-R5-01: anchor this action's completion (bound to its
        # PRE-EXEC toolchain identity) into the signed chain BEFORE its RESULT is
        # journaled, so every `already_done` entry recovered on re-entry is
        # individually chain-backed AND its toolchain is authenticated (a forged
        # toolchain in the writable pending record cannot reconstruct a matching
        # signed token). Best-effort anchor; a failed anchor surfaces on re-entry
        # via _authenticate_ship_actions.
        if success and commit_action is not None:
            commit_action(name, idk, tc_entry, reversible, approval_ref)
        journal.write("SHIP_ACTION_RESULT", action=name, index=index, idempotency_key=idk,
                      exit=exit_code, timed_out=timed_out, status=status,
                      duration_s=round(dur, 3))
        records.append({"name": name, "reversible": reversible, "status": status,
                        "exit": exit_code, "approval_ref": approval_ref,
                        "duration_s": round(dur, 3)})

        if success:
            if action.get("rollback"):
                rollback_stack.append(action)
            continue

        # FAILURE (nonzero or timeout) → roll back in reverse (invariant #5).
        rb = _rollback(action_has_own=action, stack=rollback_stack, journal=journal,
                       ship_ws=ship_ws, base_env=base_env,
                       base_secret_values=base_secret_values,
                       resolve_action_creds=resolve_action_creds, log_dir=log_dir)
        return {"outcome": SHIP_FAILED, "actions": records, "pending_action": None,
                "failed_action": name, "rollbacks": rb["records"],
                "rollback_failed": rb["failed"],
                "toolchain": toolchain, "rollback_toolchain": rb["toolchain"]}

    return {"outcome": SHIPPED, "actions": records, "pending_action": None,
            "failed_action": None, "rollbacks": [], "rollback_failed": False,
            "toolchain": toolchain, "rollback_toolchain": []}


def _rollback(*, action_has_own, stack, journal, ship_ws, base_env,
              base_secret_values, resolve_action_creds, log_dir):
    """Roll back in REVERSE order: the FAILED action's OWN rollback first (it may
    have partially applied), then each already-succeeded prior action's rollback
    from `stack` in reverse. A rollback that itself FAILS (nonzero/timeout/launch
    error) is journaled SHIP_ROLLBACK_FAILED and flagged `failed=True` — surfaced
    loudly, never swallowed — but the remaining rollbacks are still attempted
    (best-effort unwind)."""
    targets = []
    if action_has_own is not None and action_has_own.get("rollback"):
        targets.append(action_has_own)
    targets.extend(reversed(stack))

    rb_records = []
    rb_toolchain = []
    any_failed = False
    for action in targets:
        name = action["name"]
        rollback_argv = action.get("rollback")
        if not rollback_argv:
            continue
        try:
            cred_values = resolve_action_creds(action)
        except (df_creds.CredsError, ShipError) as e:
            journal.write("SHIP_ROLLBACK_FAILED", action=name, detail=f"cred resolve: {e}")
            rb_records.append({"name": name, "status": "rollback_cred_failed", "exit": None})
            any_failed = True
            continue
        redactor = df_creds.Redactor(
            list(base_secret_values or []) + list(cred_values.values()))
        try:
            cwd = _resolve_cwd(ship_ws, action.get("cwd"))
        except ShipError as e:
            journal.write("SHIP_ROLLBACK_FAILED", action=name, detail=str(e))
            rb_records.append({"name": name, "status": "rollback_cwd_invalid", "exit": None})
            any_failed = True
            continue
        # DF-R4-08: record the rollback executable's identity BEFORE it runs, too
        # (a rollback tool is as security-relevant as the forward action) —
        # resolved against the rollback's cwd, pre-exec.
        rb_tc_entry = toolchain_identity(name, rollback_argv[0] if rollback_argv else None, cwd,
                                         child_env=_child_env(base_env, cred_values))
        rb_toolchain.append(rb_tc_entry)
        journal.write("SHIP_ROLLBACK_INTENT", action=name, toolchain=rb_tc_entry)
        exit_code, timed_out, out, err, dur = _run_one(
            rollback_argv, cwd=cwd, child_env=_child_env(base_env, cred_values),
            timeout_s=action["timeout_s"])
        _write_logs(log_dir, name, ".rollback", out, err, redactor)
        if exit_code == 0 and not timed_out:
            journal.write("SHIP_ROLLED_BACK", action=name, duration_s=round(dur, 3))
            rb_records.append({"name": name, "status": "rolled_back", "exit": 0})
        else:
            # LOUD, never swallowed: the operator must intervene — a rollback
            # that could not undo its action leaves real infrastructure in an
            # unknown state.
            journal.write("SHIP_ROLLBACK_FAILED", action=name, exit=exit_code,
                          timed_out=timed_out, duration_s=round(dur, 3))
            rb_records.append({"name": name,
                               "status": "timed_out" if timed_out else "rollback_failed",
                               "exit": exit_code})
            any_failed = True
    return {"records": rb_records, "failed": any_failed, "toolchain": rb_toolchain}


def _approval_ref(approval_ctx):
    """A value-free reference to the release approval that covered an action —
    the attestation's nonce (a public, single-use id), for the sealed ship
    record + journal. Never a signature or key."""
    att = getattr(approval_ctx, "attestation", None)
    if isinstance(att, dict):
        claim = att.get("claim")
        if isinstance(claim, dict) and isinstance(claim.get("nonce"), str):
            return claim["nonce"]
    return None


def _utcnow():
    import datetime
    return datetime.datetime.now(datetime.timezone.utc)
