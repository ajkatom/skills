# dark-factory M29a — candidate env/IPC sanitization + full process-tree teardown (audit DF-02 core) Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use `- [ ]`.

**Goal:** Close the two portable, high-value pieces of audit **DF-02** (candidate code insufficiently isolated): (1) candidate/verifier scenarios currently inherit the FULL `os.environ` (`run_scenarios.py:502,647`), leaking `SSH_AUTH_SOCK`, `*_PROXY`, cloud creds, agent sockets to generated code (Codex R3 #12); (2) CLI scenarios launch via plain `subprocess.run` with NO process group, so a candidate's `setsid`/double-forked children survive the run (Codex R4 #3) — HTTP scenarios already reap via `start_new_session=True` + `_reap_process_group`, CLI does not. Fix both. **Deferred to M29b/c (noted):** default-deny host-read sandbox (29c), copy-on-run scratch (29d), Linux netns egress (29e), containerized verifier (29f) — larger, platform-specific.

**Threat model:** detection/prevention of the confined candidate exfiltrating host secrets via inherited env/IPC and of surviving background processes — in-model, portable, testable on macOS+Linux.

**Tech Stack:** Python stdlib. pytest. `.venv/bin/python -m pytest dark-factory/tests -q` from repo root.

## Global Constraints
- **Allowlist, not denylist, for env:** candidate scenarios get a MINIMAL allowlisted env (PATH, HOME, LANG/LC_*, TMPDIR/TMP, TERM, TZ, and the SHELL/PWD basics a program needs) PLUS the explicitly-injected `env_extra` (twin `DF_TWIN_*` endpoints, M11 credential-allowlist vars) — NOT `dict(os.environ, ...)`. A hard denylist (SSH_AUTH_SOCK, SSH_AGENT_PID, *_PROXY/*_proxy, AWS_*, GOOGLE_*, ANTHROPIC_*, OPENAI_*, GH_TOKEN, etc.) is additionally scrubbed even if it sneaks onto the allowlist path (belt-and-suspenders). Applies to BOTH CLI and HTTP scenario launches.
- **Back-compat:** twin endpoints + credential-allowlist env (the legitimately-injected `env_extra`) still reach the candidate; existing twin/credential/e2e tests stay green. If a test relied on the candidate seeing an arbitrary inherited var, that's the bug being fixed — update it, but confirm it wasn't a legitimate injected var.
- **Process teardown parity:** CLI scenarios get the SAME `start_new_session=True` + `_reap_process_group` discipline HTTP scenarios already have; the whole tree is killed on success/failure/timeout.
- **Fail-closed:** env construction never silently passes a denylisted var; reaping never leaves the pgid alive (SIGTERM→wait→SIGKILL, as the HTTP path already does).
- **Commit trailer:** `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`.

## File Structure
```
dark-factory/scripts/run_scenarios.py   # T1 candidate_env + apply to both launches; T2 CLI pgid+reap
dark-factory/scripts/df_sandbox.py        # T1 (optional) home for candidate_env if cleaner there
dark-factory/references/isolation.md       # T3 docs
dark-factory/tests/test_candidate_env.py    # T1
dark-factory/tests/test_scenario_teardown.py # T2
```

---

### Task 1: env/IPC sanitization for candidate scenario execution
**Files:** modify `run_scenarios.py` (both `_run_http_scenario` ~502 and `run_scenario` ~647 env construction); create `test_candidate_env.py`.

- Add `candidate_env(env_extra: dict|None) -> dict`: returns `{allowlisted os.environ subset} ∪ (env_extra or {})`, then removes any key in the denylist (even from env_extra? NO — env_extra is supervisor-injected and trusted; scrub the denylist only from the inherited-allowlist portion, and assert env_extra never contains a denylisted name in a defensive check). Allowlist + denylist as module constants with clear comments.
- Replace `dict(os.environ, **(env_extra or {}))` (line ~502) and `dict(os.environ, **env_extra)` (line ~647) with `candidate_env(env_extra)`.
- Tests: candidate env EXCLUDES `SSH_AUTH_SOCK`, `HTTP_PROXY`/`http_proxy`, `AWS_SECRET_ACCESS_KEY`, `OPENAI_API_KEY`, an arbitrary `MY_HOST_SECRET` set in os.environ; INCLUDES `PATH`, `HOME`, and any injected `env_extra` (e.g. `DF_TWIN_FOO=...`, a credential-allowlist var); a denylisted var present in os.environ never reaches the result. Drive via monkeypatching os.environ.
- Commit `feat(dark-factory): candidate scenarios run under a minimal allowlisted env, host secrets scrubbed (DF-02/M29a Task 1)`.

---

### Task 2: full process-tree teardown for CLI scenarios (parity with HTTP)
**Files:** modify `run_scenarios.py` `run_scenario` (~633-686); create `test_scenario_teardown.py`.

- CLI scenario launch: switch `subprocess.run(...)` to `subprocess.Popen(..., start_new_session=True)` + capture output with a timeout, then `_reap_process_group(proc, pgid)` in a `finally` (mirror `_run_http_scenario`'s pattern at ~512-518 + the reap). Preserve the existing exec_wrapper prefix, cwd=workspace, env=candidate_env, timeout semantics, and the returned observed-output shape (don't change what `run_scenario` returns to callers).
- Test: a CLI scenario whose command spawns a **detached background child** (e.g. `python -c "import subprocess,os; subprocess.Popen(['sleep','300']); ...print marker"`) → after `run_scenario` returns, the background child is NOT alive (assert via the pgid being fully reaped / the child pid gone). A normal scenario still returns correct observed output + timeout still fires + is reaped.
- Full suite once (baseline 1178 passed/6 skip on main after M28a — expect green + new tests, zero regressions; watch existing run_scenarios/e2e tests for any reliance on run() vs Popen).
- Commit `feat(dark-factory): CLI scenarios reap their full process tree on completion/timeout (DF-02/M29a Task 2)`.

---

### Task 3: docs + e2e
**Files:** `references/isolation.md`; extend a test.
- `isolation.md`: new "Candidate process + env containment (DF-02)" note — candidate/verifier scenarios run under a minimal allowlisted env (host secrets/agents/proxies scrubbed) and with full process-group teardown (no surviving background children), at every tier. Honest scope: this is the env/IPC + process half of DF-02; host-read filesystem isolation (default-deny sandbox), copy-on-run, and network-namespace egress are M29b/c.
- Commit `docs(dark-factory): document candidate env/process containment (DF-02/M29a Task 3)`.

## Self-Review
**Covered:** DF-02 env/IPC leak + CLI process-tree survival (portable, testable). **Deferred (documented):** default-deny sandbox, copy-on-run, netns egress, containerized verifier → M29b/c. **Honest:** this narrows but does not fully close DF-02; the remaining host-read isolation is the larger, platform-specific piece.
