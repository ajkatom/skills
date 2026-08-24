# M46 — RA-06 (idempotent dispatch recovery) + RA-07 (mount only the adapter executable)

Two High findings from the Codex re-audit.

## RA-06 (High) — crash recovery can repeat a completed (paid) builder dispatch
**Confirmed:** M35 added `DISPATCH_INTENT`/`DISPATCH_RESULT` +
`_unresolved_dispatch_intent`, but that only catches an intent with NO matching
result. After `DISPATCH_RESULT` is journaled (the builder call COMPLETED and
wrote the workspace) but before the iteration's verification/finalization
completes and `next_iter` advances, a crash lets `resume` re-enter the SAME
iteration `i` and **re-dispatch the builder** — repeating a completed, paid
model request. `_unresolved_dispatch_intent` returns None (the intent is
resolved), so plain `--decision continue` proceeds and re-runs iteration `i`
from the top, including the builder call. The idempotency_key is
`(invocation, iteration)`, but nothing consults an EXISTING resolved result to
skip the re-dispatch.

**Fix — make the whole intent→result→verify→finalize interval idempotent:**
- Before dispatching the builder in iteration `i`, check the journal for a
  `DISPATCH_RESULT` whose `idempotency_key == _dispatch_idempotency_key(
  invocation, i)`. If one exists, the build for this iteration already
  COMPLETED and its output is already in the persisted `workspace` — so SKIP
  the builder call and proceed straight to verification of the existing
  workspace, reusing the recorded result (journal `DISPATCH_REPLAYED` with the
  key, value-free). No second paid call.
- This is sound because: the workspace persists on disk across a crash; a
  journaled `DISPATCH_RESULT` means the adapter returned and the workspace
  write completed (the result is journaled AFTER the adapter call resolves).
  The reserved budget for that call was already committed at intent time
  (M35), so replaying does NOT double-count spend.
- Add a helper `_resolved_dispatch_result(run_dir, invocation, iteration)`
  returning the recorded result dict (status/usage) for that key, or None.
  Thread it into the loop's dispatch site: `if a resolved result exists for
  (invocation,i): skip invoke_adapter, use it`.
- Interaction with `--decision reconcile` (M35): reconcile is for an
  UNRESOLVED intent (re-dispatch accepting possible duplicate). RA-06 is the
  RESOLVED case — it must AUTO-skip, never re-dispatch, on plain continue.
  Keep the two paths distinct and documented.
- Edge: a partial/failed adapter call journals its result as an error/None
  outcome — replay must reproduce the SAME handling (an errored dispatch that
  was journaled as ABORTED_BUILD_ERROR already terminated the run; it won't be
  resumed into a re-dispatch). Only a successful `DISPATCH_RESULT` triggers the
  skip-and-verify replay.
- Tests: drive a run to just-after `DISPATCH_RESULT` for iteration i (crash
  simulation: kill/return before finalization with next_iter still = i), then
  resume and assert the builder is NOT re-invoked (a counting fake builder’s
  call count is unchanged) and the run proceeds to verify/converge; assert
  `DISPATCH_REPLAYED` journaled. Contrast with the unresolved case (still
  UNKNOWN_OUTCOME/reconcile).

## RA-07 (High) — broad adapter-directory mount can expose host secrets
**Confirmed** (supervisor.py:4809 & :4867): hardened/enterprise compute
`adapter_ro_dir = os.path.dirname(os.path.realpath(adapter))` and mount the
ENTIRE directory read-only (`ro_mounts = [adapter_ro_dir]`) into the builder
container. An adapter placed in a broad directory (`~/bin`, a repo root, a
dir also holding credentials/keys) exposes all of it to the builder.

**Fix — mount only the adapter executable (+ explicitly-declared extras):**
- Mount the adapter FILE itself, not its directory:
  `ro_mounts = [adapter_executable_path]` (docker `-v file:file:ro` works for a
  single file; `df_container._resolve_mount_path` + the `{p}:{p}:ro` spec
  already handle a file path). Do this for BOTH `build_argv` (hardened) and
  `build_enterprise_argv` (enterprise).
- Self-containedness: the shipped in-container adapters (`api_anthropic`,
  `api_openai`) are stdlib-only single files — verify they import no sibling
  module at runtime (grep their imports; they should be stdlib-only). If any
  shipped adapter needs a sibling file, mount that specific file too (an
  explicit, minimal allowlist in code), never the whole dir. (The CLI adapters
  claude/codex/gemini don't run in-container anyway — they need a binary the
  minimal image lacks — so the API adapters are the real in-container case.)
- Optional operator escape hatch (only if needed): a config field
  `roles.builder.container_mounts: ["/abs/path", …]` for an adapter that
  genuinely needs extra files — each validated (absolute, disjoint from the
  control root, existing). Default: executable only. Only add this if a shipped
  adapter actually requires it; otherwise keep it executable-only and document
  that a multi-file adapter must declare its extras.
- Tests: assert the built docker argv mounts the adapter FILE, not its
  directory (no `-v <dir>:<dir>:ro` for the adapter's parent); a hardened +
  enterprise argv test; the in-container api adapter e2e (already exists) still
  runs to completion with only the file mounted (proves self-containedness).

## Tasks
1. **RA-06** — `_resolved_dispatch_result` helper + skip-and-verify replay in
   `_run_loop`'s dispatch site + `DISPATCH_REPLAYED` journal; tests
   (resolved→no re-dispatch; unresolved→still UNKNOWN_OUTCOME).
2. **RA-07** — supervisor: mount adapter executable (file) not dirname, both
   tiers; confirm api adapters are self-contained (or mount their minimal
   declared extras); tests (argv mounts file; in-container adapter still works).
3. **Docs** — `references/hardened.md` + `references/enterprise.md` (adapter is
   mounted as a single executable, not its directory; a multi-file adapter must
   declare extras), `references/audit.md` (DISPATCH_REPLAYED; crash-recovery is
   now idempotent across the full dispatch→finalize interval).

## Rules / invariants
- Fail CLOSED; real `raise`/return-nonzero, never bare `assert` (`-O`).
- Superset only: RA-06 must not change the happy path (no crash → no replay,
  identical behavior) and must not break M35's unresolved-intent/reconcile
  path. RA-07 must not break the existing in-container api-adapter e2e.
- Regression tests fail before / pass after for both.
- Full suite green (baseline = M45's count once merged; use
  `DOCKER_CONFIG=/tmp/dockercfg`). No commits — leave dirty for opus review.

## Out of scope (M47)
- RA-08 (candidate egress default-deny at qualifying tiers + process
  containment), H1 init selector, hermetic dependency locks + CI, and the
  honest top-level QUALIFIED re-statement now that RA-01..RA-07 are fixed.
