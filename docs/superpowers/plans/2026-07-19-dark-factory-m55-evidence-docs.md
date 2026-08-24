# M55 — DF-R4-08/09/10 evidence accuracy (code) + DF-R4-11 doc-honesty sweep

Final R4 milestone. Two parts:
- **M55a (CODE, opus-reviewed):** DF-R4-08 toolchain-hash-before-exec, DF-R4-10
  digest-pinned image for every dispatch, DF-R4-09 seal builder model_identity.
- **M55b (DOCS, no review — orchestrator does inline):** DF-R4-09 soften the
  "different model enforced" overclaims + DF-R4-11 the doc/on-ramp
  inconsistency table.

## M55a — code

### DF-R4-08 (Medium) — ship toolchain identity recorded AFTER execution
`_ship_toolchain_identity(actions)` (supervisor.py:6974) runs in
`_seal_ship_result` (7199) AFTER `df_ship.run_actions`. So a self-modifying
deploy tool's recorded digest is the POST-execution file, not what actually
ran; relative execs resolve against the SUPERVISOR cwd, not the action's ship
workspace; and rollback executables are not recorded. "Records what ran" is
overclaimed.

Fix (in `df_ship.run_actions` + supervisor):
- Resolve + hash each action's executable (`argv[0]`) BEFORE `subprocess`
  spawns it, resolving a relative `argv[0]` against the action's `cwd`
  (the ship workspace), not the supervisor cwd. Record `{argv0, resolved_path,
  sha256_if_regular_readable, note}` bound into that action's INTENT/RESULT as
  it runs (so the identity is of the bytes that started the action). Do the
  same for each ROLLBACK executable when a rollback runs.
- `_seal_ship_result` reads the per-action toolchain from the run_actions
  result instead of re-resolving after the fact. Keep the record shape
  backward-compatible (manifest `ship_result.json` toolchain field). Honest
  `note` when non-resolvable (a bare command found on PATH, or absent).
- Tests: a self-modifying stub (writes different bytes to itself after
  running) → the recorded sha256 is the PRE-exec bytes; a relative `argv[0]`
  resolves against the ship_ws; a rollback exe is recorded.

### DF-R4-10 (Medium) — container image tag-resolution race
`_finalize_container_manifest` records `resolved_image_digest` (118) but
`df_container.build_argv`/`build_enterprise_argv` and the probes are invoked
with `c["image"]` — the ORIGINAL, possibly-mutable TAG (2865/2879/2930/5393
+ enterprise). A tag can move between digest-inspection and dispatch, or
between iterations, so the manifest's recorded digest may not describe the
image that actually ran every dispatch.

Fix:
- Resolve the image digest ONCE, EARLY (before the first builder dispatch /
  probe in a container run), and use a DIGEST-PINNED reference
  (`<repo>@sha256:<digest>`) for EVERY container invocation in the run —
  build_argv, build_enterprise_argv, probe_container, probe_seccomp,
  probe_enterprise_egress. Record that pinned ref in the manifest. If the
  operator already pinned `@sha256:` in config, use it as-is. If the digest
  can't be resolved (offline / resolve failure): a config that did NOT pin a
  digest currently WARNS (fail-open) — keep that behavior for back-compat BUT
  make the manifest honest that dispatches used the unpinned tag
  (`image_pinned:false`, `resolved_image_digest:null`), and consider a config
  knob to require pinning fail-closed (out of scope unless trivial). The core
  fix is: when a digest IS available, ALL dispatches use it, so the recorded
  digest == what ran.
- Thread the resolved pinned ref from where it's computed to the build/probe
  call sites (a `cfg["_container"]["_effective_image"]` or a local threaded
  through `_run_loop`). Keep `_finalize_container_manifest` reporting the same
  digest.
- Tests: with a resolvable digest, build_argv/probes are called with the
  `@sha256:`-pinned ref (capture the image arg); an already-pinned config is
  used verbatim; the manifest's resolved digest matches the ref dispatched.

### DF-R4-09-code (Medium) — seal builder model_identity
M50 added optional `roles.<role>.model_identity` (operator-asserted) and seals
it for author/critic, but NOT for the builder (the builder has no
`authored_by`-style manifest field). An auditor can't compare all three roles'
declared identities from the terminal manifest alone. Fix: seal the builder's
`model_identity` (when set) into the manifest (e.g. a `builder_identity` field
or into the existing builder/confinement manifest surface), labeled
operator-ASSERTED not verified. Absent ⇒ unchanged. Test: a builder
model_identity appears verbatim in the sealed manifest.

## M55b — doc-honesty sweep (orchestrator, inline, no adversarial review)

DF-R4-09-docs + DF-R4-11. Correct each against the CODE:
- README quickstart `supervisor.py verify --control-root` → there is NO
  `verify` subcommand; it's `verify-manifest --run-dir` (+ `verify-chain`).
- GLOSSARY "Reversible action — an operation with a defined and credible
  rollback" → reversibility is operator-ASSERTED (rollback argv is OPTIONAL,
  not verified).
- "different model enforced fail-closed" (SKILL/README/OVERVIEW) → "distinct
  adapter IDENTITY (a resolved path, plus digest when pinned); a different
  MODEL is recommended but not system-verified" (align with M50's relabel).
- H2 "byte-for-byte equivalent to legacy checkpoint:pause" → H2 now ALSO
  pauses before ship (M36b); note the deliberate change.
- Enterprise "no single operator/person can ship" → `custody.threshold`
  permits 1-of-N and proves KEY/SIGNATURE distinctness, not distinct HUMAN
  ownership.
- "Qualified results are signed" → standard can qualify with
  `audit.signing:false`; signing is mandatory only at hardened/enterprise.
- Budget ceiling "signature-only" → a direct config edit is accepted unless
  the optional `resume_overrides` policy is configured.
- `hardened.dep_cache_dir` "presented as an init answer" → the closed init
  option set rejects `hardened.*`; it's a post-init edit.
- H3 "pauses at a soft alert / when approaching the cap" → it CONTINUES
  through the alert and pauses at the actual admission cap.
- Security gates "run in a locked-down environment" → external gate processes
  are ordinary HOST subprocesses (not sandboxed from host paths); built-ins
  are in-process. Correct the overclaim.
- config-reference: stale "legacy Linux host-read isolation" (M29c added the
  default-deny namespace backend); "the `hardened` block requires exactly
  hardened" (the loader ALSO accepts it for enterprise, which composes the
  hardened path).
- OVERVIEW "role adapters can verify" → verification is the DETERMINISTIC
  oracle; model adapters serve builder/author/critic, not verification.
- SKILL.md reference list "before-ship gate deferred" → it landed in M36b.
- (Optional, non-blocking) trim SKILL.md toward <500 lines if cheap.

Verify EACH claim against the actual code before rewriting; do not introduce
new inaccuracies. No behavior change in M55b.

## Rules
Fail CLOSED; real `raise`/return-nonzero, never bare `assert` (suite under
`python -O`). SUPERSET/back-compat: absent model_identity, an unresolvable
digest (warn path), and non-container runs unchanged. Full suite green
(baseline current main 1934 passed, 27 skipped). M55a: no commit, leave dirty
for review. M55b: orchestrator commits with M55a after review.
