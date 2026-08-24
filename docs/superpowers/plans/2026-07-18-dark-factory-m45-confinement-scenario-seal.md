# M45 — RA-04 (confinement enabled∧required) + RA-05 (sealed scenario bundle)

Two High findings from the Codex re-audit, both config/run integrity.

## RA-04 (High) — enterprise confinement can be configured OFF
**Confirmed** (df_config.py:1761): enterprise validation requires
`builder_confinement.required: true` but NOT `builder_confinement.enabled:
true`. The contradictory `{ "enabled": false, "required": true }` passes
validation while runtime confinement is DISABLED — an enterprise run that
claims mandatory confinement but doesn't confine.

**Fix (two layers):**
1. **Coherence at ANY tier:** `required: true` with `enabled: false` is
   incoherent (you cannot "require" a mechanism you turned off) → `ConfigError`
   in the `builder_confinement` block itself, regardless of tier. (Today
   `required` defaults to `enabled`, so this only bites an EXPLICIT
   `{enabled:false, required:true}` — exactly the audited case.)
2. **Enterprise explicitness:** the enterprise gate additionally requires
   `builder_confinement.enabled: true` (not only `required`), with a clear
   message. Belt-and-suspenders on top of (1).
- Tests: `{enabled:false, required:true}` → ConfigError (both a standalone
  block test and an enterprise-config test); `{enabled:true, required:true}`
  still valid; enterprise without `enabled` → ConfigError. Confirm no existing
  valid config regresses (enabled:true default-required path unchanged).

## RA-05 (High) — scenario bundle is recorded but not enforced immutable
**Confirmed** (supervisor.py resume recomputes `_scenario_set_hash(scenarios_dir)`
from the LIVE control root each time, ~:3690 for run / the resume manifest_base
build): the run-start scenario set hash is bound into the first manifest + the
M36a FSM chain, but on RESUME the current directory is re-hashed and used as-is
— the acceptance criteria (hidden scenarios) can be edited between run start
and resume with no detection. A run could be qualified against a DIFFERENT
scenario set than it started with.

**Fix:** seal the run-start bundle and enforce it on resume, fail-closed.
- The FSM chain already binds `scenario_set_sha256` in every entry (M36a), and
  the chain is hash-validated on resume — so the run-start value is available
  and tamper-evident. On resume (state_version 0.2, after `_validate_fsm_chain`
  passes), recompute `_scenario_set_hash(scenarios_dir)` from the live control
  root and compare it to the scenario hash bound in the chain's genesis/first
  entry (the run-start bundle). Mismatch ⇒ refuse with a distinct
  `SCENARIO_BUNDLE_CHANGED` stderr + journal event + exit 2 (fail-closed);
  never silently qualify against edited criteria.
  - Add a helper `_chain_scenario_set_sha256(run_dir)` that reads the first
    `fsm_chain.jsonl` entry's `scenario_set_sha256` (the chain is already
    validated by this point, so trusting it is sound).
  - The extra generative-scenario dir (`extra_scenarios_dir`/`gen_dir`, if any)
    must be covered too if it participates in the sealed set — check how the
    run-start hash was computed and match it exactly (don't hash a superset on
    resume vs a subset at run-start, or vice-versa → that would false-positive).
    Verify `_scenario_set_hash` inputs are identical at run-start and resume.
- Legacy 0.1 states (no chain): there is no sealed run-start hash. Persist the
  run-start `scenario_set_sha256` into `state.json` at first `save_state`
  (additive field) so future paused runs can enforce it even without the
  chain; a truly pre-M45 0.1 state with neither chain nor the field journals
  `SCENARIO_BUNDLE_UNSEALED_LEGACY` and proceeds (can't enforce what was never
  sealed — honest, documented, and only affects runs paused before this lands).
- The primary `run` path is unaffected (it computes the hash once at start and
  seals it — that IS the run-start bundle).

## Tasks
1. **RA-04** — `df_config.py` builder_confinement coherence + enterprise
   `enabled` requirement; tests.
2. **RA-05** — `supervisor.py` resume: `_chain_scenario_set_sha256` +
   compare-or-refuse (`SCENARIO_BUNDLE_CHANGED`, exit 2) after chain
   validation; persist run-start hash into state.json for the legacy path;
   tests (edit a scenario file between run-pause and resume → refused; unchanged
   bundle → resumes normally; a `dev`-cohort edit AND a `final`-cohort edit both
   caught; legacy-state path documented).
3. **Docs** — `references/enterprise.md` (confinement must be enabled, not just
   required), `references/config-reference.md` (builder_confinement coherence
   rule), `references/audit.md` (scenario bundle sealed at run start + enforced
   on resume; new SCENARIO_BUNDLE_CHANGED status).

## Rules / invariants
- Fail CLOSED; real `raise`/return-nonzero, never bare `assert` (suite runs
  under `python -O`).
- Superset only: no existing valid config or resumable run regresses. A normal
  pause/resume with an unchanged bundle must resume byte-compatibly. The
  RA-05 enforcement adds a check; it must not false-positive on the legitimate
  same-bundle resume (watch the extra/gen scenario dir hashing parity).
- Regression tests must fail before the fix and pass after (RA-04: the
  `{enabled:false,required:true}` enterprise config; RA-05: an edited scenario
  between pause and resume).
- Full suite green (baseline 1832 passed, 12 skipped;
  `DOCKER_CONFIG=/tmp/dockercfg` to dodge the keychain hang). No commits.

## Out of scope (later milestones)
- RA-06 (dispatch idempotency), RA-07 (adapter-executable-only mount) → M46.
- RA-08 (candidate egress default + containment) + H1 init selector + hermetic
  locks/CI + QUALIFIED re-statement → M47.
