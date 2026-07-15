# Coverage + mutation gates (M7) — the fail-closed pre-build gate

Before any builder is ever invoked, the supervisor runs two control-plane
checks against the loaded scenarios. Either failure aborts the run —
**exit 2**, outcome `GATE_FAILED` — with **no build**: the builder process
is never started, so no scenario content can leak via a build attempt.

## 1. Mutation validation (always on)

A scenario's `then` assertion must be **discriminating**: it must reject a
deliberately-wrong ("mutant") observation, not just accept the right one. A
tautological check — e.g. `{"stdout_contains": ""}`, which matches *any*
stdout because the empty string is a substring of everything — passes
regardless of what the build actually does. A green run against an inert
check proves nothing.

`df_gates.is_discriminating(then)` constructs one fixed adversarial
observation (`exit_code` off by one, `stdout`/`stderr` replaced with a
constant marker string) and evaluates `then` against it via the same
`run_scenarios.evaluate_then` the real verifier uses. If `then` does not
reject the mutant, it is inert. `df_gates.validate_oracle(scenarios)`
returns the sorted list of inert scenario `id`s across the whole set.

This check runs unconditionally, for every scenario, on every run — there
is no opt-out. It is deterministic (no randomness): the same scenario set
always produces the same verdict.

**On failure:** the supervisor journals `ORACLE_GATE_FAILED(inert=[...])`
(scenario IDs only — never `then`/`given`/`title` content), finalizes a
`GATE_FAILED` manifest with `oracle: {"mutation_validated": false, "inert":
[...]}` and `coverage: {"checked": false}` (mutation runs first, before
coverage is computed), and returns exit 2.

## 2. Coverage gate (`behaviors.json`, opt-in)

`<control_root>/behaviors.json` declares the spec's behavior set — the
traceability contract between the spec and the scenario set:

```json
{
  "behaviors": [
    {"id": "BHV-001", "description": "greets a named user"},
    {"id": "BHV-002"}
  ]
}
```

- `id` must match `^BHV-[A-Za-z0-9-]{1,32}$` and be unique within the file.
- `description` is optional, free text, human-only (never leaves the
  control root).
- The file is **entirely human/planner-authored** — nothing parses spec
  prose to infer behaviors. If it declares a behavior your scenarios never
  cover, that is treated as a real gap.
- **Absent file → coverage is skipped**, honestly recorded as
  `coverage: {"checked": false}`. This is the back-compatible default:
  every control root that predates M7 behaves exactly as before.

`df_gates.load_behaviors(control_root)` loads and validates the file
(`None` if absent; `df_gates.GateError` on any malformed content — bad
JSON, wrong shape, invalid or duplicate ids). `df_gates.check_coverage
(behaviors, scenarios)` returns:

```json
{
  "checked": true,
  "behaviors": ["BHV-001", "BHV-002"],
  "uncovered_dev": [],
  "orphan_scenarios": [],
  "final_covered": ["BHV-001"]
}
```

- **`uncovered_dev`**: declared behavior IDs with zero `cohort: "dev"`
  scenario. A behavior with *only* a `final` scenario still lands here —
  a sealed exam is not a substitute for dev-loop feedback.
- **`orphan_scenarios`**: scenario IDs whose `behavior_id` was never
  declared in `behaviors.json` — a scenario for a behavior nobody wrote
  down, which is just as much a traceability break as an uncovered
  behavior.
- **`final_covered`**: declared behavior IDs with ≥1 `cohort: "final"`
  scenario — **recorded, not gated** (see Honest scope below).

**The gate PASSES iff `uncovered_dev == [] and orphan_scenarios == []`.**

**On failure:** the supervisor journals `COVERAGE_GATE_FAILED(uncovered=
[...], orphans=[...])` (behavior/scenario IDs only), finalizes a
`GATE_FAILED` manifest with `coverage` set to the full `check_coverage`
result and `oracle: {"mutation_validated": true, "inert": []}` (mutation
already passed, since it runs first), and returns exit 2.

A malformed `behaviors.json` (`GateError`) is a config-class error: it
journals `GATE_ERROR(detail=...)`, prints to stderr, and returns exit 2
without a manifest — the same treatment as other precondition failures
(e.g. a bad audit key).

## Gate ordering and manifest fields

Order is fixed: **mutation first, then coverage.** An inert oracle is a
more fundamental defect than a coverage gap (a scenario that can't fail is
useless even if it's perfectly traced to a behavior), and mutation
validation doesn't depend on `behaviors.json` existing at all.

On a full pass, the supervisor journals `GATE_PASSED(coverage_checked=...,
scenarios=<count>)` and threads `coverage` + `oracle: {"mutation_validated":
true, "inert": []}` into every subsequent terminal manifest for that run —
`COMPLETE_QUALIFIED`/`COMPLETE_UNQUALIFIED`, `CAP_REACHED`,
`FINAL_EXAM_FAILED`, `SECURITY_GATE_FAILED`, `ABORTED_BUILD_ERROR`, and (via
`resume`) `ACCEPTED_WAIVED`/`ABORTED_BY_HUMAN`. Every terminal manifest from a
run carries `coverage` and `oracle`, so an auditor never has to guess whether
either gate ran. (M9 adds a `security` field threaded the same way — see
`references/security-gates.md`.)

**Resume does not re-gate.** The gate runs once, in `run`, before the
first iteration. A paused-and-resumed run already passed it; re-running it
on every `resume --decision continue` could spuriously fail an
already-approved run (e.g. transient scenario-file edits during a pause
that this gate is not the mechanism for policing). `resume()` instead
*recomputes* `coverage`/`oracle` — cheap and deterministic from the
control root + scenario set — purely so its own terminal manifests
(`accept`/`abort`/a subsequent `continue`'s terminal) carry accurate
fields, without re-enforcing the gate's pass/fail verdict.

## Honest scope

- **Dev coverage is a hard gate; final coverage is recorded, not gated.**
  M7 requires every declared behavior to have a `dev` scenario. It does
  **not** require a `final` scenario — `final_covered` is informational.
  A missing sealed exam for a behavior is already surfaced honestly by
  M6's `final_exam.ran` (a control root with no `final` scenarios at all
  administers no sealed exam, and the manifest says so). Making "≥1 final
  scenario per behavior" a hard gate is deferred to a later milestone
  (alongside verifier-only variants).
- **This is structural discrimination, not artifact-mutant testing.**
  `is_discriminating` proves a `then` *can* reject a wrong observation —
  it does not generate mutants of the actual built artifact and check that
  the scenario catches them. Full mutation testing needs a mutant-builder
  (deliberately breaking the implementation N ways and confirming each
  scenario that should catch a given break does) — that is future work.
  What M7 catches is the concrete, common failure mode: a check written so
  loosely it would pass literally anything.
- **No critic-model review.** Nothing here judges whether a scenario tests
  the *right* behavior, only whether its assertion is non-trivial and
  whether it's traced to a declared behavior. A scenario can be
  discriminating and covered and still test the wrong thing — that
  remains the spec author's responsibility, aided (not replaced) by the
  coverage gate's traceability requirement.
- **`behaviors.json` is human-declared, not derived.** No prose-parsing:
  if the spec lists ten behaviors and `behaviors.json` only declares
  eight, the gate has no way to know the other two exist. Author it
  directly from the spec's behavior list.

## Interaction with other checks

The gate runs strictly before workspace snapshotting and isolation
resolution — before anything the builder could ever touch. It is
unaffected by `assurance` tier (`cooperative`/`standard`) and by
`audit.signing` (a signed `GATE_FAILED` manifest signs and verifies
exactly like any other terminal manifest, via the same `finalize_manifest`
path). A scenario file that fails IR validation (`run_scenarios.OracleError`
— e.g. missing required fields) is caught earlier, during scenario
loading, and reported as `ABORTED_BUILD_ERROR`, not `GATE_FAILED` — that
is a malformed-input error, not a gate verdict.
