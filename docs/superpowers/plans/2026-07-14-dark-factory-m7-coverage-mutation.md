# dark-factory M7 — Coverage Gate + Mutation-Validated Oracle Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Make a green verdict *mean something*. M6 made the dev/final split real; M7 proves (before any build) that (1) **coverage** — every declared spec behavior traces to ≥1 dev scenario, with no orphan scenarios (traceability, §4.1/§5.1); and (2) the oracle is **non-inert** — every scenario's `then` assertion is *discriminating* (it rejects a deliberately-wrong observation), catching tautological checks that would pass any output (mutation validation, §5.1/§15.4). Both run as a **fail-closed pre-build gate**: a coverage miss, an orphan scenario, or an inert check aborts the run (exit 2) before the builder ever runs. Both are opt-in + back-compatible: a control root with no `behaviors.json` skips the coverage check (honestly recorded), and mutation validation runs whenever scenarios exist.

**Architecture:** A new `df_gates.py` holds pure, unit-testable gate logic. Mutation validation reuses a refactored-out pure assertion evaluator (`evaluate_then(then, observed) -> taxonomy|None`) extracted from `run_scenarios.run_scenario` (behavior byte-identical). The supervisor runs the gate ONCE before the build loop; on failure it journals `COVERAGE_GATE_FAILED` / `ORACLE_GATE_FAILED`, finalizes a `GATE_FAILED` manifest (qualified=False), and returns 2 — no build, no leak. Manifest records `coverage` + `oracle` sub-objects for audit.

**Honest scope:** Coverage is checked against a human-declared `behaviors.json` (the traceability contract), not by parsing prose — the human/planner declares the behavior set. Stratified "≥1 final family per behavior" (§15.3) is *recorded* (which behaviors have a final scenario) but only **dev** coverage is a hard gate in M7 (a missing final scenario means "no sealed exam for that behavior," already surfaced by M6's `final_exam.ran`). Mutation validation here is a *structural* discrimination check on the assertion (does the `then` reject an adversarial observation), not full artifact-mutant generation (which needs a mutant-builder — deferred). It catches the real inert-check failure mode: assertions that pass regardless of output.

**Tech Stack:** Python stdlib only. pytest. `.venv/bin/python -m pytest dark-factory/tests -v` from repo root `/Users/alonadelson/Projects/ai_projects/skills`.

## Global Constraints

- **Runtime stdlib only.** Back-compatible: no `behaviors.json` ⇒ coverage check skipped, manifest `coverage.checked=false`; mutation validation always runs when scenarios load.
- **Fail-closed BEFORE build:** the gate runs before the first builder invocation. A failure aborts with **exit 2** and a `GATE_FAILED` outcome — the builder is never run, so no scenario content can leak via a build.
- **Barrier:** gate failures journal/record only **behavior-IDs and scenario-IDs**, never scenario `title/given/when/then` content beyond what's structurally necessary (mutation validation operates on `then` in-memory; it must not write `then`/`given`/`title` into any builder-visible artifact — the gate runs entirely control-plane, before the workspace has a builder).
- **`evaluate_then` refactor must be behavior-preserving:** `run_scenario`'s pass/fail/taxonomy output stays byte-identical (existing oracle tests must pass unchanged).
- **Mutation validation is deterministic** (no randomness) — a scenario is discriminating iff its `then` rejects the constructed adversarial observation.
- **Exit codes unchanged (0/2/3/10).** `GATE_FAILED` is a pre-run config-class failure → exit 2 (like other precondition failures).
- **Commit messages end with:** `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`.

## File Structure

```
dark-factory/
  scripts/
    run_scenarios.py    # Task 1 — extract pure evaluate_then(then, observed) -> taxonomy|None
    df_gates.py         # Task 1 (mutation) + Task 2 (coverage) — pure gate logic
    supervisor.py       # Task 3 — pre-build gate; GATE_FAILED exit 2; manifest coverage/oracle
  references/
    coverage-gates.md   # Task 3 — behaviors.json schema + gate semantics + honesty
    scenario-format.md  # Task 1 — note the discrimination requirement
  SKILL.md              # Task 3 — declare behaviors + gate step
  tests/
    test_evaluate_then.py    # Task 1
    test_mutation.py         # Task 1
    test_coverage.py         # Task 2
    test_e2e_gates.py        # Task 3
```

Control plane: `<control_root>/behaviors.json` — `{"behaviors":[{"id":"BHV-001","description":"..."}]}`.

---

### Task 1: Extract `evaluate_then` + mutation validation (`is_discriminating`)

**Files:**
- Modify: `dark-factory/scripts/run_scenarios.py`
- Create: `dark-factory/scripts/df_gates.py`
- Modify: `dark-factory/references/scenario-format.md`
- Create: `dark-factory/tests/test_evaluate_then.py`
- Create: `dark-factory/tests/test_mutation.py`

**Interfaces:**
- **Refactor (behavior-preserving):** extract the `then`-evaluation logic currently inside `run_scenario` into a module-level pure function `run_scenarios.evaluate_then(then: dict, observed: dict) -> str | None` — returns the failure taxonomy (`"wrong_exit_code"|"wrong_output"`) or `None` if the assertions pass, using the SAME `_norm`/priority rules as today (`exit_code` checked before output; `timeout`/`crash` are set by the subprocess layer, not here). `run_scenario` calls it. The `observed` dict has keys `exit_code`(int|None), `stdout`(str), `stderr`(str). Existing run_scenario output must be identical.
- `df_gates.GateError(ValueError)`.
- `df_gates.is_discriminating(then: dict) -> bool` — a `then` is discriminating iff it REJECTS a constructed adversarial observation. Construct `mutant = {"exit_code": (then["exit_code"] + 1) if "exit_code" in then else 999999, "stdout": "\x00DF-MUTANT-\x00", "stderr": "\x00DF-MUTANT-\x00"}` and return `evaluate_then(then, mutant) is not None` (i.e. the assertion fails on the mutant). A tautological `then` (e.g. `{"stdout_contains": ""}` — empty substring matches anything) returns False. Import evaluate_then from run_scenarios.
- `df_gates.validate_oracle(scenarios: list) -> list[str]` — returns the list of scenario `id`s whose `then` is NOT discriminating (inert). Empty list = all good.

- [ ] **Step 1: Write the failing tests.**
  - `test_evaluate_then.py`: table of (then, observed) → expected taxonomy/None, covering exit_code mismatch → "wrong_exit_code", stdout_equals/contains/stderr mismatch → "wrong_output", all-match → None, and the exit-before-output priority. (Mirror the existing oracle tests' cases so the refactor is proven equivalent.)
  - `test_mutation.py`: `is_discriminating` True for a normal `then` (`{"exit_code":0,"stdout_equals":"Hello"}`); False for tautological ones (`{"stdout_contains":""}`, a `then` whose only assertion the mutant happens to satisfy); `validate_oracle` returns the inert scenario IDs.
- [ ] **Step 2:** verify fail. **Step 3:** refactor `evaluate_then` out of `run_scenario` (keep run_scenario identical externally); implement df_gates `is_discriminating`/`validate_oracle`; note the discrimination requirement in `scenario-format.md`. **Step 4:** verify pass + **the existing `test_oracle.py` / `test_oracle_cohort.py` must stay green** (proves the refactor didn't change behavior) + full suite (193 + new). **Step 5:** commit `feat(dark-factory): extract pure evaluate_then + mutation-validation of scenario oracles`.

---

### Task 2: Coverage check (`behaviors.json` traceability)

**Files:**
- Modify: `dark-factory/scripts/df_gates.py`
- Create: `dark-factory/tests/test_coverage.py`

**Interfaces:**
- `df_gates.load_behaviors(control_root: str) -> list[dict] | None` — loads `<control_root>/behaviors.json` if present: validate `{"behaviors":[{"id":<BHV regex>,"description"?:str}]}`, ids unique + match `^BHV-[A-Za-z0-9-]{1,32}$`; return the list. Absent file → `None` (coverage optional). Malformed → `GateError`.
- `df_gates.check_coverage(behaviors: list[dict], scenarios: list[dict]) -> dict` — returns `{"checked": True, "behaviors": [ids], "uncovered_dev": [ids with no dev scenario], "orphan_scenarios": [scenario ids whose behavior_id is not declared], "final_covered": [behavior ids with >=1 final scenario]}`. A behavior is dev-covered iff ≥1 scenario with that behavior_id has cohort "dev". The gate PASSES iff `uncovered_dev == [] and orphan_scenarios == []`.
- (When `behaviors is None`: the supervisor records `{"checked": False}` and does not fail.)

- [ ] **Step 1:** `test_coverage.py`: load_behaviors (valid, absent→None, malformed→GateError, bad id→GateError, dup id→GateError); check_coverage — full coverage passes (uncovered/orphan empty); a behavior with only a final scenario → in `uncovered_dev` (needs a dev scenario) and in `final_covered`; a scenario with an undeclared behavior_id → in `orphan_scenarios`.
- [ ] **Step 2-4:** implement; verify; full suite green.
- [ ] **Step 5:** commit `feat(dark-factory): behavior->scenario coverage gate (traceability)`.

---

### Task 3: Supervisor pre-build gate + e2e + docs

**Files:**
- Modify: `dark-factory/scripts/supervisor.py`
- Create: `dark-factory/references/coverage-gates.md`
- Modify: `dark-factory/SKILL.md`
- Create: `dark-factory/tests/test_e2e_gates.py`

**Interfaces:** Read the current supervisor `run()`/`_run_locked()`/`_run_loop()`. Add a gate phase that runs ONCE before the build loop (in `_run_locked`, after scenarios/spec are known, before entering `_run_loop`; do NOT run it on resume of an already-gated run — gate on the initial run only, or make it idempotent/cheap and run it before each `_run_loop` entry; simplest correct: run in `_run_locked` for a fresh run; a resumed run already passed the gate). Steps:
1. Load scenarios (already validated by run_scenarios). Run **mutation validation**: `inert = df_gates.validate_oracle(scenarios)`. If non-empty → journal `ORACLE_GATE_FAILED(inert=<scenario_ids>)`, finalize manifest outcome `GATE_FAILED` + qualified=False + `oracle={"mutation_validated": False, "inert": inert}` + `coverage=...`, return 2.
2. Load behaviors (`df_gates.load_behaviors`). If present → `cov = df_gates.check_coverage(behaviors, scenarios)`; if `cov["uncovered_dev"] or cov["orphan_scenarios"]` → journal `COVERAGE_GATE_FAILED(uncovered=..., orphans=...)`, finalize `GATE_FAILED` manifest (qualified False, coverage=cov, oracle ok), return 2. If absent → `cov={"checked": False}`.
3. On gate pass, journal `GATE_PASSED(coverage_checked=cov["checked"], scenarios=len)`, thread `coverage` + `oracle={"mutation_validated": True, "inert": []}` into `manifest_base` so EVERY subsequent terminal's manifest carries them.
- The gate is entirely control-plane (before any builder invocation) — barrier-trivially safe.

- [ ] **Step 1:** `test_e2e_gates.py` (drive CLI as subprocess): (a) a control with `behaviors.json` fully covered + discriminating scenarios → converges exit 0, manifest `coverage.checked==True`, `coverage.uncovered_dev==[]`, `oracle.mutation_validated==True`; (b) a control whose `behaviors.json` declares a behavior with no dev scenario → exit 2, journal `COVERAGE_GATE_FAILED`, and **no BUILD journal entry** (the builder never ran); (c) a control with an inert scenario (`then` = `{"stdout_contains":""}`) → exit 2, `ORACLE_GATE_FAILED`, no BUILD entry; (d) a control with no behaviors.json → converges, `coverage.checked==False` (back-compat).
- [ ] **Step 2:** `coverage-gates.md`: behaviors.json schema, the two gates (coverage + mutation), fail-closed exit 2, honest scope (dev-coverage hard / final-coverage recorded, structural mutation not artifact-mutant). SKILL.md: add a "Declare behaviors" sub-step (author `behaviors.json` from the spec's BHV list) + note the pre-build gate rejects uncovered behaviors and inert scenarios before building.
- [ ] **Step 3:** verify docs vs code; full suite green; commit `feat(dark-factory): fail-closed pre-build coverage+mutation gate; e2e + docs`.

---

## Self-Review Notes (plan ↔ spec)

**Covered (M7):** the coverage gate (behavior→scenario traceability, §4.1/§5.1) and mutation validation of the oracle (checks must reject a wrong observation — no inert/tautological checks approve a build, §5.1/§15.4), both as a fail-closed pre-build gate (exit 2, no build on failure); manifest `coverage`+`oracle` audit fields on every terminal; `evaluate_then` extracted as a pure, independently-tested function.

**Deliberately deferred (honest, in coverage-gates.md):** full **artifact-mutant** generation + a mutation *score* threshold (§15.4 — needs a mutant-builder; M7 does structural discrimination, catching the real inert-check failure mode); a **critic-model review** of scenario adequacy (§4.1 — a second-model pass); stratified **≥1 final family per behavior as a hard gate** (M7 records final coverage; hard-gating it belongs with M12's verifier-only variants). M7 makes the checks non-inert and the behaviors traceable; those complete the rigor.

**Honesty note:** structural mutation validation proves a check *can* fail, not that the scenario tests the *right* behavior — that's the spec author's job, aided by the coverage gate's traceability. coverage-gates.md states this plainly.
```
