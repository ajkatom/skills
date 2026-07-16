# dark-factory M19 — Authoring Scaffold (`dark-factory init`) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Make "provide context and specs" a guided flow instead of hand-writing every control-plane file. `dark-factory init` scaffolds a **ready-to-run control root** — validated `config.json`, `spec.md`, a `scenarios/` directory of discriminating holdout scenarios (one+ per behavior, dev + a sealed final cohort), and `behaviors.json` — from a small set of answers (interactively via the SKILL, or from a JSON answers file for scripting). The orchestrator (human/Claude) authors the spec AND the scenarios; the builder subprocess still never sees them — init just removes the authoring friction, and it **fails if the scaffolded control root doesn't validate** (config loads, oracle is discriminating, coverage is complete) so a user can't produce a broken control plane.

**Architecture:** `df_init.py` (stdlib) has pure builders — `build_config(answers) -> dict`, `build_behaviors(answers) -> dict`, `build_scenarios(answers) -> list[dict]`, `scaffold(control_root, answers)` (writes the tree) — plus `validate_scaffold(control_root)` that runs the real `df_config.load_config` + `df_gates.validate_oracle` + `df_gates.check_coverage` and returns a pass/fail report. An `answers` dict is the single contract: `{app_name, spec_text, assurance, workspace_root, builder_adapter, behaviors:[{id,description,scenarios:[{cohort,run,then,title}]}], options:{security_gates?,twins?,budget?,knowledge_base?}}`. A `init` CLI subcommand in `supervisor.py` reads answers from `--answers <file.json>` (or stdin) and scaffolds+validates. The SKILL gains an **interview script** (a reference doc the orchestrator follows) that elicits the answers, and — crucially — guidance on writing GOOD holdout scenarios (behavior-per-scenario, discriminating `then`, dev/final split, the exit_code/stdout_contains oracle shape).

**Honest scope (stated in docs):** init produces a *starting* control root — the human still reviews/tightens the scenarios (they are the contract; init can only scaffold what the answers describe). init validates structure (config loads, oracle discriminating, coverage complete) but cannot verify the scenarios truly capture intent — that is the human's judgment. init does NOT run a build; it prints the exact `supervisor.py run` command. Cross-model/tier/twins options are scaffolded into config but their live prerequisites (Docker for hardened, CLIs for cross-model) are checked at `run`, not `init` (init notes them).

**Tech Stack:** Python stdlib. pytest. `.venv/bin/python -m pytest dark-factory/tests -v` from repo root `/Users/alonadelson/Projects/ai_projects/skills`.

## Global Constraints

- **Scaffold must validate or fail:** `scaffold` followed by `validate_scaffold` must pass (config loads; every scenario's `then` is discriminating per `df_gates.is_discriminating`; `check_coverage` has empty `uncovered_dev` + `orphan_scenarios`); the CLI exits nonzero + prints the specific failure if not, and (default) removes/【marks】the invalid tree rather than leaving a broken control root that would fail-closed at run.
- **Barrier respected in generated artifacts:** the scaffolded `spec.md` (builder-visible) must NOT contain scenario content; `build_config`/`build_scenarios` keep scenarios only under `scenarios/`. A generated spec that embeds a scenario's exact expected output is a scaffold bug (add a check: no scenario `then` literal appears in spec.md).
- **Reuses the real validators:** init calls `df_config.load_config`, `df_gates.validate_oracle`, `df_gates.check_coverage`, `run_scenarios.load_scenarios` — never a reimplementation — so a control root init blesses is one `run` accepts.
- **Back-compat:** additive only (new module + new `init` subcommand + SKILL section); all existing tests green.
- **Commit messages end with:** `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`.

## File Structure

```
dark-factory/
  scripts/
    df_init.py         # Task 1 — builders + scaffold + validate_scaffold
    supervisor.py      # Task 2 — `init` CLI subcommand
  references/
    authoring.md       # Task 2 — the interview script + how to write good holdout scenarios
    config-reference.md
  SKILL.md             # Task 2 — init flow + pointer
  examples/
    kv-service/answers.json  # Task 2 — a worked example answers file (the KV web service)
  tests/
    test_init.py           # Task 1
    test_e2e_init.py        # Task 2
```

---

### Task 1: df_init builders + scaffold + validate

**Files:** create `dark-factory/scripts/df_init.py`, `dark-factory/tests/test_init.py`.

**Interfaces (Produces):**
```python
class InitError(RuntimeError): ...

def build_config(answers: dict) -> dict
    # config.json dict: config_version 0.1, feedback "ids", autonomy (4 default;
    # 5 only if assurance hardened/enterprise else InitError), checkpoint "auto"
    # default, assurance (validated against supported_tiers), max_iterations
    # (default 8, 1..20), workspace_root (must be disjoint from control_root —
    # answers carry both), roles.builder.adapter, budget billing default
    # "subscription", plus any options blocks (security_gates/twins/budget/
    # knowledge_base) passed through. Raises InitError on a violation BEFORE
    # writing anything.

def build_behaviors(answers: dict) -> dict   # {"behaviors":[{id,description}...]} from answers.behaviors ids
def build_scenarios(answers: dict) -> list[dict]
    # one scenario dict per answers.behaviors[].scenarios[] entry: ir_version
    # 0.1, id "<BID>-S<n>"/"-F<n>", behavior_id, cohort, title, given,
    # when{run,timeout_s}, then. Every behavior needs >=1 dev scenario; each
    # `then` must be discriminating (else InitError naming the behavior).

def scaffold(control_root: str, answers: dict) -> None
    # write config.json, spec.md (= answers.spec_text), behaviors.json,
    # scenarios/<id>.json. Refuses to overwrite a non-empty control_root
    # (InitError) unless answers.force.

def validate_scaffold(control_root: str) -> tuple[bool, dict]
    # runs the REAL load_config + load_scenarios + validate_oracle +
    # check_coverage; returns (ok, report) with report =
    # {config_ok, inert:[...], coverage:{...}, spec_leak:[...]}. spec_leak =
    # any scenario `then` string literal found verbatim in spec.md (barrier
    # scaffold check). ok iff config loads, inert empty, coverage complete,
    # spec_leak empty.
```

- [ ] **Step 1 (TDD):** `test_init.py` — build_config: valid answers → a config df_config.load_config accepts; autonomy 5 + cooperative → InitError; workspace not disjoint → InitError (via load in validate). build_scenarios: a behavior with an inert `then` (e.g. `{"stdout_contains":""}`) → InitError; good ones → discriminating. scaffold+validate_scaffold on a complete answers dict (reuse the KV example) → (True, report) with empty inert/uncovered/spec_leak; an answers dict whose spec_text embeds a scenario's exact expected output → spec_leak non-empty → (False, ...). Refuse overwrite of a non-empty dir without force.
- [ ] **Step 2:** Implement → green. Full suite.
- [ ] **Step 3:** Commit `feat(dark-factory): df_init — scaffold + validate a ready-to-run control root`.

---

### Task 2: `init` CLI + interview docs + worked example

**Files:** modify `supervisor.py`, `SKILL.md`, `config-reference.md`; create `references/authoring.md`, `examples/kv-service/answers.json`, `dark-factory/tests/test_e2e_init.py`.

**Interfaces:**
- `supervisor.py` `init` subcommand: `init --control-root <cr> --answers <file.json|-> [--force]` → `df_init.scaffold` then `df_init.validate_scaffold`; on ok → print the scaffolded tree summary + the exact `run` command + any run-time prerequisites (Docker for hardened/enterprise; the builder CLI; approver keys for enterprise custody); on not-ok → print the report's failures, remove the invalid tree (unless --force-keep), exit 2.
- `references/authoring.md`: the interview script the orchestrator follows — (1) what does the app do + its interface (the spec); (2) which tier (map cooperative/standard/hardened/enterprise to what each guarantees + prerequisites); (3) the must-pass behaviors, and for each, 1-3 holdout scenarios (a concrete input → expected exit_code/stdout/stderr) — with the guidance: one behavior per scenario, make each `then` discriminating (a real assertion, not `stdout_contains:""`), keep dev vs a sealed final cohort, the builder NEVER sees these; (4) options (security_gates, twins for external deps, budget, knowledge_base). Then: run `init`, review the generated scenarios, `run`.
- `examples/kv-service/answers.json`: the KV JSON HTTP API answers (the acceptance app) as a copyable worked example.
- SKILL.md: an "Authoring a run (`init`)" section pointing at authoring.md, framed as the on-ramp for "provide context and specs".

- [ ] **Step 1:** `test_e2e_init.py` (CLI subprocess): `init` with the KV example answers → exit 0, a control root that then `df_config.load_config` + `validate_oracle` + `check_coverage` all accept (and, if fast, a subsequent `run` with the FAKE builder converges — proving init produces a runnable control root); `init` with an answers file containing an inert scenario → exit 2 + the inert behavior named + no leftover control root; `init` refuses a non-empty dir without --force.
- [ ] **Step 2:** authoring.md + example + SKILL.md; verify docs vs code. Full suite green.
- [ ] **Step 3:** Commit `feat(dark-factory): init CLI + authoring interview docs + KV worked example`.

---

## Self-Review Notes (plan ↔ spec)

**Covered (M19 / DoD on-ramp):** the "when provided context and specs" ergonomics — a guided, validated scaffold so a user reaches a runnable control root without hand-writing config + oracle + coverage; the scaffold reuses the real validators so `init` blesses exactly what `run` accepts; a barrier scaffold-check (no scenario content leaks into the builder-visible spec); a worked example + an interview script (how to pick a tier, how to write discriminating holdout scenarios).

**Deliberately deferred (honest, in authoring.md):** init cannot judge whether scenarios truly capture intent (human's job — it validates structure, not semantics); it does not auto-generate scenarios from the spec (the orchestrator writes them, following the guidance — auto-derivation would risk teaching-to-the-test and is out of scope); it does not run the build (prints the `run` command).

**Honesty note:** init FAILS closed — a scaffolded control root that doesn't validate is rejected (and removed) rather than left to fail confusingly at `run`, and a spec that embeds scenario answers is caught as a barrier scaffold bug.
