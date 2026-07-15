# dark-factory M6 — Sealed Final-Exam Holdout (dev/final split) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Implement the founding anti-overfitting mechanism — the ML **train/dev/test** split. Scenarios carry a `cohort` (`dev` | `final`). The loop iterates against **dev** scenarios (the only ones that produce feedback); when dev converges, the **sealed final-exam** cohort runs **exactly once**, its results are **never fed back**, and a final failure is a **terminal `FINAL_EXAM_FAILED`** outcome (the artifact is rejected — dark-factory does not iterate against the held-out exam). Regression (a previously-green dev behavior going red) is tracked and journaled. Pass is unconditional 100% dev + 100% final.

**Architecture:** Additive + back-compatible. Oracle IR v0 gains an optional `"cohort": "dev"|"final"` field (default `"dev"`), so every existing control root — where no scenario declares a cohort — behaves exactly as today (all-dev, no sealed exam). `run_all(..., cohort=None|"dev"|"final")` filters by cohort. `_run_loop` runs `cohort="dev"` each iteration; the converged branch (dev all-pass) now runs `cohort="final"` once before declaring success. The final cohort is **holdout** — its content never reaches the builder: final results are never passed to `project_feedback`, never written to the workspace, and only its behavior-IDs (not content) appear in the control-plane journal/manifest.

**Honest scope:** M6 splits cohorts by **authorship** (the human labels each scenario `dev` or `final`) and runs the final set once after dev converges. The full spec rigor of §15.3 — freezing generators/cohorts and drawing *verifier-only* secret seeds *after artifact freeze* — needs verifier-only hidden variants (deferred to M12). A control root with **no `final` scenarios** runs as today and its manifest honestly records `final_exam.ran = false` ("no sealed exam was administered"). Authoring a final cohort is how you opt into the sealed-exam gate.

**Tech Stack:** Python stdlib only. pytest. `.venv/bin/python -m pytest dark-factory/tests -v` from repo root `/Users/alonadelson/Projects/ai_projects/skills`.

## Global Constraints

- **Runtime stdlib only.** Back-compatible: absent `cohort` ⇒ `dev`; a control root with no `final` scenarios behaves byte-identically to today except the manifest gains `final_exam.ran=false`.
- **The barrier now covers the final cohort too:** final scenario content (title/given/when/then/observed) NEVER reaches the builder prompt, the workspace, or feedback. `project_feedback` is called ONLY on dev results. Final results are written only to `run_dir` (control plane). Only final **behavior-IDs** (never content) may appear in journal/manifest.
- **Final exam runs exactly once**, after dev converges, and is **never fed back** — a final failure is terminal (`FINAL_EXAM_FAILED`), the artifact is rejected, the loop does not continue. (Spec §15.4: "a failed final exam is terminal.")
- **Exit codes unchanged (0/2/3/10):** dev+final both pass → 0. `FINAL_EXAM_FAILED` is a non-converged terminal the human evaluates → **exit 3** (like the cap), distinguished by outcome/journal state. Config/build error → 2. Paused → 10.
- **`qualified` is never true on a final failure or a no-final run's exam** — a `FINAL_EXAM_FAILED` manifest is `qualified=False`; a run with no final cohort keeps its existing tier-based qualified value but records `final_exam.ran=false` so the (absent) exam is not misread as passed.
- **Pass threshold is unconditional 100%** of dev and 100% of final (no configurable partial passing — spec §15.3).
- **Commit messages end with:** `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`.

## File Structure

```
dark-factory/
  scripts/
    run_scenarios.py     # Task 1 — cohort field + run_all(cohort=) filter
    supervisor.py        # Task 2 — dev-loop + sealed final-exam once + FINAL_EXAM_FAILED; Task 3 regression
  references/
    scenario-format.md   # Task 1 — cohort field
    audit.md / SKILL.md  # Task 4 — final_exam manifest field + cohort authoring + honesty
  tests/
    test_oracle_cohort.py     # Task 1
    test_final_exam.py        # Task 2
    test_regression.py        # Task 3
    test_e2e_final_exam.py    # Task 4
    fixtures/fake_builder_final  # Task 2 — a builder that passes dev but fails a final behavior
```

---

### Task 1: Oracle `cohort` field + cohort-filtered `run_all`

**Files:**
- Modify: `dark-factory/scripts/run_scenarios.py`
- Modify: `dark-factory/references/scenario-format.md`
- Create: `dark-factory/tests/test_oracle_cohort.py`

**Interfaces:**
- Read the current `_validate`, `load_scenarios`, `run_all` first.
- IR v0 gains optional `"cohort"` (default `"dev"`); allowed values `{"dev","final"}`, else `OracleError`. `load_scenarios` sets `sc.setdefault("cohort","dev")` after validation.
- `run_all(scenarios_dir, workspace, exec_wrapper=None, env_extra=None, cohort=None)`: `cohort=None` runs all (today's behavior, unchanged for existing callers); `cohort="dev"|"final"` runs only that cohort. The report dict gains `"cohort": <the filter or "all">` and `"count": len(results)`. If a requested cohort has **zero** scenarios, `run_all` returns `{"report_version":..., "cohort":..., "results":[], "all_pass":True, "count":0}` — **empty cohort ⇒ all_pass True with count 0** (an empty dev set is a config error caught elsewhere; an empty final set is the honest "no sealed exam" case the supervisor detects via `count==0`). Do NOT raise on empty here.

- [ ] **Step 1: Write the failing tests** — `test_oracle_cohort.py`: (a) absent cohort → "dev"; (b) explicit "final" honored; (c) invalid cohort "prod" → OracleError; (d) `run_all(cohort="dev")` returns only dev results with `report["cohort"]=="dev"`; (e) `run_all(cohort="final")` on a dir with no final scenarios → `{"results":[], "all_pass":True, "count":0}`. (Write real scenario JSON files under tmp_path via a helper; reuse the greeter-style toy.)
- [ ] **Step 2:** verify fail. **Step 3:** implement (validation allows cohort; load sets default; run_all filters + adds cohort/count; empty→all_pass True count 0). Update `scenario-format.md` with the `cohort` field (default dev; final = sealed holdout, run once, never fed back). **Step 4:** verify pass + full suite (178 + new, 1 skip). **Step 5:** commit `feat(dark-factory): scenario cohort field (dev/final) + cohort-filtered run_all`.

---

### Task 2: Supervisor — dev loop + sealed final-exam once + FINAL_EXAM_FAILED

**Files:**
- Modify: `dark-factory/scripts/supervisor.py`
- Create: `dark-factory/tests/fixtures/fake_builder_final` (executable)
- Create: `dark-factory/tests/test_final_exam.py`

**Interfaces:** Read the current `_run_loop`. Changes:
1. Each iteration's verify becomes `report = run_all(scenarios_dir, workspace, exec_wrapper=exec_prefix, env_extra=verify_env_extra, cohort="dev")`. Feedback, checkpoint, journal VERIFY all operate on **dev** exactly as today.
2. Replace the `if report["all_pass"]:` (CONVERGED) block: when **dev** all-passes, run the sealed final exam ONCE:
   ```python
   final = run_all(scenarios_dir, workspace, exec_wrapper=exec_prefix, env_extra=verify_env_extra, cohort="final")
   atomic_write(os.path.join(run_dir, "final_exam_report.json"), canonical_json(final))
   final_ran = final["count"] > 0
   journal.write("FINAL_EXAM", ran=final_ran, passing=sum(1 for r in final["results"] if r["pass"]), total=final["count"])
   fe = {"ran": final_ran, "passed": bool(final["all_pass"]) if final_ran else None, "count": final["count"]}
   if final_ran and not final["all_pass"]:
       journal.write("FINAL_EXAM_FAILED", failing=[r["behavior_id"] for r in final["results"] if not r["pass"]])
       mf = dict(mb_clean, outcome="FINAL_EXAM_FAILED", iterations=i, qualified=False, final_exam=fe)
       finalize_manifest(run_dir, mf, audit_key=audit_key); _clear_state(); _kb_writeback(cfg, journal, mf, [])
       print(f"dark-factory: FINAL-EXAM FAILED (artifact rejected; held-out scenarios not disclosed). Run: {run_dir}")
       return 3
   # dev converged AND (final passed OR no final cohort):
   journal.write("CONVERGED", iteration=i)
   eff = manifest_base.get("_effective_tier", "cooperative")
   outcome = "COMPLETE_QUALIFIED" if eff == "standard" else "COMPLETE_UNQUALIFIED"
   mf = dict(mb_clean, outcome=outcome, iterations=i, final_exam=fe)
   finalize_manifest(run_dir, mf, audit_key=audit_key); _clear_state(); _kb_writeback(cfg, journal, mf, [])
   print(...CONVERGED... + ("" if final_ran else " [no sealed final exam administered]"))
   return 0
   ```
   CRITICAL barrier: `project_feedback` is NEVER called on `final`; nothing from `final` is written to `workspace`; only behavior-IDs go to the journal. The final env uses the same reset twin env as dev's verify (fine — same phase).
3. Every other terminal (build error, twin error, cap, OracleError) is unchanged except: add `final_exam={"ran": False, "passed": None, "count": 0}` to their manifest dicts for a consistent schema (a non-converged run administered no exam).

- [ ] **Step 1:** Create `fixtures/fake_builder_final` — a builder whose greet.py passes the **dev** behaviors but deliberately fails a **final**-only behavior (e.g. dev checks `greet.py World`→`Hello, World!`; a final scenario checks an edge case like `greet.py ""` or a second behavior the builder gets wrong). Design the toy so dev converges but final fails, to exercise FINAL_EXAM_FAILED. Also confirm the normal `FAKE` builder passes both when the final cohort mirrors dev behaviors.
- [ ] **Step 2:** Write `test_final_exam.py`:
  - `test_dev_converges_then_final_passes_qualified_or_complete` — control with dev + final cohorts the builder satisfies; run converges (exit 0), manifest `final_exam.ran==True and passed==True`, journal has FINAL_EXAM.
  - `test_final_failure_is_terminal_and_not_fed_back` — using `fake_builder_final`: exit 3, journal ends `FINAL_EXAM_FAILED`, manifest outcome `FINAL_EXAM_FAILED` + qualified False; assert NO `feedback_iter_*` file references any final behavior and the final behavior-IDs never appear in any `prompt_iter_*.md` (barrier — final never fed back).
  - `test_no_final_cohort_back_compat` — a control with only dev (today's shape): converges exit 0, manifest `final_exam.ran==False`, stdout notes no sealed exam.
- [ ] **Step 3-4:** Implement; verify; full suite green (existing loop/manifest/e2e tests: some assert manifest fields — adding `final_exam` is additive; if a test asserts an exact manifest keyset it must be updated to include final_exam, which is legitimate). Confirm the barrier assertions pass.
- [ ] **Step 5:** commit `feat(dark-factory): sealed final-exam runs once, never fed back; FINAL_EXAM_FAILED is terminal`.

---

### Task 3: Regression tracking (green→red on dev)

**Files:**
- Modify: `dark-factory/scripts/supervisor.py`
- Create: `dark-factory/tests/test_regression.py`

**Interfaces:** In `_run_loop`, maintain `prev_dev_status: dict[behavior_id, bool]` across iterations (per behavior: did every scenario of that behavior pass this iteration). After each dev verify, compute this iteration's per-behavior pass map; any behavior that was True last iteration and is False now is a **regression** → `journal.write("REGRESSION", iteration=i, behavior_id=<id>)` (ID only — barrier-safe) for each. Record the set of regressed behavior-IDs seen across the run in the manifest as `regressions: [<behavior_id>...]` (sorted, deduped). This is informational + auditable; it does not change control flow (a regressed behavior is failing, so the loop already won't converge). Resume must reload `prev_dev_status` — simplest: persist it in `state.json` (add a `dev_status` field) so a resumed run compares against the pre-pause status; if absent (old state), start empty.

- [ ] **Step 1:** `test_regression.py`: a builder that passes behavior B in iteration 1 but breaks it in iteration 2 (create a fixture `fake_builder_regress` that flips) while another stays failing → assert a `REGRESSION` journal entry names B at iteration 2, and the final manifest `regressions` contains B. Also `test_no_regression_when_monotonic` — a normal converging run has empty `regressions`.
- [ ] **Step 2-4:** implement (compute per-behavior map, diff vs prev, journal, persist in state.json, aggregate to manifest); verify; full suite green.
- [ ] **Step 5:** commit `feat(dark-factory): track and journal dev-scenario regressions (green->red)`.

---

### Task 4: E2E + docs

**Files:**
- Create: `dark-factory/tests/test_e2e_final_exam.py`
- Modify: `dark-factory/SKILL.md`, `dark-factory/references/scenario-format.md`

- [ ] **Step 1:** `test_e2e_final_exam.py` — drive the supervisor CLI as a subprocess on a dev+final toy: (a) converges exit 0 with `final_exam.passed==True`; (b) a MARKER embedded in the FINAL scenarios' title/given NEVER appears in any prompt, any feedback file, or the workspace (the held-out exam stays hidden); (c) `verify-manifest` OK. A second run with `fake_builder_final` → exit 3, `FINAL_EXAM_FAILED`, and the final MARKER still never leaked. Guard nothing (cooperative tier, always runs).
- [ ] **Step 2:** SKILL.md: in the "Acceptance world" step, document authoring **dev** vs **final** cohorts (`"cohort":"final"` = sealed exam, run once after dev converges, never fed back; a final failure rejects the artifact); note a run with no final cohort administers no sealed exam (manifest `final_exam.ran=false`). Add to Hard rules: never feed final-exam results back; never author final scenarios in a builder-driving session.
- [ ] **Step 3:** verify docs vs code; full suite green; commit `test(dark-factory): e2e sealed final-exam hidden + terminal-on-fail; docs`.

---

## Self-Review Notes (plan ↔ spec)

**Covered (M6):** the dev/**sealed final-exam** split (§4.1/§15.3) with the exam run once after dev converges, **never fed back**, and **terminal on failure** (§15.4); regression tracking (green→red, §6/§15.3); unconditional 100% pass threshold; the barrier extended to cover final-cohort content; honest `final_exam.ran` labeling so a no-final run is not misread as having passed a sealed exam.

**Deliberately deferred:** verifier-only **hidden** final variants + secret seeds drawn post-artifact-freeze (§15.3 — needs M12's verifier-only twin/variant machinery); the **coverage gate** + **mutation validation** (M7 — proving the cohorts are complete and the checks non-inert). M6 makes the split real; M7 makes the checks trustworthy.

**Honesty note:** cohorts are author-labeled, not independently generated, so a lazy author could put weak scenarios in `final`; the coverage gate + mutation validation (M7) are what make "final passed" mean something. M6 states this and records `final_exam.ran` so the presence/absence of a real exam is always auditable.
```
