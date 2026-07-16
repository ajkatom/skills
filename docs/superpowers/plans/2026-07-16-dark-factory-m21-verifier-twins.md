# dark-factory M21 — Verifier-Only Twin Implementations + Fidelity Surfacing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Generalize M12's verifier-only variant *seeds* into a verifier-only twin *implementation*: a twin may declare a separate `verify_launch` — a **different, spec-conformant mock used only during verification passes** — so a builder that overfit the build-time twin's specific behavior FAILS verification. Plus surface each twin's human-declared **fidelity** label on the manifest (so a reader sees what honesty level the run's twins claimed), and record which twins used a verifier-only implementation. Additive to M12; measured real-vs-twin fidelity scoring stays deferred (needs the real service — documented).

**Architecture:** `df_twins.load_defs` accepts an optional `verify_launch` (same shape/validation as `launch`). `TwinSet.start(defs, run_dir, timeout_s, extra_env=None, phase="build")` uses `verify_launch` when `phase=="verify"` and it is defined, else `launch`; the supervisor already resets twins before each verify pass — it passes `phase="verify"` there and `phase="build"` at build-start. The variant-seed machinery (M12) is unchanged and composes (a verify twin can ALSO support variant seeds). The manifest gains a `twins` field: a list `[{"name", "fidelity", "verify_only_impl": bool, "supports_variants": bool}]`, threaded on every terminal like M12's `twin_evidence`. Barrier unchanged: `verify_launch` and its behavior are control-plane; nothing new reaches the builder.

**Honest scope (stated in docs):** `verify_launch` is the AUTHOR's separate implementation — dark-factory runs it at verify time but cannot check it is truly spec-conformant (author's judgment, same as any twin). It strengthens anti-hardcoding (a builder can't overfit a mock it can't see at verify) but does NOT measure fidelity to a real service — a numeric real-vs-twin fidelity SCORE needs the real service and stays deferred (digital-twins.md). Fidelity here is the human label surfaced for audit, not a computed metric.

**Tech Stack:** Python stdlib. pytest. `.venv/bin/python -m pytest dark-factory/tests -v` from repo root `/Users/alonadelson/Projects/ai_projects/skills`.

## Global Constraints

- **Additive + back-compat:** a twin with no `verify_launch` behaves EXACTLY as M12 (build twin reused at verify). All existing twin tests + the 926 suite stay green.
- **Barrier:** `verify_launch`/its responses/the fidelity labels NEVER reach the builder (no env/prompt/feedback). The builder only ever sees the build-phase twin env (M12 already forwards only DF_TWIN_* endpoints, which point at whichever impl is running that phase).
- **Fail-closed lifecycle:** a `verify_launch` that fails to start / not ready within timeout → the verify pass aborts with the existing twin-precondition error (TWIN error → non-zero), exactly like a failing `launch`; always process-group reaped (M5a discipline). Never a vacuous pass.
- **Variant seeds compose:** if a twin has BOTH `verify_launch` and `supports_variants`, the verify impl receives the per-pass DF_TWIN_VARIANT_SEED (M12) too.
- **Manifest additive:** `twins` field on every terminal (fresh + resume), values are names/labels/flags only — no twin response data.
- **Commit messages end with:** `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`.

## File Structure

```
dark-factory/
  scripts/
    df_twins.py       # Task 1 — verify_launch def + phase-aware start
    supervisor.py     # Task 2 — phase wiring + manifest twins field
  references/
    digital-twins.md  # Task 2 — verify_launch + fidelity surfacing + honest scope
  tests/
    test_df_twins.py            # Task 1 (extend)
    test_e2e_verifier_twin.py    # Task 2
    fixtures/twin_build_*, twin_verify_*  # Task 2
```

---

### Task 1: df_twins verify_launch + phase-aware start

**Files:** modify `df_twins.py`; extend `dark-factory/tests/test_df_twins.py`.

**Interfaces:**
- `load_defs`: optional `"verify_launch"` — if present, validate as a non-empty `list[str]` (same rule as `launch`); a non-list/empty/non-str-element → `TwinError`. Absent → def has no verify_launch (build launch reused).
- `TwinSet.start(defs, run_dir, timeout_s, extra_env=None, phase="build")`: for each def, the argv used is `d["verify_launch"]` iff `phase == "verify"` and `d` has a truthy `verify_launch`, else `d["launch"]`. Everything else (endpoint file, observer file, extra_env/seed, readiness, pgid capture, reaping) unchanged. `reset(defs, run_dir, timeout_s, extra_env=None, phase="verify")` forwards `phase` (default "verify" — reset is only ever called before verify passes).
- Add `TwinSet.phase_launched: {name: "build"|"verify"}` (or record on start) so a test/manifest can confirm which impl ran. Keep it simple: a dict attribute set at start.

- [ ] **Step 1 (TDD):** extend `test_df_twins.py` — load_defs accepts a valid `verify_launch`; invalid (`[]`, non-list, non-str element) → TwinError; `start(phase="build")` launches `launch`, `start(phase="verify")` launches `verify_launch` when defined (use two tiny fixture twins that report which impl they are via their endpoint/observation), and falls back to `launch` at verify when `verify_launch` absent; `phase_launched` records the choice; a `verify_launch` that never becomes ready → TwinError + reaped (no orphan). Existing df_twins tests green (default phase="build", no verify_launch → byte-identical).
- [ ] **Step 2:** Implement → green. Full suite (926 + new).
- [ ] **Step 3:** Commit `feat(dark-factory): twin verify_launch — a verifier-only twin implementation (phase-aware start)`.

---

### Task 2: supervisor phase wiring + manifest twins field + e2e + docs

**Files:** modify `supervisor.py`, `references/digital-twins.md`; create `dark-factory/tests/test_e2e_verifier_twin.py` + build/verify twin fixtures.

**Interfaces:**
- `supervisor`: at twin BUILD-start pass `phase="build"`; at each verify reset (dev cohort AND sealed final exam) pass `phase="verify"` (so the verify passes use `verify_launch` when defined). The M12 variant-seed extra_env still flows to the verify reset. Confirm the BUILDER's env (`build_env_extra`) comes from the BUILD-phase start (build impl) — never the verify impl.
- Manifest `twins` field: `[{"name", "fidelity": <def fidelity str or "">, "verify_only_impl": bool(def has verify_launch), "supports_variants": bool}]` sorted by name, on every terminal (fresh + resume), threaded like `twin_evidence`. When twins disabled → `twins: []` or None (match the M12 `twin_evidence` disabled convention).

- [ ] **Step 1:** `test_e2e_verifier_twin.py` (CLI subprocess): a control with a twin that has BOTH `launch` (build impl returns a FIXED marker value) and `verify_launch` (verify impl returns a DIFFERENT spec-conformant value), and a scenario whose assertion depends on the twin's value:
  - **(a) honest builder converges:** a reference builder whose app CALLS the twin (uses whatever value the running twin returns) → converges (at verify it correctly uses the verify impl's value).
  - **(b) overfit builder rejected:** a reference builder whose app HARDCODES the build impl's fixed marker (as if it overfit the build twin) → at verify the verify impl returns a different value, the scenario fails wrong_output, run does NOT converge (CAP_REACHED/exit 3). This is the point of verify_launch — proves a builder can't overfit a mock it can't see at verify.
  - Assert the manifest `twins` field records `verify_only_impl: true` + the fidelity label; no orphan twin processes after.
- [ ] **Step 2:** `digital-twins.md`: the `verify_launch` verifier-only implementation (what it defends against — overfitting a mock the builder can't see at verify; composes with variant seeds), the manifest `twins`/fidelity surfacing, and the honest scope (author-supplied impl, not checked for conformance; fidelity is a label not a measured score; real-vs-twin fidelity scoring still deferred). Cross-check config/scenario docs.
- [ ] **Step 3:** Verify docs vs code; full suite green; commit `feat(dark-factory): verifier-only twin impl e2e (overfit builder rejected) + manifest twins/fidelity + docs`.

---

## Self-Review Notes (plan ↔ spec)

**Covered (M21 / residue #11):** verifier-only twin IMPLEMENTATIONS (`verify_launch`) — a different mock at verify time than build, generalizing M12's variant seeds to defend against a builder overfitting a mock it can't see at verify (spec §7.4 "vary twin inputs the candidate can't predict"); per-twin fidelity + verify-only-impl surfaced on the manifest for audit; fail-closed lifecycle + barrier + variant-seed composition preserved.

**Deliberately deferred (honest, in digital-twins.md):** a MEASURED real-vs-twin fidelity score + drift detection (needs the real service — unchanged deferral from M3a/M12); auto-checking that `verify_launch` is truly spec-conformant (author's judgment, same as any twin); a library of built-in twin implementations (authors supply their own).

**Honesty note:** `verify_launch` strengthens anti-hardcoding but is the author's own implementation — dark-factory runs it, doesn't vouch for its conformance; the surfaced fidelity is a human label for audit, explicitly NOT a computed metric.
