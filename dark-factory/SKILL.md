---
name: dark-factory
description: Use when the user wants to build a task/feature "dark-factory style" — the human writes a spec, an isolated builder agent implements it WITHOUT ever seeing the hidden acceptance scenarios, a verifier runs those scenarios, and only behavior-ID + failure-taxonomy feedback crosses back until convergence. Triggers on "dark factory", "dark-factory", "hidden tests", "holdout scenarios", "build without seeing the tests", or requests to prevent an AI builder from teaching to the test. M1 walking skeleton: cooperative tier only (honor-system isolation, honestly unqualified).
---

# dark-factory (M1 walking skeleton)

Runs a StrongDM-style dark-factory loop: **spec in → hidden holdout scenarios
→ isolated builder (spec-only) → verifier → deterministic ID feedback → loop →
outcome**. Design spec: `docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md`
(Codex-approved). This milestone ships the **cooperative tier only**: isolation
is honor-system (no OS read-denial yet — that is M2), so every run is
explicitly **UNQUALIFIED** and can never claim a probe-proven barrier.

## Workflow (create one todo per step)

1. **Engage.** Announce the skill; offer opt-out. Ask which directory to use as
   the control root (MUST be outside the project repo and outside any workspace
   tree; suggest `~/.dark-factory/<project-name>`).
2. **Spec.** Interview the user → write `<control_root>/spec.md`. The user
   approves it. Behaviors should be numbered (BHV-001, BHV-002, …).
3. **Acceptance world — SEPARATE CONTEXT.** Author the holdout scenarios in
   `<control_root>/scenarios/*.json` (oracle IR v0 — see
   `references/scenario-format.md`) **in a different session/subagent than any
   builder work**, deriving them ONLY from spec.md. Never echo scenario content
   into the main conversation if the same conversation will drive the builder.
4. **Config.** Write `<control_root>/config.json` per
   `references/config-reference.md` (assurance MUST be `cooperative` in M1;
   builder adapter: `<skill_dir>/scripts/adapters/claude`).
5. **Run.** `python3 <skill_dir>/scripts/supervisor.py run --control-root <control_root> [--project-src <dir>]`
   Exit 0 = converged/accepted · 3 = cap reached · 2 = config/build/abort error ·
   **10 = paused at a checkpoint** (autonomy 4 / `checkpoint: pause`).
6. **At a checkpoint (exit 10).** Show the user `runs/<id>/checkpoint_iter_N.md` (per-behavior
   pass/fail — no scenario text). Then, on their decision, run:
   - **continue** → `supervisor.py resume --control-root <cr> --decision continue`
   - **adjust spec** → edit `<control_root>/spec.md`, then `resume --decision continue`
   - **accept** (stop, waived/unverified) → `resume --decision accept`
   - **abort** → `resume --decision abort`
   Repeat until exit 0/2/3.
7. **Report.** Outcome, iterations, per-behavior status from `journal.jsonl`, the workspace
   path, and `verify-manifest --run-dir <run_dir>`. State that cooperative tier is unqualified.

## Hard rules

- Scenario files and their content NEVER enter: the builder prompt, the
  workspace, the main builder-driving conversation, or any feedback.
- Only the supervisor writes run state. Do not hand-edit `runs/`.
- Secrets: never put credentials in config.json/spec.md/scenarios; the claude
  adapter uses your ambient login.
- This milestone cannot produce a qualified ship-candidate. Say so.

## References

- `references/config-reference.md` — config schema
- `references/scenario-format.md` — oracle IR v0
- `references/role-adapters.md` — adapter protocol
