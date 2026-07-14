---
name: dark-factory
description: Use when the user wants to build a task/feature "dark-factory style" — the human writes a spec, an isolated builder agent implements it WITHOUT ever seeing the hidden acceptance scenarios, a verifier runs those scenarios, and only behavior-ID + failure-taxonomy feedback crosses back until convergence. Triggers on "dark factory", "dark-factory", "hidden tests", "holdout scenarios", "build without seeing the tests", or requests to prevent an AI builder from teaching to the test. Tiers: `cooperative` (honor-system, unqualified) and `standard` (OS read-denial sandbox — macOS/Linux — probe-verified and qualified). Per-iteration human checkpoints (pause/resume) at autonomy 4.
---

# dark-factory

Runs a StrongDM-style dark-factory loop: **spec in → hidden holdout scenarios
→ isolated builder (spec-only) → verifier → deterministic ID feedback → loop →
outcome**. Design spec: `docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md`
(Codex-approved). Two assurance tiers ship: **cooperative** (honor-system isolation — every run is explicitly UNQUALIFIED) and **standard** (OS read-denial sandbox on macOS/Linux, verified by a fail-closed startup denial probe — a converged run is QUALIFIED). Higher tiers (hardened/enterprise) are not yet backed and are refused.

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
   `references/config-reference.md` (builder adapter:
   `<skill_dir>/scripts/adapters/claude`).
   - `assurance`: `cooperative` (works everywhere, unqualified) or `standard` (real OS
     read-denial sandbox → qualified; needs macOS `sandbox-exec` or Linux `bwrap`, and a
     passing startup denial probe). If `standard` can't be honored, the run fails closed
     unless you pass `run --allow-downgrade` (→ cooperative, unqualified).
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
- A **cooperative** run is always UNQUALIFIED — say so. A **standard** run is qualified ONLY when its startup denial probe passed (manifest `qualified: true` / outcome `COMPLETE_QUALIFIED`); never call a cooperative, downgraded, aborted, or capped run a qualified ship-candidate — report the manifest's actual `qualified` value.

## References

- `references/config-reference.md` — config schema
- `references/scenario-format.md` — oracle IR v0
- `references/role-adapters.md` — adapter protocol
