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
   Also ask (optional, default none): do you have a **knowledge base** to draw on
   and record to? — a markdown **wiki** (give a directory path) or an **open-brain
   / MCP** memory. If a wiki: set `knowledge_base` in config.json; on `write_back:
   true` the supervisor appends a barrier-safe run summary (no scenario text) to
   `<path>/dark-factory-runs.md`. If open-brain: you (this session) may read it for
   grounding and, only with the user's OK, `capture_thought` the run outcome — the
   supervisor does not touch MCP. Absence of a KB is never an error.
2. **Spec.** Interview the user → write `<control_root>/spec.md`. The user
   approves it. Behaviors should be numbered (BHV-001, BHV-002, …).
3. **Acceptance world — SEPARATE CONTEXT.** Author the holdout scenarios in
   `<control_root>/scenarios/*.json` (oracle IR v0 — see
   `references/scenario-format.md`) **in a different session/subagent than any
   builder work**, deriving them ONLY from spec.md. Never echo scenario content
   into the main conversation if the same conversation will drive the builder.
4. **Config.** Write `<control_root>/config.json` per
   `references/config-reference.md`.
   - **Choose the builder model.** Run
     `python3 -c "import sys; sys.path.insert(0,'<skill_dir>/scripts'); import df_adapters, json; print(json.dumps(df_adapters.available_builders()))"`
     to see which of claude / codex / gemini are installed. Ask the user which model should BUILD; offer only the available
     ones. Set `roles.builder.adapter` to `<skill_dir>/scripts/adapters/<name>`.
     **No silent fallback** — if the chosen model's CLI is absent the run fails
     closed (`resolve_builder` raises; the run aborts). Verification stays the
     deterministic scenario runner regardless of builder — dark-factory has no LLM
     judge to swap.
   - **Vendor diversity (recommended, not required).** Author the spec and the
     holdout scenarios with a *different* model/session than the builder (e.g.
     Claude authors, Codex builds). Different vendors have different blind spots,
     which hardens the holdout — the "second librarian from a different library."
     Never author scenarios in the same session that will drive the builder.
   - `assurance`: `cooperative` (works everywhere, unqualified) or `standard` (real OS
     read-denial sandbox → qualified; needs macOS `sandbox-exec` or Linux `bwrap`, and a
     passing startup denial probe). If `standard` can't be honored, the run fails closed
     unless you pass `run --allow-downgrade` (→ cooperative, unqualified).
4b. **Twins (optional).** If the task's code talks to external services, define behavioral mocks in `<control_root>/twins/*.json` (see `references/digital-twins.md`) and set `twins.enabled: true` in config.json. The builder develops against the twins, and the verifier resets them fresh before each verify pass for deterministic verification. Results are **twin-observed** — you must validate against the real service or staging before shipping.
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
- Signed audit is opt-in (`audit.signing: true` in config); verify with `verify-manifest --key-path <path>`. A signed manifest with no key prints UNVERIFIED and exits non-zero (fail-closed) — never treat it as OK.

## Composing with other skills (control-plane only)

dark-factory's *builder* is an external sandboxed CLI that loads no skills — so
composition applies only to THIS orchestrating session's own steps, which run
around the builder, never inside it:

| Step | Prefer, if available | Barrier note |
|---|---|---|
| Author the spec (step 2) | `superpowers:brainstorming`, `grill-me-codex`, `writing-plans` | fine — spec is SHARED with the builder |
| Author scenarios (step 3) | keep manual, in a **separate session** | never delegate this into a builder-driving session |
| Stuck loop (cap reached, likely spec ambiguity) | `superpowers:systematic-debugging` | operates on spec + behavior IDs only, never scenario internals |
| Cleanup an accepted artifact | `/simplify`, `code-review` on the workspace | post-acceptance, outside the barrier |

**Honesty:** at `cooperative`/`standard` tiers this is *guidance*, not enforcement —
these tiers sandbox the builder, not the orchestrator. An **enforced** per-tier skill
allowlist with content-hash pinning (spec §3B) requires the orchestrator itself to run
sandboxed, which is a `hardened`/`enterprise` capability (not yet built). Never author
or reveal holdout scenarios in a session that will also drive the builder.

## References

- `references/config-reference.md` — config schema
- `references/digital-twins.md` — twin definition, lifecycle, and honest scope (M3a)
- `references/knowledge-base.md` — KB integration (optional, spec §3A)
- `references/scenario-format.md` — oracle IR v0
- `references/role-adapters.md` — adapter protocol
