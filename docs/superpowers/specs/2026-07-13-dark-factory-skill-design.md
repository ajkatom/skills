# dark-factory — skill design spec

**Date:** 2026-07-13
**Status:** Approved design → ready for implementation planning
**Repo:** personal `skills` (symlinked into `~/.claude/skills`, like `loop-designer`)

## 1. Summary

`dark-factory` is a **process skill** that wraps any task or plan into a miniature
"dark factory" run — the [Level 5 operating model](#12-source-grounding) where **no
human writes or reviews code**: the human writes/approves a spec and evaluates
outcomes; agents build and review the code behind an information barrier.

The skill orchestrates this pipeline:

> **spec → hidden holdout scenarios + shared digital twins → isolated builder (spec-only) → verifier runs scenarios in the twin universe → filtered feedback → loop → outcome checkpoint (human evaluates actual results).**

The two non-negotiable requirements (from the user) are baked into the mechanism:

1. **Tests are scenarios** — behavioral acceptance specs, not unit tests of internals.
2. **The builder cannot see the tests before/while building**, so it cannot influence
   ("teach to") the build. Enforced by a real information barrier, not an honor-system
   instruction.

### 1.1 Goals

- Turn a spec into shipped-candidate software via an autonomous build/verify loop the
  human only *supervises at outcome checkpoints*.
- Make the acceptance criteria **un-gameable** by hiding them from the builder (an
  ML-style holdout set).
- Test end-to-end against a **digital twin** universe, never production.
- Let the user **assign each role to a different tool/model** (e.g. Claude plans,
  Codex builds, Gemini tests) — their decision, with principled defaults.
- Work out of the box with all-Claude; degrade gracefully when other CLIs are absent.

### 1.2 Source grounding

All from the user's second-brain vault (`~/Projects/ai_projects/second_brain/`),
ingested 2026-07-13 from the video *"The 5 Levels of AI Coding"* (Nate B Jones,
citing Dan Shapiro's ladder and StrongDM's factory):

- `wiki/concepts/dark-factory.md` — the two hard mechanisms; brownfield limits.
- `wiki/concepts/vibe-coding-levels.md` — the L0–L5 maturity ladder (the level dial).
- `wiki/entities/strongdm.md` — the documented L5 factory; scenarios + twins as the
  **two co-equal architectural ideas**.
- `wiki/concepts/verification-loop.md` — "the check must be external to the thing
  being checked"; scenarios as holdout; pull external ground-truth signal.
- `wiki/concepts/cross-model-orchestration.md` — the division of labor (strongest
  reasoner plans, token-efficient model builds, different-vendor critic) and the
  "bounded iteration / termination rule" discipline.
- `wiki/concepts/ai-coding-adoption-gap.md` — why the bottleneck moves to spec quality.

The SKILL.md should cite these so the skill stays grounded in the user's own notes.

### 1.3 Non-goals

- Not a general-purpose test framework. Scenarios are acceptance-level and behavioral.
- Does **not** merge or deploy. The accepted candidate is handed back; merging/deploy
  is a human action (and a gated one).
- Does **not** run unbounded/unattended cloud loops. Bounded by a hard iteration cap;
  scheduling/routines remain `loop-designer` / `/schedule` territory.
- Does **not** claim cryptographic isolation (see [§8](#8-honest-limits-of-isolation)).
- Does not replace `loop-designer` — it *runs* one specific verify loop; `loop-designer`
  *designs* loop mixes. They compose.

## 2. The pipeline and the information barrier

Three planes. The whole design turns on **what each plane can see**.

```
      ┌──────────── CONTROL PLANE (holdout-bearing) ─────────────┐
YOU → │  spec.md (shared) · config · scenarios/ [HOLDOUT] · twins/ │
spec  └─────┬──────────────────────┬──────────────────┬──────────┘
            │ spec + twins          │ scenarios+build  │ ACTUAL
            ▼ (never scenarios)     ▼                  │ outcomes
     ┌── BUILD PLANE ──┐    ┌── VERIFY PLANE ──┐        │
     │ isolated worktree│   │ run scenarios vs │────────┘
     │ builder = tool X │◄──│ build in twin env│
     │ spec-only        │   │ → verifier-report│
     └──────────────────┘   └───────┬──────────┘
           ▲ filtered behavioral     │ fail
           │ summary only ───────────┘
           └─ loop until pass / cap → OUTCOME CHECKPOINT → you evaluate
```

### 2.1 Visibility matrix (the core invariant)

| Artifact | Planner | Test authority | Builder | Verifier | Human |
|---|:--:|:--:|:--:|:--:|:--:|
| **Spec** | writes | reads | reads | reads | owns/approves |
| **Digital twins** | | writes | reads (builds against) | reads (runs in) | |
| **Scenarios (holdout)** | | writes | **✗ HIDDEN** | reads (runs) | reads |
| **Actual outcomes** | | | **✗ filtered feedback only** | writes | reads |

The ML analogy done properly: the **environment/schema is shared** (twins) so the
builder can develop and integration-test; the **test set is held out** (scenarios) so
it cannot overfit. Everything hinges on the builder never receiving `scenarios/` — in
its context *or* its filesystem.

## 3. Roles (pluggable across tools/models)

Four agent roles + the human. Each maps to a tool the user chooses; the skill ships a
thin **adapter** per tool describing how to invoke it in a working directory and
capture its output.

| Role | Responsibility | Default tool | Constraint |
|---|---|---|---|
| **Planner** | Interviews the human, drafts the detailed spec (Karpathy method: uncover the goal, spec agilely, be precise). Human owns/approves. | Claude (strongest reasoner) | — |
| **Test authority** | Owns the entire hidden acceptance world: authors **scenarios** (holdout) **and** builds/collects **twins** (shared). | Claude | **must ≠ Builder** (warn/refuse) |
| **Builder** | Implements from the **spec only** (+ filtered feedback), in the isolated workspace. Never sees scenarios. | Claude subagent | isolated cwd |
| **Verifier** | Runs the scenarios against the build in a fresh twin universe; writes **actual outcomes**. | Claude | — |

### 3.1 Principled defaults (from `cross-model-orchestration`)

Defaults are all-Claude (works immediately). The recommended cross-model mapping — and
the *why* — is documented so the user can opt in:

- **Planner = strongest reasoner** (Claude) — planning quality gates the whole run.
- **Test authority = different vendor from Builder** — blind-spot diversity ("a second
  librarian from a different library") makes the holdout harder to game.
- **Builder = token-efficient adequate model** (Codex/GPT) — execution burns the most
  tokens; delegate it to the cheaper capable model.
- **Verifier = ideally a different vendor from Builder** — independent grader.

The user's example ("Claude plans, Codex builds, Gemini tests") is exactly this pattern
and is just a config edit. Cross-model adapters require those CLIs installed; the skill
detects absence and falls back to Claude with a note.

## 4. Two verification pillars

Neither works alone: scenarios with no environment can't run end-to-end; twins with no
scenarios have nothing to assert.

### 4.1 Holdout scenarios (the *what*)

- **Format:** behavioral, `Given / When / Then`, one scenario per behavior, in
  markdown. Assert **observable behavior**, never internal units.
- **Storage:** control plane only (`.dark-factory/scenarios/`), gitignored so a
  `git worktree` checkout never contains them. Never copied into the build workspace.
- **Derivation:** the Test authority writes them from the spec, independently of the
  builder.

### 4.2 Digital twins (the *where*)

- **What:** behavioral clones of every external service the software touches (e.g.
  simulated Okta/Slack/Jira/DB/HTTP APIs), giving a safe, reproducible, prod-free world.
- **Scaling:** full service clones for integration-heavy tasks; a **minimal
  deterministic harness/fixtures** for a self-contained/offline task — but a twin layer
  is **always present** as the reproducible env (it is a first-class pillar, not an
  optional add-on).
- **Visibility:** **shared** — the builder develops and self-tests against the twins;
  the verifier runs the hidden scenarios against the build in a **freshly reset** twin
  universe to produce actual outcomes.
- **Detection:** external services are inferred from the spec; the user confirms/edits
  the list.

## 5. The level dial (from `vibe-coding-levels`)

The skill runs the **Level 5 machinery** (agents write *and* review code). How far the
human steps back is a dial off Shapiro's ladder:

- **Level 4 — developer as product manager (default).** The human evaluates **actual
  outcomes at every iteration checkpoint** and may adjust the spec mid-run. This matches
  the user's chosen "orchestrate + outcome checkpoints" behavior.
- **Level 5 — lights-off.** The loop runs to convergence (or the cap) untouched; the
  human evaluates outcomes **once at the end**.
- **Optional L4→L5 ramp:** checkpoint every iteration at first, widen the interval as
  trust in the spec/twins builds.

## 6. The build/verify loop and checkpoints

Per iteration:

1. **Builder** implements from spec (+ prior `feedback.md`) in the isolated workspace.
2. **Verifier** runs all scenarios against the build in a fresh twin universe →
   `runs/run-N/verifier-report.md` with **actual outcomes** (per-scenario pass/fail,
   observed behavior, artifacts/logs) — never the builder's self-report.
3. **All pass** → candidate ready. **Else** → `filter-feedback` produces
   `runs/run-N/feedback.md` (per the leakage policy) and the loop repeats.
4. **Checkpoint** per the level dial (L4: after each iteration; L5: at end). The human
   sees actual outcomes and chooses: **accept · adjust spec · continue · abort.**

**Termination:** hard `max_iterations` cap (default 5, echoing the cross-model
"bounded iteration / termination rule"). Reaching the cap without full pass is itself an
outcome the human evaluates.

### 6.1 Failure-feedback (anti-gaming) policy

When a scenario fails, what returns to the builder is **configurable**, default
**behavioral**:

- **`count`** — only "N of M scenarios still failing." Maximum holdout integrity; risk
  of slow/stalled convergence.
- **`behavioral` (default)** — a spec-level description of the wrong observed behavior
  ("after submitting the reset form, no email arrives"), with the scenario's literal
  text, inputs, and assertions **stripped**. Preserves the holdout while letting the
  loop converge (StrongDM-style).
- **`full`** — the failing scenario verbatim. Fastest convergence but hands the builder
  the test → overfitting → defeats the holdout. Provided only for completeness/debugging.

`filter-feedback` is a **security-critical** step: it must reliably strip holdout
content. Implemented as a small deterministic script plus a tightly-constrained model
call, not free-form summarization.

## 7. Greenfield vs. brownfield

The source is explicit that you **cannot dark-factory a legacy/brownfield repo** ("the
system *is* the specification"). The skill therefore **detects** which it is and never
pretends legacy is greenfield:

- **Greenfield** (empty/new target) → full pipeline as above.
- **Brownfield** (existing non-trivial codebase) → runs the **incremental path** first
  and warns the human: (1) reverse-engineer a spec + scenario/holdout suite from the
  running system; (2) stand up twins for its external dependencies; (3) only then run
  new work through the L4/L5 loop alongside the maintained legacy. The skill states the
  reduced guarantees plainly rather than overclaiming.

## 8. Honest limits of isolation

The barrier's strength depends on the setup, and the skill documents this rather than
overclaiming:

- **Strong:** cross-vendor builder in its own sandbox (e.g. Codex `--yolo` sandbox), or
  any builder in a container with filesystem scoping. The builder process never receives
  the scenarios path.
- **"Holdout in practice":** same-machine, same-model (Claude subagent) builder. The
  scenarios are absent from its context and its worktree, but a builder with shell
  access could in principle traverse the filesystem. Mitigations: gitignored control
  plane so the worktree lacks it; the scenarios path is never passed; an explicit
  "operate only within your workspace" instruction. **Not** cryptographically sealed.

This honest framing is itself a deliverable (a `references/isolation.md`).

## 9. Packaging

**Chosen approach: hybrid (C).** Considered alternatives:

- **A. Prose-only** (like `loop-designer`) — simplest, but isolation and feedback
  filtering would rely on the model doing it correctly every run. Rejected: the barrier
  must be mechanical.
- **B. Fully script-backed** — most deterministic, most to build/maintain. Overkill for
  the judgment-heavy steps (spec interview, scenario authoring, outcome evaluation).
- **C. Hybrid (selected)** — `SKILL.md` orchestrates; **prose** for judgment steps;
  **small helper scripts for the deterministic, security-critical steps**: workspace
  isolation, the feedback filter, and the tool adapters. Best balance of *real*
  isolation and maintainability.

### 9.1 File layout

Skill (in the repo, symlinked to `~/.claude/skills/dark-factory`):

```
dark-factory/
  SKILL.md                     # orchestrator: the workflow below, + guardrails
  references/
    scenario-format.md         # Given/When/Then holdout scenario spec + examples
    digital-twins.md           # twin patterns per service; minimal-harness fallback
    role-adapters.md           # how each tool fills each role; cross-model defaults
    isolation.md               # the barrier, worktree mechanics, honest limits
    brownfield.md              # the incremental path
    config-reference.md        # config.yml schema
    example-run.md             # a full worked walkthrough (like loop-designer)
  scripts/
    isolate-workspace.sh       # git worktree + copy spec/twins, exclude scenarios
    filter-feedback.*          # strip holdout content → behavioral summary
    run-scenarios.*            # execute scenarios against build in twin env
    adapters/                  # claude / codex / gemini invocation wrappers
```

Control plane, created per project (gitignored):

```
.dark-factory/
  config.yml                   # level, leakage, max_iterations, role→tool map, twins
  spec.md                      # human-owned spec (SHARED)
  twins/                       # digital twins (SHARED)
  scenarios/                   # HOLDOUT — never enters the build workspace
  runs/run-N/{verifier-report.md, feedback.md, status.md}
  DARK-FACTORY.md              # manifest / how to drive the run
```

Build plane: an isolated `git worktree` at a path outside the main tree, containing the
code + copied-in `spec.md` + `twins/`, and **no** `scenarios/`.

### 9.2 Config schema (sketch)

```yaml
level: 4                       # 4 = checkpoint each iteration; 5 = lights-off
leakage: behavioral            # count | behavioral | full
max_iterations: 5
roles:
  planner:        { tool: claude }
  test_authority: { tool: claude }            # scenarios + twins; must ≠ builder
  builder:        { tool: claude, mode: subagent }   # e.g. { tool: codex }
  verifier:       { tool: claude }            # e.g. { tool: gemini }
twins:
  services: []                 # auto-detected from spec; human confirms
```

## 10. Workflow the skill follows (one todo per step)

1. **Engage + classify.** Announce dark-factory is engaging (offer opt-out). Detect
   greenfield vs brownfield; infer external services for twins.
2. **Spec (Planner).** If none, interview the human → `spec.md`; human approves. If a
   plan/spec exists, load and confirm it.
3. **Config.** Write/confirm `config.yml`. **Warn if `builder == test_authority`.**
4. **Acceptance world (Test authority).** Author holdout **scenarios** +
   build/collect **twins**. Scenarios stay in the control plane.
5. **Isolate.** `isolate-workspace` creates the build worktree with spec + twins, no
   scenarios.
6. **Loop** (§6): build → verify (actual outcomes) → filtered feedback → repeat until
   pass or cap, checkpointing per level.
7. **Outcome checkpoint / hand-off.** Present actual outcomes; human evaluates and
   accepts/adjusts/aborts. Accepted candidate is handed back (human merges).
8. **Record.** Persist the run log; optionally capture learnings to the second brain.

## 11. Guardrails

- **Builder ≠ Test authority** (warn/refuse) — else the holdout is self-authored.
- **Scenarios never enter** the build workspace or the builder's context; only filtered
  behavioral feedback crosses the barrier.
- **Verifier reports actual outcomes** (evidence/artifacts), never the builder's
  self-report — aligns with `verification-before-completion`.
- **Twins only** in the loop — never real production, credentials, or data.
- **Bounded iteration** — hard cap; reaching it is a human-evaluated outcome.
- **Brownfield honesty** — never treat legacy as greenfield; run the incremental path.
- **Isolation honesty** — document the practical strength of the barrier for the chosen
  setup; never overclaim a seal.

## 12. Success criteria (for the skill itself)

- Given a greenfield task + approved spec, the skill produces a build whose **actual**
  scenario outcomes are presented to the human, with the builder **demonstrably** never
  having received the scenarios (verifiable: the build workspace contains no
  `scenarios/`; the builder's dispatched context excludes them).
- Roles are reconfigurable to different tools via `config.yml`; all-Claude works with no
  extra CLIs; cross-model works when the CLIs are present.
- The level dial changes checkpoint cadence (L4 per-iteration vs L5 end-only).
- Failure feedback to the builder honors the leakage policy (default behavioral;
  holdout content stripped).
- Brownfield input triggers the incremental path + warning, not a false greenfield run.

## 13. Open items to resolve during planning

- Exact adapter contract (stdin/stdout, workdir, timeout) shared by claude/codex/gemini.
- `filter-feedback` implementation split (deterministic strip vs. constrained model call)
  and how it is tested (it is itself security-critical).
- Scenario runner: how scenarios (behavioral markdown) are executed — a lightweight
  interpreter/harness vs. generated executable checks — while keeping them tool-agnostic.
- Whether the worked example ships greenfield-only or also a brownfield walkthrough.
```
