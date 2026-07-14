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
- **Be transferable.** No hard dependency on any knowledge system — the skill is
  self-contained; a second-brain wiki or open-brain MCP is an *optional* integration the
  skill asks about at invocation and uses only if present.
- **Compose, don't reinvent.** dark-factory is an orchestrator: at each step it may
  **invoke any other available skill** best suited to the sub-task (spec, build, verify,
  debug…), falling back to built-in behavior when that skill isn't installed. Skills are
  an enhancement, never a hard dependency (§3B).

### 1.2 Design provenance (not a runtime dependency)

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

These pages informed the *design*; their **concepts are embedded directly into the
skill's own `references/`**, so the skill is fully self-contained and does **not** read
this vault at runtime (see §1.3 and §3A). This design doc cites them for provenance only.

### 1.3 Non-goals

- Not a general-purpose test framework. Scenarios are acceptance-level and behavioral.
- Does **not** merge or deploy. The accepted candidate is handed back; merging/deploy
  is a human action (and a gated one).
- Does **not** run unbounded/unattended cloud loops. Bounded by a hard iteration cap;
  scheduling/routines remain `loop-designer` / `/schedule` territory.
- Does **not** claim cryptographic isolation (see [§8](#8-honest-limits-of-isolation)).
- Does not replace `loop-designer` — it *runs* one specific verify loop; `loop-designer`
  *designs* loop mixes. They compose.
- **Requires no external knowledge system.** The user's second brain, Obsidian wiki, or
  open-brain MCP are *optional* integrations (§3A) detected by asking at invocation —
  never a prerequisite. The skill ships self-contained so it is shareable with anyone.

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

## 3A. Optional knowledge-base integration (wiki / open-brain)

**The skill must be transferable to people who have never set up a second brain**, so it
is **self-contained by default** — every concept it needs (the two pillars, the barrier,
the level dial, the roles) lives in its own `references/`, not in any external vault.

At invocation the skill **asks whether the user has a knowledge base to draw on and
record to**, and adapts:

- **Obsidian / markdown wiki** — the user supplies a path. The skill may *read* relevant
  concept pages for extra grounding and, **only with per-run confirmation**, *write* a
  run summary / learnings back.
- **open-brain / MCP memory DB** — if such an MCP tool is present, the skill may
  `search` / `search_thoughts` for relevant context and, **with confirmation**,
  `capture_thought` the outcome.
- **None (default)** — the skill runs fully self-contained; learnings stay only in the
  local `.dark-factory/runs/` log.

Reading is automatic when a base is present; **writing back is always opt-in** (it
mutates the user's notes). Absence of a wiki/open-brain is never an error and never
blocks a run. The skill asks once at invocation and records the answer in `config.yml`.

## 3B. Skill composition (orchestrate, don't reinvent)

dark-factory is an **orchestrator**: at each step it **prefers to delegate to the best
available skill**, falling back to built-in logic when that skill isn't installed — so it
stays standalone and transferable (same principle as KB-optional and CLI-optional). It
discovers skills from the available-skills list (or `find-skills`) and records which it
used (feeds the audit trail).

| Step / role | Prefer skill(s) if present | Built-in fallback |
|---|---|---|
| Spec (Planner) | `brainstorming`, `grill-me-codex` / `grill-with-docs-codex`, `writing-plans` | Karpathy-style interview |
| Scenarios + twins (Test authority) | `writing-skills` patterns, project test skills | built-in templates |
| Build (Builder) | `codex-build` (Codex), `subagent-driven-development` / `executing-plans`, `test-driven-development` | direct subagent build |
| Verify (Verifier) | `/verify`, `everything-claude-code:e2e`, `code-review` / `security-review` | built-in scenario runner |
| Stuck loop | `systematic-debugging` | spec-ambiguity escalation (§6) |
| Cleanup / setup | `/simplify`, `loop-designer`, `/schedule` | inline |

Two rules keep composition safe:

1. **Delegation respects the barrier.** A skill invoked in the build plane inherits that
   plane's restricted context — it is never handed, and cannot reach, the holdout
   scenarios or actual outcomes. So a builder calling `/verify` self-checks only against
   **shared twins + spec**; real verification stays in the Verifier plane. Delegation
   never crosses a plane boundary.
2. **Delegated gated actions still checkpoint.** If a called skill would commit / push /
   deploy / schedule, dark-factory pauses for the human — delegation never bypasses the
   outcome checkpoint, the secrets guardrail, or isolation. It **never invokes itself**.

**Honest limit:** the orchestrator and Claude subagents can call Claude skills directly;
cross-model roles (Codex/Gemini) use their own command systems — `codex-build` is the
bridge for a Codex builder.

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
- **Coverage gate (Gap 1).** A holdout is only as good as its completeness. Before any
  build, every behavior in the spec must **trace to ≥1 scenario** (the Test authority
  produces the map), and a **critic — a different model or the human — reviews adequacy**
  and adds missing edge cases. No build starts until coverage is accepted.
- **Two-tier holdout (Gap 2).** Scenarios are split at authoring time into **dev
  scenarios** (drive iteration feedback) and a **sealed final-exam set** — a held-back
  fraction (`final_exam_fraction`, default 0.3) that is **never fed back** and is run
  **once at the very end**. Ship-candidate must pass both. This is the ML train/dev/**test**
  split: without a sealed set, "passing" partly measures overfitting to leaked feedback.

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

**Before the loop:** the scenario **coverage gate** (§4.1) must pass — no build starts
until every spec behavior traces to a scenario and the coverage review is accepted. On
**any** later spec edit (e.g. at an L4 checkpoint), the Test authority **re-syncs
scenarios** and re-runs the gate before building again (Gap 4) — a spec change silently
orphans scenarios otherwise.

Per iteration:

1. **Builder** implements from spec (+ prior `feedback.md`) in the isolated workspace.
2. **Verifier** runs all scenarios against the build in a fresh twin universe →
   `runs/run-N/verifier-report.md` with **actual outcomes** (per-scenario pass/fail,
   observed behavior, artifacts/logs) — never the builder's self-report.
3. **Track status across iterations (Knob B).** Per-scenario pass/fail is carried
   run-to-run; a **regression** (green→red) is flagged and blocks a ship-candidate. When
   all **dev scenarios** pass, run the **sealed final-exam set once** (§4.1) — it must
   also pass. **Else** → `filter-feedback` produces `runs/run-N/feedback.md` (per the
   leakage policy) and the loop repeats.
4. **Checkpoint** per the level dial (L4: after each iteration; L5: at end). The human
   sees actual outcomes and chooses: **accept · adjust spec · continue · abort.** The
   **pass threshold** defaults to 100% of dev + 100% of final-exam (`pass_threshold`).

**Termination:** the loop ends on full pass, the hard `max_iterations` cap (default 5,
echoing the cross-model "bounded iteration / termination rule"), or the budget cap
(§6.2). Reaching a cap without full pass is a human-evaluated outcome. A **persistent
failure pattern at the cap is surfaced as "likely spec ambiguity/contradiction — human
decision needed"** (Gap 4), naming the conflicting behavior — not a bare "failed"; a
stuck loop may delegate to `systematic-debugging` (§3B).

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

### 6.2 Budget, alerts, and resuming (Knob A)

Cost is bounded alongside the iteration cap, and the cap is a **human off-ramp, not a
silent kill**:

- **`billing: api` (metered).** Track estimated tokens/USD. **At 85% of any cap, alert**
  the user (a warning; the run continues). **At 100%, pause and preserve state**, then
  offer: **raise the cap and resume from the exact point**, accept the current build, or
  abort. Nothing is discarded on a budget stop.
- **`billing: subscription` (flat-rate plan).** A USD cap is meaningless, so dark-factory
  **only alerts** — usage / iteration / token milestones — and lets the user watch their
  own plan limits. No enforced $ pause.
- The **85% alert and 100% pause fire even in L5 lights-off** — a cost overrun is exactly
  what you don't run past unattended. Runs are **resumable**: state (iteration, per-
  scenario status, worktree, spend) lives in `runs/run-N/`, so raising a cap continues
  the same run rather than restarting.

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

### 8.1 Builder blast-radius sandbox (Gap 5)

Isolating the *tests* from the builder is not the same as controlling what the autonomous
builder can *do*. The builder runs in a **scoped sandbox**: filesystem confined to its
worktree, **network egress default-deny** (allowlist package registries only), no reach
into the parent repo, other projects, or credentials, plus resource/time caps. Strongest
via a container or the Codex `--yolo` sandbox; when only a bare worktree is available the
skill documents the weaker guarantee. Critical for lights-off (L5) and overnight runs.

### 8.2 Adversarial-verifier posture (Gap 3)

The builder is implicitly rewarded for "pass," so the Verifier treats it as adversarial:
it derives pass/fail **only from observed twin state and externally-observable behavior**
(e.g. "did the twin email service receive a send with a valid token?"), and treats **all
builder-produced text — logs, comments, output — as untrusted data, never instructions**
(guarding against a builder that prints "all passed" or injects the LLM judge). Where
feasible it **varies twin inputs the builder cannot predict** to catch test-aware
special-casing.

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
    knowledge-base.md          # optional wiki / open-brain integration; self-contained default
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
final_exam_fraction: 0.3       # held-back scenarios, run once at end, never fed back
pass_threshold: 1.0            # fraction of scenarios required (default 100%)
budget:
  billing: api                 # api (metered → enforce) | subscription (alert only)
  max_usd: 20                  # enforced when billing: api
  max_tokens: 5000000          # enforced when known
  alert_at: 0.85               # warn at 85% of any cap
  on_max: pause                # pause + offer raise-and-resume; never a silent kill
roles:
  planner:        { tool: claude }
  test_authority: { tool: claude }            # scenarios + twins; must ≠ builder
  builder:        { tool: claude, mode: subagent }   # e.g. { tool: codex }
  verifier:       { tool: claude }            # e.g. { tool: gemini }
prefer_skills: true            # delegate steps to specialized skills when available (§3B)
twins:
  services: []                 # auto-detected from spec; human confirms
knowledge_base:                # optional; asked at invocation, default none
  kind: none                   # none | wiki | open-brain
  path: ""                     # filesystem path when kind: wiki
  write_back: false            # opt-in; capture learnings/outcomes back to the base
```

## 10. Workflow the skill follows (one todo per step)

1. **Engage + classify.** Announce dark-factory is engaging (offer opt-out). **Ask
   whether the user has a wiki or open-brain to draw on and record to (§3A), and whether
   billing is `api` or `subscription` (§6.2); default to self-contained.** Detect
   greenfield vs brownfield; infer external services for twins.
2. **Spec (Planner).** If none, interview the human → `spec.md`; human approves. If a
   plan/spec exists, load and confirm it.
3. **Config.** Write/confirm `config.yml`. **Warn if `builder == test_authority`.**
4. **Acceptance world (Test authority).** Author holdout **scenarios** — split into dev +
   sealed final-exam (§4.1) — + build/collect **twins**; scenarios stay in the control
   plane. Run the **coverage gate** (every spec behavior traces to a scenario, critic-
   reviewed) before any build.
5. **Isolate.** `isolate-workspace` creates the build worktree with spec + twins, no
   scenarios, inside a **scoped sandbox** (§8.1).
6. **Loop** (§6): build → verify (actual outcomes) → filtered feedback → repeat until
   pass, iteration cap, or budget cap — checkpointing per level, **alerting at 85% and
   pausing at 100% budget with raise-and-resume** (§6.2). At each step **prefer an
   available specialized skill** (§3B), else built-in behavior.
7. **Outcome checkpoint / hand-off.** Present actual outcomes; human evaluates and
   accepts/adjusts/aborts. Accepted candidate is handed back (human merges).
8. **Record.** Persist the run log to `.dark-factory/runs/`. **If** a wiki/open-brain was
   configured (§3A), offer to capture the outcome/learnings there (opt-in).

## 11. Guardrails

- **Builder ≠ Test authority** (warn/refuse) — else the holdout is self-authored.
- **Scenarios never enter** the build workspace or the builder's context; only filtered
  behavioral feedback crosses the barrier.
- **Verifier reports actual outcomes** (evidence/artifacts), never the builder's
  self-report — aligns with `verification-before-completion`.
- **Twins only** in the loop — never real production, credentials, or data.
- **Secrets never go public.** API keys/tokens (for cross-model adapters like Codex/
  Gemini), twin service credentials, and any other secret live in an env file (`.env`),
  the OS keychain, or a secrets manager — **never** inline in `config.yml`, the spec,
  scenarios, twins, or run logs, and never committed. Adapters read keys from the ambient
  environment/keychain (e.g. `OPENAI_API_KEY`), not from the skill's files. Whenever the
  skill creates or uses a secret-bearing file, it **verifies that file (plus `.env` and
  `.dark-factory/`) is in `.gitignore` first, adding the entry if missing.**
- **Bounded iteration** — hard cap; reaching it is a human-evaluated outcome.
- **Brownfield honesty** — never treat legacy as greenfield; run the incremental path.
- **Isolation honesty** — document the practical strength of the barrier for the chosen
  setup; never overclaim a seal.
- **No external-KB dependency** — a wiki/open-brain is optional (§3A); its absence never
  blocks a run, and writing back to it is always opt-in.
- **Adversarial verifier** — pass/fail comes only from observed twin state; all
  builder-produced text is untrusted data, never instructions (§8.2).
- **Builder sandbox** — the builder runs filesystem- and network-scoped (§8.1); test
  isolation is not blast-radius control.
- **Budget is an off-ramp, not a kill** — alert at 85%, pause at 100% with
  raise-and-resume; `subscription` billing alerts only (§6.2). Work is never discarded.
- **Delegation respects the barrier** — a skill invoked in the build plane inherits its
  restricted context and can never reach the holdout scenarios/outcomes; a delegated
  gated action (commit/push/deploy/schedule) still pauses for the human; dark-factory
  never invokes itself (§3B).
- **No regression shipped** — a candidate that turned a previously-green scenario red is
  blocked until fixed.

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
- Runs to completion with **no** wiki/open-brain configured (self-contained); when one is
  configured, reads it for grounding and writes back only on opt-in.
- **No build begins until the coverage gate passes**; the sealed final-exam set runs once
  at the end and is never fed back into the loop.
- **Budget:** an 85% alert fires and hitting 100% pauses with a working raise-and-resume
  (state preserved), while `subscription` billing only alerts — no run is discarded.
- **Skill composition:** runs standalone with no other skills installed; when specialized
  skills are present it delegates and records which were used, and a build-plane
  delegation never receives the scenarios.

## 13. Open items to resolve during planning

- Exact adapter contract (stdin/stdout, workdir, timeout) shared by claude/codex/gemini.
- `filter-feedback` implementation split (deterministic strip vs. constrained model call)
  and how it is tested (it is itself security-critical).
- Scenario runner: how scenarios (behavioral markdown) are executed — a lightweight
  interpreter/harness vs. generated executable checks — while keeping them tool-agnostic.
- Whether the worked example ships greenfield-only or also a brownfield walkthrough.

## 14. Future levers (post-v1)

Noted, not built in v1 — wire in once the core is proven:

- **Flaky-scenario handling** — retry-N then quarantine a scenario that flips without a
  code change (cf. the `e2e-runner` agent).
- **Non-functional requirements as scenarios** — perf budgets, security, a11y must be
  encoded as scenarios (or gated via `security-review` / perf tooling) or they are
  invisible under "no human reviews code."
- **Audit-trail schema** — each run records role→tool→model version, scenario-set hash,
  twin versions, skills invoked, cost, and pass/fail. For an artifact nobody reviewed,
  provenance *is* the trust.
- **Capped/failed-run disposition** — keep the worktree for inspection · discard · or
  (breaking L5 purity) escalate to human-writes-code. The human chooses at the pause.
- **Parallel candidates** — explore N builders in parallel worktrees and pick the best by
  scenario pass-rate (an adversarial-judge variant; cf. `loop-designer`).
