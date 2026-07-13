---
name: loop-designer
description: Use when the user asks to plan, design, scope, or write a new project, feature, or task — designs a custom mix of Anthropic's four loop types (turn-based verification, goal-based /goal, time-based /loop & /schedule, proactive unattended routines) for that specific work. Detects which loops fit, interviews the user with loop-specific questions, then writes the config files (LOOPS.md, goal.md, verification SKILL.md, CLAUDE.md) plus paste-ready /goal, /loop, /schedule commands. Triggers on planning requests and on mentions of loops, recurring/scheduled/unattended work, verification criteria, or measurable success thresholds.
---

# Loop Designer

Design a **custom loop mix** for a project or task using Anthropic's four loop types,
then generate the config files and paste-ready launch commands. Based on
"Loop Engineering: Getting Started with Loops" (claude.com/blog/getting-started-with-loops).

**Core idea:** a loop is "agents repeating cycles of work until a stop condition is met."
Loops are chosen by how they're *triggered* and how they *stop*. Not every task needs
every loop — use the smallest set that fits.

## The four loop types

| # | Loop | Trigger | Stop condition | Primitive | Delegates |
|---|------|---------|----------------|-----------|-----------|
| 1 | Turn-based | user prompt | Claude judges done | skills (verification) | the *check* |
| 2 | Goal-based | manual prompt | goal met OR max turns | `/goal` + evaluator | the *stop condition* |
| 3 | Time-based | time interval | user cancel / work done | `/loop` (local), `/schedule` (cloud) | the *trigger* |
| 4 | Proactive | event/schedule, no human present | per-task goal met; routine runs until disabled | `/schedule` + `/goal` + skills + auto mode | the *prompt* |

## When this skill runs

Whenever the user asks to **plan, scope, design, or write a project / feature / task.**
It also fires on explicit mentions of loops, recurring/scheduled/unattended work, or
measurable success criteria.

**It does NOT launch loops.** `/loop`, `/schedule`, and `/goal` are user-triggered and
billed. This skill prepares config files + the exact commands; the user runs them.

## Workflow (create one todo per step)

1. **Announce + offer opt-out.** One line, then continue:
   > "This looks like a good candidate for loops — I'll ask a few quick questions to
   > design them. Say **'skip loops'** to plan without them."
   If the user opts out, stop here and plan normally.
2. **Classify.** Infer from the task which of the four loops plausibly apply. Present a
   short "why these loops" table. Only ask a loop's GATE question where applicability is
   genuinely ambiguous. Turn-based is almost always in (every build has a definition of
   done); loops 2–4 are opt-in.
3. **Interview.** For each applicable loop, ask its question set below — **one question
   at a time.** The instant a gate answer is "no," drop that loop and move on. Keep every
   question bound to the specific project (real routes, metrics, cadences, side effects) —
   never generic loop boilerplate.
4. **Generate.** Write the output files + `LOOPS.md` manifest with all paste-ready commands.
5. **Hand off.** Show the manifest and the exact commands to run. Do not run them.

## Per-loop question sets

Specialize every question to the project. The bracketed hints show the *kind* of
concrete detail to fill in from the task.

### 1. Turn-based → verification (nearly always on)
Delegates *the check*, so these build the project's verification.
- Definition of "done" I can check myself? [tests green / page renders / lint clean / output exists]
- How to verify — a shell command, a browser interaction, or a script? [name the real command/route]
- Quantitative gates? [coverage ≥ X%, zero new console errors, response contains field Y]

### 2. Goal-based (`/goal`)
- **GATE:** Is there a single measurable metric that defines success? *(no → skip)*
- Exact metric + threshold? [Lighthouse ≥ 90, all tests pass, p95 < 200ms, accuracy ≥ 95%]
- What command/evaluator produces that number? [the real script or command]
- Max attempts before stopping? [e.g. stop after 5 tries]

### 3. Time-based (`/loop` / `/schedule`)
- **GATE:** Does this recur, or need to poll something over time? *(no → skip)*
- Interval? [every 5m / hourly / daily 9am]
- Local or cloud? Decide by: must the machine be on? needs local repo/tools/secrets?
  *(local → `/loop`; cloud → `/schedule`)*
- Stop condition? [until CI green / until PR merged / run indefinitely]

### 4. Proactive (`/schedule` + `/goal` + auto mode)
- **GATE:** Should this run unattended, with no human watching? *(no → skip)*
- What event/schedule starts each run? [every hour / daily 8am / on new issue]
- Per-run goal / stop condition? ["don't stop until every item this run is triaged"]
- Auto mode — run without per-step permission? What's the blast-radius limit?
  [alert-only vs. allowed to open PRs but never merge]
- Model routing — cheap/fast model for bulk, capable model for judgment calls?
- Parallelism — explore N solutions in parallel worktrees with an adversarial judge?

## Adaptive verification rule (turn-based output)

- **Trivial** single deterministic command (e.g. `npm test && npm run lint`) →
  append a short **## Verification** section to `CLAUDE.md`. Keep it always-visible.
- **Heavy** — multi-step, browser/screenshots, or quantitative thresholds →
  generate `.claude/skills/verify-<task>/SKILL.md` and add a one-line pointer to it
  in `CLAUDE.md`. This keeps `CLAUDE.md` lean (it loads every turn; a skill loads on demand).

## Output files

| File | Purpose | Loop |
|------|---------|------|
| `LOOPS.md` | Master manifest: chosen loops, rationale, and **all paste-ready commands** | all |
| `goal.md` | `/goal` success criteria + evaluator | goal-based |
| `.claude/skills/verify-<task>/SKILL.md` | self-check run each turn (heavy checks only) | turn-based |
| `CLAUDE.md` | loop conventions + verification pointer (or inline trivial check) | all |
| `plan.md` | only if also planning — links to `LOOPS.md` | — |

`LOOPS.md` is the hub — the user acts from it. See `references/templates.md` for the
exact template of each generated file, and `references/example-deal-radar.md` for a full
worked walkthrough (a project that exercises all four loops).

## Guardrails (from the source article)

- Define clear stop/success criteria so loops converge — but not *prematurely*.
  Deterministic criteria (a test passing, a score threshold) beat "good enough."
- Model choice and effort level are the biggest levers on loop cost. Route bulk work to
  cheaper models; reserve the capable model for judgment.
- Don't run routines more often than needed. Pilot dynamic/parallel workflows on a small
  slice before large runs.
- Only propose the loops the task needs. A one-off task may need just turn-based.
