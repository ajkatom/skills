# Loop Designer Skill — Design Spec

**Date:** 2026-07-12
**Author:** Alon Adelson (with Claude)
**Source concept:** `second_brain/raw/blog_2026-06-30_getting_started_loops.md` (Anthropic, "Loop Engineering: Getting Started with Loops")

---

## Purpose

A Claude Code skill that, whenever the user asks to **plan or write a project or task**, detects that one or more of Anthropic's four loop types could help, interviews the user with **loop-specific questions**, and then writes the appropriate **config files + paste-ready launch commands** so the user can run the loops.

The skill designs a *custom loop mix* per project — it may use all four loop types or a subset, depending on what the task requires.

## The four loop types (reference)

| # | Loop | Trigger | Stop condition | Primitive | Delegates |
|---|------|---------|----------------|-----------|-----------|
| 1 | Turn-based | user prompt | Claude judges done | skills (verification) | the *check* |
| 2 | Goal-based | manual prompt | goal met OR max turns | `/goal` + evaluator | the *stop condition* |
| 3 | Time-based | time interval | user cancel / work done | `/loop` (local), `/schedule` (cloud) | the *trigger* |
| 4 | Proactive | event/schedule, no human present | per-task goal met; routine runs until disabled | `/schedule` + `/goal` + skills + auto mode | the *prompt* |

## Design decisions (locked)

1. **Activation:** Auto-trigger during planning/writing tasks, **with an explicit opt-out.** When the skill fires it announces itself and offers the user a one-line way to skip loop design ("say 'skip loops' to plan without them").
2. **Output:** **Config files + ready-to-paste commands.** The skill does NOT launch loops — `/loop`, `/schedule`, `/goal` are user-triggered and billed. The skill prepares everything and hands the user the exact commands.
3. **Verification home (turn-based):** Adaptive —
   - Trivial single deterministic command → append a short **Verification** section to `CLAUDE.md`.
   - Multi-step / browser / screenshots / quantitative thresholds → generate a dedicated `verify-<task>/SKILL.md` and point to it from `CLAUDE.md`.

## Workflow

```
1. Detect: user asks to plan/write a project or task.
2. Announce + opt-out: "Loops could help here — I'll ask a few questions to design them.
   Say 'skip loops' to plan without them."
3. Classify: infer from the task which of the 4 loops plausibly apply. Ask the single
   GATE question only where applicability is ambiguous.
4. Interview: for each applicable loop, ask its question set (below), one question at a
   time. Skip a loop the moment its gate is "no".
5. Generate: write the config files + LOOPS.md manifest with all paste-ready commands.
6. Hand off: show the user the manifest and the exact commands to run.
```

Turn-based is almost always in (every coding task has a definition of done). Loops 2–4 are opt-in via one gate question each.

## Per-loop question sets

### 1. Turn-based → verification (nearly always on)
- Definition of "done" I can check myself? (tests green / page renders / lint clean / output exists)
- How to verify it — shell command, browser interaction, or script?
- Any quantitative thresholds? (coverage ≥ X%, zero new console errors, response has field Y)

**Writes:** verification `SKILL.md` (or `CLAUDE.md` section per the adaptive rule) + `CLAUDE.md` pointer.

### 2. Goal-based (`/goal`)
- GATE: Is there a single measurable metric that defines success? (no → skip)
- Exact metric + threshold? (Lighthouse ≥ 90, all tests pass, p95 < 200ms)
- What command/evaluator produces that number?
- Max attempts before stopping? (e.g. stop after 5 tries)

**Writes:** `goal.md` (criteria + evaluator) + ready `/goal …` command.

### 3. Time-based (`/loop` / `/schedule`)
- GATE: Does this recur, or need to poll something over time? (no → skip)
- Interval? (every 5m / hourly / daily 9am)
- Local or cloud? — decided by: must the machine be on? needs local repo/tools/secrets?
  (local → `/loop`; cloud → `/schedule`)
- Stop condition? (until CI green / until PR merged / run indefinitely)

**Writes:** `LOOPS.md` entry + ready `/loop` or `/schedule` command.

### 4. Proactive (`/schedule` + `/goal` + auto mode)
- GATE: Should this run unattended, no human watching? (no → skip)
- What event/schedule starts each run? (every hour, on new issue, …)
- Per-run goal / stop condition? (don't stop until every report this run is triaged)
- Auto mode — run without per-step permission? risk tolerance / blast radius?
- Model routing — cheap model for bulk, capable model for judgment calls?
- Parallelism — explore N solutions in parallel worktrees with an adversarial judge?

**Writes:** routine spec in `LOOPS.md` + ready `/schedule …` command.

## File layout (output artifacts)

| File | Purpose | Loop |
|------|---------|------|
| `LOOPS.md` | Master manifest: which loops chosen, why, and **all paste-ready commands** in one place | all |
| `goal.md` | `/goal` success criteria + evaluator | goal-based |
| `.claude/skills/verify-<task>/SKILL.md` | self-check the turn-based loop runs each turn (heavy checks only) | turn-based |
| `CLAUDE.md` | loop conventions + verification pointer (or inline trivial check) | all |
| `plan.md` | only if also planning — links to `LOOPS.md` | — |

`LOOPS.md` is the hub. It records the rationale for the chosen loop mix and lists every launch command so the user has one place to act from.

## The skill itself (packaging)

- Lives at `~/.claude/skills/loop-designer/SKILL.md` (single-file skill, matching the repo's existing skills like `find-skills`).
- `description` frontmatter must trigger on planning/writing-a-project/task requests, and mention loops, `/goal`, `/loop`, `/schedule`, recurring/scheduled/unattended work.
- Body contains: the four-loop reference table, the classification + opt-out flow, the per-loop question sets, the adaptive verification rule, the file-layout/output rules, and templates for each generated file.
- Includes worked mini-examples (e.g. "get Lighthouse ≥ 90" → goal-based; "triage bug reports hourly" → proactive) so triggering and output are unambiguous.

## Non-goals / YAGNI

- Not launching loops automatically (billed/interactive — user triggers them).
- Not auto-creating cloud schedules (declined; commands only).
- No GUI/visual companion.
- Not forcing all four loops — only what the task needs.

## Success criteria

- On a planning request, the skill fires, announces itself, and offers opt-out.
- It correctly narrows to the applicable loop subset and asks only relevant questions, one at a time.
- It produces `LOOPS.md` plus the correct per-loop files, and the paste-ready commands actually run as written.
- Trivial verification lands in `CLAUDE.md`; heavy verification lands in a `verify-<task>/SKILL.md`.
