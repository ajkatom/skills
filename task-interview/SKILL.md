---
name: task-interview
description: Model-agnostic task-kickoff interviewer and loop designer — works verbatim on Claude, OpenAI/Codex, and Gemini. Interviews the person one question at a time to pin down the goal and outcome, the guardrails (always do / ask first / never do), where the context lives (folders, repos, docs), and the test criteria that end the work loop; then models the work as a loop graph with verification gates and writes a TASK-BRIEF.md contract before any work starts. Use whenever the user kicks off a new task, project, feature, or agent run; says "interview me", "brief me", "set up this task", or "what do you need to know"; hands over vague or underspecified work; or mentions goals, outcomes, guardrails, success criteria, stop conditions, or pointing an agent at the right folders.
---

# Task Interview

Turn a vague request into a contract an agent can execute: interview the human,
design the work as a **loop graph**, agree on the **test criteria that end the
loop**, and write it all into a `TASK-BRIEF.md` before touching the work.

**Why this exists.** A loop is "an agent repeating cycles of work until a stop
condition is met." Loops without agreed, checkable stop conditions don't
converge — the agent either quits early or churns forever. And agents fail far
more often from vague specs than from weak models: explicit goals, guardrails,
context, and success criteria are the highest-leverage prompt content on every
frontier model. This skill front-loads exactly that.

## Portability rules

This file is plain markdown with no host-specific tool calls, so it runs
unchanged on Claude, OpenAI/Codex, or Gemini (see
`references/platform-adapters.md` for installation on each). Two rules keep it
portable at runtime:

- Use whatever the host provides — file reading, shell, subagents — when it
  helps, but never depend on it. If you can't read a folder the human points
  you at, say so and ask them to paste the relevant content.
- Write outputs as plain markdown files (or a markdown reply if you can't
  write files). No host-specific config formats in the brief itself.

## Phase 1 — Interview

Ask **one question at a time**. Never present a form. For each question,
propose a concrete default inferred from what you already know — "I'd suggest
X, does that hold?" beats an open-ended quiz, and it shows the human you've
been listening. Skip anything the conversation has already answered. Stop
interviewing the moment another answer wouldn't change the work: the goal is a
sufficient brief, not a complete questionnaire.

Cover four tracks, in this order (full question bank with phrasings and edge
cases: `references/question-bank.md`):

1. **Goal & outcome.** What does done look like, and why does it matter? Aim
   at the goal, not the task — if the literal steps the human describes don't
   serve the outcome they name, surface that now. Pin the deliverable's form
   (file, PR, report, running service) and who consumes it.
2. **Guardrails.** Sort constraints into three buckets — **always do**,
   **ask first** (irreversible actions, spending money, expanding scope,
   touching production or shared state), and **never do**. Suggest defaults
   for the buckets; don't make the human invent them from nothing.
3. **Context.** Where does the truth live — folders, repos, docs, URLs, a
   knowledge base? What's authoritative vs. stale, and what should be ignored?
   If you can read the locations, skim them now and confirm what you found;
   grounding later questions in real file names builds trust and catches
   wrong pointers early.
4. **Test criteria — the loop's exit.** Propose measurable criteria that end
   the loop; let the human veto or sharpen them. Run the **fit check**: is
   each criterion objectively checkable (a command, a count, a threshold — not
   "looks good"), is feedback fast enough to loop on, and do you have access
   to run the check? Then agree on **max iterations** before escalating to a
   human, and on **who judges** — a deterministic command, a separate judge
   pass, or a human checkpoint. Deterministic beats judge beats human, but
   subjective work gets a judge pass with a written rubric, not vibes.

## Phase 2 — Design the loop graph

Model the work as a small directed graph, not a flat checklist:

- **Node** = the smallest bucket of work that produces something reviewable.
  Every node carries its own inner loop: *plan → execute → verify against the
  node's criteria → pass (advance) or fail (change something and retry)*.
  A node that fails its check `max_retries` times stops and escalates with
  what it tried — silent churn is a bug.
- **Edge** = a real dependency. Independent nodes are parallel branches — on
  hosts with subagents they can actually run in parallel; elsewhere they're
  just order-free.
- **Gate** = a join node that verifies combined work before anything
  irreversible or expensive: a judge pass, a test suite, or a human
  checkpoint. Guardrails from the interview attach here — every "ask first"
  action gets a gate in front of it.
- **Exit** = the whole graph terminates only when the Phase-1 test criteria
  pass. Generation and verification stay separated: whoever produced the work
  doesn't get to be the only thing that grades it.

Draw the graph as a mermaid diagram plus a node table (id, work, verification,
max retries, escalation). Keep it small — 3 to 9 nodes; if it's bigger, the
buckets are too fine. Template and a worked example:
`references/templates.md`.

## Phase 3 — Write the brief and get sign-off

Write `TASK-BRIEF.md` (template in `references/templates.md`) with exactly
these sections: Goal & outcome · Guardrails · Context map · Loop graph · Exit
criteria & budget · Open questions. Show it to the human and get an explicit
yes before executing. The brief is the contract: if the work later drifts from
it, that's a conversation, not a silent decision.

## Executing the loop (when the host can)

If this environment can do the work, run the graph: one node at a time, log
every iteration (node, what changed, verification result, kept or reverted) in
an append-only log the human can read later, and checkpoint at every gate.
Never mark the task done without the exit criteria actually passing — "it ran
without errors" is not a criterion. When something durable is learned (a rate
limit, a quirk, a better approach), write it back into the context locations
from the brief so the next run never relearns it. If the environment can't
execute (a chat with no tools), the signed-off brief *is* the deliverable —
hand it over ready to paste into whichever agent will do the work.

## References

| File | When to read it |
|------|-----------------|
| `references/question-bank.md` | During Phase 1, for the full per-track question sets |
| `references/templates.md` | During Phases 2–3, for the TASK-BRIEF template, loop-graph example, and iteration-log format |
| `references/platform-adapters.md` | When installing this skill on Claude Code, Codex, Gemini CLI, or a plain chat |

## Sources

Built on: Anthropic's loop engineering guide ("Getting Started with Loops" —
loops as cycles until a stop condition; deterministic criteria; cost levers),
Anthropic's Claude/Opus prompting guidance generalized to all providers
(explicit success criteria and context up front; high-level goals with clear
exit criteria over rigid step scripts), the Karpathy-style operating
principles (Spec → Verification → Environment; small buckets; eval criteria
before execution; always-do / ask-first / never-do guardrails), and Kieran
Klaassen's compound engineering (clarify before building; plan → build with
tests → multi-agent review; capture learnings so the next run is faster).
