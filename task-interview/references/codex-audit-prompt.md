# Codex audit prompt

Paste-ready prompt for auditing this skill with OpenAI Codex (or any second
model — the point is a decorrelated reviewer that didn't write the skill).
Run from the repo root, e.g.:

```bash
codex "$(cat task-interview/references/codex-audit-prompt.md)"
```

---

You are an adversarial auditor. Audit the `task-interview/` skill in this
repository: `SKILL.md` plus everything in `task-interview/references/`. You
did not write it; your job is to find real problems, not to praise it.

Context: the skill's stated contract is to (1) be model-agnostic — usable
verbatim on Claude, OpenAI/Codex, and Gemini, (2) interview the person one
question at a time for goal/outcome, guardrails, context locations, and the
test criteria that end the work loop, (3) design the work as a loop graph
with verification gates, and (4) produce a TASK-BRIEF.md contract before any
work starts.

Check, at minimum:

1. **Portability.** Does any instruction in the body silently depend on a
   Claude-only or Codex-only capability? Would a Gemini CLI or plain-chat
   session following it verbatim hit a dead end?
2. **Convergence.** Follow the loop-graph rules as written on a small
   imagined task. Can a loop run forever, or end without its criteria
   passing? Are escalation paths reachable and specific?
3. **Interview quality.** Could an agent following Phase 1 as written
   degenerate into a form/questionnaire, skip the fit check, or accept
   unfalsifiable criteria like "looks good"?
4. **Internal consistency.** Do SKILL.md, the question bank, and the
   templates agree with each other (section names, bucket names, retry
   semantics)? Do all referenced files exist and all internal paths resolve?
5. **Safety of the guardrail defaults.** Would the suggested defaults ever
   encourage an irreversible action without a gate?
6. **Size and signal.** Anything that pads the context without changing
   agent behavior? Anything load-bearing that's missing (state a concrete
   failure it would cause)?

Report format: a numbered list of findings, each with severity
(BLOCKER / MAJOR / MINOR / NIT), the file and section, the concrete failure
scenario, and a proposed fix. If a category has no findings, say so
explicitly. End with a verdict: PASS, PASS-WITH-NITS, or FAIL.
