# Question bank

Full question sets for the four interview tracks. These are raw materials, not
a script: ask one at a time, always with a proposed default, and skip anything
already answered. Bind every question to the actual task — real folder names,
real metrics, real commands — never generic boilerplate.

## Track 1 — Goal & outcome

- What does *done* look like, in one sentence? [a merged PR / a report the
  team reads / a page that loads in under a second]
- Why does this matter — what breaks or stays broken if we don't do it?
  (This is what lets the agent aim at the goal when the steps turn out wrong.)
- What form is the deliverable, and who consumes it? [file at path X / PR
  against branch Y / dashboard / email draft]
- Is there an example of "good" I can look at? [a past PR, a doc, a competitor
  page]
- What's explicitly *out* of scope this round?

**Watch for:** the human describing a *task* ("add a retry to the fetch call")
when they have an unstated *goal* ("stop the nightly job from failing"). Name
the goal back to them and confirm which one you're accountable for.

## Track 2 — Guardrails

Propose the three buckets pre-filled with sensible defaults for the task, then
let the human edit. Defaults worth suggesting almost everywhere:

**Always do**
- Verify output against the agreed criteria before calling anything done
- Work in small reviewable increments; keep an iteration log
- Reuse an existing tool/script/pattern before writing a new one
- Write durable learnings back where the next run will find them

**Ask first** (stop and get an explicit yes)
- Irreversible actions: deleting data, modifying production or shared
  resources, sending, publishing, committing/pushing (calibrate to the task —
  in some repos pushing to a feature branch is routine)
- Spending money or consuming metered/paid API calls
- Expanding scope beyond the agreed bucket
- Overwriting instructions, configs, or saved workflows

**Never do**
- Store or hard-code secrets outside the designated secrets store
- Mark work complete without passing verification
- Fabricate or pad data to fill a gap — flag the gap instead

Then ask only for the task-specific deltas: "Anything you'd add to *never*?
Anything in *ask first* that's actually fine to do freely here?"

## Track 3 — Context

- Where does the truth live for this task? [repo + path / a docs folder / a
  wiki / a spreadsheet / a URL]
- Which sources are authoritative, and which are stale or misleading? (An
  explicit "ignore the old `docs/v1` folder" saves hours.)
- Is there a knowledge base or notes file I should ground myself in before
  general knowledge? Where do learnings get written back?
- Are there credentials/access I'll need, and where do they properly live?
  (Never ask the human to paste secrets into chat.)
- If you can read the filesystem: skim the named locations *now*, then
  confirm — "I see `src/jobs/nightly.py` and `docs/runbook.md`, is that the
  right area?" If you can't read them, ask the human to paste the few files
  that matter most.

## Track 4 — Test criteria (the loop's exit)

Propose criteria first — the human should be editing a draft, not staring at
a blank page. Then fit-check each criterion:

1. **Objective?** A command, count, or threshold — "all tests in `tests/`
   pass", "p95 < 200ms", "0 rows with null id" — not "looks clean".
2. **Fast feedback?** Checkable in minutes, so the loop can actually loop.
   A criterion that takes a week to observe (SEO rank, churn) can't end a
   loop; find a fast proxy and note the real metric in the brief.
3. **Accessible?** You can run the check yourself, or a named judge/human
   can. A criterion nobody present can evaluate is decoration.

Then settle the loop budget and judging:

- **Max iterations** per node and overall before escalating to a human
  [e.g. 3 retries per node, 10 total turns]. An escalation says what was
  tried and what the check reported — never just "it didn't work".
- **Who judges?** In order of preference: a deterministic command → a
  separate judge pass with a written rubric (the generator and the grader
  should not be the same breath) → a human checkpoint. Subjective work
  (copy, design) gets the judge pass, with the rubric written into the brief.
- **External verification** where possible: cross-check counts against a
  known total, a sample against the source, a response against the documented
  spec. External confirmation beats internal confidence.
