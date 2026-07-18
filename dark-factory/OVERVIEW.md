# dark-factory, in plain language

This document skips the implementation details and explains **what
dark-factory is for**, **how it works at a high level**, and **what each
reference doc in `references/` is about** — for anyone who wants the gist
without reading `SKILL.md` or the code. If you want the operational,
step-by-step version, see [`README.md`](README.md) and `SKILL.md`.

## The problem this solves

If you ask an AI to build something and then grade its work using tests it
can see, it's tempting for it to "teach to the test" — write code that
passes the specific checks in front of it rather than genuinely solving the
problem you described. This gets worse the more autonomous the AI is: if
nobody reviews every line, a program that games its own tests can look
finished when it isn't.

## The idea: a builder that can't see the answer key

dark-factory solves this the way you'd grade a human's take-home exam
fairly: the person writing the code (the **builder**) only ever sees the
assignment (your spec). The actual test questions (the **hidden acceptance
scenarios**) are held by a separate grader (the **verifier**) that the
builder never has access to. After each attempt, the builder is told
*something* went wrong — which numbered requirement failed and roughly what
kind of failure it was (e.g. "wrong output" vs. "crashed") — but never the
actual test itself, and never the right answer. It tries again with that
hint, and this repeats until everything passes (**converged**) or it gives
up trying (the run stops and a human decides what's next).

At the strongest settings, this isn't just an honor system — the builder
literally runs somewhere (a locked-down sandbox, or its own disposable
container) where it is *physically incapable* of reading the hidden test
files, the same way a student can't see a sealed answer key even if they
wanted to.

## The four "how much do you trust this" tiers

You pick one of these per project, depending on how much is at stake. (Note:
these are **assurance tiers** — how hard it is for the builder to cheat — a
different axis from **how much a human stays in the loop**, which is the
separate "intervention mode" choice explained in the callout after the
list.)

1. **cooperative** — the builder is just asked nicely not to peek. Fastest
   and simplest, but nothing stops a determined or buggy attempt from
   cheating. Every run is honestly labeled "unverified."
2. **standard** — the builder runs under real operating-system protection
   that blocks it from reading the hidden test files, and this protection is
   tested at startup (if the protection doesn't actually work, the run
   refuses to start rather than pretending it's safe).
3. **hardened** — the builder runs inside its own disposable mini-computer
   (a Docker container) that the hidden tests are never even placed into —
   there's nothing to sneak a read of, because it was never there. This tier
   also *unlocks the option* to run fully unattended, no human needed to
   click "continue" between attempts — that unattended mode is a separate
   setting you opt into, not something hardened does automatically.
4. **enterprise** — everything in hardened, plus: the container can't quietly
   phone home to the internet (only one pre-approved, credential-injecting
   gateway), and before anything ships, a *separate group of people* (not
   just the one operator who ran it) have to independently sign off,
   cryptographically, that the result is real. Nobody can ship something
   alone even if they wanted to fake success.

**Tiers vs. how-much-a-human-watches — two different questions.** The four
items above answer "how hard is it for the builder to cheat." A separate
setting, the **intervention mode**, answers "how much does a human stay in
the loop," and there are four of them:

1. **Directed (H1)** — you check in constantly: before each retry, after each
   attempt is graded, and again before anything is finalized.
2. **Supervised (H2, the default)** — you review after each attempt and once
   more before it finalizes, but retries run on their own in between.
3. **Guarded (H3)** — it runs by itself and only stops to ask you when
   something genuinely needs a decision (like approaching your spending
   limit).
4. **Lights-out (H4)** — fully unattended, no human ever needed. Crucially, if
   a situation comes up that *would* need a human, it stops with a clear
   failure rather than quietly guessing and proceeding — and this mode is
   only available at the `hardened`/`enterprise` tiers.

Picking `hardened` doesn't turn on lights-out by itself — the mode is a
separate choice. (Older projects that used the previous "autonomy 4/5 +
checkpoint" settings still work and are mapped onto these modes
automatically.)

## What it can build with

The builder can be Claude, Codex, or Gemini (driven the normal way, via their
command-line tools), or a direct API call to Anthropic's or OpenAI's models
(no command-line tool needed at all — useful for the mini-computer container
above, which doesn't have those tools installed). You can mix and match: any
of the above can act as the builder, and grading always works the same
deterministic way regardless of which model wrote the code.

## Safety nets

Some are always on, some optional:

- **Security scanning** on whatever the builder wrote, so a working-but-secretly-
  dangerous result (a hardcoded password, an injection bug) still gets
  caught even if all the tests pass. From the `standard` tier up this is
  **mandatory** — a build that trips a gate can't be marked "qualified." If
  you decide to accept a specific finding anyway, you don't get to just turn
  the gate off: an authorized person has to **sign a waiver** for that exact
  finding, and the waiver expires. It also runs in its own locked-down
  environment so scanning can't be used as a way to read the hidden tests.
- A **budget** so a run can't spend more than you've allowed, with warnings
  before it happens. Raising the ceiling mid-run to get past a spending halt
  also requires a **signed authorization**, not a quiet edit.
- One clear **verdict**: a run is "qualified" only if *everything* held — the
  builder really was walled off, the candidate couldn't read your host, the
  record is signed, and the security gates passed (or were properly waived).
  If any one of those falls short, it says exactly which one, instead of a
  vague "mostly OK."
- **Digital twins** — fake stand-ins for real external services (so a build
  that's supposed to talk to a payment processor doesn't actually need one
  during development).
- Ways to point it at an **existing codebase** instead of a blank slate,
  and to plug in a shared knowledge base if you have one.
- A signed, tamper-evident **paper trail** of every run, so you can prove
  later exactly what happened and that nobody edited the record afterward.
- Optionally, a governed **ship phase**: once a run is qualified, it can run
  your own ship steps (merge, deploy, migrate) on the sealed artifact — audited,
  crash-safe, and able to roll back on failure. The reversible ones run on their
  own; anything **irreversible** (a prod deploy) won't run until an authorized
  person **signs off** — even a fully unattended run stops and waits for that
  signature rather than pushing to production on its own.

## What each reference doc covers

Every file below lives in `references/`. They're written for someone
implementing or auditing the mechanism, not for a first read — this list is
just so you know which one to open.

- **`authoring.md`** — the guided interview for writing your spec and hidden
  test scenarios, and how to turn them into a ready-to-run project folder.
  You can also have an **independent agent** (a different model than the
  builder) write the hidden scenarios for you, with the same barrier — see its
  "Agent-authored scenarios" section.
- **`scenario-adequacy.md`** — how agent-authored scenarios are made
  THOROUGH: class-typed coverage (happy/boundary/failure), a sharpness battery
  (each assertion must reject a battery of near-miss mutants — it mutates the
  observation, not the built code), and a decorrelated second-model **critic**
  that adversarially reviews the set (advisories surfaced, never auto-applied).
  Includes the honest residual: human spec fidelity + non-functional properties
  the oracle can't express.
- **`scenario-format.md`** — the exact file format for a hidden test
  scenario (the thing the builder is never allowed to see), including the
  generative property/fuzz kind (M43a): assert an invariant over many
  seeded machine-generated inputs — the bugs one fixed example can't catch.
- **`role-adapters.md`** — how dark-factory talks to whichever AI model is
  doing the building or verifying, including the two API-only adapters that
  need no command-line tool installed.
- **`builder-confinement.md`** — how the builder's AI tool is stripped down
  so it can't use side-channels (other AI helper tools, web browsing) to
  cheat, and an honest account of which tools this has actually been proven
  to work for.
- **`modes.md`** — the four intervention modes (Directed / Supervised /
  Guarded / Lights-out): exactly when each one stops for a human, and how the
  fully-unattended mode fails safely instead of guessing.
- **`isolation.md`** — the "standard" trust level: how the operating system
  itself is used to block the builder from reading the hidden tests, and the
  default-deny profile that stops the *built program itself* from reading
  your host or reaching your local services while it's being tested.
- **`hardened.md`** — the "hardened" trust level: running the builder in its
  own disposable container that never has the hidden tests inside it.
- **`enterprise.md`** — the strongest trust level: locking down internet
  access and requiring multiple independent people to sign off before a
  result counts as shipped.
- **`orchestrator-lockdown.md`** — a related but separate concern: locking
  down *your own* AI assistant session (the one running dark-factory for
  you), which has to be configured outside dark-factory itself since a tool
  can't restrain the very session that's running it.
- **`credentials.md`** — how API keys and other secrets are handed to the
  builder safely, without them ending up in logs, files, or version control.
- **`security-gates.md`** — an automatic security scan of whatever the
  builder produced, run even on a build that passed every test, so a
  planted vulnerability doesn't slip through just because the tests didn't
  catch it.
- **`coverage-gates.md`** — a sanity check that runs before any build even
  starts, making sure the hidden tests are actually capable of catching
  mistakes (and don't accidentally reveal the answer).
- **`budget.md`** — spending limits and (for the API-based builders) real
  token-usage and cost tracking.
- **`digital-twins.md`** — fake stand-ins for real external services, so
  development and testing don't need the real thing.
- **`audit.md`** — the signed, tamper-evident record kept of every run,
  including the single "is this qualified, and if not, exactly why not"
  verdict.
- **`prevention-grade-roadmap.md`** — an honest account of what this skill
  detects versus what it could only prevent with extra infrastructure it
  deliberately doesn't require, and what's deferred for later.
- **`brownfield.md`** — using dark-factory on an existing codebase instead
  of starting from scratch, by freezing "what it currently does" as a
  baseline the build isn't allowed to break.
- **`knowledge-base.md`** — optionally connecting a shared notes/wiki system
  so runs can draw on and contribute back institutional knowledge.
- **`config-reference.md`** — the complete list of every setting in a
  project's configuration file, for looking one up.
- **`linux-ci.md`** — how the parts of this that only work on Linux (rather
  than the maintainer's everyday Mac) get tested anyway.
- **`example-cross-model.md`** — a worked, real example of a run where a
  different AI model did the building.
