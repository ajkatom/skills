# skills

Personal, portable Agent Skills, version-controlled here and symlinked into the
skill directory used by Claude Code, Codex, or another filesystem-capable agent.

## loop-designer

Designs a custom mix of Anthropic's four loop types for a project or task, interviews
you with loop-specific questions, and writes the config files + paste-ready
`/goal`, `/loop`, `/schedule` commands. It prepares everything; you launch the loops.

- Skill: [`loop-designer/SKILL.md`](loop-designer/SKILL.md)
- Templates: [`loop-designer/references/templates.md`](loop-designer/references/templates.md)
- Worked example: [`loop-designer/references/example-deal-radar.md`](loop-designer/references/example-deal-radar.md)
- Design spec: [`docs/superpowers/specs/2026-07-12-loop-designer-skill-design.md`](docs/superpowers/specs/2026-07-12-loop-designer-skill-design.md)

### Install / update

The skill is used live via a symlink:

```
ln -sfn "$PWD/loop-designer" ~/.claude/skills/loop-designer
```

## task-interview

Model-agnostic (Claude, OpenAI/Codex, Gemini) task-kickoff interviewer: asks
one question at a time to pin down the goal & outcome, guardrails (always do /
ask first / never do), where the context lives, and the test criteria that end
the loop — then models the work as a loop graph with verification gates and
writes a `TASK-BRIEF.md` contract before any work starts. The skill body is
plain markdown with no host-specific tool calls, so the same file installs
into Claude Code, Codex/`AGENTS.md`, Gemini CLI/`GEMINI.md`, or a plain chat.

- Skill: [`task-interview/SKILL.md`](task-interview/SKILL.md)
- Question bank: [`task-interview/references/question-bank.md`](task-interview/references/question-bank.md)
- Templates (TASK-BRIEF, loop graph, iteration log): [`task-interview/references/templates.md`](task-interview/references/templates.md)
- Platform installs: [`task-interview/references/platform-adapters.md`](task-interview/references/platform-adapters.md)
- Codex audit prompt: [`task-interview/references/codex-audit-prompt.md`](task-interview/references/codex-audit-prompt.md)

### Install / update

Claude Code:

```bash
ln -sfn "$PWD/task-interview" ~/.claude/skills/task-interview
```

Codex and Agent Skills-compatible hosts:

```bash
mkdir -p ~/.agents/skills
ln -sfn "$PWD/task-interview" ~/.agents/skills/task-interview
```

Gemini CLI and plain chat: see
[`task-interview/references/platform-adapters.md`](task-interview/references/platform-adapters.md).

## extract-apple-mail

Exports user-selected Apple Mail mailboxes into a private, resumable archive of
immutable `.eml` sources, extracted attachments, deterministic Markdown source
views, portable manifests, and an independently verified Karpathy-style wiki
staging layout. The runtime is local and model-agnostic: Python's standard
library plus macOS JXA, with no LLM calls or direct reads of Mail's private
database.

- Skill: [`extract-apple-mail/SKILL.md`](extract-apple-mail/SKILL.md)
- Archive schema: [`extract-apple-mail/references/archive-schema.md`](extract-apple-mail/references/archive-schema.md)
- Verification contract: [`extract-apple-mail/references/verification.md`](extract-apple-mail/references/verification.md)
- Design spec: [`docs/superpowers/specs/2026-07-25-extract-apple-mail-skill-design.md`](docs/superpowers/specs/2026-07-25-extract-apple-mail-skill-design.md)
- Tests: `python3 -m unittest discover -s extract-apple-mail/tests -v`

### Install / update

Claude Code:

```bash
ln -sfn "$PWD/extract-apple-mail" ~/.claude/skills/extract-apple-mail
```

Codex and Agent Skills-compatible hosts:

```bash
mkdir -p ~/.agents/skills
ln -sfn "$PWD/extract-apple-mail" ~/.agents/skills/extract-apple-mail
```

For another local agent, point it at `extract-apple-mail/SKILL.md` and allow
local Python and `osascript` execution. No model-specific API is required.

## dark-factory

Runs a StrongDM-style "dark factory" loop: you write a spec, an isolated
builder agent implements it without ever seeing the hidden acceptance
scenarios, a verifier runs them, and only behavior-ID + failure-taxonomy
feedback crosses back until convergence. Four assurance tiers ship —
cooperative, standard (OS sandbox + default-deny candidate isolation),
hardened (Docker, denial by construction), and enterprise (+ locked egress
+ split-custody sign-off) — crossed with four intervention modes (H1
Directed … H4 Lights-out) for how much a human is in the loop. Security
gates are mandatory at standard+ (a converged artifact with a planted secret
is rejected, cleared only by a signed, expiring waiver), and `qualified` is
one authoritative state machine over isolation + host-read + control-plane +
app-security + waiver validity. The hidden scenarios can be written by a human
or by an independent **author** agent (a different model than the builder),
adversarially reviewed by a second **decorrelated critic** model, and can be
**generative** — seeded property/fuzz and bounded-concurrency scenarios that
assert an invariant (round-trip, idempotency, no-lost-update, "never crashes")
over many machine-generated inputs. Past the sealed artifact, an optional
**governed ship phase** runs operator-defined actions (merge/deploy/…),
reversible ones unattended and irreversible ones behind a signed K-of-N
release approval. Cross-model builders too: claude/codex/gemini CLIs, or a
stdlib HTTP adapter straight to the Anthropic/OpenAI APIs, no CLI required.

- README (quickstart, tiers, layout): [`dark-factory/README.md`](dark-factory/README.md)
- Plain-language overview: [`dark-factory/OVERVIEW.md`](dark-factory/OVERVIEW.md)
- Security glossary: [`dark-factory/GLOSSARY.md`](dark-factory/GLOSSARY.md)
- Skill (operational instructions): [`dark-factory/SKILL.md`](dark-factory/SKILL.md)
- Design spec: [`docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md`](docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md)
- Adversarial review log: [`docs/superpowers/specs/2026-07-13-dark-factory-review-log.md`](docs/superpowers/specs/2026-07-13-dark-factory-review-log.md)
- Tests: `.venv/bin/python -m pytest dark-factory/tests -v`

### Install / update

```
ln -sfn "$PWD/dark-factory" ~/.claude/skills/dark-factory
```
