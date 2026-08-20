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

## gemini-myq-gate

Makes "OK Google, open the gate" work for a myQ-controlled gate even though
Chamberlain blocked all third-party integrations. Three built paths: a $0
phone-side bridge (Google Home routine → myQ app launch → MacroDroid
accessibility tap on the official app — nothing for Chamberlain to block), a
dedicated spare-phone bridge fronted by Home Assistant for whole-house
speaker support, and the hardware endgame (Wi-Fi relay on the gate operator's
dry-contact input, ESPHome firmware included).

- Guide + decision tree: [`gemini-myq-gate/README.md`](gemini-myq-gate/README.md)
- Macro build steps: [`gemini-myq-gate/macrodroid/opengate-macro.md`](gemini-myq-gate/macrodroid/opengate-macro.md)
- Home Assistant package: [`gemini-myq-gate/home-assistant/gate.yaml`](gemini-myq-gate/home-assistant/gate.yaml)
- Relay firmware: [`gemini-myq-gate/esphome/gate-relay.yaml`](gemini-myq-gate/esphome/gate-relay.yaml)

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
