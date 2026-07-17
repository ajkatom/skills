# skills

Personal Claude Code skills, version-controlled here and symlinked into `~/.claude/skills`.

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

## dark-factory

Runs a StrongDM-style "dark factory" loop: you write a spec, an isolated
builder agent implements it without ever seeing the hidden acceptance
scenarios, a verifier runs them, and only behavior-ID + failure-taxonomy
feedback crosses back until convergence. Four assurance tiers ship —
cooperative, standard (OS sandbox), hardened (Docker, denial by
construction), and enterprise (+ locked egress + split-custody sign-off) —
plus cross-model builders (claude/codex/gemini CLIs, or a stdlib HTTP
adapter straight to the Anthropic/OpenAI APIs, no CLI required).

- README (quickstart, tiers, layout): [`dark-factory/README.md`](dark-factory/README.md)
- Plain-language overview: [`dark-factory/OVERVIEW.md`](dark-factory/OVERVIEW.md)
- Skill (operational instructions): [`dark-factory/SKILL.md`](dark-factory/SKILL.md)
- Design spec: [`docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md`](docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md)
- Adversarial review log: [`docs/superpowers/specs/2026-07-13-dark-factory-review-log.md`](docs/superpowers/specs/2026-07-13-dark-factory-review-log.md)
- Tests: `.venv/bin/python -m pytest dark-factory/tests -v`

### Install / update

```
ln -sfn "$PWD/dark-factory" ~/.claude/skills/dark-factory
```
