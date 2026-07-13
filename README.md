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
