# Platform adapters

The skill body is plain markdown with no host-specific tool calls, so
"porting" it is just putting the same file where each host looks for
instructions. The YAML frontmatter at the top of `SKILL.md` is read by
Claude Code and by other Agent Skills-compatible hosts; hosts that don't
understand it will see it as a few lines of text and lose nothing.

## Claude Code

```bash
ln -sfn "$PWD/task-interview" ~/.claude/skills/task-interview
```

Invoke with `/task-interview`, or let it auto-trigger from the description.
Claude Code extras that map cleanly onto the brief once it's signed off:
parallel nodes can run as subagents, and this repo's `loop-designer` skill
can turn the exit criteria into `/goal` / `/loop` / `/schedule` commands.

## OpenAI Codex (and other Agent Skills-compatible hosts)

```bash
mkdir -p ~/.agents/skills
ln -sfn "$PWD/task-interview" ~/.agents/skills/task-interview
```

Alternatively, paste the body of `SKILL.md` (everything below the
frontmatter) into the project's `AGENTS.md` under a "Task kickoff" heading —
Codex reads `AGENTS.md` at the start of every session.

## Gemini CLI

Add the body of `SKILL.md` to the project's `GEMINI.md` (or
`~/.gemini/GEMINI.md` for all projects), which Gemini CLI loads as context.
Keep the reference files next to it and point at them with relative paths, or
inline the question bank if the install is a single file.

## Plain chat (ChatGPT, Gemini app, Claude app — no tools)

Paste the body of `SKILL.md` as the first message or into custom
instructions, prefixed with: "Act on these instructions for our whole
conversation. You cannot read files here, so ask me to paste anything you
need." Phase 1 and 2 work fully in chat; Phase 3's deliverable is the brief
itself, which the human then hands to whatever agent executes.

## What to check after installing anywhere

Start a session and say "I want to kick off a new task — interview me."
The agent should ask exactly one question (about the goal), with a proposed
default — not a form, not a wall of questions. That's the smoke test.
