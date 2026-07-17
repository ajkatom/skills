# Locking down the orchestrator session (spec §3B / residue #7)

> **What this covers:** how to enforce a **skill/tool allowlist on the orchestrator
> session itself** — the Claude (or other agent) session that *runs* dark-factory to
> build your app. dark-factory **cannot** do this from inside its own skill code (a
> skill cannot sandbox the session that is executing it), so this is an **operator
> step at the harness layer**. This file is the recipe.

## Why the skill can't do it itself

dark-factory already confines the **builder** — the model that writes your app runs
as a **separate subprocess** with its tools/MCP/skills stripped (M14
`builder_confinement`) and, at `standard`/`hardened`/`enterprise`, inside an
OS sandbox / container it cannot escape. That is the security-critical boundary and
it is enforced.

The **orchestrator** — the session invoking the skill — is a different actor. It is
**trusted by construction**: you launched it, it holds your credentials, and it is
the thing calling dark-factory. A skill's own Python cannot revoke the capabilities
of the session executing it (there is no self-sandbox primitive). Enforcing "the
orchestrator may only use these skills/tools" is therefore a **harness
configuration**, done *before/around* the run — exactly like choosing which OS user
or container the whole thing runs in.

## The recipe (Claude Code)

Run the orchestrator under a restricted profile. Combine as many of these as your
threat model wants; each is enforced by the harness, not by dark-factory:

1. **Tool allow/deny at the session level.** In the project/user `settings.json`
   `permissions` block, or via the CLI flags, restrict the orchestrator to only the
   tools a dark-factory run needs (`Bash`, `Read`, `Write`, `Edit`, plus whatever
   your KB/skills need) and deny the rest:
   - `--allowedTools "Bash Read Write Edit"` (allowlist), or
   - `--disallowedTools "..."` (denylist), or
   - `settings.json` `permissions.deny` / `permissions.allow`.
2. **Deny MCP.** `--strict-mcp-config` with **no** MCP servers configured — so the
   orchestrator cannot reach arbitrary MCP connectors mid-run.
3. **Constrain which skills load.** Keep only the skills a run needs on the skill
   path; a run does not need the whole plugin catalog. (dark-factory itself + your
   chosen KB/planning skills.)
4. **A `PreToolUse` hook as the hard gate.** A hook is harness-executed, so it *can*
   veto a tool call the model tries to make. Add a `PreToolUse` hook that blocks any
   tool / skill outside your allowlist (exit non-zero → the call is refused). This
   is the enforcement dark-factory's own code cannot provide, moved to the layer
   that can. Point the hook at a small script that checks the tool name / skill
   against your list.
5. **OS-level containment of the orchestrator** (strongest). Run the entire
   orchestrator session as a **dedicated low-privilege OS user** or **inside a
   container** with only the working tree mounted and no ambient credentials beyond
   what the run needs. This bounds even a hook bypass.

## Verify it (don't trust — probe)

Before relying on the allowlist, prove it: from the locked-down orchestrator, ask it
to use a tool/skill you intend to have **denied** and confirm the harness **refuses**
the call (the hook exits non-zero / the tool is not available). If the denied action
runs, the allowlist is not in force — fix the config before a real run. This mirrors
dark-factory's own fail-closed discipline: a control you did not probe is a control
you do not have.

## Honest scope

- This is **operator-configured harness enforcement**, not a guarantee dark-factory's
  code makes about its own session. The skill provides the recipe; you apply it.
- It constrains the **orchestrator**. The **builder** is already confined by
  dark-factory (M14 + the tier sandbox) independently of this.
- Content-hash **pinning** of the exact allowed skill versions (spec §3B) depends on
  your harness exposing skill versions to the hook; where it does, pin them in the
  hook's allowlist, where it doesn't, pin at the deployment layer (a fixed,
  vetted skill directory the orchestrator loads from).
