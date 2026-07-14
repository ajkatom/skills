# Example: cross-model run (Codex builds)

A live dark-factory run with **Codex as the builder** — proving the builder is
pluggable across models via the protocol-0.1 adapter seam. Verification stays
the deterministic scenario runner (no LLM judge).

Observed 2026-07-14 on macOS with `codex-cli 0.144.1`.

## Setup

- `config.json`: `assurance: cooperative`, `feedback: ids`, `autonomy: 5`
  (lights-off), `roles.builder.adapter` → `scripts/adapters/codex`.
- Toy spec: a `greet.py` CLI (BHV-001 greeting, BHV-002 usage error).
- Two hidden holdout scenarios under `control/scenarios/` — never shown to the builder.

## Run

```
$ python3 dark-factory/scripts/supervisor.py run --control-root <cr>
dark-factory: COOPERATIVE MODE — unqualified: no probe-proven isolation; ...
dark-factory: CONVERGED (unqualified, cooperative tier). Workspace: <ws>  Run: <run>
EXIT=0
```

Journal:

```
INIT                   {"qualified": false, "tier": "cooperative"}
SNAPSHOT               {"file_count": 0}
BUILD                  {"iteration": 1}     # codex adapter invoked
VERIFY                 {"iteration": 1, "passing": 2, "total": 2}
CONVERGED              {"iteration": 1}
```

INIT recorded the builder adapter as `scripts/adapters/codex`.

## Acceptance

- **Audit:** `verify-manifest` → `OK`.
- **Holdout barrier:** scenario titles ("greets by name", "usage error") appear
  in neither the workspace nor any `prompt_iter_*.md` — Codex built from the spec
  only, exactly like the Claude builder.
- **Artifact:** the `greet.py` Codex wrote runs correctly — `Hello, Alon!` (exit
  0) and the usage error (exit 2).

## Notes

- The codex adapter runs `codex exec --sandbox danger-full-access
  --skip-git-repo-check <prompt>` (no `-m` pin). Codex's own sandbox is disabled
  because, under the `standard` tier, dark-factory provides the OS sandbox itself
  — and that sandbox denies the builder reads of the control root, so a
  cross-model builder inherits holdout isolation with no supervisor change.
- `gemini` was not installed on this box (`available_builders()` →
  `{"claude": true, "codex": true, "gemini": false}`), so the Gemini adapter
  ships but is unverified live — honestly noted, like the Linux bwrap backend.
