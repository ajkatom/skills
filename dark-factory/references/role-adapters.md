# Adapter protocol v0.1 (M1)

An adapter is any executable. The supervisor spawns it, writes one JSON
request to stdin, and reads one JSON response from stdout.

Request: `{"adapter_protocol":"0.1","role":"builder","workdir":"<abs>",
"prompt_file":"<abs>","timeout_s":600}`
Response: `{"adapter_protocol":"0.1","status":"ok"|"error","detail":"...",
"usage":{"known":false}}`

Rules: exit 0 even on in-band `status:"error"`; non-zero exit or unparseable
stdout aborts the run (`ABORTED_BUILD_ERROR`). No silent substitution — the
configured adapter path is invoked or the run fails (spec section 7.8).

Shipped adapters (protocol 0.1, all in `scripts/adapters/`):
- `claude` — claude CLI, headless, `--permission-mode acceptEdits`.
- `codex` — `codex exec`, Codex's own sandbox disabled (dark-factory provides
  the OS sandbox), no `-m` pin (uses ~/.codex default).
- `gemini` — Gemini CLI, `--yolo --prompt`.

Pick the builder with `df_adapters.available_builders()` (installed CLIs) and
`df_adapters.resolve_builder(name)` — the latter raises rather than substitute a
different model. Under the `standard` tier the OS sandbox denies the holdout to
whatever model builds, so cross-model builders inherit isolation. Verification is
always the deterministic scenario runner — there is no cross-model "judge".
