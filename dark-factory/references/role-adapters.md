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
- `api_anthropic` (M24) — a stdlib HTTP client, no CLI at all. See below.
- `api_openai` — a stdlib HTTP client for OpenAI's Chat Completions API, same
  shape as `api_anthropic`. See below.

Pick the builder with `df_adapters.available_builders()` (installed CLIs) and
`df_adapters.resolve_builder(name)` — the latter raises rather than substitute a
different model. Under the `standard` tier the OS sandbox denies the holdout to
whatever model builds, so cross-model builders inherit isolation. Verification is
always the deterministic scenario runner — there is no cross-model "judge".

(`api_anthropic`/`api_openai` are not in `df_adapters.BUILDERS` — that
registry's `available_builders()` check is "is this CLI on PATH", which
doesn't apply to an adapter with no CLI; select one by pointing
`roles.builder.adapter` at `scripts/adapters/api_anthropic` or
`scripts/adapters/api_openai` directly.)

## `api_anthropic` — the Messages-API builder adapter (M24)

`scripts/adapters/api_anthropic` drives a real model over the **Anthropic
Messages HTTP API** instead of a CLI — stdlib `urllib`/`json` only, no
subprocess, no third-party dependency. That is the entire point of this
adapter: **it needs nothing a minimal container doesn't already have**
(`python3`), so it is the first builder adapter that can run to completion
inside the hardened/enterprise tier's container. `claude`/`codex`/`gemini`
all shell out to a binary that plain `python:3.12-alpine` doesn't ship —
inside that container they fail closed with "CLI not found on PATH". This
adapter has no such dependency, closing the gap `references/hardened.md`
("Image requirements for real builders") documented: a real cross-model
build inside the container used to require a user-supplied image with the
CLI baked in; now a stdlib HTTP adapter needs no image customization at all.

**Protocol.** Same adapter-protocol 0.1 request/response as every other
adapter (`workdir`, `prompt_file`, `timeout_s`, `confine`). The model sees
only the prompt file's content (spec + prior-iteration feedback), exactly
like the CLI adapters.

**Request.** `POST {ANTHROPIC_BASE_URL}/v1/messages` (`ANTHROPIC_BASE_URL`
env, default `https://api.anthropic.com`) with header `x-api-key:
$ANTHROPIC_API_KEY`, `anthropic-version: 2023-06-01`, and a body naming
`model` (`DF_API_MODEL` env, default `claude-sonnet-4-5`) plus a `system`
prompt that imposes a strict output contract.

**Output contract.** The model MUST reply with exactly one JSON object:
```json
{"files": {"<relative/path>": "<complete literal file content>", ...}}
```
No prose, no explanation, no fenced block containing anything else (a
leading/trailing ` ```json ` fence around the object IS tolerated and
stripped). Every value fully replaces whatever is at that path — this
pipeline does not apply patches or diffs. A model reply that doesn't parse
into this shape is an adapter **error**, never a garbage/partial build:
fail-closed, matching every other adapter's "no best-effort success" posture.

**First-text-block / thinking handling.** Extended-thinking models (e.g.
claude-sonnet-5) emit a `"thinking"` content block *before* the `"text"`
block, so `content[0]["text"]` is not safe to read blindly (it KeyErrors on
a thinking block). The adapter scans `content` and takes the first block
whose `type` is `"text"` (or that simply carries a string `"text"` field),
skipping any thinking block(s) ahead of it. Found live: a real
claude-sonnet-5 KV-store build returned `content=[thinking, text]`.

**Path-safety (security-critical).** Every path in the model's reply goes
through `_safe_join`: absolute paths, `..`-traversal segments, and a symlink
that resolves outside `workdir` are all rejected. Every path is validated
**before any file is written** — an unsafe path anywhere in the reply
discards the whole reply (all-or-nothing), never a partial tree.

**Key handling.** `ANTHROPIC_API_KEY` is read from env, sent only in the
`x-api-key` header, and never appears in a response `detail`, stdout,
stderr, or any written file — not even on a failure path (no key, HTTP
error, unparseable reply, unsafe path all produce a short, key-free
`{"status":"error","detail":"..."}`; the adapter never raises uncaught and
never dumps a raw response body beyond a bounded snippet).

**Overrides.** `ANTHROPIC_BASE_URL` — point at a test stub, or (enterprise)
the credential-proxy endpoint instead of `api.anthropic.com` directly.
`DF_API_MODEL` — pin a specific model id.

**Confinement.** `df_confine.PROFILES["api_anthropic"]` is `supported: True`
on structural grounds, not a live tool-denial probe — see
`references/builder-confinement.md` ("api_anthropic — structural
confinement") for why a plain HTTP client needs no such probe.

**Proven live.** `dark-factory/tests/test_e2e_api_container.py` runs this
adapter, live, INSIDE a real `python:3.12-alpine` Docker container
(`network: bridge`, the adapter's directory ro-mounted, the workspace
rw-mounted — the same `df_container.build_argv` shape the hardened tier
uses for every builder call) against a local stub Messages endpoint reached
via `host.docker.internal` (the M17 host-service pattern). This is
deterministic (stub-brained, no paid calls) and runs in the suite. Separately,
in development, a **real** `claude-sonnet-5` built a small KV-store app this
same way (in-container, over the real Messages API) and passed all 12 hidden
acceptance scenarios — see `references/hardened.md` for the honest split
between what the suite proves (the mechanism) and what was proven live but
not automated (a real paid model).

## `api_openai` — the Chat Completions builder adapter

`scripts/adapters/api_openai` is the OpenAI-equivalent of `api_anthropic`:
same stdlib-only, no-CLI, structurally-confined design, driving a real model
over **OpenAI's Chat Completions HTTP API** instead of the Anthropic Messages
API. It closes the same gap for OpenAI models that `api_anthropic` closes for
Claude models — a minimal `python:3.12-alpine` container with no CLI can
still run a real build.

**Protocol.** Identical adapter-protocol 0.1 request/response shape.

**Request.** `POST {OPENAI_BASE_URL}/v1/chat/completions` (`OPENAI_BASE_URL`
env, default `https://api.openai.com`) with header `Authorization: Bearer
$OPENAI_API_KEY`, and a body naming `model` (`DF_API_MODEL` env, default
`gpt-4o`), a `system` message imposing the same strict `{"files": {...}}`
output contract as `api_anthropic`, plus `response_format:
{"type":"json_object"}` — a Chat Completions feature that constrains the
provider to emit valid JSON. This is belt-and-suspenders on top of the same
fence-stripping/parsing `api_anthropic` uses, not a replacement for it: the
adapter still validates and parses the reply itself rather than trusting the
provider flag to hold against every model.

**Output contract, path-safety, key handling, overrides.** Identical to
`api_anthropic` (see above) — same `_safe_join`, same all-or-nothing write
with rollback on a mid-write `OSError`, same never-leaks-the-key discipline
(`OPENAI_API_KEY` only ever appears in the `Authorization` header),
`OPENAI_BASE_URL`/`DF_API_MODEL` overrides.

**Usage field-name mapping.** OpenAI's Chat Completions response reports
usage as `{"prompt_tokens": N, "completion_tokens": M}` — the adapter maps
these onto the SAME protocol-uniform field names `api_anthropic` uses
(`input_tokens`/`output_tokens`) so the supervisor's cost-metering
accounting (`references/budget.md`) stays provider-agnostic; it never sees
the OpenAI-specific field names.

**Confinement.** `df_confine.PROFILES["api_openai"]` is `supported: True` on
the same structural grounds as `api_anthropic` — a plain HTTP client has no
agentic tool/MCP/sub-agent surface to strip or probe.

**Model-naming caveat.** The request body sends `max_tokens` (the
long-standing Chat Completions parameter). Some newer reasoning-tuned
OpenAI models expect `max_completion_tokens` instead and will reject
`max_tokens` with an HTTP 400 — the adapter still fails closed cleanly on
that (`"api returned HTTP 400"`), it just won't build. If pinning
`DF_API_MODEL` to such a model, verify it accepts `max_tokens` first (or
expect this adapter to need a small follow-up change for that model
family).

**Proven live.** `dark-factory/tests/test_openai_adapter.py` drives this
adapter end-to-end (subprocess, protocol 0.1) against a local stub Chat
Completions endpoint (`tests/fixtures/stub_chat_api`) — deterministic, no
paid calls, runs in the suite. Unlike `api_anthropic`, this adapter does
**not** yet have an in-container e2e test or a real-paid-model live proof —
that is a deliberate, honest scope boundary (not deferred silently): the
container-level mechanism (`df_container.build_argv` + `host.docker.internal`
reaching a host-side stub or the real API) is identical to what
`test_e2e_api_container.py` already proves for `api_anthropic`, so the
residual risk is low, but it has not been separately exercised for this
adapter. An operator with an `OPENAI_API_KEY` can run it live the same way
`api_anthropic` was proven live (point `roles.builder.adapter` at
`scripts/adapters/api_openai`, set `DF_API_MODEL` if the default doesn't fit).
