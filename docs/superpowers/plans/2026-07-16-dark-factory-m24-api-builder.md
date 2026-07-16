# dark-factory M24 — API-Key Builder Adapter (real model inside the container) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** A **stdlib-only builder adapter** (`adapters/api_anthropic`) that drives a real model via the **Anthropic Messages HTTP API** — no CLI to install — so a real model can build **inside the minimal hardened/enterprise container** (which has python3 but no `claude`/`codex` binary). The adapter reads the spec from the prompt file, POSTs it to the Messages API (key from env, base URL overridable so it can point at the enterprise egress proxy OR a test stub), parses the model's file output, and **writes each file into the workspace with strict path-safety** (a returned path that escapes the workspace is refused). Live real-model-in-container is then one operator step: an API key + `network: bridge` (governed by the M17 proxy at enterprise). We prove the full **mechanism** live — the adapter running inside `python:3.12-alpine` against a local stub endpoint, building an app to a qualified+signed artifact — and document the key as the only remaining input.

**Architecture:** `adapters/api_anthropic` (executable, stdlib `urllib`/`json`) speaks adapter-protocol 0.1: reads the request JSON (`workdir`, `prompt_file`, `timeout_s`, `confine`), composes a Messages request (system = the builder prompt content + a strict output contract, `model` from env `DF_API_MODEL` default a current Claude model id, key from `ANTHROPIC_API_KEY`, base from `ANTHROPIC_BASE_URL` default `https://api.anthropic.com`), POSTs, parses the model's reply which MUST be a single JSON object `{"files": {"<relpath>": "<content>", ...}}`, and writes each file under `workdir` after `_safe_join` rejects absolute paths / `..` traversal / symlink escapes. On any error (no key, HTTP non-200, unparseable reply, unsafe path) → an in-band adapter error (status "error", detail) — NEVER writes a partial/unsafe tree, never leaks the key. `df_confine` gets an `api_anthropic` profile (it's a plain HTTP client — confinement = the env it's handed; at enterprise the proxy is its only egress).

**Honest scope (stated in docs):** the adapter is proven end-to-end **against a local stub Messages endpoint** (deterministic, no paid calls) INCLUDING a live run inside the hardened container; the ONLY thing the stub stands in for is the model's brain — every other layer (container, network, HTTP, parse, path-safe write, verify, security gates, signed audit) is the real thing. A live *paid-model* in-container run needs `ANTHROPIC_API_KEY` + `network: bridge` (or the enterprise proxy) — an operator step, documented, not faked. The output contract is a strict `{"files": {...}}` JSON (a model that ignores it → adapter error, fail-closed — the run does not converge on garbage). Real models on the host already build fine (proven at cooperative/standard); this milestone is specifically about the container path.

**Tech Stack:** Python stdlib (urllib, json). Docker (live in-container run). pytest. `.venv/bin/python -m pytest dark-factory/tests -v` from repo root `/Users/alonadelson/Projects/ai_projects/skills`.

## Global Constraints

- **Path-safety (security-critical):** a file path in the model's reply is written ONLY if it resolves to a path strictly under `workdir` (reject absolute, `..`-escape, and a symlink whose target escapes). An unsafe path → adapter error, no files written (all-or-nothing: validate every path BEFORE writing any). Test with adversarial paths (`/etc/x`, `../../x`, `a/../../x`).
- **No key leak:** the API key is read from env, sent only in the `x-api-key` header to the base URL, and NEVER written to stdout/stderr/the workspace/any error message. A stub-endpoint test greps the adapter's output + workspace for the key → absent.
- **Fail-closed:** no key / HTTP error / unparseable reply / non-`{"files":...}` shape / unsafe path → status "error" with a short detail (no key, no raw reply body dump beyond a bounded snippet) → the supervisor records ABORTED_BUILD_ERROR (existing behavior), run does not converge. Never a partial write.
- **Additive:** new adapter + a confinement profile + tests; no change to existing adapters/tiers. All 1066 tests stay green.
- **Commit messages end with:** `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`.

## File Structure

```
dark-factory/
  scripts/
    adapters/api_anthropic   # Task 1 — the stdlib Messages-API builder adapter
    df_confine.py            # Task 2 — api_anthropic confinement profile
  references/
    role-adapters.md         # Task 2 — the API adapter + real-model-in-container
    hardened.md              # Task 2 — the operator step (key + bridge/proxy)
  tests/
    fixtures/stub_messages_api   # Task 1 — a stdlib stub Anthropic endpoint
    test_api_adapter.py           # Task 1
    test_e2e_api_container.py      # Task 2 (live, skipif no docker)
```

---

### Task 1: the api_anthropic adapter + stub endpoint

**Files:** create `dark-factory/scripts/adapters/api_anthropic` (executable), `dark-factory/tests/fixtures/stub_messages_api` (executable), `dark-factory/tests/test_api_adapter.py`.

**Interfaces:**
- `adapters/api_anthropic` (protocol 0.1): read request JSON on stdin; `prompt = open(prompt_file).read()`; build Messages POST to `{base}/v1/messages` with headers `x-api-key: $ANTHROPIC_API_KEY`, `anthropic-version: 2023-06-01`, `content-type: application/json`, body `{"model": $DF_API_MODEL, "max_tokens": N, "system": <builder output-contract>, "messages": [{"role":"user","content": prompt}]}`; timeout from the request. Parse the response `content[0].text` → strict `{"files": {...}}` JSON (tolerate a leading/trailing ```json fence — strip it). For each path: `_safe_join(workdir, path)` (reject unsafe → error). Write all files (create parent dirs). Emit `{"adapter_protocol":"0.1","status":"ok","detail":"","usage":{"known":false}}` on success, or `{"...","status":"error","detail":"<short>"}` on any failure. Never raise uncaught; never print the key.
- `fixtures/stub_messages_api`: a tiny stdlib http.server that binds a port (prints/writes it), accepts POST `/v1/messages`, and returns a canned Messages-shaped JSON whose `content[0].text` is a `{"files": {...}}` for a requested app (parameterize which app via an env var so tests can request greet vs a bad-shape vs an unsafe-path reply). Used as the adapter's `ANTHROPIC_BASE_URL` in tests — no paid calls, deterministic.

- [ ] **Step 1 (TDD):** `test_api_adapter.py` — drive the adapter (as a subprocess, protocol 0.1) with `ANTHROPIC_BASE_URL` pointed at the stub + `ANTHROPIC_API_KEY=test-...`: (a) stub returns a greet `{"files":{"greet.py":...}}` → adapter writes greet.py under workdir, status ok; (b) stub returns an unsafe path (`../../x` and `/etc/x`) → adapter status error, NO file written anywhere (assert the escape target absent); (c) stub returns a non-`{"files":...}` shape / non-JSON → status error; (d) missing ANTHROPIC_API_KEY → status error "no api key", no HTTP call made; (e) stub returns HTTP 500 → status error; (f) the api key value NEVER appears in the adapter's stdout/stderr or any written file (grep). All deterministic (stub, no network).
- [ ] **Step 2:** Implement → green. Full suite (1066 + new).
- [ ] **Step 3:** Commit `feat(dark-factory): api_anthropic builder adapter — stdlib Messages-API client, path-safe file writes`.

---

### Task 2: confinement profile + live in-container e2e + docs

**Files:** modify `df_confine.py`, `references/role-adapters.md`, `references/hardened.md`; create `dark-factory/tests/test_e2e_api_container.py`.

- `df_confine`: add an `api_anthropic` profile — it's a plain HTTP client (no MCP/skills/tools to strip); confinement for it = the env it's handed (the credential broker / proxy controls the key + egress). Mark `supported: True` for a clean-env probe (it doesn't need a live-tool confinement probe like the CLI builders — document why: there is no agentic tool surface to escape through, only an HTTP POST to a fixed endpoint). If the confinement model requires a probe, make it a trivially-passing structural one (the adapter's argv/env is fully controlled by the supervisor).
- [ ] **Step 1:** `test_e2e_api_container.py` (skipif no docker): a HARDENED control root whose builder adapter is `api_anthropic`, with the stub_messages_api running on the host (reachable from the container via `host.docker.internal` — the M17 pattern) returning the KV app, `network: bridge`, `ANTHROPIC_BASE_URL`+`ANTHROPIC_API_KEY` passed into the container as the builder env (via the M11 credentials allowlist or directly for the test) → the adapter runs INSIDE python:3.12-alpine, POSTs the stub, writes app.py, and the container pipeline CONVERGES qualified + signed (verify-manifest OK). This proves real-model-in-container end-to-end with only the model's brain stubbed. Assert: sandbox_backend container-docker, qualified True, the built app.py present + passing the KV scenarios, no key in any run artifact.
- [ ] **Step 2:** `role-adapters.md`: the `api_anthropic` adapter (protocol, the strict `{"files":...}` output contract, path-safety, key from env, base-url override), and **why it unlocks real-model-in-container** (stdlib, no CLI → runs in the minimal container). `hardened.md`: the operator step to go from the proven mechanism to a live paid model — set `ANTHROPIC_API_KEY`, `network: bridge` (or, at enterprise, add `api.anthropic.com` to the credential-proxy allowlist so egress stays governed), point `ANTHROPIC_BASE_URL` at the real API. Honest scope: the e2e stubs the model's brain; every other layer is real.
- [ ] **Step 3:** Verify docs vs code; full suite green; run the live in-container e2e for real; commit `feat(dark-factory): real-model-in-container e2e via api_anthropic (stub-brained, live container) + docs`.

---

## Self-Review Notes (plan ↔ spec)

**Covered (M24 / residue #4):** a stdlib API-key builder adapter that runs a model inside the minimal hardened/enterprise container (no CLI needed) — with strict path-safety on the model's file output, no key leak, fail-closed on any error, and a LIVE in-container e2e proving the full pipeline (container + network + HTTP + parse + path-safe write + verify + security gates + signed audit) with only the model's brain stubbed. This closes the M10-documented gap ("real-model-in-container needs a builder image with the CLI") by removing the CLI requirement entirely — a stdlib HTTP adapter needs nothing but python3, which the container already has.

**Deliberately deferred (honest, in docs):** a live PAID-model in-container run (needs an ANTHROPIC_API_KEY + network egress — the one operator step, documented, gated exactly like the gemini live builder); an OpenAI/Chat-Completions variant (`api_openai` — same shape, trivial to add once the Anthropic one lands); streaming/token-usage metering from the API (the adapter could parse `usage` from the Messages response to finally give real cost metering — noted as a natural follow-on now that a raw API response is in hand, but out of this milestone's scope); model-agnostic output contracts beyond `{"files":...}`.

**Honesty note:** the e2e stubs ONLY the model's brain (a canned Messages response) — the container, the network hop, the HTTP client, the path-safe write, and the whole verify/gate/sign pipeline are real and run live; the step to a real model is a documented key+egress config, not new code.
