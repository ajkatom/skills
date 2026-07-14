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
Shipped: `scripts/adapters/claude` (claude CLI, headless, cwd=workspace).
Codex/Gemini adapters land in M4.
