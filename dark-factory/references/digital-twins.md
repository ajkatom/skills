# Digital Twins Reference (M3a)

A **digital twin** is a launchable behavioral mock of an external service that your task's code talks to. Twins run alongside the builder and verifier to enable development and deterministic verification without hitting real production services.

## Twin Definition Schema (twin_version 0.1)

Each twin is defined by a JSON file in `<control_root>/twins/<name>.json`.

| Field | Type | Rules | Notes |
|---|---|---|---|
| `twin_version` | string | Must be `"0.1"` | Required. Future versions may add new fields. |
| `name` | string | `^[a-z][a-z0-9_]{0,30}$` (lowercase, digits, underscore; max 31 chars) | Unique within a control root. Used to derive the environment variable name. |
| `launch` | array of strings | Non-empty list of command parts (argv). | The command that starts the twin service. Runs with `cwd = <control_root>/runs/<invocation_id>` (the run dir) and inherited environment plus `DF_ENDPOINT_FILE`. **A relative path resolves against the run dir, not `twins/`** — use an **absolute path** to your twin script (e.g. `["python3", "/abs/path/to/greeter.py"]`). |
| `env_var` | string | Optional; defaults to `DF_TWIN_<NAME_UPPER>`. Not format-validated — supply a valid environment-variable name. | Environment variable name exposed to the builder and scenario verifier. Defaults to `DF_TWIN_<NAME_UPPER>` (e.g., `greeter` → `DF_TWIN_GREETER`). |
| `fidelity` | string | Human-readable note. | Describes the mock's honesty level relative to the real service (e.g., `"dev mock, basic HTTPS stub"`, `"async job enqueue only, no scheduler"`, `"read-only, no mutations"`). A human-readable honesty note in the def file (documentation only; not read or surfaced by the supervisor). |

### Example Twin Definition

```json
{
  "twin_version": "0.1",
  "name": "greeter",
  "launch": ["python3", "/abs/path/to/greeter.py"],
  "env_var": "DF_TWIN_GREETER",
  "fidelity": "dev mock, HTTP only, no auth"
}
```

## Endpoint-File Readiness Protocol

The supervisor passes `DF_ENDPOINT_FILE=<path>` to each twin's launch command (as an environment variable). The twin **must**:

1. Once it can accept connections, write exactly one line to that file: `<host>:<port>` (e.g., `127.0.0.1:8080`).
2. Keep running after writing the endpoint file.

The supervisor waits up to `twins.startup_timeout_s` (default 20 seconds, configurable in `config.json`) for the endpoint file to be written. If:
- The file never appears → the run aborts (exit 2, journaled `TWIN_ERROR`).
- The twin process exits before writing the endpoint file → the run aborts (exit 2, `TWIN_ERROR`).

### Why This Protocol?

Twins must discover an ephemeral network port at runtime (avoid hardcoding ports; they may be in use). By writing the endpoint to a file, the supervisor can reliably detect readiness without polling HTTP endpoints or parsing logs — deterministic, language-agnostic, and testable in isolation.

## Lifecycle

The supervisor orchestrates twin lifecycle:

1. **Startup (before builder runs).** If `twins.enabled: true` in config.json, the supervisor starts all twin services defined in `<control_root>/twins/*.json`. Each twin is given `DF_ENDPOINT_FILE=<path>` and waits for the endpoint file up to `twins.startup_timeout_s` seconds. If any twin fails to start, the run aborts (exit 2).

2. **Builder development.** The builder runs with all twin endpoints exposed as environment variables (e.g., `DF_TWIN_GREETER=127.0.0.1:8080`). The builder's code can call out to the twins via localhost.

3. **Reset before each verify pass.** Before each verify pass (loop iteration) runs, the supervisor **terminates and restarts** all twins from scratch. This ensures deterministic, repeatable verification: the supervisor resets all twins to a fresh state once before the whole scenario suite for that iteration runs, then each scenario verifies against that fresh instance. (Scenarios within a single verify pass share the reset instance; per-scenario reset is not provided.)

4. **Scenario verification.** Each scenario's `when.run` commands run with the twin endpoints in their environment, same as the builder.

5. **Teardown (always).** At every terminal state — convergence, cap reached, abort, pause checkpoint, or error — the supervisor **always terminates** all twins. This prevents orphaned processes and ensures clean sandbox exit.

## Composition: Twins Outside the Sandbox

Twins are **trusted infrastructure**: they run **outside** the OS read-denial sandbox and are defined by you (the human), not by the builder. This allows:

- **Localhost access:** The sandboxed builder and verifier can reach twins on localhost (the sandbox allows loopback network access; it denies reading the holdout filesystem, not networking).
- **Persistent state (dev only).** Twins can maintain state across builder iterations (see "Honest Scope" below).
- **No sandbox containment.** Twins are not subject to `sandbox-exec` (macOS) or `bwrap` (Linux) read-denial; they can access files, write logs, etc.

## Honest Scope: Dev-Shared Twins (M3a)

### What M3a Ships

This milestone deploys a **shared twin** model: the **same twin instance** that the builder develops against is used by the verifier. This is appropriate for:

- **Development.** Builders need feedback-loop speed; a dev twin running locally (not mocked into scenario JSON) enables rapid iteration.
- **Behavioral contracts.** Verify that your code handles the twin's happy path and error cases consistently.

### What M3a Does NOT Ship (Deferred)

The dark-factory spec (§5.2) envisions **verifier-only hidden twin variants** chosen after the spec freezes — a different mock behavior for each scenario to test adversarial/edge cases without the builder seeing them. This requires:

- Sandboxed scenario orchestration (the current scenario runner cannot control twins).
- Per-scenario twin configuration discovery without revealing scenarios to the builder.

These features arrive in `hardened`/`enterprise` tiers (not yet built). M3a deliberately does not include them.

### Fidelity and Drift

Per-service **fidelity scoring** (measuring how well the twin predicts real-world behavior) and drift-detection (alerting when the real service diverges) are also deferred. Track this separately outside dark-factory.

### Results Are Twin-Observed

When dark-factory reports **results**, they are labeled **`twin-observed`** — not production-verified. This means:

- The builder's code worked against the mock.
- The verifier's scenarios passed against the mock.
- **This does not prove behavior against the real service.**

### Human-Gated Real / Staging Check (Required)

Before you ship code that relies on external services, a **human must validate** against the real service or a staging replica:

1. **Manual smoke test:** Call a few key endpoints on the real service (or staging) with your built code.
2. **Compare behavior:** Confirm the real service response matches what your mock twin said it would.
3. **Check error handling:** Trigger a real (or staged) error condition and verify your code handles it.
4. **Audit fidelity notes:** Read the `fidelity` string in your twin definitions and verify each claim.

Twins are behavioral mocks, not the production contract. The real service owner and its API documentation are the source of truth.

## Worked Example: Greeter Twin

This small HTTP server twin demonstrates the protocol:

```python
#!/usr/bin/env python3
"""A stdlib HTTP twin for tests. Binds an ephemeral port, writes host:port to
$DF_ENDPOINT_FILE, then serves GET /greet/<name> -> 'Hello, <name>!' (200).
Behavioral mock of a 'greeter service' — never a production contract."""
import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/greet/"):
            name = self.path[len("/greet/"):]
            body = f"Hello, {name}!".encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404); self.end_headers()

    def log_message(self, *a):  # quiet
        pass


def main():
    srv = HTTPServer(("127.0.0.1", 0), H)
    host, port = srv.server_address
    ep = os.environ.get("DF_ENDPOINT_FILE")
    if ep:
        with open(ep, "w", encoding="utf-8") as f:
            f.write(f"{host}:{port}")
    srv.serve_forever()


if __name__ == "__main__":
    main()
```

**Twin definition (`twins/greeter.json`):**

```json
{
  "twin_version": "0.1",
  "name": "greeter",
  "launch": ["python3", "/abs/path/to/greeter.py"],
  "fidelity": "dev mock, HTTP only, no authentication"
}
```

**Usage in your code (builder or scenario):**

```python
import os
import urllib.request

endpoint = os.environ.get("DF_TWIN_GREETER")  # e.g., "127.0.0.1:8080"
if endpoint:
    response = urllib.request.urlopen(f"http://{endpoint}/greet/World")
    print(response.read().decode())  # "Hello, World!"
```

## Config Integration

To enable twins, set `twins.enabled: true` in your `<control_root>/config.json`:

```json
{
  "config_version": "0.1",
  "twins": {
    "enabled": true,
    "startup_timeout_s": 20
  }
}
```

| Field | Type | Default | Notes |
|---|---|---|---|
| `twins.enabled` | boolean | `false` | When `true`, the supervisor loads and starts twins. At least one twin def must exist in `<control_root>/twins/`. |
| `twins.startup_timeout_s` | integer | `20` | Max seconds to wait for each twin to write its endpoint file (1..120). |

## Summary

Twins are a **development convenience** and **dev-shared verification aid** in M3a. They allow isolated, fast iteration and deterministic testing without hitting real services. But they are **mocks**, not the production contract. Always validate against the real service or staging before shipping.
