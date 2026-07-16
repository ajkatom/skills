# dark-factory M20 — First-Class HTTP Scenario Type Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Add a first-class **HTTP scenario type** to the oracle so a web service can be verified by actually **starting it, issuing a real HTTP request, and asserting on the response status + JSON body (incl. a small JSON-path)** — instead of the inline `handle()`-harness pattern the acceptance apps used. Additive: existing `when.run` (argv) scenarios are byte-identical; a scenario opts in with `when.http`. Reuses the process-group reaping + fail-closed discipline already in `run_scenarios`/`df_twins`.

**Architecture:** `run_scenarios` grows an HTTP execution path: a scenario `when.http = {"start": [argv], "port_env": "PORT", "ready_path": "/health", "request": {...}}` starts the built service (in the workspace, under the same exec-wrapper/twin-env as `run`), waits until `ready_path` returns any response (or a timeout), issues `request`, captures `(status, headers, body)`, then reaps the service by process group. New `then` keys — `http_status` (int), `body_contains` (substring of raw body), `json_equals`/`json_contains` (subset match on the parsed JSON), `json_path` (`{"a.b[0].c": value}` dotted/indexed path equals) — are evaluated by an extended pure `evaluate_http(then, observed)`. The oracle IR version bumps to `0.3` (additive). `df_gates.is_discriminating` learns the http keys so an inert http oracle (e.g. `body_contains: ""`) is rejected by the mutation gate exactly like the CLI keys.

**Honest scope (stated in docs):** the HTTP type starts ONE instance per scenario on an ephemeral port and issues ONE request (a sequence/session type is a later refinement); `json_path` is a small dotted/indexed accessor, not full JSONPath; readiness is a bounded poll of `ready_path` (a service that never becomes ready → the scenario fails `crash`/`timeout`, fail-closed). The service runs under the SAME isolation wrapper as a CLI scenario (standard/hardened), so the holdout stays unreachable to it.

**Tech Stack:** Python stdlib (http.client/urllib, socket, subprocess). pytest. `.venv/bin/python -m pytest dark-factory/tests -v` from repo root `/Users/alonadelson/Projects/ai_projects/skills`.

## Global Constraints

- **Additive + back-compat:** a scenario has EITHER `when.run` (existing) XOR `when.http` (new); load-time validation requires exactly one. All existing tests + the 874 suite stay green.
- **Fail-closed:** a service that fails to start, never becomes ready within the timeout, or crashes → the scenario FAILS with a taxonomy (`crash`/`timeout`), never a vacuous pass. The service is ALWAYS reaped (process-group kill, like df_twins), even on assertion failure or timeout — no orphan servers.
- **Isolation preserved:** the HTTP service is launched under the same `exec_wrapper` (standard/hardened sandbox) + twin env as CLI scenarios, so the control root/holdout is unreachable from it.
- **Mutation gate covers http:** `is_discriminating` rejects an http `then` that passes against an adversarial mutant response (so `body_contains:""` / an empty `json_contains` is caught pre-build).
- **Taxonomy unchanged vocabulary:** http failures map onto the FIXED taxonomy — wrong `http_status` → `wrong_exit_code` (status is the http analogue of exit code), body/json mismatch → `wrong_output`, no-response/unready → `crash`/`timeout`. No new taxonomy constant (keeps id_feedback + the barrier intact).
- **Commit messages end with:** `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`.

## File Structure

```
dark-factory/
  scripts/
    run_scenarios.py   # Task 1 — http execution + evaluate_http; Task 2 load-time validation
    df_gates.py        # Task 1 — is_discriminating over http then-keys
  references/
    scenario-format.md # Task 2 — the http scenario type + json_path
  tests/
    test_http_oracle.py      # Task 1
    test_e2e_http_oracle.py   # Task 2
```

---

### Task 1: HTTP execution + evaluate_http + mutation gate

**Files:** modify `run_scenarios.py`, `df_gates.py`; create `test_http_oracle.py`.

**Interfaces:**
```python
# run_scenarios.py
def evaluate_http(then: dict, observed: dict) -> str | None
    # observed = {"http_status": int|None, "body": str, "json": <parsed|None>}.
    # Priority: no response (status None) -> "crash"; http_status mismatch ->
    # "wrong_exit_code"; body_contains / json_equals / json_contains / json_path
    # mismatch -> "wrong_output"; else None (pass).
    # json_path: {"a.b[0]": value} — dotted keys + [i] indexing; a missing path
    # or !=value -> mismatch. json_* keys with observed["json"] is None -> mismatch.

def _run_http_scenario(sc, workspace, exec_wrapper, env_extra, timeout_s) -> dict
    # start sc["when"]["http"]["start"] (argv) in workspace under (exec_wrapper or [])
    # with env (os.environ + env_extra + {port_env: <ephemeral>} if port_env given),
    # start_new_session=True (own process group). Poll ready_path via http to
    # 127.0.0.1:<port> until 2xx/any-status or deadline; on ready, issue request
    # (method/path/headers/body); capture (status, body, parsed-json-or-None).
    # ALWAYS os.killpg the group in finally. Returns observed dict for evaluate_http.
    # port: if port_env given the service binds it; else the service must print
    # its port or use a fixed one — support port_env as the primary mechanism
    # (document); a service that binds :0 and reports the port is out of scope v1
    # (use a chosen ephemeral port passed via port_env).
```
- `run_all` dispatches per scenario: `when.run` → existing path; `when.http` → `_run_http_scenario` + `evaluate_http`. The final pass/fail + taxonomy fold into the SAME report shape (so id_feedback + cohorts + twin evidence all keep working; twin_observed still applies if the http service used a twin).
- `df_gates.is_discriminating`: detect an http `then` (has `http_status`/`body_contains`/`json_*`) and build an adversarial mutant observed (`{"http_status": (then http_status +1) or 599, "body": "\x00MUTANT", "json": {"__mutant__": True}}`); discriminating iff `evaluate_http(then, mutant) is not None`.

- [ ] **Step 1 (TDD):** `test_http_oracle.py` — evaluate_http unit matrix (status hit/miss; body_contains; json_contains subset; json_path dotted+indexed hit/miss; json_* with json None → mismatch; priority: status-miss before body); `_run_http_scenario` live against a tiny stdlib http.server fixture that binds `PORT` and serves `/health` + a JSON route (status/body/json captured; a never-ready service → crash/timeout; the server process is reaped — assert no leftover via the pid/pgid); is_discriminating over http then-keys (inert `body_contains:""` → not discriminating; a real status/body assertion → discriminating).
- [ ] **Step 2:** Implement → green. Full suite (874 + new).
- [ ] **Step 3:** Commit `feat(dark-factory): first-class HTTP scenario type (start service + real request + json assertions)`.

---

### Task 2: load-time validation + e2e + docs

**Files:** modify `run_scenarios.py` (load validation), `references/scenario-format.md`; create `test_e2e_http_oracle.py`.

- `load_scenarios`: validate a scenario has EXACTLY ONE of `when.run` / `when.http` (both or neither → OracleError naming the id); an `http` block requires `start` (non-empty argv list) + `request` (method+path); `then` for an http scenario must use http keys (a CLI `then` on an http scenario, or vice-versa, → OracleError); `ir_version` accepts `0.1`/`0.2`/`0.3`. This runs BEFORE any build (like the existing shape validation), all cohorts.
- [ ] **Step 1:** `test_e2e_http_oracle.py` (CLI subprocess): a control whose spec asks for a tiny HTTP `/health`+`/echo` service, an http scenario asserting `http_status:200` + `json_contains:{"status":"ok"}` + a `json_path`, built by a deterministic reference builder → converges; a builder whose service returns the wrong status → the http scenario fails `wrong_exit_code` and the run does NOT converge (proves the http oracle actually discriminates end-to-end); no orphan server process after the run.
- [ ] **Step 2:** `scenario-format.md`: the `when.http` type (start/port_env/ready_path/request), the http `then` keys + `json_path` mini-syntax, the taxonomy mapping (status→wrong_exit_code, body/json→wrong_output), the isolation note (service runs under the tier sandbox), and the honest scope (single instance, single request, small json_path). config/scenario cross-check.
- [ ] **Step 3:** Verify docs vs code; full suite green; commit `feat(dark-factory): http-scenario load validation + e2e + scenario-format docs`.

---

## Self-Review Notes (plan ↔ spec)

**Covered (M20):** the flagged residue #10 — a first-class HTTP scenario type (real server + real request + status/body/JSON/json-path assertions), additive to the oracle IR, mutation-gate-covered, fail-closed (unready/crash → taxonomy, always reaped), isolation-preserving (service under the tier sandbox), taxonomy-compatible (maps onto the fixed vocabulary so the barrier + id_feedback are untouched).

**Deliberately deferred (honest, in scenario-format.md):** multi-request sessions / stateful HTTP flows (v1 is one request per scenario); full JSONPath (v1 is a small dotted/indexed accessor); auto-detected ephemeral ports reported by the service (v1 injects the port via `port_env`); non-HTTP protocols.

**Honesty note:** an HTTP service that never becomes ready or crashes fails the scenario with a real taxonomy — never a vacuous pass — and is always process-group-reaped, matching the twin-lifecycle discipline; the mutation gate rejects an inert http oracle exactly like a CLI one.
