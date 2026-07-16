# dark-factory M18 — Loose Ends (notification delivery + license gate) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Close two flagged gaps in already-shipped features: (1) **notification_sink delivery** — M8 recorded a `notification_sink` config value but only journaled/printed budget alerts; wire real delivery (webhook POST / file append) so 85%-budget-alerts and budget pauses actually reach an operator channel, fail-soft; (2) **license-policy gate** — spec §7.6 lists license policy as a mandatory security gate; M9 ships the SBOM (declared deps) but no license enforcement. Add an offline license gate: an operator allowlist checked against license metadata DECLARED in the artifact's manifests / vendored package metadata, honestly scoped (no network, no transitive resolution).

**Architecture:** `df_notify.py` (stdlib) delivers a small JSON event to a sink URL (`http`/`https` POST) or a `file://` path (append ndjson); the supervisor calls it at BUDGET_ALERT/BUDGET_PAUSE when `budget.notification_sink` is set, never raising (delivery failure → journal `NOTIFY_FAILED`, continue — an alert channel being down must not fail the run). License enforcement extends `df_security` with `license_scan(root, allowlist)` reading `[project].license`/`license`/classifiers from pyproject.toml, `license` from package.json, and vendored dep license fields (node_modules/*/package.json, *.dist-info/METADATA) present in the artifact; a declared license not in the allowlist, or a dependency with NO declared license when `require_license` is set, is a finding. Wired as an M9 gate name `license` under the existing `security_gates` machinery (fail_on-eligible), so it reuses the fail-closed gate runner + manifest recording.

**Honest scope (stated in docs):** notification delivery is best-effort (fire-and-forget with a short timeout; not a guaranteed-delivery queue). The license gate covers licenses **declared** in manifests / **vendored** metadata that physically exist in the artifact tree — it does NOT resolve the license of an un-vendored transitive dependency (that needs a network lookup or a license DB, out of the offline/stdlib model); this is documented, and an un-vendored dep is reported as `license: unknown` rather than silently passed when `require_license` is on. Cost metering (the third flagged miss) stays deferred: the builder CLIs don't emit parseable token/cost usage in headless mode (`usage.known=false`), so honest metering waits on adapter usage reporting — documented in budget.md, not faked.

**Tech Stack:** Python stdlib. pytest. `.venv/bin/python -m pytest dark-factory/tests -v` from repo root `/Users/alonadelson/Projects/ai_projects/skills`.

## Global Constraints

- **Notification is fail-soft:** a delivery failure NEVER changes the run's exit code or outcome — journal `NOTIFY_FAILED` and continue. (Contrast the audit sink, which is fail-CLOSED when required — notification is an operator convenience, not an integrity anchor.) The delivered payload carries NO secret/token values (reuse the M11 redactor on the event).
- **License gate is fail-closed like other M9 gates:** a `license` finding when `license` ∈ `fail_on` → `SECURITY_GATE_FAILED` (exit 3, never qualified), via the existing gate runner. Absent config → no license gate (back-compat).
- **Back-compat:** absent `notification_sink` → today's behavior (journal + print only); absent `security_gates.license`/license allowlist → no license gate. All 796 existing tests stay green.
- **Deferred, documented:** cost metering stays `usage.known=false`; budget.md states why.
- **Commit messages end with:** `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`.

## File Structure

```
dark-factory/
  scripts/
    df_notify.py       # Task 1 — deliver(sink, event) http/file, fail-soft
    df_security.py     # Task 2 — license_scan + license gate in run_gates
    df_config.py       # Tasks 1-2 — notification_sink delivery cfg; license allowlist cfg
    supervisor.py      # Task 1 — call df_notify at BUDGET_ALERT/PAUSE
  references/
    budget.md          # Task 1 — delivery + cost-metering-deferred note
    security-gates.md  # Task 2 — license gate + honest scope
    config-reference.md
  tests/
    test_notify.py         # Task 1
    test_license_gate.py   # Task 2
```

---

### Task 1: notification_sink delivery

**Files:** create `dark-factory/scripts/df_notify.py`, `dark-factory/tests/test_notify.py`; modify `df_config.py`, `supervisor.py`, `references/budget.md`, `config-reference.md`.

**Interfaces:**
```python
# df_notify.py
class NotifyError(RuntimeError): ...   # only raised internally; deliver() never propagates
def deliver(sink: str, event: dict, *, timeout_s: int = 10, redactor=None) -> tuple[bool, str]
    # sink: "http(s)://..." → POST json.dumps(event) (Content-Type application/json);
    #       "file:///abs/path" → append one ndjson line.
    # event passed through redactor.redact_obj first if given (no secret values).
    # Returns (True,"delivered") | (False, reason). NEVER raises — all errors →
    # (False, ...). Unknown scheme → (False, "unsupported sink scheme").
```
- `df_config.py`: the existing `budget.notification_sink` string — validate when set: must be `http://`, `https://`, or `file://<abs>`; else ConfigError. (Keep default "" = no delivery.) Inject into `cfg["_budget"]["notification_sink"]` (already carried; just add validation).
- `supervisor.py`: at the BUDGET_ALERT and BUDGET_PAUSE points (M8), if `notification_sink` set, call `df_notify.deliver(sink, {"event": "BUDGET_ALERT"|"BUDGET_PAUSE", "invocation":..., "estimated_usd":..., "builder_calls":..., "cap":..., "ts":...}, redactor=redactor)`; on False → `journal.write("NOTIFY_FAILED", reason=...)`; on True → `journal.write("NOTIFY_SENT", event=...)`. Never affects control flow.

- [ ] **Step 1 (TDD):** `test_notify.py` — deliver to a `file://` tmp path appends the event (json line, redacted); deliver to a live in-process http.server receiver (mirror M13's serve pattern) POSTs the JSON (receiver saw it); unreachable http → (False, ...) NOT raised; unsupported scheme (`ftp://`) → (False, ...); a secret value in the event is redacted when a redactor is passed. Config: valid http/https/file accepted; a bare path or `ftp://` → ConfigError. Supervisor (monkeypatched deliver): BUDGET_ALERT with a sink → NOTIFY_SENT journaled; deliver returning False → NOTIFY_FAILED journaled + run still converges (exit unchanged).
- [ ] **Step 2:** Implement → green. Full suite (796 + new).
- [ ] **Step 3:** budget.md: notification delivery (fail-soft, http/file, no secrets) + the cost-metering-deferred note (usage.known=false; honest metering needs adapter usage reporting). config-reference rows. Commit `feat(dark-factory): notification_sink delivery for budget alerts (http/file, fail-soft, redacted)`.

---

### Task 2: license-policy gate

**Files:** modify `dark-factory/scripts/df_security.py`, `df_config.py`, `references/security-gates.md`, `config-reference.md`; create `dark-factory/tests/test_license_gate.py`.

**Interfaces:**
```python
# df_security.py
def license_scan(root: str, allowlist: list[str], *, require_license: bool = False) -> list[dict]
    # Returns findings [{"file","package","license","rule"}] where rule ∈
    # {"disallowed-license","missing-license"}. Sources (only those physically
    # present in the artifact tree — offline, no network):
    #   - pyproject.toml: [project] license (string or {text=}/{file=}) + a
    #     `License ::` trove classifier;
    #   - package.json: "license" (SPDX string) / "licenses" (legacy array);
    #   - vendored dep metadata: node_modules/*/package.json "license";
    #     *.dist-info/METADATA "License:" / "Classifier: License ::".
    # A declared license NOT in `allowlist` → "disallowed-license". A discovered
    # package with NO declared license AND require_license → "missing-license".
    # allowlist entries matched case-insensitively; empty allowlist → every
    # declared license is disallowed (operator must list them). Deterministic
    # (sorted). Skips .git/binary/symlinks like the other scanners.
```
- Wire into `run_gates` (M9): a new built-in gate `license`, enabled when `security_gates.license` is truthy; `run_gates` runs `license_scan(workspace, allowlist, require_license)` → gate `license` = {"status": "fail" if findings else "pass", "findings": findings}; participates in `fail_on` exactly like `secret_scan`/`dangerous_scan` (so `fail_on: ["license"]` makes a disallowed license reject the artifact fail-closed).
- `df_config.py`: `security_gates.license` block `{enabled:bool(False), allowlist:[spdx...], require_license:bool(False)}`; validate (allowlist list of non-empty strings; bools); inject into `cfg["_security"]["license"]`. `license` becomes a valid `fail_on` name (extend the M9 cross-reference validation).

- [ ] **Step 1 (TDD):** `test_license_gate.py` — license_scan over a tmp tree: pyproject with `license="MIT"` + allowlist ["MIT"] → no finding; allowlist ["Apache-2.0"] → disallowed-license finding naming MIT; package.json "GPL-3.0" not in allowlist → finding; a vendored node_modules/foo/package.json with a disallowed license → finding naming foo; require_license with a dep lacking a license → missing-license; case-insensitive match; deterministic order. run_gates: `license` gate fails when a disallowed license present + in fail_on → failed=["license"]; clean tree → pass. Config matrix + `fail_on:["license"]` accepted.
- [ ] **Step 2:** Implement → green. Full suite.
- [ ] **Step 3:** security-gates.md: the license gate (sources, allowlist, require_license, honest scope — declared/vendored only, un-vendored transitive = unknown, no network); note it's a §7.6 mandatory-gate-eligible check. config-reference rows. Commit `feat(dark-factory): license-policy security gate (declared/vendored license allowlist, offline, fail-closed)`.

---

## Self-Review Notes (plan ↔ spec)

**Covered (M18):** the budget feature's stubbed `notification_sink` now delivers (fail-soft, redacted, http/file) — completing M8's §6.2/§15.7 alerting; spec §7.6's "license policy" mandatory-gate item as an offline, fail-closed gate over declared/vendored license metadata, wired into the existing M9 gate runner (so it inherits fail_on + manifest recording + the security-report artifact).

**Deliberately deferred (honest, in docs):** authoritative cost metering (adapters return `usage.known=false`; needs the builder CLIs to emit token/cost usage — budget.md says so, not faked); transitive/un-vendored license resolution (needs a network license lookup or a bundled license DB — out of the offline/stdlib model; un-vendored deps are reported `unknown`, not silently passed); a guaranteed-delivery notification queue (M18 is best-effort fire-and-forget).

**Honesty note:** notification is fail-SOFT (an operator convenience — a down alert channel must not fail a run), explicitly contrasted with the fail-CLOSED audit sink (an integrity anchor); the license gate reports un-vendored deps as `unknown` rather than overclaiming coverage it doesn't have.
