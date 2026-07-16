# dark-factory M22 — Enterprise Refinements (configurable+probed seccomp, durable notifications) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Two genuinely-buildable, live-testable enterprise/ops refinements: (1) **configurable + live-probed enterprise seccomp** — M17 ships one fixed conservative seccomp profile; make it an operator knob (`enterprise.seccomp_profile`) that is JSON-validated AND **live-probed to actually deny the syscalls it claims** (a profile that doesn't block `mount`/`ptrace` is rejected fail-closed), and ship a stricter `enterprise-strict.json` variant; (2) **durable notification delivery** — M18's notification is best-effort fire-and-forget, so a transient sink outage silently drops the alert; add an at-least-once option that **spools undelivered events to disk and retries** (still fail-soft to the run — a down sink never fails the build — but the alert is not lost silently). The rest of the enterprise "refinements" surface (mTLS on the proxy channel, HSM-backed approver keys, per-role candidate seccomp) is documented as deferred with reasons.

**Architecture:** `df_config` adds `enterprise.seccomp_profile` (a path; defaults to the shipped `seccomp/enterprise.json`; validated as a Docker seccomp JSON dict with `defaultAction` + a `syscalls` list; injected into `cfg["_enterprise"]`). `df_container.probe_seccomp(image, profile_path)` (M16-harness style) runs a container under the profile and asserts a denied syscall (e.g. `mount`) fails with EPERM AND an allowed op (file write in /tmp) succeeds — fail-closed: a profile that doesn't deny → probe False → enterprise refuses. `df_notify` gains `deliver_durable(sink, event, spool_dir, *, attempts, redactor)`: tries `deliver`; on failure appends the (redacted) event to `<spool_dir>/pending.ndjson` and returns `(False, "spooled")`; a `flush_spool(sink, spool_dir, redactor)` re-attempts spooled events (removing delivered ones). The supervisor uses the durable path when `budget.notification_durable: true`, flushing the spool at run start. Never raises; never fails the run.

**Honest scope (stated in docs):** the seccomp probe proves the profile denies the ONE canary syscall it checks (`mount`) + a couple more it's told to check — it is not a full profile audit (a profile could still allow other dangerous calls the operator didn't think to deny; the probe raises the floor, doesn't prove completeness). Durable notification is at-least-once with a local disk spool + bounded retry — not a real message queue (no cross-host durability, no ordering guarantees, no dedup beyond the spool file); it stays fail-soft (a permanently-down sink leaves events spooled, never fails the run). mTLS/HSM/per-role-candidate-seccomp remain deferred (need real PKI / an HSM / Linux-only candidate seccomp wiring).

**Tech Stack:** Python stdlib. Docker (seccomp probe — live here). pytest. `.venv/bin/python -m pytest dark-factory/tests -v` from repo root `/Users/alonadelson/Projects/ai_projects/skills`.

## Global Constraints

- **Seccomp fail-closed:** at enterprise, if `probe_seccomp` fails (profile doesn't deny the canary syscalls, or the container can't run it) → the enterprise run refuses (SandboxError, exit 2) or journaled DOWNGRADE under --allow-downgrade — never runs under an unverified profile.
- **Notification stays fail-soft:** durable delivery NEVER raises and NEVER changes the run's exit/outcome. A permanently-down sink → events remain in the spool (a warning journaled), run proceeds. Spooled events carry NO secret values (redactor applied before spooling, like M18).
- **Back-compat:** absent `enterprise.seccomp_profile` → the M17 default profile (byte-identical behavior); absent `notification_durable` → M18 best-effort (byte-identical). All 942 tests stay green.
- **Commit messages end with:** `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`.

## File Structure

```
dark-factory/
  scripts/
    df_container.py    # Task 1 — probe_seccomp
    df_config.py       # Task 1 — enterprise.seccomp_profile; Task 2 — notification_durable
    supervisor.py      # Task 1 — enterprise seccomp probe gate; Task 2 — durable notify + flush
    df_notify.py       # Task 2 — deliver_durable + flush_spool
    seccomp/enterprise-strict.json  # Task 1
  references/
    enterprise.md      # Task 1 — configurable/probed seccomp + deferred (mTLS/HSM)
    budget.md          # Task 2 — durable notification
    config-reference.md
  tests/
    test_seccomp_probe.py     # Task 1
    test_notify_durable.py     # Task 2
```

---

### Task 1: configurable + live-probed enterprise seccomp

**Files:** modify `df_container.py`, `df_config.py`, `supervisor.py`, `references/enterprise.md`, `config-reference.md`; create `seccomp/enterprise-strict.json`, `dark-factory/tests/test_seccomp_probe.py`.

**Interfaces:**
- `df_config`: `enterprise.seccomp_profile` optional path (default = the shipped `scripts/seccomp/enterprise.json`). Validate: file exists, parses as JSON, is a dict with a string `defaultAction` and a list `syscalls`. Else ConfigError. Inject `cfg["_enterprise"]["seccomp"] = <resolved abs path>`.
- `df_container.probe_seccomp(image, profile_path, *, timeout_s=120, runner=subprocess.run) -> bool`: run `docker run --rm --security-opt seccomp=<profile> --cap-add SYS_ADMIN <image> sh -c '<probe>'` where the probe attempts `mount` (must fail EPERM/non-zero) AND writes /tmp/ok (must succeed), printing a marker line; True ONLY IF the denied-syscall attempt failed AND the allowed op succeeded (fail-closed: any error/timeout/ambiguous → False). Add `unshare` + `ptrace` canaries too (each must be denied). (Add SYS_ADMIN so a profile that fails to deny `mount` would otherwise SUCCEED — proving the seccomp filter, not the cap, does the denying.)
- `supervisor` enterprise resolve: after the existing container/egress checks, `probe_seccomp(image, cfg["_enterprise"]["seccomp"])` — fail → PROBE_FAILED + SandboxError (or DOWNGRADE under --allow-downgrade), same discipline as the egress probe. Record `enterprise_seccomp={"profile": <basename>, "probe": "verified"}` on the manifest.
- `seccomp/enterprise-strict.json`: a stricter profile (the M17 denials + more, e.g. also deny `clone`(with CLONE_NEWNS flag is hard — just add more syscalls: `keyctl`,`add_key`,`request_key`,`acct`,`quotactl`,`ioperm`,`iopl`) — valid Docker seccomp JSON.

- [ ] **Step 1 (TDD):** `test_seccomp_probe.py` — config: default profile injected when absent; a bad path / non-JSON / missing defaultAction → ConfigError; the strict profile validates. probe_seccomp with injected fake runner: marker shows denied+allowed → True; denied-op SUCCEEDED (profile too loose) → False; allowed-op failed → False; timeout/nonzero → False. **Live (skipif no docker):** `probe_seccomp(DEFAULT_IMAGE, enterprise.json)` → True (mount denied, /tmp write ok); a deliberately-empty profile ({"defaultAction":"SCMP_ACT_ALLOW","syscalls":[]}) → False (mount NOT denied) — proving the probe catches a loose profile.
- [ ] **Step 2:** Implement → green. Full suite (942 + new).
- [ ] **Step 3:** enterprise.md (configurable/probed seccomp + the honest "probes the canary syscalls, not a full audit" scope + mTLS/HSM deferred) + config-reference rows. Commit `feat(dark-factory): configurable + live-probed enterprise seccomp profile (fail-closed)`.

---

### Task 2: durable notification delivery

**Files:** modify `df_notify.py`, `df_config.py`, `supervisor.py`, `references/budget.md`, `config-reference.md`; create `dark-factory/tests/test_notify_durable.py`.

**Interfaces:**
- `df_notify.deliver_durable(sink, event, spool_dir, *, attempts=1, timeout_s=10, redactor=None) -> (bool, str)`: calls `deliver` up to `attempts` times; on final failure, append the REDACTED event as one ndjson line to `<spool_dir>/pending.ndjson` (create dir) → return `(False, "spooled")`; success → `(True, "delivered")`. Never raises.
- `df_notify.flush_spool(sink, spool_dir, *, timeout_s=10, redactor=None) -> dict`: read `<spool_dir>/pending.ndjson` (absent → `{"flushed":0,"remaining":0}`); re-attempt each event via `deliver`; rewrite the file with only the still-undelivered events; return counts. Never raises.
- `df_config`: `budget.notification_durable` bool (default False), `budget.notification_attempts` int ≥1 (default 3). Injected into `cfg["_budget"]`.
- `supervisor`: at run start, if durable + a sink → `flush_spool(sink, <control_root>/.notify-spool, redactor=redactor)` (journal NOTIFY_FLUSH counts). At BUDGET_ALERT/PAUSE, when durable → `deliver_durable(..., spool_dir=..., attempts=...)` instead of `deliver`; spooled → journal NOTIFY_SPOOLED (still fail-soft, exit unchanged).

- [ ] **Step 1 (TDD):** `test_notify_durable.py` — deliver_durable to a live in-process receiver → delivered, spool empty; to an unreachable sink → (False,"spooled") + pending.ndjson has the (redacted) event, NEVER raises; attempts>1 retries then spools; flush_spool with a now-reachable receiver delivers the spooled event + empties the file; a still-down sink on flush → events remain, counts correct; a secret in the event is redacted in the spool file. Supervisor (monkeypatched): durable + down sink → NOTIFY_SPOOLED journaled + run still converges (exit unchanged); a later run flushes the spool (NOTIFY_FLUSH).
- [ ] **Step 2:** Implement → green. Full suite.
- [ ] **Step 3:** budget.md (durable at-least-once + spool + honest "local spool, not a real MQ" scope) + config-reference rows. Commit `feat(dark-factory): durable at-least-once notification delivery (disk spool + retry, fail-soft)`.

---

## Self-Review Notes (plan ↔ spec)

**Covered (M22 / residue #9):** enterprise seccomp made a configurable, JSON-validated, LIVE-PROBED knob (fail-closed if the profile doesn't actually deny the canary syscalls) + a shipped strict variant; notification delivery upgraded from best-effort to durable at-least-once (disk spool + bounded retry + start-of-run flush), still fail-soft. Both live-tested (seccomp against the real Docker daemon; notification against an in-process receiver).

**Deliberately deferred (honest, in enterprise.md/budget.md):** mTLS on the credential-proxy channel (needs real PKI/cert management); HSM/KMS-backed approver keys (df_custody uses file keys — HSM is a drop-in for sign, not built here); per-role candidate seccomp (the candidate/verifier runs host-side under the OS sandbox — applying seccomp there is Linux-only bwrap wiring, separate work); a cross-host durable message queue (M22's spool is local-disk at-least-once, not a real MQ — no cross-host durability/ordering/dedup).

**Honesty note:** the seccomp probe raises the floor (denies the canary syscalls it checks) but is NOT a completeness proof of the profile; durable notification is a local spool (at-least-once, fail-soft) not a real queue — both stated plainly so no one over-reads the guarantee.
