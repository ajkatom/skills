# dark-factory M16 — Linux-Container Test Harness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Give the Linux-only security claims **live coverage on this Mac** by running targeted probes inside a real Linux kernel (Docker Desktop's linuxkit VM): (1) the **bwrap standard-tier backend** — until now unit-tested only (the suite's platform-skipped test) — proves read+write denial live; (2) the two kernel primitives M17's enterprise tier needs: **iptables egress denial** (NET_ADMIN) and **seccomp/no-new-privs** self-application. Each probe is fail-closed: it must positively demonstrate the enforcement (denied action observably fails, allowed action observably succeeds), never infer it from a flag.

**Architecture:** `df_linux_probes.py` contains small, self-contained probe drivers (pure stdlib, runnable inside a container): `probe_bwrap(deny_root, workspace)` (calls the existing `df_sandbox` Linux backend + `probe_denial` — the REAL production code path, not a copy), `probe_egress_denial(target_ip)` (iptables OUTPUT DROP then a socket connect must fail, while a pre-rule connect check proves the network worked), `probe_no_new_privs()` (prctl via ctypes; verify with a re-read). `tests/test_linux_harness.py` (skipif no docker) starts an alpine container with the exact caps each probe needs (`SYS_ADMIN`+seccomp-unconfined for bwrap; `NET_ADMIN` for iptables), bind-mounts `dark-factory/scripts` read-only, and runs each driver via `docker run ... python3 -c/-m`, asserting the driver's machine-readable verdict line. Feasibility already verified live on this machine (bwrap OK with those flags; iptables OK; prctl NNP OK).

**Honest scope (stated in the test docstrings + isolation.md note):** the harness proves the *mechanisms* on a real Linux kernel; it does not turn the macOS suite into a Linux CI (a native Linux run of the full suite remains the gold standard — the harness is the honest local substitute). The container needs `SYS_ADMIN` for bwrap's namespaces — acceptable for a TEST harness, never for production isolation (documented). Alpine's `apk add bubblewrap iptables` happens at container start (network required on first run; image layers cached after).

**Tech Stack:** Python stdlib + Docker CLI. pytest. `.venv/bin/python -m pytest dark-factory/tests -v` from repo root `/Users/alonadelson/Projects/ai_projects/skills`.

## Global Constraints

- **Fail-closed probes:** each probe prints exactly one verdict line `DF-PROBE <name> PASS|FAIL <reason>`; the test asserts the exact PASS line; any container/spawn/timeout error → test failure (when docker is live) — no silent skip once the harness starts.
- **Positive + negative halves:** egress probe must show connect SUCCEEDS before the DROP rule and FAILS after (else the "denial" could be a dead network); bwrap probe reuses `df_sandbox.probe_denial`'s existing read+write canary discipline (already fail-closed); NNP probe re-reads `PR_GET_NO_NEW_PRIVS == 1`.
- **Production code path, not a copy:** the bwrap probe imports and drives `df_sandbox` itself inside the container — so the LIVE assertion covers the same code the standard tier runs on Linux.
- **skipif no docker** at module level (mirror test_container.py); suite stays green on docker-less machines.
- **No production behavior changes:** this milestone adds probes + tests + docs only; `df_sandbox`/`supervisor` untouched.
- **Commit messages end with:** `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`.

## File Structure

```
dark-factory/
  scripts/df_linux_probes.py     # Task 1 — probe drivers (verdict-line protocol)
  tests/test_linux_harness.py    # Task 1 — docker-driven live probes
  references/isolation.md        # Task 1 — harness note (what it proves / doesn't)
```

---

### Task 1: probes + harness + docs (single task — small, coherent, one reviewer gate)

**Files:** create `dark-factory/scripts/df_linux_probes.py`, `dark-factory/tests/test_linux_harness.py`; modify `dark-factory/references/isolation.md`.

**Interfaces:**
```python
# df_linux_probes.py — each callable prints ONE verdict line and exits 0(PASS)/1(FAIL):
#   python3 df_linux_probes.py bwrap <deny_root> <workspace>
#   python3 df_linux_probes.py egress <target_ip> <port>
#   python3 df_linux_probes.py nnp
def probe_bwrap(deny_root, workspace) -> tuple[bool, str]
    # sys.platform must be linux; backend = df_sandbox.BACKENDS["linux"];
    # backend.available() (bwrap on PATH) else FAIL "bwrap missing";
    # df_sandbox.probe_denial(backend, deny_root, workspace) -> PASS/FAIL.
def probe_egress_denial(target_ip="1.1.1.1", port=443, timeout=3) -> tuple[bool, str]
    # 1) socket connect BEFORE any rule -> must SUCCEED (else FAIL "no baseline
    #    connectivity — egress denial would be vacuous");
    # 2) subprocess: iptables -A OUTPUT -d <ip> -j DROP (FAIL on nonzero rc);
    # 3) socket connect AFTER -> must now FAIL (timeout/refused) -> PASS.
def probe_no_new_privs() -> tuple[bool, str]
    # ctypes libc prctl(PR_SET_NO_NEW_PRIVS=38,1,0,0,0) rc 0 AND
    # prctl(PR_GET_NO_NEW_PRIVS=39,0,0,0,0) returns 1 -> PASS.
```
- `test_linux_harness.py` (module `DOCKER_LIVE` guard + session image-prep fixture):
  - Image prep: `docker run` a named cached image or build once via `docker build -q` from an inline Dockerfile string (`FROM python:3.12-alpine` + `RUN apk add --no-cache bubblewrap iptables`) — cached across runs; the fixture tolerates the ~60s first build.
  - `test_bwrap_denial_live_on_linux`: run the container with `--cap-add SYS_ADMIN --security-opt seccomp=unconfined -v <scripts>:/df:ro` executing `python3 /df/df_linux_probes.py bwrap /tmp/deny /tmp/ws` (create dirs in-container first via `sh -c`); assert stdout contains `DF-PROBE bwrap PASS` and rc 0. THIS is the live coverage for the standard tier's Linux backend.
  - `test_egress_denial_live`: `--cap-add NET_ADMIN` (default bridge network), run `egress 1.1.1.1 443`; assert `DF-PROBE egress PASS` (probe itself enforces the before/after halves).
  - `test_no_new_privs_live`: no extra caps; assert `DF-PROBE nnp PASS`.
  - `test_probe_drivers_fail_closed_on_macos`: running `probe_bwrap` directly on this Mac returns (False, ...) mentioning linux — the driver never false-passes off-platform.
- isolation.md: a short "Linux live-coverage harness" section — what it proves (bwrap read+write denial on a real kernel via the production code path; the two M17 primitives), what it doesn't (not a full Linux CI run; SYS_ADMIN is test-harness-only, never a production posture).

- [ ] **Step 1 (TDD):** write `test_linux_harness.py` + the macOS fail-closed unit test; verify the docker tests fail (probes module absent), unit test fails.
- [ ] **Step 2:** implement `df_linux_probes.py`; run the harness live (docker is up) until all three live probes PASS for real; full suite `.venv/bin/python -m pytest dark-factory/tests -q | tail -1` (678 existing green + yours).
- [ ] **Step 3:** isolation.md section; docs-vs-code check. Commit `feat(dark-factory): Linux live-coverage harness — bwrap denial, iptables egress, no-new-privs proven on a real kernel`.

---

## Self-Review Notes (plan ↔ spec)

**Covered (M16):** live, kernel-real verification of the Linux standard-tier backend (previously only platform-skipped unit coverage) using the production `df_sandbox` code path; live proof of the two kernel primitives M17's enterprise tier builds on (egress DROP, no-new-privs), each with a non-vacuity half (baseline connectivity check; NNP re-read).

**Deliberately deferred (honest):** a full native-Linux CI run of the entire suite (the harness is a local substitute, said so in docs); seccomp *filter* installation beyond NNP (M17 will add the actual per-role seccomp profile — NNP is the prerequisite primitive); rootless-container variants of the harness.
