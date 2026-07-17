# dark-factory M27 — Candidate network authority (spec §7.4) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Close the buildable half of spec §7.4 ("the candidate reaches only the twin data-plane"). Today the candidate — the built app, executed by the verifier's scenario runner under the standard/hardened OS sandbox — has **unrestricted network** at standard/hardened (only enterprise's builder-container egress lock touches network, and that's the builder, not the candidate). This milestone adds an opt-in `candidate_network` config (`"unrestricted"` default | `"deny"` | `"loopback"`) enforced by the existing OS-sandbox backends and verified by a new fail-closed live probe, applied ONLY to the candidate/verifier wrapper (`run_all`'s `exec_wrapper`) — never to the builder's wrapper (CLI builders need egress to reach their model APIs).

**Honest scope (buildable vs. not):** macOS `sandbox-exec` supports both `deny` (no network at all) and `loopback` (only 127.0.0.1 — the twin data-plane — reachable; all other egress denied). Linux `bwrap --unshare-net` supports `deny` airtightly (fresh network namespace) but CANNOT support `loopback`: the namespace's loopback is its own, so host-bound twins are unreachable — veth/slirp plumbing is out of scope. `loopback` on Linux therefore **fails closed** (refusal, never silent downgrade), and this limit is documented. Two interaction refusals are mandatory at load/gate time: `deny` + twins enabled (twins would be silently unreachable) and `deny` + any `when.http` scenario (the verifier couldn't reach the candidate's server) are both `ConfigError`s — fail closed, never a mysteriously-failing run. `candidate_network != "unrestricted"` at `cooperative` is also a `ConfigError` (no sandbox exists there to enforce it — refusing beats pretending).

**Architecture:** `df_sandbox.py`'s two backends gain a `network="unrestricted"` keyword on `wrap_prefix` (macOS: appends `(deny network*)` and, for loopback, re-allows localhost inside the same profile; Linux: appends `--unshare-net` for deny, raises `SandboxError` for loopback). A new `probe_network_denial(backend, deny_root, workspace, network)` live-probes the wrapper the same way `probe_denial` does filesystem denial: a host-side listener on a **non-loopback** local IP proves outbound denial non-vacuously (baseline unwrapped connect succeeds → wrapped connect must fail), and in loopback mode a second listener on 127.0.0.1 proves loopback still works (non-vacuity in the other direction). `df_config.py` validates the field + the two interaction refusals. `supervisor.py` builds a SECOND wrapper for the candidate (`os_backend.wrap_prefix(control_root, workspace, network=cfg["candidate_network"])`), probes it fail-closed when restricted, and passes it as `run_all`'s `exec_wrapper` — the builder's `exec_prefix` is untouched.

**Tech Stack:** Python stdlib. pytest. `.venv/bin/python -m pytest dark-factory/tests -v` from repo root `/Users/alonadelson/Projects/ai_projects/skills` (macOS host — the macOS `sandbox-exec` paths run live in the suite; Linux `bwrap` paths are covered by the existing Linux-container harness pattern, `@pytest.mark.skipif(sys.platform != "linux")`).

## Global Constraints

- **Candidate-only:** the network restriction wraps ONLY the scenario runner's `exec_wrapper` (candidate + brownfield probes). The builder's `exec_prefix` (standard tier) keeps `network="unrestricted"` — a CLI builder must still reach its provider API. Nothing about hardened/enterprise BUILDER containers changes.
- **Fail-closed everywhere:** an unsupported combination (loopback on Linux), a failed network probe, or a config conflict (deny+twins, deny+http-scenarios, restricted-at-cooperative) is a refusal (`ConfigError` / exit 2), never a silent downgrade to unrestricted.
- **Back-compat:** `candidate_network` absent → `"unrestricted"` → byte-identical behavior everywhere (wrap_prefix called with the default keyword produces today's exact argv; no probe runs).
- **Non-vacuous probes:** every "denied" verdict requires a passing baseline proving the same operation succeeds unwrapped — `probe_denial`'s existing discipline.
- **Commit messages end with:** `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`.

## File Structure

```
dark-factory/
  scripts/
    df_sandbox.py        # Task 1 — wrap_prefix(network=...), probe_network_denial
    df_config.py          # Task 2 — candidate_network validation + interaction refusals
    supervisor.py          # Task 2 — candidate wrapper + probe wiring at run/resume
  references/
    isolation.md           # Task 3 — candidate-network section (incl. Linux loopback limit)
    config-reference.md    # Task 3 — candidate_network row
    digital-twins.md       # Task 3 — note: loopback mode is the twin-compatible restriction
  tests/
    test_candidate_network.py  # Tasks 1-2 (new file)
    test_e2e_candidate_network.py  # Task 3 (new file)
```

---

### Task 1: `df_sandbox` — network-aware wrap_prefix + live probe

**Files:**
- Modify: `dark-factory/scripts/df_sandbox.py`
- Test: `dark-factory/tests/test_candidate_network.py` (create)

**Interfaces:**
- Consumes: existing `_MacOSBackend.wrap_prefix(deny_root, workspace)` / `_LinuxBackend.wrap_prefix(deny_root, workspace)` and `SandboxError`.
- Produces: `wrap_prefix(deny_root, workspace, network="unrestricted")` on BOTH backends (`network` in `("unrestricted", "deny", "loopback")`; any other value raises `SandboxError`; `loopback` on the Linux backend raises `SandboxError`), and module-level `probe_network_denial(backend, deny_root, workspace, network) -> (ok: bool, reason: str)` — `(True, ...)` ONLY when the wrapper provably enforces the requested mode (see below); any spawn failure/timeout/ambiguity → `(False, reason)`.

**Implementation notes (read the existing code first — match its style):**

- macOS profile additions, appended INSIDE the same profile string `wrap_prefix` already builds:
  - `deny`: append `(deny network*)`.
  - `loopback`: append `(deny network*)(allow network* (local ip "localhost:*"))(allow network* (remote ip "localhost:*"))` — the exact SBPL accepted syntax must be verified by the live probe (that's what the probe is FOR; if this syntax is wrong the probe fails and the run refuses — fail-closed by design, same posture as M14's flag verification). The implementer should hand-verify the syntax once with a quick `sandbox-exec -p '<profile>' python3 -c ...` experiment and adjust if needed (e.g. `(remote ip "localhost:*")` vs `(local ip ...)` variants) — whatever form makes the probe's four checks pass is the right form, and the probe keeps it honest forever after.
  - `unrestricted`: byte-identical to today's profile.
- Linux argv additions: `deny` → append `--unshare-net` to the existing bwrap argv (before the command); `loopback` → `raise SandboxError("candidate_network 'loopback' is not supported by the bwrap backend: --unshare-net's namespace has its own loopback, so host-bound twins would be unreachable; use 'deny' (no twins/http) or run on macOS")`; `unrestricted` → unchanged.
- `probe_network_denial(backend, deny_root, workspace, network)`:
  - `network == "unrestricted"` → `(True, "unrestricted: no network probe applies")` without spawning anything.
  - Otherwise, host-side setup: start TWO ephemeral TCP listener sockets in-process (plain `socket.socket()`, `listen(1)`, no thread needed — a pending connection completes at the TCP level without `accept()`): one bound to `127.0.0.1`, one bound to a non-loopback local address discovered via the UDP-connect trick (`s.connect(("10.255.255.255", 1)); local_ip = s.getsockname()[0]`) — if the machine has no non-loopback address (offline laptop), return `(False, "no non-loopback local address available to probe outbound denial")` (fail closed, never skip).
  - BASELINE (non-vacuity): run a small `python3 -c` child UNWRAPPED that connects to the non-loopback listener; it must succeed, else `(False, "baseline connect failed — probe environment unusable")`.
  - WRAPPED checks, one `python3 -c` child under `backend.wrap_prefix(deny_root, workspace, network=network)`, printing one marker line per check (mirror `probe_denial`'s marker style exactly):
    - connect to the non-loopback listener → must FAIL (`OSError`) in both `deny` and `loopback` modes;
    - connect to the 127.0.0.1 listener → in `loopback` mode must SUCCEED (proves the mode isn't just a broken profile that denies everything — twins must remain reachable); in `deny` mode must FAIL.
  - Any missing/extra marker, nonzero exit, timeout, or unexpected marker value → `(False, reason)`.

- [ ] **Step 1 (TDD):** Write `dark-factory/tests/test_candidate_network.py` with (adjust imports/path-setup to match sibling test files):

```python
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
import df_sandbox  # noqa: E402

IS_MAC = sys.platform == "darwin"
IS_LINUX = sys.platform == "linux"


def test_wrap_prefix_default_network_is_byte_identical(tmp_path):
    backend = df_sandbox.detect_backend()
    if backend is None:
        pytest.skip("no sandbox backend on this host")
    deny = tmp_path / "cr"; ws = tmp_path / "ws"
    deny.mkdir(); ws.mkdir()
    legacy = backend.wrap_prefix(str(deny), str(ws))
    explicit = backend.wrap_prefix(str(deny), str(ws), network="unrestricted")
    assert legacy == explicit


def test_wrap_prefix_rejects_unknown_network_mode(tmp_path):
    backend = df_sandbox.detect_backend()
    if backend is None:
        pytest.skip("no sandbox backend on this host")
    deny = tmp_path / "cr"; ws = tmp_path / "ws"
    deny.mkdir(); ws.mkdir()
    with pytest.raises(df_sandbox.SandboxError):
        backend.wrap_prefix(str(deny), str(ws), network="bogus")


@pytest.mark.skipif(not IS_MAC, reason="macOS sandbox-exec backend")
def test_macos_deny_and_loopback_modify_profile(tmp_path):
    deny = tmp_path / "cr"; ws = tmp_path / "ws"
    deny.mkdir(); ws.mkdir()
    backend = df_sandbox._MacOSBackend()
    deny_argv = backend.wrap_prefix(str(deny), str(ws), network="deny")
    loop_argv = backend.wrap_prefix(str(deny), str(ws), network="loopback")
    assert "(deny network*)" in deny_argv[-1]
    assert "(deny network*)" in loop_argv[-1]
    assert "localhost" in loop_argv[-1]


@pytest.mark.skipif(not IS_LINUX, reason="Linux bwrap backend")
def test_linux_deny_adds_unshare_net_and_loopback_raises(tmp_path):
    deny = tmp_path / "cr"; ws = tmp_path / "ws"
    deny.mkdir(); ws.mkdir()
    backend = df_sandbox._LinuxBackend()
    argv = backend.wrap_prefix(str(deny), str(ws), network="deny")
    assert "--unshare-net" in argv
    with pytest.raises(df_sandbox.SandboxError):
        backend.wrap_prefix(str(deny), str(ws), network="loopback")


def test_probe_unrestricted_passes_without_spawning(tmp_path):
    backend = df_sandbox.detect_backend()
    if backend is None:
        pytest.skip("no sandbox backend on this host")
    ok, reason = df_sandbox.probe_network_denial(
        backend, str(tmp_path), str(tmp_path), "unrestricted")
    assert ok is True


@pytest.mark.skipif(not IS_MAC, reason="live macOS sandbox probe")
def test_probe_deny_live_macos(tmp_path):
    deny = tmp_path / "cr"; ws = tmp_path / "ws"
    deny.mkdir(); ws.mkdir()
    backend = df_sandbox._MacOSBackend()
    ok, reason = df_sandbox.probe_network_denial(
        backend, str(deny), str(ws), "deny")
    assert ok is True, reason


@pytest.mark.skipif(not IS_MAC, reason="live macOS sandbox probe")
def test_probe_loopback_live_macos(tmp_path):
    deny = tmp_path / "cr"; ws = tmp_path / "ws"
    deny.mkdir(); ws.mkdir()
    backend = df_sandbox._MacOSBackend()
    ok, reason = df_sandbox.probe_network_denial(
        backend, str(deny), str(ws), "loopback")
    assert ok is True, reason


@pytest.mark.skipif(not IS_LINUX, reason="live bwrap probe")
def test_probe_deny_live_linux(tmp_path):
    deny = tmp_path / "cr"; ws = tmp_path / "ws"
    deny.mkdir(); ws.mkdir()
    backend = df_sandbox._LinuxBackend()
    if not backend.available():
        pytest.skip("bwrap not installed")
    ok, reason = df_sandbox.probe_network_denial(
        backend, str(deny), str(ws), "deny")
    assert ok is True, reason
```

  (The two live macOS probe tests are REAL end-to-end evidence and run in the normal suite on this Mac. Check how sibling tests obtain the backend — if `detect_backend()`/`_MacOSBackend` names differ, use the real names.)

- [ ] **Step 2:** Run the new file — new tests FAIL (`TypeError: wrap_prefix() got an unexpected keyword` / missing `probe_network_denial`).
- [ ] **Step 3:** Implement per the notes above. Live-verify the SBPL loopback syntax by hand once; whatever form passes all four probe checks is correct.
- [ ] **Step 4:** New file green. Full suite green (`.venv/bin/python -m pytest dark-factory/tests -q`).
- [ ] **Step 5:** Commit `feat(dark-factory): network-aware sandbox wrap_prefix + live network-denial probe (§7.4 Task 1)`.

---

### Task 2: config `candidate_network` + supervisor candidate-wrapper wiring

**Files:**
- Modify: `dark-factory/scripts/df_config.py`, `dark-factory/scripts/supervisor.py`
- Test: extend `dark-factory/tests/test_candidate_network.py`

**Interfaces:**
- Consumes: Task 1's `wrap_prefix(..., network=...)` + `probe_network_denial`; existing `cfg["_twins"]` enabled flag and scenario loading (find where the supervisor loads scenarios and where `run_all(..., exec_wrapper=exec_prefix, ...)` is called — both call sites, dev loop + final exam + resume path + brownfield characterize).
- Produces: `cfg["candidate_network"]` (validated string, default `"unrestricted"`); the supervisor passes a candidate-specific wrapper to every `run_all` call.

**df_config rules (find the right spot among the existing top-level field validations):**
- Optional `candidate_network`, default `"unrestricted"`; must be one of the three values (bool/other types rejected).
- `!= "unrestricted"` requires `assurance` in `("standard", "hardened", "enterprise")` — at `cooperative` there is no sandbox to enforce it: `ConfigError("candidate_network requires assurance: standard or above (cooperative has no sandbox to enforce it)")`.
- `== "deny"` + twins enabled (however the config exposes that — check `_twins`) → `ConfigError("candidate_network 'deny' would make configured twins unreachable; use 'loopback' (macOS) or remove twins")`.
- Do NOT try to check scenario contents (http scenarios) at config-load time — config load doesn't read scenarios. That check belongs in the supervisor's pre-build gate (below).

**supervisor wiring:**
- Where `resolve_isolation` returns `exec_prefix`: when `cfg["candidate_network"] != "unrestricted"` AND the effective tier provides an OS backend, build `candidate_prefix = os_backend.wrap_prefix(control_root, workspace, network=cfg["candidate_network"])` and run `probe_network_denial` fail-closed (probe fails → journal a `PROBE_FAILED`-style event + exit 2 with a clear message, same posture as the existing denial-probe failure path — find and mirror it). When unrestricted → `candidate_prefix = exec_prefix` exactly (no behavior change). Note the Linux+loopback `SandboxError` from `wrap_prefix` must surface as the same clean refusal, not a traceback.
- Pre-build gate addition (near the coverage/mutation gate, where scenarios are already loaded): `candidate_network == "deny"` + any scenario with `when.http` → refuse (exit 2, `GATE_FAILED`-style, message naming the scenario id) — the verifier could never reach the candidate's server.
- Thread `candidate_prefix` into EVERY `run_all(..., exec_wrapper=...)` call (dev loop, final exam, resume paths) and the brownfield characterize call — grep all `exec_wrapper=exec_prefix` call sites; the builder's `invoke_adapter(exec_prefix=...)` sites stay untouched.
- Manifest: record `candidate_network` on the terminal manifest (simplest honest spot — alongside where the tier/backend fields already go; find the existing pattern).

- [ ] **Step 1 (TDD):** extend `test_candidate_network.py`: config — valid values accepted w/ default; bogus value/bool → ConfigError; restricted-at-cooperative → ConfigError; deny+twins → ConfigError; loopback+twins at standard → accepted. Supervisor — (a) monkeypatch-capture `run_all` and assert the exec_wrapper it receives differs from the builder's `exec_prefix` when `candidate_network: "deny"` (contains the network flags) and is identical when unrestricted; (b) a failing `probe_network_denial` (monkeypatched to `(False, "x")`) → run exits 2 before any build; (c) deny + an http scenario in the control root → exit 2 gate refusal, builder never invoked. Follow the existing supervisor-test harness patterns (find how test_hardened_config.py fakes `invoke_adapter` and asserts rc==2).
- [ ] **Step 2:** Confirm new tests FAIL, implement, green.
- [ ] **Step 3:** Full suite green.
- [ ] **Step 4:** Commit `feat(dark-factory): candidate_network config + candidate-only sandbox wrapper, fail-closed probe + gates (§7.4 Task 2)`.

---

### Task 3: e2e + docs

**Files:**
- Create: `dark-factory/tests/test_e2e_candidate_network.py`
- Modify: `dark-factory/references/isolation.md`, `config-reference.md`, `digital-twins.md`, `dark-factory/SKILL.md`

- [ ] **Step 1 (e2e, macOS-live):** `test_e2e_candidate_network.py` — a real standard-tier run (mirror an existing standard-tier e2e's control-root scaffolding) where the SCENARIO's candidate program attempts an outbound TCP connect to a host-side non-loopback listener (same listener trick as the Task 1 probe) and prints `CONNECTED` on success / `DENIED` on OSError; with `candidate_network: "deny"` the scenario's expected output is `DENIED` and the run CONVERGES — i.e. the e2e proves the candidate genuinely couldn't reach the network *through the actual run path*, not just through the probe. Add a second test: same control root with `candidate_network` absent → the candidate CAN connect (expected output `CONNECTED`, converges) — the non-vacuity twin of the first. Skip both on non-macOS (`sys.platform != "darwin"`).
- [ ] **Step 2:** Full suite green.
- [ ] **Step 3 (docs):** `isolation.md` — new "Candidate network authority (§7.4)" section: what it restricts (candidate/verifier wrapper only, builder untouched), the three modes, the live probe, the fail-closed refusals (cooperative, deny+twins, deny+http, Linux+loopback), and the honest Linux-loopback limit (netns-vs-host-loopback, veth/slirp out of scope). `config-reference.md` — `candidate_network` row. `digital-twins.md` — one paragraph: `loopback` is the twin-compatible restriction; `deny` is refused with twins. `SKILL.md` — mention the field where tiers/config are summarized (grep for a natural spot) + the References entry for isolation.md if it enumerates topics.
- [ ] **Step 4:** Commit `feat(dark-factory): candidate-network e2e proof + docs (§7.4 Task 3)`.

---

## Self-Review Notes (plan ↔ spec)

**Covered:** §7.4's enforceable core — the candidate's network authority is now an explicit, probed, fail-closed control at standard/hardened/enterprise: `deny` (both OSes) and `loopback` = "candidate reaches only the twin data-plane" (macOS). Applied candidate-only, preserving builder API egress. Non-vacuous live probes and a live e2e on the host OS the suite actually runs on.

**Deliberately not built (honest, in isolation.md):** Linux `loopback` (bwrap netns has its own loopback; bridging to host twins needs veth/slirp — out of scope); per-scenario network modes (one run-wide setting); IP/port-granular allowlists beyond loopback-vs-all (YAGNI until a real need).

**Honesty note:** `unrestricted` remains the default — this is opt-in hardening, and absent config nothing changes byte-for-byte. A restricted mode that cannot be proven live (probe failure, unsupported combo) refuses the run rather than running unrestricted — the control you didn't probe is a control you don't have.
