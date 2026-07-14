# dark-factory M5a — Tamper-evident Audit + Process-group Reaping Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Ship the two `hardened`-tier hardening pieces that are high-value AND fully verifiable on this machine: (1) an **HMAC-signed, tamper-evident audit manifest** with a supervisor-only key kept outside every run/control/workspace tree — closing the "a local process can recompute the unsigned SHA-256" weakness (Codex R1); (2) **process-group twin reaping** so a shell-wrapper twin can't leak a grandchild (the M3a follow-up). Both are opt-in, never change exit codes, and preserve the barrier.

**Architecture:** Audit signing adds an `audit.signing` config flag. When on, the supervisor loads (or generates) a 256-bit key from a path OUTSIDE the control root and workspace (default `~/.dark-factory/audit.key`, mode 0600), computes `HMAC-SHA256(key, canonical(manifest.json))`, and writes it to a `manifest.hmac` sidecar in addition to `manifest.sha256`. `verify-manifest` verifies the HMAC when a key is available (falling back to the existing SHA-256 + journal check), so a tamperer who rewrites `manifest.json` + `manifest.sha256` but lacks the key cannot forge `manifest.hmac`. Reaping: `df_twins` launches each twin in a **new session/process group** (`start_new_session=True`) and `stop()` signals the whole group (`os.killpg`), reaping shell-wrapper grandchildren.

**Honest limits (stated in docs):** signed audit is tamper-evident only while the key stays secret. At `standard` tier the OS sandbox denies the *control root* but not the home dir, so a determined candidate could read `~/.dark-factory/audit.key` — there, signing defends against **casual/accidental** rewrite, not a determined attacker. Genuine tamper-evidence against a malicious builder requires the deny-all per-role sandbox of `hardened`/`enterprise` (where the key path is unreachable). The container sandbox, credential broker, network-authority graph, verifier-only hidden twin variants, and remote/off-box audit sink remain deferred (infrastructure-gated: no running container daemon / broker on this box).

**Tech Stack:** Python ≥ 3.9 stdlib only (`hmac`, `hashlib`, `secrets`, `os`, `signal`, `subprocess`). pytest for tests. No new deps.

**Source spec:** `…/2026-07-13-dark-factory-skill-design.md` §7.5 (audit: local hashed → **signed chain** → off-box), §7.2/§8.1 (per-role isolation), and the M3a whole-branch follow-up (process-group reaping).

## Global Constraints

- **Runtime code is Python stdlib only.** Tests run `.venv/bin/python -m pytest dark-factory/tests -v` from repo root `/Users/alonadelson/Projects/ai_projects/skills`.
- **Signing is opt-in** (`audit.signing: true`, default false). Absent/false → behavior byte-identical to today (SHA-256 sidecar only). The 158 existing tests must stay green.
- **The signing key NEVER enters a run artifact, the control root, the workspace, the manifest, or any journal/log.** Only its HMAC output is written. The key file is created mode 0600.
- **HMAC is over the canonical `manifest.json` bytes** (the exact bytes written), so it transitively covers `journal_sha256` (which the manifest already contains) and every manifest field.
- **Signing/verification/reaping never change an exit code** (0/2/3/10). A missing/unreadable key when `signing:true` at finalize is a real config failure surfaced BEFORE the run starts (validated in config), not mid-terminal.
- **Reaping must not orphan:** `stop()` still never raises and remains idempotent; group-kill is best-effort with the same SIGTERM→SIGKILL discipline. No twin (or its children) survives a run.
- **Commit messages end with:** `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`.

## File Structure

```
dark-factory/
  scripts/
    df_audit.py            # Task 1 — key mgmt + HMAC sign/verify (new, isolated, unit-testable)
    df_config.py           # Task 1 — validate audit.signing + key_path; inject cfg["_audit"]
    supervisor.py          # Task 2 — finalize_manifest signs; verify_manifest verifies HMAC
    df_twins.py            # Task 3 — start_new_session + killpg group reaping
  references/
    audit.md               # Task 4 — signed-audit doc + honest key-secrecy limits
    config-reference.md    # Task 1 — audit rows
  SKILL.md                 # Task 4 — hardened-audit note
  tests/
    test_df_audit.py       # Task 1
    test_audit_config.py   # Task 1
    test_manifest_signing.py  # Task 2
    test_twins_reaping.py     # Task 3
    fixtures/twin_shell_wrapper  # Task 3 — a bash-wrapper twin that spawns a grandchild
```

---

### Task 1: `df_audit.py` (key + HMAC) and `audit` config

**Files:**
- Create: `dark-factory/scripts/df_audit.py`
- Modify: `dark-factory/scripts/df_config.py`
- Modify: `dark-factory/references/config-reference.md`
- Create: `dark-factory/tests/test_df_audit.py`
- Create: `dark-factory/tests/test_audit_config.py`

**Interfaces:**
- `df_audit.AuditKeyError(RuntimeError)`.
- `df_audit.load_or_create_key(key_path: str) -> bytes` — if the file exists, read its 64 hex chars → 32 bytes; else create parent dir (mode 0700), generate `secrets.token_bytes(32)`, write as hex with mode 0600, return it. Raises `AuditKeyError` if the file exists but is malformed.
- `df_audit.sign(key: bytes, data: bytes) -> str` — `hmac.new(key, data, hashlib.sha256).hexdigest()`.
- `df_audit.verify(key: bytes, data: bytes, sig_hex: str) -> bool` — constant-time `hmac.compare_digest`.
- `df_config`: injects `cfg["_audit"] = {"signing": bool, "key_path": str}`. Absent `audit` block → `{"signing": False, "key_path": ""}`. If `audit.signing` present it must be bool. `audit.key_path` optional str, default `~/.dark-factory/audit.key` (expanduser) when signing is true. **When `signing` is true**, the key's parent dir must be OUTSIDE the control root and outside `workspace_root` (reuse the existing `_disjoint` helper) — else `ConfigError` (the key must never live where the sandboxed builder could reach or where a run writes).

- [ ] **Step 1: Write the failing tests**

`dark-factory/tests/test_df_audit.py`:

```python
import os
import stat

import pytest

import df_audit


def test_create_then_load_roundtrips(tmp_path):
    kp = tmp_path / "sub" / "audit.key"
    k1 = df_audit.load_or_create_key(str(kp))
    assert len(k1) == 32
    mode = stat.S_IMODE(os.stat(kp).st_mode)
    assert mode == 0o600
    k2 = df_audit.load_or_create_key(str(kp))
    assert k1 == k2  # stable


def test_malformed_key_raises(tmp_path):
    kp = tmp_path / "audit.key"
    kp.write_text("not-hex", encoding="utf-8")
    with pytest.raises(df_audit.AuditKeyError):
        df_audit.load_or_create_key(str(kp))


def test_sign_verify_roundtrip():
    k = b"\x01" * 32
    sig = df_audit.sign(k, b"hello")
    assert df_audit.verify(k, b"hello", sig)
    assert not df_audit.verify(k, b"tampered", sig)
    assert not df_audit.verify(b"\x02" * 32, b"hello", sig)  # wrong key


def test_verify_rejects_garbage_sig():
    assert df_audit.verify(b"\x01" * 32, b"x", "nothex") is False
```

`dark-factory/tests/test_audit_config.py`:

```python
import pytest

import df_config
from test_config import write_config


def test_absent_audit_defaults_off(tmp_path):
    cr = tmp_path / "control"; write_config(cr)
    cfg = df_config.load_config(str(cr))
    assert cfg["_audit"] == {"signing": False, "key_path": ""}


def test_signing_true_defaults_key_path_outside(tmp_path):
    cr = tmp_path / "control"; write_config(cr, audit={"signing": True})
    cfg = df_config.load_config(str(cr))
    assert cfg["_audit"]["signing"] is True
    assert cfg["_audit"]["key_path"].endswith("audit.key")


def test_signing_key_inside_control_root_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, audit={"signing": True, "key_path": str(cr / "k.key")})
    with pytest.raises(df_config.ConfigError, match="key"):
        df_config.load_config(str(cr))


def test_signing_must_be_bool(tmp_path):
    cr = tmp_path / "control"; write_config(cr, audit={"signing": "yes"})
    with pytest.raises(df_config.ConfigError, match="signing"):
        df_config.load_config(str(cr))
```

- [ ] **Step 2: Verify fail.**

- [ ] **Step 3: Implement `df_audit.py` + df_config validation + config-reference rows.**

`df_audit.py`:

```python
"""Tamper-evident audit signing (spec 7.5). Stdlib only.

An HMAC-SHA256 over the manifest bytes, keyed by a supervisor-only key kept
OUTSIDE every run/control/workspace tree. A local tamperer who rewrites the
manifest cannot forge the HMAC without the key. Tamper-evidence holds only
while the key stays secret (see references/audit.md for the tier caveat).
"""
import hashlib
import hmac
import os
import secrets


class AuditKeyError(RuntimeError):
    pass


def load_or_create_key(key_path: str) -> bytes:
    if os.path.exists(key_path):
        try:
            raw = open(key_path, encoding="utf-8").read().strip()
            key = bytes.fromhex(raw)
        except ValueError as e:
            raise AuditKeyError(f"malformed audit key at {key_path}: {e}")
        if len(key) != 32:
            raise AuditKeyError(f"audit key at {key_path} must be 32 bytes")
        return key
    d = os.path.dirname(os.path.abspath(key_path))
    os.makedirs(d, mode=0o700, exist_ok=True)
    key = secrets.token_bytes(32)
    fd = os.open(key_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(key.hex())
    return key


def sign(key: bytes, data: bytes) -> str:
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def verify(key: bytes, data: bytes, sig_hex: str) -> bool:
    try:
        expected = hmac.new(key, data, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, sig_hex)
    except (TypeError, ValueError):
        return False
```

df_config: add validation + `cfg["_audit"]` injection following the established pattern; when `signing` true, default `key_path = os.path.expanduser("~/.dark-factory/audit.key")` and require its parent dir `_disjoint` from control root and workspace_root.

config-reference rows:

```markdown
| `audit.signing` | bool | default false. When true the supervisor HMAC-signs each run manifest with a supervisor-only key, writing a `manifest.hmac` sidecar; `verify-manifest` then checks the signature (tamper-evident while the key stays secret). |
| `audit.key_path` | str | default `~/.dark-factory/audit.key` (mode 0600). MUST be outside the control root and workspace. Never written into any run artifact. |
```

- [ ] **Step 4: Verify pass + full suite (166 passed, 1 skipped).**
- [ ] **Step 5: Commit** `feat(dark-factory): audit HMAC signing key module + config`.

---

### Task 2: Sign the manifest on finalize; verify the HMAC

**Files:**
- Modify: `dark-factory/scripts/supervisor.py`
- Create: `dark-factory/tests/test_manifest_signing.py`

**Interfaces:**
- Read the current `finalize_manifest` / `verify_manifest`. When `cfg["_audit"]["signing"]`:
  - `finalize_manifest` (needs access to the audit cfg — pass `audit=None` param, default None = unsigned as today): after writing `manifest.json`, compute `sig = df_audit.sign(key, canonical_manifest_bytes)` and `atomic_write(run_dir/manifest.hmac, sig + "\n")`. The key is loaded once per run (in `_run_locked`, from `cfg["_audit"]["key_path"]`) and threaded in — NEVER stored in the manifest.
  - `verify_manifest(run_dir, key=None)`: keep the existing sha256 + journal checks; ADD — if `manifest.hmac` exists, a `key` MUST be supplied and the HMAC must verify over the manifest bytes, else `TAMPERED (bad/missing signature)` → False. The CLI `verify-manifest` gains an optional `--key-path`; if given, load the key and pass it. If `manifest.hmac` exists but no key is provided, print `UNVERIFIED (signed manifest; supply --key-path)` and return False (fail-closed: a signed manifest with no key is not "OK").
- Wire `finalize_manifest(..., audit=<loaded key or None>)` at every terminal that already calls it (reuse the manifest dict pattern). Loading the key: in `_run_locked`, if `cfg["_audit"]["signing"]`, `key = df_audit.load_or_create_key(cfg["_audit"]["key_path"])` once; on `AuditKeyError` abort BEFORE the loop (journal `AUDIT_KEY_ERROR`, return 2 — a precondition failure, honestly not a silent pass).

- [ ] **Step 1: Write the failing tests**

`dark-factory/tests/test_manifest_signing.py`:

```python
import json
import os

import df_audit
import supervisor
from test_supervisor import FAKE, setup_control


def _signed_control(tmp_path, key_path):
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")
    cfg = json.loads((cr / "config.json").read_text())
    cfg["audit"] = {"signing": True, "key_path": str(key_path)}
    (cr / "config.json").write_text(json.dumps(cfg))
    return cr


def test_signed_run_writes_hmac_and_verifies(tmp_path):
    kp = tmp_path / "keys" / "audit.key"
    cr = _signed_control(tmp_path, kp)
    assert supervisor.run(str(cr), None) == 0
    run_id = os.listdir(cr / "runs")[0]
    rd = cr / "runs" / run_id
    assert (rd / "manifest.hmac").exists()
    key = df_audit.load_or_create_key(str(kp))
    assert supervisor.verify_manifest(str(rd), key=key) is True


def test_tampered_signed_manifest_fails_without_key_forgery(tmp_path):
    kp = tmp_path / "keys" / "audit.key"
    cr = _signed_control(tmp_path, kp)
    supervisor.run(str(cr), None)
    rd = cr / "runs" / os.listdir(cr / "runs")[0]
    # attacker rewrites manifest.json AND recomputes manifest.sha256 (no key)
    m = json.loads((rd / "manifest.json").read_text())
    m["outcome"] = "COMPLETE_QUALIFIED"
    import df_common
    text = df_common.canonical_json(m)
    (rd / "manifest.json").write_text(text)
    (rd / "manifest.sha256").write_text(df_common.sha256_str(text) + "\n")
    key = df_audit.load_or_create_key(str(kp))
    assert supervisor.verify_manifest(str(rd), key=key) is False  # hmac catches it


def test_signed_manifest_unverified_without_key(tmp_path):
    kp = tmp_path / "keys" / "audit.key"
    cr = _signed_control(tmp_path, kp)
    supervisor.run(str(cr), None)
    rd = cr / "runs" / os.listdir(cr / "runs")[0]
    assert supervisor.verify_manifest(str(rd), key=None) is False  # fail-closed


def test_unsigned_run_unchanged(tmp_path):
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")  # no audit block
    assert supervisor.run(str(cr), None) == 0
    rd = cr / "runs" / os.listdir(cr / "runs")[0]
    assert not (rd / "manifest.hmac").exists()
    assert supervisor.verify_manifest(str(rd)) is True  # sha256 path unchanged
```

- [ ] **Step 2-4:** Implement, verify the 4 tests + the existing manifest tests stay green (verify_manifest's new signature `key=None` must not break existing callers — default None keeps the sha256-only path). Full suite green.
- [ ] **Step 5: Commit** `feat(dark-factory): HMAC-sign run manifests; verify-manifest checks the signature`.

---

### Task 3: Process-group twin reaping

**Files:**
- Modify: `dark-factory/scripts/df_twins.py`
- Create: `dark-factory/tests/fixtures/twin_shell_wrapper` (executable)
- Create: `dark-factory/tests/test_twins_reaping.py`

**Interfaces:**
- `TwinSet.start`: launch each `Popen` with `start_new_session=True` (new process group == pid). Record the pid.
- `TwinSet.stop`: for each child, `os.killpg(os.getpgid(proc.pid), signal.SIGTERM)`; after grace, `os.killpg(..., SIGKILL)`; then reap. Wrap each in try/except (`ProcessLookupError`, `OSError`) — still never raises, still idempotent. Falls back to `proc.terminate()`/`kill()` if `getpgid` fails.
- The `signal` import (previously unused) is now used.

- [ ] **Step 1: Write the fixture + failing test**

`dark-factory/tests/fixtures/twin_shell_wrapper`:

```bash
#!/usr/bin/env bash
# A twin that spawns a grandchild (a background sleeper) and writes a marker
# with the grandchild PID, then writes its own endpoint and waits. Used to
# prove process-group reaping kills the grandchild too.
python3 -c "import time; open('$DF_GRANDCHILD_PIDFILE','w').write(str(__import__('os').getpid())); time.sleep(300)" &
GC=$!
echo "$GC" > "$DF_GRANDCHILD_PIDFILE.launcher"
# write endpoint so the supervisor/df_twins considers us ready
echo "127.0.0.1:1" > "$DF_ENDPOINT_FILE"
sleep 300
```

`dark-factory/tests/test_twins_reaping.py`:

```python
import json
import os
import time

import df_twins

HERE = os.path.dirname(os.path.abspath(__file__))
WRAP = os.path.join(HERE, "fixtures", "twin_shell_wrapper")


def _alive(pid):
    try:
        os.kill(pid, 0); return True
    except (ProcessLookupError, OSError):
        return False


def test_stop_reaps_grandchild_process(tmp_path):
    gc_pidfile = tmp_path / "gc.pid"
    td = tmp_path / "twins"; td.mkdir()
    (td / "w.json").write_text(json.dumps({
        "twin_version": "0.1", "name": "w",
        "launch": ["bash", WRAP]}), encoding="utf-8")
    run_dir = tmp_path / "run"; run_dir.mkdir()
    os.environ["DF_GRANDCHILD_PIDFILE"] = str(gc_pidfile)
    ts = df_twins.TwinSet()
    try:
        ts.start(df_twins.load_defs(str(td)), str(run_dir), 20)
        # wait for the grandchild pid to be recorded
        for _ in range(100):
            if gc_pidfile.exists() and gc_pidfile.read_text().strip():
                break
            time.sleep(0.05)
        gc_pid = int(gc_pidfile.read_text().strip())
        assert _alive(gc_pid)
        ts.stop()
        time.sleep(0.3)
        assert not _alive(gc_pid)  # grandchild reaped via process group
    finally:
        ts.stop()
        os.environ.pop("DF_GRANDCHILD_PIDFILE", None)
```

```bash
chmod +x dark-factory/tests/fixtures/twin_shell_wrapper
```

- [ ] **Step 2-4:** Verify the test fails against current code (grandchild survives), implement the group-kill, verify it passes. Full suite green + `pgrep -f 'sleep 300' || echo NONE` clean after. Existing df_twins tests stay green.
- [ ] **Step 5: Commit** `fix(dark-factory): reap twin process groups so shell-wrapper grandchildren cannot leak`.

---

### Task 4: Docs — signed audit + honest tier framing

**Files:**
- Create: `dark-factory/references/audit.md`
- Modify: `dark-factory/SKILL.md`

- [ ] **Step 1:** Write `references/audit.md`: the local SHA-256 sidecar (all tiers) vs the opt-in HMAC signature (`audit.signing`), the key location/secrecy rule, `verify-manifest [--key-path]` behavior (OK / TAMPERED / UNVERIFIED-without-key), and the honest limit: **tamper-evident only while the key is secret — at `standard` the candidate could read the home-dir key, so signing there defends casual/accidental rewrite; genuine protection against a malicious builder needs the deny-all `hardened` sandbox where the key path is unreachable. Off-box/remote audit sink is the enterprise frontier, not yet built.**
- [ ] **Step 2:** SKILL.md: add a one-line note under Hard rules — signed audit is available via `audit.signing`; verify a signed run with `verify-manifest --key-path <path>`; a signed manifest with no key reports UNVERIFIED (never trust it as OK).
- [ ] **Step 3:** Verify docs match code (verify-manifest CLI flags, config field names); full suite unchanged; commit `docs(dark-factory): tamper-evident audit reference + honest key-secrecy limits`.

---

## Self-Review Notes (plan ↔ spec)

**Covered (M5a):** the signed-audit rung of §7.5 (local hash → **signed**) as an opt-in, tamper-evident-while-key-secret HMAC with a supervisor-only key kept outside every run/control/workspace tree; fail-closed verification (a signed manifest with no key is UNVERIFIED, not OK); process-group twin reaping (the M3a follow-up) so shell-wrapper twins can't leak grandchildren. Both opt-in, exit-code-invariant, barrier-preserving; unsigned/disabled paths byte-identical.

**Deliberately deferred (infrastructure-gated, stated honestly):** the container/VM sandbox backend + `hardened` per-role capability manifests (need a running container daemon to verify — Docker present but daemon down here); the host-side credential broker/proxy; the network-authority graph; verifier-only hidden twin variants (need the sandboxed orchestrator); and the **off-box/remote** audit sink (§7.5 top rung — the true tamper anchor against a local root). These land when the infrastructure is available to build+verify, not before.

**Known honesty notes:** signing is only as strong as key secrecy; the doc states the per-tier reality (casual protection at standard, genuine at hardened). HMAC (symmetric) proves *the holder of the key* signed it — fine for a single-owner supervisor; asymmetric signing + a remote sink are the enterprise upgrade.
```
