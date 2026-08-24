# dark-factory M28 — Bind the built artifact to the signed manifest (audit DF-01) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Close audit finding **DF-01 (Critical)**: the signed manifest binds the run's *inputs* (config, spec, scenarios, input `snapshot_sha256`, journal) but **not the built application workspace**. So a run can be qualified/attested and the workspace then modified while `verify` and custody attestation still pass — the approver isn't signing the actual artifact. This milestone records a canonical digest of the **final workspace** in the signed manifest, and makes `verify` and custody-attach recompute-and-compare so a changed workspace fails closed.

**Architecture:** Add `snapshot_source.artifact_manifest(root)` / `artifact_digest(root)` — a canonical `{files:[{path,size,mode,sha256}]}` tree hash of the FINAL workspace (mirrors the existing `build_manifest`, but adds the executable bit so a chmod is detected, and it is a SEPARATE function so the input-snapshot path stays byte-identical). The supervisor computes it right before every terminal `finalize_manifest` that has a real workspace, and records `manifest["artifact"] = {"workspace_sha256", "file_count", "mode": "...", "files":[...]}`. Because `finalize_manifest` hashes+signs the whole manifest text, the artifact digest is covered by `manifest.sha256`, `manifest.hmac`, and (enterprise) the custody attestation over those bytes. `verify_manifest(run_dir, workspace=...)` and `verify_custody_cmd` recompute `artifact_digest(workspace)` and FAIL if it differs from the recorded value; `attach_custody` refuses to attest when the live workspace doesn't match the manifest (approvers sign the real artifact, not a stale record).

**Tech Stack:** Python stdlib. pytest. `.venv/bin/python -m pytest dark-factory/tests -q` from repo root `/Users/alonadelson/Projects/ai_projects/skills`.

## Global Constraints

- **Fail-closed:** a workspace that differs from the recorded artifact digest (changed byte, added/removed/renamed file, or changed exec bit), OR a workspace that is absent when verification is asked to confirm it, resolves to **verification failure**, never a silent pass.
- **Input path untouched:** the existing `build_manifest`/`snapshot`/input `snapshot_sha256` behavior is byte-identical — `artifact_manifest` is a new, separate function. All existing snapshot/manifest tests stay green.
- **Back-compat for old manifests:** `verify_manifest` on a pre-M28 manifest with no `artifact` field still verifies its integrity as before (the new artifact check only runs when `manifest["artifact"]` is present); it prints an explicit "no artifact digest recorded (pre-M28 run) — cannot confirm the live workspace" note rather than a false clean pass.
- **Every terminal with a workspace records it:** CONVERGED, FINAL_EXAM_FAILED, budget PAUSE-then-terminal, security-gate rejection, etc. — any terminal manifest written after the workspace exists carries `artifact`. Terminals BEFORE a workspace exists (config/gate aborts) carry `artifact: null`.
- **Commit messages end with:** `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`.

## File Structure

```
dark-factory/
  scripts/
    snapshot_source.py   # Task 1 — artifact_manifest/artifact_digest (+ exec bit)
    supervisor.py         # Task 2 — record manifest["artifact"]; verify recompute; custody guard
    df_custody.py          # Task 2 — attach refuses on workspace mismatch (if custody logic lives here)
  references/
    audit.md               # Task 3 — document artifact binding + verify semantics
    enterprise.md          # Task 3 — custody now binds the artifact
  tests/
    test_artifact_binding.py   # Tasks 1-2 (new)
    test_snapshot.py            # Task 1 (confirm input path unchanged)
```

---

### Task 1: `snapshot_source.artifact_manifest` / `artifact_digest`

**Files:** modify `dark-factory/scripts/snapshot_source.py`; create `dark-factory/tests/test_artifact_binding.py`.

**Interfaces:**
- Produces: `artifact_manifest(root) -> {"manifest_version":"0.1","files":[{"path","size","mode","sha256"}]}` (sorted by path; `mode` is `st.st_mode & 0o111` reduced to a bool-ish `exec` flag OR the octal permission — use `stat.S_IMODE(st.st_mode) & 0o111` and store as int so a chmod +x is detected; symlinks/special/multi-link files raise `SnapshotError` exactly like `build_manifest`), and `artifact_digest(root) -> (manifest, sha256_hex)` = `sha256_str(canonical_json(manifest))`.
- Consumes: existing `sha256_file`, `canonical_json`, `sha256_str`, `SnapshotError`, `EXCLUDE_DIRS`.

- [ ] **Step 1 (TDD):** `test_artifact_binding.py`:

```python
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
import snapshot_source  # noqa: E402


def _mk(root, rel, content, mode=0o644):
    p = os.path.join(root, rel)
    os.makedirs(os.path.dirname(p) or root, exist_ok=True)
    with open(p, "w") as f:
        f.write(content)
    os.chmod(p, mode)
    return p


def test_artifact_digest_stable_and_order_independent(tmp_path):
    a = tmp_path / "a"; b = tmp_path / "b"
    a.mkdir(); b.mkdir()
    _mk(str(a), "x.py", "print(1)\n"); _mk(str(a), "sub/y.txt", "hi\n")
    _mk(str(b), "sub/y.txt", "hi\n"); _mk(str(b), "x.py", "print(1)\n")
    _, da = snapshot_source.artifact_digest(str(a))
    _, db = snapshot_source.artifact_digest(str(b))
    assert da == db  # identical trees -> identical digest regardless of creation order


def test_artifact_digest_changes_on_one_byte(tmp_path):
    a = tmp_path / "a"; a.mkdir()
    _mk(str(a), "x.py", "print(1)\n")
    _, d1 = snapshot_source.artifact_digest(str(a))
    _mk(str(a), "x.py", "print(2)\n")  # one byte changed
    _, d2 = snapshot_source.artifact_digest(str(a))
    assert d1 != d2


def test_artifact_digest_changes_on_exec_bit(tmp_path):
    a = tmp_path / "a"; a.mkdir()
    p = _mk(str(a), "run.sh", "#!/bin/sh\n", mode=0o644)
    _, d1 = snapshot_source.artifact_digest(str(a))
    os.chmod(p, 0o755)  # +x only, contents unchanged
    _, d2 = snapshot_source.artifact_digest(str(a))
    assert d1 != d2, "a chmod +x must change the artifact digest"


def test_artifact_digest_changes_on_added_and_removed_file(tmp_path):
    a = tmp_path / "a"; a.mkdir()
    _mk(str(a), "x.py", "print(1)\n")
    _, d1 = snapshot_source.artifact_digest(str(a))
    _mk(str(a), "extra.py", "print(9)\n")
    _, d2 = snapshot_source.artifact_digest(str(a))
    assert d1 != d2
    os.remove(os.path.join(str(a), "extra.py")); os.remove(os.path.join(str(a), "x.py"))
    _mk(str(a), "renamed.py", "print(1)\n")
    _, d3 = snapshot_source.artifact_digest(str(a))
    assert d3 != d1  # a rename is a different tree


def test_artifact_manifest_rejects_symlink(tmp_path):
    a = tmp_path / "a"; a.mkdir()
    _mk(str(a), "real.txt", "hi\n")
    os.symlink(str(a / "real.txt"), str(a / "link.txt"))
    with pytest.raises(snapshot_source.SnapshotError):
        snapshot_source.artifact_manifest(str(a))


def test_build_manifest_input_path_unchanged(tmp_path):
    # artifact_manifest is SEPARATE: build_manifest still has NO mode field.
    a = tmp_path / "a"; a.mkdir()
    _mk(str(a), "x.py", "print(1)\n")
    bm = snapshot_source.build_manifest(str(a))
    assert bm["files"][0].get("mode") is None  # input snapshot schema unchanged
    am = snapshot_source.artifact_manifest(str(a))
    assert "mode" in am["files"][0]
```

- [ ] **Step 2:** Run `test_artifact_binding.py` → FAIL (`artifact_manifest`/`artifact_digest` missing).
- [ ] **Step 3:** Implement in `snapshot_source.py`. `artifact_manifest` mirrors `build_manifest`'s walk + symlink/special/multi-link `SnapshotError` guards, but each entry is `{"path": rel, "size": st.st_size, "mode": stat.S_IMODE(st.st_mode) & 0o111, "sha256": sha256_file(full)}` (store the exec-bit triplet as an int; contents+size+exec detected, ordinary rw perms ignored to avoid umask noise). `artifact_digest(root)` returns `(m, sha256_str(canonical_json(m)))`. Do NOT modify `build_manifest`/`snapshot`.
- [ ] **Step 4:** `test_artifact_binding.py` + `test_snapshot.py` green; full suite green.
- [ ] **Step 5:** Commit `feat(dark-factory): snapshot_source.artifact_manifest/digest — canonical output-tree hash (DF-01 Task 1)`.

---

### Task 2: record `artifact` on terminal manifests + verify + custody guard

**Files:** modify `dark-factory/scripts/supervisor.py` (+ `df_custody.py` if the attach path lives there — grep `attach_custody`/`verify_custody`); extend `test_artifact_binding.py`.

**Interfaces:**
- Consumes: Task 1's `snapshot_source.artifact_digest`; existing `finalize_manifest`, `verify_manifest`, `verify_custody_cmd`, and the custody-attach command.
- Produces: `manifest["artifact"]` on every terminal-with-workspace; `verify_manifest(run_dir, workspace=None)` gains an artifact check; custody attach refuses on mismatch.

**Implementation:**
- Add a helper `_artifact_manifest_field(workspace) -> dict|None`: returns `{"workspace_sha256": digest, "file_count": len(files), "files": manifest["files"]}` from `snapshot_source.artifact_digest(workspace)`, or `None` if the workspace path doesn't exist / a `SnapshotError` (record `{"error": "<class>"}` rather than crash — a workspace that can't be canonically hashed, e.g. a symlink the builder planted, must be a LOUD recorded fact, and the run's qualification must fail closed: if a terminal is a QUALIFIED outcome and the artifact can't be hashed, downgrade the outcome/qualified flag with a journaled `ARTIFACT_UNHASHABLE` event — do not emit a qualified manifest whose artifact is unverifiable).
- Thread `artifact=_artifact_manifest_field(workspace)` into EVERY terminal manifest dict that is written after the workspace exists (find each `finalize_manifest(...)` call with a real `workspace` — CONVERGED, final-exam terminals, security-gate rejection, budget terminal, resume terminals). Terminals before the workspace exists set `artifact=None` (mirror how `snapshot_sha256=None` is already set on those early aborts).
- `verify_manifest(run_dir, key=None, workspace=None)`: after the existing digest/HMAC/journal checks, if `manifest.get("artifact")` is a dict with a `workspace_sha256`: when `workspace` is provided, recompute `snapshot_source.artifact_digest(workspace)` and require equality — mismatch prints `ARTIFACT MISMATCH: workspace differs from the signed manifest` and returns False. When `workspace` is None (caller didn't point at a live tree), print `artifact digest recorded but no --workspace given to confirm it` and DO NOT pass on that basis alone (return the integrity result, but the printed line makes clear the live artifact was not confirmed). A manifest with `artifact: null` (pre-M28 or pre-workspace abort) prints the explicit "no artifact digest recorded" note.
- The `verify` CLI subcommand: accept an optional `--workspace <path>` (default: derive it as `os.path.join(cfg["workspace_root"], invocation)` when resolvable from the run, so the common case needs no flag) and pass it to `verify_manifest`.
- Custody attach (`attach_custody` / the `df-custody attach` command): before writing the attestation, recompute `artifact_digest(workspace)` and refuse (non-zero, clear message) if it doesn't match `manifest["artifact"]["workspace_sha256"]` — an approver must not attest a workspace that no longer matches what was qualified. If the manifest has no `artifact` (pre-M28), refuse with "manifest predates artifact binding; re-run to attest".
- `verify_custody_cmd`: same recompute-and-compare against the live workspace as part of its checks.

- [ ] **Step 1:** Read the current `verify_manifest`, `verify_custody_cmd`, the custody-attach command, and every `finalize_manifest(` call site in `supervisor.py`. Confirm where `workspace` is in scope at each terminal.
- [ ] **Step 2 (TDD):** extend `test_artifact_binding.py`: drive a real converged run (mirror an existing e2e's control-root + fake builder that writes a converging workspace — find one, e.g. `test_e2e_standard.py`/`test_e2e_invariant.py`), then assert: (a) `manifest["artifact"]["workspace_sha256"]` is present and equals `artifact_digest(workspace)`; (b) `verify_manifest(run_dir, workspace=workspace)` returns True on the pristine tree; (c) after mutating one byte in the workspace, `verify_manifest(run_dir, workspace=workspace)` returns False; (d) after a chmod +x, False; (e) custody attach refuses on a mutated workspace (enterprise-shaped fixture, or a focused unit test of the attach guard with a hand-built manifest+workspace); (f) a pre-M28 manifest (no `artifact` key) still verifies integrity True and prints the "no artifact digest" note.
- [ ] **Step 3:** Confirm the new tests FAIL, implement, green. Full suite green (watch for existing manifest/e2e tests that assert an exact manifest key set — they must tolerate the new `artifact` key; update any exact-equality assertion).
- [ ] **Step 4:** Commit `feat(dark-factory): bind the built workspace into the signed manifest + verify/custody recompute (DF-01 Task 2)`.

---

### Task 3: docs

**Files:** modify `dark-factory/references/audit.md`, `dark-factory/references/enterprise.md`; check `SKILL.md` verify step.

- [ ] **Step 1:** `audit.md` — new "Artifact binding (DF-01)" section: the manifest records `artifact.workspace_sha256` (a canonical path+size+exec-bit+content tree hash of the built workspace) under the same signature as everything else; `verify --workspace <dir>` recomputes and fails closed on any drift; a pre-artifact manifest is honestly flagged as unconfirmable. `enterprise.md` — custody attestation now binds the artifact: `df-custody attach` refuses if the live workspace doesn't match the qualified manifest, so approvers sign the exact built result. Note the honest boundary: this binds the *workspace tree*; it does not itself produce a packaged/release bundle (that's a separate future step) — but nothing can be attested that doesn't match the tree that was qualified.
- [ ] **Step 2:** Update `SKILL.md`'s verify step to mention `--workspace`. Commit `docs(dark-factory): document artifact binding + custody artifact guard (DF-01 Task 3)`.

---

## Self-Review Notes (plan ↔ finding)

**Covered:** DF-01 — the signed manifest now includes a canonical digest of the built workspace (contents + structure + exec bits), covered by `manifest.sha256`/`manifest.hmac`/custody; `verify` and custody-attach recompute-and-compare and fail closed on any post-qualification change. Acceptance test from the roadmap (qualify → change one byte/mode/name → verification fails) is implemented.

**Deliberately deferred (documented honest scope):** a content-addressed *packaged release bundle* (tarball/OCI) distinct from the workspace tree — the roadmap's fuller "immutable release artifact" — is a later step; M28 binds the workspace tree itself, which is what qualification actually ran against. Exec bits are captured; finer POSIX metadata (uid/gid, xattrs, setuid) is out of scope (the workspace is builder-authored plain files; setuid/special files are already rejected by the SnapshotError guards).

**Honesty note:** the bind is only as strong as the manifest signature it rides under — cooperative/standard use HMAC/sha256 (tamper-evident, not tamper-proof, exactly as `finalize_manifest` already documents); enterprise adds the ed25519 custody attestation over the same bytes. M28 does not change those trust boundaries; it puts the *artifact* inside them.
