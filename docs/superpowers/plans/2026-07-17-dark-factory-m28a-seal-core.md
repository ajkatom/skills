# dark-factory M28a — DF-01 artifact-binding core (seal-first) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Close the audit's Critical **DF-01** at its core: bind the *built artifact* to the signed manifest so that what is attested/shipped is provably what was verified. This is the first, cleanly-mergeable slice of the Codex-approved M28 (`docs/superpowers/plans/2026-07-17-dark-factory-audit-remediation-APPROVED.md`). **Seal-first:** the converged workspace is frozen into a **content-addressed immutable object BEFORE the final exam**, the final exam + security gates run **against that frozen object**, its `object_id` is recorded in the signed manifest, and `verify`/custody recompute-and-compare **by identity** — so a post-verification change to the workspace fails closed.

**Scope of M28a (this milestone) vs deferred:** M28a delivers the object store + freeze-before-final-exam + manifest binding + verify-by-identity + custody-by-object-id + retention + the acceptance/race tests. **Deferred to their natural milestones (noted, not dropped):** the gate *network/IPC sandbox* hardening → M33; builder/verifier *projections* mounted into candidate containers → M29; the full multi-sub-state *qualification FSM* → M36/M33. M28a still runs gates read-only against the frozen object (the sandbox hardening is additive later).

**Tech Stack:** Python stdlib (`os`, `ctypes` for `renameat2`/`renamex_np`, `hashlib`). pytest. `.venv/bin/python -m pytest dark-factory/tests -q` from `/Users/alonadelson/Projects/ai_projects/skills`.

## Global Constraints
- **Seal-first ordering:** freeze+publish the artifact object BEFORE the final exam; the final exam + gates read the frozen object, never the mutable workspace. A run that would be QUALIFIED but whose artifact can't be frozen (hostile metadata, unhashable) fails closed (`ARTIFACT_UNHASHABLE`, not qualified).
- **Verify by identity, fail closed:** any object mismatch (content/structure/mode/empty-dir), a pruned object, or a pre-M28 manifest with no artifact → a distinct non-success `verify` status; custody/handoff refuse it. Never a silent pass.
- **Back-compat:** a run/config that doesn't reach a workspace-bearing terminal, and verification of old manifests, keep working (old manifests → explicit `UNBOUND`, not a crash).
- **Detection-grade honesty:** docstrings/tests state plainly this proves in-model detection (confined candidate + accidents + mutating gate), NOT same-user prevention (documented residual).
- **Commit messages end with:** `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`.

## File Structure
```
dark-factory/scripts/df_seal.py     # T1 — content-addressed freeze/publish/verify primitive
dark-factory/scripts/supervisor.py   # T2 — seal-first order-of-ops + manifest artifact field; T3 verify/custody
dark-factory/scripts/df_custody.py    # T3 — attach/verify bind object_id
dark-factory/references/audit.md       # T4 — artifact binding docs
dark-factory/references/enterprise.md  # T4 — custody binds the artifact
dark-factory/tests/test_df_seal.py      # T1
dark-factory/tests/test_artifact_binding.py  # T2-T4 (e2e + race + acceptance)
```

---

### Task 1: `df_seal.py` — content-addressed freeze / publish / verify primitive

**Files:** create `dark-factory/scripts/df_seal.py`, `dark-factory/tests/test_df_seal.py`.

**Interfaces (produce):**
- `class SealError(RuntimeError)`.
- `freeze(src_dir, object_store) -> object_id`: canonically hash `src_dir` and publish it as an immutable object under `object_store/objects/<object_id>/` with a sidecar `object_store/objects/<object_id>.json`. Returns the hex `object_id`.
- `object_manifest(src_dir) -> dict`: the canonical sidecar dict `{ "seal_version":"1", "files":[{path,size,mode,sha256}], "dirs":[<rel dir paths incl. empty>] }` — sorted; `mode = stat.S_IMODE(st.st_mode) & 0o111`. Rejects (SealError) symlinks, special files, multi-link files, **setuid/setgid/world-writable files, and world-writable/setgid dirs**. Includes EMPTY directories (structure binding).
- `object_id_of(manifest) -> str` = `sha256(canonical_json(manifest))`.
- `verify_object(object_store, object_id) -> bool`: recompute the sidecar over `objects/<object_id>/` and require it equals the stored sidecar AND `object_id_of` it == `object_id`; False on any mismatch, missing object, or missing/invalid sidecar.

**Implementation notes:**
- Reuse `df_common.canonical_json`, `sha256_file`, `sha256_str`.
- **FD-relative traversal:** open the root dir with `os.open(src_dir, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)` and walk with `os.scandir`/`os.open(..., dir_fd=...)`+`O_NOFOLLOW`, `os.lstat`/`fstat` to reject hostile entries before reading. (A pragmatic `os.walk` with per-entry `os.lstat` + `O_NOFOLLOW` opens for file reads is acceptable if fully fd-safe; document the choice.)
- **Atomic no-overwrite publish:** copy into `object_store/tmp/<uuid>/`, `fsync` files+dir, then publish via `renameat2(AT_FDCWD, tmp, AT_FDCWD, dst, RENAME_NOREPLACE)` (Linux) / `renamex_np(tmp, dst, RENAME_EXCL)` (macOS) through `ctypes`; **raise SealError where neither primitive is available** (never a plain overwriting `os.rename`). If `dst` already exists (same digest), `verify_object` it byte-for-byte and reuse; if it exists but fails verification, quarantine it (rename to `objects/.corrupt-<id>-<uuid>`) and republish. **The sidecar is written LAST as the commit record** — an object dir without a valid sidecar is treated as uncommitted (quarantine/recover).
- Never follow or write outside `object_store`.

- [ ] **Step 1 (TDD):** `test_df_seal.py` covering: identical trees (built in different order) → identical `object_id`; one-byte change / exec-bit change / added-or-removed file / rename / **added empty dir** each change the id; symlink/special/multi-link/setuid/setgid/world-writable file/dir each raise SealError; `freeze` then `verify_object` True; after freeze, mutating a file inside `objects/<id>/` makes `verify_object` False (detection); publishing the same tree twice reuses the object (idempotent) and does not raise; an object dir with its sidecar deleted → `verify_object` False (uncommitted); where the atomic primitive is unavailable (monkeypatch to simulate) `freeze` raises SealError. A **race-injection** test: monkeypatch the copy step to mutate the source mid-freeze and assert the published object is internally consistent with its own sidecar (freeze hashes what it published, not a torn read) OR raises — never silently publishes a mismatched sidecar.
- [ ] **Step 2:** Run → RED. **Step 3:** Implement. **Step 4:** `test_df_seal.py` green; full suite green.
- [ ] **Step 5:** Commit `feat(dark-factory): df_seal — content-addressed freeze/publish/verify primitive (DF-01/M28a Task 1)`.

---

### Task 2: supervisor seal-first order-of-ops + manifest `artifact` field
**Files:** modify `supervisor.py`; extend `test_artifact_binding.py`.

- On the dev-loop **CONVERGED** path, BEFORE the final exam: `object_id = df_seal.freeze(<workspace output dir>, <object_store under control_root>)`; run the **final exam + security gates against the frozen object** (point `run_all`/gate `cwd` at `objects/<object_id>/`, read-only); on a `SealError` → terminal `ARTIFACT_UNHASHABLE`, not qualified.
- Record `manifest["artifact"] = {"object_id", "seal_version", "file_count", "dir_count"}` (from the sidecar) on the CONVERGED and final-exam terminals (the terminals written after a workspace exists). Terminals before a workspace → `artifact: null` (mirror existing `snapshot_sha256=None`). Thread it through a small helper so all workspace-bearing `finalize_manifest(...)` sites carry it (grep every `finalize_manifest(` in `_run_loop`).
- Object store lives at `<control_root>/objects/` (created lazily); recorded so `verify` can find it.
- Tests: a converged run's `manifest["artifact"]["object_id"]` equals `df_seal.object_id_of(df_seal.object_manifest(workspace_output))`; the final exam provably ran against the object dir (assert the path passed to `run_all` is the object dir, not the live workspace); a workspace with a planted symlink → `ARTIFACT_UNHASHABLE`, not qualified.
- Commit `feat(dark-factory): seal the artifact before the final exam + bind object_id into the signed manifest (DF-01/M28a Task 2)`.

---

### Task 3: verify-by-identity + custody-by-object-id + retention
**Files:** modify `supervisor.py` (`verify_manifest`, `verify_custody_cmd`, verify CLI), `df_custody.py`; extend tests.

- `verify_manifest(run_dir, key=None, object_store=None)`: after the existing integrity checks, if `manifest.get("artifact")`: `df_seal.verify_object(object_store, artifact["object_id"])` must be True — else print `ARTIFACT MISMATCH`/`ARTIFACT UNAVAILABLE` and return a distinct non-success. A manifest with `artifact: null`/absent → print + return distinct `UNBOUND` status (not a clean pass). Default `object_store` = `<control_root>/objects` derived from the run when resolvable; verify CLI accepts `--object-store`.
- `df_custody.attach`/`verify_custody_cmd`: bind + require `manifest["artifact"]["object_id"]`; `verify_object` must pass against the live object store before attesting/verifying; refuse (clear non-zero) on mismatch/unavailable, and refuse a pre-M28 (`UNBOUND`) manifest with "predates artifact binding". Take the control-root lock around attach + chain append.
- Retention: refuse deletion of a referenced object (a helper `df_seal` can expose, or supervisor policy); verifying a pruned object → `ARTIFACT UNAVAILABLE`.
- Tests: pristine → verify True; mutate one byte/mode/name/empty-dir in `objects/<id>/` → verify False; custody attach refuses a mutated object; pre-M28 manifest → `UNBOUND` non-success + custody refuses; pruned object → unavailable.
- Commit `feat(dark-factory): verify + custody bind the artifact object_id, fail closed on drift (DF-01/M28a Task 3)`.

---

### Task 4: e2e + acceptance + docs
**Files:** `test_artifact_binding.py` (e2e), `references/audit.md`, `references/enterprise.md`, `SKILL.md` verify step.

- e2e: a real converged standard-tier run (mirror an existing standard e2e) → assert artifact bound, `verify` passes; then mutate the object and assert `verify` exits non-success; a gate that writes into the object is rejected (gate ran read-only against the object). Honest test comment: in-model detection, not same-user prevention.
- Docs: `audit.md` "Artifact binding (DF-01)" — seal-first object store, `verify --object-store`, `UNBOUND` for old manifests, detection-grade residual; `enterprise.md` — custody binds `object_id`; `SKILL.md` verify step mentions the object store.
- Commit `docs+test(dark-factory): artifact-binding e2e + acceptance + docs (DF-01/M28a Task 4)`.

---

## Self-Review (plan ↔ finding)
**Covered:** DF-01 core — freeze-before-final-exam, content-addressed object with structure+mode+content binding, signed-manifest binding, verify-by-identity fail-closed, custody-by-object-id, retention, race/acceptance tests. **Deferred (noted):** gate network/IPC sandbox → M33; container projections → M29; full qualification sub-state FSM → M36/M33. **Honesty:** detection-grade; the same-user residual is documented, not claimed solved.
