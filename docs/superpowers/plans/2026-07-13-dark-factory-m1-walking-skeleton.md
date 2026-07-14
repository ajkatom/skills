# dark-factory M1 — Walking Skeleton Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove the dark-factory invariant end-to-end on a toy scale: a builder implements from spec-only, never sees the hidden holdout scenarios, a verifier runs them, deterministic ID-only feedback loops until convergence or cap, with a journaled FSM and a hashed audit manifest.

**Architecture:** A deterministic Python `supervisor.py` (sole state-changer) drives the loop: config/tier validation → lstat-manifest source snapshot into an isolated workspace → builder invoked via a versioned JSON adapter protocol (stdin request / stdout response) → oracle IR v0 scenarios executed by `run_scenarios.py` → `id_feedback.py` projects failures to behavior-IDs + a fixed taxonomy (no LLM, no scenario text) → journal + manifest. Milestone 1 implements only the `cooperative` assurance tier (honestly unqualified — no OS read-denial yet; that is M2).

**Tech Stack:** Python ≥ 3.9 **stdlib-only at runtime** (json, hashlib, subprocess, os, argparse, uuid, tempfile, stat, shutil). `pytest` for tests only, installed in a repo-root `.venv`. No YAML, no third-party runtime deps.

**Source spec:** `docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md` (Codex-approved R6). This plan implements the §15 M1 slice; M2–M5 items are explicitly out of scope (see Self-Review notes at bottom).

## Global Constraints

- **Runtime code is Python stdlib only** — no pip dependency may be imported by anything under `dark-factory/scripts/`.
- **Config is JSON** (`config.json`), not YAML — stdlib-only rule. (The spec sketch shows YAML; M1 documents this divergence in `references/config-reference.md`.)
- **The holdout control root and the build workspace must be disjoint directory trees** — the supervisor refuses to run otherwise (spec §11).
- **Scenario content never enters the workspace, the builder prompt, supervisor stdout, or feedback files** — feedback carries only `behavior_id` matching `^BHV-[A-Za-z0-9-]{1,32}$` plus taxonomy enums from exactly `("wrong_exit_code", "wrong_output", "timeout", "crash")` (spec §6.1).
- **`feedback: "ids"` is the only channel in M1** — `behavioral`/`full` are rejected by config validation.
- **Tier registry gates tiers:** `scripts/supported_tiers.json` lists only `cooperative` (`qualified: false`) in M1; `standard`/`hardened`/`enterprise` are rejected with "no conforming backend" (spec §2.3). Every `cooperative` run prints an UNQUALIFIED warning and its outcome is `COMPLETE_UNQUALIFIED`, never a qualified ship-candidate.
- **`max_iterations`: int 1..20, default 5** (spec §6).
- **All hashing = SHA-256 over canonical JSON** (`sort_keys=True`, separators `(",", ":")`, UTF-8).
- **Adapter protocol version `"0.1"`; oracle IR version `"0.1"`; all output docs carry their version field.**
- **Supervisor exit codes:** `0` converged, `2` config/usage/build error, `3` iteration cap reached.
- **Snapshot excludes `.git`, rejects all symlinks, special files, and multi-hardlink files** (spec §7.1, lstat manifest).
- **Tests run with `.venv/bin/python -m pytest dark-factory/tests -v`** from the repo root `/Users/alonadelson/Projects/ai_projects/skills`.
- **Every commit message ends with:** `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>` (adjust to the executing model if different).

## File Structure

```
dark-factory/
  SKILL.md                          # Task 10 — conversational front end (v0)
  references/
    config-reference.md             # Task 2 — config.json schema v0
    scenario-format.md              # Task 4 — oracle IR v0 schema
    role-adapters.md                # Task 6 — adapter protocol v0
  scripts/
    df_common.py                    # Task 1 — canonical JSON, sha256, atomic write
    supported_tiers.json            # Task 2 — tier registry v0
    df_config.py                    # Task 2 — config load + validation
    snapshot_source.py              # Task 3 — lstat manifest + snapshot copy
    run_scenarios.py                # Task 4 — oracle IR runner (verifier)
    id_feedback.py                  # Task 5 — deterministic ID/taxonomy projection
    adapters/
      claude                        # Task 6 — real claude CLI adapter (executable)
    supervisor.py                   # Task 7 — FSM, lock, journal, loop; Task 8 adds manifest
  tests/
    conftest.py                     # Task 1 — sys.path shim for scripts/
    test_common.py                  # Task 1
    test_config.py                  # Task 2
    test_snapshot.py                # Task 3
    test_oracle.py                  # Task 4
    test_feedback.py                # Task 5
    test_adapters.py                # Task 6
    test_supervisor.py              # Task 7
    test_manifest.py                # Task 8
    test_e2e_loop.py                # Task 9 — the invariant test
    fixtures/
      fake_builder                  # Task 6 — converging fake builder (executable)
      fake_builder_stubborn         # Task 7 — never-converging fake builder (executable)
```

Control plane created at runtime (never inside the repo; tests use tmp_path):

```
<control_root>/
  config.json                       # human-owned
  spec.md                           # human-owned (SHARED with builder)
  scenarios/*.json                  # HOLDOUT — oracle IR files
  runs/<invocation_id>/
    journal.jsonl                   # append-only FSM journal
    prompt_iter_N.md                # what the builder was sent (auditable)
    verifier_report_iter_N.json     # full observed outcomes (control plane only)
    feedback_iter_N.json            # the ID/taxonomy projection that crossed the barrier
    manifest.json + manifest.sha256 # Task 8 — audit manifest + self-hash sidecar
<workspace_root>/<invocation_id>/   # build plane: snapshot + spec.md + feedback.json only
```

---

### Task 1: Scaffold, test harness, and `df_common.py`

**Files:**
- Create: `dark-factory/scripts/df_common.py`
- Create: `dark-factory/tests/conftest.py`
- Create: `dark-factory/tests/test_common.py`
- Modify: `.gitignore` (repo root — add `.venv/`)

**Interfaces:**
- Consumes: nothing (first task).
- Produces (used by every later task):
  - `canonical_json(obj) -> str` — deterministic JSON: `sort_keys=True`, separators `(",", ":")`, `ensure_ascii=False`.
  - `sha256_str(s: str) -> str` — hex digest of UTF-8 bytes.
  - `sha256_file(path: str) -> str` — streaming hex digest.
  - `atomic_write(path: str, text: str) -> None` — tempfile + `os.replace`, creates parent dirs.

- [ ] **Step 1: Create the venv and install pytest**

```bash
cd /Users/alonadelson/Projects/ai_projects/skills
python3 -m venv .venv
.venv/bin/python -m pip install --quiet pytest
.venv/bin/python -m pytest --version
```

Expected: a pytest version line (e.g. `pytest 8.x.y`).

- [ ] **Step 2: Add `.venv/` to `.gitignore`**

Append to `/Users/alonadelson/Projects/ai_projects/skills/.gitignore`:

```
# Python test harness for dark-factory
.venv/
__pycache__/
```

- [ ] **Step 3: Write the conftest shim and the failing test**

`dark-factory/tests/conftest.py`:

```python
import os
import sys

sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts"))
)
```

`dark-factory/tests/test_common.py`:

```python
import os

import df_common


def test_canonical_json_is_deterministic_and_compact():
    a = {"b": 1, "a": [2, 1], "c": {"y": None, "x": "é"}}
    s = df_common.canonical_json(a)
    assert s == '{"a":[2,1],"b":1,"c":{"x":"é","y":null}}'
    # key order in the input must not matter
    assert s == df_common.canonical_json({"c": {"x": "é", "y": None}, "a": [2, 1], "b": 1})


def test_sha256_str_known_vector():
    assert (
        df_common.sha256_str("abc")
        == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )


def test_sha256_file_matches_sha256_str(tmp_path):
    p = tmp_path / "f.txt"
    p.write_text("abc", encoding="utf-8")
    assert df_common.sha256_file(str(p)) == df_common.sha256_str("abc")


def test_atomic_write_creates_parents_and_replaces(tmp_path):
    target = tmp_path / "deep" / "nested" / "out.txt"
    df_common.atomic_write(str(target), "one")
    assert target.read_text(encoding="utf-8") == "one"
    df_common.atomic_write(str(target), "two")
    assert target.read_text(encoding="utf-8") == "two"
    # no stray tempfiles left behind
    leftovers = [f for f in os.listdir(target.parent) if f.startswith(".tmp-")]
    assert leftovers == []
```

- [ ] **Step 4: Run tests to verify they fail**

```bash
cd /Users/alonadelson/Projects/ai_projects/skills
.venv/bin/python -m pytest dark-factory/tests/test_common.py -v
```

Expected: FAIL — `ModuleNotFoundError: No module named 'df_common'`.

- [ ] **Step 5: Implement `df_common.py`**

`dark-factory/scripts/df_common.py`:

```python
"""Shared helpers for dark-factory scripts. Python stdlib only."""
import hashlib
import json
import os
import tempfile


def canonical_json(obj) -> str:
    """Deterministic JSON used for all hashing: sorted keys, compact, UTF-8."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_str(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def atomic_write(path: str, text: str) -> None:
    """Write text to path atomically (tempfile + os.replace). Creates parent dirs."""
    d = os.path.dirname(os.path.abspath(path))
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".tmp-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
```

- [ ] **Step 6: Run tests to verify they pass**

```bash
.venv/bin/python -m pytest dark-factory/tests/test_common.py -v
```

Expected: 4 passed.

- [ ] **Step 7: Commit**

```bash
git add .gitignore dark-factory/scripts/df_common.py dark-factory/tests/conftest.py dark-factory/tests/test_common.py
git commit -m "feat(dark-factory): scaffold M1 with df_common helpers and pytest harness

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 2: Tier registry and config validation

**Files:**
- Create: `dark-factory/scripts/supported_tiers.json`
- Create: `dark-factory/scripts/df_config.py`
- Create: `dark-factory/references/config-reference.md`
- Test: `dark-factory/tests/test_config.py`

**Interfaces:**
- Consumes: `df_common.canonical_json`, `df_common.sha256_str`.
- Produces:
  - `df_config.ConfigError(ValueError)` — raised on any invalid config.
  - `df_config.load_supported_tiers() -> dict` — parsed registry.
  - `df_config.load_config(control_root: str) -> dict` — validated config dict, with two injected keys: `cfg["_qualified"]: bool` (from the registry) and `cfg["_config_sha256"]: str` (hash of the canonical raw config).

- [ ] **Step 1: Write the failing tests**

`dark-factory/tests/test_config.py`:

```python
import json

import pytest

import df_config


def write_config(control_root, **overrides):
    cfg = {
        "config_version": "0.1",
        "autonomy": 4,
        "assurance": "cooperative",
        "feedback": "ids",
        "max_iterations": 5,
        "workspace_root": str(control_root.parent / "ws"),
        "roles": {"builder": {"adapter": "/bin/true", "timeout_s": 60}},
        "budget": {"billing": "subscription"},
    }
    cfg.update(overrides)
    control_root.mkdir(parents=True, exist_ok=True)
    (control_root / "config.json").write_text(json.dumps(cfg), encoding="utf-8")
    return cfg


def test_valid_cooperative_config_loads_and_is_unqualified(tmp_path):
    cr = tmp_path / "control"
    write_config(cr)
    cfg = df_config.load_config(str(cr))
    assert cfg["assurance"] == "cooperative"
    assert cfg["_qualified"] is False
    assert len(cfg["_config_sha256"]) == 64


def test_unbacked_tier_is_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, assurance="standard")
    with pytest.raises(df_config.ConfigError, match="no conforming backend"):
        df_config.load_config(str(cr))


def test_non_ids_feedback_is_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, feedback="behavioral")
    with pytest.raises(df_config.ConfigError, match="feedback"):
        df_config.load_config(str(cr))


def test_max_iterations_bounds(tmp_path):
    cr = tmp_path / "control"
    for bad in (0, 21, "5", None):
        write_config(cr, max_iterations=bad)
        with pytest.raises(df_config.ConfigError, match="max_iterations"):
            df_config.load_config(str(cr))


def test_workspace_inside_control_root_is_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, workspace_root=str(cr / "ws"))
    with pytest.raises(df_config.ConfigError, match="disjoint"):
        df_config.load_config(str(cr))


def test_control_root_inside_workspace_is_rejected(tmp_path):
    cr = tmp_path / "ws" / "control"
    write_config(cr, workspace_root=str(tmp_path / "ws"))
    with pytest.raises(df_config.ConfigError, match="disjoint"):
        df_config.load_config(str(cr))


def test_missing_builder_adapter_is_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, roles={"builder": {}})
    with pytest.raises(df_config.ConfigError, match="adapter"):
        df_config.load_config(str(cr))


def test_missing_config_file_is_clear(tmp_path):
    with pytest.raises(df_config.ConfigError, match="missing config"):
        df_config.load_config(str(tmp_path / "nowhere"))
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
.venv/bin/python -m pytest dark-factory/tests/test_config.py -v
```

Expected: FAIL — `ModuleNotFoundError: No module named 'df_config'`.

- [ ] **Step 3: Implement the registry and `df_config.py`**

`dark-factory/scripts/supported_tiers.json`:

```json
{
  "registry_version": "0.1",
  "tiers": {
    "cooperative": {
      "qualified": false,
      "backend": "process-v0",
      "note": "No OS read-denial primitive; isolation is honor-system. Cannot claim probe-proven isolation or produce a qualified ship-candidate. See spec section 2.2."
    }
  }
}
```

`dark-factory/scripts/df_config.py`:

```python
"""Config loading + validation for dark-factory. Stdlib only."""
import json
import os

from df_common import canonical_json, sha256_str

SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
TAXONOMY = ("wrong_exit_code", "wrong_output", "timeout", "crash")


class ConfigError(ValueError):
    pass


def load_supported_tiers() -> dict:
    with open(os.path.join(SCRIPTS_DIR, "supported_tiers.json"), encoding="utf-8") as f:
        return json.load(f)


def _disjoint(a: str, b: str) -> bool:
    a = os.path.realpath(a)
    b = os.path.realpath(b)
    return not (a == b or a.startswith(b + os.sep) or b.startswith(a + os.sep))


def load_config(control_root: str) -> dict:
    path = os.path.join(control_root, "config.json")
    if not os.path.exists(path):
        raise ConfigError(f"missing config: {path}")
    with open(path, encoding="utf-8") as f:
        raw = json.load(f)

    tiers = load_supported_tiers()["tiers"]
    tier = raw.get("assurance")
    if tier not in tiers:
        raise ConfigError(
            f"assurance tier {tier!r} has no conforming backend in this build; "
            f"supported: {sorted(tiers)} (spec section 2.3)"
        )

    if raw.get("feedback") != "ids":
        raise ConfigError("M1 supports only feedback: 'ids' (spec section 6.1)")

    mi = raw.get("max_iterations")
    if not isinstance(mi, int) or isinstance(mi, bool) or not (1 <= mi <= 20):
        raise ConfigError("max_iterations must be an int in 1..20")

    ws = raw.get("workspace_root")
    if not ws:
        raise ConfigError("workspace_root is required")
    if not _disjoint(ws, control_root):
        raise ConfigError("workspace_root must be disjoint from the control root")

    adapter = raw.get("roles", {}).get("builder", {}).get("adapter")
    if not adapter:
        raise ConfigError("roles.builder.adapter is required")

    cfg = dict(raw)
    cfg["_qualified"] = bool(tiers[tier]["qualified"])
    cfg["_config_sha256"] = sha256_str(canonical_json(raw))
    return cfg
```

`dark-factory/references/config-reference.md`:

```markdown
# dark-factory config.json — schema v0 (M1)

Lives at `<control_root>/config.json`. JSON, not YAML: runtime is stdlib-only
(divergence from the spec sketch, which shows YAML; a YAML front end can come later).

| Field | Type | M1 rule |
|---|---|---|
| `config_version` | str | `"0.1"` |
| `autonomy` | int | informational in M1 (checkpointing lands in M2) |
| `assurance` | str | must exist in `scripts/supported_tiers.json`; M1 ships only `cooperative` (unqualified — prints a warning, outcome is `COMPLETE_UNQUALIFIED`) |
| `feedback` | str | must be `"ids"` in M1 |
| `max_iterations` | int | 1..20 |
| `workspace_root` | str | absolute path; must be disjoint from the control root |
| `roles.builder.adapter` | str | path to an executable speaking adapter protocol 0.1 |
| `roles.builder.timeout_s` | int | optional, default 600 |
| `budget.billing` | str | `"subscription"` (alert-only) in M1; metered admission lands later |
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
.venv/bin/python -m pytest dark-factory/tests/test_config.py -v
```

Expected: 8 passed.

- [ ] **Step 5: Commit**

```bash
git add dark-factory/scripts/supported_tiers.json dark-factory/scripts/df_config.py dark-factory/references/config-reference.md dark-factory/tests/test_config.py
git commit -m "feat(dark-factory): tier registry + fail-closed config validation

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 3: lstat source snapshot

**Files:**
- Create: `dark-factory/scripts/snapshot_source.py`
- Test: `dark-factory/tests/test_snapshot.py`

**Interfaces:**
- Consumes: `df_common.canonical_json`, `df_common.sha256_file`, `df_common.sha256_str`.
- Produces:
  - `snapshot_source.SnapshotError(ValueError)`.
  - `snapshot_source.build_manifest(src_root: str) -> dict` — `{"manifest_version": "0.1", "files": [{"path", "size", "sha256"}, ...]}` sorted by path; raises on symlinks, special files, `st_nlink > 1`; skips `.git`.
  - `snapshot_source.snapshot(src_root: str, dest_root: str) -> tuple[dict, str]` — copies manifest files, returns `(manifest, manifest_sha256)`.

- [ ] **Step 1: Write the failing tests**

`dark-factory/tests/test_snapshot.py`:

```python
import os

import pytest

import snapshot_source


def make_src(tmp_path):
    src = tmp_path / "src"
    (src / "pkg").mkdir(parents=True)
    (src / "a.txt").write_text("alpha", encoding="utf-8")
    (src / "pkg" / "b.txt").write_text("beta", encoding="utf-8")
    (src / ".git").mkdir()
    (src / ".git" / "HEAD").write_text("ref: refs/heads/main", encoding="utf-8")
    return src


def test_manifest_lists_files_sorted_and_skips_git(tmp_path):
    src = make_src(tmp_path)
    m = snapshot_source.build_manifest(str(src))
    assert m["manifest_version"] == "0.1"
    assert [e["path"] for e in m["files"]] == ["a.txt", os.path.join("pkg", "b.txt")]
    assert all(len(e["sha256"]) == 64 for e in m["files"])


def test_symlink_is_rejected(tmp_path):
    src = make_src(tmp_path)
    os.symlink("/etc/hosts", src / "evil_link")
    with pytest.raises(snapshot_source.SnapshotError, match="symlink"):
        snapshot_source.build_manifest(str(src))


def test_symlinked_dir_is_rejected(tmp_path):
    src = make_src(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    os.symlink(outside, src / "evil_dir")
    with pytest.raises(snapshot_source.SnapshotError, match="symlink"):
        snapshot_source.build_manifest(str(src))


def test_hardlinked_file_is_rejected(tmp_path):
    src = make_src(tmp_path)
    os.link(src / "a.txt", src / "hard.txt")
    with pytest.raises(snapshot_source.SnapshotError, match="multi-link"):
        snapshot_source.build_manifest(str(src))


def test_fifo_is_rejected(tmp_path):
    src = make_src(tmp_path)
    os.mkfifo(src / "pipe")
    with pytest.raises(snapshot_source.SnapshotError, match="special"):
        snapshot_source.build_manifest(str(src))


def test_snapshot_copies_content_and_hash_is_stable(tmp_path):
    src = make_src(tmp_path)
    dest = tmp_path / "dest"
    m1, h1 = snapshot_source.snapshot(str(src), str(dest))
    assert (dest / "a.txt").read_text(encoding="utf-8") == "alpha"
    assert (dest / "pkg" / "b.txt").read_text(encoding="utf-8") == "beta"
    assert not (dest / ".git").exists()
    m2 = snapshot_source.build_manifest(str(src))
    import df_common
    assert h1 == df_common.sha256_str(df_common.canonical_json(m2))


def test_empty_source_gives_empty_manifest(tmp_path):
    src = tmp_path / "empty"
    src.mkdir()
    dest = tmp_path / "dest"
    m, h = snapshot_source.snapshot(str(src), str(dest))
    assert m["files"] == []
    assert os.path.isdir(dest)
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
.venv/bin/python -m pytest dark-factory/tests/test_snapshot.py -v
```

Expected: FAIL — `ModuleNotFoundError: No module named 'snapshot_source'`.

- [ ] **Step 3: Implement `snapshot_source.py`**

`dark-factory/scripts/snapshot_source.py`:

```python
"""lstat-manifest source snapshot (spec section 7.1). Stdlib only.

Builds a history-free copy of an approved source root for the build
workspace: no .git, no symlinks, no special files, no multi-hardlink files
(st_nlink > 1 is the conservative rejection for hardlink escape).
"""
import os
import shutil
import stat

from df_common import canonical_json, sha256_file, sha256_str

EXCLUDE_DIRS = {".git"}


class SnapshotError(ValueError):
    pass


def build_manifest(src_root: str) -> dict:
    src_root = os.path.realpath(src_root)
    entries = []
    for dirpath, dirnames, filenames in os.walk(src_root):
        dirnames[:] = sorted(d for d in dirnames if d not in EXCLUDE_DIRS)
        for d in list(dirnames):
            full = os.path.join(dirpath, d)
            if os.path.islink(full):
                raise SnapshotError(f"symlink not allowed in source: {full}")
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            st = os.lstat(full)
            if stat.S_ISLNK(st.st_mode):
                raise SnapshotError(f"symlink not allowed in source: {full}")
            if not stat.S_ISREG(st.st_mode):
                raise SnapshotError(f"special file not allowed in source: {full}")
            if st.st_nlink > 1:
                raise SnapshotError(f"multi-link file not allowed in source: {full}")
            rel = os.path.relpath(full, src_root)
            entries.append(
                {"path": rel, "size": st.st_size, "sha256": sha256_file(full)}
            )
    entries.sort(key=lambda e: e["path"])
    return {"manifest_version": "0.1", "files": entries}


def snapshot(src_root: str, dest_root: str):
    """Copy the manifest's files into dest_root. Returns (manifest, manifest_sha256)."""
    manifest = build_manifest(src_root)
    os.makedirs(dest_root, exist_ok=True)
    for e in manifest["files"]:
        s = os.path.join(src_root, e["path"])
        d = os.path.join(dest_root, e["path"])
        os.makedirs(os.path.dirname(d) or dest_root, exist_ok=True)
        with open(s, "rb") as fs, open(d, "wb") as fd:
            shutil.copyfileobj(fs, fd)
    return manifest, sha256_str(canonical_json(manifest))
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
.venv/bin/python -m pytest dark-factory/tests/test_snapshot.py -v
```

Expected: 7 passed.

- [ ] **Step 5: Commit**

```bash
git add dark-factory/scripts/snapshot_source.py dark-factory/tests/test_snapshot.py
git commit -m "feat(dark-factory): lstat-manifest source snapshot with special-file rejection

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 4: Oracle IR v0 and the scenario runner (verifier)

**Files:**
- Create: `dark-factory/scripts/run_scenarios.py`
- Create: `dark-factory/references/scenario-format.md`
- Test: `dark-factory/tests/test_oracle.py`

**Interfaces:**
- Consumes: nothing beyond stdlib (kept import-independent so M2 can reuse it inside a sandboxed verifier).
- Produces:
  - `run_scenarios.OracleError(ValueError)` — invalid IR.
  - `run_scenarios.load_scenarios(scenarios_dir: str) -> list[dict]` — validated IR dicts, sorted by filename.
  - `run_scenarios.run_scenario(sc: dict, workspace: str) -> dict` — one result: `{"id", "behavior_id", "pass": bool, "taxonomy": None|str, "observed": {"exit_code", "stdout", "stderr"}}`.
  - `run_scenarios.run_all(scenarios_dir: str, workspace: str) -> dict` — `{"report_version": "0.1", "results": [...], "all_pass": bool}`.
  - Taxonomy priority when multiple assertions fail: `timeout` > `crash` > `wrong_exit_code` > `wrong_output`.
  - `stdout_equals` / `stderr_equals` compare after stripping one trailing newline from both sides.

- [ ] **Step 1: Write the failing tests**

`dark-factory/tests/test_oracle.py`:

```python
import json

import pytest

import run_scenarios


def write_scenario(d, name, **kw):
    sc = {
        "ir_version": "0.1",
        "id": "BHV-001-S1",
        "behavior_id": "BHV-001",
        "title": "prints ok",
        "given": "an ok.py exists",
        "when": {"run": ["python3", "ok.py"], "timeout_s": 10},
        "then": {"exit_code": 0, "stdout_equals": "ok"},
    }
    sc.update(kw)
    d.mkdir(parents=True, exist_ok=True)
    (d / name).write_text(json.dumps(sc), encoding="utf-8")
    return sc


def make_workspace(tmp_path, body='print("ok")'):
    ws = tmp_path / "ws"
    ws.mkdir(exist_ok=True)
    (ws / "ok.py").write_text(body + "\n", encoding="utf-8")
    return ws


def test_load_validates_and_sorts(tmp_path):
    d = tmp_path / "scen"
    write_scenario(d, "b.json", id="BHV-001-S2")
    write_scenario(d, "a.json", id="BHV-001-S1")
    scs = run_scenarios.load_scenarios(str(d))
    assert [s["id"] for s in scs] == ["BHV-001-S1", "BHV-001-S2"]


def test_load_rejects_bad_ir_version(tmp_path):
    d = tmp_path / "scen"
    write_scenario(d, "a.json", ir_version="9.9")
    with pytest.raises(run_scenarios.OracleError, match="ir_version"):
        run_scenarios.load_scenarios(str(d))


def test_load_rejects_bad_behavior_id(tmp_path):
    d = tmp_path / "scen"
    write_scenario(d, "a.json", behavior_id="oops!")
    with pytest.raises(run_scenarios.OracleError, match="behavior_id"):
        run_scenarios.load_scenarios(str(d))


def test_load_rejects_empty_then(tmp_path):
    d = tmp_path / "scen"
    write_scenario(d, "a.json", then={})
    with pytest.raises(run_scenarios.OracleError, match="assertion"):
        run_scenarios.load_scenarios(str(d))


def test_passing_scenario(tmp_path):
    d = tmp_path / "scen"
    sc = write_scenario(d, "a.json")
    ws = make_workspace(tmp_path)
    r = run_scenarios.run_scenario(sc, str(ws))
    assert r["pass"] is True and r["taxonomy"] is None
    assert r["observed"]["exit_code"] == 0


def test_wrong_output_taxonomy(tmp_path):
    d = tmp_path / "scen"
    sc = write_scenario(d, "a.json")
    ws = make_workspace(tmp_path, body='print("wrong")')
    r = run_scenarios.run_scenario(sc, str(ws))
    assert r["pass"] is False and r["taxonomy"] == "wrong_output"


def test_wrong_exit_code_beats_wrong_output(tmp_path):
    d = tmp_path / "scen"
    sc = write_scenario(d, "a.json")
    ws = make_workspace(tmp_path, body='import sys\nprint("wrong")\nsys.exit(3)')
    r = run_scenarios.run_scenario(sc, str(ws))
    assert r["taxonomy"] == "wrong_exit_code"


def test_timeout_taxonomy(tmp_path):
    d = tmp_path / "scen"
    sc = write_scenario(
        d, "a.json", when={"run": ["python3", "ok.py"], "timeout_s": 1}
    )
    ws = make_workspace(tmp_path, body="import time\ntime.sleep(30)")
    r = run_scenarios.run_scenario(sc, str(ws))
    assert r["pass"] is False and r["taxonomy"] == "timeout"


def test_crash_taxonomy_when_command_cannot_start(tmp_path):
    d = tmp_path / "scen"
    sc = write_scenario(
        d, "a.json", when={"run": ["./does-not-exist-xyz"], "timeout_s": 5}
    )
    ws = make_workspace(tmp_path)
    r = run_scenarios.run_scenario(sc, str(ws))
    assert r["pass"] is False and r["taxonomy"] == "crash"


def test_run_all_report_shape(tmp_path):
    d = tmp_path / "scen"
    write_scenario(d, "a.json")
    write_scenario(
        d, "b.json", id="BHV-002-S1", behavior_id="BHV-002",
        then={"exit_code": 0, "stdout_contains": "o"},
    )
    ws = make_workspace(tmp_path)
    rep = run_scenarios.run_all(str(d), str(ws))
    assert rep["report_version"] == "0.1"
    assert rep["all_pass"] is True
    assert len(rep["results"]) == 2
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
.venv/bin/python -m pytest dark-factory/tests/test_oracle.py -v
```

Expected: FAIL — `ModuleNotFoundError: No module named 'run_scenarios'`.

- [ ] **Step 3: Implement `run_scenarios.py`**

`dark-factory/scripts/run_scenarios.py`:

```python
"""Oracle IR v0 runner (the verifier's executable check contract). Stdlib only.

IR v0: one JSON file per scenario:
  {
    "ir_version": "0.1",
    "id": "BHV-001-S1",              # scenario id
    "behavior_id": "BHV-001",         # ^BHV-[A-Za-z0-9-]{1,32}$
    "title": "...", "given": "...",   # human view; NEVER crosses the barrier
    "when": {"run": ["cmd", ...], "timeout_s": 10},
    "then": {"exit_code": 0,
             "stdout_equals"|"stdout_contains"|
             "stderr_equals"|"stderr_contains": "..."}   # >= 1 assertion
  }
Taxonomy priority on failure: timeout > crash > wrong_exit_code > wrong_output.
Equality assertions strip one trailing newline from both sides.
"""
import glob
import json
import os
import re
import subprocess

IR_VERSION = "0.1"
BEHAVIOR_RE = re.compile(r"^BHV-[A-Za-z0-9-]{1,32}$")
ASSERT_KEYS = {
    "exit_code",
    "stdout_equals",
    "stdout_contains",
    "stderr_equals",
    "stderr_contains",
}


class OracleError(ValueError):
    pass


def _validate(sc: dict, fname: str) -> None:
    if sc.get("ir_version") != IR_VERSION:
        raise OracleError(f"{fname}: ir_version must be {IR_VERSION!r}")
    for key in ("id", "behavior_id", "title", "given", "when", "then"):
        if key not in sc:
            raise OracleError(f"{fname}: missing {key!r}")
    if not BEHAVIOR_RE.fullmatch(sc["behavior_id"]):
        raise OracleError(f"{fname}: invalid behavior_id {sc['behavior_id']!r}")
    run = sc["when"].get("run")
    if not isinstance(run, list) or not run or not all(isinstance(x, str) for x in run):
        raise OracleError(f"{fname}: when.run must be a non-empty list of strings")
    then = sc["then"]
    if not isinstance(then, dict) or not (set(then) & ASSERT_KEYS) or set(then) - ASSERT_KEYS:
        raise OracleError(f"{fname}: then needs >=1 known assertion key {sorted(ASSERT_KEYS)}")


def load_scenarios(scenarios_dir: str) -> list:
    scs = []
    for path in sorted(glob.glob(os.path.join(scenarios_dir, "*.json"))):
        with open(path, encoding="utf-8") as f:
            sc = json.load(f)
        _validate(sc, os.path.basename(path))
        scs.append(sc)
    if not scs:
        raise OracleError(f"no scenarios found in {scenarios_dir}")
    return scs


def _norm(s: str) -> str:
    return s[:-1] if s.endswith("\n") else s


def run_scenario(sc: dict, workspace: str) -> dict:
    timeout = sc["when"].get("timeout_s", 30)
    observed = {"exit_code": None, "stdout": "", "stderr": ""}
    taxonomy = None
    try:
        proc = subprocess.run(
            sc["when"]["run"],
            cwd=workspace,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        observed = {
            "exit_code": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
        }
    except subprocess.TimeoutExpired:
        taxonomy = "timeout"
    except (FileNotFoundError, PermissionError, OSError):
        taxonomy = "crash"

    if taxonomy is None:
        then = sc["then"]
        if "exit_code" in then and observed["exit_code"] != then["exit_code"]:
            taxonomy = "wrong_exit_code"
        elif (
            ("stdout_equals" in then and _norm(observed["stdout"]) != _norm(then["stdout_equals"]))
            or ("stdout_contains" in then and then["stdout_contains"] not in observed["stdout"])
            or ("stderr_equals" in then and _norm(observed["stderr"]) != _norm(then["stderr_equals"]))
            or ("stderr_contains" in then and then["stderr_contains"] not in observed["stderr"])
        ):
            taxonomy = "wrong_output"

    return {
        "id": sc["id"],
        "behavior_id": sc["behavior_id"],
        "pass": taxonomy is None,
        "taxonomy": taxonomy,
        "observed": observed,
    }


def run_all(scenarios_dir: str, workspace: str) -> dict:
    results = [run_scenario(sc, workspace) for sc in load_scenarios(scenarios_dir)]
    return {
        "report_version": "0.1",
        "results": results,
        "all_pass": all(r["pass"] for r in results),
    }
```

`dark-factory/references/scenario-format.md`:

```markdown
# Oracle IR v0 (M1) — hidden holdout scenario format

One JSON file per scenario in `<control_root>/scenarios/`. HOLDOUT: these files
never enter the build workspace, the builder prompt, or feedback.

Fields: `ir_version` ("0.1"), `id`, `behavior_id` (`^BHV-[A-Za-z0-9-]{1,32}$`),
`title`/`given` (human view only), `when.run` (argv list executed with
cwd = build workspace, `when.timeout_s` default 30), `then` (>= 1 of:
`exit_code`, `stdout_equals`, `stdout_contains`, `stderr_equals`,
`stderr_contains`; equality strips one trailing newline).

Failure taxonomy (the ONLY thing that crosses the barrier, with the
behavior_id): `timeout` > `crash` > `wrong_exit_code` > `wrong_output`
(priority order when several assertions fail). Coarse by design — the
taxonomy is leak-resistant, not diagnostic.

The versioned IR + this runner contract is the seam where M2+ swaps in
richer backends (spec section 5.1) without redesign.
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
.venv/bin/python -m pytest dark-factory/tests/test_oracle.py -v
```

Expected: 10 passed.

- [ ] **Step 5: Commit**

```bash
git add dark-factory/scripts/run_scenarios.py dark-factory/references/scenario-format.md dark-factory/tests/test_oracle.py
git commit -m "feat(dark-factory): oracle IR v0 and deterministic scenario runner

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 5: Deterministic ID/taxonomy feedback projection

**Files:**
- Create: `dark-factory/scripts/id_feedback.py`
- Test: `dark-factory/tests/test_feedback.py`

**Interfaces:**
- Consumes: verifier report dict from `run_scenarios.run_all` (shape defined in Task 4).
- Produces:
  - `id_feedback.FeedbackLeakError(ValueError)`.
  - `id_feedback.project_feedback(report: dict) -> dict` — `{"feedback_version": "0.1", "channel": "ids", "total": int, "failing_count": int, "failures": [{"behavior_id": str, "taxonomy": [str, ...]}, ...]}`, failures sorted by behavior_id, taxonomy lists sorted.
  - `id_feedback.validate_feedback(fb: dict) -> None` — raises `FeedbackLeakError` unless the structure matches the allowlist exactly. **This is the security-critical projection: it never touches `title`, `given`, `when`, `then`, or `observed`.**

- [ ] **Step 1: Write the failing tests**

`dark-factory/tests/test_feedback.py`:

```python
import json

import pytest

import id_feedback

MARKER = "HOLDOUT-MARKER-93e1"


def make_report():
    return {
        "report_version": "0.1",
        "all_pass": False,
        "results": [
            {
                "id": "BHV-001-S1",
                "behavior_id": "BHV-001",
                "pass": False,
                "taxonomy": "wrong_output",
                "observed": {"exit_code": 0, "stdout": f"secret {MARKER}", "stderr": ""},
            },
            {
                "id": "BHV-001-S2",
                "behavior_id": "BHV-001",
                "pass": False,
                "taxonomy": "wrong_exit_code",
                "observed": {"exit_code": 3, "stdout": MARKER, "stderr": MARKER},
            },
            {
                "id": "BHV-002-S1",
                "behavior_id": "BHV-002",
                "pass": True,
                "taxonomy": None,
                "observed": {"exit_code": 2, "stdout": "", "stderr": f"usage {MARKER}"},
            },
        ],
    }


def test_projection_contains_only_ids_and_taxonomy():
    fb = id_feedback.project_feedback(make_report())
    assert fb == {
        "feedback_version": "0.1",
        "channel": "ids",
        "total": 3,
        "failing_count": 2,
        "failures": [
            {"behavior_id": "BHV-001", "taxonomy": ["wrong_exit_code", "wrong_output"]}
        ],
    }


def test_projection_never_leaks_observed_or_scenario_text():
    fb = id_feedback.project_feedback(make_report())
    assert MARKER not in json.dumps(fb)


def test_all_pass_produces_empty_failures():
    rep = make_report()
    for r in rep["results"]:
        r["pass"], r["taxonomy"] = True, None
    rep["all_pass"] = True
    fb = id_feedback.project_feedback(rep)
    assert fb["failing_count"] == 0 and fb["failures"] == []


def test_validate_rejects_extra_keys():
    fb = id_feedback.project_feedback(make_report())
    fb["hint"] = "the expected output is Hello"
    with pytest.raises(id_feedback.FeedbackLeakError):
        id_feedback.validate_feedback(fb)


def test_validate_rejects_bad_behavior_id():
    fb = id_feedback.project_feedback(make_report())
    fb["failures"][0]["behavior_id"] = "BHV-001 (expects Hello, World!)"
    with pytest.raises(id_feedback.FeedbackLeakError):
        id_feedback.validate_feedback(fb)


def test_validate_rejects_unknown_taxonomy():
    fb = id_feedback.project_feedback(make_report())
    fb["failures"][0]["taxonomy"] = ["expected 'Hello, World!'"]
    with pytest.raises(id_feedback.FeedbackLeakError):
        id_feedback.validate_feedback(fb)
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
.venv/bin/python -m pytest dark-factory/tests/test_feedback.py -v
```

Expected: FAIL — `ModuleNotFoundError: No module named 'id_feedback'`.

- [ ] **Step 3: Implement `id_feedback.py`**

`dark-factory/scripts/id_feedback.py`:

```python
"""Deterministic ID/taxonomy feedback projection (spec section 6.1). Stdlib only.

This is the ONLY thing that crosses the information barrier back to the
builder. It is a pure structural projection: it reads behavior_id, pass,
and taxonomy from the verifier report and NOTHING else — no titles, no
given/when/then, no observed output, no model call.
"""
import re

TAXONOMY = ("wrong_exit_code", "wrong_output", "timeout", "crash")
BEHAVIOR_RE = re.compile(r"^BHV-[A-Za-z0-9-]{1,32}$")
ALLOWED_TOP = {"feedback_version", "channel", "total", "failing_count", "failures"}
ALLOWED_FAILURE = {"behavior_id", "taxonomy"}


class FeedbackLeakError(ValueError):
    pass


def project_feedback(report: dict) -> dict:
    failing = {}
    for r in report["results"]:
        if not r["pass"]:
            failing.setdefault(r["behavior_id"], set()).add(r["taxonomy"])
    fb = {
        "feedback_version": "0.1",
        "channel": "ids",
        "total": len(report["results"]),
        "failing_count": sum(1 for r in report["results"] if not r["pass"]),
        "failures": [
            {"behavior_id": b, "taxonomy": sorted(t)}
            for b, t in sorted(failing.items())
        ],
    }
    validate_feedback(fb)
    return fb


def validate_feedback(fb: dict) -> None:
    if set(fb) != ALLOWED_TOP:
        raise FeedbackLeakError(f"feedback keys must be exactly {sorted(ALLOWED_TOP)}")
    if fb["feedback_version"] != "0.1" or fb["channel"] != "ids":
        raise FeedbackLeakError("bad feedback_version/channel")
    if not isinstance(fb["total"], int) or not isinstance(fb["failing_count"], int):
        raise FeedbackLeakError("total/failing_count must be ints")
    if not isinstance(fb["failures"], list):
        raise FeedbackLeakError("failures must be a list")
    for f in fb["failures"]:
        if set(f) != ALLOWED_FAILURE:
            raise FeedbackLeakError(f"failure keys must be exactly {sorted(ALLOWED_FAILURE)}")
        if not BEHAVIOR_RE.fullmatch(f["behavior_id"]):
            raise FeedbackLeakError(f"invalid behavior_id: {f['behavior_id']!r}")
        if not isinstance(f["taxonomy"], list) or not f["taxonomy"]:
            raise FeedbackLeakError("taxonomy must be a non-empty list")
        for t in f["taxonomy"]:
            if t not in TAXONOMY:
                raise FeedbackLeakError(f"unknown taxonomy value: {t!r}")
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
.venv/bin/python -m pytest dark-factory/tests/test_feedback.py -v
```

Expected: 6 passed.

- [ ] **Step 5: Commit**

```bash
git add dark-factory/scripts/id_feedback.py dark-factory/tests/test_feedback.py
git commit -m "feat(dark-factory): deterministic ID/taxonomy feedback projection with leak validation

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 6: Adapter protocol v0, claude adapter, fake builder fixture

**Files:**
- Create: `dark-factory/scripts/adapters/claude` (executable)
- Create: `dark-factory/tests/fixtures/fake_builder` (executable)
- Create: `dark-factory/references/role-adapters.md`
- Test: `dark-factory/tests/test_adapters.py`

**Interfaces:**
- Consumes: nothing from earlier tasks (adapters are standalone executables).
- Produces (the protocol every adapter speaks, used by Task 7's supervisor):
  - **Request (stdin, JSON):** `{"adapter_protocol": "0.1", "role": "builder", "workdir": "<abs path>", "prompt_file": "<abs path>", "timeout_s": <int>}`
  - **Response (stdout, JSON):** `{"adapter_protocol": "0.1", "status": "ok"|"error", "detail": "<str>", "usage": {"known": false}}`
  - Adapter process exit code 0 even on `status: "error"` (protocol errors are in-band); a non-zero exit or unparseable stdout is a supervisor-level `ABORTED_BUILD_ERROR`.
  - `fake_builder` behavior (drives the e2e loop deterministically): reads the toy spec expectation; if `<workdir>/feedback.json` does **not** exist it writes a **buggy** `greet.py` (prints `Hi, <name>!`); if it exists it writes the **correct** `greet.py` (prints `Hello, <name>!`). Both versions handle the no-args usage error (exit 2, `usage: greet.py <name>` on stderr).

- [ ] **Step 1: Write the failing tests**

`dark-factory/tests/test_adapters.py`:

```python
import json
import os
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
FAKE = os.path.join(HERE, "fixtures", "fake_builder")
CLAUDE_ADAPTER = os.path.join(HERE, "..", "scripts", "adapters", "claude")


def invoke(adapter, req):
    proc = subprocess.run(
        [adapter], input=json.dumps(req), capture_output=True, text=True, timeout=30
    )
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


def make_req(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir(exist_ok=True)
    pf = tmp_path / "prompt.md"
    pf.write_text("Build greet.py per SPEC.", encoding="utf-8")
    return {
        "adapter_protocol": "0.1",
        "role": "builder",
        "workdir": str(ws),
        "prompt_file": str(pf),
        "timeout_s": 20,
    }


def test_fake_builder_writes_buggy_version_first(tmp_path):
    req = make_req(tmp_path)
    resp = invoke(FAKE, req)
    assert resp["status"] == "ok" and resp["adapter_protocol"] == "0.1"
    out = subprocess.run(
        ["python3", "greet.py", "World"],
        cwd=req["workdir"], capture_output=True, text=True,
    )
    assert out.stdout.strip() == "Hi, World!"  # deliberately wrong greeting


def test_fake_builder_fixes_after_feedback(tmp_path):
    req = make_req(tmp_path)
    invoke(FAKE, req)
    (tmp_path / "ws" / "feedback.json").write_text(
        json.dumps({"failures": [{"behavior_id": "BHV-001", "taxonomy": ["wrong_output"]}]}),
        encoding="utf-8",
    )
    invoke(FAKE, req)
    out = subprocess.run(
        ["python3", "greet.py", "World"],
        cwd=req["workdir"], capture_output=True, text=True,
    )
    assert out.stdout.strip() == "Hello, World!"


def test_fake_builder_usage_error_both_versions(tmp_path):
    req = make_req(tmp_path)
    invoke(FAKE, req)
    out = subprocess.run(
        ["python3", "greet.py"], cwd=req["workdir"], capture_output=True, text=True
    )
    assert out.returncode == 2 and "usage:" in out.stderr


def test_claude_adapter_reports_error_when_cli_missing(tmp_path):
    req = make_req(tmp_path)
    env = dict(os.environ, PATH="/nonexistent-bin")
    proc = subprocess.run(
        [CLAUDE_ADAPTER], input=json.dumps(req),
        capture_output=True, text=True, timeout=30, env=env,
    )
    assert proc.returncode == 0
    resp = json.loads(proc.stdout)
    assert resp["status"] == "error"
    assert "claude" in resp["detail"]
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
.venv/bin/python -m pytest dark-factory/tests/test_adapters.py -v
```

Expected: FAIL — `FileNotFoundError` (adapter executables do not exist).

- [ ] **Step 3: Implement the adapters**

`dark-factory/tests/fixtures/fake_builder`:

```python
#!/usr/bin/env python3
"""Deterministic fake builder for tests. Speaks adapter protocol 0.1.

Behavior: without <workdir>/feedback.json writes a buggy greet.py
("Hi, <name>!"); with feedback present writes the correct one
("Hello, <name>!"). Models a builder that misreads the spec once,
then fixes the flagged behavior. Never reads scenarios (cannot — they
are not reachable from the workspace).
"""
import json
import os
import sys

BUGGY = (
    "import sys\n"
    "if len(sys.argv) < 2:\n"
    "    print(\"usage: greet.py <name>\", file=sys.stderr)\n"
    "    sys.exit(2)\n"
    "print(f\"Hi, {sys.argv[1]}!\")\n"
)
GOOD = BUGGY.replace("Hi, ", "Hello, ")


def main():
    req = json.load(sys.stdin)
    wd = req["workdir"]
    body = GOOD if os.path.exists(os.path.join(wd, "feedback.json")) else BUGGY
    with open(os.path.join(wd, "greet.py"), "w", encoding="utf-8") as f:
        f.write(body)
    print(json.dumps({"adapter_protocol": "0.1", "status": "ok", "detail": "",
                      "usage": {"known": False}}))


if __name__ == "__main__":
    main()
```

`dark-factory/scripts/adapters/claude`:

```python
#!/usr/bin/env python3
"""Claude Code adapter, protocol 0.1. Invokes the claude CLI headless with
cwd = the build workspace. The model only ever sees the prompt file content
(spec + ID feedback) and the workspace directory."""
import json
import shutil
import subprocess
import sys


def respond(status, detail=""):
    print(json.dumps({"adapter_protocol": "0.1", "status": status,
                      "detail": detail, "usage": {"known": False}}))


def main():
    req = json.load(sys.stdin)
    with open(req["prompt_file"], encoding="utf-8") as f:
        prompt = f.read()
    if shutil.which("claude") is None:
        respond("error", "claude CLI not found on PATH")
        return
    try:
        proc = subprocess.run(
            ["claude", "-p", prompt, "--permission-mode", "acceptEdits"],
            cwd=req["workdir"],
            timeout=req.get("timeout_s", 600),
            capture_output=True,
            text=True,
        )
    except subprocess.TimeoutExpired:
        respond("error", "claude CLI timed out")
        return
    if proc.returncode != 0:
        respond("error", (proc.stderr or proc.stdout)[-2000:])
        return
    respond("ok")


if __name__ == "__main__":
    main()
```

Make both executable:

```bash
chmod +x dark-factory/tests/fixtures/fake_builder dark-factory/scripts/adapters/claude
```

`dark-factory/references/role-adapters.md`:

```markdown
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
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
.venv/bin/python -m pytest dark-factory/tests/test_adapters.py -v
```

Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
git add dark-factory/scripts/adapters/claude dark-factory/tests/fixtures/fake_builder dark-factory/references/role-adapters.md dark-factory/tests/test_adapters.py
git commit -m "feat(dark-factory): adapter protocol v0.1 with claude adapter and fake builder fixture

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 7: Supervisor — FSM, lock, journal, and the build/verify loop

**Files:**
- Create: `dark-factory/scripts/supervisor.py`
- Create: `dark-factory/tests/fixtures/fake_builder_stubborn` (executable)
- Test: `dark-factory/tests/test_supervisor.py`

**Interfaces:**
- Consumes: `df_config.load_config`, `snapshot_source.snapshot`, `run_scenarios.run_all`, `id_feedback.project_feedback`, `df_common.*`, adapter protocol 0.1 (Task 6).
- Produces:
  - CLI: `python3 supervisor.py run --control-root CR [--project-src DIR]` → exit `0` (converged), `2` (config/build error), `3` (cap reached).
  - `supervisor.acquire_lock(control_root: str) -> str` / `supervisor.release_lock(lock_path: str)` — `<CR>/.lock` via `O_CREAT|O_EXCL` holding the pid; stale (dead pid) locks are removed with a warning.
  - `supervisor.compose_prompt(spec_text: str, feedback: dict|None) -> str` — spec + ID feedback + fixed builder rules; **built only from spec + validated feedback, structurally never from scenarios**.
  - `supervisor.run(control_root: str, project_src: str|None) -> int` — the loop; journals JSONL states to `runs/<id>/journal.jsonl`: `INIT`, `SNAPSHOT`, `BUILD`, `VERIFY`, `FEEDBACK`, then one terminal: `CONVERGED` + `COMPLETE_UNQUALIFIED`, `CAP_REACHED`, or `ABORTED_BUILD_ERROR`.
  - Journal line shape: `{"ts": "<UTC ISO8601>", "state": "<STATE>", "data": {...}}`.
  - Exports **into the workspace**: `spec.md` (always) and `feedback.json` (after a failing iteration). Nothing else crosses.

- [ ] **Step 1: Create the stubborn fake builder fixture**

`dark-factory/tests/fixtures/fake_builder_stubborn`:

```python
#!/usr/bin/env python3
"""Fake builder that never converges: always writes the buggy greet.py."""
import json
import os
import sys

BUGGY = (
    "import sys\n"
    "if len(sys.argv) < 2:\n"
    "    print(\"usage: greet.py <name>\", file=sys.stderr)\n"
    "    sys.exit(2)\n"
    "print(f\"Hi, {sys.argv[1]}!\")\n"
)


def main():
    req = json.load(sys.stdin)
    with open(os.path.join(req["workdir"], "greet.py"), "w", encoding="utf-8") as f:
        f.write(BUGGY)
    print(json.dumps({"adapter_protocol": "0.1", "status": "ok", "detail": "",
                      "usage": {"known": False}}))


if __name__ == "__main__":
    main()
```

```bash
chmod +x dark-factory/tests/fixtures/fake_builder_stubborn
```

- [ ] **Step 2: Write the failing tests**

`dark-factory/tests/test_supervisor.py`:

```python
import json
import os

import pytest

import supervisor

HERE = os.path.dirname(os.path.abspath(__file__))
FAKE = os.path.join(HERE, "fixtures", "fake_builder")
STUBBORN = os.path.join(HERE, "fixtures", "fake_builder_stubborn")
MARKER = "HOLDOUT-MARKER-93e1"

TOY_SPEC = """# greet CLI
Create an executable python file `greet.py` in the workspace root.
- `python3 greet.py <name>` prints exactly `Hello, <name>!` and exits 0.
- `python3 greet.py` with no arguments prints `usage: greet.py <name>` to stderr and exits 2.
"""


def scenario(sid, bid, run, then, title):
    return {
        "ir_version": "0.1", "id": sid, "behavior_id": bid,
        "title": title, "given": f"{MARKER} workspace has greet.py",
        "when": {"run": run, "timeout_s": 10}, "then": then,
    }


def setup_control(tmp_path, adapter, max_iterations=5):
    cr = tmp_path / "control"
    (cr / "scenarios").mkdir(parents=True)
    (cr / "config.json").write_text(json.dumps({
        "config_version": "0.1", "autonomy": 4, "assurance": "cooperative",
        "feedback": "ids", "max_iterations": max_iterations,
        "workspace_root": str(tmp_path / "ws"),
        "roles": {"builder": {"adapter": adapter, "timeout_s": 30}},
        "budget": {"billing": "subscription"},
    }), encoding="utf-8")
    (cr / "spec.md").write_text(TOY_SPEC, encoding="utf-8")
    scs = [
        scenario("BHV-001-S1", "BHV-001", ["python3", "greet.py", "World"],
                 {"exit_code": 0, "stdout_equals": "Hello, World!"},
                 f"{MARKER} greets World"),
        scenario("BHV-001-S2", "BHV-001", ["python3", "greet.py", "Alon"],
                 {"exit_code": 0, "stdout_equals": "Hello, Alon!"},
                 f"{MARKER} greets Alon"),
        scenario("BHV-002-S1", "BHV-002", ["python3", "greet.py"],
                 {"exit_code": 2, "stderr_contains": "usage:"},
                 f"{MARKER} usage error"),
    ]
    for i, sc in enumerate(scs):
        (cr / "scenarios" / f"s{i}.json").write_text(json.dumps(sc), encoding="utf-8")
    return cr


def read_journal(cr):
    runs = os.listdir(cr / "runs")
    assert len(runs) == 1
    lines = (cr / "runs" / runs[0] / "journal.jsonl").read_text(encoding="utf-8")
    return [json.loads(l) for l in lines.strip().splitlines()], runs[0]


def test_converging_run_exits_zero_and_journals(tmp_path):
    cr = setup_control(tmp_path, FAKE)
    rc = supervisor.run(str(cr), None)
    assert rc == 0
    entries, _ = read_journal(cr)
    states = [e["state"] for e in entries]
    assert states[0] == "INIT" and states[1] == "SNAPSHOT"
    assert "CONVERGED" in states and states[-1] == "COMPLETE_UNQUALIFIED"
    # two iterations: buggy then fixed
    assert states.count("BUILD") == 2 and states.count("FEEDBACK") == 1


def test_stubborn_run_hits_cap_with_exit_3(tmp_path):
    cr = setup_control(tmp_path, STUBBORN, max_iterations=2)
    rc = supervisor.run(str(cr), None)
    assert rc == 3
    entries, _ = read_journal(cr)
    states = [e["state"] for e in entries]
    assert states[-1] == "CAP_REACHED" and states.count("BUILD") == 2
    # cap message names failing behaviors, not scenario content
    cap = entries[-1]["data"]
    assert cap["failing_behaviors"] == ["BHV-001"]


def test_lock_prevents_concurrent_runs(tmp_path):
    cr = setup_control(tmp_path, FAKE)
    lock = supervisor.acquire_lock(str(cr))
    try:
        with pytest.raises(supervisor.LockError):
            supervisor.acquire_lock(str(cr))
    finally:
        supervisor.release_lock(lock)
    # released -> can acquire again
    supervisor.release_lock(supervisor.acquire_lock(str(cr)))


def test_stale_lock_is_reclaimed(tmp_path):
    cr = setup_control(tmp_path, FAKE)
    cr_lock = cr / ".lock"
    cr_lock.write_text("999999999", encoding="utf-8")  # dead pid
    lock = supervisor.acquire_lock(str(cr))
    supervisor.release_lock(lock)


def test_adapter_hard_failure_aborts_with_exit_2(tmp_path):
    cr = setup_control(tmp_path, "/bin/false")  # exits nonzero, no protocol output
    rc = supervisor.run(str(cr), None)
    assert rc == 2
    entries, _ = read_journal(cr)
    assert entries[-1]["state"] == "ABORTED_BUILD_ERROR"


def test_prompt_contains_spec_and_feedback_but_never_scenarios(tmp_path):
    cr = setup_control(tmp_path, FAKE)
    supervisor.run(str(cr), None)
    _, run_id = read_journal(cr)
    run_dir = cr / "runs" / run_id
    p1 = (run_dir / "prompt_iter_1.md").read_text(encoding="utf-8")
    p2 = (run_dir / "prompt_iter_2.md").read_text(encoding="utf-8")
    assert "greet.py" in p1 and MARKER not in p1
    assert "BHV-001" in p2 and MARKER not in p2  # iteration 2 carries ID feedback
    assert "Hello, <name>!" in p1  # spec text is fine — it is SHARED
```

- [ ] **Step 3: Run tests to verify they fail**

```bash
.venv/bin/python -m pytest dark-factory/tests/test_supervisor.py -v
```

Expected: FAIL — `ModuleNotFoundError: No module named 'supervisor'`.

- [ ] **Step 4: Implement `supervisor.py`**

`dark-factory/scripts/supervisor.py`:

```python
"""dark-factory supervisor: the sole state-changing entry point (spec 7.7).

M1 walking skeleton, cooperative tier only. FSM:
  INIT -> SNAPSHOT -> [BUILD -> VERIFY -> (FEEDBACK ->)]* ->
  CONVERGED -> COMPLETE_UNQUALIFIED | CAP_REACHED | ABORTED_BUILD_ERROR
"""
import argparse
import datetime
import json
import os
import subprocess
import sys
import uuid

from df_common import atomic_write, canonical_json, sha256_file, sha256_str
from df_config import ConfigError, load_config
from id_feedback import project_feedback
from run_scenarios import run_all
from snapshot_source import snapshot

BUILDER_RULES = """## Builder rules
- You are the BUILDER in a dark-factory run. Implement the specification below
  in the current working directory.
- Work ONLY inside this directory.
- Hidden acceptance scenarios exist; they are NOT visible to you. Do not try to
  find or read them. Verification feedback arrives only as behavior IDs plus a
  coarse failure taxonomy.
"""


class LockError(RuntimeError):
    pass


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def acquire_lock(control_root: str) -> str:
    path = os.path.join(control_root, ".lock")
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError:
        try:
            pid = int(open(path, encoding="utf-8").read().strip())
            os.kill(pid, 0)  # raises if dead
        except (ValueError, ProcessLookupError, PermissionError):
            sys.stderr.write(f"dark-factory: removing stale lock {path}\n")
            os.unlink(path)
            return acquire_lock(control_root)
        raise LockError(f"another invocation holds {path} (pid {pid})")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(str(os.getpid()))
    return path


def release_lock(lock_path: str) -> None:
    if os.path.exists(lock_path):
        os.unlink(lock_path)


class Journal:
    def __init__(self, path: str):
        self.path = path
        os.makedirs(os.path.dirname(path), exist_ok=True)

    def write(self, state: str, **data) -> None:
        line = canonical_json({"ts": _now(), "state": state, "data": data})
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
            f.flush()
            os.fsync(f.fileno())


def compose_prompt(spec_text: str, feedback) -> str:
    fb_block = (
        json.dumps(feedback, indent=2, sort_keys=True)
        if feedback is not None
        else "none — first iteration"
    )
    return (
        f"{BUILDER_RULES}\n## Specification\n{spec_text}\n"
        f"\n## Verification feedback (previous round; behavior IDs + taxonomy only)\n"
        f"{fb_block}\n"
    )


def invoke_adapter(adapter: str, role: str, workdir: str, prompt_file: str, timeout_s: int):
    req = {
        "adapter_protocol": "0.1",
        "role": role,
        "workdir": workdir,
        "prompt_file": prompt_file,
        "timeout_s": timeout_s,
    }
    try:
        proc = subprocess.run(
            [adapter], input=json.dumps(req), capture_output=True, text=True,
            timeout=timeout_s + 60,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError, OSError) as e:
        return None, f"adapter spawn failed: {e}"
    if proc.returncode != 0:
        return None, f"adapter exited {proc.returncode}: {proc.stderr[-500:]}"
    try:
        resp = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None, f"adapter wrote unparseable stdout: {proc.stdout[-500:]}"
    if resp.get("adapter_protocol") != "0.1":
        return None, "adapter protocol mismatch"
    return resp, None


def _scenario_set_hash(scenarios_dir: str) -> str:
    files = {
        name: sha256_file(os.path.join(scenarios_dir, name))
        for name in sorted(os.listdir(scenarios_dir))
        if name.endswith(".json")
    }
    return sha256_str(canonical_json(files))


def run(control_root: str, project_src) -> int:
    control_root = os.path.abspath(control_root)
    try:
        cfg = load_config(control_root)
    except ConfigError as e:
        sys.stderr.write(f"dark-factory: config error: {e}\n")
        return 2

    lock = acquire_lock(control_root)
    try:
        return _run_locked(control_root, project_src, cfg)
    finally:
        release_lock(lock)


def _run_locked(control_root: str, project_src, cfg) -> int:
    invocation = _now().replace(":", "").replace("-", "") + "-" + uuid.uuid4().hex[:8]
    run_dir = os.path.join(control_root, "runs", invocation)
    os.makedirs(run_dir, exist_ok=True)
    journal = Journal(os.path.join(run_dir, "journal.jsonl"))

    if not cfg["_qualified"]:
        sys.stderr.write(
            "dark-factory: COOPERATIVE MODE — unqualified: no probe-proven "
            "isolation; outcome can never be a qualified ship-candidate.\n"
        )

    spec_path = os.path.join(control_root, "spec.md")
    if not os.path.exists(spec_path):
        sys.stderr.write(f"dark-factory: missing spec: {spec_path}\n")
        return 2
    spec_text = open(spec_path, encoding="utf-8").read()
    scenarios_dir = os.path.join(control_root, "scenarios")
    if not os.path.isdir(scenarios_dir) or not any(
        n.endswith(".json") for n in os.listdir(scenarios_dir)
    ):
        sys.stderr.write(f"dark-factory: no scenarios in {scenarios_dir}\n")
        return 2
    adapter = cfg["roles"]["builder"]["adapter"]
    timeout_s = cfg["roles"]["builder"].get("timeout_s", 600)

    journal.write(
        "INIT",
        invocation=invocation,
        tier=cfg["assurance"],
        qualified=cfg["_qualified"],
        config_sha256=cfg["_config_sha256"],
        spec_sha256=sha256_str(spec_text),
        scenario_set_sha256=_scenario_set_hash(scenarios_dir),
        adapter=adapter,
        adapter_sha256=sha256_file(adapter) if os.path.exists(adapter) else None,
    )

    workspace = os.path.join(cfg["workspace_root"], invocation)
    if project_src:
        manifest, snap_hash = snapshot(project_src, workspace)
    else:
        os.makedirs(workspace, exist_ok=True)
        manifest, snap_hash = {"manifest_version": "0.1", "files": []}, sha256_str(
            canonical_json({"manifest_version": "0.1", "files": []})
        )
    atomic_write(os.path.join(workspace, "spec.md"), spec_text)
    journal.write("SNAPSHOT", workspace=workspace, snapshot_sha256=snap_hash,
                  file_count=len(manifest["files"]))

    feedback = None
    converged = False
    last_report = None
    for i in range(1, cfg["max_iterations"] + 1):
        prompt = compose_prompt(spec_text, feedback)
        prompt_file = os.path.join(run_dir, f"prompt_iter_{i}.md")
        atomic_write(prompt_file, prompt)
        resp, err = invoke_adapter(adapter, "builder", workspace, prompt_file, timeout_s)
        if err or resp["status"] != "ok":
            journal.write("ABORTED_BUILD_ERROR", iteration=i,
                          detail=err or resp.get("detail", ""))
            sys.stderr.write(f"dark-factory: build error at iteration {i}\n")
            return 2
        journal.write("BUILD", iteration=i)

        report = run_all(scenarios_dir, workspace)
        last_report = report
        atomic_write(
            os.path.join(run_dir, f"verifier_report_iter_{i}.json"),
            canonical_json(report),
        )
        passing = sum(1 for r in report["results"] if r["pass"])
        journal.write("VERIFY", iteration=i, passing=passing,
                      total=len(report["results"]))

        if report["all_pass"]:
            journal.write("CONVERGED", iteration=i)
            converged = True
            break

        feedback = project_feedback(report)
        atomic_write(
            os.path.join(run_dir, f"feedback_iter_{i}.json"), canonical_json(feedback)
        )
        atomic_write(os.path.join(workspace, "feedback.json"), canonical_json(feedback))
        journal.write("FEEDBACK", iteration=i,
                      failing=[f["behavior_id"] for f in feedback["failures"]])

    if converged:
        journal.write(
            "COMPLETE_UNQUALIFIED",
            note="cooperative tier cannot produce a qualified ship-candidate",
            workspace=workspace,
        )
        print(f"dark-factory: CONVERGED (unqualified, cooperative tier). "
              f"Workspace: {workspace}  Run: {run_dir}")
        return 0

    failing = sorted(
        {r["behavior_id"] for r in last_report["results"] if not r["pass"]}
    )
    journal.write("CAP_REACHED", failing_behaviors=failing,
                  note="likely spec ambiguity — human decision needed")
    print(f"dark-factory: CAP REACHED after {cfg['max_iterations']} iterations. "
          f"Still failing: {', '.join(failing)}. Likely spec ambiguity — "
          f"human decision needed. Run: {run_dir}")
    return 3


def main():
    ap = argparse.ArgumentParser(prog="dark-factory supervisor")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p_run = sub.add_parser("run", help="execute the build/verify loop")
    p_run.add_argument("--control-root", required=True)
    p_run.add_argument("--project-src", default=None)
    args = ap.parse_args()
    if args.cmd == "run":
        sys.exit(run(args.control_root, args.project_src))


if __name__ == "__main__":
    main()
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
.venv/bin/python -m pytest dark-factory/tests/test_supervisor.py -v
```

Expected: 6 passed.

- [ ] **Step 6: Commit**

```bash
git add dark-factory/scripts/supervisor.py dark-factory/tests/fixtures/fake_builder_stubborn dark-factory/tests/test_supervisor.py
git commit -m "feat(dark-factory): supervisor FSM with lock, journal, and build/verify loop

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 8: Audit manifest + verify command

**Files:**
- Modify: `dark-factory/scripts/supervisor.py` (add manifest finalization + `verify-manifest` subcommand)
- Test: `dark-factory/tests/test_manifest.py`

**Interfaces:**
- Consumes: journal + run artifacts from Task 7.
- Produces:
  - `supervisor.finalize_manifest(run_dir: str, extra: dict) -> str` — writes `manifest.json` (canonical) + `manifest.sha256` sidecar; manifest fields: `manifest_version` ("0.1"), `invocation`, `outcome`, `iterations` (int), `tier`, `qualified`, `config_sha256`, `spec_sha256`, `scenario_set_sha256`, `snapshot_sha256`, `adapter_sha256`, `journal_sha256`, `finished_ts`. Returns the manifest hash.
  - `supervisor.verify_manifest(run_dir: str) -> bool` — recomputes `manifest.json`'s hash against the sidecar AND the journal file's hash against `journal_sha256`; prints `OK` / `TAMPERED`.
  - CLI: `python3 supervisor.py verify-manifest --run-dir RD` → exit 0 (OK) / 4 (tampered/missing).
  - `run()` calls `finalize_manifest` on every terminal state (converged, cap, abort). **Honesty note (goes in the code docstring): a local process that can rewrite both files can defeat this — tamper-evidence with a real trust anchor is `hardened`+ (spec §7.5).**

- [ ] **Step 1: Write the failing tests**

`dark-factory/tests/test_manifest.py`:

```python
import json
import os
import subprocess
import sys

import supervisor
from test_supervisor import FAKE, setup_control  # reuse Task 7 helpers

SUP = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "scripts", "supervisor.py"
)


def run_and_get_run_dir(tmp_path):
    cr = setup_control(tmp_path, FAKE)
    assert supervisor.run(str(cr), None) == 0
    run_id = os.listdir(cr / "runs")[0]
    return str(cr / "runs" / run_id)


def test_manifest_written_on_completion(tmp_path):
    rd = run_and_get_run_dir(tmp_path)
    m = json.load(open(os.path.join(rd, "manifest.json"), encoding="utf-8"))
    assert m["manifest_version"] == "0.1"
    assert m["outcome"] == "COMPLETE_UNQUALIFIED"
    assert m["qualified"] is False and m["tier"] == "cooperative"
    assert m["iterations"] == 2
    for key in ("config_sha256", "spec_sha256", "scenario_set_sha256",
                "snapshot_sha256", "journal_sha256"):
        assert len(m[key]) == 64
    assert os.path.exists(os.path.join(rd, "manifest.sha256"))


def test_verify_manifest_ok(tmp_path):
    rd = run_and_get_run_dir(tmp_path)
    assert supervisor.verify_manifest(rd) is True


def test_verify_manifest_detects_manifest_edit(tmp_path):
    rd = run_and_get_run_dir(tmp_path)
    p = os.path.join(rd, "manifest.json")
    m = json.load(open(p, encoding="utf-8"))
    m["outcome"] = "QUALIFIED_SHIP_CANDIDATE"
    open(p, "w", encoding="utf-8").write(json.dumps(m))
    assert supervisor.verify_manifest(rd) is False


def test_verify_manifest_detects_journal_edit(tmp_path):
    rd = run_and_get_run_dir(tmp_path)
    jp = os.path.join(rd, "journal.jsonl")
    with open(jp, "a", encoding="utf-8") as f:
        f.write('{"ts":"later","state":"FORGED","data":{}}\n')
    assert supervisor.verify_manifest(rd) is False


def test_verify_manifest_cli_exit_codes(tmp_path):
    rd = run_and_get_run_dir(tmp_path)
    ok = subprocess.run([sys.executable, SUP, "verify-manifest", "--run-dir", rd],
                        capture_output=True, text=True)
    assert ok.returncode == 0 and "OK" in ok.stdout
    with open(os.path.join(rd, "journal.jsonl"), "a", encoding="utf-8") as f:
        f.write("tamper\n")
    bad = subprocess.run([sys.executable, SUP, "verify-manifest", "--run-dir", rd],
                         capture_output=True, text=True)
    assert bad.returncode == 4 and "TAMPERED" in bad.stdout
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
.venv/bin/python -m pytest dark-factory/tests/test_manifest.py -v
```

Expected: FAIL — `AttributeError: module 'supervisor' has no attribute 'verify_manifest'` (and missing manifest.json).

- [ ] **Step 3: Implement manifest finalization in `supervisor.py`**

Add to `dark-factory/scripts/supervisor.py` (after the `Journal` class):

```python
def finalize_manifest(run_dir: str, extra: dict) -> str:
    """Write manifest.json + manifest.sha256 sidecar.

    HONESTY (spec 7.5, cooperative/standard tier): a local process that can
    rewrite both files can defeat this. It detects accidental edits and
    casual tampering only; a signed chain / off-box anchor is hardened+.
    """
    journal_path = os.path.join(run_dir, "journal.jsonl")
    manifest = dict(extra)
    manifest["manifest_version"] = "0.1"
    manifest["journal_sha256"] = sha256_file(journal_path)
    manifest["finished_ts"] = _now()
    text = canonical_json(manifest)
    atomic_write(os.path.join(run_dir, "manifest.json"), text)
    digest = sha256_str(text)
    atomic_write(os.path.join(run_dir, "manifest.sha256"), digest + "\n")
    return digest


def verify_manifest(run_dir: str) -> bool:
    mp = os.path.join(run_dir, "manifest.json")
    sp = os.path.join(run_dir, "manifest.sha256")
    jp = os.path.join(run_dir, "journal.jsonl")
    if not (os.path.exists(mp) and os.path.exists(sp) and os.path.exists(jp)):
        print("TAMPERED (missing manifest, sidecar, or journal)")
        return False
    text = open(mp, encoding="utf-8").read()
    if sha256_str(text) != open(sp, encoding="utf-8").read().strip():
        print("TAMPERED (manifest.json does not match manifest.sha256)")
        return False
    manifest = json.loads(text)
    if sha256_file(jp) != manifest.get("journal_sha256"):
        print("TAMPERED (journal.jsonl does not match manifest)")
        return False
    print("OK")
    return True
```

Wire it into `_run_locked` — collect the shared fields once after the `INIT` journal write:

```python
    manifest_base = {
        "invocation": invocation,
        "tier": cfg["assurance"],
        "qualified": cfg["_qualified"],
        "config_sha256": cfg["_config_sha256"],
        "spec_sha256": sha256_str(spec_text),
        "scenario_set_sha256": _scenario_set_hash(scenarios_dir),
        "adapter_sha256": sha256_file(adapter) if os.path.exists(adapter) else None,
    }
```

Then set `manifest_base["snapshot_sha256"] = snap_hash` right after the `SNAPSHOT` journal write, and finalize at each terminal:

- In the `ABORTED_BUILD_ERROR` branch, before `return 2`:
  `finalize_manifest(run_dir, dict(manifest_base, outcome="ABORTED_BUILD_ERROR", iterations=i))`
- In the converged branch, before `return 0`:
  `finalize_manifest(run_dir, dict(manifest_base, outcome="COMPLETE_UNQUALIFIED", iterations=i))`
- In the cap branch, before `return 3`:
  `finalize_manifest(run_dir, dict(manifest_base, outcome="CAP_REACHED", iterations=cfg["max_iterations"]))`

(Note: in the converged branch `i` is still bound to the converging iteration.)

And extend `main()` with the subcommand:

```python
    p_ver = sub.add_parser("verify-manifest", help="check a run's audit manifest")
    p_ver.add_argument("--run-dir", required=True)
```

and in the dispatch:

```python
    elif args.cmd == "verify-manifest":
        sys.exit(0 if verify_manifest(args.run_dir) else 4)
```

- [ ] **Step 4: Run the new tests AND the full suite (regression check)**

```bash
.venv/bin/python -m pytest dark-factory/tests -v
```

Expected: all tests pass (Tasks 1–8; 5 new manifest tests included).

- [ ] **Step 5: Commit**

```bash
git add dark-factory/scripts/supervisor.py dark-factory/tests/test_manifest.py
git commit -m "feat(dark-factory): hashed audit manifest with verify-manifest command

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 9: End-to-end invariant test (the point of the whole milestone)

**Files:**
- Test: `dark-factory/tests/test_e2e_loop.py`

**Interfaces:**
- Consumes: everything — drives `supervisor.py` as a subprocess exactly the way a user would.
- Produces: executable proof of the dark-factory invariant (spec §14 success criterion 1, M1 form): the builder converged against scenarios it **demonstrably never saw** — no scenario text in the workspace, prompts, feedback, or supervisor stdout.

- [ ] **Step 1: Write the failing test**

`dark-factory/tests/test_e2e_loop.py`:

```python
"""M1 acceptance: the walking-skeleton loop converges WITHOUT the builder
ever seeing the holdout. Scenario titles/givens carry a unique MARKER string;
we assert the marker never appears anywhere the builder could look."""
import json
import os
import subprocess
import sys

from test_supervisor import FAKE, MARKER, setup_control

SUP = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "scripts", "supervisor.py"
)


def walk_files(root):
    for dirpath, _, filenames in os.walk(root):
        for name in filenames:
            yield os.path.join(dirpath, name)


def test_e2e_converges_and_never_leaks_holdout(tmp_path):
    cr = setup_control(tmp_path, FAKE)
    ws_root = tmp_path / "ws"

    proc = subprocess.run(
        [sys.executable, SUP, "run", "--control-root", str(cr)],
        capture_output=True, text=True, timeout=120,
    )
    assert proc.returncode == 0, proc.stderr

    # 1. It converged: the built artifact actually implements the spec.
    run_id = os.listdir(cr / "runs")[0]
    run_dir = cr / "runs" / run_id
    workspace = None
    for entry in json.loads("[" + ",".join(
        (run_dir / "journal.jsonl").read_text(encoding="utf-8").strip().splitlines()
    ) + "]"):
        if entry["state"] == "SNAPSHOT":
            workspace = entry["data"]["workspace"]
    assert workspace is not None
    out = subprocess.run(["python3", "greet.py", "Alon"], cwd=workspace,
                         capture_output=True, text=True)
    assert out.stdout.strip() == "Hello, Alon!"

    # 2. THE INVARIANT: no holdout content anywhere the builder could look.
    #    (a) not in the workspace filesystem
    for path in walk_files(workspace):
        with open(path, "rb") as f:
            assert MARKER.encode() not in f.read(), f"holdout leaked into {path}"
    #    (b) no scenarios directory materialized in the workspace
    assert not os.path.exists(os.path.join(workspace, "scenarios"))
    #    (c) not in any builder prompt
    for name in os.listdir(run_dir):
        if name.startswith("prompt_iter_"):
            text = (run_dir / name).read_text(encoding="utf-8")
            assert MARKER not in text, f"holdout leaked into {name}"
    #    (d) not in any feedback file, and feedback is schema-clean
    import id_feedback
    for name in os.listdir(run_dir):
        if name.startswith("feedback_iter_"):
            fb = json.loads((run_dir / name).read_text(encoding="utf-8"))
            id_feedback.validate_feedback(fb)
            assert MARKER not in json.dumps(fb)
    #    (e) not in supervisor stdout/stderr
    assert MARKER not in proc.stdout and MARKER not in proc.stderr

    # 3. The audit chain verifies.
    ver = subprocess.run(
        [sys.executable, SUP, "verify-manifest", "--run-dir", str(run_dir)],
        capture_output=True, text=True,
    )
    assert ver.returncode == 0

    # 4. Honesty: the run is explicitly unqualified (cooperative tier).
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["qualified"] is False
    assert manifest["outcome"] == "COMPLETE_UNQUALIFIED"
    assert "COOPERATIVE MODE" in proc.stderr
```

- [ ] **Step 2: Run the test**

```bash
.venv/bin/python -m pytest dark-factory/tests/test_e2e_loop.py -v
```

Expected: PASS if Tasks 1–8 are correct. If it fails, the failure message names exactly which invariant broke — fix the responsible module (this test writes no new production code; treat any failure as a real defect in an earlier task and fix it there, keeping its unit tests green).

- [ ] **Step 3: Run the full suite one more time**

```bash
.venv/bin/python -m pytest dark-factory/tests -v
```

Expected: all tests pass.

- [ ] **Step 4: Commit**

```bash
git add dark-factory/tests/test_e2e_loop.py
git commit -m "test(dark-factory): e2e invariant test — builder converges without seeing the holdout

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 10: SKILL.md front end, README, install, and a real-claude smoke run

**Files:**
- Create: `dark-factory/SKILL.md`
- Modify: `README.md` (repo root — add the dark-factory section)

**Interfaces:**
- Consumes: everything shipped in Tasks 1–9.
- Produces: the user-facing skill entry point; the `~/.claude/skills/dark-factory` symlink; a human-observed smoke run with the real claude adapter.

- [ ] **Step 1: Write `dark-factory/SKILL.md`**

```markdown
---
name: dark-factory
description: Use when the user wants to build a task/feature "dark-factory style" — the human writes a spec, an isolated builder agent implements it WITHOUT ever seeing the hidden acceptance scenarios, a verifier runs those scenarios, and only behavior-ID + failure-taxonomy feedback crosses back until convergence. Triggers on "dark factory", "dark-factory", "hidden tests", "holdout scenarios", "build without seeing the tests", or requests to prevent an AI builder from teaching to the test. M1 walking skeleton: cooperative tier only (honor-system isolation, honestly unqualified).
---

# dark-factory (M1 walking skeleton)

Runs a StrongDM-style dark-factory loop: **spec in → hidden holdout scenarios
→ isolated builder (spec-only) → verifier → deterministic ID feedback → loop →
outcome**. Design spec: `docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md`
(Codex-approved). This milestone ships the **cooperative tier only**: isolation
is honor-system (no OS read-denial yet — that is M2), so every run is
explicitly **UNQUALIFIED** and can never claim a probe-proven barrier.

## Workflow (create one todo per step)

1. **Engage.** Announce the skill; offer opt-out. Ask which directory to use as
   the control root (MUST be outside the project repo and outside any workspace
   tree; suggest `~/.dark-factory/<project-name>`).
2. **Spec.** Interview the user → write `<control_root>/spec.md`. The user
   approves it. Behaviors should be numbered (BHV-001, BHV-002, …).
3. **Acceptance world — SEPARATE CONTEXT.** Author the holdout scenarios in
   `<control_root>/scenarios/*.json` (oracle IR v0 — see
   `references/scenario-format.md`) **in a different session/subagent than any
   builder work**, deriving them ONLY from spec.md. Never echo scenario content
   into the main conversation if the same conversation will drive the builder.
4. **Config.** Write `<control_root>/config.json` per
   `references/config-reference.md` (assurance MUST be `cooperative` in M1;
   builder adapter: `<skill_dir>/scripts/adapters/claude`).
5. **Run.** `python3 <skill_dir>/scripts/supervisor.py run --control-root <control_root> [--project-src <dir>]`
   Exit 0 = converged (unqualified) · 3 = cap reached (likely spec ambiguity —
   show the failing behavior IDs and ask the user) · 2 = config/build error.
6. **Report.** Show the user: outcome, iterations, per-behavior status from the
   run's `journal.jsonl`, the workspace path, and
   `supervisor.py verify-manifest --run-dir <run_dir>` output. State plainly
   that the cooperative tier is unqualified.

## Hard rules

- Scenario files and their content NEVER enter: the builder prompt, the
  workspace, the main builder-driving conversation, or any feedback.
- Only the supervisor writes run state. Do not hand-edit `runs/`.
- Secrets: never put credentials in config.json/spec.md/scenarios; the claude
  adapter uses your ambient login.
- This milestone cannot produce a qualified ship-candidate. Say so.

## References

- `references/config-reference.md` — config schema
- `references/scenario-format.md` — oracle IR v0
- `references/role-adapters.md` — adapter protocol
```

- [ ] **Step 2: Add the README section**

Append to `README.md` after the loop-designer section:

```markdown
## dark-factory

Runs a StrongDM-style "dark factory" loop: you write a spec, an isolated
builder agent implements it without ever seeing the hidden acceptance
scenarios, a verifier runs them, and only behavior-ID feedback crosses back
until convergence. M1 = walking skeleton (cooperative tier, honestly
unqualified isolation).

- Skill: [`dark-factory/SKILL.md`](dark-factory/SKILL.md)
- Design spec: [`docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md`](docs/superpowers/specs/2026-07-13-dark-factory-skill-design.md)
- Adversarial review log: [`docs/superpowers/specs/2026-07-13-dark-factory-review-log.md`](docs/superpowers/specs/2026-07-13-dark-factory-review-log.md)
- Tests: `.venv/bin/python -m pytest dark-factory/tests -v`

### Install / update

```
ln -sfn "$PWD/dark-factory" ~/.claude/skills/dark-factory
```
```

- [ ] **Step 3: Install the symlink and run the full suite**

```bash
ln -sfn "/Users/alonadelson/Projects/ai_projects/skills/dark-factory" ~/.claude/skills/dark-factory
ls -l ~/.claude/skills/dark-factory
.venv/bin/python -m pytest dark-factory/tests -v
```

Expected: symlink points into the repo; all tests pass.

- [ ] **Step 4: Real-claude smoke run (human-observed, not CI)**

Set up a real toy run in the scratchpad and watch the loop with the actual claude CLI as builder:

```bash
SCRATCH=/private/tmp/claude-501/-Users-alonadelson-Projects-ai-projects-skills/26a52c7c-b9e1-49e1-a8f5-c926b8ef727d/scratchpad
CR=$SCRATCH/df-smoke/control
mkdir -p "$CR/scenarios"
cat > "$CR/spec.md" <<'EOF'
# greet CLI
Create an executable python file `greet.py` in the workspace root.
- BHV-001: `python3 greet.py <name>` prints exactly `Hello, <name>!` and exits 0.
- BHV-002: `python3 greet.py` with no arguments prints `usage: greet.py <name>` to stderr and exits 2.
EOF
cat > "$CR/config.json" <<EOF
{
  "config_version": "0.1", "autonomy": 4, "assurance": "cooperative",
  "feedback": "ids", "max_iterations": 3,
  "workspace_root": "$SCRATCH/df-smoke/ws",
  "roles": {"builder": {"adapter": "/Users/alonadelson/Projects/ai_projects/skills/dark-factory/scripts/adapters/claude", "timeout_s": 300}},
  "budget": {"billing": "subscription"}
}
EOF
cat > "$CR/scenarios/s1.json" <<'EOF'
{"ir_version":"0.1","id":"BHV-001-S1","behavior_id":"BHV-001","title":"greets by name","given":"built workspace","when":{"run":["python3","greet.py","World"],"timeout_s":10},"then":{"exit_code":0,"stdout_equals":"Hello, World!"}}
EOF
cat > "$CR/scenarios/s2.json" <<'EOF'
{"ir_version":"0.1","id":"BHV-002-S1","behavior_id":"BHV-002","title":"usage error","given":"built workspace","when":{"run":["python3","greet.py"],"timeout_s":10},"then":{"exit_code":2,"stderr_contains":"usage:"}}
EOF
python3 /Users/alonadelson/Projects/ai_projects/skills/dark-factory/scripts/supervisor.py run --control-root "$CR"
```

Expected: the COOPERATIVE MODE warning on stderr, then `dark-factory: CONVERGED (unqualified, cooperative tier)` — usually in 1 iteration since real claude reads the spec correctly. Then verify the audit:

```bash
RUN_DIR=$(ls -d "$CR"/runs/* | head -1)
python3 /Users/alonadelson/Projects/ai_projects/skills/dark-factory/scripts/supervisor.py verify-manifest --run-dir "$RUN_DIR"
grep -r "greets by name" "$SCRATCH/df-smoke/ws" && echo "LEAK!" || echo "no holdout leak in workspace"
```

Expected: `OK`, then `no holdout leak in workspace`. **Show this output to the user** — it is the human-observed acceptance of M1.

- [ ] **Step 5: Commit**

```bash
git add dark-factory/SKILL.md README.md
git commit -m "feat(dark-factory): SKILL.md front end, README, and install symlink

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

## Self-Review Notes (plan ↔ spec)

**Covered by this plan (M1 slice):** two non-negotiables (scenarios as behavioral holdout; builder never receives them — honor-system at `cooperative`, with the e2e test proving non-exposure through the skill's own channels); deterministic `ids` feedback (§6.1); tier registry + fail-closed rejection of unbacked tiers (§2.3); `cooperative` = unqualified, `COMPLETE_UNQUALIFIED` outcome (§2.2); disjoint control/workspace roots (§11); lstat snapshot (§7.1); supervisor as sole state-changer with lock + journal (§7.7); adapter protocol 0.1, no silent fallback (§7.8); oracle IR 0.1 as the versioned seam (§5.1); cap → "likely spec ambiguity" surfacing (§6); hashed local audit manifest + verify, with stated honesty limits (§7.5).

**Deliberately deferred (later milestone plans, per §15):** OS read-denial + denial probes + `standard` tier (M2); dev/final holdout split, freeze-ordering, coverage gate, mutation validation (M2); mandatory security gates (M2); digital twins + fidelity (M3); Codex/Gemini adapters, skill allowlist, KB integration (M4); container sandbox, credential broker, signed audit, network authority (M5). The `supported_tiers` registry makes this deferral honest at runtime, not just on paper.

**Known M1 honesty notes (stated in code/docs, not hidden):** manifest tamper-evidence is casual-only; builder isolation is honor-system; taxonomy is coarse by design; `budget` is recorded but not enforced (subscription/alert-only mode).
