# dark-factory M4b — Skill Composition + Knowledge Base Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Finish M4's original scope by adding the two deferred axes: (1) optional **knowledge-base integration** — a real, barrier-safe wiki run-summary write-back plus the engage-time "do you have a wiki / open-brain?" ask; and (2) **control-plane skill composition** — documented guidance for delegating the orchestration steps (spec authoring, stuck-loop debugging, cleanup) to other skills without ever touching the holdout.

**Architecture — the honest boundary:** dark-factory's *builder* is an external CLI (claude/codex/gemini) run in an OS-sandboxed workspace; it loads no skills. So "skill composition" (spec §3B) applies only to the **control plane** — the Claude session running `SKILL.md` — which delegates its *own* steps (spec → brainstorming/grill-me-codex; stuck loop → systematic-debugging; accepted-artifact cleanup → /simplify or code-review). The barrier is trivially preserved: those delegations happen *around* the sandboxed builder, never inside it, and the scenario-authoring rule (separate session, never echoed to a builder-driving session) is unchanged. **Enforced** per-tier skill allowlists with content-hash pinning (spec §3B, M2b-review finding) require the orchestrator itself to run sandboxed — that is a `hardened`/`enterprise` capability, so at `cooperative`/`standard` composition is honor-system guidance, stated as such. KB integration is concrete: a `knowledge_base` config block + a `df_kb.py` wiki write-back that appends only barrier-safe run metadata (outcome, tier, qualified, iterations, failing behavior IDs — never scenario text). open-brain (MCP) is a Claude-session opt-in the supervisor can't perform, so it's workflow guidance, not supervisor code.

**Tech Stack:** Python ≥ 3.9 stdlib only at runtime. pytest for tests. No new deps.

**Source spec:** `…/2026-07-13-dark-factory-skill-design.md` §3A (optional KB, opt-in write-back), §3B (skill composition, barrier-respecting, per-tier allowlist), §9. This completes the M4 "cross-model + composition + KB" milestone (cross-model shipped in M4).

## Global Constraints

- **Runtime code is Python stdlib only.** Tests run `.venv/bin/python -m pytest dark-factory/tests -v` from repo root `/Users/alonadelson/Projects/ai_projects/skills`.
- **KB write-back is barrier-safe by construction:** the wiki run summary contains ONLY `when`, `outcome`, `tier`, `qualified`, `iterations`, and a list of failing **behavior IDs** (`^BHV-[A-Za-z0-9-]{1,32}$`). It NEVER contains scenario title/given/when/then, observed stdout/stderr, prompt text, or the marker string. A `no-leak` test asserts a planted MARKER never appears.
- **Write-back is opt-in** (`knowledge_base.write_back: true`) and defaults off. Absence of a KB is never an error and never blocks a run.
- **KB is optional and self-contained:** no run depends on a wiki/open-brain existing.
- **No config regressions:** the `knowledge_base` block is optional; existing configs without it still validate.
- **Commit messages end with:** `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`.

## File Structure

```
dark-factory/
  scripts/
    df_config.py                # Task 1 — validate + inject knowledge_base as cfg["_kb"]
    df_kb.py                    # Task 2 — barrier-safe wiki run-summary write-back
    supervisor.py               # Task 3 — call df_kb at each terminal when opted in
  references/
    config-reference.md         # Task 1 — knowledge_base rows
    knowledge-base.md           # Task 4 — KB integration + skill-composition guidance
  SKILL.md                      # Task 4 — engage KB ask + control-plane composition section
  tests/
    test_kb_config.py           # Task 1
    test_df_kb.py               # Task 2
    test_kb_writeback.py        # Task 3
```

---

### Task 1: `knowledge_base` config field

**Files:**
- Modify: `dark-factory/scripts/df_config.py`
- Modify: `dark-factory/references/config-reference.md`
- Create: `dark-factory/tests/test_kb_config.py`

**Interfaces:**
- Consumes: existing `df_config.load_config` structure (raises `ConfigError`; injects `cfg["_..."]` keys).
- Produces: `cfg["_kb"]` — a normalized dict `{"kind": "none"|"wiki"|"open-brain", "path": str, "write_back": bool}`. Rules: absent block → `{"kind":"none","path":"","write_back":False}`. `kind` must be one of the three. When `kind=="wiki"`: `path` required, must be an existing directory (else `ConfigError`). `write_back` must be a bool (default False). `open-brain` needs no path (MCP handled by the session, not the supervisor).

- [ ] **Step 1: Write the failing tests**

`dark-factory/tests/test_kb_config.py`:

```python
import json

import pytest

import df_config
from test_config import write_config  # reuse the existing helper


def test_absent_kb_defaults_to_none(tmp_path):
    cr = tmp_path / "control"
    write_config(cr)
    cfg = df_config.load_config(str(cr))
    assert cfg["_kb"] == {"kind": "none", "path": "", "write_back": False}


def test_wiki_kb_requires_existing_dir(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, knowledge_base={"kind": "wiki", "path": str(tmp_path / "nope")})
    with pytest.raises(df_config.ConfigError, match="wiki"):
        df_config.load_config(str(cr))


def test_wiki_kb_valid(tmp_path):
    wiki = tmp_path / "wiki"
    wiki.mkdir()
    cr = tmp_path / "control"
    write_config(cr, knowledge_base={"kind": "wiki", "path": str(wiki), "write_back": True})
    cfg = df_config.load_config(str(cr))
    assert cfg["_kb"] == {"kind": "wiki", "path": str(wiki), "write_back": True}


def test_open_brain_kb_needs_no_path(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, knowledge_base={"kind": "open-brain"})
    cfg = df_config.load_config(str(cr))
    assert cfg["_kb"]["kind"] == "open-brain" and cfg["_kb"]["write_back"] is False


def test_bad_kb_kind_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, knowledge_base={"kind": "notion"})
    with pytest.raises(df_config.ConfigError, match="knowledge_base"):
        df_config.load_config(str(cr))


def test_kb_write_back_must_be_bool(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, knowledge_base={"kind": "open-brain", "write_back": "yes"})
    with pytest.raises(df_config.ConfigError, match="write_back"):
        df_config.load_config(str(cr))
```

- [ ] **Step 2: Run to verify fail**

```bash
cd /Users/alonadelson/Projects/ai_projects/skills
.venv/bin/python -m pytest dark-factory/tests/test_kb_config.py -v
```
Expected: FAIL (`KeyError: '_kb'` / no validation).

- [ ] **Step 3: Implement in `df_config.py`**

Read `df_config.py`. After the existing checks and before `cfg = dict(raw)` (or before the final return, following the file's established pattern), add `knowledge_base` normalization+validation. Insert:

```python
    kb_raw = raw.get("knowledge_base", {})
    if not isinstance(kb_raw, dict):
        raise ConfigError("knowledge_base must be an object")
    kb_kind = kb_raw.get("kind", "none")
    if kb_kind not in ("none", "wiki", "open-brain"):
        raise ConfigError(
            f"knowledge_base.kind must be none|wiki|open-brain, got {kb_kind!r}"
        )
    kb_write_back = kb_raw.get("write_back", False)
    if not isinstance(kb_write_back, bool):
        raise ConfigError("knowledge_base.write_back must be a bool")
    kb_path = kb_raw.get("path", "")
    if kb_kind == "wiki":
        if not kb_path or not os.path.isdir(kb_path):
            raise ConfigError(
                f"knowledge_base kind 'wiki' requires 'path' to be an existing directory: {kb_path!r}"
            )
```

Then inject on the returned cfg (alongside the other `cfg["_..."]` injections):

```python
    cfg["_kb"] = {"kind": kb_kind, "path": kb_path, "write_back": kb_write_back}
```

(`os` is already imported in df_config.py.)

Add rows to `dark-factory/references/config-reference.md`:

```markdown
| `knowledge_base.kind` | str | optional: `none` (default) \| `wiki` \| `open-brain`. Enables optional grounding + opt-in run-summary write-back. |
| `knowledge_base.path` | str | required existing directory when kind=`wiki`; the run summary is appended to `<path>/dark-factory-runs.md`. |
| `knowledge_base.write_back` | bool | default false. When true + kind=`wiki`, the supervisor appends a barrier-safe run summary (outcome/tier/qualified/iterations/failing behavior IDs — no scenario text). `open-brain` write-back is done by the Claude session (MCP), not the supervisor. |
```

- [ ] **Step 4: Verify pass**

```bash
.venv/bin/python -m pytest dark-factory/tests/test_kb_config.py -v
.venv/bin/python -m pytest dark-factory/tests -q | tail -1   # 123 + 6 new = 129 passed, 1 skipped
```

- [ ] **Step 5: Commit**

```bash
git add dark-factory/scripts/df_config.py dark-factory/references/config-reference.md dark-factory/tests/test_kb_config.py
git commit -m "feat(dark-factory): optional knowledge_base config block

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 2: `df_kb.py` — barrier-safe wiki run-summary write-back

**Files:**
- Create: `dark-factory/scripts/df_kb.py`
- Create: `dark-factory/tests/test_df_kb.py`

**Interfaces:**
- Consumes: stdlib (`os`, `re`); the injected `cfg["_kb"]` shape from Task 1; a manifest dict (has `outcome`, `tier`, `qualified`, `iterations`, `invocation`, `finished_ts`).
- Produces:
  - `df_kb.KBLeakError(ValueError)`.
  - `df_kb.build_summary(manifest: dict, failing_behaviors: list[str]) -> str` — a markdown block with ONLY: `finished_ts`, `invocation`, `outcome`, `tier`, `qualified`, `iterations`, and the failing behavior IDs. Validates each behavior id against `^BHV-[A-Za-z0-9-]{1,32}$`; raises `KBLeakError` on anything else (defense against a caller passing raw text).
  - `df_kb.write_run_summary(kb: dict, manifest: dict, failing_behaviors: list[str]) -> str | None` — if `kb["kind"]=="wiki"` and `kb["write_back"]`, append `build_summary(...)` (preceded by a blank line) to `<kb["path"]>/dark-factory-runs.md` (create the file if absent) and return that path; otherwise return `None` (no-op for none/open-brain or write_back off).

- [ ] **Step 1: Write the failing tests**

`dark-factory/tests/test_df_kb.py`:

```python
import os

import pytest

import df_kb

MARKER = "HOLDOUT-MARKER-93e1"


def manifest(**over):
    m = {"invocation": "20260714T000000Z-abcd1234", "finished_ts": "2026-07-14T00:00:01Z",
         "outcome": "CAP_REACHED", "tier": "standard", "qualified": False, "iterations": 3}
    m.update(over)
    return m


def test_build_summary_contains_only_safe_fields():
    s = df_kb.build_summary(manifest(), ["BHV-002", "BHV-001"])
    assert "CAP_REACHED" in s and "standard" in s and "BHV-001" in s and "BHV-002" in s
    assert "20260714T000000Z-abcd1234" in s


def test_build_summary_rejects_non_behavior_id():
    with pytest.raises(df_kb.KBLeakError):
        df_kb.build_summary(manifest(), [f"expected {MARKER}"])


def test_write_run_summary_wiki_appends(tmp_path):
    wiki = tmp_path / "wiki"; wiki.mkdir()
    kb = {"kind": "wiki", "path": str(wiki), "write_back": True}
    p1 = df_kb.write_run_summary(kb, manifest(), ["BHV-001"])
    p2 = df_kb.write_run_summary(kb, manifest(outcome="COMPLETE_QUALIFIED", qualified=True), [])
    assert p1 == p2 == os.path.join(str(wiki), "dark-factory-runs.md")
    body = open(p1, encoding="utf-8").read()
    assert body.count("## dark-factory run") == 2  # appended, not overwritten
    assert "COMPLETE_QUALIFIED" in body


def test_write_run_summary_noop_when_disabled(tmp_path):
    wiki = tmp_path / "wiki"; wiki.mkdir()
    assert df_kb.write_run_summary({"kind": "wiki", "path": str(wiki), "write_back": False}, manifest(), []) is None
    assert df_kb.write_run_summary({"kind": "none", "path": "", "write_back": True}, manifest(), []) is None
    assert df_kb.write_run_summary({"kind": "open-brain", "path": "", "write_back": True}, manifest(), []) is None
    assert not (wiki / "dark-factory-runs.md").exists()


def test_write_run_summary_never_leaks_marker(tmp_path):
    wiki = tmp_path / "wiki"; wiki.mkdir()
    kb = {"kind": "wiki", "path": str(wiki), "write_back": True}
    # a manifest polluted with marker-bearing fields must not leak them into the wiki
    m = manifest(spec_sha256=MARKER, extra_note=f"secret {MARKER}")
    df_kb.write_run_summary(kb, m, ["BHV-001"])
    assert MARKER not in open(wiki / "dark-factory-runs.md", encoding="utf-8").read()
```

- [ ] **Step 2: Run to verify fail**

```bash
.venv/bin/python -m pytest dark-factory/tests/test_df_kb.py -v
```
Expected: FAIL (`ModuleNotFoundError: No module named 'df_kb'`).

- [ ] **Step 3: Implement `df_kb.py`**

`dark-factory/scripts/df_kb.py`:

```python
"""Barrier-safe knowledge-base write-back (spec 3A). Stdlib only.

Appends a run summary to a wiki file. The summary is built from an ALLOWLIST
of manifest fields plus failing behavior IDs — it structurally cannot carry
scenario text, observed output, or prompts, because it never reads them.
open-brain (MCP) write-back is performed by the Claude session, not here.
"""
import os
import re

BEHAVIOR_RE = re.compile(r"^BHV-[A-Za-z0-9-]{1,32}$")
_SUMMARY_FILE = "dark-factory-runs.md"


class KBLeakError(ValueError):
    pass


def build_summary(manifest: dict, failing_behaviors: list) -> str:
    for b in failing_behaviors:
        if not BEHAVIOR_RE.fullmatch(b):
            raise KBLeakError(f"failing_behaviors must be BHV ids only (offending value withheld)")
    failing = ", ".join(sorted(failing_behaviors)) if failing_behaviors else "none"
    return (
        f"## dark-factory run {manifest.get('finished_ts', '')}\n"
        f"- invocation: `{manifest.get('invocation', '')}`\n"
        f"- outcome: **{manifest.get('outcome', '')}**\n"
        f"- tier: {manifest.get('tier', '')}  qualified: {manifest.get('qualified', '')}\n"
        f"- iterations: {manifest.get('iterations', '')}\n"
        f"- failing behaviors: {failing}\n"
    )


def write_run_summary(kb: dict, manifest: dict, failing_behaviors: list):
    if kb.get("kind") != "wiki" or not kb.get("write_back"):
        return None
    path = os.path.join(kb["path"], _SUMMARY_FILE)
    with open(path, "a", encoding="utf-8") as f:
        f.write("\n" + build_summary(manifest, failing_behaviors))
    return path
```

- [ ] **Step 4: Verify pass**

```bash
.venv/bin/python -m pytest dark-factory/tests/test_df_kb.py -v
.venv/bin/python -m pytest dark-factory/tests -q | tail -1   # 135 passed, 1 skipped
```

- [ ] **Step 5: Commit**

```bash
git add dark-factory/scripts/df_kb.py dark-factory/tests/test_df_kb.py
git commit -m "feat(dark-factory): barrier-safe wiki run-summary write-back

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 3: Wire KB write-back into the supervisor terminals

**Files:**
- Modify: `dark-factory/scripts/supervisor.py`
- Create: `dark-factory/tests/test_kb_writeback.py`

**Interfaces:**
- Consumes: `df_kb.write_run_summary`, `cfg["_kb"]` (Task 1), and the per-terminal manifest already built by `finalize_manifest` (Task 8/M2b). Failing behavior IDs are available at terminals: the CAP terminal computes a `failing` list; converged/accepted → `[]`; aborted/build-error → `[]` (or the last-known failing set if cheaply available — otherwise `[]`).
- Produces: after `finalize_manifest(...)` at EACH terminal, when `cfg["_kb"]["kind"] == "wiki"` and `write_back`, call `df_kb.write_run_summary(cfg["_kb"], <the manifest dict just finalized>, failing_list)` and journal a `KB_WRITEBACK` line with the returned path (or skip silently if None). A write-back failure (OSError) must NOT crash the run — wrap in try/except, journal `KB_WRITEBACK_ERROR`, continue. **KB write-back never changes the exit code.**

Read the current `supervisor.py` first — `finalize_manifest` returns the manifest hash, not the dict, so capture the manifest dict you pass in (each terminal already builds `dict(manifest_base, outcome=..., iterations=...)`). Add `import df_kb` at top. Implement a small local helper `_kb_writeback(cfg, journal, manifest_dict, failing)` that does the guarded call + journaling, and invoke it right after each `finalize_manifest` call.

- [ ] **Step 1: Write the failing tests**

`dark-factory/tests/test_kb_writeback.py`:

```python
import json
import os

import supervisor
from test_supervisor import FAKE, STUBBORN, setup_control  # existing helpers


def _wiki_cfg(tmp_path, adapter, wiki, **over):
    cr = setup_control(tmp_path, adapter, checkpoint="auto", **over)
    cfg = json.loads((cr / "config.json").read_text())
    cfg["knowledge_base"] = {"kind": "wiki", "path": str(wiki), "write_back": True}
    (cr / "config.json").write_text(json.dumps(cfg))
    return cr


def test_converged_run_appends_wiki_summary(tmp_path):
    wiki = tmp_path / "wiki"; wiki.mkdir()
    cr = _wiki_cfg(tmp_path, FAKE, wiki)
    assert supervisor.run(str(cr), None) == 0
    body = (wiki / "dark-factory-runs.md").read_text(encoding="utf-8")
    assert "## dark-factory run" in body and "failing behaviors: none" in body


def test_cap_run_appends_failing_behaviors(tmp_path):
    wiki = tmp_path / "wiki"; wiki.mkdir()
    cr = _wiki_cfg(tmp_path, STUBBORN, wiki, max_iterations=2)
    assert supervisor.run(str(cr), None) == 3
    body = (wiki / "dark-factory-runs.md").read_text(encoding="utf-8")
    assert "CAP_REACHED" in body and "BHV-001" in body


def test_no_writeback_when_disabled(tmp_path):
    wiki = tmp_path / "wiki"; wiki.mkdir()
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")  # no knowledge_base block
    assert supervisor.run(str(cr), None) == 0
    assert not (wiki / "dark-factory-runs.md").exists()


def test_writeback_failure_does_not_crash_run(tmp_path):
    # point the wiki at a dir, then make the summary file unwritable by removing the dir mid-config:
    wiki = tmp_path / "wiki"; wiki.mkdir()
    cr = _wiki_cfg(tmp_path, FAKE, wiki)
    os.chmod(wiki, 0o500)  # read+exec only → append fails
    try:
        rc = supervisor.run(str(cr), None)
    finally:
        os.chmod(wiki, 0o700)
    assert rc == 0  # KB failure never changes the exit code
    run_id = os.listdir(cr / "runs")[0]
    journal = (cr / "runs" / run_id / "journal.jsonl").read_text()
    assert "KB_WRITEBACK_ERROR" in journal
```

(If `STUBBORN` is not exported by test_supervisor, use the module-level fixture path the way the existing cap test does; check test_supervisor.py for the exact name.)

- [ ] **Step 2: Run to verify fail**

```bash
.venv/bin/python -m pytest dark-factory/tests/test_kb_writeback.py -v
```
Expected: FAIL (no write-back yet).

- [ ] **Step 3: Implement the wiring in `supervisor.py`**

Add `import df_kb` with the other imports. Add the helper near `finalize_manifest`:

```python
def _kb_writeback(cfg, journal, manifest_dict, failing):
    kb = cfg.get("_kb", {"kind": "none"})
    if kb.get("kind") != "wiki" or not kb.get("write_back"):
        return
    try:
        path = df_kb.write_run_summary(kb, manifest_dict, failing)
        if path:
            journal.write("KB_WRITEBACK", path=path)
    except (OSError, df_kb.KBLeakError) as e:
        journal.write("KB_WRITEBACK_ERROR", detail=str(e))
```

At EACH terminal, capture the manifest dict and call the helper after `finalize_manifest`. For example the CONVERGED terminal:

```python
        mf = dict(manifest_base, outcome="COMPLETE_QUALIFIED" if ... else "COMPLETE_UNQUALIFIED", iterations=i)
        finalize_manifest(run_dir, mf)
        _clear_state(run_dir)
        _kb_writeback(cfg, journal, mf, [])
```

Do the same at CAP (`failing` = the computed failing list), and at each ABORTED terminal and the resume terminals (`failing=[]` unless a failing list is already in scope). Keep the manifest dict you already build; don't recompute. **Ensure the exit code is returned exactly as before** — `_kb_writeback` returns None and never affects control flow.

- [ ] **Step 4: Verify pass + full regression**

```bash
.venv/bin/python -m pytest dark-factory/tests/test_kb_writeback.py -v
.venv/bin/python -m pytest dark-factory/tests -q | tail -1   # 139 passed, 1 skipped
```

- [ ] **Step 5: Commit**

```bash
git add dark-factory/scripts/supervisor.py dark-factory/tests/test_kb_writeback.py
git commit -m "feat(dark-factory): opt-in KB write-back at run terminals (never affects exit code)

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 4: SKILL.md — KB ask + control-plane skill-composition guidance

**Files:**
- Modify: `dark-factory/SKILL.md`
- Create: `dark-factory/references/knowledge-base.md`
- Modify: `dark-factory/references/config-reference.md` (only if Task 1 didn't already add the KB rows — verify, don't duplicate)

**Interfaces:** operator guidance only; no code.

- [ ] **Step 1: Add the KB ask to the Engage step**

In `SKILL.md` step 1 (Engage), append:

```markdown
   Also ask (optional, default none): do you have a **knowledge base** to draw on
   and record to? — a markdown **wiki** (give a directory path) or an **open-brain
   / MCP** memory. If a wiki: set `knowledge_base` in config.json; on `write_back:
   true` the supervisor appends a barrier-safe run summary (no scenario text) to
   `<path>/dark-factory-runs.md`. If open-brain: you (this session) may read it for
   grounding and, only with the user's OK, `capture_thought` the run outcome — the
   supervisor does not touch MCP. Absence of a KB is never an error.
```

- [ ] **Step 2: Add a control-plane skill-composition section**

Add a new section to `SKILL.md` after "Hard rules":

```markdown
## Composing with other skills (control-plane only)

dark-factory's *builder* is an external sandboxed CLI that loads no skills — so
composition applies only to THIS orchestrating session's own steps, which run
around the builder, never inside it:

| Step | Prefer, if available | Barrier note |
|---|---|---|
| Author the spec (step 2) | `superpowers:brainstorming`, `grill-me-codex`, `writing-plans` | fine — spec is SHARED with the builder |
| Author scenarios (step 3) | keep manual, in a **separate session** | never delegate this into a builder-driving session |
| Stuck loop (cap reached, likely spec ambiguity) | `superpowers:systematic-debugging` | operates on spec + behavior IDs only, never scenario internals |
| Cleanup an accepted artifact | `/simplify`, `code-review` on the workspace | post-acceptance, outside the barrier |

**Honesty:** at `cooperative`/`standard` tiers this is *guidance*, not enforcement —
these tiers sandbox the builder, not the orchestrator. An **enforced** per-tier skill
allowlist with content-hash pinning (spec §3B) requires the orchestrator itself to run
sandboxed, which is a `hardened`/`enterprise` capability (not yet built). Never author
or reveal holdout scenarios in a session that will also drive the builder.
```

- [ ] **Step 3: Write `references/knowledge-base.md`**

```markdown
# Knowledge-base integration (optional, spec §3A)

dark-factory is self-contained; a KB is optional and never required.

- **wiki** (`knowledge_base.kind: wiki`, `path: <dir>`): with `write_back: true`
  the supervisor appends a **barrier-safe** run summary to
  `<path>/dark-factory-runs.md` at each terminal — only `outcome`, `tier`,
  `qualified`, `iterations`, and failing **behavior IDs**. No scenario text,
  observed output, or prompts. A KB write-back failure never changes the run's
  exit code (it journals `KB_WRITEBACK_ERROR` and continues).
- **open-brain** (`kind: open-brain`): the supervisor does nothing — MCP is a
  Claude-session capability. This session may read it for grounding and, only on
  the user's OK, `capture_thought` the outcome.
- **none** (default): fully standalone.

Reading a KB for grounding is always this session's job; the supervisor only ever
*writes* the wiki summary, and only when opted in.
```

- [ ] **Step 4: Verify + commit**

```bash
grep -n "knowledge_base" dark-factory/references/config-reference.md   # rows exist (from Task 1); no dupes
.venv/bin/python -m pytest dark-factory/tests -q | tail -1   # unchanged: 139 passed, 1 skipped (docs-only)
git add dark-factory/SKILL.md dark-factory/references/knowledge-base.md dark-factory/references/config-reference.md
git commit -m "docs(dark-factory): KB engage-ask + control-plane skill-composition guidance

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

## Self-Review Notes (plan ↔ spec)

**Covered (M4b slice, finishing M4):** optional KB config (§3A) with validation; a barrier-safe wiki run-summary write-back (allowlisted manifest fields + behavior IDs only, MARKER-absence tested); opt-in, failure-tolerant supervisor wiring that never changes the exit code; the engage-time KB ask; control-plane skill-composition guidance (§3B) mapping each orchestration step to a preferred skill with barrier notes; open-brain framed as a session/MCP opt-in (not supervisor code).

**Deliberately deferred (honest):** ENFORCED per-tier skill allowlists with content-hash pinning (§3B) — requires a sandboxed orchestrator, a `hardened`/`enterprise` capability (M5). open-brain *write-back* from the supervisor — impossible without MCP in-process; done by the session instead. Cross-model *verifier* — never (deterministic runner by design).

**Known honesty notes:** at cooperative/standard, skill composition is honor-system guidance (stated in SKILL.md); the wiki write-back is barrier-safe by construction because `build_summary` reads only an allowlist of manifest fields and rejects any failing-behavior value that isn't a `BHV-` id.
```
