# dark-factory M15 — Brownfield Path (detection + characterization regression guards) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Make dark-factory safe to point at an EXISTING codebase (spec §8). Three properties: (1) **detection** — the skill classifies a run as greenfield or brownfield and never treats legacy as greenfield; (2) **characterization regression guards** — before the builder touches anything, the supervisor observes the CURRENT system at human-chosen probe points and freezes that behavior into holdout regression scenarios (dev cohort), so any change that breaks captured existing behavior fails verification exactly like a new-behavior miss — and the builder never sees these scenarios (barrier intact); (3) **reduced-guarantee honesty** — a brownfield manifest states that characterization captures OBSERVED behavior at the probes, not full semantics, so assurance is bounded by probe coverage.

**Architecture:** New module `df_brownfield.py` (stdlib): `detect_mode(project_src, snapshot_manifest)` classifies; `characterize(src_root, probes, exec_wrapper)` runs each probe command against a throwaway copy of the current source and returns generated regression scenarios (`cohort: "dev"`, `behavior_id: "BHV-REGRESS-<n>"`, `then` = the OBSERVED exit_code + stdout/stderr equality). The supervisor, when `mode` resolves to brownfield, characterizes BEFORE the build loop and writes the generated scenarios into `<run_dir>/generated-scenarios/` (control-plane, builder-denied like all scenarios) then merges them into the dev cohort the verifier loads — the builder's prompt/workspace never include them. Manifest records `mode`, `characterization: {probes, generated, note}`.

**Honest scope (stated in docs):** characterization is a **behavioral snapshot at the probe points the human supplies** — it guards exactly what the probes exercise, nothing more; unprobed behavior can still regress silently, so probe curation is the human's job and the manifest states the residual. Characterization observes the current artifact by RUNNING it (the probe commands are trusted human input, run under the same exec_wrapper as verification); it does not reverse-engineer semantics or auto-discover behavior. A probe whose output is nondeterministic (timestamps, PIDs) would freeze a flaky guard — docs tell the user to make probes deterministic (the mutation gate from M7 already rejects a `then` that can't discriminate, catching empty/degenerate probes). Auto-generating twins from a running system (spec §8's "infer twin services") stays deferred — M15 characterizes the artifact's CLI behavior, not its service dependencies.

**Tech Stack:** Python stdlib. pytest. `.venv/bin/python -m pytest dark-factory/tests -v` from repo root `/Users/alonadelson/Projects/ai_projects/skills`.

## Global Constraints

- **Barrier:** generated regression scenarios are holdout — written to run_dir (control-plane), merged into the verifier's dev cohort, NEVER into the builder's prompt/workspace/feedback. Feedback stays IDs + taxonomy; a regression failure reports `{behavior_id: "BHV-REGRESS-<n>", taxonomy}` — no probe content crosses.
- **Detection is fail-safe toward brownfield:** `mode: auto` (default) → brownfield iff `project_src` is set AND its snapshot has ≥1 file; else greenfield. Explicit `mode: brownfield` with an empty/absent project_src → ConfigError (nothing to characterize). Explicit `mode: greenfield` with a non-empty project_src → allowed but the manifest records `mode: greenfield` and a `legacy_ignored: true` warning (honest: the human overrode detection).
- **Characterization runs under the verification exec_wrapper** (the same OS sandbox/container isolation the candidate uses) — a probe can read the snapshot copy but the control root stays denied, same as any scenario run.
- **Deterministic-probe requirement:** each generated scenario's `then` must pass the M7 mutation gate (`is_discriminating`) — a probe that produces a degenerate/inert `then` (e.g. empty stdout with no exit-code signal) → the pre-build coverage/mutation gate already fails the run; M15 adds a clearer up-front `BrownfieldError` naming the offending probe.
- **Back-compat:** absent `mode` + absent project_src → greenfield, byte-identical to today. Existing 517 tests stay green. Manifest `mode`/`characterization` additive.
- **Commit messages end with:** `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`.

## File Structure

```
dark-factory/
  scripts/
    df_brownfield.py    # Task 1 — detect_mode + characterize
    df_config.py        # Task 2 — mode + brownfield.probes config
    supervisor.py       # Task 2 — characterize-before-build, merge into dev cohort, manifest
  references/
    brownfield.md       # Task 3 — the incremental path + reduced-guarantee honesty
    config-reference.md
  SKILL.md              # Task 3 — brownfield step
  tests/
    fixtures/legacy_app         # Task 1 — a tiny existing "app" to characterize
    fixtures/fake_builder_break # Task 3 — a builder that breaks captured behavior
    test_brownfield.py          # Task 1
    test_brownfield_config.py   # Task 2
    test_e2e_brownfield.py      # Task 3
```

---

### Task 1: df_brownfield — detection + characterization

**Files:** create `dark-factory/scripts/df_brownfield.py`, `dark-factory/tests/fixtures/legacy_app`, `dark-factory/tests/test_brownfield.py`.

**Interfaces (Produces):**
```python
class BrownfieldError(ValueError): ...

def detect_mode(configured_mode: str, project_src: str | None,
                snapshot_manifest: dict | None) -> str
    # configured_mode in {"auto","greenfield","brownfield"}.
    # snapshot_manifest is snapshot_source.build_manifest(project_src) or None.
    # "auto": "brownfield" iff project_src and snapshot_manifest["files"] non-empty,
    #         else "greenfield".
    # "brownfield": require project_src + non-empty files, else BrownfieldError.
    # "greenfield": always "greenfield" (caller records legacy_ignored if files exist).

def characterize(src_root: str, probes: list[dict], exec_wrapper=None) -> list[dict]
    # probes: [{"id": "<slug>", "run": ["cmd", ...], "timeout_s": int}] (human-supplied).
    # Copies src_root to a throwaway temp dir (via snapshot_source.snapshot, so the
    # same no-symlink/no-special-file hygiene applies), runs each probe there under
    # exec_wrapper (a list prefix or None), and returns one scenario per probe:
    #   {"ir_version":"0.1","id":f"BHV-REGRESS-{i}-S1","behavior_id":f"BHV-REGRESS-{i}",
    #    "cohort":"dev","title":f"regression guard: {probe['id']}",
    #    "given":"captured from the pre-change system",
    #    "when":{"run": probe["run"], "timeout_s": probe["timeout_s"]},
    #    "then":{"exit_code": <observed>, "stdout_equals": <observed>, "stderr_equals": <observed>}}
    # Validation: probes a non-empty list; each has a unique slug id (^[a-z0-9-]{1,32}$),
    # a non-empty run list[str], timeout_s int in 1..120 → else BrownfieldError.
    # A probe that TIMES OUT or whose observation can't be captured → BrownfieldError
    # naming the probe (can't freeze a guard you couldn't observe). The temp copy is
    # always removed (finally).
```

- [ ] **Step 1 (TDD):** `legacy_app` fixture — a tiny deterministic stdlib CLI (e.g. `python3 legacy_app add 2 3` → prints `5`, exit 0; bad args → stderr + exit 2). `test_brownfield.py`:
  - detect_mode: auto+empty→greenfield; auto+nonempty→brownfield; brownfield+empty→BrownfieldError; brownfield+None→BrownfieldError; greenfield+nonempty→"greenfield".
  - characterize: two probes against legacy_app → two scenarios with the OBSERVED exit_code/stdout_equals/stderr_equals; ids BHV-REGRESS-0/1; cohort dev; each `then` is discriminating (import df_gates.is_discriminating and assert True — proves the captured guard isn't inert). Probe validation errors (dup id, empty run, bad timeout, empty list). A deliberately-slow probe (`sleep 5`, timeout_s 1) → BrownfieldError naming it; temp copy gone afterward (no leftover temp dirs — capture tempfile base and assert cleanup). exec_wrapper threaded (pass a harmless prefix like `[sys.executable, "-c", "import sys,os; os.execvp(sys.argv[1], sys.argv[1:])", ...]`? simpler: assert characterize passes the wrapper by using a wrapper that sets an env var the probe echoes — or just unit-test with wrapper=None and cover wrapper plumbing in Task 2's supervisor test).
- [ ] **Step 2:** Verify fail → implement → green.
- [ ] **Step 3:** Full suite green (517 + new). Commit `feat(dark-factory): df_brownfield — greenfield/brownfield detection + behavioral characterization`.

---

### Task 2: config `mode`/`probes` + supervisor characterize-before-build + manifest

**Files:** modify `dark-factory/scripts/df_config.py`, `supervisor.py`, `references/config-reference.md`; create `dark-factory/tests/test_brownfield_config.py`.

**Interfaces:**
- Consumes Task 1 (`df_brownfield.detect_mode/characterize/BrownfieldError`).
- Produces:
  - `cfg["_brownfield"] = {"mode": "auto"|"greenfield"|"brownfield", "probes": [ {id,run,timeout_s} ]}` — `mode` default "auto"; `probes` default []; validation: mode in the three values; probes a list of dicts each with slug `id`, non-empty `run` list[str], `timeout_s` int 1..120; a `mode: "brownfield"` with empty `probes` → ConfigError (brownfield with nothing to characterize is a no-op that would falsely claim regression coverage); probes present with `mode: "greenfield"` → ConfigError (contradictory).
  - Supervisor `_run_locked`, after snapshot (the existing `if project_src:` block builds `workspace` + `snap_hash`) and BEFORE the build loop:
    ```python
    snap_manifest = snapshot_source.build_manifest(project_src) if project_src else None
    try:
        mode = df_brownfield.detect_mode(cfg["_brownfield"]["mode"], project_src, snap_manifest)
    except df_brownfield.BrownfieldError as e:
        sys.stderr.write(f"dark-factory: brownfield: {e}\n"); return 2
    legacy_ignored = (mode == "greenfield" and snap_manifest and snap_manifest["files"])
    generated = []
    if mode == "brownfield":
        try:
            generated = df_brownfield.characterize(project_src, cfg["_brownfield"]["probes"], exec_wrapper=exec_prefix)
        except df_brownfield.BrownfieldError as e:
            sys.stderr.write(f"dark-factory: brownfield characterization failed: {e}\n"); return 2
        gen_dir = os.path.join(run_dir, "generated-scenarios"); os.makedirs(gen_dir, exist_ok=True)
        for sc in generated:
            atomic_write(os.path.join(gen_dir, sc["id"] + ".json"), canonical_json(sc))
        journal.write("CHARACTERIZED", mode=mode, generated=len(generated),
                      behavior_ids=[sc["behavior_id"] for sc in generated])
    ```
    (`exec_prefix` is the verifier wrapper resolved just above — characterization runs under the same isolation.)
  - The verifier's dev cohort must include the generated scenarios. Find where `run_all(scenarios_dir, ...)` loads scenarios; add an `extra_scenarios` path (the `gen_dir`) OR pass the generated scenario dicts through. Cleanest: `run_all(..., extra_scenarios_dir=gen_dir or None)` — `load_scenarios` unions the control `scenarios/` dir with `extra_scenarios_dir` (dev cohort only; generated are always cohort dev). Dup id across the two dirs → OracleError. The pre-build coverage/mutation gate (M7) runs over the union too — an inert generated `then` fails the gate with a clear message.
  - Manifest additive: `mode: <mode>`, `characterization: {"probes": len(probes), "generated": len(generated), "note": "behavioral snapshot at probe points; unprobed behavior may regress", "legacy_ignored": bool(legacy_ignored)} if mode=="brownfield" or legacy_ignored else {"probes":0,"generated":0}`. Threaded fresh + resume (the M9/M11/M12 pattern). On resume, the generated scenarios already live in the prior run_dir — re-characterization is NOT re-run (resume reuses the sealed cohort); document + test that resume reads the existing generated-scenarios dir rather than re-observing the (now possibly-changed) source.
- [ ] **Step 1 (TDD):** `test_brownfield_config.py` — config matrix (defaults; mode values; brownfield+empty-probes → ConfigError; greenfield+probes → ConfigError; bad probe shapes); supervisor (monkeypatch/real legacy_app): brownfield run generates scenarios into run_dir/generated-scenarios, journal CHARACTERIZED, manifest mode/characterization; the generated scenarios are in the verifier's dev cohort (a run whose builder breaks a captured behavior → that BHV-REGRESS id fails); the builder's prompt/workspace never contain the generated scenario content (grep); greenfield+project_src+explicit greenfield → legacy_ignored true in manifest; resume reuses generated dir (doesn't re-characterize — assert the source can change between run and resume without new generated scenarios).
- [ ] **Step 2:** Implement → green.
- [ ] **Step 3:** config-reference rows. Full suite green. Commit `feat(dark-factory): brownfield mode + characterization regression guards wired into the dev cohort`.

---

### Task 3: e2e + docs

**Files:** create `dark-factory/tests/test_e2e_brownfield.py`, `dark-factory/tests/fixtures/fake_builder_break`, `references/brownfield.md`; modify `SKILL.md`.

- [ ] **Step 1:** `fake_builder_break` — a builder that, given a brownfield task, writes an artifact that satisfies the NEW-behavior spec scenario but BREAKS a characterized existing behavior (e.g. reimplements `legacy_app` so `add` now returns wrong output). `test_e2e_brownfield.py` (CLI subprocess, --project-src legacy_app):
  - **(a) regression caught:** a brownfield control (probes capturing `add 2 3`→`5` and a bad-arg case) + a spec asking for a NEW subcommand + `fake_builder_break` (adds the new subcommand but breaks `add`) → the run does NOT converge: the BHV-REGRESS scenario for `add` fails, feedback carries that behavior_id + `wrong_output`, run ends CAP_REACHED exit 3. Assert the builder-facing feedback/prompt bytes contain no probe command text beyond what the spec already says (grep for the captured stdout `"5"` in a context that would only come from the generated scenario — i.e. assert the generated scenario JSON never appears in builder files).
  - **(b) honest builder converges:** a builder that adds the new subcommand WITHOUT breaking `add` → converges exit 0; manifest `mode: brownfield`, `characterization.generated == <n>`; the final exam + regression guards all green.
  - **(c) detection:** a run with `--project-src legacy_app` and NO mode config → manifest `mode: brownfield` (auto-detected, legacy not treated as greenfield); a run with no project-src → `mode: greenfield`.
- [ ] **Step 2:** `brownfield.md` — the incremental path (snapshot current source → characterize at human probes → freeze as holdout regression guards → build new behavior against the spec without seeing the guards → converge only when new + regression + final all pass); the reduced-guarantee honesty (probe-coverage-bounded; make probes deterministic; twins-from-system deferred); how to write good probes. SKILL.md: a brownfield sub-step (detect; supply `brownfield.probes` for behavior that must not regress) + pointer. config-reference cross-check.
- [ ] **Step 3:** Docs-vs-code verify; full suite green; commit `feat(dark-factory): brownfield e2e (regression caught, honest build converges, auto-detection) + docs`.

---

## Self-Review Notes (plan ↔ spec)

**Covered (M15):** spec §8 — detects greenfield vs brownfield and never treats legacy as greenfield (fail-safe-toward-brownfield `auto`); runs the incremental path (characterize the running system into a holdout regression suite) and states reduced guarantees (manifest `characterization.note` + brownfield.md); §5.1 compatibility — characterization needs no known-good REFERENCE implementation, it captures the system's OWN current behavior, and the existing M7 mutation gate still guards against inert generated oracles. Barrier preserved: generated guards are holdout, IDs+taxonomy only.

**Deliberately deferred (honest, in brownfield.md):** auto-inference of twin SERVICES from a running system (spec §8 aside — M15 characterizes CLI behavior, not service topology); semantic reverse-engineering / behavior auto-discovery (probes are human-curated, not mined); characterization of non-CLI surfaces (HTTP endpoints, libraries) beyond what a probe command can exercise; drift-detection between the frozen guard and a later real system.

**Honesty note:** characterization guarantees only what the probes exercise — brownfield.md leads with this so a green brownfield run is never mis-read as "nothing broke," only "nothing the probes covered broke." The manifest carries the same caveat so an auditor sees the bound.
