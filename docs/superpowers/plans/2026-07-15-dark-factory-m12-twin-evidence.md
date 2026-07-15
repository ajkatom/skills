# dark-factory M12 — Twin Evidence & Verifier-Only Variants Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Implement spec §7.4's verification-time authority mechanics that are buildable without new infrastructure: (1) **evidence from observer state, not candidate output** — twins record every interaction to an **observation log inside `run_dir`** (control-root-denied to builder and candidate), and the oracle gains assertions over that log, so "the code really called the service" becomes checkable evidence the candidate cannot forge; (2) **verifier-only variants the candidate can't predict** — at verify time (only), twins receive an unpredictable per-pass seed and serve seed-derived tokens; an oracle assertion requires the candidate's output to echo the served token, so a builder that hardcodes build-time twin responses fails verification; (3) **close a discovered write-hole in the standard tier** — the macOS sandbox profile denies `file-read*` only, so a malicious builder/candidate could blind-WRITE or truncate control-root files (scenarios, journal, observation logs); M12 adds `file-write*` denial + a write-probe, fail-closed.

**Architecture:** `TwinSet.start` additionally passes each twin `DF_OBSERVER_FILE=<run_dir>/twins/<name>.observations.ndjson` plus caller-supplied `extra_env` (the verify-pass seed `DF_TWIN_VARIANT_SEED=<uuid>`; build-phase twins get NO seed). Twins append flushed ndjson observation lines (`{"event":..., "detail":..., "token":...}`). `run_all` records each observation file's byte OFFSET before every scenario and reads only the delta after, attributing observations per scenario; `evaluate_then` gains two additive assertion keys over an extended `observed` dict (`twin_observations: {name: [lines]}`, `twin_tokens: {name: [tokens]}`), producing new fixed-taxonomy value `no_twin_evidence` (priority after `wrong_output`). The feedback channel stays IDs + taxonomy — `no_twin_evidence` is a vocabulary constant, no content crosses. `df_gates.is_discriminating`'s synthetic mutant carries EMPTY twin evidence, so any twin assertion rejects it (discriminating by construction).

**Honest scope (stated in docs):** the observation log is trustworthy because the candidate cannot write it (standard: OS write+read denial on the control root, probe-verified; hardened: not mounted) — at `cooperative` it is honor-system like everything else there. "Authenticated network graph" (candidate→twin data-plane vs verifier→control-plane as *network* policy) and off-box evidence channels remain deferred — M12's channel is filesystem-denial-based, which is the same authority that already protects the holdout. Twins must flush observation lines per event (contract, documented); a twin that buffers may under-report. Variant tokens prove liveness against THIS twin, not fidelity to any real service — fidelity scoring stays deferred (per digital-twins.md).

**Tech Stack:** Python stdlib. pytest. `.venv/bin/python -m pytest dark-factory/tests -v` from repo root `/Users/alonadelson/Projects/ai_projects/skills`.

## Global Constraints

- **Barrier:** the variant seed, observation logs, and token values NEVER reach the builder (no env, no prompt, no feedback field). Feedback stays `{behavior_id, taxonomy}` with taxonomy from the FIXED vocabulary — now `("wrong_exit_code","wrong_output","timeout","crash","no_twin_evidence")`. `id_feedback.py`'s `TAXONOMY` tuple is the single source; `FeedbackLeakError` discipline unchanged.
- **Fail-closed write-denial:** the upgraded macOS profile denies `file-read*` AND `file-write*` on the control root; `probe_denial` proves BOTH (read canary unreadable AND write attempt fails) or returns False. Linux bwrap's tmpfs mask already blocks both — assert it in the probe the same way (the probe is backend-agnostic).
- **Back-compat:** scenarios without twin assertions behave exactly as today; twins without `DF_OBSERVER_FILE` support (they ignore the env var) still work — observation-less twins simply fail any twin-evidence assertion (fail-closed for scenarios that demand evidence, no-op otherwise). Absent twins config → zero change. All 454 existing tests stay green (the write-denial probe change may require probe fixtures to update — behavior-preserving updates only).
- **Additive manifest:** `twin_evidence = {"variants": bool, "observed_assertions": int} | None` threaded like M9/M10/M11 fields.
- **Oracle IR stays v0-compatible:** new keys additive; `run_scenarios.py` docstring updated; schema validation rejects a `twin_observed`/`stdout_echoes_twin` referencing an UNDECLARED twin name at load time (GateError/OracleError at run start, not mid-run).
- **Commit messages end with:** `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`.

## File Structure

```
dark-factory/
  scripts/
    df_sandbox.py        # Task 1 — write-denial profile + dual probe
    df_twins.py          # Task 2 — observer file + extra_env plumbing
    run_scenarios.py     # Task 3 — oracle IR v0.2 + per-scenario observation deltas
    id_feedback.py       # Task 3 — taxonomy constant + no_twin_evidence
    df_gates.py          # Task 3 — mutant carries empty twin evidence
    supervisor.py        # Task 3 — verify-pass seed, manifest twin_evidence
  references/
    digital-twins.md     # Task 4 — evidence + variants sections
  SKILL.md               # Task 4
  tests/
    fixtures/twin_greeter          # Task 2 — observations + variant token
    fixtures/fake_builder_hardcode # Task 4 — fakes output, never calls twin
    test_sandbox_write_denial.py   # Task 1
    test_twin_observer.py          # Task 2
    test_twin_evidence_oracle.py   # Task 3
    test_e2e_twin_evidence.py      # Task 4
```

---

### Task 1: standard-tier write denial + dual probe

**Files:** modify `dark-factory/scripts/df_sandbox.py`; create `dark-factory/tests/test_sandbox_write_denial.py`.

**Interfaces:**
- `_MacOSBackend.wrap_prefix` profile becomes `(version 1)(allow default)(deny file-read* (subpath "{real}"))(deny file-write* (subpath "{real}"))`.
- `probe_denial(backend, deny_root, workspace)` now proves BOTH: the existing read canary stays; ADD a write probe — the wrapped process attempts `open(<deny_root>/.probe-write-<uuid>, "w")` and must hit the exception branch (marker `DF-WRITE-DENIED`); ALSO attempts truncating the read canary (`open(canary, "w")`) — must fail. True ONLY IF read denial proven AND write denial proven (rc 0 + both markers, same launch-failure discipline as today). Any write probe file that somehow appears in deny_root → return False AND unlink it (finally).
- Backend contract unchanged for callers (`wrap_prefix(deny_root, workspace)`); bwrap prefix unchanged (tmpfs masks both) — the dual probe simply verifies it too.

- [ ] **Step 1 (TDD):** `test_sandbox_write_denial.py` — macOS profile string contains both deny clauses; live probe (skipif backend unavailable) returns True on this mac AND no probe artifacts remain in deny_root after; a fake backend whose prefix does NOT deny writes (e.g. empty prefix `[]`) → probe returns False (write leaks through); a fake backend denying writes but not reads → False; launch-failure (bogus prefix) → False. Update any existing probe tests that assert the old profile string (behavior-preserving).
- [ ] **Step 2:** Implement → green. Full suite (454 + new; existing standard-tier e2e must still pass — the tightened profile must not break legitimate candidate/builder behavior since neither ever legitimately writes to the control root).
- [ ] **Step 3:** Commit `fix(dark-factory): standard tier denies control-root WRITES too; dual read+write probe`.

---

### Task 2: twin observer + extra_env plumbing + upgraded fixture

**Files:** modify `dark-factory/scripts/df_twins.py`, `dark-factory/tests/fixtures/twin_greeter`; create `dark-factory/tests/test_twin_observer.py`.

**Interfaces:**
- `load_defs` accepts optional `"supports_variants": bool` (default False; non-bool → TwinError). Def dict carries it through.
- `TwinSet.start(defs, run_dir, timeout_s, extra_env=None)` — new optional param: `child_env = dict(os.environ, DF_ENDPOINT_FILE=ep_file, DF_OBSERVER_FILE=obs_file, **(extra_env or {}))` where `obs_file = <run_dir>/twins/<name>.observations.ndjson`. `reset(defs, run_dir, timeout_s, extra_env=None)` forwards it. `TwinSet.observer_files` attribute: `{name: obs_file}` populated at start (empty after stop).
- Twin observation contract (documented in the module docstring + digital-twins.md in Task 4): a twin SHOULD append one JSON line per interaction to `DF_OBSERVER_FILE`, flushed immediately: `{"event": "<short>", "detail": "<short>", "token": "<str, optional>"}`. Twins ignoring the env var still work (no log → no evidence).
- `twin_greeter` fixture upgraded: appends a flushed observation line per request (`{"event":"GET","detail":self.path}`); if `DF_TWIN_VARIANT_SEED` is set, responses become `Hello, <name>! [vt-<sha256(seed+path)[:12]>]` and the observation line gains `"token": "vt-..."`; without the seed, behavior is exactly today's.

- [ ] **Step 1 (TDD):** `test_twin_observer.py` — start twin_greeter with no extra_env: requests produce flushed ndjson observations at observer_files[name]; response text unchanged (no token). With `extra_env={"DF_TWIN_VARIANT_SEED": seed}`: response contains `vt-` token, observation line records the same token, token differs for a different seed (unpredictability), token deterministic for same seed+path. `observer_files` empty after stop(). load_defs: supports_variants true/false/invalid matrix. Existing df_twins tests green (extra_env default preserves behavior).
- [ ] **Step 2:** Implement → green. Full suite.
- [ ] **Step 3:** Commit `feat(dark-factory): twin observation logs + verifier-only variant seed plumbing`.

---

### Task 3: oracle IR v0.2 — twin evidence assertions, taxonomy, gates, supervisor seed

**Files:** modify `dark-factory/scripts/run_scenarios.py`, `id_feedback.py`, `df_gates.py`, `supervisor.py`; create `dark-factory/tests/test_twin_evidence_oracle.py`.

**Interfaces:**
- `run_scenarios` additive `then` keys:
  - `"twin_observed": {"twin": "<name>", "contains": "<nonempty str>"}` — the per-scenario observation DELTA for that twin must contain the substring (raw line match).
  - `"stdout_echoes_twin": {"twin": "<name>"}` — at least one `token` from that twin's per-scenario delta appears in `observed["stdout"]`. No tokens recorded → fail.
  - Both produce taxonomy `"no_twin_evidence"` on failure. Priority: timeout > crash > wrong_exit_code > wrong_output > no_twin_evidence (evaluate the existing keys first; only if they pass, evaluate twin keys).
  - `evaluate_then(then, observed)` reads `observed.get("twin_observations", {})` (`{name: [str lines]}`) and `observed.get("twin_tokens", {})` (`{name: [str]}`) — absent keys behave as empty (fail-closed for twin assertions, no-op otherwise).
  - Load-time validation: a twin assertion whose `twin` is not in the runner's known twin names → OracleError BEFORE any scenario runs. `run_all(..., observer_files=None)` gains the param (`{name: path}`); when None, known twin names = {} (so any twin assertion errors at load — correct: no twins configured). Per scenario: snapshot each observer file's size before the candidate runs; after, read from that offset, parse ndjson lines tolerantly (unparseable line → kept as raw string in twin_observations, ignored for tokens), build the two dicts into `observed`.
- `id_feedback.TAXONOMY = ("wrong_exit_code", "wrong_output", "timeout", "crash", "no_twin_evidence")`.
- `df_gates.is_discriminating`: mutant dict gains `"twin_observations": {}, "twin_tokens": {}` — a twin assertion evaluated against the mutant fails (evidence absent) → discriminating. A scenario whose ONLY assertion is `twin_observed` with `contains: ""`... `contains` must be non-empty at load (OracleError), so no new inert class.
- `supervisor.py`: at each verify pass (dev cohort AND final exam), the twin reset gains a fresh seed: `verify_env_extra = ts.reset(twin_defs, run_dir, twin_timeout, extra_env={"DF_TWIN_VARIANT_SEED": uuid.uuid4().hex})` — ONLY when at least one twin def has `supports_variants` (else no seed, exactly today's reset). Build-phase `ts.start` NEVER gets a seed. `run_all(..., observer_files=ts.observer_files if ts else None)`. The seed value is never journaled/manifested (grep-proof in tests). Manifest additive `twin_evidence = {"variants": <any supports_variants>, "observed_assertions": <count of twin-assertion scenarios>} if twins_enabled else None`, threaded fresh+resume like M11's `credentials`.
  - IMPORTANT barrier note: `verify_env_extra` currently flows ONLY to `run_all` (scenario/candidate env) — confirm the builder never receives it (the builder gets `build_env_extra` from the seedless build start; M11's env merging must keep these separate). Add a test pinning: builder env (captured) contains no `DF_TWIN_VARIANT_SEED`.

- [ ] **Step 1 (TDD):** `test_twin_evidence_oracle.py` — evaluate_then unit matrix (twin_observed hit/miss/absent-observations; stdout_echoes_twin token-present/none-recorded/token-not-echoed; priority: wrong_output beats no_twin_evidence; both-pass); load-time OracleError for unknown twin name / empty contains; run_all offset-delta attribution (two scenarios against one live twin_greeter — each sees only its own requests); is_discriminating with twin assertions; TAXONOMY tuple; supervisor tests (monkeypatched): seed present in verify reset env only when supports_variants, absent from build start, absent from builder captured env, absent from journal/manifest bytes; manifest twin_evidence shape on converged + abort; resume threading.
- [ ] **Step 2:** Implement → green. Full suite.
- [ ] **Step 3:** Commit `feat(dark-factory): oracle twin-evidence assertions + verifier-only variant seed (IDs+taxonomy barrier intact)`.

---

### Task 4: e2e — hardcoder fails, honest builder converges + docs

**Files:** create `dark-factory/tests/test_e2e_twin_evidence.py`, `dark-factory/tests/fixtures/fake_builder_hardcode`; modify `references/digital-twins.md`, `SKILL.md`.

- [ ] **Step 1:** `test_e2e_twin_evidence.py` (CLI subprocess; mirror test_e2e_twins.py's control setup with twin_greeter + a scenario whose `then` includes `stdout_contains` AND `stdout_echoes_twin`; twin def has `supports_variants: true`):
  - **(a) hardcoder rejected:** `fake_builder_hardcode` writes a greet.py that prints `Hello, World!` WITHOUT calling the twin → scenarios fail with `no_twin_evidence` (assert the taxonomy in the feedback file / journal), run ends CAP_REACHED exit 3; the feedback the builder received contains ONLY behavior_id + taxonomy (no token, no seed — grep feedback bytes for `vt-` and the seed → absent).
  - **(b) honest builder converges:** the existing `fake_builder_twin` (which calls the twin via DF_TWIN_GREETER) — update its artifact template if needed so the twin's variant token flows through its stdout naturally (it prints the twin's response verbatim) → converges exit 0; manifest `twin_evidence.variants` true; the final-exam pass also carried a FRESH seed (assert the seeds used differ across passes via the twin observation logs' tokens differing between iteration verify and final exam — read run_dir logs directly).
  - **(c) evidence channel is protected:** at standard tier (skipif no OS sandbox), after run (b) completes, take the SAME wrap_prefix the run used (`df_sandbox.current_backend().wrap_prefix(control_root, workspace)`) and launch a probe process under it that attempts to append a forged observation line to the run's actual observer file (a real path under run_dir): the append must FAIL and the file's content must be unchanged (byte-compare before/after). This proves Task 1's write denial protects the real evidence channel — note the candidate cannot even LEARN this path in-run (read denial); the probe is the stronger "even with the path, writing fails" claim.
- [ ] **Step 2:** docs — digital-twins.md: observation contract (flush-per-line), variant seed semantics (verify-only, unpredictable, never in feedback), evidence assertions with a worked scenario example, the honest-scope paragraph (filesystem-authority channel, network-graph enforcement deferred; cooperative = honor-system); SKILL.md: one paragraph + pointer. Update the run_scenarios.py docstring IR summary (Task 3 did the code; verify docs match).
- [ ] **Step 3:** Docs-vs-code verify; full suite green; commit `feat(dark-factory): twin-evidence e2e (hardcoder rejected, variants fresh per pass) + docs`.

---

## Self-Review Notes (plan ↔ spec)

**Covered (M12):** spec §7.4 standard — "evidence read from twin/observer state, not from anything the candidate writes" (observation logs in the denied control root; write-hole closed so "cannot write" is probe-proven, not assumed); §7.4 hardened+ — "vary twin inputs the candidate can't predict" (per-pass uuid seed, verify-only, token echo assertion); "append-only channel the candidate cannot address" (candidate provably cannot read OR write the log at standard+); anti-teaching-to-the-test strengthened: hardcoding twin responses now fails verification with a dedicated taxonomy the builder can act on without learning content.

**Deliberately deferred (honest, in digital-twins.md):** network-level authenticated graph (data-plane vs control-plane as enforced network policy — needs per-role network namespaces/proxies); off-box evidence sink (M13 territory); twin fidelity scoring vs real services and drift detection (already deferred in digital-twins.md — unchanged); verifier-only hidden twin IMPLEMENTATIONS (a fully different mock at verify time — M12 ships variant SEEDS within one implementation, which is the anti-hardcode property; swapping whole implementations is a config exercise the docs describe but M12 doesn't automate).

**Honesty note:** the write-hole fix (Task 1) is disclosed as a fix to a pre-existing gap, not silently folded in — the standard tier's manifest claim ("probe-verified read denial") was true; M12 upgrades the claim to read+write and the probe proves both.
