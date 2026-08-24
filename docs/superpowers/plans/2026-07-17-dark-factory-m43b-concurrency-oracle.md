# M43b — bounded-concurrency oracle (races, lost updates, crash-under-parallelism)

## Goal
The last machine-closable slice of the oracle ceiling: detect **concurrency
bugs** — lost updates, corruption/crash under parallel access, non-idempotent
handling of concurrent retries — by executing generated step sequences **in
parallel** against the candidate and checking concurrency invariants. Builds
directly on the M43a engine (`df_generate` seeded cases, `df_invariants`
fixed vocabulary, `run_property_scenario` execution); this milestone adds the
parallel driver + the concurrency invariants.

**Owner decision (2026-07-17): ONE STRIKE = FAIL.** Any observed violation
across the attempts fails the scenario — a lost update seen once IS a real
bug. The honest caveat is documented, not hidden: a PASS is probabilistic
(absence of an observed race is not proof of none); the oracle raises the
detection floor, it does not prove race-freedom.

## The IR extension (additive to M43a's `when.property`)
A property scenario MAY add a `concurrency` block:
```jsonc
"when": {
  "property": {
    "generate": { "vars": {...}, "cases": 20, "seed": 99 },
    "steps": [ {"run": ["kv","put","{k}","{v1}"]} ],
    "concurrency": {
      "workers": 4,          // 2..MAX_WORKERS (validated ceiling, e.g. 16)
      "attempts": 5,         // interleaving attempts per case, 1..MAX_ATTEMPTS (e.g. 20)
      "per_worker_vars": ["v1"]   // vars regenerated per worker (distinct values per worker)
    },
    "timeout_s": 10
  }
},
"then": { "invariant": {"name": "no_lost_update", "args": {...}} }
```
- With `concurrency` present, EACH generated case runs `attempts` times; each
  attempt launches `workers` parallel executions of the step sequence (vars in
  `per_worker_vars` get per-worker distinct generated values; others shared).
  Everything remains seeded/deterministic in WHAT is generated; the
  interleaving itself is inherently OS-scheduled (that is the point) — the
  invariant, not the schedule, decides pass/fail.
- Concurrency invariants (added to the FIXED `df_invariants` vocabulary):
  - `no_lost_update` — after N workers each wrote a distinct value to the same
    key, a final read returns ONE of the written values intact (never a torn/
    merged/empty result); optionally `last_write_wins_consistent` variant.
  - `no_crash_no_hang` — every worker's every step exits within its timeout
    with an allowed exit/status (no 5xx, no crash, no deadlock past
    timeout — a hang IS a failure, enforced by the per-case timeout).
  - `idempotent_under_concurrency` — N workers submitting the SAME logical
    operation concurrently yields the same terminal observation as one
    (e.g. concurrent identical PUTs → one consistent value; concurrent
    identical "create" → exactly-one semantics per the declared contract arg).
  - `serializable_counter` (optional if cheap) — N concurrent increments of a
    declared counter step → final value == initial + N (the canonical
    lost-update detector when the app exposes a counter).
- ONE STRIKE: the first attempt (in any case) whose invariant check fails
  records the violation (control-plane counterexample: case index, attempt
  index, per-worker observations) and the scenario FAILS with the existing
  `property_violated` taxonomy (no new taxonomy needed — value-free feedback
  unchanged). All attempts passing ⇒ PASS, manifest records
  `{workers, attempts, cases}` so the probabilistic strength is auditable.

## Execution design (Task order for the implementer)
1. **`df_generate`**: `per_worker_vars` support — per-worker values drawn from
   the same seeded stream (deterministic: seed → case → worker index).
   Validate `concurrency` block bounds (workers/attempts ceilings, per_worker_vars
   ⊆ declared vars).
2. **`df_invariants`**: the 3-4 concurrency invariants over PER-WORKER
   observation lists (`fn(case_vars, worker_observations, args)`), plus
   discrimination checks (each must reject a constructed violating
   observation set — e.g. a torn value for `no_lost_update` — so a vacuous
   concurrency invariant is gate-flagged, mirroring M43a/M42).
3. **`run_scenarios`**: parallel driver in `run_property_scenario` — launch
   the workers' step sequences via `concurrent.futures.ThreadPoolExecutor`
   (each worker's steps are subprocesses, so threads only marshal I/O; the
   REAL parallelism is the N candidate processes). Each worker runs under the
   SAME candidate confinement wrapper + env as any scenario; process-group
   reaping per worker (no orphan on timeout — a hung worker is killed and
   counts as `no_crash_no_hang` failure). Per-case wall-clock cap =
   `timeout_s` (shared deadline), plus the M43a total budget.
4. **Gates/supervisor**: concurrency scenarios ride the existing property
   wiring (M7 pre-build discrimination gate, `property_violated` feedback,
   manifest property fields extended with `{workers, attempts}`, journal
   value-free). Nothing new to the barrier: per-worker observations/
   counterexamples are control-plane only, exactly like M43a.
5. **Author/critic**: author may emit concurrency properties (prompt gains the
   block + invariants); critic may raise a blocking `missing_case` for a
   behavior with obvious shared-mutable-state semantics lacking a concurrency
   property (advisory where it's a judgment call).
6. **Tests + docs**: unit (generator per-worker determinism; each invariant
   holds/violates/discriminates), integration (a deliberately racy stub CLI —
   e.g. read-modify-write a file without locking — FAILS `no_lost_update`
   with one-strike semantics; a locked/atomic stub PASSES; a hanging stub
   fails `no_crash_no_hang` within the deadline; deterministic-by-seed
   inputs), e2e (a run whose cohort includes a concurrency property: racy
   stub → `property_violated`, atomic stub → converges). Timing discipline:
   the racy stub must make the race RELIABLE (e.g. a deliberate sleep between
   read and write) so the suite is deterministic — never a flaky test.
   Docs: scenario-format (the block), scenario-adequacy (what concurrency
   testing does/doesn't prove — one-strike + probabilistic-pass caveat),
   audit (manifest fields), authoring/SKILL/README/OVERVIEW one line each.
   Example: kv-service gains a `no_lost_update` concurrency scenario.

## Bounds + honesty (document verbatim)
- One strike = fail (owner decision); a single observed violation is a real
  bug. A PASS is probabilistic detection, not proof — recorded workers ×
  attempts × cases quantify the effort. This is the industry-honest framing.
- The suite's own tests use engineered-reliable races (deterministic); real
  candidate races are inherently probabilistic — the oracle raises the floor.
- Perf/load/latency remain permanently out (separate tool).
- MAX_WORKERS/MAX_ATTEMPTS ceilings keep runs bounded; hang = failure by
  deadline, never a stuck run.

## Back-compat
`concurrency` is additive inside `when.property`; absent ⇒ M43a behavior
byte-identical. No new taxonomy (reuses `property_violated`).
