# Brownfield path (M15) — characterizing an existing system into regression guards

**Honest scope up front:** brownfield mode does **not** teach dark-factory
what your existing system means. It runs a handful of commands you choose
against the CURRENT artifact, freezes exactly what came back, and refuses to
let a build change that — for those commands only. **A green brownfield run
means "nothing the probes covered broke," never "nothing broke."** Everything
below exists in service of that one sentence: read it, then decide what to
probe.

## Why this exists

Every other dark-factory milestone assumes a **greenfield** build: there is
no pre-existing artifact, so there is nothing to protect except the new spec.
Point `--project-src` at a real, already-shipping codebase and that
assumption breaks — a builder that satisfies the new spec perfectly can
still silently regress behavior nobody asked it to touch, because nobody
told it (or the verifier) that behavior existed. Brownfield mode closes that
gap the same way dark-factory closes every other gap: not by trusting the
builder to be careful, but by giving the **verifier** something concrete to
check that the builder never sees.

## The incremental path

1. **Snapshot.** Point `--project-src` at the existing source tree. The
   supervisor detects the run is brownfield (see Detection below) before the
   builder ever runs.
2. **Characterize at human-chosen probes.** You supply `brownfield.probes` —
   real commands that exercise behavior you don't want to lose (e.g. `python3
   app.py add 2 3`). Before the first build iteration, the supervisor copies
   the snapshotted source into a throwaway directory (`df_brownfield.
   characterize`, via the same `snapshot_source.snapshot` hygiene as every
   other snapshot) and actually RUNS each probe there, under the same
   `exec_wrapper`/sandbox isolation the verifier uses for everything else — a
   probe can read the snapshot copy, but the control root stays denied, same
   as any scenario run.
3. **Freeze the observation as a holdout regression guard.** Each probe's
   OBSERVED `exit_code`/`stdout`/`stderr` becomes one `cohort: "dev"`
   scenario, `behavior_id: "BHV-REGRESS-<n>"`, written to `<run_dir>/
   generated-scenarios/<id>.json` — control-plane, alongside `scenarios/`,
   **never inside the builder's workspace**. These are merged into the
   verifier's dev-cohort load (`run_scenarios.load_scenarios`'s
   `extra_scenarios_dir`) — a generated `id` colliding with a hand-authored
   one is an `OracleError`, not a silent overwrite.
4. **Build the new behavior against the spec, without ever seeing the
   guards.** The builder gets the spec and, on failure, behavior-ID +
   taxonomy feedback — identical to every other dark-factory run. It has no
   way to know `BHV-REGRESS-0` exists, what command produced it, or what
   output it expects. If the builder breaks the captured behavior, that
   scenario fails exactly like a missed new-behavior scenario: same
   taxonomy, same feedback shape, same barrier.
5. **Converge only when new + regression + final all pass.** There is no
   separate "regression" verdict — `BHV-REGRESS-*` scenarios are ordinary
   dev-cohort scenarios once generated. Convergence, the final exam (if any),
   and every other gate apply to them exactly as to hand-authored scenarios.

## Detection (fail-safe toward brownfield)

`brownfield.mode` (default `"auto"`):

- **`auto`** — `brownfield` iff `--project-src` is given AND its snapshot has
  ≥1 file, else `greenfield`. A non-empty existing tree is **never** silently
  treated as greenfield under `auto` — that is the fail-safe direction spec
  §8 requires.
- **`brownfield`** (explicit) — requires a non-empty `project_src`, else a
  runtime refusal (`dark-factory: brownfield: ...`, exit 2): there would be
  nothing to characterize.
- **`greenfield`** (explicit) — always skips characterization, even against
  a non-empty `project_src`. The manifest then honestly records
  `characterization.legacy_ignored: true` — a deliberate human override of
  detection, not a bug.

Every fresh run journals `MODE_DETECTED(mode, legacy_ignored)` unconditionally,
brownfield or not, so the journal alone tells you which branch a run took.

**Zero-probe brownfield is a valid, but UNGUARDED, back-compat no-op.**
Auto-detecting brownfield (any `project_src` with files) with no
`brownfield.probes` configured at all — every pre-M15 `--project-src` run,
for instance — must not silently read as "regressions checked" when nothing
was actually guarded. That combination:

- prints a stderr WARN (`brownfield detected but no probes configured — NO
  regression guards were captured; add brownfield.probes to guard existing
  behavior.`),
- journals a distinct `BROWNFIELD_UNGUARDED(reason)` entry instead of
  `CHARACTERIZED`,
- and sets `characterization.note` to an unambiguous unguarded message (never
  the "behavioral snapshot at probe points" wording a real characterization
  gets) — so an auditor can tell "brownfield, nothing guarded" apart from
  "guards captured and passed" by reading the manifest alone.

(Explicit `mode: "brownfield"` with an *empty* `probes` list is rejected at
config-load time instead — a `ConfigError`, not a runtime no-op — because an
explicit ask for characterization with nothing to characterize is a
configuration mistake, not a legitimate back-compat path. Only
auto-detection can reach the zero-probe no-op above.)

## Reduced-guarantee honesty

- **Probe-coverage-bounded.** Characterization guards *exactly* the commands
  you listed in `brownfield.probes`, at the exact arguments you gave them —
  nothing else. A behavior you didn't probe can regress with zero signal
  from this mechanism. This is not a defect to be fixed later; it is the
  entire shape of the guarantee. Say it out loud when reporting a brownfield
  run: "nothing the probes covered broke," not "nothing broke."
- **Make probes deterministic.** A probe command must produce the same
  `exit_code`/`stdout`/`stderr` every time it's run against the same source —
  no timestamps, PIDs, random ordering, wall-clock-dependent output, or
  network calls. A nondeterministic probe freezes a flaky guard: it will
  fail the NEXT time it's checked even though nothing regressed, or (worse)
  pass despite a real regression because the observed baseline was already
  wrong. `df_brownfield.characterize` defends in depth here too — a probe
  whose captured `then` is non-discriminating (`df_gates.is_discriminating`
  — the same mutation check M7 runs on every hand-authored scenario) raises
  `BrownfieldError` naming the probe rather than silently freezing an inert
  guard.
- **Generated guards are deliberately excluded from the M7 coverage gate.**
  `BHV-REGRESS-<n>` behavior IDs are never declared in `behaviors.json` (you
  can't declare them in advance — their IDs are assigned by characterization
  order at run time) and are never referenced there after the fact either;
  if they were checked against `behaviors.json`, every one of them would be
  flagged as an `orphan_scenarios` false positive. Their own
  discriminating-ness is enforced directly by `characterize()` (above), not
  by the coverage gate — a different, narrower guarantee than what
  `behaviors.json` gives hand-authored scenarios, and that's intentional:
  characterization doesn't have a human-declared behavior list to trace
  against, only the observation it just took.
- **Twins-from-a-running-system stay deferred.** Spec §8 also floats
  inferring twin SERVICE definitions from a running system. M15
  characterizes CLI behavior only (a probe is a command, not a service
  topology) — auto-generating a twin definition from live traffic or a
  running dependency is not implemented.
- **No semantic reverse-engineering or auto-discovery.** Probes are
  human-curated, not mined. Nothing inspects the existing codebase to
  propose probes, infer behaviors, or guess what's worth protecting — that
  judgment call is yours.
- **No non-CLI characterization.** Only what a probe command (argv + exit
  code + stdout + stderr) can exercise is characterized. An HTTP endpoint, a
  library's importable API, or a GUI is out of scope unless you can express
  the check as a CLI invocation.
- **No drift detection.** A frozen guard is checked once, against the
  builder's artifact, during this run. Nothing re-observes the real system
  later to notice the guard has gone stale relative to a system that changed
  out from under it.

## How to write good probes

- **Deterministic output.** See above — no timestamps, PIDs, ordering that
  varies run to run, or external network dependencies.
- **Cover the behaviors you can't afford to lose.** Probes are a curation
  exercise, not exhaustive testing. Prioritize the commands whose silent
  breakage would be expensive or embarrassing, not everything the CLI can
  do.
- **One behavior per probe.** Each probe becomes exactly one
  `BHV-REGRESS-<n>` — keep each probe's command narrow enough that a failure
  points at one thing, the same discipline good hand-authored scenarios
  already follow (spec §6).
- **Respect the shape.** `{"id": "<slug, ^[a-z0-9-]{1,32}$, unique>", "run":
  ["<argv>", ...], "timeout_s": <int, 1..120>}`. A probe that times out or
  can't be spawned (`FileNotFoundError`/`PermissionError`/other `OSError`)
  raises `BrownfieldError` naming it — "can't freeze a guard you couldn't
  observe" — rather than silently skipping it.

## Resume never re-characterizes

`resume()` doesn't receive `--project-src` and must not re-observe a
possibly-changed source mid-run. It reuses the ORIGINAL run's `<run_dir>/
generated-scenarios/` verbatim — recovering `mode`/`legacy_ignored` from the
`MODE_DETECTED` journal entry — rather than calling `df_brownfield.
characterize` again. If the real source changes between a pause and a
`resume`, the sealed guard reflects the system **as it was when
characterized**, not as it is now.

## See also

- `references/config-reference.md` — `brownfield.mode`/`brownfield.probes`
  schema + validation rules
- `references/coverage-gates.md` — the M7 mutation/coverage gates
  characterization deliberately sits outside of (coverage), and reuses
  directly (mutation/`is_discriminating`)
- `references/scenario-format.md` — the oracle IR generated scenarios are
  expressed in, same as hand-authored ones
