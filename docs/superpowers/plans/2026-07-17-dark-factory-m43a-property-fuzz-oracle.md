# M43a — generative property + fuzz oracle (push the oracle's non-functional ceiling)

## Goal
Expand what the oracle can *express* from "one fixed input → one expected
observation" to **generative property / metamorphic / robustness (fuzz)**
testing: assert an INVARIANT over many machine-generated inputs. This closes
the biggest remaining machine-side gap M42 documented — the classes of
production bug a fixed example can't catch (round-trip integrity, idempotency,
determinism, "never crashes / always honors the error contract" under
malformed input). Bounded-concurrency (race conditions) is the sibling gain
and lands in **M43b** — this milestone is the shared generative engine +
property + fuzz kinds. **Still explicitly out** (a different tool, not a
correctness oracle): throughput/load/latency-SLA/sustained-traffic perf
testing — name that in the docs.

## Design principles (keep it in the oracle's spirit)
- **Declarative, not code.** Generators and invariants come from a FIXED,
  validated vocabulary (like the `then` assertion keys) — NEVER operator- or
  agent-supplied executable code. No arbitrary-code surface on the verifier
  side.
- **Deterministic + reproducible.** Every generative scenario carries a fixed
  `seed`; generation is a pure function of (seed, spec). The manifest records
  seed + case count so a run is reproducible and a failure is replayable.
- **Barrier-preserving.** A property failure's COUNTEREXAMPLE (the specific
  generated input) is scenario-grade secret — it goes to the control-plane
  (journal/manifest/operator), and the builder feedback carries ONLY
  behavior-id + a new fixed taxonomy `property_violated` (never the input,
  never the value). Same impoverished-feedback discipline as every other
  failure.
- **Bounded.** Per-case timeout, a hard `cases` cap (validated ceiling), and a
  total wall-clock budget — a generative scenario can never run unbounded.

## The new scenario kind (fits the existing IR)
A third mutually-exclusive `when` shape alongside `run`/`http`:
`when.property`. Shape:
```jsonc
{
  "ir_version": "...", "id": "...", "behavior_id": "BHV-...",
  "title": "...", "given": "...", "class": "boundary"|"failure"|"happy",
  "when": {
    "property": {
      "generate": {                     // typed input variables
        "vars": { "k": {"kind":"string","charset":"ascii_printable","min_len":1,"max_len":32},
                  "v": {"kind":"json","shape":"scalar_or_object"} },
        "cases": 50,                     // 1..MAX_CASES (validated ceiling, e.g. 500)
        "seed": 1234                     // required, reproducible
      },
      "steps": [                          // templated CLI or HTTP actions, {var} substituted
        {"run": ["kv","put","{k}","{v}"]},
        {"run": ["kv","get","{k}"]}
      ],
      "timeout_s": 10                     // per-case
    }
  },
  "then": { "invariant": {"name":"round_trip","args":{"key":"k","value":"v","observe_step":1}} }
}
```
- `generate.vars[].kind` ∈ a FIXED set: `int{min,max}`, `string{charset∈
  {ascii_printable,alnum,unicode,bytes},min_len,max_len}`, `json{shape∈
  {scalar,scalar_or_object,array}}`, `choice{options:[...]}`, and — for fuzz —
  `malformed{base:<var-or-literal>}` which yields adversarial variants of a
  base (bit-flip, truncate, oversize, wrong-type, control chars, injection
  tokens, empty). Deterministic given the seed.
- `steps` are the SAME `run`/`http` actions the oracle already executes, with
  `{var}` placeholders substituted from the generated case (substitution is
  literal string interpolation into argv/URL/body — validated to reject a
  placeholder that isn't a declared var).
- `then.invariant.name` ∈ a FIXED vocabulary evaluated over the case's step
  observations:
  - `round_trip` — a later step's observation reflects a value an earlier step
    set (write→read returns what was written).
  - `idempotent` — repeating the terminal step doesn't change the observation.
  - `deterministic` — same generated input over two executions → identical
    observation.
  - `robust` / `never_crashes` — every step exits in an allowed set / HTTP
    status is never 5xx and stderr is not a stack trace (the fuzz workhorse).
  - `error_contract` — for a `malformed` input, the terminal observation
    matches a declared shape (status class 4xx + an `error` key / non-zero
    exit + error on stderr), i.e. it FAILS CLEANLY rather than crashing or
    silently accepting garbage.
  - `monotonic` / `sorted` — an output ordering invariant.
  A property PASSES iff the invariant holds for ALL `cases`; on the first
  violation it records the counterexample (control-plane) and reports
  `property_violated`.

## Approach (6 tasks)

### Task 1 — generators (`df_generate.py`, new) + tests
Pure, seeded, stdlib. `generate_cases(generate_spec) -> list[dict]` returns
`cases` dicts mapping var→value, deterministic in `seed`. Each `kind` a small
generator; `malformed` composes over a base to yield adversarial variants.
Validation of the `generate` block (kinds, bounds, `cases` ≤ MAX_CASES, seed
present-and-int) lives here + is called by `_validate`. No I/O, no build —
fully unit-testable.

### Task 2 — the invariant vocabulary (`df_invariants.py`, new) + tests
`INVARIANTS = {name: fn}`; each `fn(case_vars, step_observations, args) ->
(ok: bool, detail: str)` over the per-case step observations (each observation
is the same dict `evaluate_then`/`evaluate_http` consume). Fixed set (above).
Pure, deterministic, no code-eval. Validation of `then.invariant` (name in
vocabulary, args reference declared vars/steps) here. A `sharpness`-equivalent
`invariant_is_discriminating(invariant, generate)` — the invariant must reject
a constructed violating observation battery (reuse the M42 sharpness idea) so
a vacuous invariant (always-true) is gate-flagged, not silently passing.

### Task 3 — execute property scenarios (`run_scenarios.py`)
- `_validate`: add the `property` branch (exactly-one-of run/http/property;
  validate generate + steps templating + invariant). `then` for a property
  scenario is exactly `{"invariant": {...}}` (reject the CLI/HTTP assertion
  keys there — mismatched kind).
- Execution: `run_property_scenario(sc, workspace, exec_wrapper, env_extra,
  ...)` — for each generated case: substitute vars into each step, run the
  step (reuse the existing CLI/HTTP execution incl. the candidate sandbox
  wrapper + twin plumbing + process-group reaping), collect step observations,
  evaluate the invariant. Stop at the first violation (record the
  counterexample) OR pass after all cases. Per-case + total timeout enforced;
  the whole thing runs UNDER the same candidate confinement as any scenario.
- The generated inputs/counterexample are scenario-grade: written only to the
  control-plane report, never to the builder workspace/feedback.

### Task 4 — supervisor + feedback + adequacy integration
- Wire property scenarios through `run_all` / dev + final cohorts exactly like
  run/http scenarios; a failing property yields the same ID+taxonomy feedback
  path with the new `property_violated` taxonomy (add to the FIXED failure
  vocabulary in `id_feedback`/validate_feedback — barrier-safe, value-free).
- M42 sharpness/adequacy: a property scenario's "sharpness" = Task 2's
  invariant-discrimination; it counts toward `class` coverage (fuzz scenarios
  are naturally `failure`/`boundary`). The pre-build M7 gate runs
  invariant-discrimination + generate-validity for property scenarios.
- Manifest: record per property scenario `{cases, seed, invariant}` and, on
  failure, that a counterexample exists (NOT its content in any
  builder-reachable place; the counterexample lands in the control-plane run
  report only). Journal `PROPERTY_VIOLATED` with behavior-id + invariant name
  + case index (value-free).

### Task 5 — author/critic emit property + fuzz (M40/M42 integration)
- `df_author`: the author prompt gains the property/fuzz vocabulary; the
  author MAY emit property scenarios, and for a `failure`/`boundary` class the
  critic can require a robustness/error_contract property (a new critic
  `missing_case` sub-kind: "no fuzz/robustness property for BHV-x"). Keep the
  barrier-safe retry feedback (behavior-id + missing-invariant only).
- `df_critic`: may raise a blocking `missing_case` when a behavior that handles
  external input has no `robust`/`error_contract` property. Advisory when it's
  a judgment call.

### Task 6 — tests + docs + honest residual + a worked example
- `test_generate.py`, `test_invariants.py` (each generator deterministic in
  seed; each invariant holds/violates correctly; discrimination flags a
  vacuous invariant), `test_property_scenario.py` (validate + execute a
  round_trip + a robust/fuzz property against a stub CLI: passes on a correct
  stub, reports `property_violated` + a control-plane counterexample on a buggy
  stub; barrier: the counterexample never reaches the workspace/feedback),
  `test_e2e_property.py` (a full run whose dev cohort includes a fuzz property;
  a deliberately non-robust stub fails with `property_violated`, a robust stub
  converges).
- Add a property/fuzz scenario to `examples/kv-service` (round_trip over
  generated k/v + an error_contract fuzz over malformed values).
- Docs: `references/scenario-format.md` (the property kind — generators,
  invariant vocabulary, seed/determinism, bounds), `references/oracle-*` /
  `references/scenario-adequacy.md` (property/fuzz close the fixed-example gap;
  **honest residual now: concurrency = M43b; perf/load/scale = a separate
  tool, still out; and the human spec-fidelity residual unchanged**),
  `references/audit.md` (property manifest fields + `property_violated`),
  SKILL.md/README/OVERVIEW one line.

## Back-compat
`when.property` is a new, purely additive kind. Absent ⇒ nothing changes; all
existing run/http scenarios validate + run byte-identically. New taxonomy
`property_violated` only ever appears for property scenarios.

## Out of scope (documented)
- **Bounded-concurrency scenarios (M43b)** — parallel step execution +
  concurrency invariants (`no_lost_update`, `no_crash_no_hang`,
  `idempotent_under_concurrency`). Builds directly on this engine.
- Throughput/load/latency-SLA/soak testing — a perf tool with statistical
  rigor + real infra, not a correctness oracle. Explicitly out, permanently.
- Operator/agent-supplied invariant CODE — declarative fixed vocabulary only
  (security + the oracle's whole philosophy).

## Key decisions
- Declarative generators + fixed invariant vocabulary (no code-eval), seeded +
  reproducible, bounded — fits the oracle IR and stays deterministic in the
  suite.
- Counterexamples are scenario-grade secrets: control-plane only, feedback is
  `property_violated` + behavior-id — the barrier is preserved.
- Integrates with M42 (sharpness→invariant-discrimination; class coverage;
  author/critic can emit + require fuzz/robustness properties).
- Honest residual stated: this + M43b cover property/metamorphic/robustness/
  concurrency; load/scale/latency remain a different tool.
