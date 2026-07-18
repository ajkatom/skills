# Scenario adequacy (M42)

Dark-factory's barrier proves the builder never saw the tests. That says
nothing about whether the tests are any *good*. M42 maximizes how ADEQUATE the
hidden scenarios are, so that after it runs the only residual gap to
production-readiness is the fidelity of the **human inputs** (spec, behaviors)
plus non-functional properties the oracle cannot express — and even the human
gap is made **visible** rather than silent.

Four levers, in increasing power. The first two are GATES (they run in the M7
pre-build slot for BOTH human- and agent-authored scenarios); the last two are
the decorrelated critic (author-time, agent-authored runs only).

## 1. Class-typed coverage (structural)

Every scenario carries an optional `class ∈ {happy, boundary, failure}`,
ORTHOGONAL to `cohort` (dev/final = feedback-vs-sealed; class = what-kind-of-
case):

- **happy** — a normal, valid input on the intended path.
- **boundary** — an edge: empty, max/min, duplicate, missing field, wrong type,
  an off-by-one limit.
- **failure** — the ERROR contract the spec promises on invalid use.

Absent `class` ⇒ `happy` (back-compat: every pre-M42 scenario is implicitly a
happy case). The **adequacy gate** (`df_gates.check_adequacy`) requires each
declared behavior to be covered by the policy's `required_classes` (default
`min_per_class` 1), not merely "≥1 scenario" — structurally killing
happy-path-only test sets. Gate failure (`ADEQUACY_GATE_FAILED`) is fail-closed,
BEFORE any build, naming the under-covered `{behavior, missing:[classes]}`.

Policy defaults (resolved in `df_config`):
- absent `scenario_adequacy` + human-authored ⇒ `["happy"]` (today's behavior;
  every scenario satisfies it, so the gate is a no-op).
- absent `scenario_adequacy` + an agent author (`roles.author`) ⇒
  `["happy","boundary","failure"]` (an agent writing the tests gets the
  strongest machine floor), critic enabled iff `roles.critic` is set.
- an explicit `scenario_adequacy` block overrides per key.

## 2. Sharpness proof (assertion-mutant battery)

The M7 oracle gate no longer asks "does this `then` reject ONE synthetic garbage
observation" — it asks "does this `then` reject a **battery** of near-miss
mutant observations, one per asserted dimension." `df_gates.sharpness(then)`
returns `{passed, killed, total, survivors}`; a `then` a near-miss SURVIVES is
not sharp, and its id + surviving mutant KINDS are reported.

The battery per assertion type (each mutant holds the OTHER assertions at a
value that passes, and perturbs only the dimension under test):

- **CLI** — `exit_code`: off-by-one ±1, a wrong sentinel, and crash/None;
  `stdout/stderr_equals`: char-changed, whitespace-only, appended-noise,
  truncated, empty (when the asserted value isn't itself empty), reversed lines;
  `stdout/stderr_contains`: empty, char-changed, truncated (a superset is NOT a
  required kill — `contains` legitimately accepts it).
- **HTTP** — `http_status`: ±1, a nearby code, crash/None; `body_contains`: as
  the CLI contains; `json_equals` (strict): value-changed, key-removed,
  type-flipped, extra-field, non-parseable body; `json_contains` (subset):
  value-changed, key-removed, type-flipped, non-parseable (an extra field is
  NOT a required kill); `json_path`: value-changed, type-flipped, missing.
- **twin** — no evidence (existing), wrong-token, partial-token.

**A concrete near-miss the OLD single-mutant check missed.** The old check built
ONE compound mutant that flipped `exit_code` AND stdout AND stderr at once, and
passed a `then` as long as ANY channel differed. So `{"exit_code": 0,
"stdout_contains": ""}` PASSED — the compound mutant also flipped the exit code,
returning `wrong_exit_code`, even though the stdout assertion is inert (every
output contains `""`). The M42 battery ISOLATES the stdout dimension (holding
`exit_code` correct) and the empty-stdout mutant SURVIVES → the scenario is
flagged. Isolating dimensions is what turns "non-tautological overall" into
"sharp on every assertion it makes."

Two deliberate non-flags (learned from real scenarios), both principled — a
near-miss must genuinely *miss*:
- `stderr_equals: ""` ("assert no error output") is SHARP, not a tautology: the
  empty mutant would be the identity (== the asserted value), so it is not
  generated; whitespace/char-changed/appended near-misses all die.
- `stdout_contains: ""` is INERT: NO output can fail to contain `""`, so the
  empty mutant survives — exactly the tautology signal.

### HONEST SCOPE (do not overclaim)

The sharpness battery mutates the **observation** — it is deterministic, stdlib,
needs NO build. It proves the scenario's ASSERTION is sharp against wrong
observations. It is **NOT** full code-mutation testing of the built artifact
(mutate the app, re-run the scenarios) — that is language-specific and a heavier
future step. It also cannot catch a scenario that is weak only because its
asserted values are *jointly* trivial to produce (e.g. `exit 0` + empty output),
since each dimension is individually discriminating; that is a documented limit
of per-dimension isolation.

## 3. Decorrelated critic (the second mind)

One author model has blind spots, and two correlated minds (an author + a
builder of the same lineage) tend to miss the SAME unknown-unknowns. The
optional `roles.critic` is a SECOND, independent (different-model) agent that
adversarially reviews the AUTHORED scenario set. It sits on the VERIFIER side of
the barrier, like the author: it may see spec + behaviors + the authored
scenarios + the oracle format, and it emits a strict JSON verdict:

```
{"blocking":  [{"behavior_id","kind":"missing_class|weak_assertion|missing_case","detail"}],
 "advisories":[{"topic","detail"}]}
```

`blocking` findings drive a bounded author↔critic revision loop (`max_rounds`,
default 2): the author re-emits addressing them (barrier-safe feedback:
behavior-id + kind + the critic's detail, which is verifier-side and never
reaches the builder), the set is re-validated through all gates, and re-critiqued
until the critic is clean or the bound is hit — **fail-closed** on
non-convergence (`CRITIC_UNRESOLVED`, nothing installed). A critic that can't run
or emits an unparseable verdict also fails closed (`CRITIC_ABORTED`).

### Model distinctness (collusion + decorrelation), fail-closed

`df_config` enforces TWO inequalities on resolved (`realpath`) adapter paths:

- `realpath(critic) != realpath(builder)` — **collusion**: a critic must not
  bless scenarios its own model will build against.
- `realpath(critic) != realpath(author)` — **decorrelation**: the same model
  cannot decorrelate from itself.

A single `roles.critic.allow_same_model_ack: true` waives BOTH and is sealed
into the manifest's `critic.same_model_ack` for an auditor. The ideal is three
distinct models (e.g. author=Codex, critic=Gemini, builder=Claude); the config
enforces the two inequalities, not a specific assignment. A `roles.critic`
without a `roles.author` is refused (there is nothing agent-authored to review).

### Barrier discipline (enforced + tested)

The critic's output — the verdict, blocking findings, and `scenario_review.md` —
is CONTROL-PLANE and MUST NEVER enter the builder workspace. The loop runs at
author time (a discarded pre-run step whose scratch workdir is torn down after
extraction). `test_e2e_critic.py` asserts byte-for-byte that a converged run's
builder workspace never contains `scenarios/`, `critic.json`, or
`scenario_review.md`, and that no scenario `then` content ever reaches the
journal.

## 4. Spec-gap advisories (the visible human residual)

The critic's `advisories` are likely-MISSING REQUIREMENTS ("a production X
usually also needs auth / idempotency / pagination / rate limiting; your
behaviors declare none — confirm intended"). They are **NEVER auto-applied** —
inventing requirements would be the machine overriding human intent. Instead
they are written to `scenario_review.md` (control plane) and journaled
`CRITIC_ADVISORY` (count only), surfaced to the operator. This converts a SILENT
spec gap into a VISIBLE one — the most a machine can honestly do about the
human-input residual.

## The honest residual AFTER M42

M42 makes the machine-closable gap ~zero and the human-input gap visible. It
does NOT claim to cross these two ceilings — state them plainly:

- **Spec / behaviors fidelity** — still human input. Lever 4 makes gaps VISIBLE
  (advisories), but a machine cannot invent your intent. If the spec omits a
  requirement, no gate can conjure it; the critic can only flag the likely
  omission for a human to confirm.
- **Oracle non-functional ceiling — pushed by M43a, honestly restated.**
  **M43a** (the `when.property` kind, `references/scenario-format.md`) closes
  the fixed-example gap M42 documented: generative property / metamorphic /
  robustness(fuzz) scenarios now catch round-trip, idempotency, determinism,
  and "never crashes / honors the error contract on malformed input" bugs a
  single example can't. A property scenario's sharpness is *invariant
  discrimination* (`df_invariants.invariant_is_discriminating` — a vacuous,
  always-true invariant configuration is gate-flagged pre-build, exactly like
  an inert `then`), and property scenarios count toward class coverage like
  any other (a fuzz property is naturally `failure`/`boundary`). The barrier
  is preserved with the same discipline: the generated counterexample and the
  invariant/expected-output secret stay control-plane (feedback is
  behavior-id + `property_violated` only). Note the honest boundary — a
  candidate STEP may persist its generated INPUT into the workspace as
  ordinary state (`put {k} {v}` → `store.json`), exactly as a fixed input
  already does; that is safe because a property invariant is generic (holds
  for all inputs), so a leaked input is not gameable. What
  REMAINS out: **bounded-concurrency** scenarios (races, lost updates) are
  **M43b**, built on the same generative engine; **perf / load / scale /
  latency-SLA / real-traffic remains a separate tool** — a correctness
  oracle cannot honestly express them — permanently out of scope here.

- **Class labels are self-declared, not semantically verified.** The adequacy
  gate checks class COVERAGE *structurally* — that each behavior carries a
  scenario tagged `happy`, `boundary`, `failure` per the policy. It does NOT (and
  deliberately cannot) verify that a scenario tagged `failure` actually
  exercises a failure: a happy assertion mislabeled `class: "failure"` satisfies
  the gate. This is by design — a "failure" scenario can legitimately assert a
  specific stdout on exit 0, so a brittle label-semantics check would produce
  false rejections. The semantic correctness of a class label is the
  **author's/critic's** responsibility: for AGENT-authored scenarios the
  decorrelated critic is the backstop (it can raise `missing_class`/`missing_case`
  blocking findings when a labeled class doesn't do its job); for HUMAN-authored
  scenarios it rests on author judgment (and the recommended human review). The
  gate guarantees the SHAPE of coverage, not the intent behind each label.

So after M42 + M43a, for an oracle-expressible service, the residual reduces to
"did the human spec/behaviors capture the requirement" + "is it concurrency
(M43b) or perf/load/scale (a different tool, permanently out)" (plus the
self-declared-label caveat above, backstopped by the critic for agent-authored
runs). The human spec-fidelity residual is UNCHANGED by M43a — no generated
input can prove the spec captured intent.

## Manifest record (`adequacy`)

Every terminal that ran the gate seals an `adequacy` field: `required_classes`,
`min_per_class`, `per_behavior_class_coverage`, `under_covered`, a `sharpness`
summary (`scenarios`, `min_killed`, `weakest`), and a `critic` record
(`enabled` + the author-time `review` = rounds / blocking_resolved / advisories,
read back from `authored.jsonl`). A top-level `critic` field mirrors
`authored_by` (adapter, sha256, same_model_ack). See `references/audit.md`.

## Config

```json
"roles": {
  "builder": {"adapter": "…"},
  "author":  {"adapter": "…"},
  "critic":  {"adapter": "…", "timeout_s": 600, "allow_same_model_ack": false}
},
"scenario_adequacy": {
  "required_classes": ["happy", "boundary", "failure"],
  "min_per_class": 1,
  "critic": {"enabled": true, "max_rounds": 2}
}
```

All keys optional; see `references/config-reference.md` for defaults.
