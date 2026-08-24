# M42 — scenario adequacy maximization (push the machine-side gap to zero)

## Goal
Close every gap between "converged/qualified" and "production-ready" that a
MACHINE can close, so the only residual is the fidelity of the **human
inputs** (spec, behaviors, context) — and even that residual is made
**visible** rather than silent. Four levers, in increasing power:

1. **Class-typed coverage** — every behavior must be covered by happy +
   boundary + failure scenarios, not just "≥1 scenario." (Structural; kills
   happy-path-only.)
2. **Sharpness proof** — each scenario's assertion must reject a BATTERY of
   near-miss mutants, not just one synthetic garbage output. (Proves the
   checks are sharp, not merely non-tautological.)
3. **Decorrelated critic pass** — a SECOND, different-model agent adversarially
   reviews the scenario set for gaps; the author revises in a bounded loop.
   (Attacks the unknown-unknowns two correlated minds would both miss.)
4. **Spec-gap advisories** — the critic surfaces likely-missing REQUIREMENTS
   ("a production X usually also needs auth / idempotency / pagination / rate
   limiting; your behaviors declare none — confirm intended") as **advisory,
   operator-facing** output. Never auto-added (inventing requirements would be
   the machine overriding human intent) — but it converts a silent spec gap
   into a visible one, which is the most a machine can honestly do about the
   human-input residual.

**Honest residual AFTER M42 (state this in the docs, do not paper over it):**
- **Spec/behaviors/context fidelity** — still human input. M42 makes gaps
  *visible* (lever 4) but cannot invent your intent.
- **Oracle non-functional ceiling** — load/scale/latency-SLA/real-traffic
  concurrency are not expressible as input→output scenarios and stay out
  (a *tooling* boundary, not a human-input one; a later M43 could add
  property/fuzz/bounded-concurrency scenarios to push it further — perf/scale
  remains a different tool). Name this explicitly.
So after M42, for an oracle-expressible service, the residual reduces to
"did the human spec/behaviors capture the requirement" + "is it a
non-functional property the oracle can't express" — exactly the user's target.

## Design constraints (barrier + collusion)
- The critic sits on the VERIFIER side of the barrier, like the author: it may
  see spec + behaviors + scenarios; its output must NEVER reach the builder
  (same install/barrier discipline as M40).
- **Model distinctness (collusion/decorrelation):** enforce
  `realpath(critic) != realpath(builder)` (collusion — a critic must not bless
  scenarios its own model will build against) AND
  `realpath(critic) != realpath(author)` (decorrelation — the whole point is a
  second, independent mind), fail-closed, with an `allow_same_model_ack`
  escape hatch sealed into the manifest exactly like M40's author check. The
  ideal is three distinct models (e.g. author=Codex, critic=Gemini,
  builder=Claude); the config enforces the two inequalities, not a specific
  assignment.

## Approach (6 tasks)

### Task 1 — scenario `class` taxonomy + adequacy coverage gate (`df_gates.py`)
- Add an OPTIONAL scenario field `class` ∈ `{"happy","boundary","failure"}`
  (orthogonal to the existing `cohort` dev/final axis — cohort = feedback-vs-
  sealed, class = what-kind-of-case). Absent ⇒ `"happy"` (back-compat: every
  existing scenario is implicitly happy, so nothing pre-M42 breaks).
- `check_adequacy(behaviors, scenarios, policy) -> report`: per behavior,
  which of the required classes are covered. `policy` (from config, see Task 5)
  names `required_classes` (default `["happy"]` = today's behavior; agent-
  authored runs default to `["happy","boundary","failure"]`) and
  `min_per_class` (default 1). Report `under_covered = [{behavior, missing:[...]}]`.
  Gate PASSES iff empty. Keep `check_coverage` (dev/final) intact; adequacy is
  an additional gate.

### Task 2 — sharpness proof: assertion-mutant battery (`df_gates.py`)
- Replace the single-mutant `is_discriminating` with `sharpness(then) ->
  {passed: bool, killed: int, total: int, survivors: [mutant-kind]}` that runs
  a BATTERY of near-miss mutants per assertion type and requires the `then` to
  reject ALL of them:
  - CLI: off-by-one exit code, empty stdout, whitespace-only stdout, the
    expected stdout with one field dropped / one char changed / truncated,
    a superset (extra noise appended), wrong-order lines.
  - HTTP: status±1 and a couple of nearby codes, empty body, body with the
    asserted key removed / value changed / type changed (str↔int), an extra
    unexpected field, `null` where a value is expected.
  - twin: an observation with no evidence (existing), plus wrong-token /
    partial-token.
  A `then` that any mutant SURVIVES is not sharp → its id + surviving mutant
  kinds are reported. Deterministic, stdlib, no build needed (mutates the
  *observation*, reusing `evaluate_then`/`evaluate_http`). `validate_oracle`
  becomes the `passed==False` filter (back-compat: a scenario that killed the
  old single mutant but survives a new near-miss is newly flagged — that IS
  the strengthening; update fixtures faithfully). Gate on it (existing
  ORACLE_GATE_FAILED path, now battery-backed).
  NOTE clearly in docs: this proves the scenario's ASSERTION is sharp against
  wrong observations; it is not full code-mutation testing of the built
  artifact (that's language-specific + a heavier future step) — an honest,
  bounded strengthening.

### Task 3 — author role emits class-typed, sharp scenarios (`df_author.py`)
- Extend `compose_author_prompt`: require, per behavior, the `required_classes`
  set, each tagged with `class`, and instruct the author to make each `then`
  sharp (assert on scenario-specific data, cover boundaries: empty, max,
  malformed, duplicate, missing, wrong-type; cover failure: the error contract).
- Route authored scenarios through Task 1 (adequacy) + Task 2 (sharpness) in
  `validate_authored`, in ADDITION to the existing gates. Missing class or a
  non-sharp scenario ⇒ folded into the retry feedback (impoverished, barrier-
  safe: behavior-id + missing-class / survived-mutant-kind only, never a
  suggested assertion — the author must fix it, we don't hand it the answer).

### Task 4 — the decorrelated critic role (`df_critic.py` + supervisor)
- New OPTIONAL `roles.critic.adapter`. `df_critic.py`: compose a critic prompt
  (spec + behaviors + the AUTHORED scenarios + the oracle format) asking for a
  strict JSON verdict:
  `{"blocking": [{"behavior_id","kind":"missing_class|weak_assertion|
  missing_case","detail"}], "advisories": [{"topic","detail"}]}`.
  `blocking` findings drive a bounded author↔critic revision loop (the author
  re-emits addressing them; re-validated; cap N rounds, fail-closed on
  non-convergence with a clear terminal). `advisories` (likely-missing
  requirements) are NEVER auto-applied — they're written to a
  `scenario_review.md` in the control plane + journaled `CRITIC_ADVISORY`
  (count only) + surfaced to the operator, since they concern human intent.
- The critic sees scenarios (verifier side); its output is control-plane and
  MUST never enter the builder workspace (assert, like M40). Enforce the
  model-distinctness inequalities (Task's design constraint) in df_config.
- Journal `CRITIC_REVIEW` (rounds, blocking count resolved, advisory count) —
  content-free re: assertions, barrier-safe.

### Task 5 — config + manifest surface (`df_config.py`, supervisor)
- Config `scenario_adequacy: {required_classes:[...], min_per_class:int,
  critic:{enabled:bool, max_rounds:int}}` → `cfg["_adequacy"]`. Defaults:
  absent ⇒ back-compat (`required_classes:["happy"]`, critic off). For an
  AGENT-AUTHORED control root (M40 author role present), default
  `["happy","boundary","failure"]` + critic enabled if `roles.critic` set.
- `roles.critic` validation + the two model-distinctness inequalities +
  `allow_same_model_ack` (sealed into manifest `critic` field like M40's
  `authored_by`).
- Manifest `adequacy = {required_classes, per_behavior_class_coverage,
  sharpness:{scenarios, min_killed, weakest}, critic:{rounds, blocking_resolved,
  advisories}}` sealed at every terminal that ran the gate. This is the
  auditable "how thorough were the tests" record.
- The adequacy + sharpness gates run in the EXISTING M7 pre-build gate slot
  (before any build) for BOTH human- and agent-authored scenarios; the critic
  loop runs at author time (agent-authored only).

### Task 6 — tests + docs + honest-residual writeup
- `test_adequacy.py`: class taxonomy default; adequacy gate under/over-cover;
  policy defaults (human vs agent-authored).
- `test_sharpness.py`: battery kills a near-miss the old single-mutant missed;
  a genuinely sharp scenario passes; per-mutant survivor reporting.
- `test_critic.py` + `test_e2e_critic.py`: a stub critic emitting blocking
  findings drives an author revision that then passes; advisories surface to
  `scenario_review.md` + journal, never enter the workspace; model-distinctness
  rejection (critic==builder, critic==author) + ack path; bounded-round
  fail-closed.
- Barrier regression: builder workspace still never contains scenarios/ or
  scenario_review.md; a run with adequacy+critic is byte-for-byte barrier-clean.
- Docs: `references/scenario-adequacy.md` (NEW — the four levers, the class
  taxonomy, the sharpness battery, the critic role + decorrelation rationale,
  and THE HONEST RESIDUAL: human spec/behavior fidelity + the oracle non-
  functional ceiling, with a pointer to a possible M43 property/fuzz/
  concurrency expansion and an explicit "perf/scale is a different tool"),
  `references/authoring.md` (class-typed authoring + adequacy policy),
  `references/audit.md` (`adequacy` manifest field), `references/role-adapters.md`
  (critic role + the two inequalities), `references/config-reference.md`,
  SKILL.md (offer adequacy policy + critic in the interview), README/OVERVIEW
  (one line: agent-authored scenarios can now be class-typed, sharpness-proven,
  and adversarially critiqued by a second model — narrowing the gap to human
  spec fidelity + non-functional properties the oracle can't express).

## Out of scope (documented, honest)
- Full code-mutation testing of the BUILT artifact (mutate the app, re-run
  scenarios) — language-specific + heavy; the sharpness battery is the
  bounded, deterministic substitute.
- Non-functional oracle expansion (property/fuzz/bounded-concurrency
  scenarios) — a genuinely valuable follow-on (M43) that would push the oracle
  ceiling; perf/scale/real-traffic remains a separate tool, out of scope.
- Auto-adding requirements the critic infers (would override human intent) —
  advisories are surfaced, never applied.

## Key decisions
- `class` is a new, back-compat-defaulted axis (absent ⇒ happy); adequacy +
  sharpness are ADDITIONAL gates, never a weakening of existing ones.
- Sharpness mutates the OBSERVATION (deterministic, no build) — a bounded,
  honest strengthening, explicitly not full code-mutation testing.
- The critic is a decorrelated second model (critic≠builder for collusion,
  critic≠author for decorrelation), barrier-disciplined; blocking findings
  gate, advisories only inform (human owns intent).
- The residual is stated, not hidden: M42 makes the machine-closable gap ~zero
  and the human-input gap VISIBLE; it does not claim to cross the oracle's
  non-functional ceiling.
