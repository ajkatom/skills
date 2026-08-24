# M36a — Four intervention modes + single qualification state machine + phase-aware hash-chained FSM

_Coherent core slice of the approved plan's M36. Lands: (1) four distinct
intervention modes H1–H4 with the full state-transition table below; (2) the
SINGLE qualification state machine folding barrier ∧ host_isolation ∧
control_plane ∧ app_security ∧ waiver_validity into one authoritative
`qualified` with derived sub-states + distinct non-qualified codes; (3) a
versioned, phase-aware, hash-chained FSM checkpoint validated on every
resume; (4) the full (autonomy, checkpoint, tier) → mode legacy mapping,
dual-field rejection, and a migration command. DEFERRED to M36b (documented):
signed resume overrides (budget/credential-value refresh with approver
allowlist/threshold + replay protection) and spec-fork lineage (parent's
sealed artifact → child input snapshot). The attach-based WAIVER_PENDING from
M33a already works; M36a adds WAIVER_PENDING as a first-class FSM phase but
does NOT add a new interactive waiver pause (that stays attach-time)._

## Why this is security-relevant, not just ergonomics
Two concrete gaps close here:
1. **host_isolation is sealed but not enforced.** M29b seals
   `host_isolation.qualified` but the top-level `qualified` is still just
   `eff in _QUALIFYING_TIERS and app_security_qualified` — a run whose
   candidate host-isolation probe FAILED and was `--allow-downgrade`'d to
   `allow_host_read` can still seal `COMPLETE_QUALIFIED`. M36a's single SM
   makes `qualified` require host_isolation too.
2. **No fail-closed unattended contract.** Today `checkpoint:"auto"` (L5)
   simply doesn't pause; there is no explicit "any human-needed condition
   under lights-out is a deterministic terminal, never a silent proceed."
   H4 makes that a contract.

## The four modes — full state-transition table

Phases in one iteration `i`: `BUILD_i → VERIFY_i → (iterate | FINAL_EXAM →
SECURITY_GATES → SEAL)`. Cross-cutting guard conditions that can arise:
`BUDGET_ALERT`, `GATE_FAILED`, `WAIVER_NEEDED` (a standard+ gate finding with
a waiver policy in force), `QUALIFICATION_LIMITED` (a sub-state came back
false: host-isolation limited, etc.), `CAP_REACHED`, `CUSTODY_PENDING`
(enterprise).

| Condition / decision point | **H1 Directed** | **H2 Supervised** | **H3 Guarded-autonomous** | **H4 Lights-out** |
|---|---|---|---|---|
| Before each `BUILD_i` (i≥2, i.e. after first feedback) | PAUSE (approve/edit-spec/accept/abort) | run | run | run |
| After each `VERIFY_i` (not converged, i<cap) | PAUSE (checkpoint) | PAUSE (checkpoint) | run | run |
| Before `FINAL_EXAM` / seal on convergence | PAUSE (approve ship) | PAUSE (approve ship) | run | run |
| `BUDGET_ALERT` (soft ceiling) | PAUSE | PAUSE | PAUSE | **TERMINAL** `BUDGET_HALTED` (exit 3), fail-closed |
| `BUDGET` hard ceiling exceeded | TERMINAL | TERMINAL | TERMINAL | TERMINAL (all modes) |
| `GATE_FAILED` (mandatory gate, no covering waiver) | TERMINAL `SECURITY_GATE_FAILED` | TERMINAL | TERMINAL | TERMINAL (all modes; a gate failure is never "pause & fix live") |
| `WAIVER_NEEDED` (finding + waiver policy in force) | TERMINAL `SECURITY_GATE_FAILED` + waiver hint (attach out-of-band) | same | same | same (all modes — waivers are always attach-time in M36a) |
| `QUALIFICATION_LIMITED` (a sub-state false) | seal with distinct non-qualified code | same | same | same (all modes — honest terminal, never a pause that could be skipped) |
| `CAP_REACHED` | TERMINAL `CAP_REACHED` | TERMINAL | TERMINAL | TERMINAL (all modes) |
| `CUSTODY_PENDING` (enterprise) | TERMINAL `CUSTODY_PENDING` (attach out-of-band) | same | same | same (all modes) |
| Noninteractive stdin (no TTY / SDK) while a PAUSE is due | PAUSE = persist checkpoint + exit `PAUSED` (33); a human resumes later | same | (only guard PAUSEs, same handling) | H4 **never** PAUSEs, so N/A |
| Tier requirement | any qualifying tier | any | any | **hardened/enterprise only** (same gate as legacy autonomy 5) |

Notes baked into the table:
- A `PAUSE` is always the existing mechanism: write `checkpoint_iter_i.md` +
  `save_state` + journal `CHECKPOINT` + return `PAUSED` (33). Modes differ
  only in WHICH transitions pause. There is no live interactive prompt — the
  loop persists and exits, a human resumes. (This is already how "pause"
  works; M36a generalizes which points trigger it.)
- H4's defining property: **no transition ever returns PAUSED**. Every
  condition that would pause in H1–H3 is, in H4, either "run" or a
  deterministic fail-closed TERMINAL. This is what "lights-out" must mean to
  be safe — never a silent proceed past a human-needed decision, never an
  indefinite block.
- H3's defining property: runs the build/verify loop with no per-iteration
  pause, but PAUSEs at genuine guard conditions (budget soft-alert) so a
  human can intervene before spend continues — while GATE/QUALIFICATION
  outcomes are honest terminals, not pauses.

## Approach (6 tasks)

### Task 1 — `df_modes.py` (new) + config
- `INTERVENTION_MODES = ("H1","H2","H3","H4")` with human-name aliases
  (`directed/supervised/guarded/lights_out`) accepted and canonicalized.
- `pause_points(mode) -> frozenset` and predicate helpers
  `pauses_before_build(mode,i)`, `pauses_after_verify(mode)`,
  `pauses_before_ship(mode)`, `pauses_on_budget_alert(mode)` — ONE source of
  truth for the table above; the supervisor asks these, never hardcodes.
- `legacy_mode(autonomy, checkpoint) -> mode`: the full mapping —
  `(4,"pause")→H1`? No: legacy `pause` paused only AFTER verify (not before
  build, not before ship), so `(4,"pause")→H2` (supervised is the faithful
  equivalent), `(4,"auto")→H3` (autonomy 4 ran without per-iter pause but
  wasn't lights-out), `(5,"auto")→H4`, `(5,"pause")` was already contradictory
  → keep rejecting. Document each mapping with the behavioral justification;
  add compat fixtures proving an old config's observable pause behavior is
  UNCHANGED under its mapped mode.
- `df_config.py`: accept `intervention_mode` (canonicalized). **Reject dual
  fields**: if `intervention_mode` AND (`autonomy` or `checkpoint`) both
  present → `ConfigError` (name the migration command). If only legacy fields
  → map + set `cfg["_intervention_mode"]` + keep `cfg["_checkpoint"]`/autonomy
  derivations working for any other reader. H4 requires hardened/enterprise
  (reuse the autonomy-5 tier gate). Default when nothing set: `H2` (faithful
  to today's `autonomy 4 → checkpoint pause`).

### Task 2 — single qualification state machine (`df_qualify.py` new)
- `SUBSTATES = ("barrier","host_isolation","control_plane","app_security",
  "waiver_validity")`.
- `derive(manifest_fields) -> {qualified: bool, substates: {name: bool},
  code: str}` — pure function over already-computed fields:
  - `barrier` = eff tier in `_QUALIFYING_TIERS` (probe-proven isolation).
  - `host_isolation` = `manifest["host_isolation"]["qualified"]`.
  - `control_plane` = audit-signing present where required + artifact bound
    (the existing integrity conditions; wire the booleans the supervisor
    already has — do NOT invent new checks).
  - `app_security` = `app_security_qualified` (M33a).
  - `waiver_validity` = (no waiver in play) OR (a valid attestation covers
    every failing finding) — reuse M33a's result, not a re-implementation.
  - `qualified` = AND of all five. When false, `code` is the FIRST failing
    substate's distinct terminal code: `barrier`→already tier-driven,
    `host_isolation`→`HOST_ISOLATION_LIMITED`, `app_security`→
    `SECURITY_GATE_FAILED` (existing), `waiver_validity`→`WAIVER_INVALID`,
    `control_plane`→`CONTROL_PLANE_UNVERIFIED`. Deterministic precedence,
    documented.
- Seal `manifest["qualification"] = {qualified, substates, code}` at every
  terminal; the top-level `qualified` boolean becomes
  `derive(...)["qualified"]` (single source — the CONVERGED branch's
  `qualified = eff in _QUALIFYING_TIERS and app_security_qualified` is
  REPLACED by this). Non-CONVERGED terminals (CAP_REACHED, ABORTED, gate
  failed) keep `qualified=False` and gain the `qualification` field for
  auditability. This is the security fix: host_isolation now gates
  `qualified`.

### Task 3 — phase-aware, hash-chained, versioned FSM checkpoint
- Extend `save_state` to a `state_version:"0.2"` that additionally records
  `phase` (e.g. `AWAIT_BUILD_2`, `AWAIT_VERIFY_3`, `AWAIT_SHIP`) and appends
  a transition to a hash chain: each entry
  `{seq, phase, ts, prev_chain, entry_hash}` where
  `entry_hash = sha256(canonical_json({seq,phase,ts,prev_chain,bound_ids}))`
  and `bound_ids` includes the run's `artifact.object_id` (once sealed) and
  the scenario-set hash. Persist ATOMICALLY (existing `atomic_write`),
  appending to `fsm_chain.jsonl` in run_dir; the latest `entry_hash` also
  lands in the saved state so a resume can verify head-of-chain.
- On `resume`: recompute the chain from `fsm_chain.jsonl`, verify every
  `entry_hash` and `prev_chain` linkage and that the head matches the saved
  state's recorded head; ANY mismatch → refuse with a distinct
  `FSM_CHAIN_CORRUPT` stderr + exit 2 (fail-closed; this detects accidental
  corruption, an in-model integrity check — NOT a defense against a
  same-user forger, which is out of scope per the detection-grade decision;
  document that scope). `state_version:"0.1"` states (pre-M36a) resume with a
  back-compat path that skips chain validation (no chain existed) — journaled
  as `FSM_CHAIN_ABSENT_LEGACY`.
- Back-compat: every existing resume test must stay green; the chain is
  additive.

### Task 4 — supervisor wiring
- Replace the single `if cfg["_checkpoint"] == "pause" and i < max` pause
  gate with mode-driven pause points (Task 1 predicates) at: before-build
  (i≥2), after-verify, before-ship. Each pause writes the phase into the FSM
  chain + state.
- H4: assert no pause point is ever taken; the budget SOFT alert path that
  currently pauses must, under H4, become the `BUDGET_HALTED` terminal
  (fail-closed) — find the budget-alert pause (~3146) and branch on mode.
- Every terminal seals `manifest["qualification"]` via `df_qualify.derive`
  and sets `outcome`/`qualified` from it (host_isolation now folded in — a
  downgraded/limited host-isolation run seals `HOST_ISOLATION_LIMITED`,
  qualified False).
- Journal a `MODE` event at run start with the resolved mode + (if mapped)
  the legacy source.

### Task 5 — `df-migrate-config` command
- `supervisor.py df-migrate-config <control_root>` reads `config.json`, and if
  it uses legacy `autonomy`/`checkpoint`, rewrites it to the equivalent
  `intervention_mode` (validate-before-write; atomic; print a diff summary;
  refuse if dual fields already present — that's a hand-edit to resolve). Idempotent
  (already-migrated → no-op with a message). Leaves a `.bak`.

### Task 6 — tests + docs
- `test_modes.py`: the mapping table (every legacy pair → mode), dual-field
  rejection, H4 tier gate, canonicalization of aliases.
- `test_qualification.py`: `derive` truth table incl. the host_isolation gap
  (host_isolation false ⇒ qualified false ⇒ code HOST_ISOLATION_LIMITED),
  precedence ordering, each substate false in isolation.
- `test_fsm_chain.py`: chain builds + validates on resume; a corrupted
  `fsm_chain.jsonl` entry ⇒ FSM_CHAIN_CORRUPT refusal; legacy 0.1 state
  resumes.
- e2e per mode (fake builder, fast): H1 pauses before build-2 AND before
  ship; H2 pauses after verify + before ship; H3 runs straight through to
  seal with no pause but PAUSEs on a forced budget soft-alert; H4 runs to seal
  and, on a forced budget soft-alert, TERMINATES `BUDGET_HALTED` (never
  pauses). A host-isolation-downgraded standard run seals
  `HOST_ISOLATION_LIMITED`, qualified False.
- Migration e2e: an old `{autonomy:4,checkpoint:pause}` config → `H2`,
  observable pause behavior unchanged.
- Docs: `references/modes.md` (new — the table + resume workflow + H4
  fail-closed contract), `references/audit.md` (`qualification` field +
  substates + codes; FSM chain), SKILL.md (interview: pick a mode; the four
  explained in one line each; migration pointer),
  `references/prevention-grade-roadmap.md` (M36b deferrals: signed resume
  overrides, spec-fork lineage; FSM chain is corruption-detection not
  forgery-proof).

## Out of scope (M36b, documented residuals)
- Signed resume overrides (budget-ceiling raise, credential-VALUE refresh)
  with an approver allowlist/threshold + canonical payload + replay
  protection independent of the supervisor HMAC.
- Spec-fork: parent's sealed artifact object as the child run's input
  snapshot, with lineage; mandatory run-ID resume/fork selection UI +
  superseded-parent marking.
- Interactive WAIVER_PENDING pause (waivers remain attach-time; the phase
  exists in the FSM but doesn't add a new pause).

## Key decisions
- **Modes are pause-point sets over the EXISTING pause mechanism** — no new
  interactive-prompt machinery, so blast radius stays bounded and every
  existing resume path keeps working.
- **`df_qualify.derive` is the ONE place** `qualified` is computed — kills the
  drift risk of several call sites each AND-ing a different subset.
- **FSM chain is corruption-detection (in-model)**, explicitly not forgery
  resistance against a same-user process — consistent with detection-grade.
- Default mode `H2` = today's behavior; legacy configs map with unchanged
  observable pausing (compat fixtures prove it).
