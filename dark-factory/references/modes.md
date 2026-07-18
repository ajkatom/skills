# Intervention modes (H1–H4)

M36a replaces the two-axis `autonomy` + `checkpoint` knobs with ONE
`intervention_mode` that names *which transitions pause*. A mode is a
**pause-point set over the existing pause mechanism** — there is no new
interactive-prompt machinery. A "pause" is always the same four steps it has
always been: write a checkpoint report, `save_state`, journal `CHECKPOINT`, and
return exit **10 (PAUSED)**; a human later `resume`s.

## The four modes

| Mode | Alias | Before build i (i≥2) | After non-converged verify (i<cap) | Budget cap reached | Tier |
|---|---|---|---|---|---|
| **H1** | `directed` | **PAUSE** | **PAUSE** | **PAUSE** | any qualifying |
| **H2** | `supervised` | run | **PAUSE** | **PAUSE** | any qualifying |
| **H3** | `guarded` | run | run | **PAUSE** | any qualifying |
| **H4** | `lights_out` | run | run | **TERMINAL `BUDGET_HALTED`** (exit 3) | **hardened/enterprise only** |

- **H2 is the default** and reproduces legacy `checkpoint:"pause"` (autonomy 4)
  byte-for-byte: it pauses only after a non-converged verify.
- **H3** reproduces legacy `checkpoint:"auto"`: it runs the loop straight
  through but still PAUSEs on a budget guard so a human can raise the cap.
- **H1 directed** adds a *before-build* gate: after each checkpoint the human
  explicitly approves (or edits `spec.md`, or aborts) before the next builder
  call is spent. This is the only mode that gates rebuilds.
- **H4 lights-out** never returns PAUSED. Every condition that would pause in
  H1–H3 is, under H4, either "run" or a deterministic fail-closed **TERMINAL**.
  A budget cap becomes `BUDGET_HALTED` (exit 3) instead of a pause: a lights-out
  run is only safe if it never silently proceeds past a human-needed decision
  **and** never blocks forever waiting for a human who isn't watching. H4 reuses
  legacy autonomy-5's tier gate (hardened/enterprise only).

Config-time errors that always apply: a mandatory security gate that failed
with no covering waiver, a hard budget/CAP terminal, and a
`QUALIFICATION_LIMITED` sub-state (e.g. host-isolation limited) are TERMINALS in
**every** mode — never a pause you could skip.

## The before-ship gate (H1/H2) — M36b

On convergence, **H1 and H2 pause for a human ship approval** before the
artifact is sealed. The pause fires only **after** the final exam PASSES, the
security gates PASS, and the frozen artifact re-verifies by identity — the run
is one approval away from `COMPLETE_QUALIFIED`. H3 (guarded) and H4 (lights-out)
never pause here.

M36a deferred this because the existing pause mechanism resumes by *rebuilding*,
and a ship pause happens *after* the artifact is already frozen — resuming it
must seal *without* re-dispatching a paid builder call (the M35 crash-dispatch
invariant). M36b adds the **seal-reentry** resume path to do exactly that:

- **Pausing.** In the converged branch, before sealing, the supervisor persists
  an `AWAIT_SHIP` FSM checkpoint carrying the converged iteration, the sealed
  final-exam result, and the frozen `artifact.object_id`; it appends an
  `AWAIT_SHIP` transition to the hash chain (binding that object_id) and writes
  `checkpoint_ship.md`. `state.json` records `phase: "AWAIT_SHIP"` +
  `ship_meta`.
- **`resume --decision continue`.** Re-validates the FSM chain, **re-verifies
  the frozen object matches its sidecar** (fail-closed on drift), **re-runs the
  security gates over the frozen object**, and seals via the SAME
  `df_qualify.derive` path — **never entering the build loop**, so the builder
  call count is unchanged (`SHIP_RESUME` is journaled). The artifact is
  immutable, so re-running the gates is cheap; re-running (rather than trusting
  the persisted verdict) is the honest fail-closed choice.
- **`resume --decision abort`.** Seals a distinct **`SHIP_DECLINED`** terminal
  (qualified `False`) that still binds the frozen artifact object (the declined
  candidate stays auditable) — not `ABORTED_BY_HUMAN`.

## The ship phase in H4 lights-out (M41)

The before-ship gate above governs whether to **enter** shipping. The *ship
phase itself* (M41, `references/ship.md`) — running operator ship actions on the
qualified artifact — runs the same way in every mode; the difference is only the
signature gate on irreversible actions:

- **Reversible actions run straight through, unattended**, in H4 exactly as in
  H1–H3. After a qualified seal (H3/H4 straight-through, or the H1/H2
  before-ship approval), reversible ship actions execute with no further human
  step.
- **An irreversible (`reversible:false`) action never runs unattended.** The
  FIRST irreversible action with no covering signed release approval seals
  **`SHIP_APPROVAL_PENDING`** — the run STAYS `qualified`, nothing irreversible
  ran, and the phase does not block. A `df-release attach` + a subsequent
  `supervisor.py ship … --run-dir …` then runs the gated action. This holds in
  H4: **lights-out does the *doing*, but a human is accountable for an
  irreversible prod action via a one-time signature, never by running the
  command.** (`SHIP_APPROVAL_PENDING` is the ship-phase analogue of enterprise's
  `CUSTODY_PENDING`: a fail-closed "authorized human input required" terminal
  that never silently proceeds and never blocks.)

Under **H1** a converging run therefore pauses up to three times per final
cycle: `AWAIT_VERIFY_i`, `AWAIT_BUILD_{i+1}`, then `AWAIT_SHIP`. Under **H2**
(the default) it pauses at `AWAIT_VERIFY_i` and then `AWAIT_SHIP`. This is a
deliberate, documented behavior change from M36a: a supervised mode now signs
off the ship.

**Credential-value refresh needs no override or special handling here:** resume
re-resolves credentials on *every* resume under the sealed credential policy, so
the ship-resume already picks up a changed secret value automatically.

## Resume workflow

Identical to before. At a pause:

- `checkpoint_iter_N.md` — an after-verify checkpoint (H1/H2).
- `checkpoint_build_N.md` — an H1 before-build checkpoint (review the prior
  feedback before approving the next build).
- `checkpoint_ship.md` — an H1/H2 before-ship checkpoint (approve the converged,
  frozen artifact before it seals). `continue` seals without rebuilding; `abort`
  seals `SHIP_DECLINED`.

Then one of:

```
supervisor.py resume --control-root <cr> --decision continue   # approve / build again / seal
supervisor.py resume --control-root <cr> --decision accept     # stop, waived/unverified
supervisor.py resume --control-root <cr> --decision abort      # (from AWAIT_SHIP: SHIP_DECLINED)
```

Under **H1**, a converging run pauses up to three times per final cycle: after
the verify (`AWAIT_VERIFY_i`), before the approved rebuild (`AWAIT_BUILD_{i+1}`),
and before the ship (`AWAIT_SHIP`). The before-build approval is one-shot (a
`build_approved_through` cursor in the saved state), so resuming an approved
build does not re-pause it.

## Migrating a legacy config

A config may use the new `intervention_mode` **or** the legacy
`autonomy`/`checkpoint` pair, never both (specifying both is a hard
`ConfigError`). To convert an old config:

```
supervisor.py df-migrate-config <control_root>
```

It maps `(4,"pause")→H2`, `(4,"auto")→H3`, `(5,"auto")→H4` (and rejects the
contradictory `(5,"pause")`), rewrites `config.json`, leaves a `config.json.bak`,
and is idempotent. The mapped mode's observable pause behavior is unchanged from
the legacy config's.
