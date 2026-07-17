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

## DEFERRED: the before-ship gate

The original plan sketched a *before-ship* PAUSE (approve the artifact before
sealing) for H1 and H2. M36a **defers** it — no mode pauses before ship — for
two reasons:

1. **Back-compat.** A before-ship pause on H2 (the default) would fire a second
   pause on every converging run, changing the observable behavior of the whole
   converge-after-resume test corpus. The plan's own mapping note ("legacy
   `pause` paused only after verify — not before build, not before ship") and
   the hard back-compat mandate both forbid this.
2. **The pause mechanism.** The existing mechanism resumes by advancing the
   iteration and rebuilding. A ship-approval pause happens *after* the converged
   artifact exists, so resuming it must seal *without* rebuilding — otherwise it
   re-dispatches a paid builder call, violating the crash-dispatch invariant
   ("resume never silently re-dispatches"). Supporting that cleanly needs
   seal-reentry machinery beyond a pause-point set.

The `AWAIT_SHIP` phase and the `pauses_before_ship()` predicate exist (they
return False everywhere) so a future milestone can enable the gate in one place
once seal-reentry is designed.

## Resume workflow

Identical to before. At a pause:

- `checkpoint_iter_N.md` — an after-verify checkpoint (H1/H2).
- `checkpoint_build_N.md` — an H1 before-build checkpoint (review the prior
  feedback before approving the next build).

Then one of:

```
supervisor.py resume --control-root <cr> --decision continue   # approve / build again
supervisor.py resume --control-root <cr> --decision accept     # stop, waived/unverified
supervisor.py resume --control-root <cr> --decision abort
```

Under **H1**, a converging run pauses twice per cycle: once after the verify
(`AWAIT_VERIFY_i`) and once before the approved rebuild (`AWAIT_BUILD_{i+1}`).
The before-build approval is one-shot (a `build_approved_through` cursor in the
saved state), so resuming an approved build does not re-pause it.

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
