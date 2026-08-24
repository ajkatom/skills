# M61 — attempt-aware + rollback-aware ship crash recovery (Codex R6 DF-R6-01/02/09)

Branch `dark-factory-m61-ship-recovery`, worktree `../skills-worktree-m61`. The two High
crash-recovery defects + the double-seal. Implemented by hand; MANDATORY opus review (interlocks
with M56b evidence authentication).

## The defects
- **R6-01 (High):** `_unresolved_ship_action` matches results to intents by the STABLE
  idempotency_key. A reconciled retry reuses the same key, so an OLD `reconciled_unknown` result
  resolves a NEW intent → a second crash silently re-fires the action with no fresh reconcile.
- **R6-02 (High):** `_ship_completed_actions` treats every historical `ok` as permanently done and
  ignores later `SHIP_ROLLED_BACK`; re-entry skips an action that was actually undone and can seal
  SHIPPED with that effect absent. Also a crash after `SHIP_ROLLBACK_INTENT` before its result is
  not classified unknown.
- **R6-09 (Medium):** `_ship_phase` calls `_seal_ship_result` unconditionally, then AGAIN inside the
  SHIP_EVIDENCE_PENDING branch → one event seals two records/anchors/off-box versions.

## Design — one ordered-pass recovery state
Add `attempt_id` (uuid hex) to every dispatch: journaled on SHIP_ACTION_INTENT and carried onto its
SHIP_ACTION_RESULT (all statuses), and on SHIP_ROLLBACK_INTENT / SHIP_ROLLED_BACK /
SHIP_ROLLBACK_FAILED. A result resolves the intent with the SAME attempt_id (not the idk). Legacy
journals (no attempt_id) fall back to idk matching.

`_ship_action_recovery_state(run_dir)` walks the journal IN ORDER and returns:
- `applied`: action → the data of its LATEST `ok` result NOT followed by a `SHIP_ROLLED_BACK` for
  that action (the currently-applied set).
- `unresolved_forward`: the latest SHIP_ACTION_INTENT whose attempt_id has no SHIP_ACTION_RESULT, else None.
- `unresolved_rollback`: the latest SHIP_ROLLBACK_INTENT with no SHIP_ROLLED_BACK/SHIP_ROLLBACK_FAILED
  for that attempt, else None.

Thin wrappers: `_unresolved_ship_action` → forward; `_ship_completed_actions` → `applied` keys;
`_ship_completed_action_facts` → derived from `applied` (so the auth set == the skip set, rolled-back
actions excluded from both). `_ship_phase` treats an unresolved rollback as SHIP_UNKNOWN_OUTCOME too
(reconcile/abort), and the reconcile RESULT write carries the dangling intent's attempt_id so it can
never resolve a future retry.

Remove the redundant second `_seal_ship_result` (R6-09) — the unconditional seal already covers every
outcome.

## Tests (test_m61_ship_recovery.py)
- R6-01: intent K(a1) → reconciled_unknown K(a1) → new intent K(a2), crash → `_unresolved_ship_action`
  returns the a2 intent (NOT None); a full two-crash-after-reconcile flow returns SHIP_UNKNOWN_OUTCOME
  again, never a silent third dispatch.
- R6-02: prepare ok → deploy failed → SHIP_ROLLED_BACK prepare → `_ship_completed_actions` excludes
  prepare; a crash-after-rollback re-entry re-runs prepare and cannot seal SHIPPED with it absent.
- rollback unknown: SHIP_ROLLBACK_INTENT with no result → unresolved_rollback → SHIP_UNKNOWN_OUTCOME.
- R6-09: a SHIP_EVIDENCE_PENDING seals EXACTLY one record/one terminal journal event/one anchor.
- back-compat: a legacy journal (no attempt_id) still recovers correctly by idk.
- regression: existing M49/M53/M56/M56b ship-integrity + evidence-auth tests stay green (facts==applied).

Pipeline: opus adversarial review (crash-recovery + evidence-auth interlock) → fix → merge + full gate.
