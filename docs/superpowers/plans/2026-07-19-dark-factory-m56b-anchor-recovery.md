# M56b — ship anchor-failure recovery (Codex R5 DF-R5-02, High)

The last open R5 item. Two fail-closed BRICKS become first-class recoverable states with an
authenticated evidence-only retry. Real actions are NEVER re-run.

## The two bricks (auditor's repros)
1. **Per-action:** `df_ship.run_actions` calls the commit hook (signs the per-action completion
   token) but IGNORES its return; a failed anchor still journals `status:"ok"`. On re-entry,
   `_authenticate_ship_actions` finds an ok-line with NO signed token → permanent refusal
   (exit 2) even though the action really ran. Groundwork already in place (M56):
   `_make_ship_action_committer._commit` RETURNS `_anchor_ship_local`'s status.
2. **Terminal:** `_seal_ship_result` writes non-success terminals (SHIP_FAILED etc.) then ignores
   the anchor status; an unanchored terminal record permanently refuses re-entry. No
   evidence-only repair path exists for non-SHIPPED terminals (SHIPPED has _ship_audit_retry).

## Design
- **A (per-action):** in `run_actions`, consume the commit hook's status. On anchor failure:
  journal `SHIP_ACTION_EVIDENCE_PENDING` (distinct state, NOT `ok`), STOP the loop (no further
  actions — the evidence chain must not fall behind reality), return
  `outcome: SHIP_EVIDENCE_PENDING` (constant landed in M56) with completed records + the
  evidence-pending action name. Supervisor seals a RECOVERABLE `SHIP_EVIDENCE_PENDING` ship
  record (distinct exit code, like SHIPPED_AUDIT_PENDING's 12) — never SHIPPED, never a brick.
- **B (terminal):** `_seal_ship_result` returns anchor_status (already does for some paths —
  verify); `ship_cmd` propagates EVERY terminal-anchor failure into the same recoverable
  pending mechanism (a `<kind>_anchor_pending` marker or the sealed record's own field) instead
  of silently persisting an unauthenticated terminal.
- **C (evidence-only retry):** on re-entry of a `SHIP_EVIDENCE_PENDING` run: authenticate
  everything that CAN be (existing signed per-action tokens for earlier actions), re-sign the
  MISSING completion token(s) from the journaled SHIP_ACTION_INTENT facts (intent is written
  fsync'd PRE-exec; its facts — toolchain/reversible/approval_ref/idk — are what the token
  binds) + the journaled RESULT exit, then continue the normal action loop from the next
  not-yet-run action (or seal, if all ran). For an unanchored TERMINAL: re-anchor the
  reconstructed terminal record (reconstruct-from-facts, mirroring _ship_audit_retry — never
  copy a writable pending blob, DF-R5-01 discipline).
- **Honesty note:** a token re-signed at RETRY time authenticates journal facts that sat
  unauthenticated during the outage window. Same-user tamper in that window is detectable only
  via the journal-vs-chain gap — document as detection-grade (consistent with the threat model
  everywhere else), and journal an explicit `SHIP_EVIDENCE_RESIGNED` event naming the window.

## Tests
- auditor repro 1: prep action + failing signer → SHIP_EVIDENCE_PENDING (not ok/brick); signer
  recovers → evidence-only retry re-signs, then the irreversible action proceeds through its
  normal approval gate; deploy runs exactly once.
- auditor repro 2: SHIP_FAILED terminal-anchor failure → recoverable; retry re-anchors, re-entry
  returns the honest terminal (still SHIP_FAILED, exit 3-class), never 2-brick.
- forged ok-line during the outage window → refused (no matching intent/token, journal-chain gap).
- anchor fails on action k of n → actions k+1..n NEVER ran before retry.
- SHIPPED path untouched (regression: existing M53/M56 tests).

Pipeline: implement by hand in ../skills-worktree-m56b → opus adversarial review (MANDATORY —
ship-evidence integrity) → fix + re-verify via reviewer repros → merge + full-suite gate.
