# M56 — ship-evidence integrity + recovery (Codex R5 DF-R5-01/02/07/08)

The critical R5 cluster. Root theme (same as R4's DF-R3-02/03): the ship
phase's SIGNED evidence must (a) reflect only AUTHENTICATED facts, never a
copy of a writable blob, and (b) recover safely — not brick — when the
evidence-write (anchor/sink) itself transiently fails.

## DF-R5-01 (High) — editable pending evidence laundered into signed SHIPPED
`_ship_audit_retry` (supervisor.py ~7347) does `shipped = dict(prior)` — it
copies the ENTIRE unanchored, writable `SHIPPED_AUDIT_PENDING` record and
rewrites only `outcome`/`ts`, then push+anchor+SIGNs those bytes.
`_pending_ship_authenticated` (~7193) authenticates only the action-NAME set
(via signed per-action tokens), not the record's `artifact_object_id`, action
exit codes, or `toolchain`. So a control-root writer edits those fields in a
legitimately-produced pending record (keeping the authenticated action names +
`status:ok`) and the retry blesses the forged record — the signed chain then
attests a lie about which artifact shipped / what ran. (M53 closed the
action-SET laundering; this is the residual: every OTHER pending field is
unauthenticated.)

Fix — NEVER copy the pending blob; RECONSTRUCT the final SHIPPED record from
authenticated facts:
- The final record's fields must derive ONLY from signed/authenticated
  sources: `artifact_object_id` from the sealed MANIFEST (already
  HMAC/hash-bound), the per-action results (name, exit status, `toolchain`)
  from the SIGNED per-action journal tokens (the tokens must therefore COMMIT
  the exit status + toolchain identity, not just "action ran ok" — extend the
  per-action commit payload to bind exit + toolchain sha256), and the ship
  metadata from the run's authenticated state. Build the SHIPPED record from
  those, ignoring any field present only in the writable pending file.
- If a field cannot be reconstructed from an authenticated source, fail closed
  (distinct refusal), never fall back to the pending file's value.
- `_pending_ship_authenticated` additionally rejects a pending record whose
  reconstructible fields DISAGREE with the authenticated facts (defense in
  depth) — but authority is the reconstruction, not the file.
- Regression: the auditor's exact repro (run one action, force the final
  anchor to fail → legit pending, restore key, EDIT object_id/exit/toolchain
  keeping the action name+ok, retry) → the finalized SHIPPED record carries the
  AUTHENTICATED object_id/exit/toolchain (NOT the edited values), or refuses;
  the forged values never reach the signed/off-box bytes. Must fail before the
  fix, pass after.

## DF-R5-02 (High) — anchor failures brick recovery
Two paths:
1. `df_ship.run_actions` calls the per-action commit hook BEFORE journaling
   `status:ok`, but IGNORES the hook's return (df_ship.py ~341-348;
   supervisor.py ~7103). A failed per-action anchor still journals `ok`, so
   re-entry's `_pending_ship_authenticated` later refuses (no signed token for
   that action) → permanent brick after a real reversible action ran.
2. `_seal_ship_result` writes non-success terminal records (SHIP_FAILED) BEFORE
   anchoring and ignores the anchor status (~7339-7344); a failed terminal
   anchor → unauthenticated terminal → re-entry refuses (exit 2), no
   evidence-only repair path.

Fix:
- Make the per-action commit hook's return a FIRST-CLASS result: if the anchor
  fails, do NOT journal `status:ok`; instead journal a distinct
  `SHIP_ACTION_ANCHOR_FAILED` (the action DID run — record that, value-free)
  and stop, sealing a distinct RECOVERABLE state (e.g. `SHIP_EVIDENCE_PENDING`,
  exit 12) rather than a bricking `ok`-without-token.
- Propagate every TERMINAL-record anchor status (SHIP_FAILED, SHIPPED_AUDIT_
  PENDING, SHIP_APPROVAL_PENDING): a failed anchor → the same recoverable
  pending state, never a silently-unauthenticated terminal.
- Provide an AUTHENTICATED evidence-only retry: re-entering a
  SHIP_EVIDENCE_PENDING run re-attempts ONLY the anchor/push of the ALREADY-RUN
  actions' authenticated facts (reconstructed per R5-01), NEVER reruns a real
  action, and finalizes on success. Reuse M53's push-first/positive-readback
  discipline.
- Regressions: the two auditor repros (per-action anchor fail → approval-resume
  no longer bricks, recovers after key restore; terminal SHIP_FAILED anchor
  fail → recoverable, not exit-2 brick).

## DF-R5-07 (Medium) — required S3 ship evidence can't be idempotently re-verified
`_sink_readback` implements GET verification only for `http-append`;
`s3-objectlock` returns `None` (supervisor.py ~1646). M53 requires a POSITIVE
readback for a required sink on re-entry, so an S3-backed SHIPPED can never
positively re-verify → every re-entry re-pushes, and if S3 is briefly down the
completed ship flips to audit-pending/exit 12.

Fix: implement S3 Object-Lock readback — GET the object by the recorded
version-id/key, verify the returned bytes' sha256 == the receipt's
`body_sha256` and the ETag/version binding (and, where available, the
Object-Lock/retention facts). A positive match satisfies the required-receipt
check idempotently; a genuine mismatch fails closed. Do NOT weaken the
positive-confirmation rule. If S3 credentials/SDK are unavailable in the
environment, the readback is honestly inconclusive (stays pending) — but a
REACHABLE S3 with the object present must confirm. Test with a stub S3
endpoint (mirror the http-append stub-sink tests; no real AWS).

## DF-R5-08 (Medium) — torn ship journal raises an uncaught exception
`_ship_journal_events` (supervisor.py ~6725) lets malformed JSON raise;
`ship_cmd` (~7676) doesn't catch it → a truncated trailing line (natural on
power loss) crashes with `JSONDecodeError`.

Fix: parse the ship journal tolerantly — a SINGLE malformed TRAILING partial
line (the classic torn append) is treated as a narrowly-defined recoverable/
unknown tail (documented), while malformed content on an EARLIER complete line
is corruption → a controlled non-zero refusal (distinct status + diagnostic),
NEVER an uncaught exception. Add tests: a `{"ts":`-truncated tail → controlled
outcome; a corrupt interior line → controlled refusal.

## Rules
Fail CLOSED; real `raise`/return-nonzero, never bare `assert` (suite under
`python -O`). SUPERSET: preserve every M41/M44/M49/M53 ship invariant
(push-first, positive readback, per-action reserve-before, rollback-in-reverse,
cred redaction, ship_ws cleanup, exactly-once, qualified-never-reopened).
Absent-ship-block + no-sink standard runs byte-identical. Deterministic tests
(stub actions/sinks; no real AWS/docker/paid). Full suite green (baseline
current main 1944 passed, 27 skipped). NO git commit — leave dirty for review.

**Reviewer instruction (critical):** attack the GENERAL CLASS, not just the
reported repro. For R5-01 specifically: try to get ANY unauthenticated field
(not only the ones the audit edited) from a writable pending record into the
signed/off-box final bytes. For R5-02: try to brick a recovery, or to make the
evidence-only retry rerun a real action or finalize on forged facts.
