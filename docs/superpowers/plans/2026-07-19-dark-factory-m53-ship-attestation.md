# M53 — DF-R4-03 + DF-R4-04: signed-ship attestation integrity

R4 re-audit, the two deepest remaining findings. Both are: a `SHIPPED`
result can be locally authoritative WITHOUT the required signed/off-box
evidence actually existing. M49 fixed the sink-status→outcome mapping; these
are the residual ordering + receipt-authentication + local-anchor-failure
gaps. Principle: **local `SHIPPED` must NEVER be authoritative before the
required off-box evidence succeeds, and the receipt proving it must not be
locally forgeable.**

## DF-R4-04 (High) — crash window + locally-forgeable receipt

**Ordering defect (`supervisor.py:7203-7222`).** `_seal_ship_result(...)`
writes `ship_result.json` with `SHIPPED`, locally chain-anchors it, AND pushes
off-box — all in one call — and ONLY THEN (7207) does the caller downgrade to
`SHIPPED_AUDIT_PENDING` if the push failed. A crash in that window leaves a
signature-valid local `SHIPPED` with no successful sink. Re-entry sees
`SHIPPED` and returns 0. (`_anchor_ship_record` also appends the local
`SHIPPED` chain entry BEFORE it attempts the sink — same inversion in the
audit-only retry.)

**Forgeable receipt (`_sink_receipt_bound` 1566-1583; `df_audit_sink.push`
77-85).** Verification accepts a receipt whose `body_sha256 ==
sha256_str(att_text)` — body_sha256 is LOCALLY computable, so a same-user
attacker fabricates the whole `*_sink_receipt.json`. `push` DOES capture a
server-returned `receipt` when the sink provides one, but falls back to a
local `sha256(body)` and verification never requires the server value.

**Fix — push-first, then commit; require a server-authentic receipt:**
- Restructure the ship seal so that when a REQUIRED sink is configured:
  1. actions run; build the FINAL canonical `SHIPPED` record bytes;
  2. push those exact bytes off-box FIRST;
  3. **only on a push that returns a SERVER-issued receipt** → write+anchor
     the local `SHIPPED` record + persist the receipt bound to those bytes;
  4. on push failure → seal `SHIPPED_AUDIT_PENDING` DIRECTLY (no interim
     authoritative local `SHIPPED` is ever written/anchored). No crash window
     in which a local `SHIPPED` exists without the required evidence.
- `df_audit_sink.push`: distinguish a SERVER-issued receipt from the local
  fallback — return `{"receipt": ..., "server_issued": bool, ...}`
  (`server_issued=True` only when the server actually returned a `receipt`
  field; the sha256 fallback is `server_issued=False`). For s3-objectlock,
  the server-issued proof is the returned `VersionId`/ETag (+ object-lock
  retention confirmation where available) — capture it; `server_issued=True`
  only if the store returned a version/etag.
- `_sink_receipt_bound` (and the ship-verify path): for a REQUIRED sink,
  require `server_issued is True` AND (best-effort, when reachable) a READBACK
  that the anchored object exists with the same bytes/version — a
  locally-forged receipt (no server value, or a value the sink can't confirm
  on readback) is REJECTED. Keep the body_sha256 binding as the
  bytes-match check, but it is no longer SUFFICIENT alone for a required sink.
  Document honestly: a sink kind that cannot return a server-authentic receipt
  cannot satisfy `required:true` fail-closed (reject at config or at ship with
  a clear reason) — detection-grade rests on the off-box trust domain, so a
  purely-local receipt is not evidence.
- The audit-only retry (`_ship_audit_retry`, `_anchor_ship_record`): same
  order — push off-box FIRST, and only on a server-issued receipt commit the
  local `SHIPPED` chain entry + flip the record to `SHIPPED`. A still-failing
  or non-server-authentic push keeps `SHIPPED_AUDIT_PENDING`.

## DF-R4-03 (High) — local signed-anchor failure still reports SHIPPED

`_anchor_ship_record` catches audit-key + chain-append failures, warns, and
CONTINUES; it uses `load_or_create_key` (can mint a REPLACEMENT key mid-ship,
corrupting the chain); and `_seal_ship_result` returns only the SINK status,
so a local-anchor failure with no required-sink failure is not propagated —
the caller returns `SHIPPED`/0 with no signed local anchor.

**Fix:**
- `_anchor_ship_record` returns a LOCAL-ANCHOR status
  (`anchored` / `anchor_failed`) distinct from the sink status; use
  `df_audit.load_key` (NEVER `load_or_create_key`) for an established signed
  run — a missing key after an action is a fail-closed pending state, never a
  new key. `_seal_ship_result` returns `(record, anchor_status,
  local_anchor_status)`.
- In `_ship_phase`: after an action ran, if signing is on and the required
  local signed anchor cannot be committed → seal `SHIPPED_AUDIT_PENDING`
  (evidence incomplete), return the distinct `SHIP_AUDIT_PENDING` (=12), never
  `SHIPPED`/0. The idempotent retry then re-attempts the anchor (with
  `load_key`, fail-closed) + the off-box push, finalizing `SHIPPED` only when
  BOTH the local signed anchor and the server-authentic off-box receipt exist.

## Tests (`tests/test_m53_ship_attestation.py` + extend `test_m49_ship_integrity.py`)
- **Crash-window (DF-R4-04):** simulate a crash AFTER a failed required-sink
  push but where the OLD code would have left a local `SHIPPED`; assert the new
  order NEVER writes an authoritative local `SHIPPED` before the push succeeds
  (the on-disk record after a failed push is `SHIPPED_AUDIT_PENDING`, and no
  chain entry anchors a `SHIPPED` record), and re-entry does NOT return 0.
- **Forged receipt (DF-R4-04):** a `SHIPPED_AUDIT_PENDING` run + a
  hand-written `ship_sink_receipt.json` with a correct local `body_sha256` but
  NO server-issued value → verify/re-entry REFUSES to report fully-shipped
  (the exact auditor repro: `forged_receipt_accepted_rc` must be nonzero now).
  A genuine server-issued receipt (stub sink returns `{"receipt": "..."}`) →
  finalizes SHIPPED/0.
- **Local-anchor failure (DF-R4-03):** signing on, `load_key` made to fail
  only AFTER an action ran → seal `SHIPPED_AUDIT_PENDING`/12, NOT `SHIPPED`/0;
  no replacement key created (assert the key file is unchanged/absent);
  restore + retry → SHIPPED once anchor + receipt both succeed. Prove the
  action ran exactly once across the whole sequence (counter file).
- Superset: M41/M44/M49 ship invariants intact (sealed-bytes materialization,
  per-action anchoring authenticated on re-entry, unresolved-intent exit 11,
  rollback-in-reverse, cred redaction, `qualified` never re-opened, ship_ws
  cleanup on every path). Absent-ship-block byte-identical. Runs with NO sink
  (standard non-enterprise) unaffected.

## Rules
Fail CLOSED; real `raise`/return-nonzero, never bare `assert` (suite runs
under `python -O`). SUPERSET — every existing ship invariant stays; you ADD
the ordering inversion, the server-authentic-receipt requirement, and the
local-anchor-failure pending state. Deterministic tests (stub actions +
an in-process toggle sink that can return/withhold a server receipt and
succeed/fail on demand, mirroring the M49 test sink; no real infra/paid).
Full suite green (baseline current main 1917 passed, 27 skipped). Do NOT git
commit — leave dirty for adversarial review. This is the deepest ship-security
change — expect a hard opus review (crash windows, receipt forgery,
double-run, chain consistency).

## Out of scope (later R4 milestones)
- DF-R4-05/06/07 modes/tiers/adapters → M54.
- DF-R4-08/09/10/11 evidence + doc honesty → M55.
