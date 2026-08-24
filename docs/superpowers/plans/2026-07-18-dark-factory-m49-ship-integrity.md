# M49 — ship-phase audit integrity (DF-R3-02, DF-R3-03, DF-R3-06)

Codex re-audit #06 ship-phase findings. All in `_ship_phase` /
`_seal_ship_result` / `_anchor_ship_record` (`scripts/supervisor.py` ~6595-6790)
+ `df_ship.py`. The ship phase is the outward-facing surface (it runs real
operator commands), so these are worth closing even though none touches the
core qualification chain.

## DF-R3-02 (High) — required off-box sink failure still reports SHIPPED/0
`_anchor_ship_record` (~6625-6640) warns-and-returns on a REQUIRED sink push
failure; `_seal_ship_result` ignores the outcome; `_ship_phase` prints SHIPPED
+ returns 0. So a production action can run while the required off-box audit
evidence is missing, and automation sees success.

Fix:
- `_anchor_ship_record` returns a status: `"ok"` / `"skip"` (no sink) /
  `"optional_fail"` / `"required_fail"`. Keep it best-effort on the audit KEY
  and the local chain append (an action may already have run — never crash),
  but SURFACE the required-sink outcome instead of swallowing it. On success,
  write `ship_sink_receipt.json` bound to the record bytes (`body_sha256`),
  reusing the M44 receipt-binding helper (`_sink_receipt_bound`).
- `_seal_ship_result` returns `(record, anchor_status)`.
- `_ship_phase`: when actions SHIPPED but `anchor_status == "required_fail"`,
  seal the record with a DISTINCT outcome **`SHIPPED_AUDIT_PENDING`** and
  return a distinct nonzero exit (add `SHIP_AUDIT_PENDING = 12` alongside the
  existing UNKNOWN_OUTCOME=11). The real-world actions ARE done (never re-run
  them) — this reports "shipped but not yet off-box-attested," not failure.
- **Idempotent audit-only retry:** on re-entry, if the prior
  `ship_result.json` outcome is `SHIPPED_AUDIT_PENDING`, do NOT re-run actions
  — retry ONLY the off-box anchoring (`_anchor_ship_record` for the existing
  sealed record). On success, re-seal the SAME record as `SHIPPED` (exit 0);
  still failing → stay `SHIPPED_AUDIT_PENDING` (exit 12). (This is why the
  anchor must be separable from action execution.)
- Verify path (`_load_release_attestation` / any ship-verify): a run whose
  sealed config has `audit.sink.required` and whose ship outcome is SHIPPED
  must have a bound `ship_sink_receipt.json` to count as fully attested;
  absent ⇒ report `SHIPPED_AUDIT_PENDING`, never a silent fully-shipped.

## DF-R3-03 (Medium) — local ship terminal state trusted without authentication
On re-entry `_ship_phase` reads `ship_result.json` (~6690) and treats
SHIPPED/SHIP_FAILED as terminal, and `_ship_completed_actions` reads the ship
journal (~6735) to decide `already_done` — both WITHOUT authentication. A
same-user control-root writer can plant a `SHIPPED` result (suppress a real
ship) or edit the journal (skip actions / force a false SHIPPED).

Fix (leverage the EXISTING signed audit chain — `_anchor_ship_record` already
appends the ship record's sha256 to `audit-chain.jsonl` under a signed
entry when `audit.signing` is on):
- **When `audit.signing` is enabled** (the case for hardened/enterprise, and
  any run with signing): authenticate BOTH before trusting them on re-entry:
  - `ship_result.json`: recompute its sha256, require a matching, signature-
    valid chain entry for this run's `ship` kind. No matching valid entry ⇒
    the file was planted/altered ⇒ REFUSE (exit 2, distinct
    `SHIP_STATE_UNAUTHENTICATED`), never trust the outcome.
  - ship journal (`already_done`): anchor a signed digest of the ship journal
    into the chain at each `_seal_ship_result`; on re-entry recompute the
    journal digest and require it to match the last anchored value before
    trusting `already_done`. A post-seal-appended/edited journal ⇒ digest
    mismatch ⇒ REFUSE.
- **When signing is OFF** (e.g. standard/cooperative reversible-only ship):
  authentication is detection-grade best-effort only — document the residual
  honestly (same same-user limitation as the rest of the detection-grade
  model). Irreversible/production actions already REQUIRE hardened/enterprise
  + a signed release approval, so the high-stakes path is always on the
  authenticated branch; state that explicitly.
- Fail-closed on any chain read/verify error (missing chain when signing was
  on ⇒ refuse, not silently proceed).

## DF-R3-06 (Medium) — ship-workspace leak + unrecorded toolchain + unverifiable `reversible`
- **Leak (confirmed):** `ship_ws = tempfile.mkdtemp("df-ship-ws-")` (~6746)
  has NO cleanup after actions run — the `try` only handles the materialize
  failure. A fresh copy of the SEALED artifact bytes is left in temp on every
  ship. FIX: wrap the materialize + run + seal in `try/finally` and
  `shutil.rmtree(ship_ws, ignore_errors=True)` on EVERY exit path (success,
  fail, approval-pending, exception). Same for any per-action scratch df_ship
  creates.
- **Toolchain identity:** each action's `run[0]` (the executable) is operator
  argv whose bytes/version aren't recorded with the artifact. FIX (bounded,
  honest): at ship time, resolve `run[0]` to an absolute path and record
  `{argv0, resolved_path, sha256_if_regular_file_and_readable, version_hint?}`
  into the ship record per action (best-effort — a PATH-resolved binary we can
  stat/hash; if not resolvable/hashable, record that honestly). This does NOT
  make the external tool immutable; it records WHAT ran for the audit trail.
  Document that the toolchain is operator-controlled and only identity-recorded,
  not sealed/pinned.
- **`reversible` classification:** it's an operator assertion the system can't
  verify. FIX (policy, not magic): keep the existing signed-release-approval
  gate for `reversible:false`, and additionally require that when a
  `ship.approval` policy is configured, the release approval's covered action
  set is what authorizes each IRREVERSIBLE action (already true) — plus
  document prominently (`references/ship.md`) that `reversible:true` is an
  operator-asserted, unverified classification and a mis-classified
  production-impacting action bypasses the approval gate; recommend the
  approval policy cover-list be treated as the authority for what may run
  unattended. (No false claim that the system verifies reversibility.)

## Tests
- DF-R3-02: a stub required-sink that FAILS → ship runs the (stub) action,
  seals `SHIPPED_AUDIT_PENDING`, exit 12, actions NOT marked failed; a re-entry
  with the sink now succeeding → audit-only retry, no action re-run
  (assert the stub action ran exactly once across both), re-seals SHIPPED
  exit 0 + a bound receipt.
- DF-R3-03: with signing on, a planted `ship_result.json` (outcome SHIPPED, no
  matching chain entry) → refused exit 2 `SHIP_STATE_UNAUTHENTICATED`, action
  still runnable; a post-seal-tampered ship journal → refused; the honest happy
  path (real seal, real chain) re-enters fine.
- DF-R3-06: after a normal ship (success, fail, approval-pending, and the
  materialize-failure path) NO `df-ship-ws-*` dir remains; the ship record
  carries the per-action toolchain identity.
- All deterministic (stub actions/sink, no real infra). Full suite green
  (baseline current main ~1862 passed + docker skips).

## Rules
Fail-closed; real `raise`/return-nonzero, never bare `assert`. SUPERSET —
every existing ship invariant (M41 sealed-bytes, crash-safety unresolved-intent,
rollback, cred redaction, M44 attestation receipt) stays. `qualified` is never
re-opened by shipping. Absent-ship-block behavior byte-identical. Match house
comment style. Opus adversarial review (security-critical, outward-facing).
