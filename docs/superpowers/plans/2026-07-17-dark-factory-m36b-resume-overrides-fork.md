# M36b — signed resume overrides + spec-fork lineage + before-ship approval pause

_The deferred operator-workflow layer of the plan's M36 (M36a shipped modes +
qualification SM + FSM chain). Three separable parts, all touching the
resume path — MUST preserve the M35 crash-dispatch invariants (reserve-before-
dispatch, UNKNOWN_OUTCOME) and the M36a FSM-chain validation. This is the
LAST milestone of the audit-remediation program._

## Part A — signed resume overrides (`df_override.py`, new) — the security-relevant part
Today `resume` re-resolves credentials every time (fine — sealed policy
permits it) but there is NO governed way to raise a budget ceiling: a
BUDGET_PAUSE'd run either can't continue or would need a config edit that
nothing signs. A budget-ceiling raise is a policy change and must be
authorized, not silent.

- Reuse `df_custody` ed25519 (`validate_public_key`/`verify_one`/distinct-
  signer counting) — do NOT re-implement crypto.
- `OVERRIDE_TYPES = ("budget_ceiling",)` for M36a-scope. (Credential-VALUE
  refresh is already covered by resume's unconditional re-resolution under
  the SEALED credential policy — source/reference/allowlist never change; a
  changed value is picked up automatically, so it needs no new override.
  Document this explicitly so "credential refresh" isn't mistaken for
  missing.)
- Canonical signed payload `override_signing_bytes(claim)` = `canonical_json`
  of `{override_version:"1", run_id, override_type, params, issued_at,
  expires_at, nonce}`. For `budget_ceiling`, `params = {new_usd_ceiling:
  float}`. Signed by ≥ threshold DISTINCT allowlisted approvers
  (`{approver, sig}` alongside, never inside the signed bytes).
- **Replay protection independent of the supervisor HMAC**: a used-nonce
  ledger `<control_root>/override-nonces.json` (append-only, atomic). A nonce
  already present ⇒ REJECT (an override authorizes exactly one resume).
  Also bind to `run_id` (an override for run A can't apply to run B) and
  enforce `issued_at <= now < expires_at` (fail-closed on unparseable).
- Config: optional `resume_overrides: {approvers:[pubkey_hex,...],
  threshold:int}` → `cfg["_resume_overrides"]`; absent ⇒
  `{"approvers":[], "threshold":0}` (no override accepted — fail-closed).
  Tier-independent. If a non-empty policy is configured it MUST ride a signed
  manifest (require `audit.signing`, mirroring M33a waivers — the sealed
  approver allowlist must be HMAC-protected).
- CLI: `resume --override <file.json>` where the file is
  `{claim, signatures:[{approver,sig}]}`. `df-override keygen` (delegates to
  custody keygen) + `df-override sign --run-dir <rd> --type budget_ceiling
  --new-usd-ceiling <x> --expires <iso> --key-file <priv>` (recomputes
  run_id from the paused run, builds+signs the claim). Verified in `resume`
  BEFORE any builder call: on a valid override, journal `OVERRIDE_APPLIED`
  (type, params, distinct signer count, nonce), record the nonce, and apply
  (raise the effective `cfg["_budget"]` hard ceiling for this resume). Invalid/
  expired/replayed/short-threshold ⇒ journal `OVERRIDE_REJECTED` + refuse
  (exit 2), never a silent proceed.

## Part B — spec-fork lineage (`df-fork` command)
Let a NEW run start from a PARENT run's SEALED artifact object rather than an
empty workspace, with recorded lineage + parent supersession.

- `df-fork <control_root> --parent-run <run_dir>`: read the parent's sealed
  manifest; require `outcome` is a terminal that bound an artifact
  (`artifact.object_id` present) and the parent verifies clean
  (`_verify_manifest_status` == OK — never fork an unverified/tampered
  parent). Materialize the parent's frozen object (via `df_seal`, reading the
  object store) into the child's fresh workspace as the starting point.
- Record lineage on the child's first manifest:
  `lineage = {parent_run_id, parent_artifact_object_id,
  parent_manifest_sha256, forked_at}`. The child is otherwise a normal fresh
  `run` (its own scenarios/spec in the control root — a spec-fork adjusts the
  spec then rebuilds FROM the parent artifact).
- Mark the parent superseded: write `<parent_run_dir>/superseded_by.json`
  `{child_run_id, ts}` + journal `SUPERSEDED` in the parent. `verify-manifest`
  on a superseded parent still verifies (supersession is provenance, not
  tampering) but PRINTS the supersession so a stale artifact isn't shipped
  unknowingly.
- Fail-closed: missing/failed parent verification, absent object, or a child
  workspace that isn't empty ⇒ refuse. Validate-before-materialize.

## Part C — before-ship approval pause (completes H1/H2)
M36a deferred this because sealing on resume must NOT re-dispatch a paid
builder call. The artifact is ALREADY frozen before the final exam (M28a), so
a ship-approval pause can persist the post-convergence state and seal on
resume without rebuilding.

- `df_modes`: flip `pauses_before_ship` to True for H1 and H2 (currently
  False). H3/H4 stay False.
- In the CONVERGED branch, AFTER final-exam PASS + security-gates PASS +
  object re-verification, BUT BEFORE sealing `COMPLETE_QUALIFIED`: if
  `pauses_before_ship(mode)`, persist an `AWAIT_SHIP` FSM checkpoint carrying
  the converged iteration, the final-exam result, the sec_report, and the
  frozen `artifact.object_id` (+ append the AWAIT_SHIP transition to the hash
  chain binding that object_id); write a `checkpoint_ship.md`; return PAUSED.
- `resume` from `AWAIT_SHIP`: re-validate the FSM chain (existing), then
  **re-verify the frozen object still matches its sidecar** (fail-closed
  ARTIFACT_UNHASHABLE/mismatch — never seal a drifted object), re-run the
  security gates over the frozen artifact (cheap; the artifact is immutable
  so the result is stable, but re-running is the honest fail-closed choice vs
  trusting a persisted verdict), then seal via the SAME `df_qualify.derive`
  path as the straight-through convergence. `resume --decision abort` from
  AWAIT_SHIP ⇒ sealed `SHIP_DECLINED` terminal (qualified False), not
  shipped. NO builder dispatch occurs on this resume — assert it (the loop
  must not re-enter BUILD from AWAIT_SHIP).
- e2e: H1 and H2 now pause before ship; `continue` seals COMPLETE_QUALIFIED
  with NO second builder call (assert builder_calls unchanged across the
  ship-resume); `abort` ⇒ SHIP_DECLINED.

## Tasks
1. `df_override.py` + config `resume_overrides` + `resume --override` wiring +
   `df-override` CLI + nonce ledger + tests (`test_override.py`).
2. `df-fork` command + lineage manifest field + parent supersession + tests
   (`test_fork.py`).
3. Before-ship pause: `df_modes.pauses_before_ship`, AWAIT_SHIP checkpoint +
   seal-reentry resume + `SHIP_DECLINED` + tests (`test_e2e_ship_pause.py`).
4. Docs: `references/modes.md` (before-ship pause + AWAIT_SHIP resume),
   `references/audit.md` (override + lineage + SHIP_DECLINED),
   `references/budget.md` (signed ceiling override),
   `references/prevention-grade-roadmap.md` (mark M36 fully landed; note the
   same-user residual on override nonces/keys — detection not prevention),
   SKILL.md (interview: resume_overrides approvers; df-fork provenance).

## Key decisions
- Overrides are the ONLY new signing surface; budget-ceiling only (credential
  refresh is already covered by unconditional re-resolution under sealed
  policy — documented, not silently missing).
- Seal-reentry never re-dispatches a builder — the artifact is already frozen;
  resume re-verifies identity + re-runs gates + seals. Preserves M35.
- Fork requires a clean-verifying parent; supersession is provenance, surfaced
  at verify, never blocks verification.
- Every new decision is fail-closed: absent policy ⇒ no override; bad/replayed
  override ⇒ refuse; drifted object at ship-resume ⇒ refuse.

## Out of scope (documented)
- Credential-VALUE-refresh as a distinct signed override (covered by resume's
  existing re-resolution under sealed policy).
- Multi-parent / DAG lineage (single parent only).
- Interactive WAIVER_PENDING pause (waivers remain attach-time, M33a).
