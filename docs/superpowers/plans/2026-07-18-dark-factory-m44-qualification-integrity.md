# M44 — qualification integrity (RA-01 Critical, RA-02 Critical, RA-03 High)

## Goal
Make `QUALIFIED` mean what the docs claim: the EXACT sealed, shipped bytes
passed the final exam and every security gate, and no attestation can qualify
a run whose evidence isn't trustworthy. Fixes the Codex re-audit's two
criticals (+ the High that shares the same code path).

## RA-01 (Critical) — validation must examine the SEALED object, not the mutable workspace
**Confirmed** (supervisor.py:4985 documents it as deferred "M29d"): the run
freezes the artifact object, then runs the final exam + security gates against
the mutable `workspace`. A final-cohort scenario side effect, a test hook, or
a hostile candidate can mutate `workspace` to look clean (e.g. delete a
planted key) AFTER the freeze, so the gates certify bytes that differ from the
sealed object that gets shipped. Codex reproduced a `COMPLETE_QUALIFIED` run
whose frozen `app.py` still held a hardcoded key while `security.failed: []`.

**Fix** (uses `df_seal.materialize_object`, added in M36b — the primitive
already exists):
- In the CONVERGED branch, AFTER `_seal_workspace_artifact` produces
  `object_id`, materialize the sealed object into FRESH throwaway roots under
  the run dir (never the object store dir itself) and run validation there:
  - **Security gates:** materialize a pristine copy `R_gates` from `object_id`
    and run `df_security.run_gates(R_gates, …)`. Gates only scan, so `R_gates`
    can be treated read-only. Because `R_gates` is a copy of the SEALED bytes,
    a post-freeze workspace scrub cannot change what the gates see — the
    reproduced attack dies here.
  - **Final exam:** materialize a fresh copy `R_exam` from `object_id` and run
    the final cohort with cwd=`R_exam` (candidate execution needs to write pid
    files/DBs, so this copy is writable but discarded after). It examines
    bytes that provably came from the sealed object.
  - Each materialize re-verifies object identity (materialize_object already
    does, and refuses a non-empty dest); on any SealError → the existing
    `_artifact_unhashable_abort` fail-closed terminal (never qualify).
  - Discard `R_gates`/`R_exam` after use (best-effort cleanup; they hold no
    secret the object store doesn't already hold).
- The dev-loop verify (pre-seal iterations) is UNCHANGED — it runs on
  `workspace` because there is no sealed object yet and its results only drive
  ID+taxonomy feedback, never qualification.
- `verify_manifest` / qualification stays object-bound (already true post-M28a);
  now the EVIDENCE feeding qualification is also object-derived.
- **Documented residual (honest):** per-SCENARIO copy-on-run within the final
  cohort (a fresh copy per final scenario, so one final scenario can't mutate
  state a later one sees) is a further hardening still deferred as full M29d;
  M44 closes the shipped-vs-validated-bytes gap (gates + exam derive from the
  sealed object), which is the RA-01 attack. Update the supervisor.py:4985
  ENGINEERING NOTE to describe the new reality + this narrower residual.

## RA-02 (Critical) — a failed REQUIRED off-box sink must NOT leave a locally-qualified run
**Confirmed** (attach_custody, supervisor.py:1380 vs 1408-1418): the local
`custody_attestation.json` is written + chain-anchored BEFORE the required
sink push; on push failure it returns 3 but leaves the attestation on disk,
and `verify_custody_cmd` reads it and reports QUALIFIED without requiring the
sink receipt. So "enterprise qualification must leave the box" is not actually
enforced.

**Fix** (apply to ALL attach paths that have a required sink — custody
`attach_custody`, waiver `df-waiver attach`, release `attach_release`):
- Do the required-sink push FIRST (or, if ordering must stay, roll back on
  failure): on a `required` sink, obtain a successful receipt BEFORE the
  attestation is considered valid. If the push fails, remove/roll back the
  local attestation file (and do not leave a chain link that implies
  qualification) and return nonzero — the run must NOT be locally qualifiable.
  Write `*_sink_receipt.json` as part of the committed attestation, not an
  afterthought.
- `verify_custody_cmd` (and the waiver/release verify paths): when the sealed
  config's `audit.sink.required` is true, REQUIRE the corresponding
  `*_sink_receipt.json` to be present AND well-formed (bound to this
  attestation) — its absence ⇒ NOT qualified (a distinct
  `SINK_RECEIPT_MISSING`/PENDING status), never a silent QUALIFIED. Fail
  closed on an unparseable/mismatched receipt.
- Keep it a superset of today's checks (object identity + config-bound +
  K-of-N still required); this only ADDS the receipt requirement.

## RA-03 (High) — post-seal attestation must enforce manifest eligibility
**Confirmed** (attach_custody hardcodes `"qualified": True` at :1364 after
checking only object identity + config-bound + K-of-N): a signed but INELIGIBLE
manifest (e.g. `SECURITY_GATE_FAILED`, `HOST_ISOLATION_LIMITED`, a failed final
exam, or any non-`CUSTODY_PENDING` outcome) can acquire a qualification
attestation.

**Fix:** before attesting, require the manifest to be ELIGIBLE:
- `outcome == "CUSTODY_PENDING"` (the enterprise pending terminal — the only
  outcome a custody attestation is meant to qualify), AND
- the manifest's own pre-custody evidence all holds: `final_exam.passed` (or
  no-final-cohort per policy), `security.failed == []`, and every
  `qualification.substates` value that was determined pre-custody is true
  (barrier ∧ host_isolation ∧ control_plane ∧ app_security ∧ waiver_validity).
  Reuse `df_qualify` where possible; do NOT re-derive ad hoc.
- Any ineligibility ⇒ refuse with a clear reason (exit 3), never attest.
  Mirror the same eligibility gate in the waiver/release attach paths (a
  waiver/release must not qualify a run that failed a DIFFERENT gate).

## Tasks
1. **RA-01** — supervisor CONVERGED branch: materialize `R_gates`/`R_exam` from
   the sealed object, run gates + final exam there, discard; update the
   ENGINEERING NOTE; e2e proving the reproduced attack now FAILS (a final
   scenario that scrubs a planted key from the workspace no longer yields a
   clean gate result — the gates scan the sealed object and still see the key
   → SECURITY_GATE_FAILED, qualified False).
2. **RA-02** — attach_custody / df-waiver attach / attach_release: required-sink
   receipt gate before a valid attestation + rollback on failure; verify paths
   require the receipt when the sink is required; tests (required-sink failure
   ⇒ no local qualification; verify without receipt ⇒ not qualified).
3. **RA-03** — the three attach paths: manifest-eligibility gate (outcome +
   substates + gates + final exam) before attesting; tests (a
   SECURITY_GATE_FAILED / HOST_ISOLATION_LIMITED / failed-final manifest, even
   with valid K-of-N signatures, is REFUSED).
4. **Docs** — `references/audit.md` (validation-on-sealed-object; the receipt +
   eligibility requirements; the new verify statuses), `references/enterprise.md`
   (attach now requires a sink receipt + eligible manifest),
   `references/isolation.md`/M29d note (narrowed residual). Do NOT yet re-state
   the top-level QUALIFIED guarantee in README/SKILL — that waits until the
   whole RA program (M44–M47) lands, per the owner's "wait until fixed"
   decision.

## Rules / invariants
- Fail CLOSED everywhere; real `raise`/return-nonzero, never bare `assert`.
- Superset only: every existing check stays; M44 ADDS object-derived validation
  + receipt + eligibility gates. Absent enterprise sink / non-custody runs must
  stay byte-compatible where the new gates don't apply (a standard-tier run
  with no sink is unaffected by RA-02; RA-01 applies to ALL tiers that seal +
  gate).
- The reproduced RA-01 attack MUST be covered by a regression test that fails
  before the fix and passes after.
- Full suite green (baseline 1827 passed, 12 skipped; DOCKER_CONFIG=/tmp/dockercfg
  to dodge the known keychain hang). No commits — leave dirty for opus review.

## Out of scope (later milestones)
- RA-04 (confinement enabled∧required), RA-05 (sealed scenario bundle), RA-06
  (dispatch idempotency), RA-07 (adapter-executable-only mount), RA-08
  (candidate egress default + containment) → M45/M46/M47.
- Full per-scenario copy-on-run (M29d) — narrowed residual documented here.
