# The ship phase — governed post-seal action runner (M41)

The workflow can optionally continue **past the sealed, qualified artifact**
into a governed **ship phase**: after a run is `qualified`, run operator-defined
**ship actions** (merge, deploy, provision, migrate, monitor…) as an audited,
gated, crash-safe, rollback-capable phase — including unattended under H4
lights-out — WITHOUT weakening the fail-closed model.

dark-factory is a governed **runner, not a deploy engine.** Each action is plain
operator argv (`git`/`kubectl`/`terraform`/`flyctl`/a migration tool). The skill
provides the orchestration: qualification-gating, ordering, a signed approval
gate for irreversible actions, brokered credentials, an audit trail,
rollback-on-failure, and crash-safe resume.

**Absent a `ship` block, behavior is byte-identical to before M41** — the
workflow ends at the sealed artifact.

## The action schema (`ship` in config.json)

```jsonc
"ship": {
  "approval": {                       // required IFF any action is reversible:false
    "approvers": ["<64-hex ed25519 pubkey>", ...],
    "threshold": 2
  },
  "actions": [
    { "name": "merge",                // slug: ^[a-z0-9][a-z0-9_-]{0,63}$, unique
      "run": ["git","push","origin","HEAD:release/x"],  // non-empty list[str]
      "reversible": true,             // REQUIRED bool — no default
      "timeout_s": 120 },             // int 1..3600
    { "name": "deploy",
      "run": ["./deploy.sh","--image","..."],
      "reversible": false,            // ⇒ signed release approval required
      "rollback": ["./deploy.sh","--rollback"],   // optional list[str]
      "creds": { "env": ["PROD_DEPLOY_TOKEN"] },  // env-var NAMES only
      "cwd": "subdir",                // optional, relative + path-safe (no .., no abs, no ~)
      "timeout_s": 600 }
  ]
}
```

Validation (fail-closed at config load): `actions` a non-empty list; each `name`
a unique slug; `run` a non-empty list of strings; **`reversible` a REQUIRED
bool** (no default, so nothing is ever accidentally treated as reversible);
`rollback` an optional non-empty list of strings; `creds.env` an optional list
of env-var NAMES (a `value`/`token`/`secret`/`password` key, or a name that is
not a valid env-var identifier, is refused — the same posture as
`credential_proxy.token_env`); `timeout_s` an int in `1..3600`; `cwd` an
optional path-safe subpath of the ship workspace.

### The irreversibility interlock

If ANY action is `reversible: false`:
- `ship.approval` with `threshold >= 1` and valid approver pubkeys is
  **REQUIRED** (you cannot have an irreversible action no one can approve), and
- the run must be `assurance: hardened` or `enterprise` (an irreversible prod
  action off an unqualified-isolation tier is refused), and
- it **forces `audit.signing: true`** — the sealed approver allowlist rides in
  `config_sha256`, which is only tamper-proof under an HMAC-signed manifest
  (mirrors the M33a waiver / M36b resume-override rules). An explicit
  `audit.signing: false` is a hard rejection.

> **`reversible: true` is an operator-asserted, UNVERIFIED classification.** The
> system CANNOT verify that an action is actually reversible — it trusts the
> boolean you write. A production-impacting action mis-classified `reversible:
> true` bypasses the signed-release-approval gate entirely (M49 DF-R3-06). The
> real authority for what may run unattended is therefore the **signed release
> approval's covered action set** (`action_names` in the claim), not the
> `reversible` flag: treat the approval cover-list as the allow-list of what runs,
> and classify conservatively. dark-factory records but does NOT pin the external
> toolchain (see the audit-trail note under invariant #7).

## Hard safety invariants

1. **Ship only a qualified artifact.** The ship phase runs ONLY when the run is
   cleanly qualified — non-enterprise: `outcome COMPLETE_QUALIFIED` +
   `qualified: true`; enterprise: a valid K-of-N `custody_attestation.json`
   (so enterprise ships strictly **after** `df-custody attach`). A
   non-qualified / waived-but-limited / custody-pending run never ships.
2. **Act on the sealed bytes.** Actions run with `cwd` = a fresh workspace
   **materialized from the sealed artifact object** (`df_seal.materialize_object`,
   re-verified by identity first), never a drifted post-build workspace.
3. **Irreversible ⇒ signed approval, fail-closed.** A `reversible: false` action
   runs only under a valid, unexpired, replay-fresh, ≥threshold signed release
   approval bound to THIS `run_id + artifact_object_id + action set`. Absent or
   invalid ⇒ seal `SHIP_APPROVAL_PENDING`; never run, never block. This holds in
   **every** mode incl. H4 (lights-out never silently performs an irreversible
   prod action).
4. **Crash-safe, no double-fire.** Each action journals `SHIP_ACTION_INTENT`
   (fsync'd) to a **separate** `ship_journal.jsonl` BEFORE it spawns, and
   `SHIP_ACTION_RESULT` after. (It is a separate journal because `journal.jsonl`
   is SEALED at finalize.) On resume, an INTENT with no RESULT is `UNKNOWN` →
   refuse (`SHIP_UNKNOWN_OUTCOME`, exit 11) requiring `ship --decision
   reconcile`, never a blind re-run of a deploy.
5. **Rollback on failure.** On a nonzero exit or timeout, the failed action's own
   `rollback` runs first, then each already-succeeded prior action's `rollback`
   in REVERSE order; the run seals `SHIP_FAILED` (exit 3). A rollback that itself
   fails is journaled `SHIP_ROLLBACK_FAILED` and surfaced loudly (operator must
   intervene) — never swallowed.
6. **Secrets never surface.** Brokered credential values reach ONLY the child
   subprocess env (resolved host-side, at action time, by `df_creds`); captured
   stdout/stderr are routed through the run's Redactor before hitting disk. A
   value never enters config, the journal, the manifest, or a captured log.
7. **Off-box audit integrity, fail-closed (M49).** When `audit.sink.required` is
   set, a SHIPPED ship whose REQUIRED off-box sink push FAILS does NOT report a
   clean exit-0: it seals the DISTINCT outcome **`SHIPPED_AUDIT_PENDING`** and
   returns the distinct exit **12** (`SHIP_AUDIT_PENDING`) — the real-world
   actions ARE done (they are NEVER re-run), but the mandated off-box evidence is
   not yet anchored, so automation must not read success. Re-running `ship`
   performs an **idempotent audit-only retry**: it re-anchors ONLY the off-box
   evidence for the existing sealed record (never the actions) and, on success,
   writes a bound `ship_sink_receipt.json` and finalizes `SHIPPED`/exit 0. A
   SHIPPED record under a required sink with no bound receipt is likewise treated
   as not-yet-fully-shipped, never a silent success. **Re-entry authenticates
   local state (DF-R3-03):** when signing is on, a prior `ship_result.json` is
   trusted on re-entry ONLY if a signature-valid audit-chain entry anchors its
   digest, and each already-completed action recovered from the ship journal
   (`already_done`) is trusted ONLY if its own **per-action completion token** is
   individually anchored in the signed chain. That token is anchored as the action
   commits — BEFORE its `SHIP_ACTION_RESULT` is journaled — so an honest
   crash-before-seal recovery (and the `--decision reconcile` path) still
   authenticates every action that really ran, while a planted/edited
   `SHIP_ACTION_RESULT ok` (to skip a real action) or a planted terminal result is
   **refused** (exit 2, `SHIP_STATE_UNAUTHENTICATED`). Per-action anchoring is
   deliberate: a single seal-time journal digest could not tell a legitimate
   crash-before-first-seal (no anchor yet) from a tampered journal (both look
   anchor-less), and would brick crash recovery. Fail-closed on any chain
   read/verify error (and a signed run NEVER appends an unsigned chain entry when
   its key is unavailable — that would break the whole control-root chain). When
   signing is OFF this authentication is detection-grade best-effort only — but
   irreversible / production actions already REQUIRE hardened/enterprise + a signed
   release approval, so the high-stakes path is always on the authenticated branch.
   **Toolchain identity (DF-R3-06):** each action's resolved `run[0]` identity
   (`argv0`, resolved path, and a sha256 when it is a regular readable file) is
   recorded in the ship record for the audit trail. This does NOT pin or seal the
   external tool — it stays operator-controlled — it only records WHAT ran. The
   fresh workspace materialized from the sealed bytes is removed on every exit
   path (no sealed-artifact copy is left in temp).

`qualified` is **NOT re-opened by shipping.** The immutable `manifest.json` is
never rewritten; the ship outcome lives in a SEPARATE `ship_result.json`
(anchored into the tamper-evident audit chain, like `custody_attestation.json`).
A `SHIP_FAILED` run stays `qualified: true` with a distinct ship outcome.

## The `df-release` approval workflow (irreversible actions)

Structurally a mirror of `df-custody`/`df-waiver`, using the same ed25519
primitives and distinct-signer counting:

```
# once per approver
supervisor.py df-release keygen --out-prefix approver1

# sign a claim bound to the SEALED run+artifact, scoped to named actions (or --all)
supervisor.py df-release sign --manifest <run_dir>/manifest.json \
    --actions deploy --expires 2026-09-01T00:00:00Z --key-file approver1.key
#   (for K>1, later approvers add --claim <prior output> so all sign identical bytes)

# collect {claim, signatures} into <control_root>/release-approval.json, then:
supervisor.py df-release attach <control_root> --run-dir <run_dir>
#   -> verifies against the sealed ship.approval policy + run/artifact binding,
#      writes release_attestation.json, records the single-use nonce, anchors it.

supervisor.py ship <control_root> --run-dir <run_dir>   # now runs the gated action(s)
```

The signed claim is `{release_version, run_id, artifact_object_id, action_names,
issued_at, expires_at, nonce}`. Coverage (`ApprovalContext.covers`) RE-VERIFIES
the signatures live at every ship attempt: an approval that has since expired,
or a config/manifest that has drifted, flips the action back to gated.

## Running the ship phase

- **Auto-after-seal:** a non-enterprise run that seals `COMPLETE_QUALIFIED` with
  a `ship` block auto-enters the ship phase (unattended in H4/H3; after the
  M36b before-ship human pause in H1/H2).
- **As a deliberate step:** `supervisor.py ship <control_root> --run-dir <run_dir>`
  runs/resumes the ship phase against a qualified run (the ONLY path for
  enterprise, and the resume path after `SHIP_APPROVAL_PENDING`,
  `SHIP_UNKNOWN_OUTCOME`, or `SHIPPED_AUDIT_PENDING`). `--decision reconcile|abort`
  handles the unknown-outcome path; a plain re-`ship` on a `SHIPPED_AUDIT_PENDING`
  run runs the idempotent audit-only retry (invariant #7 — actions are never
  re-run).

Ship exit codes: `0` SHIPPED · `3` SHIP_FAILED / SHIP_APPROVAL_PENDING · `11`
SHIP_UNKNOWN_OUTCOME (a crash left a forward action's — or, DF-R6-02, a
rollback's — effect unknown; needs `--decision reconcile` or `abort`, never a
blind re-run) · `12` SHIP_AUDIT_PENDING (SHIPPED but the required off-box
evidence is not yet anchored — plain re-`ship` re-anchors) · `13`
**SHIP_EVIDENCE_PENDING** (R5 DF-R5-02 / M56b: a per-action completion token
could not be SIGNED — the action already RAN and is NEVER re-run; re-run `ship
--decision repair-evidence`, after verifying the action's real-world state, once
the audit signer is available to re-sign the evidence from the signed
pre-spawn intent facts and continue) · `2` fail-closed refusal (including
`SHIP_STATE_UNAUTHENTICATED`, a planted/tampered local ship state under a signed
run).

**Enterprise before-ship gate.** At non-enterprise tiers H1/H2 PAUSE before the
ship (`AWAIT_SHIP`). At **enterprise**, a converged run instead seals the
`CUSTODY_PENDING` terminal (exit 3): shipping is unreachable until a K-of-N
split-custody attestation is attached (`df-custody attach`), so the human gate
there is the custody sign-off, not a pause.

**No-action terminal recovery (DF-R7-05).** A materialization failure or a
reconcile-abort seals a SHIP_FAILED that ran NOTHING. If the audit signer was
down at that moment its local anchor is pending and the record cannot
self-authenticate on re-entry. A plain `ship` re-entry stays fail-closed (exit
2, never a silent re-anchor); to recover, re-run `ship --decision abort` — under
that explicit operator consent the no-action terminal is **rebuilt from
authenticated facts** (empty action set + the manifest's artifact id, never the
writable prior record) and anchored under the now-available signer. No action
runs, and it can never become SHIPPED — so this replaces the old "manually delete
the record" step with a governed command. A terminal that shows ANY completed
`ok` action (in the record OR the signed audit chain) is NOT eligible for this
shortcut and goes through full evidence binding. **`--decision abort` is
destructive, not a repair:** it seals the run FAILED. Use it only for a genuine
no-run failure; on a plain re-entry a healthy run proceeds normally, so reach for
abort only when you intend to abandon the ship.

## Honest scope — NOT sandboxed

Ship actions legitimately need **real network + credentials** (that is the
point). They are therefore **NOT network-sandboxed** and run as normal host
subprocesses. The protection is **qualification + the signature gate + the audit
trail**, NOT confinement.

### Out of scope (documented exclusions)

- **Incident response** and real-user validation / cutover *judgment*. A
  `reversible: false` cutover COMMAND can run under the signed gate, but the
  skill provides no monitoring-driven decisioning.
- **Provisioning/rotating production SECRET VALUES** — broker-name references
  only (`creds.env`); a value never lives in config/logs/manifest.
- A DSL for deploy topologies — actions are plain operator argv.
- **Reversibility verification and toolchain pinning** — `reversible` is an
  operator assertion the system trusts but cannot check, and the external tool
  (`run[0]`) is identity-recorded (invariant #7) but NOT pinned or made immutable.
  The signed-release-approval cover-list is the authority for what runs unattended.

## Residual (detection-grade, not prevention-grade)

A same-user actor with control-root write AND a signer private key can mint and
attach a release, and could in principle edit `config.json`'s `ship.approval`.
Forcing a non-empty policy to ride a SIGNED audit manifest HMAC-pins the sealed
config; the nonce ledger + distinct-signer counting bound WHO and HOW-OFTEN. The
M49 re-entry authentication (invariant #7) closes the *unauthenticated* local
ship-state trust: under a signed run a planted `ship_result.json` or a post-seal
journal edit is detected against the signed chain and refused. It rests on the
SAME root of trust as the rest of the design — the audit HMAC key (held outside
`workspace_root`); a same-user actor who also holds THAT key remains in the
documented same-user residual (they could forge chain entries too), and when
signing is OFF the local-state authentication is detection-grade best-effort only.
This is the same same-user residual documented for custody/waiver/override — see
`references/prevention-grade-roadmap.md`.
