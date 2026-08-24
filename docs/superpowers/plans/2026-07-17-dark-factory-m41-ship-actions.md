# M41 — governed post-ship action runner (the ship phase)

## Goal
Extend the workflow past the sealed artifact: after a run is **qualified**, run
operator-defined **ship actions** (merge, deploy, provision, migrate,
monitor…) as a governed, audited phase — including unattended under H4
lights-out — WITHOUT weakening the fail-closed model. Owner decisions:
- **Gated.** Reversible/idempotent actions run unattended (any mode, incl.
  H4); **irreversible** actions (prod deploy, migrations, DNS, prod merge,
  cutover) run only after a **signed release approval** (K-of-N, reusing the
  enterprise custody + M36b signed-override machinery). Lights-out still does
  the doing; a human is accountable for prod via a one-time signature, never
  by running the command.
- **General runner, not a deploy engine.** The skill executes operator-
  supplied argv (git/kubectl/terraform/flyctl/migration tools). It provides
  orchestration: qualification-gating, ordering, the signature gate, brokered
  creds, an audit trail, rollback-on-failure, and crash-safe resume.
- **Secrets stay broker-only.** Actions read credentials from operator-named
  env vars resolved host-side at action time (existing `df_creds` broker) —
  never a value in config, logs, or the manifest. Incident response is out of
  scope entirely.

## Hard safety invariants (non-negotiable)
1. **Ship only a qualified artifact.** The ship phase runs ONLY when the
   sealed manifest is `qualified` (all sub-states held). A non-qualified /
   waived-but-limited / custody-pending run never ships. (Enterprise: ship
   runs only after custody attestation qualifies it — so ship is strictly
   after `df-custody attach`, never in the CUSTODY_PENDING run itself.)
2. **Act on the sealed bytes.** Actions run with `cwd` = a fresh workspace
   **materialized from the sealed artifact object** (`df_seal.materialize_object`,
   added M36b) — re-verified by identity first. Never a drifted post-build
   workspace.
3. **Irreversible ⇒ signed approval, fail-closed.** An `reversible:false`
   action runs only if a valid, unexpired, replay-fresh, ≥threshold-signed
   release approval bound to THIS `run_id + artifact_object_id + action set`
   exists. Absent/invalid ⇒ seal `SHIP_APPROVAL_PENDING` (like
   CUSTODY_PENDING); never run, never block. This holds in EVERY mode incl.
   H4 (lights-out never silently performs an irreversible prod action).
4. **Crash-safe, no double-fire.** Reuse the M35 reserve-before pattern:
   journal `SHIP_ACTION_INTENT` (+ idempotency key) and persist BEFORE
   spawning each action; `SHIP_ACTION_RESULT` after. On resume, an action with
   INTENT and no RESULT is `UNKNOWN` → refuse with `SHIP_UNKNOWN_OUTCOME`
   (exit 11) requiring `--decision reconcile`, never a blind re-run of a
   deploy.
5. **Rollback on failure.** On a nonzero action exit (or timeout), run the
   `rollback` argv for that action and each already-succeeded prior action in
   REVERSE order (those that define one), journal `SHIP_ROLLED_BACK`, seal
   `SHIP_FAILED` (exit 3). A rollback that itself fails is journaled
   `SHIP_ROLLBACK_FAILED` and surfaced loudly (operator must intervene) — never
   swallowed.
6. **Secrets never surface.** Action stdout/stderr is captured to run_dir
   through the run's `Redactor`; brokered cred values never enter config, the
   journal, the manifest, or a captured log.

## Approach (6 tasks)

### Task 1 — config: `ship` block (`df_config.py`)
```jsonc
"ship": {
  "approval": { "approvers": [pubkey_hex...], "threshold": N },   // for irreversible actions
  "actions": [
    { "name": "merge", "run": ["git","push","origin","HEAD:release/x"],
      "reversible": true, "timeout_s": 120 },
    { "name": "deploy", "run": ["./deploy.sh","--image","..."],
      "reversible": false, "rollback": ["./deploy.sh","--rollback"],
      "creds": { "env": ["PROD_DEPLOY_TOKEN"] }, "timeout_s": 600 }
  ]
}
```
Validation: `actions` non-empty list; each `name` unique non-empty; `run` a
non-empty list of str; `reversible` a required bool (operator must consciously
declare — no default, so nothing is accidentally treated reversible);
`rollback` optional list-of-str; `creds.env` optional list of env-var NAMES
(reject an inline value / a name that looks like a literal secret, same
posture as `credential_proxy.token_env`); `timeout_s` int 1..3600; optional
`cwd` relative to the ship workspace (path-safe, no `..`/abs). If ANY action
is `reversible:false`, `ship.approval` with `threshold>=1` and valid approver
pubkeys is REQUIRED (ConfigError otherwise — you can't have an irreversible
action with no one able to approve it) and it forces `audit.signing` (the
sealed approver allowlist must be HMAC-protected, mirroring M33a waivers /
M36b overrides). Absent `ship` block ⇒ today's behavior exactly (workflow ends
at the sealed artifact). Tier-independent, but a `reversible:false` action
additionally requires `assurance: hardened|enterprise` (an irreversible prod
push off an unqualified-isolation tier is refused).

### Task 2 — `df_ship.py` (new): the action runner
- `materialize_ship_workspace(control_root, manifest) -> path`: re-verify the
  bound artifact object, materialize it into a fresh dir (reuse
  `df_seal.materialize_object`), fail-closed on drift.
- `run_actions(actions, ship_ws, *, approval_ctx, redactor, journal,
  reserve_and_persist, already_done) -> ShipResult`: iterate in order. For
  each action: if `reversible:false`, require `approval_ctx.covers(action)`
  (a verified release approval — Task 4) else return
  `SHIP_APPROVAL_PENDING`. Reserve (Task-4 intent+persist) → resolve brokered
  creds into the child env (values only in the subprocess env, never logged) →
  `subprocess.run(argv, cwd=ship_ws, env=broker_env, timeout, capture)` →
  journal result (exit, duration; stdout/stderr redacted to run_dir). On
  failure: rollback prior successes in reverse, return `SHIP_FAILED`. Pure
  orchestration; all crypto/gate logic in df_release (Task 4).
- `AShipError`; real `raise` guards; never a bare `assert`.

### Task 3 — supervisor wiring: the SHIP phase + FSM
- After a run seals `COMPLETE_QUALIFIED` (and for enterprise, after
  `df-custody attach` qualifies it): if a `ship` block is configured, enter the
  ship phase. Add FSM phases `SHIPPING` + terminal `SHIPPED` /
  `SHIP_FAILED` / `SHIP_APPROVAL_PENDING` / `SHIP_UNKNOWN_OUTCOME`; extend the
  M36a hash-chained checkpoint so a ship pause/resume is chain-validated like
  any other.
- H4 lights-out: reversible actions run straight through; the FIRST
  irreversible action with no covering approval seals `SHIP_APPROVAL_PENDING`
  (no block, no silent proceed). A `df-release attach` + `resume` then runs
  the gated actions. Attended modes: identical gate (uniform mechanism — the
  before-ship pause from M36b still governs whether to ENTER shipping;
  the signature governs irreversible actions within it).
- Seal a manifest `ship = {actions:[{name, reversible, status, exit,
  approval_ref?}], outcome, ship_workspace_object_id}`; journal
  `SHIP_STARTED`/`SHIP_ACTION_*`/`SHIPPED`/etc. `qualified` is NOT re-opened
  by shipping — a SHIP_FAILED run stays `qualified:true` (the artifact was
  qualified; shipping it failed) with a distinct ship outcome.
- CLI: `ship` subcommand to run/resume the ship phase against a qualified run
  (so shipping can be a deliberate separate step, not only auto-after-seal);
  `--decision reconcile/abort` for the UNKNOWN_OUTCOME path.

### Task 4 — `df_release.py` (new): signed release approvals
Mirror `df_override`/`df_waiver` (reuse `df_custody` ed25519, distinct-signer
counting). Canonical claim `{release_version:"1", run_id,
artifact_object_id, action_names:[...]|"*", issued_at, expires_at, nonce}`,
≥threshold distinct allowlisted approvers, replay-protected via
`<control_root>/release-nonces.json`, run_id+artifact-bound, live-clock
expiry. `df-release keygen|sign|attach`: `attach` verifies collected
signatures against the sealed run + sealed `ship.approval` policy, writes
`release_attestation.json`, anchors it. `approval_ctx.covers(action)` = the
attestation is valid now AND lists that action (or `*`). Verified at ship
time; expired/invalid ⇒ that action stays gated (SHIP_APPROVAL_PENDING),
never runs.

### Task 5 — worked examples (reversible, run unattended)
- `examples/ship-merge-pr/` — a `ship` block that pushes the qualified
  artifact to a `release/<id>` branch (reversible) with a README showing the
  H4 unattended flow.
- `examples/ship-deploy-staging/` — a `deploy.sh` stub + `ship` block doing a
  reversible staging deploy with a `rollback`, and a commented `reversible:false`
  prod action showing the `df-release sign/attach` gate.

### Task 6 — tests + docs
- `test_ship_config.py`: block validation; irreversible-without-approval ⇒
  ConfigError; approval forces audit.signing; irreversible requires
  hardened+; creds-value rejection.
- `test_release.py`: claim sign/verify, threshold, expiry, replay-ledger,
  wrong-artifact/run binding, action-name coverage.
- `test_ship.py`: ordered run; rollback-in-reverse on failure; brokered creds
  reach the child env but never the journal/manifest/log (assert a planted
  value is absent); reserve-before/UNKNOWN-on-resume; non-qualified run never
  ships.
- `test_e2e_ship.py` (stub actions — deterministic, NO real infra): H4 run →
  reversible action runs unattended → SHIPPED; a config with an irreversible
  action → SHIP_APPROVAL_PENDING → df-release attach → resume → SHIPPED; a
  failing action → rollback ran (reverse order) → SHIP_FAILED, qualified still
  true; a crash between INTENT and RESULT → resume refuses (SHIP_UNKNOWN_OUTCOME)
  until reconcile.
- Docs: `references/ship.md` (new — the phase, action schema, reversibility
  gate, df-release workflow, crash-safety, rollback, the honest "runs with
  real creds + network, gated by qualification+signature not sandboxing"
  scope, and the incident-response/prod-secrets exclusions), `references/audit.md`
  (`ship` field + outcomes), `references/modes.md` (H4 ship behavior + the
  SHIP_APPROVAL_PENDING terminal), `references/config-reference.md` (`ship`),
  SKILL.md (offer ship actions in the interview + the safety framing),
  README/OVERVIEW (one line each — the workflow can now optionally continue
  past the sealed artifact into governed ship actions; irreversible ones are
  signature-gated), and UPDATE the "Non-goals: merge/deploy/production
  operation are out of scope" text to reflect the new governed scope + its
  remaining exclusions (incident response, prod-secret management).

## Out of scope (documented)
- Incident response and real-user validation/cutover judgment (a
  `reversible:false` cutover COMMAND can be run under the signed gate, but the
  skill provides no monitoring-driven decisioning).
- Provisioning/rotating production SECRET VALUES (broker-name refs only).
- A DSL for deploy topologies — actions are plain operator argv.

## Key decisions
- One runner, one gate: reversibility is an operator-declared per-action bool;
  irreversible ⇒ signed release approval (reused custody/override crypto). No
  bespoke per-category engines.
- Ship acts on the sealed, re-verified artifact object; qualification is a
  hard precondition; secrets stay broker-only; crash-safety reuses M35;
  rollback + fail-closed everywhere.
- Absent `ship` block ⇒ byte-identical to today (workflow ends at the seal).
