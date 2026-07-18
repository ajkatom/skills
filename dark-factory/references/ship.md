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
  enterprise, and the resume path after `SHIP_APPROVAL_PENDING` or
  `SHIP_UNKNOWN_OUTCOME`). `--decision reconcile|abort` handles the unknown-outcome
  path.

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

## Residual (detection-grade, not prevention-grade)

A same-user actor with control-root write AND a signer private key can mint and
attach a release, and could in principle edit `config.json`'s `ship.approval`.
Forcing a non-empty policy to ride a SIGNED audit manifest HMAC-pins the sealed
config; the nonce ledger + distinct-signer counting bound WHO and HOW-OFTEN.
This is the same same-user residual documented for custody/waiver/override — see
`references/prevention-grade-roadmap.md`.
