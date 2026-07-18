# Example: reversible staging deploy (+ a commented irreversible prod gate)

A **reversible** staging deploy with a `rollback`, plus a commented-out
**irreversible** prod action showing the signed-approval gate.

Files:
- [`deploy.sh`](./deploy.sh) — a safe stub deploy script (echoes only; reads a
  brokered `STAGING_DEPLOY_TOKEN` from the env without printing it).
- [`ship.config.json`](./ship.config.json) — the `ship` block to paste into
  `config.json`.

## The reversible staging action

`deploy-staging` is `reversible: true`, so it runs **unattended** after the run
qualifies. It declares a `rollback`: if a *later* ship action fails, the runner
invokes `./deploy.sh --rollback` (and each prior succeeded action's rollback, in
reverse order) before sealing `SHIP_FAILED`. `creds.env: ["STAGING_DEPLOY_TOKEN"]`
names an env var resolved **host-side at action time** — its value reaches only
the `deploy.sh` subprocess env, never config/journal/manifest/logs (captured
stdout/stderr is redacted).

## The irreversible prod action (commented) and the `df-release` gate

A production deploy is `reversible: false`. That requires:
1. `assurance: hardened` or `enterprise` (an irreversible prod push off an
   unqualified-isolation tier is refused at config load), and
2. a `ship.approval` policy (`approvers` + `threshold`) — which also **forces
   `audit.signing: true`** so the sealed approver allowlist is HMAC-protected.

With those set, the ship phase seals **`SHIP_APPROVAL_PENDING`** the first time
it reaches the prod action — it never runs it, and never blocks (reversible
actions before it still ran). To authorize the one prod action:

```
# 1. each approver generates a keypair once
supervisor.py df-release keygen --out-prefix approver1

# 2. sign a claim bound to THIS run + artifact, scoped to the action
supervisor.py df-release sign --manifest <run_dir>/manifest.json \
    --actions deploy-prod --expires 2026-09-01T00:00:00Z --key-file approver1.key

# 3. collect the {claim, signatures} (merge signatures lists for K>1) into
#    <control_root>/release-approval.json, then attach:
supervisor.py df-release attach <control_root> --run-dir <run_dir>

# 4. run the gated action
supervisor.py ship <control_root> --run-dir <run_dir>
```

The approval is bound to `run_id + artifact_object_id + action_names`, expires on
a live clock, and its nonce is single-use (recorded in `release-nonces.json`) —
it can never be replayed for another run, artifact, action, or a second ship.
This holds in **every** mode, including H4 lights-out: a lights-out run does the
*doing*, but a human is accountable for the irreversible prod action via a
one-time signature, never by running the command.

## Crash safety

Each action journals `SHIP_ACTION_INTENT` (fsync'd) **before** it spawns and
`SHIP_ACTION_RESULT` after. If a process dies in between, `ship` refuses to
re-run (`SHIP_UNKNOWN_OUTCOME`, exit 11) until you `ship --decision reconcile`
(accept a possible duplicate) or `--decision abort` — never a blind re-deploy.
