# Example: ship a qualified artifact to a `release/` branch (reversible)

A minimal, **reversible** ship action: after a run seals `COMPLETE_QUALIFIED`,
push the sealed artifact to a `release/<id>` branch. Because pushing a fresh
release branch is reversible (delete the branch), no release approval is
required — it runs **unattended in every mode, including H4 lights-out**.

## Wire it up

Merge the `ship` object from [`ship.config.json`](./ship.config.json) into your
control root's `config.json`, then run as usual.

## What happens

1. The build/verify loop converges and the artifact is **sealed + qualified**
   (`COMPLETE_QUALIFIED`, `qualified: true`) — exactly as before M41.
2. The **ship phase** then auto-runs: a fresh workspace is materialized from the
   sealed artifact object (re-verified by identity), and the `git push` runs
   with that workspace as its cwd.
3. On success the run seals a `ship_result.json` (`outcome: SHIPPED`) and
   anchors it into the audit chain. `manifest.json` is **never rewritten** — the
   run stays `qualified: true`; shipping is recorded in a separate sidecar.

## H4 (lights-out) flow

Under `intervention_mode: H4` the qualified seal and the reversible ship happen
in one unattended `run`. Nothing pauses; the push just runs. (An *irreversible*
action would instead park at `SHIP_APPROVAL_PENDING` and wait for a signed
`df-release` approval — see the `ship-deploy-staging` example.)

## Run the ship phase as a separate, deliberate step

Instead of auto-after-seal you can ship later against an already-qualified run:

```
supervisor.py ship <control_root> --run-dir <control_root>/runs/<run_id>
```

## Honest scope

The push runs with **real git + network** — it is NOT network-sandboxed. The
protection is that it runs ONLY on a **qualified** artifact, on the **sealed
bytes**, with a full audit trail — not confinement. See `references/ship.md`.
