# Live validation & the production-GO evidence bundle

The hermetic test suite proves the *mechanism*. Codex's R5 arbitration
(`audit/10-r5-codex-arbitration.md`) splits acceptance into two milestones:

| Status | What it means | What proves it |
|---|---|---|
| **Code-complete; operational validation pending** | The implementation + deterministic tests satisfy the code-level acceptance criteria. | `M56–M60` merged, the full hermetic suite green, the R5 reproductions retained as regressions. |
| **Production-validated release GO** | A representative live hardened-H4 and enterprise exercise succeeds on real infrastructure and its evidence is independently verifiable. | The **evidence bundle** below, produced from a live run on disposable staging. |

Several defining claims depend on external reality that unit tests **cannot**
prove: real Docker/kernel isolation + seccomp on the deployment host, egress
confinement to the real credential proxy, the provider/credential path without
leaking the raw token into the container, server-issued readback of the exact
S3 Object-Lock object version, active retention in a separate trust domain,
custody signatures over the exact sealed manifest, and end-to-end re-entry
after a real sink outage. This runbook is how an operator runs those exercises
and captures the bundle. **It never modifies a real production target** — it
uses disposable staging.

> This is an **operator** procedure. It requires real infrastructure and
> secrets that live only on the operator's hosts; it is deliberately NOT run by
> the build agent or in CI.

## Disposable staging you provide

- a harmless sample application to build (e.g. `examples/kv-service`);
- a **digest-pinned** builder image on the target class of host
  (`hardened.image: "…@sha256:…"`);
- real Docker + kernel controls (cgroups, seccomp, netns) on that host;
- **test-only** provider credentials and custody keypairs (never production keys);
- a genuinely remote Object-Lock/WORM bucket (or equivalent separate-trust-domain
  sink) — NOT a same-host receiver, NOT local non-WORM storage;
- reversible / no-op ship actions through the boundary; and
- one irreversible action that proves approval gating **without mutating production**
  (e.g. writing a tag to a throwaway repo/bucket).

Using mocks, injected probes, a local same-host receiver, or local non-WORM
storage keeps you at **"mechanism tested,"** never "production-validated."

## Exercise A — hardened H4 (lights-out)

1. Scaffold a hardened control root with `intervention_mode: "H4"`,
   `hardened.image` digest-pinned, `hardened.network` as your builder needs,
   and any `roles.builder.support_files` your adapter imports.
2. `supervisor.py run --control-root <cr> --project-src <sample>` on the real host. H4 must run
   to a terminal with **no** pause. Confirm the manifest seals
   `requested_tier: "hardened"`, `effective_tier: "hardened"` (no silent
   downgrade), `denial_probe_passed: true`, and a `container.resolved_image_digest`
   equal across every dispatch.
3. `supervisor.py verify-manifest --run-dir <run> --key-path <key>` and
   `supervisor.py verify-chain <cr> --key-path <key>` — both must verify.
4. Ship a reversible action; then re-run `ship` and confirm it is idempotent
   (no duplicate action).

## Exercise B — enterprise custody + required WORM sink

1. Scaffold an enterprise control root: `assurance: "enterprise"`,
   `custody.threshold ≥ 2` with N distinct approver keys, a **required**
   `audit.sink` of `kind: "s3-objectlock"` pointing at the remote WORM bucket,
   and the credential proxy allowlist for your test provider.
2. `supervisor.py run --control-root <cr> --project-src <sample>`. It seals `CUSTODY_PENDING`
   (exit 3) — qualification requires the K-of-N attestation.
3. Each approver: `supervisor.py df-custody sign …` over the exact sealed
   manifest; collect signatures; `supervisor.py df-custody attach <cr> --run-dir <run>`.
   Attach pushes the qualification off-box — confirm the WORM bucket received it.
4. `supervisor.py ship <cr> --run-dir <run>` for the reversible action; then the
   irreversible action → `SHIP_APPROVAL_PENDING`. `df-release sign` + `attach`,
   then `ship` again. Confirm the required S3 receipt records a **version_id**
   and that re-entry positively reads back the exact version's bytes.
5. Optional: simulate a sink outage between ship and the readback and confirm the
   run becomes `SHIPPED_AUDIT_PENDING`/exit 12 (fail-closed), then completes on a
   later retry — never a duplicate deployment.

## Assemble the evidence bundle

After each exercise completes, produce the machine-checkable bundle:

```
supervisor.py evidence-bundle <control_root> --run-dir <run_dir> \
    --key-path <audit_key> --out bundle.json
```

`df_evidence_bundle` is **read-only** and re-runs nothing, but it is **not
offline** (DF-R7-07): verifying a required off-box sink receipt performs a
read-only HTTP GET (http-append) or a signed S3 GET (s3-objectlock) against the
remote sink — so bundle assembly needs network reachability to the sink and, for
S3, usable read credentials (`DF_AUDIT_S3_ACCESS_KEY` / `DF_AUDIT_S3_SECRET_KEY`).
It never writes to the sink. Pass `--require-production --profile hardened-h4`
(Exercise A) or `--profile enterprise` (Exercise B) to get a fail-closed
production verdict. It pulls, from the sealed artifacts, exactly the fields the
arbitration requires and drops any secret-bearing value:

- exact source commit + `config_sha256` / `spec_sha256` / `scenario_set_sha256`;
- `requested_tier` and `effective_tier`;
- resolved/persisted image digest;
- denial, confinement, seccomp, and egress probe results;
- sealed `manifest_sha256` and artifact object identity;
- signed-chain verification output;
- custody claim / signatures / attestation facts;
- off-box sink key + **version_id** + body sha256 for each receipt;
- ship result + release-approval result; and
- re-entry proof (`no_duplicate_actions`).

**The bundle contains no credential values.** Review it, then attach it to the
re-audit submission.

## Re-audit entry criteria (from the arbitration)

Start the next adversarial re-audit only when: `M56–M60` are at one pinned
commit; every R5 reproduction is retained as a regression plus the generalized
class tests; the full hermetic suite passes; every environment-dependent
skip/failure is itemized; and the submission **states** whether it seeks
**code-complete** status or full **production-validated release GO**. If it seeks
production GO, attach this evidence bundle. If it seeks code-complete, the audit
must explicitly retain "operational validation pending" and must not describe
enterprise delivery as production-proven.
