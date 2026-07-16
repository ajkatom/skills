# Enterprise tier (M17)

The `enterprise` assurance tier adds three enterprise-only guarantees on top of
everything `hardened` provides (container barrier, signed audit, required
off-box sink, required builder confinement):

1. **Split-custody sign-off** — a run is `qualified` only after **K-of-N distinct
   approvers** each ed25519-sign the run's manifest. No single operator can ship.
2. **Host-side credential proxy** — the raw provider token never enters the
   sandbox; the builder reaches providers only through a proxy that injects the
   token host-side and allowlists destination hosts.
3. **Kernel-locked egress + seccomp** — the enterprise container can reach *only*
   the proxy (iptables default-deny egress, `NET_ADMIN` dropped for the child so
   the lock cannot be undone), under a restrictive seccomp profile.

`enterprise` is **fail-closed**: `df_config` refuses to load an enterprise config
that is missing or weakens any required guarantee (custody block,
`credential_proxy.enabled: true`, `audit.sink.required: true`,
`builder_confinement.required: true`, `audit.signing`), and `resolve_isolation`
refuses at run start if the Docker/OS-sandbox/seccomp probes don't pass (with an
`--allow-downgrade` path that steps down enterprise → hardened → standard →
cooperative, each journaled).

## The split-custody two-phase ship (the core contract)

Split custody is genuinely single-operator-proof, and it is deliberately a
**two-phase** process because approvers can only sign a manifest that already
exists. The manifest is **immutable** — it is the signable artifact — and
qualification is a **separate attestation**, never a rewrite of the manifest.

**Contract:** *an enterprise run is `qualified` if and only if a valid K-of-N
`custody_attestation.json` exists over its immutable manifest bytes.* The
manifest's own `outcome` stays `CUSTODY_PENDING` forever; qualification lives in
the attestation.

### Phase 1 — the run

An enterprise run with required custody **always** terminates `CUSTODY_PENDING`
(exit 3, `qualified: false`). The build itself converged (final exam passed,
security gates passed) — but shipping requires custody sign-off, which cannot
exist yet. The run seals `manifest.json` (the signable artifact) and prints its
path + sha256 + the signing instructions. The manifest never self-qualifies —
that is the whole point (no single process or operator can ship).

The manifest carries:
- `custody = {required_k, approvers, satisfied: false, note}` — counts only, never a key.
- `proxy = {enabled: true, allowlist: [...]}`.
- `enterprise_egress = {locked: "configured", probe: "unverified"}` — the config
  *includes* the egress lockdown; `"unverified"` is honest about the fact that the
  full live egress probe (`df_container.probe_enterprise_egress`) is not re-run on
  every production run (it is expensive/network-dependent; it is exercised by the
  test suite and operator tooling).

### Phase 2a — approvers sign

Each approver signs the **exact sealed manifest bytes**:

```
supervisor.py df-custody sign --manifest <run_dir>/manifest.json --key-file <approver-privkey>
```

This prints a self-describing entry `{"approver": <public_hex>, "sig": <hex>}`.
Collect K-of-N such entries (from distinct approvers) into a JSON list at
`<control_root>/custody-signatures.json`.

Keys are generated with `supervisor.py df-custody keygen [--out-prefix <p>]`
(writes `<p>.key` at mode 0600 + `<p>.pub`, or prints both).

### Phase 2b — attach

```
supervisor.py df-custody attach <control_root> --run-dir <run_dir>
```

`attach` reads the immutable manifest and the collected signatures, runs
`verify_custody(manifest_bytes, sigs, config-approvers, config-threshold)`, and:

- **≥K distinct valid approver signatures** → writes
  `<run_dir>/custody_attestation.json` =
  `{manifest_sha256, threshold, approvers_satisfied, signatures, qualified: true, ts}`,
  anchors it into the per-control-root hash chain (`audit-chain.jsonl`,
  the M13 tamper-evident chain), **and pushes it off-box** to the required audit
  sink (fail-closed: a `required` sink that can't be reached aborts `attach` with
  exit 3, so the single most security-relevant event — qualification — always
  leaves the box). A `custody_sink_receipt.json` records the push. Exit 0.
- **fewer than K** → prints PENDING, writes **no** attestation, exit 3.

The manifest is never modified.

**Config-binding — the custody policy is pinned to the run it gates.** Both
`attach` and `verify-custody` first compare the manifest's sealed `config_sha256`
(the hash of the canonical config in effect when the manifest was sealed) against
the *current* `config.json`'s hash, and **refuse on any mismatch**. This closes
the single-operator bypass where the operator who ran the build — who necessarily
has control-root write access — edits `config.json`'s `custody` block *after* a
legitimate K-of-2 run to declare themselves the sole approver at `threshold: 1`
and self-signs: any edit to `config.json` changes `config_sha256`, so the
attestation is refused. The custody policy that qualifies a run is exactly the one
that ran it; changing it means re-running under the intended config.

### Confirming qualification

```
supervisor.py verify-custody <control_root> --run-dir <run_dir>
```

`verify-custody` is read-only and tamper-evident. It recomputes the **current**
manifest sha256, loads `custody_attestation.json`, checks that the attestation
binds *this* manifest (`manifest_sha256` must match — a one-byte manifest edit
breaks it), and **re-verifies** the attestation's recorded signatures still
satisfy K-of-N over the current manifest bytes against the config's approver
allowlist + threshold (so a forged attestation, or one carrying rogue approvers
or a lowered threshold, fails). Prints `QUALIFIED` (exit 0) or a
`PENDING`/`INVALID` reason (exit 1).

## Token never in the sandbox

The enterprise container is passed **no credential env at all** — the credential
proxy is the sole credential path (the token is read host-side by the proxy and
injected on the proxy→provider leg). As a fail-closed guard, `df_config` refuses
an enterprise config where `credential_proxy.token_env` also appears in
`credentials.allowlist` (which would otherwise bake the token into the container
as a `-e` var).

## Honest scope

- The credential proxy is a **reference** host-side broker proving the pattern
  (token never in-sandbox, host-allowlisted egress); a production deployment
  points it at a hardened proxy appliance. `host.docker.internal` is a Docker
  Desktop convenience for reaching the host-bound proxy; a native-Linux Docker
  Engine deployment would additionally need `--add-host=host.docker.internal:host-gateway`.
- The egress lock is kernel-enforced **inside the container's Linux kernel** and
  live-tested (`probe_enterprise_egress`): allowlisted-via-proxy reachable,
  direct-to-other-host denied, and the child cannot re-add iptables rules
  (NET_ADMIN dropped from the bounding set — irrevocable).
- The seccomp profile (`scripts/seccomp/enterprise.json`) is a **conservative
  default** (deny `mount`, `ptrace`, `bpf`, kernel-module ops, `setns`,
  `unshare`, …); a per-role hand-tuned profile is a documented refinement.
- Approver keys are file/CLI ed25519 keys; an HSM/KMS is a drop-in for
  `sign_manifest`.
- The `cryptography` dependency is enterprise-only, imported solely by
  `df_custody.py` (`requirements-enterprise.txt`).
