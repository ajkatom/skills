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
   the lock cannot be undone), under a restrictive, **configurable and
   live-probed** seccomp profile (M22 Task 1 — see below).

Because `enterprise` inherits the container barrier from `hardened`, it also
inherits RA-07/M46's mount narrowing: the builder container ro-mounts the
**adapter executable FILE**, never its parent directory, so an adapter placed
in a broad directory cannot leak its siblings into the (untrusted, but
egress-locked) builder. As in `hardened`, a multi-file adapter must declare its
extra files explicitly rather than rely on a directory mount. See
`references/hardened.md`.

`enterprise` is **fail-closed**: `df_config` refuses to load an enterprise config
that is missing or weakens any required guarantee (custody block,
`credential_proxy.enabled: true`, `audit.sink.required: true`,
`builder_confinement.enabled: true` **and** `builder_confinement.required: true`,
`audit.signing`), and `resolve_isolation`
refuses at run start if the Docker/OS-sandbox/seccomp probes don't pass (with an
`--allow-downgrade` path that steps down enterprise → hardened → standard →
cooperative, each journaled). The seccomp probe (M22 Task 1) is one of these
gates: a profile that parses fine but doesn't actually deny what it claims to
fails the resolve just like a down Docker daemon does.

Confinement must be **enabled**, not merely **required** (RA-04): the runtime
confine flag is `builder_confinement.enabled`, so a `{enabled: false, required:
true}` block would claim mandatory confinement while running the builder
UNCONFINED. Two layers refuse it: at **any** tier, `required: true` with
`enabled: false` is incoherent (`ConfigError` in the `builder_confinement`
block); and the enterprise gate additionally requires `enabled: true` by name.

## `init --answers` scaffolding (DF-04)

`dark-factory init` can now scaffold a complete, load-valid `enterprise`
config directly — see `references/authoring.md`, "Enterprise answers", for
the full `answers` schema (`approver_pubkeys`, `custody_threshold`,
`credential_proxy`, `audit_sink`, optional `seccomp_profile`). Two rules
worth restating here because they're security-relevant, not just
mechanical:

- **`init` never generates, sees, or stores an approver PRIVATE key.**
  Only public keys travel through `answers`/`config.json` (they're public —
  inlining them is fine). Generate each approver's keypair off-host with
  `supervisor.py df-custody keygen` and distribute the private half
  directly to that approver; `init`'s preflight
  (`df_custody.validate_public_key`) only proves the PUBLIC key you handed
  it parses as a well-formed ed25519 key, nothing about a private key that
  never existed on this host in the first place.
- **`init`'s preflight is offline and shape-only.** It proves the
  `custody.approvers` entries parse as ed25519 public keys and that
  `audit_sink`'s URL/bucket fields are well-formed with `*_env` NAMES
  (never inline secret values) — it never makes a network call. A missing
  operator input is a fail-closed `InitError` (or, with
  `answers.allow_dev_downgrade: true`, a `hardened`-tier scaffold with a
  recorded downgrade note) — `init` never emits an enterprise-shaped config
  that `df_config.load_config` would then reject.

### Manual WORM-readback preflight (operator step)

`init`'s offline preflight cannot, and does not claim to, prove the
configured audit sink is actually **WORM** (write-once-read-many): that a
pushed object reads back byte-identical, and that the bucket/object
carries an **active** retention / Object Lock configuration that would
refuse deletion before the retention period elapses. `df_audit_sink.py`
is explicit about this same boundary at the push layer — `push()` ships
bytes to the configured sink; WORM enforcement is the operator's bucket/
retention policy, not something this codebase can verify without reaching
real infrastructure.

Before relying on a scaffolded (or hand-written) `audit.sink` for real
custody attestations, run this checklist by hand (or wire it into a
CI job that has the real sink provisioned — never in this repo's regular
unit test suite, which never stands up live WORM infra):

1. **Reachability** — push a test object through the configured sink
   (`df_audit_sink.push`) and confirm a 2xx response.
2. **Readback** — fetch the object back (`http-append`: `GET` the same
   key; `s3-objectlock`: a normal S3 `GetObject`) and confirm the bytes
   match exactly what was pushed.
3. **Retention is ACTIVE, not just configured** — for `s3-objectlock`,
   confirm the bucket has Object Lock enabled AND the object itself carries
   a retention mode/date (`GetObjectRetention` — a bucket with Object Lock
   *available* but no default retention policy, or a caller with
   permissions to strip retention, does not actually guarantee WORM). For
   `http-append`, confirm the receiver's own append-only/immutability
   guarantee independently — this repo's reference receiver
   (`df_audit_receiver.py`) demonstrates the wire protocol only and says so
   explicitly in its own docstring: no auth, unencrypted HTTP, not by
   itself a hardened production trust boundary.
4. **Deletion is refused** — attempt to delete or overwrite the test
   object before its retention period elapses and confirm it is refused.

`scripts/df_init.py` carries a deliberately unimplemented stub,
`verify_worm_readback_MANUAL`, marking exactly where this checklist would
plug in as code once real infra is available to test against — it raises
`NotImplementedError` and is never called by `init`, `build_config`, or any
test, so a passing test suite can never be mistaken for a WORM guarantee
that was never actually checked.

## Configurable + live-probed seccomp (M22 Task 1)

M17 shipped exactly one fixed seccomp profile
(`scripts/seccomp/enterprise.json`), sanity-checked only *offline* — parses as
JSON, has a `defaultAction` + `syscalls` shape. That proves nothing about what
the profile actually **does** on a real kernel: a profile with
`defaultAction: SCMP_ACT_ALLOW` and an empty (or wrong) `syscalls` list parses
fine and denies nothing.

M22 Task 1 makes the profile an operator knob and proves it on a real kernel
before trusting it:

- **`enterprise.seccomp_profile`** (`df_config`, optional) — a path to a Docker
  seccomp JSON profile. Absent → the shipped M17 default
  (`scripts/seccomp/enterprise.json`), byte-identical behavior to before this
  task. When given, `df_config` validates at load time (before any run starts)
  that the file exists, parses as JSON, and is a dict with a string
  `defaultAction` and a list `syscalls` — else `ConfigError`. This is a **shape**
  check only.
- **`scripts/seccomp/enterprise-strict.json`** — a stricter shipped variant:
  the M17 denials (`mount`, `umount2`, `ptrace`, `bpf`, module load/unload,
  `kexec*`, `reboot`, `swapon`/`swapoff`, `setns`, `unshare`) plus keyring
  manipulation (`keyctl`, `add_key`, `request_key`), process accounting
  (`acct`), quota manipulation (`quotactl`), and raw I/O port access
  (`ioperm`, `iopl`). Point `enterprise.seccomp_profile` at it for the stricter
  posture.
- **`df_container.probe_seccomp(image, profile_path)`** — the **live** proof.
  Runs a real container under the resolved profile with `--cap-add SYS_ADMIN`
  (added back so a profile that *fails* to deny `mount` would otherwise
  succeed — proving the seccomp filter, not a missing capability, is what
  denies it) and attempts three canary syscalls (`mount`, `unshare`, `ptrace`)
  that must each be denied, plus an ordinary file write under `/tmp` that must
  still succeed. `resolve_isolation` calls this after the existing
  Docker/container-barrier checks; a failing probe fails the enterprise
  resolve exactly like a failing egress/container probe (`PROBE_FAILED` +
  `SandboxError`, or a journaled `DOWNGRADE` under `--allow-downgrade`) — never
  runs under an unverified profile.
- The manifest records `enterprise_seccomp = {"profile": <basename>, "probe":
  "verified"}` on every `enterprise`-tier terminal — unlike
  `enterprise_egress` (below), `"verified"` is honest here: `resolve_isolation`
  only ever returns `"enterprise"` once `probe_seccomp` already ran, live,
  against this run's image and resolved profile, and passed.

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
- `enterprise_egress = {probed: true, passed: bool, policy_digest, checked_at}` —
  **DF-05/M32**: this is a genuinely per-run result, not merely "configured". See
  "Mandatory per-run egress verification (DF-05/M32)" below for what the probe
  proves and does not, and its fail-closed refusal on failure
  (`EGRESS_PROBE_FAILED`, before this run seals `CUSTODY_PENDING` at all).

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

**Custody binds the artifact `object_id` (DF-01/M28a), not just the manifest bytes.**
`attach` first requires the manifest to carry a bound `artifact` (see
`references/audit.md`'s "Artifact binding (DF-01)" section) — a `null` artifact
(a pre-M28a manifest, or a terminal that never froze a workspace) is refused
outright, before any signature check ("predates artifact binding"). It then
independently re-verifies the bound object against the live object store
(`df_seal.verify_object`) and refuses if that object has drifted or gone
missing, even when every signature is otherwise valid. So approvers attesting
K-of-N over the manifest bytes are, transitively, attesting to the **exact
built object** those bytes reference — a signed manifest whose artifact was
mutated or pruned out from under it cannot be attached. `verify-custody`
re-runs this same object re-verification on every check, not just once at
attach time, so a custody attestation that was valid at attach time stops
reading `QUALIFIED` the moment the underlying object drifts.

`attach` reads the immutable manifest and the collected signatures, runs
`verify_custody(manifest_bytes, sigs, config-approvers, config-threshold)`, and:

- **≥K distinct valid approver signatures over an ELIGIBLE manifest** → pushes
  the attestation **off-box first** to the required audit sink, then writes
  `<run_dir>/custody_attestation.json` =
  `{manifest_sha256, threshold, approvers_satisfied, signatures, qualified: true, ts}`,
  anchors it into the per-control-root hash chain (`audit-chain.jsonl`,
  the M13 tamper-evident chain), and records the push in a
  `custody_sink_receipt.json` bound to the exact attestation bytes. Exit 0.
- **fewer than K** → prints PENDING, writes **no** attestation, exit 3.

**Eligibility gate (M44 RA-03).** K-of-N alone does NOT qualify. Before it will
attest, `attach` requires the manifest to be genuinely eligible: `outcome ==
CUSTODY_PENDING` AND its own pre-custody evidence holds — final exam passed (or
no final cohort), `security.failed == []`, and every qualification substate
(barrier ∧ host_isolation ∧ control_plane ∧ app_security ∧ waiver_validity,
recomputed from the sealed manifest via `df_qualify`). A signed-but-ineligible
manifest — `SECURITY_GATE_FAILED`, `HOST_ISOLATION_LIMITED`, a failed final
exam, or any non-`CUSTODY_PENDING` outcome — is **refused (exit 3), never
attested**. `verify-custody` re-checks the same eligibility.

**Required-sink fail-closed + rollback (M44 RA-02).** The off-box push happens
**before** the local attestation is written or chain-anchored. If the required
sink is unreachable, `attach` returns exit 3 leaving **no** local attestation,
**no** chain link, and **no** receipt — the run is not locally qualifiable
(the pre-M44 bug wrote + anchored the attestation first, then returned 3,
leaving a locally-`QUALIFIED` run). `verify-custody` correspondingly REQUIRES
the bound `custody_sink_receipt.json` whenever the sealed config's
`audit.sink.required` is true; its absence is a distinct `SINK_RECEIPT_MISSING`
verdict, never a silent `QUALIFIED`. The same off-box-first + eligibility
discipline applies to `df-waiver attach` and `df-release attach`.

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

## API-adapter proxy mode (M30/DF-03)

M17 shipped the credential proxy (`df_proxy.py`) and, separately, the two
stdlib API adapters (`api_anthropic`/`api_openai`, M24) that let a real model
build inside the enterprise container with no CLI baked into the image. An
audit (DF-03, High) found the two were never actually wired to work
**together**: enterprise passes `env=None` into the builder container (the
proxy is supposed to inject the provider key host-side), but the adapters (a)
exited immediately when their own key env var was absent, and (b) always set
their own `x-api-key`/`Authorization` header — which blocks `df_proxy`'s
injection (it only injects when the header is *absent*). Even fixing just
those two would not have been enough: an HTTPS target reached through
`HTTP(S)_PROXY` (which is all `urllib` — what these adapters use — respects)
is **CONNECT-tunneled**, and `df_proxy.do_CONNECT` is a documented 501 stub
(an opaque tunnel cannot be credential-injected at all — see `df_proxy.py`'s
module docstring). So the enterprise real-model API-adapter path could not
operate as shipped, at any of these three layers.

**The fix — proxy mode.** When the supervisor sets `DF_PROXY_DESCRIPTOR` (a
JSON object) in the builder container's environment, `api_anthropic`/
`api_openai` switch from their normal direct-to-provider request to a
different transport instead of trying to route around the CONNECT problem:

```json
{
  "endpoint": "http://127.0.0.1:PORT",
  "provider": "anthropic",
  "target_base_url": "https://api.anthropic.com",
  "capability_token": "<unguessable per-run token>"
}
```

- `endpoint` — the **local** `df_proxy`, always plaintext HTTP (`http://`);
  the adapter refuses a descriptor whose endpoint isn't `http://host:port`.
- `provider` — `"anthropic"` or `"openai"`; must match the adapter reading
  it (`api_anthropic` requires `"anthropic"`, and vice versa) — a mismatch
  is refused before any network call, defense-in-depth against a
  misconfigured/misrouted descriptor.
- `target_base_url` — the **real** provider (`https://api.anthropic.com` /
  `https://api.openai.com`), never contacted directly by the adapter; only
  `df_proxy` opens a connection to it.
- `capability_token` — the LOCAL workload credential this adapter presents
  to `df_proxy` via `Proxy-Authorization: Bearer <token>` (see below) —
  completely distinct from the provider credential; never sent to the
  provider.

In proxy mode the adapter:
1. **Skips the "no api key" exit** — `ANTHROPIC_API_KEY`/`OPENAI_API_KEY` is
   neither required nor read; the credential never enters this process.
2. **Never sets its own auth header** — no `x-api-key`/`Authorization` is
   added, so `df_proxy`'s "inject only when absent" check fires.
3. **Sends the request as plaintext HTTP to the LOCAL proxy, with the REAL
   provider's absolute `https://` URL as the request TARGET** — `df_proxy`'s
   forward-proxy form (`POST https://api.anthropic.com/v1/messages HTTP/1.1`
   addressed to the *local* `endpoint`), built directly with
   `http.client.HTTPConnection`, **not** `urllib` + `HTTP(S)_PROXY`. This is
   the crux of why it works where the naive approach doesn't: it is a plain
   HTTP forward request whose *target* happens to be an `https://` URL —
   there is no CONNECT tunnel to refuse, because nothing ever asks for one.
   `df_proxy` parses that absolute-URI target, checks it against its
   allowlist, and opens the *real* TLS connection to the provider itself,
   injecting the credential on that leg — exactly the flow `df_proxy.py`'s
   module docstring describes, now actually reachable by an adapter.
4. **Presents `Proxy-Authorization: Bearer <capability_token>`** — see
   "Hardened proxy: capability token" below.

When `DF_PROXY_DESCRIPTOR` is unset, both adapters behave byte-identically
to before this milestone (direct request, own key, own header) — proxy mode
is strictly additive.

**Hardened proxy (M30 Part B).** `df_proxy.serve()` gained three fail-closed
checks on top of the M17 shape, all enforced BEFORE any upstream connection:

- **Capability token** — every forwarded request must present
  `Proxy-Authorization: Bearer <token>` matching the proxy's, or it's
  refused (407), nothing forwarded. This is a *workload* credential (who
  may use the injecting proxy at all) — distinct from, and never sent
  anywhere near, the *provider* credential the proxy injects. `serve()`
  accepts an explicit token, a `capability_token_env` to read one from, or
  (if neither given) generates one and exposes it as `httpd.capability_token`
  — a token is always enforced, never optional.
- **Exact origin match** — the allowlist used to match hostname only (ANY
  port, ANY scheme); it now resolves to a `(scheme, host, port)` set via
  `df_proxy.parse_allowlist_entry`, and a request must match exactly. A bare
  hostname entry now permits only the two default ports (80/443), not "any
  port on that host".
- **Provider method/path lock** — `serve(provider="anthropic"|"openai", ...)`
  (or a custom `allowed_method_path`) restricts requests that are about to
  receive an INJECTED credential to that provider's one expected
  method+path (`POST /v1/messages` / `POST /v1/chat/completions`), so a
  capability token can ride the proxy only to the endpoint it was scoped
  for — not to arbitrary provider APIs. A client-supplied auth header
  (never the injection path) is unaffected by this lock.

**Config-load coherence (M30 Part C).** `df_config.py` validates, at config
LOAD time (before any run starts), that when `roles.builder.adapter` is one
of the two API adapters and `credential_proxy.enabled` is true, the
`credential_proxy.header`/`.allowlist` actually match that adapter's
provider (`api_anthropic` → `x-api-key` + `api.anthropic.com` in the
allowlist; `api_openai` → `authorization` + `api.openai.com`). A wrong
pairing is a `ConfigError` naming the mismatch, not a mystery failure the
first time a real enterprise run tries to reach the provider.

**Supervisor wiring (DF-05/M32).** The supervisor now performs this wiring
itself, in `_run_loop`'s enterprise builder-call region: when
`roles.builder.adapter` is `api_anthropic`/`api_openai` (`df_config.
_adapter_provider`), the run's credential proxy is started with a fresh
per-run `capability_token` (`secrets.token_urlsafe(32)`) and
`provider=<anthropic|openai>` (arming the M30 method/path injection lock —
see "Hardened proxy" above), and the enterprise container is given
`DF_PROXY_DESCRIPTOR` as a plain `-e` env var built from that same token +
the proxy's real endpoint + the provider's real `target_base_url`
(`https://api.anthropic.com` / `https://api.openai.com`). CLI builder
adapters (claude/codex/gemini) get no descriptor and no provider lock —
unaffected, byte-identical to before M32. The journal records that a
descriptor was **wired** (provider, endpoint, target_base_url) — **never**
the capability token value; the token also never appears in the manifest.
This is still not the provider secret entering the container: the token is
a *local workload* credential (proves to the proxy which process may use
it), and the real provider key is still only ever read host-side by the
proxy and injected on its own leg to the provider, exactly as before.
Covered by `tests/test_enterprise_egress.py`.

## Mandatory per-run egress verification (DF-05/M32)

`resolve_isolation`'s enterprise probe deliberately **skips**
`df_container.probe_enterprise_egress` — it needs a running proxy, and at
resolve time the proxy isn't up yet. Historically this meant the manifest's
`enterprise_egress` field was an honest-but-static `{"locked": "configured",
"probe": "unverified"}` — the egress lockdown was *configured* every
enterprise run, but never *empirically re-proven* on that specific run.

DF-05/M32 closes that gap: once the run's real credential proxy is started
(`_run_loop`, `effective == "enterprise"`), `_verify_enterprise_egress` runs
the deferred probe exactly **once per run** (fresh run or resume — both
restart the proxy), **before the first builder call**.

**Fail-closed, no downgrade.** If the probe does not verify — proxy path
broken, egress not actually blocked, a docker error, or any other failure
mode, including an outright exception from the probe machinery — the run
**refuses**: it journals `EGRESS_PROBE_FAILED`, seals a terminal manifest
with `outcome: "EGRESS_PROBE_FAILED"`, `qualified: false`, and
`enterprise_egress: {probed: true, passed: false, policy_digest, ...}`, and
exits 2. The builder is **never invoked**. Unlike a failed OS-sandbox/docker/
seccomp probe at `resolve_isolation` (which can *downgrade* to `hardened`
under `--allow-downgrade`), there is no downgrade path here: an enterprise
run whose egress cannot be proven this run is not enterprise, and
"hardened-but-claiming-egress-was-checked" is not an honest fallback.

**Honest split — what the mandatory probe proves, and what it does not.**
The mandatory probe is deliberately **not** a live round trip against the
real provider through the run's real, operator-configured proxy/allowlist:
- It uses the **same container image and seccomp profile** this run will
  use for the builder, run through the **same** entrypoint/iptables
  lockdown machinery (`df_container.build_enterprise_argv` +
  `probe_enterprise_egress`), so it proves *this run's* transport+lock
  actually holds live: an allowlisted-via-proxy origin is reachable, a
  direct connection to a denied host is blocked, and the child cannot
  re-add an iptables rule (NET_ADMIN dropped).
- The "allowed" leg is a **throwaway, local, always-200 stub server**
  fronted by a **throwaway proxy + capability token** that
  `_verify_enterprise_egress` starts and tears down itself — **not** the
  run's real proxy/allowlist/provider. This is deliberate: when the builder
  is an API adapter, the run's real proxy has the M30 provider method/path
  lock **armed** (see above) — a generic probe request against it would
  either be refused (method/path mismatch) or, worse, if it happened to
  match the locked method+path with no client auth header, trigger a REAL
  credential injection and a real (paid) provider call. Neither is
  acceptable for a probe that runs on **every** enterprise run at **zero**
  cost.
- **It does NOT prove** the real provider accepts the injected key, or that
  the operator-configured allowlist/header pairing is correct end to end —
  that is a live, **paid**, real-provider round trip through the run's
  actual proxy, and is a **separate, optional, operator-invoked** check
  (`test_enterprise_config.py::test_probe_enterprise_egress_live` exercises
  `probe_enterprise_egress` this way directly, skipped cleanly when no
  docker daemon is available).

`policy_digest` is a `sha256` over `{allowlist, header, proxy_endpoint}` —
the egress policy this specific run is configured with — so the manifest
records not just *that* a probe ran, but a compact fingerprint of *what* was
verified. Covered by `tests/test_enterprise_egress.py`.

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
- The seccomp profile (`scripts/seccomp/enterprise.json`, or the stricter
  `scripts/seccomp/enterprise-strict.json`, or an operator-supplied path via
  `enterprise.seccomp_profile`) is a **conservative default** (deny `mount`,
  `ptrace`, `bpf`, kernel-module ops, `setns`, `unshare`, …); a per-role
  hand-tuned profile is a documented refinement (deferred — see below).
- **The live seccomp probe is honest, bounded coverage, not a completeness
  proof.** `probe_seccomp` proves the profile denies the *specific canary
  syscalls it checks* (`mount`, `unshare`, `ptrace`) while still allowing an
  ordinary file write — it raises the floor (a profile that's toothless on
  these three is caught, fail-closed), but it is **not** a full audit of the
  profile: a profile could still leave some *other* dangerous syscall allowed
  that the operator never thought to deny and the probe never checks. Treat a
  passing probe as "doesn't fail on the syscalls we know to ask about," not
  "provably safe against every syscall."
- Approver keys are file/CLI ed25519 keys; an HSM/KMS is a drop-in for
  `sign_manifest` — **deferred** (this module uses file keys; wiring a real
  HSM/KMS signer is separate work, needing real hardware/service integration).
- **mTLS on the credential-proxy channel is deferred** — the proxy currently
  speaks plaintext HTTP on `host.docker.internal`/loopback (a private,
  container↔host channel, not exposed beyond it); real mutual-TLS needs a
  certificate authority and cert lifecycle management, out of scope here.
- **Per-role candidate seccomp is deferred** — the *candidate* (verifier) side
  runs host-side under the OS sandbox (`df_sandbox`), not the enterprise
  Docker container; applying seccomp there is Linux-only `bwrap` wiring,
  separate from this container-side profile, and not built here.
- The `cryptography` dependency is enterprise-only, imported solely by
  `df_custody.py` (`requirements-enterprise.txt`).
- **Waiver allowlist tamper-proofing (M33a / DF-06) — true by construction.**
  The signer allowlist + threshold governing a run are sealed into
  `manifest.security.waiver_policy`, and a non-empty waiver policy **requires
  `audit.signing: true`** (enforced at config load — see
  `references/security-gates.md`), so that seal rides an HMAC-signed manifest.
  No party with control-root write can widen who may waive a sealed run
  without the audit key: appending a rogue pubkey to `waiver_policy` breaks
  `manifest.hmac`, which `attach`/`verify` check. This preserves the
  single-operator-proof property at `standard`+ the same way split-custody's
  config-binding does at enterprise.
- **Trusted remote-timestamp for waiver expiry is deferred (M33a / DF-06).**
  Security-gate **waivers** (`references/security-gates.md`) are signed,
  scoped, and **expiring**: `df-waiver verify` re-checks `issued_at <= now <
  expires_at` against the local clock at every verify. M33a uses **local-time**
  expiry uniformly at every tier, including enterprise — so the residual is a
  **same-user-forgeable clock**: whoever runs the verifier can move the system
  clock to keep an expired waiver "unexpired." This is bounded exactly like the
  detection-grade audit boundary: a waiver stays bound to
  `artifact_object_id` + `gate_report_digest`, so a forged clock **cannot**
  make a waiver replayable across a different artifact or a changed set of
  findings — only extend the acceptance window of the exact finding it already
  named. A trusted remote-timestamp authority (an off-box signed time source
  the verifier can't forge), the enterprise-grade closure, is deferred to the
  same off-host trust-domain infrastructure the rest of prevention-grade needs
  — see `references/prevention-grade-roadmap.md`. The split-custody two-phase
  ship above is the exact pattern the `df-waiver` CLI mirrors.
