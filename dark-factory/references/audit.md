# dark-factory audit manifest — tamper-evidence (M5a) + hash chain / off-box sink (M13)

Every run writes a `manifest.json` + `manifest.sha256` sidecar pair. The signed variant adds a `manifest.hmac` file, opt-in via config. Both are tamper-evident *only while the key stays secret*.

M13 adds two more layers on top of the per-run manifest, both **always-on** (no config needed to get the base chain) and covered in their own section below: a per-control-root **hash chain** (`audit-chain.jsonl`) that links every run's manifest to the previous one, and an optional **off-box sink** that ships each chain entry outside the run's box.

## Manifest files

**Every run, always** (all tiers, all outcomes):

- `manifest.json`: canonical JSON with the run's outcome, iterations, per-behavior status, qualified flag, journal hash, and — only when the run was signed — `audit_signing: true`. Never written into git/artifacts; kept in the run directory only.
- `manifest.sha256`: a single line, the SHA-256 digest of the manifest text. Detects accidental edits and casual tampering (a local process rewriting both files simultaneously can defeat this; see "Honest limits" below).

## Signed manifest (opt-in)

When `audit.signing: true` in `config.json`:

- Supervisor loads (or auto-creates) a 32-byte key at `audit.key_path` (default `~/.dark-factory/audit.key`).
- The key is stored in hex-encoded text, mode `0600` (read/write owner only).
- **The key is never written into any run artifact** — not the manifest, not the workspace, not the control root.
- After finalizing the manifest, the supervisor HMAC-SHA256-signs the exact canonical manifest bytes and writes `manifest.hmac`: a single line, the hex-encoded signature.

## Verify a run

```
python3 <skill_dir>/scripts/supervisor.py verify-manifest --run-dir <path> [--key-path <keyfile>]
```

**Exit codes:**
- `0`: manifest OK — byte-integrity holds AND (DF-01/M28a) the manifest's bound artifact object independently re-verifies.
- `2`: audit key error — `--key-path` given but the file is missing or malformed. Printed to **stderr** as `dark-factory: audit key error: <detail>`; verification is never attempted (the CLI loads the key with `load_key`, which never creates one — a typo'd path fails closed instead of silently minting a fresh key and reporting a false TAMPERED).
- `4`: manifest TAMPERED (checks failed) or UNVERIFIED (signed manifest, no usable key supplied).
- `5`: ARTIFACT MISMATCH or ARTIFACT UNAVAILABLE — the manifest's byte-integrity checks passed, but the bound artifact object drifted or is missing (DF-01/M28a). See "Artifact binding (DF-01)" below.
- `6`: UNBOUND — the manifest never bound an artifact object at all (DF-01/M28a). See "Artifact binding (DF-01)" below.

**Behavior (prints to stdout, unless noted):**

1. **No `manifest.hmac` file present:**
   - Verifies `manifest.json` SHA-256 matches `manifest.sha256`.
   - Verifies the journal hash embedded in the manifest matches the actual `journal.jsonl`.
   - Missing `manifest.json`/`manifest.sha256`/`journal.jsonl` → `TAMPERED (missing manifest, sidecar, or journal)` (exit 4).
   - If those checks pass, a signature is still *expected* when either the caller passed `--key-path` or the manifest itself has `audit_signing: true` (a signed run whose `manifest.hmac` was stripped) → `UNVERIFIED (expected a signed manifest; manifest.hmac is missing)` (exit 4). This is what closes the "strip the .hmac and it verifies as unsigned OK" gap.
   - Otherwise (genuinely unsigned run, no `--key-path`, no `audit_signing` flag): `OK` (exit 0) or `TAMPERED (manifest.json does not match manifest.sha256)` / `TAMPERED (journal.jsonl does not match manifest)` (exit 4).

2. **Signed manifest** (`manifest.hmac` exists):
   - Same unsigned checks first (same outcomes/exit codes as above if they fail).
   - No `--key-path` given → `UNVERIFIED (signed manifest; supply --key-path)` (exit 4). **Fail-closed: never treat a signed manifest as OK without proof.**
   - `--key-path` given but the file is missing or the key is malformed → the CLI never reaches `verify_manifest`; it prints `dark-factory: audit key error: <detail>` to stderr and exits **2**. (Nothing is written; the key is never auto-created during verification.)
   - `--key-path` given and the key loads, but it is the **wrong** key → `TAMPERED (bad signature)` (exit 4).
   - `--key-path` given and the key is correct → `OK` (exit 0).

## `app_security_qualified` + waiver verification (M33a / DF-06)

`qualified` on a manifest is now the conjunction of the isolation dimension
and an **app-security** dimension. Every `CONVERGED`/`SECURITY_GATE_FAILED`/
`SECURITY_GATES_MISSING` manifest carries `app_security_qualified`: `true` iff
the tier does not mandate security gates (cooperative) **or** the mandatory
gates ran and nothing in `fail_on` failed. At `standard`/`hardened`/
`enterprise`, final `qualified = (tier qualifies) AND app_security_qualified`
— so a security-gate failure, or (fail-closed) mandatory gates that somehow
didn't run (`SECURITY_GATES_MISSING`, exit 3), is never a qualified ship.

A `SECURITY_GATE_FAILED` run can be re-qualified **only** by a separate,
signed `waiver_attestation.json` (never a manifest rewrite — the split-custody
model). `df-waiver verify <control_root> --run-dir <run>` re-evaluates it
against a **live clock**, so waiver expiry is checked at every verify:

| Exit | Status | Meaning |
|---|---|---|
| `0` | `WAIVED_QUALIFIED` | every failing finding covered by ≥K distinct, in-scope, unexpired allowlisted signers, right now |
| `1` | `NOT_WAIVED` | `SECURITY_GATE_FAILED` run with no attached (or not-applicable) waiver attestation — stays not-qualified |
| `7` | `WAIVER_EXPIRED` | satisfiable when attached, but a waiver has since expired — flips back to not-qualified until re-issued |
| `8` | `WAIVER_INVALID` | tamper / scope drift / short count / unreadable attestation, or the sealed manifest failed byte/artifact verification |

The attestation is anchored into the same hash chain as a custody attestation.
See `references/security-gates.md` for the full waiver workflow and binding
model.

## `host_isolation` manifest field (M29b / DF-02 host-read half)

Every terminal manifest (fresh run and resume, including pre-probe abort
branches, which carry a `probed: false` preliminary) has a sealed
`host_isolation` object describing what host-read isolation the CANDIDATE
actually ran under:

```json
{"mode": "default_deny", "probed": true, "passed": true,
 "residuals": ["file_metadata_outside_home"], "qualified": true}
```

- `mode` — `"default_deny"` (macOS standard+, the default: the candidate ran
  under the `(deny default)` profile of `references/isolation.md`'s
  "Default-deny candidate host isolation"); `"allow_host_read_optout"`
  (explicit `candidate_host_read: "allow_host_read"` config);
  `"allow_host_read_downgrade"` (`--allow-downgrade` after a failed
  confinement probe); `"legacy_allow_host_read"` (Linux until M29c);
  `"none"` (cooperative — no candidate sandbox exists).
- `probed`/`passed` — whether `probe_candidate_confinement` ran and what it
  proved, live, per run (and re-proved on every resume).
- `residuals` — the MEASURED leftover channels, named honestly:
  `host_read_open` (every non-default-deny mode), `keychain_mach_ipc_open` /
  `dns_mach_ipc_open` / `system_data_file_open` (disqualifying; each only
  appears if this machine measures the respective channel/file open — all
  closed on the reference macOS backend), `file_metadata_outside_home`
  (structural: stat/existence visibility outside `$HOME`, contents denied),
  `network_unrestricted_open` (candidate_network was configured
  unrestricted — that axis' own choice).
- `qualified` — true ONLY for `default_deny` + probe-passed + no
  disqualifying residual (the metadata and unrestricted-network ones are
  the two structural non-disqualifying entries). This is the
  `host_isolation_qualified` signal **M36's single qualification FSM will
  fold into the overall `qualified` boolean** — M29b computes and seals it
  but does not re-derive top-level `qualified` from it.

## Artifact binding (DF-01)

Before DF-01/M28a, `verify-manifest` only ever checked the manifest's OWN bytes (`manifest.json`, `manifest.sha256`, `journal.jsonl`, and the optional signature) — it said nothing about whether the *built artifact* (the workspace a converged run produced) still matched what the manifest claimed to have shipped. A converged workspace could be silently mutated after the run finished and `verify-manifest` would still print `OK`. DF-01 (audit Critical) closes that gap: seal the artifact **before** the final exam runs, bind its identity into the signed manifest, and make every later verify/custody check re-derive that identity from the live object store rather than trust a mutable workspace path.

**Seal-first object store.** On a CONVERGED dev-loop iteration, the supervisor freezes the workspace into a content-addressed object under `<control_root>/objects/objects/<object_id>/` (with a `<object_id>.json` sidecar recording every file's path/mode/content-hash and every directory) using `scripts/df_seal.py`'s `freeze()` — atomic, no-overwrite publish, fd-relative traversal on the source side so a symlink swapped into the workspace mid-freeze cannot escape the tree. This happens **before** the final exam and mandatory security gates run, and a hostile/unhashable workspace (a symlink, special file, or setuid/setgid/world-writable entry) fails the run closed as `ARTIFACT_UNHASHABLE` — never a qualified/`CONVERGED` terminal — rather than silently shipping something that couldn't be sealed.

**The manifest binds the object.** A successfully-frozen run's `manifest.json` carries:

```json
"artifact": {"object_id": "<sha256-style content hash>", "seal_version": <int>, "file_count": <int>, "dir_count": <int>}
```

`artifact` is `null` for any terminal reached before a workspace exists (e.g. `GATE_FAILED` from the pre-build coverage gate) — this mirrors the existing `snapshot_sha256: null` honesty on early aborts. After the final exam and security gates run, the supervisor re-verifies the already-frozen object against its own sidecar one more time (belt-and-suspenders: nothing should have written into the object store in between, but if it did, this catches it) and only THEN declares `CONVERGED` — a drift caught here also produces `ARTIFACT_UNHASHABLE`, `artifact: null`, never `CONVERGED`.

**`verify-manifest` recomputes the object and fails closed.** After the existing byte-integrity checks pass, `verify-manifest` recomputes the bound object's sidecar from the live object store and requires it to match the manifest's `artifact.object_id` exactly (content, mode, and structure — an added empty directory or a renamed file both count as drift). The full exit-code table:

| Exit | Status | Meaning |
|---|---|---|
| `0` | `OK` | Byte-integrity holds AND the bound artifact object independently re-verifies. |
| `4` | `TAMPERED` / `UNVERIFIED` | Manifest byte-integrity or signature check failed (unchanged from pre-M28a). |
| `5` | `ARTIFACT MISMATCH` | The bound object exists but no longer matches its own recorded identity (content/mode/name/structure drift). |
| `5` | `ARTIFACT UNAVAILABLE` | The bound object is missing from the object store entirely (pruned, never published, or the control root couldn't be derived from `--run-dir` — pass `--object-store` explicitly in that case). |
| `6` | `UNBOUND` | The manifest never bound an artifact object at all. |

`--object-store <path>` overrides the object store location `verify-manifest` checks against; it defaults to `<control_root>/objects` derived from `--run-dir`'s `<control_root>/runs/<id>` layout, and is required when `run_dir` doesn't follow that layout (e.g. a run_dir copied elsewhere for offline verification).

**`UNBOUND` is a distinct non-success — read this before automating on the exit code.** A manifest with no `artifact` field (a pre-M28a manifest, or any terminal that legitimately never reached a frozen workspace — `CAP_REACHED`, a config/gate abort, etc.) is `UNBOUND` (exit `6`), machine-distinguishable from both a clean `OK` (exit `0`) and a `MISMATCH`/`UNAVAILABLE` drift (exit `5`). **Behavior change from pre-M28a — read this if you automate on `verify-manifest`'s exit code:** before this milestone, `verify-manifest` on a legitimately artifact-less terminal (`CAP_REACHED`, a pre-build gate abort, or any manifest written before M28a) passed the (only) byte-integrity checks and printed `OK` (exit `0`). It now prints `UNBOUND` and exits `6` instead. This is an intentional fail-closed tightening — "no bound artifact is not a clean approval" — not a regression: those terminals were never shipping an artifact in the first place, and treating them as `OK` was itself the gap DF-01 closes. If any script or CI gate treated `verify-manifest`'s exit code as a boolean pass/fail, it needs to either special-case `6` as expected for those terminals, or (better) check `manifest.outcome`/`manifest.qualified` directly rather than inferring shippability from `verify-manifest` alone.

**Custody binds to the object, not just the manifest.** `attach_custody` refuses to attach with a `null` artifact ("predates artifact binding") and independently re-verifies the bound object before writing `custody_attestation.json`; `verify-custody` re-verifies the object on every check, not just once at attach time. See `references/enterprise.md`'s custody section for the full contract.

**Attestation eligibility + required off-box receipt (M44 RA-02/RA-03).** Two hardenings on top of the object binding, applied uniformly to all three post-seal attestation paths (`attach_custody`, `df-waiver attach`, `attach_release`):
- **Eligibility (RA-03).** A valid K-of-N (or waiver/release) signature set no longer qualifies an INELIGIBLE manifest. `attach_custody` requires `outcome == CUSTODY_PENDING` AND the manifest's own pre-custody evidence to hold — final exam passed (or no final cohort), `security.failed == []`, and every qualification substate (barrier ∧ host_isolation ∧ control_plane ∧ app_security ∧ waiver_validity), recomputed from the sealed manifest via `df_qualify.derive` — before it will attest. A `SECURITY_GATE_FAILED`, `HOST_ISOLATION_LIMITED`, or failed-final manifest is refused (exit 3), never attested. A security **waiver** only re-qualifies app-security, so its eligibility check is narrower (it must not cover a failed final exam) and is deliberately tier-independent; a **release** approval requires a qualified ship candidate.
- **Required off-box receipt (RA-02).** When the sealed config's `audit.sink.required` is true, the attestation is pushed off-box **first**; a required-sink push failure rolls back fail-closed, leaving NO local attestation, NO chain link, and NO receipt (the pre-M44 bug wrote + anchored the attestation, then returned nonzero, leaving a locally-QUALIFIED run). Each attach writes a `*_sink_receipt.json` bound to the exact attestation bytes (`body_sha256`), and the corresponding verify path (`verify-custody`, `df-waiver verify`, the ship-phase release check) REQUIRES that receipt when the sink is required — its absence is a distinct not-qualified status (`SINK_RECEIPT_MISSING`), never a silent QUALIFIED.

**Honest scope — detection-grade, not same-user prevention.** This is the SAME boundary `finalize_manifest`'s HMAC signing already documents for the manifest itself (see "Honest limits" below), now extended to the artifact object: `df_seal` defends against a symlink/special-file/hostile-permission entry escaping the tree during freeze, a partially-written object being reused, or the published object silently drifting from its sidecar without detection. It does **not** defend against a party with the SAME filesystem write access used to publish the object store deliberately overwriting bytes at that SAME privilege level — there is no cross-user MAC/DAC enforcement here. `verify_object`/`verify-manifest` are the detector for that residual risk (in-model detection: a confined candidate, an accident, or a mutating gate leaves evidence that gets caught, fail-closed), not a same-user-prevention guarantee. Two further scope notes:
- **(Updated M44 RA-01.)** The security gates and the sealed final exam now run against fresh copies MATERIALIZED FROM the sealed object (`R_gates` / `R_exam`), not the live `workspace` — so a final-cohort side effect that mutates `workspace` after the freeze can no longer make the gates certify bytes that differ from the shipped object. The remaining M29d residual is narrower: per-SCENARIO copy-on-run WITHIN the final cohort (isolating one final scenario's writes from a later final scenario in the same cohort) is still deferred.
- The artifact today is **the whole workspace** — a dedicated output-directory split (sealing only a designated build-output subtree rather than everything the builder touched) is deferred.

See `references/prevention-grade-roadmap.md` for the full picture: why this
detection-grade boundary is architecturally where a single-user, stdlib-only
skill has to stop, and the concrete off-host infrastructure (a privileged
signing service, off-host approver keys, an authenticated WORM sink,
fs-verity, namespaced execution) a future project would need to reach real
same-user-hostile prevention.

## Honest limits

**Tamper-evidence holds only while the key stays secret.** A local process with access to the key can forge a new manifest + signature and defeat the entire scheme. This is intrinsic to symmetric HMAC; asymmetric signing + an off-box audit sink are the enterprise upgrade.

**Signature stripping (no key required).** A signed manifest records `audit_signing: true` inside `manifest.json` itself (covered by both `manifest.sha256` and `manifest.hmac`, so it can't be flipped without also breaking the sha256 unless the attacker rewrites that too). This closes the "delete `manifest.hmac` and the run silently reads as unsigned OK" gap:

- Verify **with `--key-path`** (the operator asserting "this run must be signed"): a missing `manifest.hmac` is always `UNVERIFIED (expected a signed manifest; manifest.hmac is missing)`, never `OK` — regardless of what the manifest claims. This is the check that closes the gap fully.
- A **naive strip** (delete only `manifest.hmac`, leave `manifest.json` untouched) is also caught by a **plain** `verify-manifest` with no `--key-path`, because `audit_signing: true` is still in the manifest and the tool reports `UNVERIFIED` instead of `OK`.
- Only an attacker who strips `manifest.hmac` **and** flips `audit_signing` to `false` **and** recomputes `manifest.sha256` (all without the key) can make a *plain, no-key* verify print `OK`. This is the irreducible no-trust-anchor limit of a self-declared flag: nothing in an unsigned check can force a downgraded manifest to admit it used to be signed.

**Always verify signed runs with `--key-path`.** That is the only check that cannot be evaded by a no-key attacker stripping the signature.

**Per-tier reality:**

- **`standard` tier**: The OS sandbox (macOS `sandbox-exec` / Linux `bwrap`) denies reads of **the control root only** (scenarios/runs) — the workspace is intentionally left readable/writable, and **the home directory is not sandboxed at all**. A determined malicious builder can read `~/.dark-factory/audit.key`. Signing there defends against *casual* tampering and unintended overwrites; it does not protect against a hostile build agent.
- **`hardened` tier**: per-role capability confinement (container barrier for the builder, OS sandbox for the verifier) — see `references/hardened.md`. `hardened` also forces `audit.signing: true`, so every manifest AND every chain entry in a hardened run is HMAC-signed by default.
- **Off-box/remote audit sink** (M13, built — see below): a hash chain plus a pluggable append-only remote sink. Read the "Honest limits: the chain vs. the sink" subsection below before treating either as a proof rather than an evidence trail.

Use `standard` tier signing for development/CI sanity checks. Upgrade to `hardened` tier, and/or configure a genuinely off-box `audit.sink`, for supply-chain integrity assurance.

## Hash chain (M13): linking every run's manifest

Every run — regardless of `audit.signing`, `audit.sink`, or outcome (converged, capped, aborted, waived) — appends exactly one entry to `<control_root>/audit-chain.jsonl` immediately after its manifest is finalized:

```
entry_core = {"invocation", "manifest_sha256", "ts"}
chain_hash = sha256(canonical_json(entry_core) + prev_chain_hash)
entry       = {..entry_core, "prev_chain_hash", "chain_hash", "sig"?}
```

- `manifest_sha256` is the digest `finalize_manifest` already writes to `manifest.sha256` — the chain entry binds the EXACT manifest bytes on disk, not a separate hash.
- `prev_chain_hash` is the previous entry's `chain_hash` (or 64 zeros — `GENESIS` — for the control root's first run ever). Because each `chain_hash` folds in the previous one, silently deleting or editing an entry *in the middle* of the chain breaks every link computed from that point forward. (Dropping the most-recent entries — the chain TAIL — is a different, undetectable-locally case; see "Honest limits" below.)
- With `audit.signing: true`, each entry ALSO carries `sig`: an HMAC-SHA256 (the same M5a audit key) over `chain_hash`. A signed chain requires the key to forge a replacement link, not just internal hash consistency.

**Where it's recorded — sidecars and a separate event log, never manifest or journal.** Because the chain entry binds the manifest's *already-finalized* digest, the chain/sink results cannot be written back into that same manifest — embedding them would change the very bytes the entry hashed. So each run_dir gets sidecars instead: `audit_chain.json` (this run's chain entry, a copy of what landed in `audit-chain.jsonl`) and, only when a sink is configured, `audit_sink_receipt.json`. The manifest itself is written exactly once, by `finalize_manifest`, and is never re-finalized.

**`journal.jsonl` stays fully sealed (unchanged from M5a).** The audit anchoring runs *after* `finalize_manifest` has already hashed the whole `journal.jsonl` into `manifest.journal_sha256` (which the chain entry then binds). Writing anything back into `journal.jsonl` afterward would break that whole-file seal. So the audit-anchor events (`AUDIT_CHAINED`, and `AUDIT_SINK_OK`/`AUDIT_SINK_WARN`/`AUDIT_SINK_FAILED`) go to their OWN append log, `<run_dir>/audit_events.jsonl`, which is **not** hashed into the manifest — it is a convenience/debugging trail, not an authoritative record. `verify-manifest` still hashes `journal.jsonl` **whole** and compares it to `manifest.journal_sha256` exactly as it always has; there is no `journal_bytes` prefix, no trailing-line allowlist, and no other narrowing of that check. The authoritative, verifiable audit records are the chain file (`audit-chain.jsonl`, with its signed links, checked by `verify-chain`) and the run_dir sidecars — never `audit_events.jsonl`.

### `verify-chain`

```
python3 <skill_dir>/scripts/supervisor.py verify-chain <control_root> [--key-path <keyfile>]
```

Walks `<control_root>/audit-chain.jsonl`, recomputing every `chain_hash` from its content and the previous entry's hash. Prints `OK: <n> entries` (exit 0) or names the first break (exit 1) — e.g. a tampered `manifest_sha256`, a broken `prev_chain_hash` link (an edited-out or reordered entry), or a missing/invalid signature.

**Fail-closed on a signed chain, mirroring `verify-manifest`:** if ANY entry in the chain carries a `sig` (i.e. the chain was ever written under `audit.signing: true`) and no `--key-path` is given, `verify-chain` refuses to report success — `UNVERIFIED (signed chain; supply --key-path)` (exit 1) — rather than silently doing a structure-only check and calling it OK. Supply the correct key to get a real signature check; a wrong key still reports failure (chain-hash-level checks pass, but the signature fails).

### Off-box sink (M13): `audit.sink`

`audit.sink.kind` (default `"none"`) pushes each chain entry, as it's written, to a remote append-only target:

- **`http-append`**: PUTs the entry to `{audit.sink.url}/audit/{invocation}` against a `df_audit_receiver.py`-compatible receiver. The reference receiver (`python3 df_audit_receiver.py --port N --store-dir DIR`, or `df_audit_receiver.serve(...)` in-process for tests) accepts a PUT to a NEW key (201) and refuses PUT to an existing key (409, no overwrite) — there is no DELETE route at all. That absence of a delete/overwrite code path *is* the append-only guarantee, not merely a documented policy.
- **`s3-objectlock`**: a stdlib-only (no boto3) SigV4-signed PUT to `{endpoint}/{bucket}/{prefix}{invocation}`. The WORM property here is enforced **server-side** by the bucket's object-lock retention configuration — this client only knows how to sign and PUT; against a bucket that isn't lock-enabled, a second push to the same key would simply overwrite it.
- `audit.sink.required` (default `false`) controls what happens when the push fails (network error, receiver down, 409 from a genuine key collision, credentials missing): `true` aborts the run at finalize with a **nonzero exit** and a journaled `AUDIT_SINK_FAILED`; `false` journals `AUDIT_SINK_WARN` and the run proceeds normally. Either way, the **local chain is written first and always** — `audit-chain.jsonl` and `audit_chain.json` exist regardless of whether the sink push ever happens or succeeds.
- Credentials for `s3-objectlock` are never written to `config.json` as literal values — only the NAME of an environment variable (`access_key_env`/`secret_key_env`); `push()` resolves the actual value from `os.environ` at call time. See `references/config-reference.md` for the full field list and validation rules.

## Honest limits: the chain vs. the sink

**The chain alone is tamper-EVIDENT, not tamper-PROOF, and this is intrinsic, not an oversight.** A local process that can rewrite `audit-chain.jsonl` (the same process/account that ran the build, or anyone with filesystem access to the control root) can also recompute a fresh, internally-consistent chain over its own tampered history — `verify-chain` would report `OK` on the FORGED chain, because forging is exactly "recompute every hash correctly over new content." Signing (`audit.signing: true`) raises the bar to "also needs the audit key," but the key lives on the same box by default (`~/.dark-factory/audit.key`), so a sufficiently privileged local attacker can still forge a signed chain from scratch.

**The genuine tamper-resistance anchor is the off-box sink living in a DIFFERENT trust domain than the runner** — not merely a different directory or process. Concretely:

- **Demo, not production:** running the reference `df_audit_receiver.py` on the SAME box as the supervisor (or even a different process under the same account) proves the append-only WIRE PROTOCOL works, but a local attacker who can rewrite the chain loses nothing by also attacking the receiver's store directory — same trust domain, same blast radius. The e2e tests exercise exactly this configuration (in-process, ephemeral port) because it's fast and deterministic to test; it is explicitly NOT the production posture.
- **Production:** the receiver (or `s3-objectlock` bucket) must live somewhere the runner's own compromise can't reach — a separate host/account/cloud project, reachable only over the network, with its own credentials the runner never holds write-broader-than-append access to. An `s3-objectlock` bucket in object-lock/WORM mode, owned by a different AWS account than the one running builds, is the concrete production shape: even someone with full root on the build host cannot delete or overwrite an already-written object during its retention window, because that enforcement lives in AWS's control plane, not on the build host.
- **What `verify-chain`/`verify-manifest` can and cannot prove:** they prove internal consistency of what's currently on the box (and, with a key, that a holder of the key produced it) — they do NOT prove the box wasn't compromised before or during signing. Only an independent, off-box copy (the sink) lets a THIRD PARTY — someone who never trusted the build host — detect a rewrite: compare the box's current chain against what the sink already has; any divergence is evidence of tampering the box itself cannot hide.

**Chain TAIL truncation is undetectable locally — this is the linear-chain limit the sink exists to close.** Each entry links BACKWARD (to `prev_chain_hash`); nothing links forward to a not-yet-written successor. So deleting the most-recent N entries from `audit-chain.jsonl` leaves a shorter chain that is still perfectly internally consistent — `verify-chain` reports `OK` on it, because there is no local record that those trailing entries ever existed (the number of runs isn't independently pinned anywhere on the box). This is exactly what the off-box append-only sink mitigates: the sink already recorded those entries in a different trust domain, so a third party comparing the box's chain head against the sink's contents sees the missing tail immediately. (Mid-chain deletion/edit, by contrast, IS caught locally — it breaks every forward link from that point.)

**`journal.jsonl` is sealed WHOLE — the audit feature does not touch it.** `verify-manifest` hashes the entire `journal.jsonl` and compares to `manifest.journal_sha256`, exactly as in M5a — no prefix, no `journal_bytes`, no trailing-line allowlist. This holds because `_anchor_audit` writes its events to a separate `audit_events.jsonl` (see the chain section above), never appending to the sealed journal. Any post-finalize edit to `journal.jsonl` — appending a forged line, even one wearing an `AUDIT_*` state, or truncating it — changes the whole-file hash and reads `TAMPERED`.

**Concurrent-append serialization (carried over from the Task 1 review).** `df_audit_chain.append_entry` is crash-safe (read-modify-atomic-replace via a temp file + `os.replace`) but is NOT file-locked against a second, truly concurrent writer appending to the SAME control root's `audit-chain.jsonl` at the same moment — two processes could both read the same "last entry," compute the same `prev_chain_hash`, and one append could silently clobber the other's (last writer wins, `os.replace` is atomic but the read-then-write is not a single atomic transaction across processes). This is not a new gap introduced by M13's supervisor wiring: `acquire_lock`/`release_lock` already serialize the supervisor's OWN runs per control root one at a time (see the top of this file's `run()`/`resume()`), so a single supervisor never appends concurrently with itself. It only matters if something OTHER than the supervisor's own lock-protected run/resume calls `df_audit_chain.append_entry` directly against a shared control root (e.g. a future multi-writer or distributed setup) — that scenario is out of scope for M13 and would need its own file lock around the chain file specifically, not just the existing per-run lock.

## M36a: the `qualification` field + the phase-aware FSM chain

### `manifest["qualification"]` — the single qualification state machine
Every terminal manifest now carries a `qualification` object computed by ONE
pure function (`df_qualify.derive`):

```json
"qualification": {
  "qualified": false,
  "substates": {"barrier": true, "host_isolation": false, "control_plane": true,
                "app_security": true, "waiver_validity": true},
  "code": "HOST_ISOLATION_LIMITED"
}
```

`qualified` is the AND of five sub-states, evaluated in a fixed precedence
(first-failing wins the `code`):

1. `barrier` — the effective tier is probe-proven isolated (`_QUALIFYING_TIERS`).
   Fail → `BARRIER_UNQUALIFIED` (cooperative seals the legacy
   `COMPLETE_UNQUALIFIED` outcome).
2. `host_isolation` — `host_isolation.qualified` (M29b). **This is the M36a
   security fix:** pre-M36a the top-level `qualified` was
   `barrier ∧ app_security` and simply ignored host isolation, so a standard run
   downgraded to `allow_host_read` still sealed `COMPLETE_QUALIFIED`. It now
   gates `qualified`; fail → distinct outcome `HOST_ISOLATION_LIMITED`.
3. `control_plane` — a real content-addressed artifact object_id is bound.
   Fail → `CONTROL_PLANE_UNVERIFIED`.
4. `app_security` — `app_security_qualified` (M33a). Fail → `SECURITY_GATE_FAILED`.
5. `waiver_validity` — no waiver in play, or a valid attestation covers every
   finding. Fail → `WAIVER_INVALID`.

**Superset (fail-closed) invariant:** because the old expression's two booleans
were exactly `barrier` and `app_security` and `derive` only ADDs conjuncts, it
can newly FAIL a run the old code passed but can never newly PASS one the old
code failed. On the CONVERGED terminal the supervisor passes the exact decided
booleans; every other terminal gets an auditability record derived from manifest
fields (conservative — `app_security` defaults False when unknown, so a failed
terminal never over-claims `qualification.qualified: true`). For an **enterprise**
run the five sub-states are orthogonal to split custody: `qualification.qualified`
may be true while the top-level `qualified` is false (shipping still needs the
K-of-N attestation).

### The versioned, phase-aware, hash-chained FSM checkpoint (`state_version: "0.2"`)
A resumable pause now records its FSM `phase` (e.g. `AWAIT_VERIFY_3`,
`AWAIT_BUILD_2`, `AWAIT_BUDGET_2`) and appends a transition to a per-run
`fsm_chain.jsonl`. Each entry is
`{seq, phase, ts, prev_chain, bound_ids, entry_hash}` where
`entry_hash = sha256(canonical_json({seq, phase, ts, prev_chain, bound_ids}))`
and `bound_ids` binds the run's `artifact.object_id` (once sealed) + the
scenario-set hash. The latest `entry_hash` is recorded in `state.json`
(`fsm_chain_head`).

On **every** resume the whole chain is recomputed and verified — seq ordering,
each `prev_chain` linkage, each `entry_hash`, and that the head matches the saved
state's recorded head. Any mismatch → `FSM_CHAIN_CORRUPT` on stderr + exit 2
(fail-closed), journaled `FSM_CHAIN_CORRUPT`. A pre-M36a `state_version:"0.1"`
state (no chain) resumes through a back-compat path journaled
`FSM_CHAIN_ABSENT_LEGACY`.

**Honest scope:** the FSM chain is **corruption-detection (in-model)** — it
catches an accidental truncation/edit of the transition log or the recorded head
across a pause. It is explicitly NOT forgery-resistance against a same-user
process that can rewrite both `fsm_chain.jsonl` and `state.json`'s head together
(exactly the detection-grade scope of the manifest sha256 sidecar; a
signed/off-box anchor is the hardened+ story — see "Honest limits" above).

## Resume overrides, spec-fork lineage, before-ship pause (M36b)

**Signed resume overrides** (`df_override`). Raising a BUDGET-PAUSE'd run's
budget ceiling at resume is a policy change and must be authorized, not silent.
A `resume_overrides: {approvers:[pubkey_hex,...], threshold:int}` config block
governs it (absent ⇒ threshold 0 ⇒ no override accepted — fail-closed). An
override file is `{claim, signatures:[{approver,sig}]}` where the canonical,
signed claim is

```
{override_version:"1", run_id, override_type:"budget_ceiling",
 params:{new_usd_ceiling}, issued_at, expires_at, nonce}
```

`resume --override <file>` verifies it BEFORE any builder call, reusing
`df_custody` ed25519 (distinct-approver-by-pubkey counting). Every gate is
fail-closed: `override_version` schema pin, `run_id` binding (an override for
run A can't apply to run B), `issued_at <= now < expires_at` against a live
clock, `≥ threshold` distinct allowlisted approver signatures, and **replay
protection via the append-only `<control_root>/override-nonces.json` ledger** —
a used nonce is rejected, so an override authorizes exactly ONE resume,
independent of the supervisor HMAC. A valid override journals `OVERRIDE_APPLIED`
(type, params, distinct signer count, nonce, prev/new cap) and raises this
resume's effective `budget.max_usd`; anything invalid/expired/replayed/
short-threshold journals `OVERRIDE_REJECTED` and refuses (exit 2). A non-empty
policy REQUIRES `audit.signing` so the sealed `config_sha256` pinning the
approver allowlist is HMAC-protected. Credential-VALUE refresh needs NO override
(resume already re-resolves credentials every time under the sealed policy).

**Spec-fork lineage** (`df-fork`). `df-fork <cr> --parent-run <run_dir>` starts a
NEW run seeded from a PARENT run's sealed artifact object instead of an empty
workspace. The parent must verify clean (`verify-manifest` == OK) and bind an
`artifact.object_id`; its frozen object is materialized (`df_seal`,
validate-before-materialize) into the child's fresh workspace. The child's
manifest records `lineage = {parent_run_id, parent_artifact_object_id,
parent_manifest_sha256, forked_at}` (journaled `FORKED`), and the parent is
marked superseded: `<parent_run_dir>/superseded_by.json` + a `SUPERSEDED` event
in the parent's **unhashed** `audit_events.jsonl` (never its sealed
`journal.jsonl`, which would break the parent's journal seal). A superseded
parent STILL verifies clean — supersession is provenance, not tampering — but
`verify-manifest` PRINTS the supersession so a stale artifact isn't shipped
unknowingly.

**`SHIP_DECLINED`** (before-ship pause). Under H1/H2 a converged, frozen artifact
pauses at `AWAIT_SHIP` for a human ship approval (see `references/modes.md`).
`resume --decision continue` seals via seal-reentry (re-verify the frozen object,
re-run gates, seal via `df_qualify.derive`) with NO builder re-dispatch
(`SHIP_RESUME` journaled). `resume --decision abort` from `AWAIT_SHIP` seals a
distinct **`SHIP_DECLINED`** terminal (qualified `False`) that still binds the
frozen artifact object, so the declined candidate stays auditable.

## The ship phase (M41) — `ship_result.json` + release attestation

When a `ship` block is configured, a **qualified** run continues past the sealed
artifact into a governed ship phase (see `references/ship.md`). This NEVER
rewrites `manifest.json` — `qualified` is not re-opened by shipping. Instead it
writes SEPARATE, audit-chain-anchored sidecars in the run directory:

- `ship_journal.jsonl` — the ship phase's crash-safety journal (SEPARATE from
  the SEALED `journal.jsonl`, which may never be appended to). Each action
  journals `SHIP_ACTION_INTENT` (fsync'd, reserved) BEFORE it spawns and
  `SHIP_ACTION_RESULT` after; also `SHIP_STARTED`, `SHIP_ROLLED_BACK`,
  `SHIP_ROLLBACK_FAILED`, `SHIP_APPROVAL_PENDING`, and the terminal.
- `ship_result.json` — the sealed ship record: `{ship_version, outcome,
  actions:[{name, reversible, status, exit, approval_ref}], rollbacks,
  rollback_failed, ship_workspace_object_id, ts}`. Anchored into
  `audit-chain.jsonl` (a `<run_id>.ship.<n>` entry) exactly like
  `custody_attestation.json`.
- `release_attestation.json` — written by `df-release attach`: the verified
  K-of-N approval `{attestation_version, claim, signatures, approvers_satisfied,
  qualified, ts}` for irreversible actions. Anchored as a `<run_id>.release.<n>`
  chain entry. The single-use nonce is recorded in `<control_root>/release-nonces.json`.
- `ship_logs/<action>.stdout|.stderr` — captured, **redacted** action output
  (brokered credential values are scrubbed before the bytes hit disk).

**Ship outcomes** (in `ship_result.json`, distinct from the manifest outcome):
`SHIPPED` (exit 0) · `SHIP_FAILED` (exit 3; rollback ran in reverse; a
`rollback_failed:true` is surfaced loudly) · `SHIP_APPROVAL_PENDING` (exit 3; an
irreversible action awaits a signed `df-release` approval — the run stays
qualified, nothing irreversible ran) · `SHIP_UNKNOWN_OUTCOME` (exit 11; an action
was reserved but its outcome is unknown after a crash — needs `ship --decision
reconcile|abort`, never a blind re-run).

## `authored_by` manifest field (M40)

When the hidden scenarios were written by an **agent** author (a `roles.author`
block, see `references/authoring.md`), every terminal manifest carries
`authored_by = {adapter, adapter_sha256, same_model_ack}` — the independent
author adapter's path + content hash, and whether the different-model guarantee
was explicitly waived (`same_model_ack: true` means the author was allowed to
be the SAME model as the builder, a weaker guarantee an auditor should notice).
For a human-authored control root (no `roles.author`) the field is `null` —
byte-identical to pre-M40 on every terminal, including the pre-build aborts.
`authored_by` records only WHO wrote the scenarios, never their content; the
authoring step's own control-plane journal (`<control_root>/authored.jsonl`,
`AUTHORED_SCENARIOS`) likewise records adapter/attempts/counts only. The
barrier is unchanged: agent-authored scenarios seal through the exact path
human-authored ones do, so `run` and `verify-manifest` are untouched.

## `adequacy` + `critic` manifest fields (M42)

Every terminal that ran the M7 pre-build gate seals `adequacy` — the auditable
"how thorough were the tests" record:

- `required_classes`, `min_per_class` — the resolved policy.
- `checked` — false iff there is no `behaviors.json` to key class coverage on.
- `per_behavior_class_coverage = {behavior: {happy, boundary, failure}}` and
  `under_covered = [{behavior, missing:[classes]}]` — the class-coverage gate.
- `sharpness = {scenarios, min_killed, weakest}` — the assertion-mutant battery
  summary. `min_killed` is the weakest per-scenario kill count; `weakest` is the
  ids of any non-sharp scenarios (empty on a passing gate, which refuses to
  build otherwise).
- `critic` — `null` if no `roles.critic`; otherwise `{enabled, review}` where
  `review` (read back from `authored.jsonl`'s `CRITIC_REVIEW`) is `{rounds,
  blocking_resolved, advisories}` or `null` if the critic hasn't run.

A top-level `critic = {adapter, adapter_sha256, same_model_ack}` mirrors
`authored_by` — WHICH independent model reviewed the scenarios and whether the
two model-distinctness inequalities were waived. `null` with no `roles.critic`.

None of these records carry any scenario `then` content — mutant KINDS
("stdout_equals:empty") and class NAMES are category labels, barrier-safe. The
critic's own advisories live in `<control_root>/scenario_review.md` (control
plane, never the workspace). See `references/scenario-adequacy.md`.

## `property` manifest field + `PROPERTY_VIOLATED` journal event (M43a)

Every terminal that ran the M7 pre-build gate seals `property` — the
reproducibility + audit record for generative property/fuzz scenarios
(`references/scenario-format.md`):

- `scenarios = {scenario_id: {cases, seed, invariant}}` — with the seed
  recorded, a property run (and any counterexample) is replayable
  bit-for-bit: generation is a pure function of (seed, spec). Empty (but
  present) when the control root has no property scenarios. **A concurrency
  scenario (M43b) additionally records `{workers, attempts}`** — so the
  PROBABILISTIC detection strength of a PASS is auditable: absence of an
  observed race is not proof of race-freedom, and `workers × attempts × cases`
  quantifies how hard the oracle looked.
- `violations = [{cohort, iteration, behavior_id, invariant, case_index,
  counterexample_recorded}]` — one entry per failed property scenario per
  verify pass, VALUE-FREE: it says a counterexample EXISTS and where the
  operator can find it, never what the generated input was. **A concurrency
  violation (M43b) additionally carries a value-free `attempt_index`** (the
  int index of the interleaving attempt that struck — ONE STRIKE = fail),
  never a generated value or a per-worker observation.

Each violation is also journaled as **`PROPERTY_VIOLATED`** with the same
value-free fields. The counterexample CONTENT (the generated vars + per-step
observations + detail) lands in exactly one place: the control-plane
verifier report (`verifier_report_iter_*.json` / `final_exam_report.json` in
the run dir). It never enters the builder workspace, `feedback.json`
(id_feedback's `ALLOWED_FAILURE` keyset structurally forbids it — the
feedback carries only behavior-id + the fixed taxonomy `property_violated`),
the journal, or the manifest.
