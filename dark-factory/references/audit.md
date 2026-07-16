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
- `0`: manifest OK (unsigned, or signed and signature verified).
- `2`: audit key error — `--key-path` given but the file is missing or malformed. Printed to **stderr** as `dark-factory: audit key error: <detail>`; verification is never attempted (the CLI loads the key with `load_key`, which never creates one — a typo'd path fails closed instead of silently minting a fresh key and reporting a false TAMPERED).
- `4`: manifest TAMPERED (checks failed) or UNVERIFIED (signed manifest, no usable key supplied).

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
