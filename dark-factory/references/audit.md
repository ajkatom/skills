# dark-factory audit manifest — tamper-evidence (M5a)

Every run writes a `manifest.json` + `manifest.sha256` sidecar pair. The signed variant adds a `manifest.hmac` file, opt-in via config. Both are tamper-evident *only while the key stays secret*.

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
- **`hardened` tier** (infrastructure-gated, not yet built): Per-role capability manifests in a container/VM sandbox where the key path itself is unreachable even with root. True protection.
- **Off-box/remote audit sink** (not yet built): The enterprise frontier. A verifier running outside the build host, pulling manifests over a trusted channel, anchors the audit chain against local root compromise.

Use `standard` tier signing for development/CI sanity checks. Upgrade to `hardened` tier or remote audit for supply-chain integrity assurance.
