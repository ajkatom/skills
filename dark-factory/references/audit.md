# dark-factory audit manifest — tamper-evidence (M5a)

Every run writes a `manifest.json` + `manifest.sha256` sidecar pair. The signed variant adds a `manifest.hmac` file, opt-in via config. Both are tamper-evident *only while the key stays secret*.

## Manifest files

**Every run, always** (all tiers, all outcomes):

- `manifest.json`: canonical JSON with the run's outcome, iterations, per-behavior status, qualified flag, journal hash. Never written into git/artifacts; kept in the run directory only.
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
- `0`: manifest OK (unsigned or signature verified).
- `4`: manifest TAMPERED or UNVERIFIED.
- `2`: audit key error (malformed/missing/wrong size).

**Behavior (prints to stdout):**

1. **Unsigned manifest** (no `manifest.hmac` file):
   - Verifies `manifest.json` SHA-256 matches `manifest.sha256`.
   - Verifies the journal hash embedded in the manifest matches the actual `journal.jsonl`.
   - Print: `OK` (exit 0) or `TAMPERED <reason>` (exit 4).

2. **Signed manifest** (manifest.hmac exists):
   - Same unsigned checks first.
   - **`--key-path` is required**; if omitted or key fails to load → print `UNVERIFIED (signed manifest; supply --key-path)` (exit 4). **Fail-closed: never treat a signed manifest as OK without proof.**
   - Verifies the HMAC signature.
   - Print: `OK` (exit 0) if signature matches, or `TAMPERED (bad signature)` (exit 4).

## Honest limits

**Tamper-evidence holds only while the key stays secret.** A local process with access to the key can forge a new manifest + signature and defeat the entire scheme. This is intrinsic to symmetric HMAC; asymmetric signing + an off-box audit sink are the enterprise upgrade.

**Per-tier reality:**

- **`standard` tier**: The OS sandbox (macOS `sandbox-exec` / Linux `bwrap`) denies the control root and workspace reads/writes, but **the home directory is not sandboxed**. A determined malicious builder can read `~/.dark-factory/audit.key`. Signing there defends against *casual* tampering and unintended overwrites; it does not protect against a hostile build agent.
- **`hardened` tier** (infrastructure-gated, not yet built): Per-role capability manifests in a container/VM sandbox where the key path itself is unreachable even with root. True protection.
- **Off-box/remote audit sink** (not yet built): The enterprise frontier. A verifier running outside the build host, pulling manifests over a trusted channel, anchors the audit chain against local root compromise.

Use `standard` tier signing for development/CI sanity checks. Upgrade to `hardened` tier or remote audit for supply-chain integrity assurance.
