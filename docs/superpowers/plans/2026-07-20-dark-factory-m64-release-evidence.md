# M64 — release-attach transaction + evidence bundle v2 (Codex R6 DF-R6-08/07/10)

Branch `dark-factory-m64-release-evidence` (from main AFTER M62 merges — both touch supervisor.py).

## DF-R6-08 (Medium) — release attach is not crash-consistent
Current order in `attach_release` (~supervisor.py:8655): push off-box (fail-closed ✓) → **record_nonce**
→ write attestation → `_anchor_ship_local` (**result IGNORED**) → write receipt.

Crash windows, all of which BURN a one-time approval:
- after nonce, before attestation → nonce consumed, no attestation; re-attach rejects the consumed nonce;
- after attestation, before required receipt → `_load_release_attestation` refuses it (receipt binding), nonce gone;
- anchor failure → still prints `RELEASE ATTESTED` and returns 0 with no local chain entry.

**Fix — reorder into a replay-safe transaction, nonce LAST:**
1. push off-box (unchanged, fail-closed on required_fail);
2. write the attestation file;
3. write the receipt file;
4. `_anchor_ship_local` — **check the result**; under signing, a failure means NOT attested → report
   evidence-pending and do NOT consume the nonce (a retry re-completes);
5. `record_nonce` LAST — only after all evidence is durable.
Replay-safety: a crash before (5) leaves the nonce UNCONSUMED, so re-running `df-release attach` with the
SAME collected claim redoes 1–5 idempotently — recovery needs no new approver signatures.
Also: `_load_release_attestation` verifies local chain membership, not just receipt binding.

## DF-R6-10 (Medium) — no-action terminal anchor recovery is manual
`_failed_ship_record_bound` rightly refuses a `failed_action:null` record (M56b HIGH fix), but that makes a
materialize-failure / reconcile-abort terminal sealed during a signer outage unrecoverable without manually
deleting the record. Add an AUTHENTICATED terminal-cause token (signed at seal time when the signer is up;
when it is down, the cause is journaled and the re-anchor validates the record against that journaled cause
+ the absence of any action evidence) so these self-heal without state surgery and without ever executing an
action to repair evidence.

## DF-R6-07 (High, release acceptance) — evidence bundle v2
The bundle must PROVE, not summarize:
- **source binding:** seal the source commit + working-tree dirty digest into authenticated run state BEFORE
  dispatch; the bundle reports the SEALED value, never `git rev-parse` at assembly time;
- **manifest:** call the real verifier (HMAC + artifact binding), and prove the manifest digest is a member of
  the verified chain (not merely that the chain verifies);
- **artifact id:** read sealed `manifest.artifact.object_id` (the current top-level lookup is wrong and falls
  back to writable ship-result data);
- **custody + release:** cryptographically VERIFY the attestations (threshold, approver allowlist, scope,
  expiry), not presence/count;
- **receipts:** positively read back and binding-check;
- **re-entry proof:** attempt-aware (M61 `_ship_action_recovery_state`), from authenticated evidence not the
  raw journal;
- **production mode:** `--require-production` fails closed on ANY missing/unverified required section, so a
  partial exercise can never read as a production-GO bundle.

Pipeline: opus review (release-evidence integrity) if a reviewer survives; else rigorous self-review with
recorded repros, as in M61. Full-suite gate before merge.
