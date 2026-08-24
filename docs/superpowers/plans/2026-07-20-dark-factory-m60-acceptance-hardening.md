# M60 — R5-arbitration acceptance-criteria hardening + live-validation evidence bundle

Branch `dark-factory-m60-acceptance-hardening`, worktree `../skills-worktree-m60`. Closes the
generalized defect CLASSES + the production-GO evidence path Codex's arbitration (audit/10) requires
on top of the already-merged R5 fixes.

## Code changes
- **M60.1 (security, DF-R5-03 class):** seal builder support-file digests. `_builder_identity_field(cfg)`
  now returns `{model_identity?, support_files:[{path, sha256}]}` and feeds both manifest sites
  (fresh + resume). An adapter's structural no-tool guarantee is only as strong as the bytes it
  imports/executes, so those bytes are now auditable + run-bound. None when neither model_identity
  nor support files (byte-identical to pre-M60).
- **M60.4 (DF-R5-07):** `df_audit_sink.signed_s3_get(..., version_id="")` reads the EXACT recorded
  S3 version (`?versionId=`, signed into the SigV4 canonical query); `_sink_readback` passes
  `receipt["version_id"]`. Compares bytes (ETag never used as a content hash).
- **M60.5 (evidence bundle):** new read-only `df_evidence_bundle.assemble(cr, run_dir, key)` + CLI
  `supervisor.py evidence-bundle`. Pulls exactly the arbitration's required fields from sealed
  artifacts (commit, config/spec/scenario hashes, requested+effective tier, image digest, probes,
  manifest sha256 + artifact id, signed-chain verify output, custody facts, sink key+version+bytes
  hash, ship/release result, re-entry no-dup proof). Secret-key scrub gate; no network, no re-run.

## Tests (generalized classes the re-audit will attack)
- support-file digest sealed (fresh); changed file → changed digest; back-compat None; helper shape.
- downgrade ladders: hardened→standard→cooperative, standard→cooperative, AND
  enterprise→hardened/standard/cooperative (effective sealed + consumed, never CUSTODY_PENDING when
  downgraded).
- init→dispatch POSITIVE contract (blessed scaffold reaches BUILD).
- mutation-every-field forgery (M56 file): every non-identity field poisoned → reconstructed, none
  leaks; outcome/status remain the separately-guarded laundering surface.
- S3 readback reads the exact recorded version (a later version at the same key is NOT mis-confirmed).
- evidence bundle assembles; scrubs secret keys; missing run → error.

## Docs
- `references/live-validation.md` — the operator runbook (disposable staging, hardened-H4 +
  enterprise exercises, evidence-bundle assembly, re-audit entry criteria). SKILL.md reference bullet.

## Not in scope (operator / user)
- The actual live hardened-H4 + enterprise exercise on real Docker/kernel/S3-WORM/custody infra — the
  runbook + bundle command are the deliverable; the run itself is the operator's (Codex's
  production-GO gate). License + CI remain deferred.

Pipeline: opus review of the security-relevant M60.1 (manifest identity binding) → merge + full-suite gate.
Full suite currently: 2001 passed, 27 skipped.
