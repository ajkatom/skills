# M33a — DF-06: mandatory security gates at standard+ + signed, scoped, expiring waivers

_Scoped slice of the Codex-APPROVED remediation plan's M33. Full M33 also
specifies (a) gates executing inside the M29b default-deny host sandbox at
`standard` / the digest-pinned container at hardened+, and (b) a resumable
in-loop `WAIVER_PENDING` pause phase. Both depend on unbuilt milestones
(M29b gate sandbox; M36 phase-aware FSM), so M33a lands the buildable,
security-meaningful core NOW — mandatory gates + attach-time signed waivers —
and DOCUMENTS the two deferred parts as explicit residuals. This matches the
decoupling noted at plan approval: "supply waivers at config/attach time,
decoupling the resumable WAIVER_PENDING phase from M36."_

## Goal

Close DF-06: today a `standard`/`hardened`/`enterprise` run reaches
`COMPLETE_QUALIFIED` **without security gates ever running** —
`security_gates.enabled` defaults `false` and `qualified` is derived purely
from `eff_tier in _QUALIFYING_TIERS` (supervisor.py:2165, :3107), independent
of any gate. After M33a: at standard+, gates are MANDATORY with a per-tier
immutable minimum set; a run cannot be `qualified` unless every mandatory
gate ran and passed — OR each failing finding is covered by a valid,
in-scope, unexpired, allowlisted-signer waiver, re-verified at every
`verify`.

## Approach (5 tasks)

### Task 1 — `dark-factory/scripts/df_waiver.py` (new) + `tests/test_waiver.py`
The canonical waiver primitive. Reuses `df_custody`'s ed25519 (do NOT
re-implement crypto): `validate_public_key`, `sign_manifest`, `verify_one`,
`public_from_private`, `generate_keypair`.

- `WaiverError(RuntimeError)`.
- `finding_fingerprint(gate_name, finding) -> str`: sha256 over
  `canonical_json` of the STABLE identifying subset of a finding, normalized
  to survive cosmetic drift. For `secret_scan`/`dangerous_scan` findings
  (`{"file","line","rule"}`) fingerprint `{"gate":gate_name,"file":...,
  "rule":...}` — **deliberately EXCLUDE `line`** (a secret that moves a line
  is the same finding). For `license` (`{"file","package","license","rule"}`)
  include `file`,`package`,`rule`. Unknown gate/finding shape → fingerprint
  the whole sorted finding dict (fail toward MORE specificity, never less).
  Document the normalization + its residual (a waiver keyed file+rule also
  covers a *different* secret of the same rule in the same file — bounded,
  and re-bound to `artifact_object_id`+`gate_report_digest` so never
  replayable across artifacts).
- `gate_policy_digest(sec_cfg) -> str`: sha256 over `canonical_json` of the
  immutable+effective gate policy — the enabled built-in flags
  (secret_scan/dangerous_scan/sbom/license.enabled/dependency_audit.enabled),
  sorted `fail_on`, `strict_unavailable`, sorted external gate names. A
  policy change (e.g. dropping a gate from `fail_on`) MUST change this digest
  so an old waiver no longer applies. Exclude volatile/irrelevant fields.
- `gate_report_digest(security_field) -> str`: sha256 over `canonical_json`
  of the run's `security` manifest block (the sec_report). Binds a waiver to
  the EXACT findings it was issued against.
- Canonical signable waiver bytes: `waiver_signing_bytes(claim: dict) ->
  bytes` = `canonical_json` of the claim with keys
  `{waiver_version:"1", run_id, artifact_object_id, gate_policy_digest,
  gate_report_digest, finding_fingerprint, reason, issued_at, expires_at}`
  (ISO-8601 UTC `Z` timestamps). The signer signs THESE bytes; the
  `{signer, sig}` are attached alongside, never inside the signed claim.
- `verify_waiver_set(*, failing_findings, gates, waivers, signers, threshold,
  run_id, artifact_object_id, policy_digest, report_digest, now) ->
  (satisfied: bool, reason: str, covered: list, uncovered: list)`:
  - Compute the set of required fingerprints from every failing gate's
    findings (each failing gate name → its findings → fingerprints). A
    failing gate with NO enumerable findings (e.g. an `unavailable` mandatory
    gate, or an external gate that failed without structured findings) is
    **un-waivable** → its presence makes `satisfied=False` with a clear
    reason (you cannot waive "the scanner could not run"). Only structured,
    enumerated findings are waivable.
  - For each required fingerprint, count DISTINCT allowlisted signers whose
    waiver claim (a) is signed validly over `waiver_signing_bytes`, (b)
    matches run_id + artifact_object_id + policy_digest + report_digest +
    that fingerprint exactly, (c) `issued_at <= now < expires_at`. Covered iff
    distinct-valid-signer count `>= threshold`. Distinct-by-pubkey (mirror
    `verify_custody`'s distinct-approver counting). `threshold < 1` never
    satisfiable.
  - `satisfied` iff every required fingerprint is covered AND no un-waivable
    failing gate is present. Deterministic, human-readable `reason`.
- Unit tests: fingerprint stability across line drift; policy/report digest
  change invalidates; expired waiver not counted; wrong-artifact waiver not
  counted; below-threshold uncovered; unavailable-gate un-waivable; distinct
  signer counting (two sigs same signer = 1).

### Task 2 — mandatory-gate config forcing (`df_config.py`) + tests
In `validate` (the `security_gates` block, ~484–670), key off the CONFIGURED
`tier`:
- `MANDATORY_TIERS = ("standard","hardened","enterprise")`,
  `MANDATORY_GATES = ("secret_scan","dangerous_scan")`.
- At a mandatory tier: if `security_gates` is absent OR `enabled:false` →
  **synthesize an enabled block with the mandatory defaults** (do not silently
  leave gates off, and do not hard-error just for omission — a standard run
  with no security_gates block must still get mandatory gates). If
  `security_gates.enabled:true` but a mandatory gate flag is explicitly
  `false` → `ConfigError` ("standard+ may strengthen security gates, never
  disable secret_scan/dangerous_scan"). Force each mandatory gate INTO
  `fail_on` (union, dedup) and force `strict_unavailable:true` (a mandatory
  gate that can't run must fail closed). Operator MAY add more gates / more
  fail_on entries (strengthen).
- New OPTIONAL `security_gates.waivers` sub-block → `cfg["_security"]
  ["waivers"]` = `{"signers":[pubkey_hex,...], "threshold":int}`. Validate:
  `signers` a list of valid ed25519 pubkeys (via `df_custody.validate_public_key`,
  lowercased, deduped); `threshold` int `1 <= threshold <= len(signers)`.
  Absent → `{"signers":[], "threshold":0}` (no waivers accepted — the
  fail-closed default). Tier-INDEPENDENT (a standard run may carry a waiver
  policy). Keep this validated even when other gate flags are synthesized.
- Tests: standard with no security_gates block → mandatory gates present +
  enabled + strict_unavailable + fail_on ⊇ mandatory; standard disabling
  secret_scan → ConfigError; cooperative unchanged (gates still optional/off);
  waivers block validation (bad pubkey, threshold>len, threshold<1).

### Task 3 — qualification wiring (`supervisor.py`) + e2e
- Compute + persist digests on the sealed report: when gates run
  (`_run_security_gates`), the CONVERGED branch already writes `security` into
  the manifest. Add to the manifest `security` block (or a sibling field)
  `gate_policy_digest` and, once the sec_report is final, the run stores
  enough for attach to recompute `gate_report_digest` over the SAME bytes
  (attach recomputes from the sealed `security` field — so define
  `gate_report_digest` over exactly the persisted `security` object, and make
  sure attach reads the same object; watch for the digest-over-a-field-that-
  contains-the-digest recursion — `gate_policy_digest` may live in the
  `security` block, but `gate_report_digest` must be computed over the
  `security` block with any `gate_report_digest`/attestation keys EXCLUDED, or
  over a stable sub-object. Pick one and document it precisely.)
- Derive `app_security_qualified`: `True` iff (eff_tier NOT in mandatory tiers
  — cooperative, gates not required) OR (gates checked AND `failed` empty).
  Add it to the manifest. At standard+ a `failed`-nonempty run is ALREADY
  `SECURITY_GATE_FAILED`/`qualified=False` (supervisor.py:3020-3036) — keep
  that. The NEW invariant: at standard+, reaching `COMPLETE_QUALIFIED`
  requires `sec_report.get("checked") is True` (gates actually ran). Because
  Task 2 forces gates on at standard+, `_run_security_gates` returns a real
  checked report there; assert/guard it — if somehow `checked` is False at a
  mandatory tier, fail closed (a distinct non-qualified terminal, e.g.
  `SECURITY_GATES_MISSING`, never silent-qualify). Fold `app_security_qualified`
  into the final `qualified` at the CONVERGED branch (:3107): `qualified = (eff
  in _QUALIFYING_TIERS) and app_security_qualified`.
- e2e: a standard-tier run with a planted secret → SECURITY_GATE_FAILED,
  qualified False, manifest carries `gate_policy_digest` + the sealed
  `security` findings; a clean standard run → COMPLETE_QUALIFIED with
  `app_security_qualified:true`.

### Task 4 — `df-waiver` operator CLI + attach + verify integration + tests
Mirror `df-custody` (keygen/sign/attach) and `custody_attestation.json`:
- `df-waiver keygen` → prints an ed25519 keypair (delegates to
  `df_custody.generate_keypair`; a waiver signer key is the same primitive).
- `df-waiver sign --manifest <run>/manifest.json --fingerprint <fp>
  --expires <iso8601> --reason <str> --key-file <priv>`: recomputes run_id /
  artifact_object_id / policy_digest / report_digest FROM the sealed manifest
  (never trusts operator-supplied copies), builds the claim, signs
  `waiver_signing_bytes`, prints a `{claim, signer, sig}` JSON entry the
  operator collects. (Helper to LIST the run's failing fingerprints:
  `df-waiver findings --manifest <run>/manifest.json` so an operator knows
  what to sign.)
- `df-waiver attach <control_root> --run-dir <run_dir>`: byte-verify the
  sealed manifest first (reuse the verify path); read
  `<control_root>/waiver-signatures.json` (list of `{claim,signer,sig}`);
  recompute run_id/artifact/policy/report digests from the manifest +
  sealed `security`; call `df_waiver.verify_waiver_set` with
  `cfg`-independent signer allowlist/threshold **read from the sealed
  manifest's persisted waiver policy** (persist `_security["waivers"]` signer
  set + threshold into the manifest at seal time in Task 3, so attach/verify
  don't depend on re-loading a mutable config — the allowlist that governs a
  sealed run must itself be sealed). If satisfied → write
  `<run_dir>/waiver_attestation.json` = `{run_id, artifact_object_id,
  gate_policy_digest, gate_report_digest, threshold, covered_fingerprints,
  waivers:[{claim,signer,sig}], satisfied:true, attached_ts}` and anchor it
  like custody. Fail-closed + human-readable on any mismatch/expiry/short
  count.
- `verify-manifest` / a `df-waiver verify <run_dir>`: after byte-integrity +
  artifact-identity checks, IF the sealed outcome is `SECURITY_GATE_FAILED`
  and a `waiver_attestation.json` exists, RE-EVALUATE at `now`: recompute
  digests, re-run `verify_waiver_set` with `now=utcnow` (so expiry is checked
  AT VERIFY TIME, never a frozen boolean — an expired waiver flips the verdict
  back to NOT-qualified). Print a distinct status
  (`WAIVED_QUALIFIED` / `WAIVER_EXPIRED` / `WAIVER_INVALID`) and map to a
  distinct exit code. A `SECURITY_GATE_FAILED` run with NO attestation stays
  not-qualified (unchanged).
- Tests: full attach happy path (valid unexpired waiver → WAIVED_QUALIFIED);
  expiry re-check flips verdict at verify (freeze/advance `now`); tampered
  claim / wrong signer / below threshold → attach refuses; policy/report
  digest drift → refuses.

### Task 5 — docs
- `references/security-gates.md`: the mandatory-at-standard+ policy (immutable
  minimum set, strengthen-not-disable, strict_unavailable), and the full
  waiver workflow (fingerprint → sign → collect → attach → verify;
  expiry re-checked every verify).
- `references/audit.md`: `app_security_qualified` in the qualification
  semantics; new verify statuses/exit codes.
- `references/enterprise.md`: the DEFERRED enterprise remote-timestamp
  requirement for waiver expiry (M33a uses local-time expiry uniformly; the
  same-user-forgeable-clock residual is documented — waivers stay
  artifact+report-digest-bound so not replayable across artifacts). Point at
  `references/prevention-grade-roadmap.md`.
- SKILL.md: one runtime-interview line surfacing waivers as an option for a
  standard+ run that hits an accepted finding, + pointer.
- `references/prevention-grade-roadmap.md`: add the two M33 deferrals
  (gate-execution sandbox; enterprise trusted-time; resumable WAIVER_PENDING).

## Key decisions & tradeoffs
- **Attach model, not in-loop pause.** Waivers are supplied AFTER a
  SECURITY_GATE_FAILED run via a separate signed attestation (exactly like
  split-custody), never re-sealing the immutable manifest. Decouples M33 from
  the M36 FSM. The resumable in-loop `WAIVER_PENDING` phase is deferred.
- **Fingerprint excludes line number.** Normalizes to survive cosmetic drift;
  residual documented; artifact+report-digest binding prevents cross-artifact
  replay.
- **Sealed waiver policy.** The signer allowlist/threshold that governs a run
  is sealed INTO the manifest, so attach/verify can't be widened by editing a
  mutable config after the fact.
- **Local-time expiry (standard/hardened/enterprise) for M33a**; enterprise
  trusted-remote-timestamp is a documented deferral, consistent with the
  detection-grade decision.

## Out of scope (documented residuals)
- Gate execution inside a default-deny sandbox / digest-pinned container
  (needs M29b).
- Resumable in-loop `WAIVER_PENDING` pause phase (needs M36 FSM).
- Full multi-substate qualification FSM (barrier/host/control-plane/app_security
  as first-class derived states with per-limit codes) — M33a adds only the
  `app_security` dimension cleanly for M36 to generalize.
- Enterprise trusted remote-timestamp for expiry.
