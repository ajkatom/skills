# M51 — DF-R3-08 reproducibility (code parts; LICENSE/CI surfaced to owner)

Codex re-audit #06's softest finding — an *assurance gap*, not a defect
("does not prevent the engine from building an app"). The default container
reference is a mutable tag, there's no dep lock / CI / LICENSE. Split: do the
code-side reproducibility hardening here; SURFACE LICENSE + CI to the owner
(they're legal/infra decisions, not code correctness — do NOT invent them).

## Code fixes (M51)

### 1. Record the RESOLVED container image digest into the manifest
The image default `python:3.12-alpine` (`df_container.DEFAULT_IMAGE`) is a
mutable tag; an operator MAY already pin `hardened.image:
python:3.12-alpine@sha256:...`. Either way, make the run AUDITABLE-after-the-
fact by recording the digest Docker actually used:
- Add `df_container.resolve_image_digest(image, runner=subprocess.run) ->
  str|None` = `docker image inspect --format '{{index .RepoDigests 0}}'`
  (or `.Id` fallback) for the image, best-effort (None if unavailable — never
  crash a run over it).
- At a hardened/enterprise run, after the container probe passes, resolve the
  image digest ONCE and record it in the manifest `container` field as
  `resolved_image_digest` (alongside the existing `image`). So even a
  tag-based run's manifest says exactly which image content ran. Value-free,
  control-plane.

### 2. Warn (don't block) on an unpinned image at hardened+
- `df_config` (or the run path): when `hardened.image` (or the default) is a
  mutable tag — i.e. lacks an `@sha256:` digest — at hardened/enterprise,
  emit a one-line stderr WARNING recommending a digest pin for reproducibility
  (NOT a ConfigError — a tag is legitimate in dev; forcing a pin would break
  users). Reflect it honestly (a manifest `container.image_pinned: bool`).
  Fail-open is correct here (reproducibility advisory, not a security gate).

### 3. Dev/test dependency lock
- The skill CORE is stdlib-only; the only third-party imports are
  `cryptography` (enterprise ed25519 only) and the test toolchain (`pytest`).
  Add `dark-factory/requirements-dev.txt` pinning `pytest` + `cryptography`
  to specific versions (the ones in the working `.venv` — detect them), with
  a header comment: "the skill's RUNTIME is stdlib-only; this locks the
  DEV/TEST environment only (cryptography is used only at the enterprise tier
  for ed25519)." This makes the test environment reproducible without
  implying the skill has runtime deps it doesn't.

### 4. Reproducibility docs
- `references/reproducibility.md` (or extend the existing repro doc if one
  exists): state honestly — (a) the skill runtime is stdlib-only; (b) the
  builder CONTAINER image should be digest-pinned for a reproducible build
  environment (`hardened.image: ...@sha256:...`), the manifest now records the
  resolved digest either way; (c) the builder's OWN dependencies inside the
  container are the operator's responsibility (pointer to the M26 pinned
  dep-cache, §7.3); (d) `requirements-dev.txt` locks the test env; (e) what
  remains operator-dependent (the external toolchain, the base image freshness).
  Update `references/hardened.md` image section + `references/audit.md`
  (`container.resolved_image_digest`/`image_pinned` fields) to match.

## Tests
- `resolve_image_digest` returns the digest via a stub runner; None on a
  runner error (never raises). The manifest `container` field carries
  `resolved_image_digest` + `image_pinned` (unit test with a stubbed
  container path — mirror the existing hardened manifest tests; docker not
  required).
- unpinned-tag → `image_pinned: false` + the warning path; a `@sha256:`
  image → `image_pinned: true`, no warning.
- Deterministic, no real Docker. Full suite green (baseline current main
  1900 passed + docker skips).

## Owner decisions (SURFACE, do not implement unilaterally)
Prepare but do NOT commit as authoritative — bring these to the user:
- **LICENSE**: a repo needs a license the owner chooses (MIT/Apache-2.0/
  proprietary). Recommend one, but the choice + copyright holder are theirs.
- **CI**: a hermetic CI workflow (run the non-docker/non-paid suite subset on
  push) is valuable but is an infra/provider choice (GitHub Actions? which
  Python versions? whether to run the docker/live tests with secrets). I can
  provide a ready-to-drop-in `.github/workflows/*.yml` for their approval.
Note these as the remaining DF-R3-08 items that are the owner's call, in the
final report — the audit itself lists LICENSE/CI as owner-level, and picking
a license or standing up CI is not something to guess.

## Rules
Fail-closed for security, fail-OPEN for the reproducibility advisories (a
missing image digest / unpinned tag must NEVER block a run). Real
`raise`/return-None, never bare `assert`. Additive/back-compat: absent Docker
or a tag image behaves as today plus the new advisory fields. Match house
style. Light review (additive, low-risk).
