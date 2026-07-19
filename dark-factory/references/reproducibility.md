# Reproducibility: what's real today, what's an owner/infra TODO

This doc is the honest inventory for DF-09 (audit finding: reproducibility
gaps). It separates what dark-factory's current design actually gives you
from what still needs an owner decision or infrastructure dark-factory
itself cannot stand up (a repository policy choice, a CI runner, a signing
service). Nothing below claims full bit-for-bit reproducibility of a build —
that would require pinning the *builder model's* output too, which is
inherently non-deterministic. What's in scope here is reproducibility and
verifiability of the **mechanism and the record**: given a run's config,
spec, and scenarios, can you tell — later, independently — exactly what ran
and exactly what it produced.

## What IS reproducible/verifiable today

- **Stdlib-only core.** `cooperative` and `standard` tiers, the supervisor,
  the deterministic scenario runner, and every gate except the enterprise
  custody signing run on the Python standard library alone — no third-party
  dependency to drift, no resolver to produce a different dependency tree on
  a different machine or a different day.
- **A bounded dependency pin for the one non-stdlib path.**
  `requirements-enterprise.txt` (used only by `scripts/df_custody.py` for
  ed25519 split-custody signing) pins `cryptography>=42,<50` — a floor for
  the ed25519 API this module needs, capped below the next major so a future
  breaking release can't silently land on a fresh install. This is a
  *version-range* pin, not a hash-locked install — see the TODO list below.
- **Content-addressed artifact binding (M28a / DF-01).** On a converged run,
  the supervisor freezes the workspace into a content-addressed object under
  `<control_root>/objects/objects/<object_id>/` (`scripts/df_seal.py`,
  `freeze()`) and binds that object's identity into the signed manifest.
  `verify-manifest` re-derives the identity from the live object store and
  will report `ARTIFACT MISMATCH`/`UNAVAILABLE` (exit 5) if the workspace on
  disk no longer matches what the manifest claims to have shipped. See
  `references/audit.md`'s "Artifact binding (DF-01)" section.
- **Config/spec/scenario hashes on every manifest.** Every manifest records
  `config_sha256`, `spec_sha256`, and `scenario_set_sha256` (see
  `scripts/supervisor.py`) — an independent reader can confirm exactly which
  config, spec text, and scenario set produced a given run, and re-running
  `verify-manifest`/`verify-chain` detects drift in any of them after the
  fact.
- **Digest-pinnable container image + a recorded resolved digest (M51).**
  `hardened.image` defaults to a mutable tag (`python:3.12-alpine`), but an
  operator can set it to a digest-pinned reference
  (`python:3.12-alpine@sha256:<digest>`), recorded verbatim on the manifest's
  `container.image` field. As of M51 the manifest ALSO records, on every
  container-tier run (hardened/enterprise):
  - `container.resolved_image_digest` — the digest Docker ACTUALLY resolved
    the image to (`docker image inspect`'s RepoDigest, or the local `.Id`
    fallback), best-effort. So even a *tag*-based run leaves an auditable
    record of which image bytes ran. It is FAIL-OPEN: if Docker can't answer
    (daemon down, image never pulled) the field is `null` and the run is
    never blocked — reproducibility is an advisory here, not a security gate.
  - `container.image_pinned` — an honest boolean: does the effective image
    carry an `@sha256:` digest (`true`) or is it a mutable tag (`false`)?
  When the image is an unpinned tag at hardened/enterprise, the run emits a
  one-line stderr WARNING recommending a digest pin — advisory only, the run
  continues (a tag is legitimate in dev; forcing a pin would break users).
  See `references/hardened.md`'s "Reproducibility: pin the image by digest"
  and `references/audit.md`'s "`container` manifest field".
- **A pinned dev/test environment (M51).** `dark-factory/requirements-dev.txt`
  pins the exact toolchain used to develop and test the skill —
  `pytest==9.1.1` and `cryptography==49.0.0` — so the test environment is
  reproducible. Its header states plainly that the skill's RUNTIME is
  stdlib-only and this file locks the DEV/TEST environment only (cryptography
  is exercised only at the enterprise tier for ed25519).
- **A manual (not automated) Linux test harness.** `scripts/
  run_tests_linux.sh` runs the full suite inside a real Linux container so
  the Linux-only code paths (bwrap denial, etc.) that skip on the
  maintainer's macOS machine execute for real — see `references/linux-ci.md`.
  This closes a *coverage* gap, not a *CI* gap: it's a script a human runs by
  hand, not a pipeline that runs on every change (see TODO below).

## Honest TODO list — needs an OWNER or infra decision

These are not yet done. Each needs a decision or infrastructure outside
what a single skill's code can decide or provide for itself; they're listed
here so the gap is visible rather than silently assumed away.

- **Repository LICENSE.** Not yet chosen. This is an ownership/legal
  decision reserved for the repository owner, not something to default
  silently — flagged, not fixed, by this milestone.
- **Automated CI on macOS + Linux.** `run_tests_linux.sh` (above) proves the
  suite is Linux-clean when a human runs it, but nothing runs it
  automatically on every push/PR, on either platform. Setting up an actual
  CI workflow is infrastructure reserved for the owner — flagged as a TODO,
  not built here.
- **A hash-locked dependency install.** M51's `requirements-dev.txt` pins
  `pytest`/`cryptography` to *exact* versions, and
  `requirements-enterprise.txt`'s `cryptography>=42,<50` bounds the enterprise
  runtime — but neither is a *hash*-pinned install: reproducing the identical
  installed bytes across machines still depends on whatever the resolver/index
  serves for that version at install time. Adopting a hash-locked flow
  (`pip install --require-hashes` with `--hash=sha256:...` lines, refreshed
  deliberately) is a real follow-up, not done here.
- **Digest-pinned images by default.** `hardened.image` supports a
  digest-pinned reference (above), and M51 now WARNS on an unpinned tag at
  hardened/enterprise and records `container.image_pinned` — but nothing
  defaults to a digest or *enforces* one; an operator still has to opt in per
  run. Making digest-pinning the default, or a config-time requirement, is a
  policy decision left to the owner (a hardcoded digest in `DEFAULT_IMAGE`
  itself would be architecture- and time-specific and break on a different
  host or once the image is superseded — see `references/hardened.md`).
- **The builder's OWN in-container dependencies.** The reproducibility above
  covers the build *environment* (which image bytes ran) and the *record*
  (what the manifest attests) — NOT the packages the builder installs *inside*
  the container while building the target app. Those remain the operator's
  responsibility: provision a pre-pinned, read-only dependency cache via
  `hardened.dep_cache_dir` (M26; see `references/hardened.md` §7.3 "Pinned
  dependency cache") so the in-container build resolves against fixed bytes
  instead of the live index. dark-factory does not (and cannot) pin the
  upstream package indexes, the base image's freshness, or the external
  toolchain a given build reaches for — those stay operator/infra-dependent.
- **SBOM/provenance for dark-factory's own release artifacts.** The
  existing `sbom` security gate (`references/security-gates.md`) inventories
  a **built artifact's** declared dependencies as part of the mandatory
  post-build security gates — that is a different scope from an SBOM or
  provenance attestation for **dark-factory itself** as a shipped skill
  (e.g. a SLSA-style build provenance statement for a tagged release of this
  repository). That does not exist yet and needs release-process
  infrastructure this skill's code cannot stand up on its own.

None of the above are claimed as done anywhere else in this skill's docs;
where a doc discusses reproducibility it should point here rather than
imply these are solved.
