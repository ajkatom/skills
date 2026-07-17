# Prevention-grade vs. detection-grade: an honest roadmap

This doc is the audit-remediation deliverable promised for DF-09/DF-10: a
plain statement of which grade of assurance dark-factory actually ships
today, why the stronger grade is architecturally out of reach for a
single-user stdlib skill, and what real infrastructure — not skill code —
would be needed to get there. It exists so "we can't do X yet" is a
documented, deliberate scope boundary, not a silently-assumed gap someone
discovers the hard way.

## Where dark-factory is today: DETECTION-grade

Every tamper-evidence mechanism this skill ships — manifest HMAC signing,
the `audit-chain.jsonl` hash chain, content-addressed artifact binding
(DF-01/M28a), enterprise split-custody attestation — is explicitly
documented (see `references/audit.md`'s "Honest scope" and "Honest limits"
sections) as **detection-grade**: it catches evidence left behind by

- a confined candidate/builder trying to cheat within its sandbox,
- an accident (a mutating gate, a race, a partial write), or
- casual/unintended tampering after the fact,

fail-closed — `verify-manifest`/`verify-custody` refuse to say `OK` when the
evidence doesn't line up. This is real and load-bearing: it is the
difference between "a tampered run silently looks fine" and "a tampered run
gets caught the next time anyone checks."

## Where it can't go (yet): PREVENTION against a hostile same-OS-user process

What detection-grade explicitly does **not** do is *prevent* a process
running with the SAME filesystem/OS privilege as the one that published the
audit trail from deliberately overwriting bytes at that same privilege
level. Concretely, today:

- The manifest HMAC key and the audit-chain live on the same host, under
  the same OS user, as the run that writes them. A process with that user's
  write access can forge an internally-consistent new manifest and chain
  entry over the real one (`references/audit.md`'s "Honest limits").
- The content-addressed object store (`<control_root>/objects/`) is
  published by, and lives under, the same user as everything else — nothing
  cross-user (MAC/DAC) enforces that only the sealing process may write
  there.
- `standard`-tier's OS sandbox denies reads of the control root only; the
  home directory (where the signing key lives) is not sandboxed at all
  (`references/audit.md`, "Per-tier reality").
- Even `enterprise`'s split-custody attestation binds cryptographic sign-off
  to a sealed `config_sha256`/manifest — but the approver keypairs, the
  proxy, and the object store it all attests to still run, in this skill's
  current shape, alongside the same user on the same host.

**This is not a bug to fix in dark-factory's code.** Codex's audit proved,
adversarially, that closing this gap against a hostile process sharing the
operator's own OS user account is architecturally unreachable for a
single-user, stdlib-only, single-host skill — there is no code change
inside `dark-factory/scripts/*.py` that grants prevention against an
attacker who has exactly the privilege the legitimate run itself needs to
operate. Prevention at that grade requires infrastructure *outside* the
process boundary a skill can control.

## What PREVENTION-grade would actually require

Each item below is a real, buildable direction — but each is an
infrastructure/deployment project, not a patch to this skill's code, and
each needs an OWNER decision about how much operational complexity the
threat model justifies:

- **A privileged CAS/signing service under a separate OS user (or off-host
  entirely).** The object store publish and the manifest signing step would
  run as a distinct, more-privileged principal than the run itself, so the
  run's own compromise can't forge what that principal has already
  attested to.
- **Off-host approver keypairs, never generated or held locally.** Enterprise
  custody today can be configured with keys reachable on the same host as
  the run; true prevention needs the approver's private key to never exist
  anywhere the builder/run could reach it, even in principle (an HSM, a
  separate signing host, or a human's own offline device).
- **An authenticated remote WORM sink + signed-timestamp service.**
  `audit.sink` (M13, `references/audit.md`) already supports shipping chain
  entries off-box, but a genuinely prevention-grade anchor needs that sink
  to be a different trust domain with its own authentication (not just a
  reachable HTTP endpoint) plus a trusted timestamp authority, so "when" is
  as unforgeable as "what."
- **fs-verity / kernel-enforced immutability for the object store.** Once an
  object is published, the filesystem itself (not an application-level
  check) would refuse further writes to it — closing the "same privilege
  level can overwrite" gap at the kernel layer instead of relying on a
  verifier noticing after the fact.
- **Namespaced execution for the run itself.** Running the supervisor/build
  loop under its own Linux namespace (or a VM) separate from the operator's
  interactive session, so "the same OS user" stops being true even when the
  operator and the run nominally share an account today.

## M33a (DF-06) waiver/gate deferrals

M33a landed mandatory security gates at standard+ plus signed, scoped,
expiring **waivers** (`references/security-gates.md`). Three parts of the full
M33 are explicit, documented residuals — each depends on unbuilt milestones or
the off-host infrastructure above:

- **Security-gate execution inside a default-deny sandbox / digest-pinned
  container.** Gates run host-side today; running them under the M29b
  default-deny host sandbox (standard) / pinned container (hardened+) is
  deferred to **M29b**. A gate that runs host-side shares the runner's trust
  domain — the same detection-grade boundary as the rest of this doc.
- **A resumable in-loop `WAIVER_PENDING` pause phase.** M33a supplies waivers
  **after** a `SECURITY_GATE_FAILED` run via a separate signed attestation
  (the attach model, mirroring split-custody), decoupled from the phase-aware
  FSM. Pausing the loop mid-run to collect waivers is deferred to **M36**.
- **A trusted remote-timestamp for waiver expiry.** Waiver expiry is checked
  against the **local clock** at every verify; a same-user-forgeable clock can
  extend an existing waiver's window (but not, because of
  `artifact_object_id`+`gate_report_digest` binding, replay it onto a
  different artifact or a changed finding set). The unforgeable-"when" closure
  is the **signed-timestamp service** already listed above under "An
  authenticated remote WORM sink + signed-timestamp service."

## Framing this correctly

None of the above is scheduled work inside this skill's milestones — it is
a **future infrastructure project** that sits above dark-factory (a
deployment/operations concern, like the LICENSE and CI TODOs in
`references/reproducibility.md`), not a defect in the code that ships
today. The owner-facing decision is whether a given deployment's threat
model actually includes "a hostile process sharing my own OS user account"
— if it does, detection-grade dark-factory should be paired with the
infrastructure above; if it doesn't (the common case: one operator, running
locally, worried about accidents and confined-candidate misbehavior rather
than a co-resident attacker), detection-grade is the honest, currently-
shipped answer, and should be reported as such rather than oversold.

## References

- `references/audit.md` — the "Honest scope — detection-grade, not
  same-user prevention" and "Honest limits" sections this doc expands on
- `references/reproducibility.md` — the parallel honest-TODO doc for
  reproducibility (LICENSE, CI, hash-locked installs, digest pinning,
  release SBOM/provenance)
- `references/enterprise.md` — split-custody sign-off and the host-side
  credential proxy, the strongest mechanism shipped today and still
  same-host-scoped as described above
- `references/credentials.md` — the `-e` argv/`ps`-visibility residual,
  another same-user-privilege limit in the same family
