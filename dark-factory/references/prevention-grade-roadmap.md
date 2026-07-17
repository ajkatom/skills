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
  container.** Gates run host-side today. M29b landed the default-deny
  candidate profile itself (next section) but applies it to SCENARIO/
  characterize execution only — running the security gates under it
  (standard) / a pinned container (hardened+) remains deferred (M29c+). A
  gate that runs host-side shares the runner's trust domain — the same
  detection-grade boundary as the rest of this doc.
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

## DF-02 candidate containment status (M29a env half + M29b/M29c host-read half)

DF-02 ("the candidate inherits the operator's host") is being closed in
honest, probe-verified slices — and unlike most of this doc, the M29b/M29c
slices ARE prevention-grade against their stated adversary (the CONFINED
candidate process), because the OS kernel, not an application check, does the
denying:

- **Env + process half — merged (M29a):** minimal allowlisted candidate
  environment + full process-group teardown at every tier
  (`references/isolation.md`, "Candidate process + env containment").
- **Host-read half — merged (M29b), standard-macOS:** the candidate runs
  under a `(deny default)` `sandbox-exec` profile — host reads (`~/.ssh`,
  dotfiles, other repos) OS-denied, workspace-only writes, loopback pinned
  to the run's exact twin ports, and the keychain/DNS Mach side channels
  measured CLOSED — live-probed fail-closed per run and sealed into the
  manifest as `host_isolation` (`references/isolation.md`, "Default-deny
  candidate host isolation"). Scope notes: this confines the candidate the
  VERIFIER runs; the builder (which needs HOME/keychain/DNS) is the
  hardened/enterprise container's job, and a candidate needing host reads
  can opt out visibly (`candidate_host_read: "allow_host_read"`,
  `qualified: false`).
- **Host-read half — merged (M29c), standard-Linux:** the candidate runs in
  a REAL default-deny bwrap **mount + PID/IPC/UTS (+ net at `deny`) namespace**
  built from explicit minimal binds — NO `--ro-bind / /`, so the control root,
  `$HOME` and the rest of the host are ABSENT from the namespace (denial by
  construction), `--cap-drop ALL` blocks the mount-manipulation escape, and a
  Linux-specific per-run probe live-proves it (ENOENT-is-denial, with
  host-confirmed canaries to tell real denial from a setup bug). A passing
  Linux `standard` run now reports `host_isolation.mode: "default_deny"`,
  `qualified: true` — DF-02 Linux host-read is now **detection + prevention at
  standard**, not just detection. Deferred: `loopback` + netns-local twins on
  bwrap (M29c-2), the hardened/enterprise candidate container (M29c-3).
- **Copy-on-run scratch per scenario → M29d.**

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

## M36b residuals (deferred from M36a, documented)

M36a landed the four intervention modes, the single qualification state
machine (folding `host_isolation` into `qualified`), and the phase-aware
hash-chained FSM checkpoint. The following were deliberately deferred:

- **Signed resume overrides.** A budget-ceiling raise or credential-VALUE
  refresh at resume is not yet gated by an approver allowlist/threshold with a
  canonical payload + replay protection independent of the supervisor HMAC.
  Today raising `budget.max_usd` and `resume`-ing is an unauthenticated local
  edit (detection-grade, like the rest of the single-user posture).
- **Spec-fork lineage.** A parent run's sealed artifact object is not yet
  consumable as a child run's input snapshot with recorded lineage +
  superseded-parent marking.
- **Interactive `WAIVER_PENDING` pause.** Security-gate waivers remain
  attach-time (`df-waiver attach`); M36a adds `WAIVER_PENDING` as a first-class
  FSM phase name but does NOT add a new interactive waiver pause.
- **The before-ship (approve-ship) pause.** Deferred for both back-compat and
  mechanism reasons — see `references/modes.md`. The `AWAIT_SHIP` phase and the
  `pauses_before_ship()` predicate exist (returning False) for a future
  milestone that designs seal-reentry.

The **FSM chain is corruption-detection, not forgery-proof** — a same-user
process that rewrites both `fsm_chain.jsonl` and the recorded head together is
out of scope, exactly as for the manifest/audit-chain hashes above.
