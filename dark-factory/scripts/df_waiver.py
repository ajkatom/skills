"""M33a (DF-06): the canonical waiver primitive — signed, scoped, expiring
sign-off that lets a *specific* security-gate finding be accepted on a
*specific* sealed artifact, without ever weakening the fail-closed default.

WHY a whole module instead of a flag: at standard+ the security gates are
now mandatory (df_config forces secret_scan + dangerous_scan on, in fail_on,
strict_unavailable), so a run with an accepted-risk finding would otherwise
be permanently un-shippable. A waiver is the *auditable* escape hatch —
never "disable the gate", always "these named findings, on this exact
artifact+report, are accepted by >=K distinct allowlisted signers until a
stated expiry". Every adjective there is load-bearing and enforced below.

Crypto: this module does NOT re-implement ed25519. It reuses df_custody's
primitives (`validate_public_key`, `sign_manifest`, `verify_one`,
`public_from_private`, `generate_keypair`) exactly as the split-custody
feature does — a waiver signer key IS an ed25519 keypair, and
`verify_waiver_set`'s distinct-signer-by-pubkey counting deliberately
mirrors `df_custody.verify_custody`'s distinct-approver counting (the same
"K distinct custodians, not K signatures" invariant).

Binding model (why a waiver can never be replayed):
  - `finding_fingerprint` names WHICH finding is accepted (stable across
    cosmetic line drift — see below), and
  - a valid waiver claim must additionally match the run's `run_id`,
    `artifact_object_id` (the content-addressed object the manifest sealed),
    `gate_policy_digest` (the effective gate policy), and
    `gate_report_digest` (the exact set of findings) — ALL of them, exactly.
Change the artifact, the policy, or the findings and every prior waiver
stops applying. Expiry is re-checked at *every* verify against a live clock
(never a frozen boolean), so an expired waiver flips a run back to
not-qualified on the next `verify`.
"""
import datetime

import df_custody
from df_common import canonical_json, sha256_str


class WaiverError(RuntimeError):
    pass


# The canonical, signed waiver claim is EXACTLY these keys in this set — the
# signer signs the canonical_json of a dict restricted to them, so extra keys
# an operator/attacker might staple onto a claim object are never inside the
# signed bytes (they can't smuggle covert scope in), and a missing key is a
# loud WaiverError rather than a silently-different signature. `waiver_version`
# pins the claim schema so a future v2 claim can never be verified under v1
# rules by omission.
_CLAIM_KEYS = (
    "waiver_version",
    "run_id",
    "artifact_object_id",
    "gate_policy_digest",
    "gate_report_digest",
    "finding_fingerprint",
    "reason",
    "issued_at",
    "expires_at",
)
WAIVER_VERSION = "1"

# Keys that live in the SEALED `security` manifest block but must be EXCLUDED
# when computing `gate_report_digest` over that block — otherwise the digest
# would be computed over a field that (transitively) contains itself, or over
# derived/policy/attestation metadata that is not part of "the findings this
# waiver was issued against". `gate_report_digest` is intentionally NOT among
# the sealed keys (it is always recomputed), but it is listed here so that if
# a future writer ever persists it the recomputation stays self-consistent.
# Resolution of the recursion, stated precisely:
#   gate_report_digest(security) =
#       sha256( canonical_json( {k: v for k, v in security.items()
#                                if k not in _REPORT_DIGEST_EXCLUDE} ) )
# i.e. the digest is taken over the finding-bearing content of the block
# ({"checked","gates","failed"} plus any future finding keys), never over
# `gate_policy_digest` / `waiver_policy` / `gate_report_digest` themselves.
_REPORT_DIGEST_EXCLUDE = frozenset(
    {"gate_policy_digest", "gate_report_digest", "waiver_policy"}
)


def finding_fingerprint(gate_name: str, finding) -> str:
    """A stable, artifact-independent identifier for ONE gate finding.

    The fingerprint is what a waiver names, so its stability rules ARE the
    waiver's scope. Two goals in tension are balanced deliberately:

      - survive COSMETIC drift: a secret that merely moves to a different
        LINE is the same finding, so for `secret_scan`/`dangerous_scan`
        findings (`{"file","line","rule"}`) the fingerprint is taken over
        `{"gate", "file", "rule"}` and DELIBERATELY EXCLUDES `line`. For a
        `license` finding (`{"file","package","license","rule"}`) it is
        taken over `{"gate","file","package","rule"}` (the declared license
        STRING is excluded for the same reason — the identity is "this
        package's license, in this file, tripped this rule").

      - fail toward MORE specificity, never less: an unknown gate, or a
        finding missing the expected keys, is fingerprinted over the WHOLE
        finding object. A narrower/known shape is used only when every key it
        needs is present. So an unrecognized finding can never be waived by a
        coarser fingerprint than it deserves.

    RESIDUAL (documented, not hidden): because `line` (and the license
    string) are excluded, a waiver keyed file+rule also covers a *different*
    secret of the *same* rule in the *same* file. That residual is bounded
    two ways: (1) it is per-file+per-rule, not blanket, and (2) every waiver
    is additionally bound to `artifact_object_id` + `gate_report_digest`
    (see `verify_waiver_set`), so the moment the file's contents change the
    report digest changes and the waiver stops applying — it is never
    replayable across artifacts or across edits to the waived file.

    The two fingerprint domains cannot collide: the known-shape form hashes a
    dict whose top-level keys include `file`/`rule`, while the whole-object
    fallback hashes `{"gate", "finding": <finding>}` — disjoint key sets.
    """
    if isinstance(finding, dict):
        if gate_name in ("secret_scan", "dangerous_scan"):
            keys = ("file", "rule")
        elif gate_name == "license":
            keys = ("file", "package", "rule")
        else:
            keys = None
        if keys is not None and all(k in finding for k in keys):
            subset = {"gate": gate_name}
            for k in keys:
                subset[k] = finding[k]
            return sha256_str(canonical_json(subset))
    # Unknown gate, or a finding missing an expected key: bind the whole
    # object (maximum specificity — a cautious fingerprint is never wrong,
    # only occasionally narrower than strictly necessary).
    return sha256_str(canonical_json({"gate": gate_name, "finding": finding}))


def gate_policy_digest(sec_cfg: dict) -> str:
    """sha256 over the run's EFFECTIVE, immutable gate policy.

    A waiver is bound to the policy in force when it was issued, so ANY policy
    change that could alter what the gates decide MUST change this digest and
    thereby invalidate every prior waiver. We hash exactly the fields that
    determine gate OUTCOME selection: the enabled built-in flags, the sorted
    `fail_on` set, `strict_unavailable`, whether license / dependency_audit
    are enabled, and the sorted external gate NAMES. Volatile or
    finding-shaping-but-not-policy fields (e.g. a license allowlist, a
    dependency-audit snapshot path) are intentionally excluded here — a change
    to THOSE shows up as a different set of findings and is caught by
    `gate_report_digest` instead, so nothing slips through: policy changes bump
    the policy digest, finding changes bump the report digest.
    """
    sec_cfg = sec_cfg or {}
    license_cfg = sec_cfg.get("license") or {}
    depaudit_cfg = sec_cfg.get("dependency_audit") or {}
    policy = {
        "policy_version": WAIVER_VERSION,
        "secret_scan": bool(sec_cfg.get("secret_scan")),
        "dangerous_scan": bool(sec_cfg.get("dangerous_scan")),
        "sbom": bool(sec_cfg.get("sbom")),
        "license": bool(license_cfg.get("enabled")),
        "dependency_audit": bool(depaudit_cfg.get("enabled")),
        "fail_on": sorted(
            str(n) for n in sec_cfg.get("fail_on", []) if isinstance(n, str)
        ),
        "strict_unavailable": bool(sec_cfg.get("strict_unavailable", True)),
        "external": sorted(
            e["name"]
            for e in sec_cfg.get("external", [])
            if isinstance(e, dict) and isinstance(e.get("name"), str)
        ),
    }
    return sha256_str(canonical_json(policy))


def gate_report_digest(security_field: dict) -> str:
    """sha256 over the finding-bearing content of the SEALED `security` block.

    This binds a waiver to the EXACT findings it was issued against — a
    re-run that surfaces a different set of findings produces a different
    digest and voids the waiver. The recursion hazard (this digest would
    otherwise be computed over a block that may itself carry policy/attestation
    metadata) is resolved by excluding `_REPORT_DIGEST_EXCLUDE` — see that
    constant's comment for the precise definition. Attach and verify recompute
    this over the same sealed object with the same exclusion, so it is stable.
    """
    if not isinstance(security_field, dict):
        raise WaiverError("gate_report_digest requires the sealed security object")
    subset = {
        k: v for k, v in security_field.items() if k not in _REPORT_DIGEST_EXCLUDE
    }
    return sha256_str(canonical_json(subset))


def waiver_signing_bytes(claim: dict) -> bytes:
    """The canonical bytes a signer signs / a verifier checks for ONE claim.

    Restricting to `_CLAIM_KEYS` (and requiring every one to be present)
    means the signature covers exactly the scoped claim and nothing else:
    an operator cannot append covert fields that ride along unsigned, and a
    claim missing any binding field is a loud WaiverError, never a
    silently-different-but-accepted signature. The `{signer, sig}` pair is
    attached ALONGSIDE the claim, never inside it (a claim that signed its own
    signer could not be checked without trusting that self-assertion).
    """
    if not isinstance(claim, dict):
        raise WaiverError("waiver claim must be a JSON object")
    normalized = {}
    for k in _CLAIM_KEYS:
        if k not in claim:
            raise WaiverError(f"waiver claim missing required field {k!r}")
        normalized[k] = claim[k]
    return canonical_json(normalized).encode("utf-8")


def _parse_ts(value):
    """Parse an ISO-8601 UTC (`...Z`) timestamp into an aware UTC datetime.

    Fail-closed: anything unparseable (wrong type, bad format) returns None,
    and every caller treats None as "outside the validity window" — an
    unreadable timestamp can never be read as "still valid". Accepts the
    exact `%Y-%m-%dT%H:%M:%SZ` shape df_waiver/supervisor emit, and (via
    fromisoformat) any explicit-offset ISO-8601 variant, normalizing to UTC.
    """
    if not isinstance(value, str) or not value:
        return None
    text = value.strip()
    # `datetime.fromisoformat` accepts a trailing `Z` only on 3.11+; normalize
    # it to `+00:00` so this parses uniformly regardless of interpreter minor.
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        # A timestamp with no zone is ambiguous; the whole waiver scheme is
        # UTC (`Z`), so treat a naive stamp as UTC rather than guessing local.
        return dt.replace(tzinfo=datetime.timezone.utc)
    return dt.astimezone(datetime.timezone.utc)


def _claim_within_validity(claim: dict, now: datetime.datetime) -> bool:
    """True iff `issued_at <= now < expires_at`, all parsed as aware UTC.

    Half-open interval on purpose: a waiver is valid from its issue instant up
    to but NOT including its expiry instant, so `expires_at == now` reads as
    expired (fail-closed at the boundary). Any unparseable bound → False.
    """
    issued = _parse_ts(claim.get("issued_at"))
    expires = _parse_ts(claim.get("expires_at"))
    if issued is None or expires is None:
        return False
    if now.tzinfo is None:
        now = now.replace(tzinfo=datetime.timezone.utc)
    return issued <= now < expires


def required_fingerprints(failing_findings, gates):
    """Split a sealed report's failing gates into
    `(waivable_fingerprints, unwaivable_gate_names)`.

    `failing_findings` is the report's `failed` list — the NAMES of the gates
    that failed. For each, its structured findings become fingerprints. A
    failing gate with NO enumerable structured findings — an `unavailable`
    mandatory gate (the scanner could not run), or an external gate that
    failed with only a `detail` string — is UN-WAIVABLE: you cannot sign off
    on "the scanner could not run", only on specific enumerated findings. Its
    presence is returned so the caller can force not-satisfied.
    """
    waivable = []
    unwaivable = []
    seen = set()
    gates = gates if isinstance(gates, dict) else {}
    for name in failing_findings or []:
        gate = gates.get(name)
        findings = gate.get("findings") if isinstance(gate, dict) else None
        if not isinstance(findings, list) or not findings:
            unwaivable.append(name)
            continue
        for finding in findings:
            fp = finding_fingerprint(name, finding)
            if fp not in seen:
                seen.add(fp)
                waivable.append(fp)
    return waivable, sorted(set(unwaivable))


def verify_waiver_set(
    *,
    failing_findings,
    gates,
    waivers,
    signers,
    threshold,
    run_id,
    artifact_object_id,
    policy_digest,
    report_digest,
    now,
):
    """Decide whether a set of collected waivers fully covers a failed run.

    Returns `(satisfied, reason, covered, uncovered)`:
      - `covered`   : sorted fingerprints reaching >= threshold distinct,
                      valid, in-scope, unexpired allowlisted signers.
      - `uncovered` : sorted required fingerprints that did NOT.
      - `satisfied` : True iff `threshold >= 1` AND every required fingerprint
                      is covered AND no un-waivable failing gate is present.
      - `reason`    : deterministic, human-readable; never a private key/sig.

    A required fingerprint is COVERED iff at least `threshold` DISTINCT
    allowlisted signer public keys each supplied a waiver whose claim:
      (a) verifies (ed25519) over `waiver_signing_bytes(claim)` with that key;
      (b) matches run_id + artifact_object_id + policy_digest + report_digest
          + that fingerprint EXACTLY; and
      (c) is unexpired: `issued_at <= now < expires_at`.
    Distinct-by-pubkey mirrors df_custody.verify_custody: two signatures from
    the same signer count once. `threshold < 1` is NEVER satisfiable (a
    "0-of-N" policy would let an empty waiver set "cover" a finding, defeating
    the whole point) — the fail-closed default from df_config for a run with
    no waiver policy is exactly threshold 0.
    """
    required, unwaivable = required_fingerprints(failing_findings, gates)

    signer_set = {s.lower() for s in (signers or []) if isinstance(s, str)}
    valid_threshold = isinstance(threshold, int) and not isinstance(threshold, bool) and threshold >= 1

    covered = []
    uncovered = []
    for fp in required:
        distinct = set()
        if valid_threshold:
            for w in waivers or []:
                if not isinstance(w, dict):
                    continue
                claim = w.get("claim")
                signer = w.get("signer")
                sig = w.get("sig")
                if not (isinstance(claim, dict) and isinstance(signer, str)
                        and isinstance(sig, str)):
                    continue
                s = signer.lower()
                if s not in signer_set:
                    continue
                # Schema pin (fail-closed): only a v1 claim is verifiable under
                # v1 rules. A claim carrying a different/future `waiver_version`
                # is dropped, never reinterpreted — a future v2 claim must be
                # evaluated by v2 logic, not silently accepted here.
                if claim.get("waiver_version") != WAIVER_VERSION:
                    continue
                # Scope match — every binding field, exactly. A mismatch on
                # any one silently drops the waiver (never raises): a
                # wrong-artifact / stale-policy / stale-report / wrong-finding
                # claim simply does not count toward this fingerprint.
                if claim.get("run_id") != run_id:
                    continue
                if claim.get("artifact_object_id") != artifact_object_id:
                    continue
                if claim.get("gate_policy_digest") != policy_digest:
                    continue
                if claim.get("gate_report_digest") != report_digest:
                    continue
                if claim.get("finding_fingerprint") != fp:
                    continue
                if not _claim_within_validity(claim, now):
                    continue
                try:
                    signed = waiver_signing_bytes(claim)
                except WaiverError:
                    continue
                if not df_custody.verify_one(s, signed, sig):
                    continue
                distinct.add(s)
        if valid_threshold and len(distinct) >= threshold:
            covered.append(fp)
        else:
            uncovered.append(fp)

    covered.sort()
    uncovered.sort()

    if not valid_threshold:
        satisfied = False
        reason = (
            f"no waiver policy in force (threshold {threshold!r} < 1); "
            f"{len(required)} finding(s) require sign-off"
        )
    elif not required and not unwaivable:
        # Degenerate input: no waivable findings AND no un-waivable gates —
        # i.e. nothing was actually failing. A security primitive must FAIL
        # CLOSED here, not report a vacuous "all 0 findings covered" pass.
        # (In normal operation this is unreachable — verify_waiver_set is only
        # called on a SECURITY_GATE_FAILED run — but a caller that passes an
        # empty failing set must never get satisfied=True.)
        satisfied = False
        reason = "no waivable findings enumerated (empty failing set); fail-closed"
    elif unwaivable:
        # Even fully-covered findings can't rescue a run whose failure
        # includes something no signature can address.
        satisfied = False
        reason = (
            f"{len(covered)}/{len(required)} waivable finding(s) covered, but "
            f"{len(unwaivable)} un-waivable failing gate(s) present "
            f"({', '.join(unwaivable)}); un-waivable failures cannot be signed off"
        )
    elif uncovered:
        satisfied = False
        reason = (
            f"{len(covered)}/{len(required)} finding(s) covered by >= {threshold} "
            f"distinct signer(s); {len(uncovered)} uncovered"
        )
    else:
        satisfied = True
        reason = (
            f"all {len(covered)} finding(s) covered by >= {threshold} distinct "
            f"allowlisted signer(s), unexpired and in scope"
        )
    return satisfied, reason, covered, uncovered
