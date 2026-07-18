"""M41: the signed RELEASE-APPROVAL primitive — a governed, signed, scoped,
expiring, single-use K-of-N authorization to run IRREVERSIBLE ship actions
(prod deploy, migration, DNS cutover, prod merge) on a specific qualified
artifact.

WHY a whole module instead of "just run the deploy": an irreversible prod
action is a POLICY decision, and a policy decision must be AUTHORIZED, never
performed silently — least of all by a lights-out (H4) run. A release approval
is the auditable answer: never "turn off the gate", always "these >=K distinct
allowlisted approvers authorize THIS run's THIS artifact's THESE actions, once,
until a stated expiry". Every adjective there is load-bearing and enforced
below. A human is accountable for prod via a one-time signature — not by
running the command themselves.

Crypto: this module does NOT re-implement ed25519. It reuses df_custody's
primitives exactly as split-custody (M17), waivers (M33a) and resume-overrides
(M36b) do — an approver key IS an ed25519 keypair, and `verify_release`'s
distinct-approver-by-pubkey counting deliberately mirrors
`df_custody.verify_custody`'s "K distinct custodians, not K signatures"
invariant.

Binding model (why a release approval can never be replayed or mis-applied):
  - the signed claim is bound to `run_id` AND `artifact_object_id` (the
    content-addressed object the manifest sealed) — an approval signed for run
    A / artifact X can never authorize run B or a different artifact;
  - it is scoped to a set of `action_names` (or the wildcard `"*"`) — an
    approval for {deploy} never authorizes {migrate};
  - it carries a `nonce` recorded in an APPEND-ONLY per-control-root ledger
    (`<control_root>/release-nonces.json`) at ATTACH time; a nonce already
    present is REJECTED (an approval is single-use ACROSS the control root —
    the run/artifact binding is enforced separately);
  - `issued_at <= now < expires_at` is enforced against a LIVE clock at EVERY
    verify (attach AND every ship-time coverage check), fail closed: an
    unparseable/absent bound reads as "outside the window", so an expired
    approval flips an action back to gated on the next ship attempt.

RESIDUAL (documented, detection-grade not prevention-grade): a SAME-USER actor
with control-root write AND a signer private key can mint+attach a release and
could in principle edit config.json's `ship.approval` allowlist to add their
own pubkey. Requiring a NON-EMPTY policy to ride a SIGNED audit manifest
(df_config, mirroring M33a/M36b) HMAC-pins the config the terminal manifest
seals; the nonce ledger + distinct-signer counting bound WHO and HOW-OFTEN. A
single operator holding both a key and control-root write is the same same-user
residual the M35/M36a FSM chain documents — see
references/prevention-grade-roadmap.md.
"""
import datetime
import json
import os

import df_custody
from df_common import atomic_write, canonical_json


class ReleaseError(RuntimeError):
    pass


# The append-only used-nonce ledger lives at the control root so a nonce is
# single-use ACROSS the whole control root (the run+artifact binding is
# enforced separately by verify_release). Whole-file atomic rewrite (like the
# override ledger / fsm_chain), not O_APPEND: the file is tiny and there is
# exactly one writer at a time (attach holds the control-root lock).
NONCE_LEDGER_FILE = "release-nonces.json"


def nonce_ledger_path(control_root):
    return os.path.join(control_root, NONCE_LEDGER_FILE)


def load_used_nonces(control_root):
    """Return the set of nonces already recorded in the ledger.

    Absent ledger → empty set. A present-but-unreadable/malformed ledger is
    FAIL-CLOSED: raise ReleaseError so the caller REFUSES rather than silently
    treating a corrupt replay-protection store as "no nonces used" (which would
    defeat replay protection). Mirrors df_override.load_used_nonces."""
    path = nonce_ledger_path(control_root)
    if not os.path.exists(path):
        return set()
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError) as e:
        raise ReleaseError(
            f"cannot read the release-nonce ledger {path} (fail-closed; refusing): {e}") from e
    if not isinstance(data, list):
        raise ReleaseError(f"release-nonce ledger {path} is not a JSON list (fail-closed)")
    nonces = set()
    for entry in data:
        if isinstance(entry, str):
            nonces.add(entry)
        elif isinstance(entry, dict) and isinstance(entry.get("nonce"), str):
            nonces.add(entry["nonce"])
        else:
            raise ReleaseError(f"release-nonce ledger {path} has a malformed entry (fail-closed)")
    return nonces


def record_nonce(control_root, nonce, *, run_id, artifact_object_id, applied_at):
    """Append one accepted nonce to the ledger (atomic whole-file rewrite).

    Refuses (ReleaseError) if the nonce is ALREADY present — defense in depth
    against a double-record; attach has already checked, but recording is the
    point of no return for replay protection, so it re-checks under the same
    read it writes back."""
    path = nonce_ledger_path(control_root)
    if os.path.exists(path):
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError) as e:
            raise ReleaseError(f"cannot read the release-nonce ledger {path} to append: {e}") from e
        if not isinstance(data, list):
            raise ReleaseError(f"release-nonce ledger {path} is not a JSON list")
    else:
        data = []
    for entry in data:
        existing = entry if isinstance(entry, str) else (
            entry.get("nonce") if isinstance(entry, dict) else None)
        if existing == nonce:
            raise ReleaseError("release nonce already used (replay refused)")
    data.append({
        "nonce": nonce,
        "run_id": run_id,
        "artifact_object_id": artifact_object_id,
        "applied_at": applied_at,
    })
    atomic_write(path, canonical_json(data))


RELEASE_VERSION = "1"

# The canonical, signed claim is EXACTLY these keys in this order — the signer
# signs the canonical_json of a dict restricted to them, so extra keys an
# operator/attacker staples onto a claim object are never inside the signed
# bytes (no covert scope can ride along unsigned), and a missing key is a loud
# ReleaseError rather than a silently-different signature. `release_version`
# pins the claim schema so a future v2 claim can never be verified under v1
# rules by omission.
_CLAIM_KEYS = (
    "release_version",
    "run_id",
    "artifact_object_id",
    "action_names",
    "issued_at",
    "expires_at",
    "nonce",
)

# The wildcard scope: an approval whose `action_names` is exactly this string
# covers EVERY ship action. Any other value must be a list of action-name
# strings. (A list is the narrow, per-action scope; the wildcard is the "sign
# off on the whole ship" scope — both are legitimate, both are inside the
# signed bytes so an approver consciously chose one.)
ACTION_WILDCARD = "*"


def normalize_action_names(action_names):
    """Validate `action_names` is either the wildcard `"*"` or a non-empty list
    of non-empty name strings; return a canonical form (the wildcard string, or
    a de-duplicated sorted tuple). Raises ReleaseError on anything else so a
    malformed scope can never verify. The canonical form is used ONLY for
    validation + coverage lookup — the signed bytes always carry the claim's
    ORIGINAL `action_names` verbatim so the signature stays over exactly what
    was signed."""
    if action_names == ACTION_WILDCARD:
        return ACTION_WILDCARD
    if not isinstance(action_names, list) or not action_names:
        raise ReleaseError(
            "action_names must be the wildcard \"*\" or a non-empty list of action-name strings")
    names = []
    for n in action_names:
        if not isinstance(n, str) or not n:
            raise ReleaseError(f"action_names entries must be non-empty strings: {n!r}")
        names.append(n)
    return tuple(sorted(set(names)))


def release_signing_bytes(claim):
    """The canonical bytes a signer signs / a verifier checks for ONE claim.

    Restricting to `_CLAIM_KEYS` (and requiring every one present) means the
    signature covers exactly the scoped claim and nothing else. The
    `{approver, sig}` pair is attached ALONGSIDE the claim, never inside it.
    Raises ReleaseError on a non-dict claim or any missing field — never a
    silently-different signature."""
    if not isinstance(claim, dict):
        raise ReleaseError("release claim must be a JSON object")
    normalized = {}
    for k in _CLAIM_KEYS:
        if k not in claim:
            raise ReleaseError(f"release claim missing required field {k!r}")
        normalized[k] = claim[k]
    return canonical_json(normalized).encode("utf-8")


def _parse_ts(value):
    """Parse an ISO-8601 UTC (`...Z`) timestamp into an aware UTC datetime.

    Fail-closed: anything unparseable returns None, and every caller treats
    None as "outside the validity window". Mirrors df_override/df_waiver
    _parse_ts exactly (kept local so this module is self-contained)."""
    if not isinstance(value, str) or not value:
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=datetime.timezone.utc)
    return dt.astimezone(datetime.timezone.utc)


def _claim_within_validity(claim, now):
    """True iff `issued_at <= now < expires_at`, all parsed as aware UTC.
    Half-open interval on purpose (fail-closed at the expiry boundary). Any
    unparseable bound → False."""
    issued = _parse_ts(claim.get("issued_at"))
    expires = _parse_ts(claim.get("expires_at"))
    if issued is None or expires is None:
        return False
    if now.tzinfo is None:
        now = now.replace(tzinfo=datetime.timezone.utc)
    return issued <= now < expires


def verify_release(*, claim, signatures, approvers, threshold, run_id,
                   artifact_object_id, now, used_nonces=None):
    """Decide whether a release approval is valid RIGHT NOW.

    Returns `(satisfied, reason, distinct_count, nonce)`:
      - `satisfied`: True iff EVERY gate below passes.
      - `reason`   : deterministic, human-readable; never a private key/sig.
      - `distinct_count`: number of distinct allowlisted approvers whose
                     signature verified over `release_signing_bytes(claim)`.
      - `nonce`    : the claim's nonce (str) when well-formed, else None.

    Gates (each fail-closed; a non-dict claim never raises):
      (schema) claim is a dict; `release_version == RELEASE_VERSION`.
      (scope) `action_names` is the wildcard or a valid non-empty list.
      (run+artifact binding) `claim.run_id == run_id` AND
        `claim.artifact_object_id == artifact_object_id` — an approval for
        another run/artifact can never apply here.
      (nonce) a non-empty string nonce; and — ONLY when `used_nonces` is
        provided (attach time) — NOT already present in it. At ship-time
        coverage checks `used_nonces=None` skips this (the nonce is ALREADY in
        the ledger from attach; re-checking would wrongly reject the very
        approval attach recorded).
      (validity) `issued_at <= now < expires_at` against the live clock.
      (threshold) `threshold >= 1` (a 0-of-N policy — the fail-closed default
        for an absent `ship.approval` — is NEVER satisfiable) AND at least
        `threshold` DISTINCT allowlisted approver public keys each supplied a
        verifying signature.
    """
    nonce = claim.get("nonce") if isinstance(claim, dict) else None

    if not isinstance(claim, dict):
        return (False, "release claim is not a JSON object", 0, None)
    if claim.get("release_version") != RELEASE_VERSION:
        return (False,
                f"release_version {claim.get('release_version')!r} != {RELEASE_VERSION!r} "
                "(schema pin; refusing to reinterpret)", 0, nonce)

    try:
        normalize_action_names(claim.get("action_names"))
    except ReleaseError as e:
        return (False, f"invalid release scope: {e}", 0, nonce)

    if claim.get("run_id") != run_id:
        return (False,
                f"release bound to run_id {claim.get('run_id')!r}, not this run {run_id!r}",
                0, nonce)
    if claim.get("artifact_object_id") != artifact_object_id:
        return (False,
                f"release bound to artifact {claim.get('artifact_object_id')!r}, not this "
                f"artifact {artifact_object_id!r}", 0, nonce)

    if not isinstance(nonce, str) or not nonce:
        return (False, "release missing a non-empty nonce", 0, nonce)
    if used_nonces is not None:
        used = used_nonces if isinstance(used_nonces, (set, frozenset)) else set(used_nonces or [])
        if nonce in used:
            return (False, "release nonce already used (replay refused)", 0, nonce)

    if not _claim_within_validity(claim, now):
        return (False, "release outside its validity window (expired/not-yet-valid/unparseable)",
                0, nonce)

    valid_threshold = (isinstance(threshold, int) and not isinstance(threshold, bool)
                       and threshold >= 1)
    approver_set = {a.lower() for a in (approvers or []) if isinstance(a, str)}
    distinct = set()
    if valid_threshold:
        try:
            signed = release_signing_bytes(claim)
        except ReleaseError as e:
            return (False, f"unsignable claim: {e}", 0, nonce)
        for entry in signatures or []:
            if not isinstance(entry, dict):
                continue
            approver = entry.get("approver")
            sig = entry.get("sig")
            if not isinstance(approver, str) or not isinstance(sig, str):
                continue
            a = approver.lower()
            if a not in approver_set:
                continue
            if not df_custody.verify_one(a, signed, sig):
                continue
            distinct.add(a)

    count = len(distinct)
    if not valid_threshold:
        return (False,
                f"no release-approval policy in force (threshold {threshold!r} < 1); "
                "no approval is accepted", count, nonce)
    if count < threshold:
        return (False,
                f"{count}/{threshold} distinct allowlisted approver signatures", count, nonce)
    return (True,
            f"{count}/{threshold} distinct allowlisted approver signatures; in scope, unexpired, "
            "run+artifact bound", count, nonce)


class ApprovalContext:
    """The ship phase's live view of whether an irreversible action is
    authorized. Built from the run's `release_attestation.json` (or absent) +
    the SEALED `ship.approval` policy (approvers/threshold) + the run/artifact
    binding. `covers(action_name, now=...)` RE-VERIFIES the recorded signatures
    every call (never a stored boolean) so an approval that has since expired,
    or a manifest/config that has drifted, flips the action back to gated.

    An empty context (no attestation) covers nothing — the fail-closed default,
    so a reversible:false action with no attached, valid approval NEVER runs.
    """

    def __init__(self, *, attestation, approvers, threshold, run_id, artifact_object_id):
        self.attestation = attestation if isinstance(attestation, dict) else None
        self.approvers = list(approvers or [])
        self.threshold = threshold
        self.run_id = run_id
        self.artifact_object_id = artifact_object_id

    def covers(self, action_name, *, now):
        """Return (covered: bool, reason: str) for ONE action name.

        Covered iff a valid release attestation exists whose claim RE-VERIFIES
        now (>=threshold distinct allowlisted approvers, run+artifact bound,
        unexpired) AND whose `action_names` is the wildcard or lists this
        action. `used_nonces=None` here on purpose: the nonce was recorded in
        the ledger at attach; a ship-time coverage check must NOT treat that as
        a replay."""
        if self.attestation is None:
            return (False, "no release attestation attached")
        claim = self.attestation.get("claim")
        signatures = self.attestation.get("signatures")
        satisfied, reason, _count, _nonce = verify_release(
            claim=claim, signatures=signatures, approvers=self.approvers,
            threshold=self.threshold, run_id=self.run_id,
            artifact_object_id=self.artifact_object_id, now=now, used_nonces=None)
        if not satisfied:
            return (False, f"release attestation invalid now ({reason})")
        try:
            scope = normalize_action_names(claim.get("action_names"))
        except ReleaseError as e:
            return (False, f"invalid release scope ({e})")
        if scope == ACTION_WILDCARD:
            return (True, "covered by wildcard release approval")
        if action_name in scope:
            return (True, f"covered by release approval scoped to {action_name!r}")
        return (False, f"action {action_name!r} not in the release approval's scope")
