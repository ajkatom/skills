"""M36b (Part A): the signed resume-override primitive — a governed, signed,
scoped, expiring, single-use authorization to RAISE a BUDGET-PAUSE'd run's
budget ceiling at resume.

WHY a whole module instead of "just edit config.json and resume": raising a
budget ceiling is a POLICY change, and a policy change must be AUTHORIZED, not
silent. Today `resume` re-resolves credentials every time (fine — the sealed
credential policy permits a changed VALUE under an unchanged source/allowlist,
so a credential-value refresh needs NO override, see the note below), but there
is no governed way to lift a spend cap: a paused run either can't continue or
would need a config edit that nothing signs. A resume override is the auditable
answer — never "turn off the budget", always "these >=K distinct allowlisted
approvers authorize THIS run to run under a raised ceiling, once, until a stated
expiry". Every adjective there is load-bearing and enforced below.

Crypto: this module does NOT re-implement ed25519. It reuses df_custody's
primitives (`validate_public_key`, `sign_manifest`, `verify_one`,
`public_from_private`, `generate_keypair`) exactly as split-custody (M17) and
waivers (M33a) do — an approver key IS an ed25519 keypair, and
`verify_override`'s distinct-approver-by-pubkey counting deliberately mirrors
`df_custody.verify_custody`'s "K distinct custodians, not K signatures"
invariant.

Binding model (why an override can never be replayed or mis-applied):
  - the signed claim is bound to `run_id` (an override signed for run A can
    never apply to run B — verify_override rejects a run_id mismatch);
  - it carries a `nonce` recorded in an APPEND-ONLY per-control-root ledger
    (`<control_root>/override-nonces.json`) at the moment it is accepted, and a
    nonce already present in the ledger is REJECTED — an override authorizes
    EXACTLY ONE resume, independent of the supervisor's HMAC/journal;
  - `issued_at <= now < expires_at` is enforced against a LIVE clock (fail
    closed: an unparseable/absent bound reads as "outside the window").

CREDENTIAL-VALUE REFRESH IS OUT OF SCOPE ON PURPOSE (documented, not missing):
resume already re-resolves credentials on every resume under the SEALED
credential policy (source/reference/allowlist never change across a pause), so
a changed secret VALUE is picked up automatically. That is not a policy change,
so it needs no override. Only a budget-CEILING raise (a real policy change) is
gated here. `OVERRIDE_TYPES` is therefore `("budget_ceiling",)` for M36b scope.

RESIDUAL (documented, detection-grade not prevention-grade): a SAME-USER actor
with control-root write AND a signer private key can mint+apply an override,
and could in principle edit config.json's `resume_overrides` allowlist to add
their own pubkey. Requiring a NON-EMPTY policy to ride a SIGNED audit manifest
(df_config, mirroring M33a waivers) HMAC-pins the config the terminal manifest
seals; the nonce ledger + distinct-signer counting bound WHO and HOW-OFTEN. But
a single operator who holds both a key and control-root write is the same
same-user residual the M35/M36a FSM chain documents — see
references/prevention-grade-roadmap.md.
"""
import datetime
import json
import os

import df_custody
from df_common import atomic_write, canonical_json


class OverrideError(RuntimeError):
    pass


# The append-only used-nonce ledger lives at the control root so it is shared
# across every run/resume under that root (a nonce is single-use ACROSS the
# whole control root, not per-run — the run binding is enforced separately by
# verify_override's run_id check). Whole-file atomic rewrite (like fsm_chain),
# not O_APPEND: the file is tiny and rewriting it atomically is simpler to keep
# consistent than partial appends, and there is exactly one writer at a time
# (resume holds the control-root lock).
NONCE_LEDGER_FILE = "override-nonces.json"


def nonce_ledger_path(control_root):
    return os.path.join(control_root, NONCE_LEDGER_FILE)


def load_used_nonces(control_root):
    """Return the set of nonces already recorded in the ledger.

    Absent ledger → empty set (no override has ever been applied). A
    present-but-unreadable/malformed ledger is FAIL-CLOSED: raise OverrideError
    so the caller REFUSES the override rather than silently treating a corrupt
    replay-protection store as "no nonces used" (which would defeat replay
    protection). Accepts either the list-of-entries or bare-list-of-strings
    shape for forward/backward tolerance."""
    path = nonce_ledger_path(control_root)
    if not os.path.exists(path):
        return set()
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError) as e:
        raise OverrideError(
            f"cannot read the nonce ledger {path} (fail-closed; refusing override): {e}") from e
    if not isinstance(data, list):
        raise OverrideError(f"nonce ledger {path} is not a JSON list (fail-closed)")
    nonces = set()
    for entry in data:
        if isinstance(entry, str):
            nonces.add(entry)
        elif isinstance(entry, dict) and isinstance(entry.get("nonce"), str):
            nonces.add(entry["nonce"])
        else:
            raise OverrideError(f"nonce ledger {path} has a malformed entry (fail-closed)")
    return nonces


def record_nonce(control_root, nonce, *, run_id, override_type, applied_at):
    """Append one accepted nonce to the ledger (atomic whole-file rewrite).

    Refuses (OverrideError) if the nonce is ALREADY present — defense in depth
    against a double-record; the caller has already checked, but recording is
    the point of no return for replay protection, so it re-checks under the same
    read it writes back. The recorded entry keeps run_id/type/timestamp for
    audit; only the `nonce` field is load-bearing for replay detection."""
    path = nonce_ledger_path(control_root)
    if os.path.exists(path):
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError) as e:
            raise OverrideError(f"cannot read the nonce ledger {path} to append: {e}") from e
        if not isinstance(data, list):
            raise OverrideError(f"nonce ledger {path} is not a JSON list")
    else:
        data = []
    for entry in data:
        existing = entry if isinstance(entry, str) else (
            entry.get("nonce") if isinstance(entry, dict) else None)
        if existing == nonce:
            raise OverrideError("override nonce already used (replay refused)")
    data.append({
        "nonce": nonce,
        "run_id": run_id,
        "override_type": override_type,
        "applied_at": applied_at,
    })
    atomic_write(path, canonical_json(data))


OVERRIDE_VERSION = "1"

# M36b scope: budget-ceiling is the ONLY override type. Credential-value refresh
# is already covered by resume's unconditional re-resolution under the sealed
# policy (see the module docstring), so it is deliberately NOT an override type.
OVERRIDE_TYPES = ("budget_ceiling",)

# The canonical, signed claim is EXACTLY these keys in this order — the signer
# signs the canonical_json of a dict restricted to them, so extra keys an
# operator/attacker staples onto a claim object are never inside the signed
# bytes (no covert scope can ride along unsigned), and a missing key is a loud
# OverrideError rather than a silently-different-but-accepted signature.
# `override_version` pins the claim schema so a future v2 claim can never be
# verified under v1 rules by omission. `params` is a nested object whose
# per-type shape is validated by `validate_params` (it, too, is inside the
# signed bytes — an approver signs the exact ceiling, not a bare "raise it").
_CLAIM_KEYS = (
    "override_version",
    "run_id",
    "override_type",
    "params",
    "issued_at",
    "expires_at",
    "nonce",
)


def validate_params(override_type, params):
    """Validate `params` for `override_type`, returning a normalized copy.

    For `budget_ceiling`: `params = {"new_usd_ceiling": <positive number>}`.
    Fail-closed (OverrideError) on any wrong type / non-positive / non-finite
    value — an approver signs an EXACT ceiling, so a malformed one must never
    verify. Returns the normalized `{"new_usd_ceiling": float}` (used only as a
    validity check; the signed bytes carry the ORIGINAL params verbatim so the
    signature stays over exactly what was signed).
    """
    if override_type not in OVERRIDE_TYPES:
        raise OverrideError(
            f"unknown override_type {override_type!r}; expected one of "
            f"{', '.join(OVERRIDE_TYPES)}")
    if not isinstance(params, dict):
        raise OverrideError("override params must be a JSON object")
    if override_type == "budget_ceiling":
        val = params.get("new_usd_ceiling")
        # bool is an int subclass — reject it explicitly (True/False are never a
        # dollar ceiling). Reject NaN/inf (val != val is the NaN test).
        if isinstance(val, bool) or not isinstance(val, (int, float)):
            raise OverrideError("budget_ceiling params require a numeric new_usd_ceiling")
        if val != val or val in (float("inf"), float("-inf")):
            raise OverrideError("budget_ceiling new_usd_ceiling must be finite")
        if val <= 0:
            raise OverrideError("budget_ceiling new_usd_ceiling must be > 0")
        return {"new_usd_ceiling": float(val)}
    # Unreachable given the OVERRIDE_TYPES guard above, but fail-closed if a
    # future type is added to the tuple without a params branch here.
    raise OverrideError(f"no params validator for override_type {override_type!r}")


def override_signing_bytes(claim):
    """The canonical bytes a signer signs / a verifier checks for ONE claim.

    Restricting to `_CLAIM_KEYS` (and requiring every one present) means the
    signature covers exactly the scoped claim and nothing else. The
    `{approver, sig}` pair is attached ALONGSIDE the claim, never inside it (a
    claim that signed its own approver could not be checked without trusting
    that self-assertion). Raises OverrideError on a non-dict claim or any
    missing field — never a silently-different signature.
    """
    if not isinstance(claim, dict):
        raise OverrideError("override claim must be a JSON object")
    normalized = {}
    for k in _CLAIM_KEYS:
        if k not in claim:
            raise OverrideError(f"override claim missing required field {k!r}")
        normalized[k] = claim[k]
    return canonical_json(normalized).encode("utf-8")


def _parse_ts(value):
    """Parse an ISO-8601 UTC (`...Z`) timestamp into an aware UTC datetime.

    Fail-closed: anything unparseable (wrong type, bad format) returns None,
    and every caller treats None as "outside the validity window" — an
    unreadable timestamp can never read as "still valid". Mirrors
    df_waiver._parse_ts exactly (kept local so this module is self-contained
    and never depends on a sibling's private helper)."""
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

    Half-open interval on purpose (fail-closed at the expiry boundary:
    `expires_at == now` reads as expired). Any unparseable bound → False."""
    issued = _parse_ts(claim.get("issued_at"))
    expires = _parse_ts(claim.get("expires_at"))
    if issued is None or expires is None:
        return False
    if now.tzinfo is None:
        now = now.replace(tzinfo=datetime.timezone.utc)
    return issued <= now < expires


def verify_override(*, claim, signatures, approvers, threshold, run_id, now,
                    used_nonces):
    """Decide whether a resume override is valid to APPLY right now.

    Returns `(satisfied, reason, distinct_count, nonce)`:
      - `satisfied`: True iff EVERY gate below passes.
      - `reason`   : deterministic, human-readable; never a private key/sig.
      - `distinct_count`: number of distinct allowlisted approvers whose
                     signature verified over `override_signing_bytes(claim)`.
      - `nonce`    : the claim's nonce (str) when the claim is well-formed
                     enough to have one, else None — the caller records it in
                     the ledger ONLY on satisfied=True.

    Gates (each fail-closed; a non-dict claim never raises):
      (schema) claim is a dict; `override_version == OVERRIDE_VERSION`; a v2+
        claim is REJECTED, never reinterpreted under v1 rules.
      (type/params) `override_type` in OVERRIDE_TYPES and `params` valid for it.
      (run binding) `claim.run_id == run_id` — an override for another run can
        never apply here.
      (nonce) a non-empty string nonce NOT already present in `used_nonces`
        (replay protection, independent of the supervisor HMAC/journal).
      (validity) `issued_at <= now < expires_at` against the live clock.
      (threshold) `threshold >= 1` (a 0-of-N policy — the fail-closed default
        for an absent `resume_overrides` — is NEVER satisfiable, so an absent
        policy accepts NO override) AND at least `threshold` DISTINCT allowlisted
        approver public keys each supplied a verifying signature.
    """
    nonce = claim.get("nonce") if isinstance(claim, dict) else None

    if not isinstance(claim, dict):
        return (False, "override claim is not a JSON object", 0, None)
    if claim.get("override_version") != OVERRIDE_VERSION:
        return (False,
                f"override_version {claim.get('override_version')!r} != {OVERRIDE_VERSION!r} "
                "(schema pin; refusing to reinterpret)", 0, nonce)

    override_type = claim.get("override_type")
    try:
        validate_params(override_type, claim.get("params"))
    except OverrideError as e:
        return (False, f"invalid override: {e}", 0, nonce)

    if claim.get("run_id") != run_id:
        return (False,
                f"override bound to run_id {claim.get('run_id')!r}, not this run {run_id!r}",
                0, nonce)

    if not isinstance(nonce, str) or not nonce:
        return (False, "override missing a non-empty nonce", 0, nonce)
    used = used_nonces if isinstance(used_nonces, (set, frozenset)) else set(used_nonces or [])
    if nonce in used:
        return (False, "override nonce already used (replay refused)", 0, nonce)

    if not _claim_within_validity(claim, now):
        return (False, "override outside its validity window (expired/not-yet-valid/unparseable)",
                0, nonce)

    valid_threshold = (isinstance(threshold, int) and not isinstance(threshold, bool)
                       and threshold >= 1)
    approver_set = {a.lower() for a in (approvers or []) if isinstance(a, str)}
    distinct = set()
    if valid_threshold:
        try:
            signed = override_signing_bytes(claim)
        except OverrideError as e:
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
                f"no resume-override policy in force (threshold {threshold!r} < 1); "
                "no override is accepted", count, nonce)
    if count < threshold:
        return (False,
                f"{count}/{threshold} distinct allowlisted approver signatures", count, nonce)
    return (True,
            f"{count}/{threshold} distinct allowlisted approver signatures; in scope, unexpired, "
            "nonce fresh", count, nonce)
