"""M17 Task 1: ed25519 K-of-N split-custody.

The ONE non-stdlib dependency in dark-factory: `cryptography`, imported
ONLY here and nowhere else in the codebase (see requirements-enterprise.txt).
Every other module -- including df_config.py's shape validation of the
`custody` config block -- stays stdlib-only and never imports this module's
underlying library, only the pure functions below.

Why real asymmetric signatures instead of e.g. HMAC-over-a-shared-secret:
a verifier here holds ONLY public keys, so it can check a signature but can
never itself forge one. That is what makes split-custody genuinely
single-operator-proof -- no one party (including whoever runs the verifier)
can produce a valid K-of-N on their own with fewer than K distinct private
keys.

verify_custody's central invariant, load-bearing for the whole feature:
signatures are counted by DISTINCT approver public key, not by signature
entry. Two signatures from the same approver (even both valid, even over
the same bytes) count once. This is what "K-of-N" means -- K distinct
custodians, not K signatures from however many custodians happen to be
willing to sign twice.
"""
try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    _CRYPTOGRAPHY_IMPORT_ERROR = None
except ImportError as _e:  # pragma: no cover - exercised only without the dep installed
    _CRYPTOGRAPHY_IMPORT_ERROR = _e


class CustodyError(RuntimeError):
    pass


_MISSING_DEP_MSG = (
    "enterprise custody requires the 'cryptography' package: "
    "pip install -r requirements-enterprise.txt"
)


def _require_cryptography() -> None:
    if _CRYPTOGRAPHY_IMPORT_ERROR is not None:
        raise CustodyError(_MISSING_DEP_MSG) from _CRYPTOGRAPHY_IMPORT_ERROR


def generate_keypair() -> tuple[str, str]:
    """Generate a fresh ed25519 keypair. Returns (private_hex, public_hex),
    each the raw 32-byte key encoded as hex (64 hex chars). For approver key
    setup -- a CLI helper (`df-custody keygen`) wraps this.
    """
    _require_cryptography()
    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key()
    priv_bytes = sk.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_bytes = pk.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return priv_bytes.hex(), pub_bytes.hex()


def sign_manifest(private_hex: str, manifest_bytes: bytes) -> str:
    """Sign manifest_bytes with the ed25519 private key given as raw-32-byte
    hex. Returns the 64-byte signature as hex (128 hex chars). Raises
    CustodyError on a malformed key (wrong hex, wrong length) -- signing is
    an operator action, so a bad key is a loud failure, not a silent False.
    """
    _require_cryptography()
    try:
        key_bytes = bytes.fromhex(private_hex)
        sk = Ed25519PrivateKey.from_private_bytes(key_bytes)
        sig = sk.sign(manifest_bytes)
    except (ValueError, TypeError) as e:
        raise CustodyError(f"malformed ed25519 private key: {e}") from e
    return sig.hex()


def verify_one(public_hex: str, manifest_bytes: bytes, sig_hex: str) -> bool:
    """Verify a single ed25519 signature. Constant-time equality is provided
    by the underlying library's verify() (it does not short-circuit on the
    first mismatched byte). ANY error -- malformed pubkey hex/length,
    malformed sig hex/length, or a signature that simply doesn't verify --
    returns False. Never raises: this is a boolean predicate for use in a
    counting loop (verify_custody) that must never crash on attacker- or
    typo-controlled input.
    """
    _require_cryptography()
    try:
        pub_bytes = bytes.fromhex(public_hex)
        sig_bytes = bytes.fromhex(sig_hex)
        pk = Ed25519PublicKey.from_public_bytes(pub_bytes)
        pk.verify(sig_bytes, manifest_bytes)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def verify_custody(
    manifest_bytes: bytes,
    signatures: list[dict],
    approvers: list[str],
    k: int,
) -> tuple[bool, str]:
    """K-of-N split-custody verification.

    signatures: [{"approver": <public_hex>, "sig": <hex>}, ...]
    approvers:  the config's allowlist of known approver public keys (hex).
    k:          the required distinct-approver threshold.

    Rules (each enforced, none skippable):
      - a signature entry's "approver" MUST be a member of `approvers`,
        else it is ignored (not counted);
      - the signature MUST verify over manifest_bytes with that approver's
        public key, else it is ignored (not counted);
      - approvers are counted DISTINCTLY -- multiple valid-entry occurrences
        of the same approver count once, not multiple times;
      - a malformed entry (not a dict, missing "approver"/"sig", non-hex
        values) is ignored, never raises.

    Returns (satisfied: bool, reason: str) where satisfied is True iff the
    count of distinct, valid approver signatures is >= k. reason is always a
    human-readable "m/k distinct approver signatures" (satisfied) or a short
    explanation (not satisfied) -- never a private key or signature value.
    """
    approver_set = set(approvers)
    valid_distinct = set()

    for entry in signatures:
        if not isinstance(entry, dict):
            continue
        approver = entry.get("approver")
        sig_hex = entry.get("sig")
        if not isinstance(approver, str) or not isinstance(sig_hex, str):
            continue
        if approver not in approver_set:
            continue
        if not verify_one(approver, manifest_bytes, sig_hex):
            continue
        valid_distinct.add(approver)

    m = len(valid_distinct)
    reason = f"{m}/{k} distinct approver signatures"
    return (m >= k, reason)
