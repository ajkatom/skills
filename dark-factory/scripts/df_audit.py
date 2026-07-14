"""Tamper-evident audit signing (spec 7.5). Stdlib only.

An HMAC-SHA256 over the manifest bytes, keyed by a supervisor-only key kept
OUTSIDE every run/control/workspace tree. A local tamperer who rewrites the
manifest cannot forge the HMAC without the key. Tamper-evidence holds only
while the key stays secret (see references/audit.md for the tier caveat).
"""
import hashlib
import hmac
import os
import secrets


class AuditKeyError(RuntimeError):
    pass


def load_or_create_key(key_path: str) -> bytes:
    if os.path.exists(key_path):
        try:
            raw = open(key_path, encoding="utf-8").read().strip()
            key = bytes.fromhex(raw)
        except ValueError as e:
            raise AuditKeyError(f"malformed audit key at {key_path}: {e}")
        if len(key) != 32:
            raise AuditKeyError(f"audit key at {key_path} must be 32 bytes")
        return key
    d = os.path.dirname(os.path.abspath(key_path))
    os.makedirs(d, mode=0o700, exist_ok=True)
    key = secrets.token_bytes(32)
    fd = os.open(key_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(key.hex())
    return key


def sign(key: bytes, data: bytes) -> str:
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def verify(key: bytes, data: bytes, sig_hex: str) -> bool:
    try:
        expected = hmac.new(key, data, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, sig_hex)
    except (TypeError, ValueError):
        return False
