"""Shared helpers for dark-factory scripts. Python stdlib only."""
import hashlib
import json
import os
import tempfile


def canonical_json(obj) -> str:
    """Deterministic JSON used for all hashing: sorted keys, compact, UTF-8."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_str(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def sha256_file(path: str):
    """sha256 of a file's bytes, or None when the path is unreadable / not a
    regular file (M60 opus review 1c: a support file whose realpath is swapped
    to a directory between config-load and manifest-seal must seal an honest
    null, never crash the run with an uncaught IsADirectoryError)."""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
    except OSError:
        return None
    return h.hexdigest()


def atomic_write(path: str, text: str) -> None:
    """Write text to path atomically (tempfile + os.replace). Creates parent dirs."""
    d = os.path.dirname(os.path.abspath(path))
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".tmp-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
