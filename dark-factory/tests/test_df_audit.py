import os
import stat

import pytest

import df_audit


def test_create_then_load_roundtrips(tmp_path):
    kp = tmp_path / "sub" / "audit.key"
    k1 = df_audit.load_or_create_key(str(kp))
    assert len(k1) == 32
    mode = stat.S_IMODE(os.stat(kp).st_mode)
    assert mode == 0o600
    k2 = df_audit.load_or_create_key(str(kp))
    assert k1 == k2  # stable


def test_malformed_key_raises(tmp_path):
    kp = tmp_path / "audit.key"
    kp.write_text("not-hex", encoding="utf-8")
    with pytest.raises(df_audit.AuditKeyError):
        df_audit.load_or_create_key(str(kp))


def test_sign_verify_roundtrip():
    k = b"\x01" * 32
    sig = df_audit.sign(k, b"hello")
    assert df_audit.verify(k, b"hello", sig)
    assert not df_audit.verify(k, b"tampered", sig)
    assert not df_audit.verify(b"\x02" * 32, b"hello", sig)  # wrong key


def test_verify_rejects_garbage_sig():
    assert df_audit.verify(b"\x01" * 32, b"x", "nothex") is False
