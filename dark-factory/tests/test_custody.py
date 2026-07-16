"""M17 Task 1: df_custody — ed25519 K-of-N split-custody.

Split custody is the single-operator-proof primitive: a run is only
`qualified` once >=K DISTINCT approvers (each holding their own ed25519
private key) have signed the exact finalized manifest bytes. The verifier
(`verify_custody`) holds only PUBLIC keys, so it can check but never forge a
signature; N copies of one approver's valid signature must never count as
more than 1 toward K.

This suite covers df_custody.py in isolation (keygen/sign/verify_one/
verify_custody) plus the df_config.py `custody` block validation (shape only
— enterprise-requires-custody enforcement is Task 3).
"""
import os

import pytest

import df_config
import df_custody
from df_custody import CustodyError, generate_keypair, sign_manifest, verify_custody, verify_one
from test_config import write_config

MANIFEST = b'{"run_id":"abc123","outcome":"CONVERGED"}'
OTHER_MANIFEST = b'{"run_id":"different","outcome":"CONVERGED"}'


# ---------------------------------------------------------------------------
# generate_keypair
# ---------------------------------------------------------------------------

def test_generate_keypair_returns_hex_pair_of_expected_length():
    priv, pub = generate_keypair()
    assert isinstance(priv, str) and isinstance(pub, str)
    assert len(priv) == 64  # 32 raw bytes, hex
    assert len(pub) == 64
    bytes.fromhex(priv)
    bytes.fromhex(pub)


def test_generate_keypair_is_random_each_call():
    priv1, pub1 = generate_keypair()
    priv2, pub2 = generate_keypair()
    assert priv1 != priv2
    assert pub1 != pub2


def test_generate_keypair_round_trips_through_sign_verify():
    priv, pub = generate_keypair()
    sig = sign_manifest(priv, MANIFEST)
    assert verify_one(pub, MANIFEST, sig) is True


# ---------------------------------------------------------------------------
# sign_manifest / verify_one
# ---------------------------------------------------------------------------

def test_sign_manifest_produces_64_byte_hex_sig():
    priv, _pub = generate_keypair()
    sig = sign_manifest(priv, MANIFEST)
    assert isinstance(sig, str)
    assert len(sig) == 128  # 64 raw bytes, hex
    bytes.fromhex(sig)


def test_sign_manifest_malformed_key_raises_custody_error():
    with pytest.raises(CustodyError):
        sign_manifest("not-hex-zz", MANIFEST)


def test_sign_manifest_wrong_length_key_raises_custody_error():
    with pytest.raises(CustodyError):
        sign_manifest("ab" * 10, MANIFEST)  # 10 bytes, not 32


def test_verify_one_happy_path():
    priv, pub = generate_keypair()
    sig = sign_manifest(priv, MANIFEST)
    assert verify_one(pub, MANIFEST, sig) is True


def test_verify_one_wrong_key_returns_false():
    priv, _pub = generate_keypair()
    _other_priv, other_pub = generate_keypair()
    sig = sign_manifest(priv, MANIFEST)
    assert verify_one(other_pub, MANIFEST, sig) is False


def test_verify_one_tampered_bytes_returns_false():
    priv, pub = generate_keypair()
    sig = sign_manifest(priv, MANIFEST)
    assert verify_one(pub, OTHER_MANIFEST, sig) is False


def test_verify_one_malformed_pubkey_returns_false_not_raise():
    priv, _pub = generate_keypair()
    sig = sign_manifest(priv, MANIFEST)
    assert verify_one("zz-not-hex", MANIFEST, sig) is False


def test_verify_one_malformed_sig_returns_false_not_raise():
    _priv, pub = generate_keypair()
    assert verify_one(pub, MANIFEST, "not-hex-at-all-zz") is False


def test_verify_one_wrong_length_sig_returns_false_not_raise():
    _priv, pub = generate_keypair()
    assert verify_one(pub, MANIFEST, "ab" * 10) is False


def test_verify_one_wrong_length_pubkey_returns_false_not_raise():
    priv, _pub = generate_keypair()
    sig = sign_manifest(priv, MANIFEST)
    assert verify_one("ab" * 10, MANIFEST, sig) is False


# ---------------------------------------------------------------------------
# verify_custody — the single-operator-proof property
# ---------------------------------------------------------------------------

def _approver():
    priv, pub = generate_keypair()
    return priv, pub


def test_verify_custody_k_of_n_satisfied_with_two_distinct_valid_sigs():
    priv_a, pub_a = _approver()
    priv_b, pub_b = _approver()
    _priv_c, pub_c = _approver()
    approvers = [pub_a, pub_b, pub_c]
    sigs = [
        {"approver": pub_a, "sig": sign_manifest(priv_a, MANIFEST)},
        {"approver": pub_b, "sig": sign_manifest(priv_b, MANIFEST)},
    ]
    satisfied, reason = verify_custody(MANIFEST, sigs, approvers, 2)
    assert satisfied is True
    assert isinstance(reason, str) and "2" in reason


def test_verify_custody_only_one_valid_not_satisfied():
    priv_a, pub_a = _approver()
    _priv_b, pub_b = _approver()
    _priv_c, pub_c = _approver()
    approvers = [pub_a, pub_b, pub_c]
    sigs = [{"approver": pub_a, "sig": sign_manifest(priv_a, MANIFEST)}]
    satisfied, reason = verify_custody(MANIFEST, sigs, approvers, 2)
    assert satisfied is False
    assert isinstance(reason, str) and reason


def test_verify_custody_duplicate_approver_signatures_count_once_critical():
    # THE single-operator-proof property: two (even distinct) valid
    # signatures from the SAME approver must NOT satisfy k=2. Only one
    # private key was ever used.
    priv_a, pub_a = _approver()
    _priv_b, pub_b = _approver()
    approvers = [pub_a, pub_b]
    sig1 = sign_manifest(priv_a, MANIFEST)
    # A second, independently-produced signature from the SAME key (ed25519
    # signing is deterministic so sig1 == sig2 here, but duplicate ENTRIES
    # of the same approver must still count once regardless).
    sig2 = sign_manifest(priv_a, MANIFEST)
    sigs = [
        {"approver": pub_a, "sig": sig1},
        {"approver": pub_a, "sig": sig2},
    ]
    satisfied, reason = verify_custody(MANIFEST, sigs, approvers, 2)
    assert satisfied is False
    assert isinstance(reason, str) and reason


def test_verify_custody_unknown_approver_ignored():
    priv_a, pub_a = _approver()
    _priv_unknown, pub_unknown = _approver()
    approvers = [pub_a]  # pub_unknown is NOT in approvers
    sigs = [
        {"approver": pub_a, "sig": sign_manifest(priv_a, MANIFEST)},
        {"approver": pub_unknown, "sig": sign_manifest(_priv_unknown, MANIFEST)},
    ]
    satisfied, reason = verify_custody(MANIFEST, sigs, approvers, 2)
    assert satisfied is False  # only 1 counted (pub_a); pub_unknown ignored


def test_verify_custody_bad_sig_ignored_not_counted():
    priv_a, pub_a = _approver()
    priv_b, pub_b = _approver()
    approvers = [pub_a, pub_b]
    good = sign_manifest(priv_a, MANIFEST)
    bad = sign_manifest(priv_b, OTHER_MANIFEST)  # signed over the WRONG bytes
    sigs = [
        {"approver": pub_a, "sig": good},
        {"approver": pub_b, "sig": bad},
    ]
    satisfied, reason = verify_custody(MANIFEST, sigs, approvers, 2)
    assert satisfied is False


def test_verify_custody_malformed_sig_entry_ignored_not_crash():
    priv_a, pub_a = _approver()
    _priv_b, pub_b = _approver()
    approvers = [pub_a, pub_b]
    sigs = [
        {"approver": pub_a, "sig": sign_manifest(priv_a, MANIFEST)},
        {"approver": pub_b, "sig": "not-valid-hex-zz"},  # malformed, must not crash
        {"approver": pub_b},  # missing "sig" key entirely
        {"sig": "deadbeef"},  # missing "approver" key entirely
        "not-even-a-dict",  # garbage entry
    ]
    satisfied, reason = verify_custody(MANIFEST, sigs, approvers, 2)
    assert satisfied is False  # only pub_a counted; nothing crashed


def test_verify_custody_k_equals_n_all_must_sign():
    priv_a, pub_a = _approver()
    priv_b, pub_b = _approver()
    approvers = [pub_a, pub_b]
    sigs = [
        {"approver": pub_a, "sig": sign_manifest(priv_a, MANIFEST)},
        {"approver": pub_b, "sig": sign_manifest(priv_b, MANIFEST)},
    ]
    satisfied, _reason = verify_custody(MANIFEST, sigs, approvers, 2)
    assert satisfied is True

    sigs_missing_one = [{"approver": pub_a, "sig": sign_manifest(priv_a, MANIFEST)}]
    satisfied2, _reason2 = verify_custody(MANIFEST, sigs_missing_one, approvers, 2)
    assert satisfied2 is False


def test_verify_custody_empty_signatures_not_satisfied():
    _priv_a, pub_a = _approver()
    satisfied, reason = verify_custody(MANIFEST, [], [pub_a], 1)
    assert satisfied is False
    assert isinstance(reason, str) and reason


def test_verify_custody_reason_reports_distinct_count_and_threshold():
    priv_a, pub_a = _approver()
    _priv_b, pub_b = _approver()
    _priv_c, pub_c = _approver()
    approvers = [pub_a, pub_b, pub_c]
    sigs = [{"approver": pub_a, "sig": sign_manifest(priv_a, MANIFEST)}]
    satisfied, reason = verify_custody(MANIFEST, sigs, approvers, 2)
    assert satisfied is False
    assert "1" in reason
    assert "2" in reason


# ---------------------------------------------------------------------------
# df_config.py: cfg["_custody"] shape validation
# ---------------------------------------------------------------------------

def test_custody_absent_is_none(tmp_path):
    cr = tmp_path / "control"
    write_config(cr)
    cfg = df_config.load_config(str(cr))
    assert cfg["_custody"] is None


def test_custody_valid_block(tmp_path):
    _priv_a, pub_a = _approver()
    _priv_b, pub_b = _approver()
    _priv_c, pub_c = _approver()
    cr = tmp_path / "control"
    write_config(cr, custody={"approvers": [pub_a, pub_b, pub_c], "threshold": 2})
    cfg = df_config.load_config(str(cr))
    assert cfg["_custody"] == {"approvers": [pub_a, pub_b, pub_c], "threshold": 2}


def test_custody_non_dict_block_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, custody="oops")
    with pytest.raises(df_config.ConfigError, match="custody"):
        df_config.load_config(str(cr))


def test_custody_empty_approvers_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, custody={"approvers": [], "threshold": 1})
    with pytest.raises(df_config.ConfigError, match="approvers"):
        df_config.load_config(str(cr))


def test_custody_approvers_not_a_list_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, custody={"approvers": "not-a-list", "threshold": 1})
    with pytest.raises(df_config.ConfigError, match="approvers"):
        df_config.load_config(str(cr))


@pytest.mark.parametrize("bad", ["short", "zz" * 32, "a" * 63, "a" * 65, 12345, None])
def test_custody_malformed_approver_hex_rejected(tmp_path, bad):
    cr = tmp_path / "control"
    write_config(cr, custody={"approvers": [bad], "threshold": 1})
    with pytest.raises(df_config.ConfigError, match="approvers"):
        df_config.load_config(str(cr))


def test_custody_duplicate_approvers_rejected(tmp_path):
    _priv_a, pub_a = _approver()
    cr = tmp_path / "control"
    write_config(cr, custody={"approvers": [pub_a, pub_a], "threshold": 1})
    with pytest.raises(df_config.ConfigError, match="unique|duplicate"):
        df_config.load_config(str(cr))


def test_custody_threshold_zero_rejected(tmp_path):
    _priv_a, pub_a = _approver()
    cr = tmp_path / "control"
    write_config(cr, custody={"approvers": [pub_a], "threshold": 0})
    with pytest.raises(df_config.ConfigError, match="threshold"):
        df_config.load_config(str(cr))


def test_custody_threshold_greater_than_n_rejected(tmp_path):
    _priv_a, pub_a = _approver()
    _priv_b, pub_b = _approver()
    cr = tmp_path / "control"
    write_config(cr, custody={"approvers": [pub_a, pub_b], "threshold": 3})
    with pytest.raises(df_config.ConfigError, match="threshold"):
        df_config.load_config(str(cr))


def test_custody_threshold_not_int_rejected(tmp_path):
    _priv_a, pub_a = _approver()
    cr = tmp_path / "control"
    write_config(cr, custody={"approvers": [pub_a], "threshold": "2"})
    with pytest.raises(df_config.ConfigError, match="threshold"):
        df_config.load_config(str(cr))


def test_custody_threshold_bool_rejected(tmp_path):
    _priv_a, pub_a = _approver()
    cr = tmp_path / "control"
    write_config(cr, custody={"approvers": [pub_a], "threshold": True})
    with pytest.raises(df_config.ConfigError, match="threshold"):
        df_config.load_config(str(cr))


def test_custody_threshold_equal_to_n_ok(tmp_path):
    _priv_a, pub_a = _approver()
    _priv_b, pub_b = _approver()
    cr = tmp_path / "control"
    write_config(cr, custody={"approvers": [pub_a, pub_b], "threshold": 2})
    cfg = df_config.load_config(str(cr))
    assert cfg["_custody"]["threshold"] == 2


def test_custody_missing_threshold_rejected(tmp_path):
    _priv_a, pub_a = _approver()
    cr = tmp_path / "control"
    write_config(cr, custody={"approvers": [pub_a]})
    with pytest.raises(df_config.ConfigError, match="threshold"):
        df_config.load_config(str(cr))


def test_custody_missing_approvers_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, custody={"threshold": 1})
    with pytest.raises(df_config.ConfigError, match="approvers"):
        df_config.load_config(str(cr))


# ---------------------------------------------------------------------------
# Import guard: cryptography is imported ONLY by df_custody, and only there.
# ---------------------------------------------------------------------------

def test_cryptography_not_imported_by_df_config():
    config_path = os.path.join(
        os.path.dirname(os.path.abspath(df_config.__file__)), "df_config.py"
    )
    with open(config_path, encoding="utf-8") as f:
        text = f.read()
    assert "import cryptography" not in text
    assert "from cryptography" not in text


def test_df_custody_module_imports_cryptography_only_module():
    custody_path = os.path.abspath(df_custody.__file__)
    with open(custody_path, encoding="utf-8") as f:
        text = f.read()
    assert "cryptography" in text
