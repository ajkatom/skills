import os

import df_common


def test_canonical_json_is_deterministic_and_compact():
    a = {"b": 1, "a": [2, 1], "c": {"y": None, "x": "é"}}
    s = df_common.canonical_json(a)
    assert s == '{"a":[2,1],"b":1,"c":{"x":"é","y":null}}'
    # key order in the input must not matter
    assert s == df_common.canonical_json({"c": {"x": "é", "y": None}, "a": [2, 1], "b": 1})


def test_sha256_str_known_vector():
    assert (
        df_common.sha256_str("abc")
        == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )


def test_sha256_file_matches_sha256_str(tmp_path):
    p = tmp_path / "f.txt"
    p.write_text("abc", encoding="utf-8")
    assert df_common.sha256_file(str(p)) == df_common.sha256_str("abc")


def test_atomic_write_creates_parents_and_replaces(tmp_path):
    target = tmp_path / "deep" / "nested" / "out.txt"
    df_common.atomic_write(str(target), "one")
    assert target.read_text(encoding="utf-8") == "one"
    df_common.atomic_write(str(target), "two")
    assert target.read_text(encoding="utf-8") == "two"
    # no stray tempfiles left behind
    leftovers = [f for f in os.listdir(target.parent) if f.startswith(".tmp-")]
    assert leftovers == []
