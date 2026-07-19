"""M40 config tests for the `roles.author` role + different-model enforcement.

Covers:
  - author == builder (same resolved adapter path) -> ConfigError (fail-closed).
  - allow_same_model_ack: true overrides, and seals same_model_ack into
    cfg["_author"].
  - author != builder -> loads, cfg["_author"] populated.
  - absent roles.author -> cfg["_author"] is None (byte-identical to pre-M40).
  - shape validation (non-object, missing adapter, bad timeout/ack types).
  - at hardened+, the author adapter gets the same path hygiene as the builder.
"""
import json
import sys

import pytest

import df_config


def write_config(control_root, roles, **overrides):
    cfg = {
        "config_version": "0.1",
        "autonomy": 4,
        "assurance": "cooperative",
        "feedback": "ids",
        "max_iterations": 5,
        "workspace_root": str(control_root.parent / "ws"),
        "roles": roles,
        "budget": {"billing": "subscription"},
    }
    cfg.update(overrides)
    control_root.mkdir(parents=True, exist_ok=True)
    (control_root / "config.json").write_text(json.dumps(cfg), encoding="utf-8")
    return control_root


def test_author_equal_builder_is_refused(tmp_path):
    cr = write_config(tmp_path / "cr", {
        "builder": {"adapter": "/bin/echo"},
        "author": {"adapter": "/bin/echo"},
    })
    with pytest.raises(df_config.ConfigError, match="DIFFERENT path"):
        df_config.load_config(str(cr))


def test_author_equal_builder_via_symlink_is_refused(tmp_path):
    # realpath-based comparison: a symlink to the builder adapter is still the
    # same model, so it must be refused too (fail-closed by resolved path).
    real = tmp_path / "real_adapter"
    real.write_text("#!/bin/sh\n", encoding="utf-8")
    link = tmp_path / "linked_adapter"
    link.symlink_to(real)
    cr = write_config(tmp_path / "cr", {
        "builder": {"adapter": str(real)},
        "author": {"adapter": str(link)},
    })
    with pytest.raises(df_config.ConfigError, match="DIFFERENT path"):
        df_config.load_config(str(cr))


def test_same_model_ack_overrides_and_is_sealed(tmp_path):
    cr = write_config(tmp_path / "cr", {
        "builder": {"adapter": "/bin/echo"},
        "author": {"adapter": "/bin/echo", "allow_same_model_ack": True},
    })
    cfg = df_config.load_config(str(cr))
    assert cfg["_author"]["same_model_ack"] is True
    assert cfg["_author"]["adapter"] == "/bin/echo"


def test_different_adapters_load(tmp_path):
    cr = write_config(tmp_path / "cr", {
        "builder": {"adapter": "/bin/echo"},
        "author": {"adapter": "/bin/cat", "timeout_s": 120},
    })
    cfg = df_config.load_config(str(cr))
    assert cfg["_author"] == {"adapter": "/bin/cat", "timeout_s": 120,
                              "same_model_ack": False, "expected_sha256": None,
                              "model_identity": None}


def test_absent_author_is_none(tmp_path):
    cr = write_config(tmp_path / "cr", {"builder": {"adapter": "/bin/echo"}})
    cfg = df_config.load_config(str(cr))
    assert cfg["_author"] is None


def test_author_not_object_refused(tmp_path):
    cr = write_config(tmp_path / "cr", {
        "builder": {"adapter": "/bin/echo"}, "author": "nope"})
    with pytest.raises(df_config.ConfigError, match="roles.author must be a JSON object"):
        df_config.load_config(str(cr))


def test_author_missing_adapter_refused(tmp_path):
    cr = write_config(tmp_path / "cr", {
        "builder": {"adapter": "/bin/echo"}, "author": {"timeout_s": 60}})
    with pytest.raises(df_config.ConfigError, match="roles.author.adapter is required"):
        df_config.load_config(str(cr))


@pytest.mark.parametrize("bad", [{"timeout_s": 0}, {"timeout_s": "x"}, {"timeout_s": True}])
def test_author_bad_timeout_refused(tmp_path, bad):
    cr = write_config(tmp_path / "cr", {
        "builder": {"adapter": "/bin/echo"},
        "author": {"adapter": "/bin/cat", **bad}})
    with pytest.raises(df_config.ConfigError, match="roles.author.timeout_s"):
        df_config.load_config(str(cr))


def test_author_bad_ack_type_refused(tmp_path):
    cr = write_config(tmp_path / "cr", {
        "builder": {"adapter": "/bin/echo"},
        "author": {"adapter": "/bin/cat", "allow_same_model_ack": "yes"}})
    with pytest.raises(df_config.ConfigError, match="allow_same_model_ack must be a bool"):
        df_config.load_config(str(cr))


def test_hardened_author_requires_absolute_existing_path(tmp_path):
    # At hardened, roles.builder.adapter must be an absolute existing file
    # (sys.executable is). The author gets the SAME hygiene -- a bare command
    # name is rejected.
    cr = write_config(tmp_path / "cr", {
        "builder": {"adapter": sys.executable},
        "author": {"adapter": "cat"},   # bare name -> rejected at hardened
    }, assurance="hardened")
    with pytest.raises(df_config.ConfigError, match="roles.author.adapter to be an absolute path"):
        df_config.load_config(str(cr))


# ---------- DF-R3-04 (M50): content-digest + asserted model_identity cross-role checks ----------
#
# The realpath inequality stops the SAME adapter file across roles, but two
# distinct wrapper copies (or two api_* adapters aimed at one model) resolve to
# different paths. Two ADDITIVE cross-role checks close that honestly: an
# identical pinned `adapter_sha256` (identical content = same model) and an
# identical operator-ASSERTED `model_identity`. Each is waived by the pair's
# allow_same_model_ack. Absent both -> byte-identical to pre-M50.

_DIGEST_A = "a" * 64
_DIGEST_B = "b" * 64


def test_author_builder_same_adapter_sha256_refused(tmp_path):
    cr = write_config(tmp_path / "cr", {
        "builder": {"adapter": "/bin/echo", "adapter_sha256": _DIGEST_A},
        "author": {"adapter": "/bin/cat", "adapter_sha256": _DIGEST_A},
    })
    with pytest.raises(df_config.ConfigError, match="IDENTICAL to roles.builder.adapter_sha256"):
        df_config.load_config(str(cr))


def test_author_builder_same_adapter_sha256_waived_by_ack(tmp_path):
    cr = write_config(tmp_path / "cr", {
        "builder": {"adapter": "/bin/echo", "adapter_sha256": _DIGEST_A},
        "author": {"adapter": "/bin/cat", "adapter_sha256": _DIGEST_A,
                   "allow_same_model_ack": True},
    })
    cfg = df_config.load_config(str(cr))
    assert cfg["_author"]["same_model_ack"] is True


def test_author_builder_distinct_digests_load(tmp_path):
    cr = write_config(tmp_path / "cr", {
        "builder": {"adapter": "/bin/echo", "adapter_sha256": _DIGEST_A},
        "author": {"adapter": "/bin/cat", "adapter_sha256": _DIGEST_B},
    })
    cfg = df_config.load_config(str(cr))
    assert cfg["_author"]["expected_sha256"] == _DIGEST_B


def test_author_builder_same_model_identity_refused(tmp_path):
    cr = write_config(tmp_path / "cr", {
        "builder": {"adapter": "/bin/echo", "model_identity": "anthropic/claude-opus-4"},
        "author": {"adapter": "/bin/cat", "model_identity": "anthropic/claude-opus-4"},
    })
    with pytest.raises(df_config.ConfigError, match="model_identity is IDENTICAL"):
        df_config.load_config(str(cr))


def test_author_builder_same_model_identity_waived_by_ack(tmp_path):
    cr = write_config(tmp_path / "cr", {
        "builder": {"adapter": "/bin/echo", "model_identity": "anthropic/claude-opus-4"},
        "author": {"adapter": "/bin/cat", "model_identity": "anthropic/claude-opus-4",
                   "allow_same_model_ack": True},
    })
    cfg = df_config.load_config(str(cr))
    assert cfg["_author"]["model_identity"] == "anthropic/claude-opus-4"


def test_author_distinct_model_identity_loads_and_is_sealed_verbatim(tmp_path):
    cr = write_config(tmp_path / "cr", {
        "builder": {"adapter": "/bin/echo", "model_identity": "anthropic/claude-sonnet-4-5"},
        "author": {"adapter": "/bin/cat", "model_identity": "openai/gpt-5-codex"},
    })
    cfg = df_config.load_config(str(cr))
    # Verbatim (not normalized/stripped) into cfg for the manifest seal.
    assert cfg["_author"]["model_identity"] == "openai/gpt-5-codex"


def test_model_identity_non_string_rejected(tmp_path):
    cr = write_config(tmp_path / "cr", {
        "builder": {"adapter": "/bin/echo"},
        "author": {"adapter": "/bin/cat", "model_identity": 123},
    })
    with pytest.raises(df_config.ConfigError, match="model_identity must be a non-empty string"):
        df_config.load_config(str(cr))


def test_model_identity_empty_string_rejected(tmp_path):
    cr = write_config(tmp_path / "cr", {
        "builder": {"adapter": "/bin/echo"},
        "author": {"adapter": "/bin/cat", "model_identity": "   "},
    })
    with pytest.raises(df_config.ConfigError, match="model_identity must be a non-empty string"):
        df_config.load_config(str(cr))
