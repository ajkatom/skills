"""M47 condition #7: authenticate the adapter by CONTENT (sha256), not path.

An operator can pin `roles.<role>.adapter_sha256` (a 64-hex expected digest);
config load validates the hex shape, and the supervisor computes the adapter
file's real sha256 at run start and REFUSES (fail-closed, exit 2, journal
ADAPTER_DIGEST_MISMATCH) on any mismatch. Absent -> byte-identical to pre-M47.
"""
import json
import os

import pytest

import df_config
import supervisor
from df_common import sha256_file
from test_supervisor import FAKE, setup_control


# --- config-load hex-shape validation ---------------------------------------

def _write_cfg(cr, adapter_sha256):
    p = cr / "config.json"
    cfg = json.loads(p.read_text())
    cfg["roles"]["builder"]["adapter_sha256"] = adapter_sha256
    p.write_text(json.dumps(cfg))


def test_absent_pin_is_none_and_backcompat(tmp_path):
    cr = setup_control(tmp_path, FAKE)
    cfg = df_config.load_config(str(cr))
    assert cfg["_adapter_digests"] == {"builder": None, "author": None, "critic": None}


def test_good_hex_pin_loads_and_lowercases(tmp_path):
    cr = setup_control(tmp_path, FAKE)
    _write_cfg(cr, "AB" * 32)  # 64 hex, upper -> lowercased
    cfg = df_config.load_config(str(cr))
    assert cfg["_adapter_digests"]["builder"] == "ab" * 32


@pytest.mark.parametrize("bad", ["", "abc", "z" * 64, "ab" * 33, 123, True])
def test_bad_hex_pin_refused_at_load(tmp_path, bad):
    cr = setup_control(tmp_path, FAKE)
    _write_cfg(cr, bad)
    with pytest.raises(df_config.ConfigError, match="adapter_sha256 must be a 64-character hex"):
        df_config.load_config(str(cr))


# --- run-start content enforcement (fail-before / pass-after) ---------------

def test_matching_pin_runs(tmp_path):
    # A pin equal to the adapter's real content sha256 -> run proceeds normally.
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")
    _write_cfg(cr, sha256_file(FAKE))
    assert supervisor.run(str(cr), None) == 0


def test_mismatched_pin_refuses_exit_2_and_journals(tmp_path):
    # RED before M47 (no pin existed), GREEN after: a pin that does NOT match the
    # adapter bytes refuses fail-closed with exit 2 and a distinct journal event.
    cr = setup_control(tmp_path, FAKE, checkpoint="auto")
    _write_cfg(cr, "de" * 32)  # valid hex shape, wrong content
    assert supervisor.run(str(cr), None) == 2
    run_id = os.listdir(cr / "runs")[0]
    states = [json.loads(l)["state"] for l in
              (cr / "runs" / run_id / "journal.jsonl").read_text().splitlines()]
    assert "ADAPTER_DIGEST_MISMATCH" in states
    # Fail-closed: no build ever ran, no qualified seal.
    assert "BUILD" not in states


# --- author/critic pin enforced at AUTHORING time (review Finding 1) ---------

def test_author_pin_enforced_in_author_scenarios_cmd(tmp_path):
    """A pinned roles.author.adapter_sha256 must be enforced BEFORE the author
    adapter is invoked by `author-scenarios` — not only at a later builder
    `run`. RED before the fix (author-scenarios never checked the pin, so a
    substituted author could write the hidden scenarios undetected); GREEN
    after: it refuses fail-closed (exit 2, ADAPTER_DIGEST_MISMATCH) and installs
    NO scenarios.
    """
    from test_e2e_author import _init, FAKE_AUTHOR
    import df_init

    cr, p = _init(tmp_path, FAKE_AUTHOR)
    assert p.returncode == 0, p.stderr
    assert df_init.is_scenarios_pending(cr)

    # Pin the author to a wrong (but valid-shape) digest, simulating a swap.
    cfgp = cr / "config.json"
    cfg = json.loads(cfgp.read_text())
    cfg["roles"]["author"]["adapter_sha256"] = "de" * 32
    cfgp.write_text(json.dumps(cfg))

    rc = supervisor.author_scenarios_cmd(str(cr))
    assert rc == 2
    # Nothing authored: scenarios still pending, none installed.
    assert df_init.is_scenarios_pending(cr)
    scen = cr / "scenarios"
    assert not (scen.is_dir() and [n for n in os.listdir(scen) if n.endswith(".json")])
    # The refusal is journaled to the author command's control-plane log.
    states = [json.loads(l)["state"]
              for l in (cr / "authored.jsonl").read_text().splitlines()]
    assert "ADAPTER_DIGEST_MISMATCH" in states
    assert "AUTHORED_SCENARIOS_ATTEMPT" not in states


def test_matching_author_pin_allows_author_scenarios(tmp_path):
    """Control: a CORRECT author pin does not block authoring (byte-identical
    to no pin) — proves the enforcement is content-exact, not a blanket block.
    """
    from test_e2e_author import _init, FAKE_AUTHOR
    import df_init

    cr, p = _init(tmp_path, FAKE_AUTHOR)
    assert p.returncode == 0, p.stderr
    cfgp = cr / "config.json"
    cfg = json.loads(cfgp.read_text())
    cfg["roles"]["author"]["adapter_sha256"] = sha256_file(FAKE_AUTHOR)
    cfgp.write_text(json.dumps(cfg))

    rc = supervisor.author_scenarios_cmd(str(cr))
    assert rc == 0
    assert not df_init.is_scenarios_pending(cr)
