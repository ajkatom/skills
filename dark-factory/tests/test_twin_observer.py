import json
import os
import urllib.request

import pytest

import df_twins

HERE = os.path.dirname(os.path.abspath(__file__))
GREETER = os.path.join(HERE, "fixtures", "twin_greeter")


def write_def(twins_dir, name="greeter", **over):
    twins_dir.mkdir(parents=True, exist_ok=True)
    d = {"twin_version": "0.1", "name": name,
         "launch": ["python3", GREETER], "fidelity": "dev mock"}
    d.update(over)
    (twins_dir / f"{name}.json").write_text(json.dumps(d), encoding="utf-8")
    return d


def _read_ndjson_lines(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def test_start_with_no_extra_env_produces_flushed_observations_and_unchanged_response(tmp_path):
    write_def(tmp_path / "twins")
    run_dir = tmp_path / "run"; run_dir.mkdir()
    ts = df_twins.TwinSet()
    try:
        env = ts.start(df_twins.load_defs(str(tmp_path / "twins")), str(run_dir), 20)
        host, port = env["DF_TWIN_GREETER"].split(":")
        body = urllib.request.urlopen(f"http://{host}:{port}/greet/World", timeout=5).read().decode()
        assert body == "Hello, World!"  # exactly today's behavior, no token

        obs_path = ts.observer_files["greeter"]
        assert os.path.exists(obs_path)
        lines = _read_ndjson_lines(obs_path)
        assert len(lines) == 1
        assert lines[0]["event"] == "GET"
        assert lines[0]["detail"] == "/greet/World"
        assert "token" not in lines[0]
    finally:
        ts.stop()


def test_observer_files_populated_at_start_and_empty_after_stop(tmp_path):
    write_def(tmp_path / "twins")
    run_dir = tmp_path / "run"; run_dir.mkdir()
    ts = df_twins.TwinSet()
    assert ts.observer_files == {}
    ts.start(df_twins.load_defs(str(tmp_path / "twins")), str(run_dir), 20)
    assert set(ts.observer_files) == {"greeter"}
    expected = os.path.join(str(run_dir), "twins", "greeter.observations.ndjson")
    assert ts.observer_files["greeter"] == expected
    ts.stop()
    assert ts.observer_files == {}


def test_extra_env_seed_produces_variant_token_in_response_and_observation(tmp_path):
    write_def(tmp_path / "twins")
    run_dir = tmp_path / "run"; run_dir.mkdir()
    ts = df_twins.TwinSet()
    try:
        seed = "seed-alpha"
        env = ts.start(df_twins.load_defs(str(tmp_path / "twins")), str(run_dir), 20,
                        extra_env={"DF_TWIN_VARIANT_SEED": seed})
        host, port = env["DF_TWIN_GREETER"].split(":")
        body = urllib.request.urlopen(f"http://{host}:{port}/greet/World", timeout=5).read().decode()
        assert body.startswith("Hello, World! [vt-")
        assert "vt-" in body

        lines = _read_ndjson_lines(ts.observer_files["greeter"])
        assert len(lines) == 1
        assert lines[0]["event"] == "GET"
        assert lines[0]["detail"] == "/greet/World"
        token = lines[0]["token"]
        assert token.startswith("vt-")
        # token in response body matches token recorded in observation
        assert f"[{token}]" in body
    finally:
        ts.stop()


def test_variant_token_differs_across_seeds_and_is_deterministic_for_same_seed_and_path(tmp_path):
    write_def(tmp_path / "twins")
    run_dir1 = tmp_path / "run1"; run_dir1.mkdir()
    run_dir2 = tmp_path / "run2"; run_dir2.mkdir()

    def _get_token(run_dir, seed):
        ts = df_twins.TwinSet()
        try:
            env = ts.start(df_twins.load_defs(str(tmp_path / "twins")), str(run_dir), 20,
                            extra_env={"DF_TWIN_VARIANT_SEED": seed})
            host, port = env["DF_TWIN_GREETER"].split(":")
            body = urllib.request.urlopen(f"http://{host}:{port}/greet/Same", timeout=5).read().decode()
            return body
        finally:
            ts.stop()

    run_dir3 = tmp_path / "run3"; run_dir3.mkdir()

    body_a = _get_token(run_dir1, "seed-A")
    body_b = _get_token(run_dir2, "seed-B")
    body_a2 = _get_token(run_dir3, "seed-A")

    assert body_a != body_b  # differs across seeds (unpredictability)
    assert body_a == body_a2  # deterministic for same seed + path


def test_reset_forwards_extra_env(tmp_path):
    write_def(tmp_path / "twins")
    run_dir = tmp_path / "run"; run_dir.mkdir()
    ts = df_twins.TwinSet()
    try:
        ts.start(df_twins.load_defs(str(tmp_path / "twins")), str(run_dir), 20)
        seed = "reset-seed"
        env = ts.reset(df_twins.load_defs(str(tmp_path / "twins")), str(run_dir), 20,
                        extra_env={"DF_TWIN_VARIANT_SEED": seed})
        host, port = env["DF_TWIN_GREETER"].split(":")
        body = urllib.request.urlopen(f"http://{host}:{port}/greet/X", timeout=5).read().decode()
        assert "vt-" in body
    finally:
        ts.stop()


# --- load_defs supports_variants matrix ---

def test_load_defs_supports_variants_default_false(tmp_path):
    write_def(tmp_path / "twins")
    defs = df_twins.load_defs(str(tmp_path / "twins"))
    assert defs[0]["supports_variants"] is False


def test_load_defs_supports_variants_true(tmp_path):
    write_def(tmp_path / "twins", supports_variants=True)
    defs = df_twins.load_defs(str(tmp_path / "twins"))
    assert defs[0]["supports_variants"] is True


def test_load_defs_supports_variants_false_explicit(tmp_path):
    write_def(tmp_path / "twins", supports_variants=False)
    defs = df_twins.load_defs(str(tmp_path / "twins"))
    assert defs[0]["supports_variants"] is False


@pytest.mark.parametrize("bad", ["yes", 1, 0, "true", None, [], {}])
def test_load_defs_supports_variants_rejects_non_bool(tmp_path, bad):
    write_def(tmp_path / "twins", supports_variants=bad)
    with pytest.raises(df_twins.TwinError, match="supports_variants"):
        df_twins.load_defs(str(tmp_path / "twins"))
