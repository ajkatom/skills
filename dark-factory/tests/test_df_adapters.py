import os

import pytest

import df_adapters


def test_builders_are_the_three_known_names():
    assert set(df_adapters.BUILDERS) == {"claude", "codex", "gemini"}


def test_adapter_path_points_at_shipped_executable():
    p = df_adapters.adapter_path("codex")
    assert p.endswith(os.path.join("scripts", "adapters", "codex"))
    assert os.access(p, os.X_OK)  # shipped executable


def test_adapter_path_unknown_raises():
    with pytest.raises(KeyError):
        df_adapters.adapter_path("llama")


def test_available_builders_reflects_which(monkeypatch):
    present = {"claude", "gemini"}
    fake_which = lambda name: ("/usr/bin/" + name) if name in present else None
    avail = df_adapters.available_builders(which=fake_which)
    assert avail == {"claude": True, "codex": False, "gemini": True}


def test_resolve_builder_returns_path_when_present():
    fake_which = lambda name: "/usr/bin/" + name
    assert df_adapters.resolve_builder("codex", which=fake_which) == df_adapters.adapter_path("codex")


def test_resolve_builder_never_falls_back():
    fake_which = lambda name: None  # nothing installed
    with pytest.raises(df_adapters.BuilderUnavailable, match="codex"):
        df_adapters.resolve_builder("codex", which=fake_which)
