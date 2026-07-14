"""Builder registry + capability probe. Stdlib only.

Reports which builder CLIs are installed so the skill's invocation step can
offer only usable models, and resolves a chosen builder to its shipped adapter
path WITHOUT ever substituting a different model (no silent fallback, spec 7.8).
"""
import os
import shutil

SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))

# builder name -> required CLI on PATH. The shipped adapter is scripts/adapters/<name>.
BUILDERS = {"claude": "claude", "codex": "codex", "gemini": "gemini"}


class BuilderUnavailable(RuntimeError):
    pass


def adapter_path(name: str) -> str:
    if name not in BUILDERS:
        raise KeyError(f"unknown builder {name!r}; known: {sorted(BUILDERS)}")
    return os.path.join(SCRIPTS_DIR, "adapters", name)


def available_builders(which=shutil.which) -> dict:
    return {name: which(cli) is not None for name, cli in BUILDERS.items()}


def resolve_builder(name: str, which=shutil.which) -> str:
    if name not in BUILDERS:
        raise KeyError(f"unknown builder {name!r}; known: {sorted(BUILDERS)}")
    if which(BUILDERS[name]) is None:
        raise BuilderUnavailable(
            f"builder {name!r} requires the {BUILDERS[name]!r} CLI, which is not on "
            f"PATH; install it or choose an available builder (no fallback)"
        )
    return adapter_path(name)
