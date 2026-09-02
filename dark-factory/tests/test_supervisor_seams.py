"""Design tripwire for the supervisor package split.

supervisor.py re-exports the supervisor_* modules and is the module the suite
monkeypatches (`monkeypatch.setattr(supervisor, "<name>", ...)`). A patched name only
takes effect inside a supervisor_* module if that module calls it back THROUGH the
`supervisor` namespace (`_sup().<name>(...)`). Two things must therefore hold, or a
future test could patch a moved name and silently test nothing:

  1. every name a test patches on `supervisor` is either defined in supervisor.py
     itself or listed in supervisor_core.SUPERVISOR_SEAMS;
  2. no supervisor_* module calls a SUPERVISOR_SEAMS name directly.
"""
import ast
import glob
import os
import re

import supervisor
import supervisor_core

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.join(HERE, "..", "scripts")
MODULES = ["supervisor_core", "supervisor_audit", "supervisor_custody",
           "supervisor_isolation", "supervisor_init", "supervisor_ship"]
_PATCH_RE = re.compile(r"setattr\(\s*supervisor\s*,\s*[\"'](\w+)[\"']([^)]*)\)")


def _top_level_names(path):
    tree = ast.parse(open(path, encoding="utf-8").read())
    names = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, ast.Assign):
            for t in node.targets:
                for x in ast.walk(t):
                    if isinstance(x, ast.Name):
                        names.add(x.id)
    return names


def test_every_patched_supervisor_name_is_local_or_a_routed_seam():
    local = _top_level_names(os.path.join(SCRIPTS, "supervisor.py"))
    patched = set()
    for path in glob.glob(os.path.join(HERE, "test_*.py")):
        for m in _PATCH_RE.finditer(open(path, encoding="utf-8").read()):
            if "raising=False" in m.group(2):
                continue  # explicitly tolerant patch of a maybe-missing attribute
            patched.add(m.group(1))
    assert patched, "no monkeypatched supervisor names found — regex drifted?"
    unrouted = sorted(n for n in patched if n not in local and n not in supervisor_core.SUPERVISOR_SEAMS)
    assert not unrouted, (
        f"tests patch supervisor.{unrouted} but those names live in a supervisor_* module "
        f"and are not routed through _sup(): add them to SUPERVISOR_SEAMS and rewrite the "
        f"intra-module calls as _sup().<name>(...)")


def test_no_supervisor_module_calls_a_seam_directly():
    direct = []
    for mod in MODULES:
        tree = ast.parse(open(os.path.join(SCRIPTS, mod + ".py"), encoding="utf-8").read())
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                    and node.func.id in supervisor_core.SUPERVISOR_SEAMS):
                direct.append(f"{mod}.py:{node.lineno} {node.func.id}(")
    assert not direct, f"seam names must be called via _sup(): {direct}"


def test_every_seam_resolves_on_supervisor():
    missing = sorted(n for n in supervisor_core.SUPERVISOR_SEAMS if not hasattr(supervisor, n))
    assert not missing, missing
    # and the seam helper resolves the live module, not a second copy
    assert supervisor_core._sup() is supervisor
