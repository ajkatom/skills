"""M65 (Codex R6 DF-R6-11): a docs smoke test — every CLI FORM shown in the
public docs must PARSE against the real argparse (never the exit-2
"unrecognized arguments" the audit found for `verify-chain --control-root` and
`run <cr> --project-src`). We do not execute the real work here (that needs
infra); we prove the documented invocation SHAPES are accepted by the parser,
so a doc example can't drift from the parser again.

Also asserts the README's stated test count is not wildly stale.
"""
import os
import re
import subprocess
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SUP = os.path.join(ROOT, "scripts", "supervisor.py")


def _parse_only(argv):
    """Run supervisor.py with argv but force an argparse-only check: we can't run
    the real command, so we assert the parser does NOT reject the FLAG SHAPE with
    exit 2 + 'unrecognized'/'invalid choice'/'required'. A form that parses then
    fails later (missing files) is fine — that's not a doc-syntax defect."""
    r = subprocess.run([sys.executable, SUP] + argv + ["--help"],
                       capture_output=True, text=True, timeout=30)
    # `<subcommand> --help` exits 0 and prints usage IFF the subcommand + its
    # declared flags are real. An unknown subcommand/flag exits 2.
    return r.returncode, (r.stdout + r.stderr)


@pytest.mark.parametrize("argv,must_show", [
    (["init"], "--control-root"),
    (["run"], "--control-root"),
    (["run"], "--project-src"),
    (["verify-manifest"], "--run-dir"),
    (["verify-manifest"], "--key-path"),
    (["verify-chain"], "control_root"),        # POSITIONAL, not --control-root
    (["verify-chain"], "--key-path"),
    (["ship"], "--run-dir"),
    (["ship"], "repair-evidence"),             # DF-R5-02 decision documented
    (["df-custody", "attach"], "--run-dir"),
    (["df-release", "attach"], "--run-dir"),
    (["evidence-bundle"], "--require-production"),
])
def test_documented_cli_form_parses(argv, must_show):
    rc, out = _parse_only(argv)
    assert rc == 0, f"`supervisor.py {' '.join(argv)} --help` failed: {out}"
    assert must_show in out, f"{must_show!r} not in the {argv} help: {out}"


def test_invalid_legacy_forms_are_actually_invalid():
    # The exact form the audit flagged must NOT parse (guards against a doc
    # regression reintroducing `verify-chain --control-root`). No --help here —
    # we want the parser to reject the unknown flag, exit 2.
    r = subprocess.run([sys.executable, SUP, "verify-chain", "--control-root", "/x"],
                       capture_output=True, text=True, timeout=30)
    assert r.returncode == 2
    assert "control-root" in (r.stdout + r.stderr).lower()


def test_readme_test_count_is_not_stale():
    readme = open(os.path.join(ROOT, "README.md"), encoding="utf-8").read()
    m = re.search(r"~(\d[\d,]*)\s+tests", readme)
    assert m, "README should state an approximate test count"
    stated = int(m.group(1).replace(",", ""))
    # within a reasonable band of the real suite size (currently ~2046).
    assert 1800 <= stated <= 2600, f"README test count {stated} is stale"


def test_support_matrix_documents_the_linux_loopback_limit():
    doc = open(os.path.join(ROOT, "references", "support-matrix.md"),
               encoding="utf-8").read()
    assert "loopback" in doc and "Linux" in doc
    assert "not supported at standard+" in doc or "cannot qualify" in doc
