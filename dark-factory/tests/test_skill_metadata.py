"""DF-R4-01 (M52): SKILL.md frontmatter must be VALID, loadable metadata.

The R4 re-audit caught the `description:` as an UNQUOTED YAML plain scalar of
1186 chars containing `Tiers: ` — the ` : ` mid-scalar makes a YAML parser read
it as a mapping value and error, AND it exceeded the skill-creator validator's
1024-char limit, so the skill could fail to load at all. This locks the fix:

  - the `---`-delimited frontmatter parses as a YAML MAPPING (real parse when
    PyYAML is present, via importorskip; a stdlib line-check runs ALWAYS so the
    guard is non-vacuous even on an interpreter without PyYAML), and
  - `name` is present and `len(description) <= 1024`,

so the description can never silently regrow past the limit or reintroduce an
unquoted `: ` that breaks the parse again.
"""
import os

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
SKILL_MD = os.path.join(HERE, "..", "SKILL.md")

# The skill-creator validator's hard cap on `description`. A description longer
# than this may be rejected/truncated at load — the exact regression DF-R4-01
# named — so the test fails CLOSED at the boundary.
DESCRIPTION_MAX = 1024


def _read_frontmatter_block():
    """Return the raw text BETWEEN the opening `---` and the next `---`.

    Fail-closed (a real error, not a silent skip): the suite runs under
    `python -O`, so a bare `assert` would be stripped — every check that must
    hold raises explicitly."""
    with open(SKILL_MD, encoding="utf-8") as f:
        text = f.read()
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        raise AssertionError("SKILL.md must open with a '---' frontmatter fence")
    for i in range(1, len(lines)):
        if lines[i].strip() == "---":
            return "\n".join(lines[1:i])
    raise AssertionError("SKILL.md frontmatter has no closing '---' fence")


def _stdlib_scalar(block, key):
    """Extract a single-line scalar `key: value` from the frontmatter WITHOUT a
    YAML library, unwrapping a surrounding double- or single-quoted scalar. This
    is deliberately minimal — enough to enforce the length + no-unquoted-`: `
    guard on any interpreter, PyYAML or not."""
    prefix = key + ":"
    for line in block.splitlines():
        if line.startswith(prefix):
            value = line[len(prefix):].strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            return value
    return None


def test_frontmatter_stdlib_description_valid_and_bounded():
    """ALWAYS-ON (no PyYAML needed): `name` present, `description` present and
    <= 1024 chars, and — the DF-R4-01 root cause — an UNQUOTED description must
    not contain a ` : ` (space-colon-space) that a YAML parser would read as a
    nested mapping. A quoted description is exempt (the quotes make ` : ` a
    literal), which is the fix we shipped."""
    block = _read_frontmatter_block()

    name = _stdlib_scalar(block, "name")
    if not name:
        raise AssertionError("SKILL.md frontmatter is missing a non-empty `name`")

    # Locate the raw (still-quoted-or-not) description line to know if it is
    # quoted before applying the unquoted-`: ` rule.
    raw_desc_line = None
    for line in block.splitlines():
        if line.startswith("description:"):
            raw_desc_line = line[len("description:"):].strip()
            break
    if raw_desc_line is None:
        raise AssertionError("SKILL.md frontmatter is missing a `description`")

    quoted = (len(raw_desc_line) >= 2 and raw_desc_line[0] == raw_desc_line[-1]
              and raw_desc_line[0] in "\"'")
    description = _stdlib_scalar(block, "description")
    if not description:
        raise AssertionError("SKILL.md `description` is empty")

    if len(description) > DESCRIPTION_MAX:
        raise AssertionError(
            f"SKILL.md description is {len(description)} chars — exceeds the "
            f"{DESCRIPTION_MAX}-char skill-creator limit (DF-R4-01)")

    if not quoted and " : " in raw_desc_line:
        raise AssertionError(
            "SKILL.md description is an UNQUOTED scalar containing ' : ' — a YAML "
            "parser reads that as a nested mapping and fails to load the skill "
            "(DF-R4-01). Quote the description or remove the ' : '.")


def test_frontmatter_parses_as_yaml_mapping():
    """When PyYAML is installed (CI), enforce the STRONGEST guarantee: the
    frontmatter parses as a real YAML MAPPING with a `name` and a `description`,
    and the description honours the 1024-char cap. Skipped (never failed) when
    PyYAML is absent — the stdlib test above still holds the line."""
    yaml = pytest.importorskip("yaml")
    block = _read_frontmatter_block()
    data = yaml.safe_load(block)
    if not isinstance(data, dict):
        raise AssertionError(
            f"SKILL.md frontmatter did not parse as a YAML mapping: {type(data)!r}")
    if not data.get("name"):
        raise AssertionError("parsed frontmatter has no `name`")
    description = data.get("description")
    if not isinstance(description, str) or not description:
        raise AssertionError("parsed frontmatter has no string `description`")
    if len(description) > DESCRIPTION_MAX:
        raise AssertionError(
            f"parsed description is {len(description)} chars > {DESCRIPTION_MAX}")
