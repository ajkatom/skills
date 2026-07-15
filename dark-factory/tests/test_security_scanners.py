"""Tests for the stdlib security scanners (M9 Task 1).

Pure scanners over a directory: secret_scan, dangerous_scan, sbom.
No network, no randomness, deterministic sorted output.
"""
import json
import os

import df_security

AKIA_SECRET = "AKIAABCDEFGHIJKLMNOP"  # fake AWS access key id, AKIA + 16 caps
PRIVATE_KEY_BODY = "MIIBogIBAAJBAKfake+not+a+real+key+body=="
API_KEY_VALUE = "0123456789abcdef0123"


def _write(root, relpath, content):
    path = os.path.join(root, relpath)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return path


# --- secret_scan -----------------------------------------------------------


def test_secret_scan_finds_all_three_rule_types(tmp_path):
    root = str(tmp_path)
    _write(
        root,
        "secrets.txt",
        "\n".join(
            [
                f"aws_key = {AKIA_SECRET}",
                "-----BEGIN PRIVATE KEY-----",
                PRIVATE_KEY_BODY,
                "-----END PRIVATE KEY-----",
                f'api_key = "{API_KEY_VALUE}"',
            ]
        ),
    )
    findings = df_security.secret_scan(root)

    rules = sorted(f["rule"] for f in findings)
    assert rules == ["aws_access_key", "generic_secret_assignment", "private_key"]
    for f in findings:
        assert set(f.keys()) == {"file", "line", "rule"}
        assert f["file"] == "secrets.txt"
        assert isinstance(f["line"], int)


def test_secret_scan_findings_never_contain_secret_value(tmp_path):
    root = str(tmp_path)
    _write(
        root,
        "secrets.txt",
        "\n".join(
            [
                f"aws_key = {AKIA_SECRET}",
                "-----BEGIN PRIVATE KEY-----",
                PRIVATE_KEY_BODY,
                "-----END PRIVATE KEY-----",
                f'api_key = "{API_KEY_VALUE}"',
            ]
        ),
    )
    findings = df_security.secret_scan(root)
    dumped = json.dumps(findings)

    assert AKIA_SECRET not in dumped
    assert PRIVATE_KEY_BODY not in dumped
    assert API_KEY_VALUE not in dumped


def test_secret_scan_clean_file_returns_empty(tmp_path):
    root = str(tmp_path)
    _write(root, "clean.txt", "just some ordinary text\nwith nothing secret in it\n")
    assert df_security.secret_scan(root) == []


def test_secret_scan_skips_binary_file_without_crashing(tmp_path):
    root = str(tmp_path)
    path = os.path.join(root, "binary.dat")
    with open(path, "wb") as f:
        f.write(b"\x00\x01\x02binarydata" + AKIA_SECRET.encode())
    # Should not raise, and the NUL-containing file must be skipped (no
    # finding extracted from its content).
    findings = df_security.secret_scan(root)
    assert findings == []


def test_secret_scan_skips_git_and_symlinks(tmp_path):
    root = str(tmp_path)
    _write(root, os.path.join(".git", "config"), f"token: {AKIA_SECRET}")
    _write(root, "real.txt", "nothing here")
    target = _write(root, "target_secret.txt", f"aws_key = {AKIA_SECRET}")
    link = os.path.join(root, "link_secret.txt")
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError):
        pass  # symlinks unsupported on this platform/user; skip that part
    findings = df_security.secret_scan(root)
    files_hit = {f["file"] for f in findings}
    assert ".git/config" not in files_hit
    assert "link_secret.txt" not in files_hit
    # the real (non-symlink) file with the secret is still found
    assert "target_secret.txt" in files_hit


def test_secret_scan_sorted_by_file_line_rule(tmp_path):
    root = str(tmp_path)
    _write(root, "b.txt", f"aws_key = {AKIA_SECRET}\n")
    _write(root, "a.txt", f"aws_key = {AKIA_SECRET}\n")
    findings = df_security.secret_scan(root)
    keys = [(f["file"], f["line"], f["rule"]) for f in findings]
    assert keys == sorted(keys)


# --- dangerous_scan ----------------------------------------------------


def test_dangerous_scan_finds_all_five_rule_types(tmp_path):
    root = str(tmp_path)
    _write(
        root,
        "risky.py",
        "\n".join(
            [
                "eval(x)",
                "os.system(cmd)",
                "subprocess.run(c, shell=True)",
                "pickle.loads(d)",
                "yaml.load(s)",
            ]
        ),
    )
    findings = df_security.dangerous_scan(root)
    rules = sorted(f["rule"] for f in findings)
    assert rules == [
        "eval_exec",
        "os_system",
        "pickle_loads",
        "shell_true",
        "yaml_unsafe",
    ]
    for f in findings:
        assert set(f.keys()) == {"file", "line", "rule"}
        assert f["file"] == "risky.py"


def test_dangerous_scan_clean_file_returns_empty(tmp_path):
    root = str(tmp_path)
    _write(root, "clean.py", "def add(a, b):\n    return a + b\n")
    assert df_security.dangerous_scan(root) == []


def test_dangerous_scan_only_scans_py_files(tmp_path):
    root = str(tmp_path)
    _write(root, "not_python.txt", "eval(x)\n")
    assert df_security.dangerous_scan(root) == []


def test_dangerous_scan_sorted(tmp_path):
    root = str(tmp_path)
    _write(root, "b.py", "eval(x)\nos.system(y)\n")
    _write(root, "a.py", "eval(x)\n")
    findings = df_security.dangerous_scan(root)
    keys = [(f["file"], f["line"], f["rule"]) for f in findings]
    assert keys == sorted(keys)


# --- sbom --------------------------------------------------------------


def test_sbom_requirements_txt(tmp_path):
    root = str(tmp_path)
    _write(root, "requirements.txt", "flask==2.0\nrequests\n# comment\n\n")
    result = df_security.sbom(root)

    assert result["declared"]["pip"] == ["flask==2.0", "requests"]
    assert result["unpinned"] == ["requests"]
    assert result["count"] == 2
    assert "npm" not in result["declared"]
    assert "pyproject" not in result["declared"]


def test_sbom_package_json(tmp_path):
    root = str(tmp_path)
    _write(
        root,
        "package.json",
        json.dumps(
            {
                "dependencies": {"left-pad": "1.0.0"},
                "devDependencies": {"eslint": "8.0.0"},
            }
        ),
    )
    result = df_security.sbom(root)

    assert "left-pad==1.0.0" in result["declared"]["npm"] or "left-pad" in "".join(
        result["declared"]["npm"]
    )
    npm_names = {entry.split("==")[0] for entry in result["declared"]["npm"]}
    assert npm_names == {"left-pad", "eslint"}
    assert result["count"] == 2


def test_sbom_empty_dir_returns_empty_inventory(tmp_path):
    root = str(tmp_path)
    result = df_security.sbom(root)
    assert result["declared"] == {}
    assert result["count"] == 0
    assert result["unpinned"] == []


def test_sbom_pyproject_best_effort(tmp_path):
    root = str(tmp_path)
    _write(
        root,
        "pyproject.toml",
        "\n".join(
            [
                "[project]",
                'name = "demo"',
                "dependencies = [",
                '    "click>=8.0",',
                '    "rich",',
                "]",
            ]
        ),
    )
    result = df_security.sbom(root)
    assert "click>=8.0" in result["declared"]["pyproject"]
    assert "rich" in result["declared"]["pyproject"]
