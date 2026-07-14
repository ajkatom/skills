import json
import os
import shutil
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
ADAPTER = os.path.join(HERE, "..", "scripts", "adapters", "codex")
OK = os.path.join(HERE, "fixtures", "fake_cli_ok")
FAIL = os.path.join(HERE, "fixtures", "fake_cli_fail")


def make_req(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir(exist_ok=True)
    pf = tmp_path / "prompt.md"
    pf.write_text("Build greet.py per SPEC.", encoding="utf-8")
    return {"adapter_protocol": "0.1", "role": "builder",
            "workdir": str(ws), "prompt_file": str(pf), "timeout_s": 20}


def invoke(tmp_path, env):
    proc = subprocess.run(
        [ADAPTER], input=json.dumps(make_req(tmp_path)),
        capture_output=True, text=True, timeout=30, env=env,
    )
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


def bindir_with(tmp_path, toolname, target):
    b = tmp_path / "bin"
    b.mkdir(exist_ok=True)
    os.symlink(target, b / toolname)
    os.symlink(shutil.which("python3") or "/usr/bin/python3", b / "python3")
    return b


def test_codex_adapter_error_when_cli_missing(tmp_path):
    env = dict(os.environ, PATH=str(bindir_with(tmp_path, "nothere", OK)))
    resp = invoke(tmp_path, env)
    assert resp["status"] == "error" and "codex" in resp["detail"]


def test_codex_adapter_invokes_codex_exec_and_reports_ok(tmp_path):
    argv_out = tmp_path / "argv.txt"
    b = bindir_with(tmp_path, "codex", OK)
    env = dict(os.environ, PATH=str(b), DF_ARGV_OUT=str(argv_out))
    resp = invoke(tmp_path, env)
    assert resp["status"] == "ok" and resp["adapter_protocol"] == "0.1"
    argv = argv_out.read_text(encoding="utf-8").splitlines()
    assert argv[0] == "exec"
    assert "--skip-git-repo-check" in argv
    assert "Build greet.py per SPEC." in argv  # prompt passed through
    assert not any(a == "-m" for a in argv)  # no model pin


def test_codex_adapter_reports_error_on_nonzero_exit(tmp_path):
    env = dict(os.environ, PATH=str(bindir_with(tmp_path, "codex", FAIL)))
    resp = invoke(tmp_path, env)
    assert resp["status"] == "error" and "boom" in resp["detail"]
