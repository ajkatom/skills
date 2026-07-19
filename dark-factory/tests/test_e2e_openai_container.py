"""LIVE proof that api_openai runs a real model INSIDE the minimal
hardened-tier container (python:3.12-alpine -- no claude/codex/gemini CLI
installed), against a local stub Chat Completions endpoint -- deterministic,
no paid calls. The api_openai sibling of test_e2e_api_container.py; closes the
"api_openai has no in-container e2e" honest-scope note in references/
role-adapters.md.

Like api_anthropic, api_openai needs nothing but python3 stdlib (urllib), so
it runs to completion inside the plain image where claude/codex/gemini would
fail with "CLI not found on PATH". Only the model's BRAIN is stubbed (a canned
Chat Completions response); every other layer is the real thing and runs live:
the Docker container (built fresh via the SAME `df_container.build_argv` the
hardened tier's `_run_loop` uses, `--network bridge`, caps dropped, read-only
rootfs), the network hop from inside the container to the stub HTTP server on
the host (`host.docker.internal`, the M17 host-service pattern), the real HTTP
POST + response parse, and the path-safe write into the bind-mounted workspace.

`network: bridge` (not hardened's default `none`) is required because
api_openai's entire job is one outbound HTTP call, exactly like api_anthropic.

Also here: `test_api_openai_paid_live_in_container` -- an OPT-IN paid live
in-container run against the REAL OpenAI API, skipped unless
`DF_LIVE_PAID_OPENAI=1` AND `OPENAI_API_KEY` are both set. This is the
"wire up an opt-in paid live in-container test" deliverable: it never runs (and
never costs anything) in a normal suite; when an operator opts in, it proves
the identical container/network/parse/write path works against the real
provider, not only the stub -- the one thing the stub can't prove.
"""
import json
import os
import subprocess
import sys

import pytest

import df_container
from test_openai_adapter import TEST_KEY, _start_stub, _stop_stub

HERE = os.path.dirname(os.path.abspath(__file__))
ADAPTER = os.path.realpath(os.path.join(HERE, "..", "scripts", "adapters", "api_openai"))
IMAGE = "python:3.12-alpine"

DOCKER_LIVE = df_container.docker_available()
# `host.docker.internal` is provided by Docker Desktop (macOS/Windows). Plain
# Linux Docker Engine (e.g. CI runners) does not resolve it until the
# `--add-host=host.docker.internal:host-gateway` wiring lands (the named M16
# deferral in scripts/supervisor.py) -- so the stub-backed tests below skip
# there instead of failing (or vacuously passing on the error path).
HOST_DNS_LIVE = DOCKER_LIVE and sys.platform == "darwin"


@pytest.fixture(scope="module", autouse=True)
def _prepull_image():
    """Pre-pull the image so the live test doesn't absorb a cold download
    inside its own tighter subprocess timeout. No-op when docker is absent."""
    if DOCKER_LIVE:
        subprocess.run(["docker", "pull", "-q", IMAGE], capture_output=True, timeout=600)
    yield


def _run_adapter_in_container(workdir, prompt_file, env, timeout_s=60):
    """Build the exact docker argv supervisor._run_loop builds for a real
    hardened builder call and invoke the adapter INSIDE it the way
    supervisor.invoke_adapter does (`exec_prefix + [adapter]`, protocol-0.1
    request JSON on stdin). `env` is baked in as docker `-e` flags (the sole
    channel any env reaches the hardened builder). Returns the raw
    CompletedProcess so the caller can grep stdout+stderr for the no-key-leak
    assertion."""
    adapter_ro_file = os.path.realpath(ADAPTER)  # RA-07: adapter FILE, not dir
    docker_argv = df_container.build_argv(
        IMAGE, workdir, ro_mounts=[adapter_ro_file], network="bridge", env=env,
    )
    req = {
        "adapter_protocol": "0.1",
        "role": "builder",
        "workdir": workdir,
        "prompt_file": prompt_file,
        "timeout_s": timeout_s,
        "confine": False,
    }
    argv = docker_argv + [ADAPTER]
    return subprocess.run(
        argv, input=json.dumps(req), capture_output=True, text=True,
        timeout=timeout_s + 60,
    )


@pytest.mark.skipif(not HOST_DNS_LIVE,
                    reason="needs docker + host.docker.internal (Docker Desktop; M16)")
def test_api_openai_builds_inside_container_against_stub(tmp_path):
    stub_proc, base_on_host = _start_stub(tmp_path, "greet")
    try:
        workspace = tmp_path / "ws"
        workspace.mkdir()
        ws_real = os.path.realpath(str(workspace))

        prompt_file = workspace / "DARK_FACTORY_PROMPT.md"
        prompt_file.write_text("Build greet.py per SPEC.", encoding="utf-8")

        # Stub is bound to 127.0.0.1 on the HOST; from INSIDE the container it
        # is reached at host.docker.internal:<same port>.
        stub_port = base_on_host.rsplit(":", 1)[-1]
        container_base_url = f"http://host.docker.internal:{stub_port}"

        proc = _run_adapter_in_container(
            ws_real, str(prompt_file),
            env={"OPENAI_BASE_URL": container_base_url, "OPENAI_API_KEY": TEST_KEY},
        )

        assert proc.returncode == 0, proc.stderr
        resp = json.loads(proc.stdout)
        assert resp["adapter_protocol"] == "0.1"
        assert resp["status"] == "ok", resp.get("detail")

        # The model's file output landed in the bind-mounted workspace -- proof
        # the adapter ran to completion INSIDE the container, not on the host.
        greet = workspace / "greet.py"
        assert greet.exists(), (
            "greet.py missing from the mounted workspace -- the in-container "
            "adapter never actually wrote it"
        )
        assert "Hello" in greet.read_text(encoding="utf-8")

        # No key leak on the success path.
        assert TEST_KEY not in proc.stdout
        assert TEST_KEY not in proc.stderr
        for root, _dirs, files in os.walk(ws_real):
            for fn in files:
                content = open(
                    os.path.join(root, fn), encoding="utf-8", errors="replace"
                ).read()
                assert TEST_KEY not in content
    finally:
        _stop_stub(stub_proc)


@pytest.mark.skipif(not HOST_DNS_LIVE,
                    reason="needs docker + host.docker.internal (Docker Desktop; M16)")
def test_api_openai_container_run_key_absent_even_on_adapter_error(tmp_path):
    """Same in-container mechanism, but the stub replies with an unsafe path
    (mode="unsafe") so the adapter reports status:"error" -- the no-key-leak
    guarantee and the all-or-nothing write discipline must both hold inside
    the container on the failure path too, exactly as on the host."""
    stub_proc, base_on_host = _start_stub(tmp_path, "unsafe")
    try:
        workspace = tmp_path / "ws"
        workspace.mkdir()
        ws_real = os.path.realpath(str(workspace))

        prompt_file = workspace / "DARK_FACTORY_PROMPT.md"
        prompt_file.write_text("Build greet.py per SPEC.", encoding="utf-8")

        stub_port = base_on_host.rsplit(":", 1)[-1]
        container_base_url = f"http://host.docker.internal:{stub_port}"

        proc = _run_adapter_in_container(
            ws_real, str(prompt_file),
            env={"OPENAI_BASE_URL": container_base_url, "OPENAI_API_KEY": TEST_KEY},
        )

        assert proc.returncode == 0, proc.stderr
        resp = json.loads(proc.stdout)
        assert resp["status"] == "error"
        assert os.listdir(ws_real) == ["DARK_FACTORY_PROMPT.md"]  # no escape write

        assert TEST_KEY not in proc.stdout
        assert TEST_KEY not in proc.stderr
    finally:
        _stop_stub(stub_proc)


# ---------------------------------------------------------------------------
# OPT-IN paid live run against the REAL OpenAI API. Skipped unless the
# operator explicitly opts in AND supplies a real key -- so it never runs (and
# never costs) in a normal suite. This is the one thing the stub cannot prove:
# that the exact container/network/parse/write path works against the real
# provider. Set DF_LIVE_PAID_OPENAI=1 and OPENAI_API_KEY (optionally
# DF_API_MODEL) to run it.
# ---------------------------------------------------------------------------

_PAID_OPT_IN = os.environ.get("DF_LIVE_PAID_OPENAI") == "1"
_HAS_OPENAI_KEY = bool(os.environ.get("OPENAI_API_KEY"))


@pytest.mark.skipif(
    not (DOCKER_LIVE and _PAID_OPT_IN and _HAS_OPENAI_KEY),
    reason="opt-in paid live test: set DF_LIVE_PAID_OPENAI=1 + OPENAI_API_KEY (and have docker)",
)
def test_api_openai_paid_live_in_container(tmp_path):
    """A REAL, paid api_openai build inside the container against the real
    OpenAI API (no OPENAI_BASE_URL override -> the adapter's default
    https://api.openai.com). Proves the real-provider path end-to-end; costs a
    few tokens, hence opt-in only."""
    real_key = os.environ["OPENAI_API_KEY"]
    workspace = tmp_path / "ws"
    workspace.mkdir()
    ws_real = os.path.realpath(str(workspace))

    prompt_file = workspace / "DARK_FACTORY_PROMPT.md"
    prompt_file.write_text(
        "Build a single Python file greet.py that, run as "
        "`python greet.py <name>`, prints exactly `Hello, <name>!`. "
        "If no argument is given, use World.",
        encoding="utf-8",
    )

    # Pass the real model id through if the operator set one; otherwise the
    # adapter's own default (gpt-4o) applies.
    env = {"OPENAI_API_KEY": real_key}
    if os.environ.get("DF_API_MODEL"):
        env["DF_API_MODEL"] = os.environ["DF_API_MODEL"]

    proc = _run_adapter_in_container(ws_real, str(prompt_file), env=env, timeout_s=120)

    assert proc.returncode == 0, proc.stderr
    resp = json.loads(proc.stdout)
    assert resp["status"] == "ok", resp.get("detail")
    # Real provider usage should be reported (api_openai maps prompt/completion
    # tokens onto input/output_tokens); a real call returns known usage.
    assert resp["usage"]["known"] is True
    assert resp["usage"]["input_tokens"] > 0

    greet = workspace / "greet.py"
    assert greet.exists(), "the real model did not write greet.py into the workspace"

    # The real key never leaks to stdout/stderr or any written file.
    assert real_key not in proc.stdout
    assert real_key not in proc.stderr
    for root, _dirs, files in os.walk(ws_real):
        for fn in files:
            content = open(os.path.join(root, fn), encoding="utf-8", errors="replace").read()
            assert real_key not in content
