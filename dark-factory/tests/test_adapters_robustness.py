import json, os, subprocess
import pytest
HERE = os.path.dirname(os.path.abspath(__file__))
ADAPTERS = [os.path.join(HERE, "..", "scripts", "adapters", n) for n in ("claude", "codex", "gemini")]

@pytest.mark.parametrize("adapter", ADAPTERS)
def test_adapter_bad_json_is_in_band_error(adapter):
    proc = subprocess.run([adapter], input="not json at all", capture_output=True, text=True, timeout=20)
    assert proc.returncode == 0, proc.stderr
    resp = json.loads(proc.stdout)
    assert resp["adapter_protocol"] == "0.1" and resp["status"] == "error"

@pytest.mark.parametrize("adapter", ADAPTERS)
def test_adapter_missing_prompt_file_is_in_band_error(adapter):
    req = {"adapter_protocol": "0.1", "role": "builder", "workdir": "/tmp", "timeout_s": 5}
    proc = subprocess.run([adapter], input=json.dumps(req), capture_output=True, text=True, timeout=20)
    assert proc.returncode == 0, proc.stderr
    resp = json.loads(proc.stdout)
    assert resp["status"] == "error"
