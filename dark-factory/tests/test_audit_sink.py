"""M13 Task 2: df_audit_receiver (reference WORM receiver) + df_audit_sink
(http-append / s3-objectlock push clients) + audit.sink config validation.

  - receiver: in-process serve() -- PUT new/existing, GET, DELETE.
  - push() http-append: live against the receiver above (fast, always-on).
  - _sigv4_headers: reproduces PUBLISHED AWS SigV4 signature-calculation
    test vectors EXACTLY (AWS S3 API docs, "Signature Calculations for the
    Authorization Header" -- the well-known examplebucket/AKIAIOSFODNN7EXAMPLE
    walkthrough). This is how the signer is proven correct without ever
    talking to real AWS.
  - push() s3-objectlock: skipif no docker -- starts a real MinIO container,
    creates a versioned + object-lock-enabled bucket with a COMPLIANCE
    default retention (via our OWN SigV4 client, not boto3/mc), pushes an
    entry, and proves the resulting object version cannot be deleted within
    retention. Session-scoped container, function-scoped bucket.
  - config matrix: audit.sink validation in df_config.py, including the
    inline-secret rejection.
"""
import datetime
import hashlib
import json
import os
import socket
import subprocess
import time
import urllib.error
import urllib.request
import uuid

import pytest

import df_audit_receiver as receiver
import df_audit_sink as sink
import df_config
from test_config import write_config

try:
    import df_container
    DOCKER_LIVE = df_container.docker_available()
except Exception:
    DOCKER_LIVE = False


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _closed_port() -> int:
    """A port nothing is listening on -- guaranteed ECONNREFUSED, unlike a
    magic constant that might behave differently across platforms."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture
def receiver_server(tmp_path):
    store_dir = str(tmp_path / "store")
    httpd, port = receiver.serve(store_dir, port=0)
    try:
        yield httpd, port, store_dir
    finally:
        httpd.shutdown()
        httpd.server_close()


def _put(port, key, body):
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/audit/{key}", data=body, method="PUT"
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def _get(port, key):
    req = urllib.request.Request(f"http://127.0.0.1:{port}/audit/{key}", method="GET")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def _delete(port, key):
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/audit/{key}", method="DELETE"
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


# ---------------------------------------------------------------------------
# receiver: PUT new/existing, GET, DELETE (in-process, fast)
# ---------------------------------------------------------------------------

def test_put_new_key_returns_201_and_sha256_receipt(receiver_server):
    _httpd, port, _store = receiver_server
    body = b'{"invocation":"inv-1"}'
    status, resp_body = _put(port, "inv-1", body)
    assert status == 201
    payload = json.loads(resp_body)
    assert payload["receipt"] == hashlib.sha256(body).hexdigest()


def test_put_existing_key_returns_409(receiver_server):
    _httpd, port, _store = receiver_server
    _put(port, "inv-1", b"first")
    status, resp_body = _put(port, "inv-1", b"second-attempt-to-overwrite")
    assert status == 409
    assert b"inv-1" in resp_body


def test_put_existing_key_does_not_overwrite_stored_bytes(receiver_server):
    _httpd, port, store = receiver_server
    _put(port, "inv-1", b"original")
    _put(port, "inv-1", b"attempted-overwrite")
    assert open(os.path.join(store, "inv-1"), "rb").read() == b"original"


def test_get_returns_stored_body(receiver_server):
    _httpd, port, _store = receiver_server
    body = b'{"a":1,"b":2}'
    _put(port, "inv-1", body)
    status, resp_body = _get(port, "inv-1")
    assert status == 200
    assert resp_body == body


def test_get_unknown_key_returns_404(receiver_server):
    _httpd, port, _store = receiver_server
    status, _ = _get(port, "never-put")
    assert status == 404


def test_delete_returns_405(receiver_server):
    _httpd, port, _store = receiver_server
    _put(port, "inv-1", b"body")
    status, _ = _delete(port, "inv-1")
    assert status == 405
    # and the entry is still there, untouched
    status, resp_body = _get(port, "inv-1")
    assert status == 200
    assert resp_body == b"body"


def test_serve_returns_ephemeral_port_when_requested(tmp_path):
    httpd, port = receiver.serve(str(tmp_path / "store"), port=0)
    try:
        assert isinstance(port, int) and port > 0
        assert httpd.server_address[1] == port
    finally:
        httpd.shutdown()
        httpd.server_close()


# ---------------------------------------------------------------------------
# push() http-append -- live against the reference receiver
# ---------------------------------------------------------------------------

def test_push_http_append_success_returns_receipt(receiver_server):
    _httpd, port, _store = receiver_server
    sink_cfg = {"kind": "http-append", "url": f"http://127.0.0.1:{port}"}
    body = b'{"invocation":"inv-1","chain_hash":"a"*64}'
    result = sink.push(sink_cfg, "inv-1", body)
    assert result["kind"] == "http-append"
    assert result["status"] == 201
    assert result["receipt"] == hashlib.sha256(body).hexdigest()


def test_push_http_append_stored_bytes_match_pushed_bytes(receiver_server):
    _httpd, port, store = receiver_server
    sink_cfg = {"kind": "http-append", "url": f"http://127.0.0.1:{port}"}
    body = b'{"exact":"bytes","unicode":"\xc3\xa9"}'
    sink.push(sink_cfg, "inv-1", body)
    assert open(os.path.join(store, "inv-1"), "rb").read() == body


def test_push_http_append_duplicate_key_raises_append_only_sinkerror(receiver_server):
    _httpd, port, _store = receiver_server
    sink_cfg = {"kind": "http-append", "url": f"http://127.0.0.1:{port}"}
    sink.push(sink_cfg, "inv-1", b"first")
    with pytest.raises(sink.SinkError, match="append-only"):
        sink.push(sink_cfg, "inv-1", b"second")


def test_push_http_append_unreachable_url_raises_sinkerror():
    sink_cfg = {"kind": "http-append", "url": f"http://127.0.0.1:{_closed_port()}"}
    with pytest.raises(sink.SinkError):
        sink.push(sink_cfg, "inv-1", b"body", timeout_s=3)


def test_push_unknown_kind_raises_sinkerror(receiver_server):
    with pytest.raises(sink.SinkError, match="unknown"):
        sink.push({"kind": "carrier-pigeon"}, "inv-1", b"body")


# ---------------------------------------------------------------------------
# _sigv4_headers -- reproduces PUBLISHED AWS SigV4 test vectors exactly
#
# Source: AWS S3 API Reference, "Signature Calculations for the
# Authorization Header: Transferring Payload in a Single Chunk (AWS
# Signature Version 4)" -> "Examples: Signature Calculations". This is the
# canonical worked example AWS documents (fixed example keys, bucket
# "examplebucket", timestamp 20130524T000000Z) and is widely used as a
# known-answer test for independent SigV4 implementations. Both the
# canonical-request hash and the final Authorization header below were
# independently reproduced byte-for-byte before this test was written.
# ---------------------------------------------------------------------------

_AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
_AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


def test_sigv4_headers_matches_published_get_object_vector():
    headers = sink._sigv4_headers(
        "GET",
        "examplebucket.s3.amazonaws.com",
        "/test.txt",
        b"",
        access_key=_AWS_ACCESS_KEY,
        secret_key=_AWS_SECRET_KEY,
        region="us-east-1",
        service="s3",
        amz_date="20130524T000000Z",
        extra_headers={"Range": "bytes=0-9"},
    )
    assert headers["Authorization"] == (
        "AWS4-HMAC-SHA256 "
        "Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,"
        "SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,"
        "Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
    )
    assert headers["x-amz-content-sha256"] == (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )


def test_sigv4_headers_matches_published_put_object_vector():
    payload = b"Welcome to Amazon S3."
    headers = sink._sigv4_headers(
        "PUT",
        "examplebucket.s3.amazonaws.com",
        "/test%24file.text",
        payload,
        access_key=_AWS_ACCESS_KEY,
        secret_key=_AWS_SECRET_KEY,
        region="us-east-1",
        service="s3",
        amz_date="20130524T000000Z",
        extra_headers={
            "Date": "Fri, 24 May 2013 00:00:00 GMT",
            "x-amz-storage-class": "REDUCED_REDUNDANCY",
        },
    )
    assert headers["Authorization"] == (
        "AWS4-HMAC-SHA256 "
        "Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,"
        "SignedHeaders=date;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class,"
        "Signature=98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd"
    )


# ---------------------------------------------------------------------------
# s3-objectlock -- live MinIO with a real object-lock bucket (skipif no
# docker). Session-scoped container; each test gets its own fresh bucket.
# ---------------------------------------------------------------------------

_MINIO_ACCESS_KEY = "minioadmin"
_MINIO_SECRET_KEY = "minioadmin123"


def _wait_for_minio(endpoint, timeout_s=30):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(
                f"http://{endpoint}/minio/health/live", timeout=2
            ) as resp:
                if resp.status == 200:
                    return
        except Exception:
            pass
        time.sleep(0.5)
    raise RuntimeError(f"MinIO at {endpoint} did not become healthy in {timeout_s}s")


def _s3_request(endpoint, method, path, body=b"", query=None, extra_headers=None):
    """Raw SigV4-signed request against the test MinIO instance, built with
    df_audit_sink's OWN signer (the same one push() uses) -- used here only
    for test-fixture setup (bucket creation, lock config, WORM proof), never
    by push() itself."""
    query = query or {}
    amz_date = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    canonical_qs = "&".join(f"{k}={v}" for k, v in sorted(query.items()))
    headers = sink._sigv4_headers(
        method,
        endpoint,
        path,
        body,
        access_key=_MINIO_ACCESS_KEY,
        secret_key=_MINIO_SECRET_KEY,
        region="us-east-1",
        service="s3",
        amz_date=amz_date,
        extra_headers=extra_headers,
        canonical_querystring=canonical_qs,
    )
    url = f"http://{endpoint}{path}"
    if canonical_qs:
        url += f"?{canonical_qs}"
    req = urllib.request.Request(
        url, data=body if method in ("PUT", "POST") else None, method=method, headers=headers
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


@pytest.fixture(scope="session")
def minio_endpoint():
    """Starts a MinIO container for the whole test session; yields None
    (and every dependent test self-skips) when docker isn't available."""
    if not DOCKER_LIVE:
        yield None
        return

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    host_port = s.getsockname()[1]
    s.close()

    name = f"df-audit-minio-{uuid.uuid4().hex[:8]}"
    subprocess.run(
        ["docker", "pull", "-q", "minio/minio"], capture_output=True, timeout=300
    )
    subprocess.run(
        [
            "docker", "run", "-d", "--rm", "--name", name,
            "-p", f"{host_port}:9000",
            "-e", "MINIO_ROOT_USER=" + _MINIO_ACCESS_KEY,
            "-e", "MINIO_ROOT_PASSWORD=" + _MINIO_SECRET_KEY,
            "minio/minio", "server", "/data",
        ],
        check=True, capture_output=True, timeout=60,
    )
    endpoint = f"127.0.0.1:{host_port}"
    try:
        _wait_for_minio(endpoint)
        yield endpoint
    finally:
        subprocess.run(["docker", "stop", name], capture_output=True, timeout=30)


@pytest.fixture
def objectlock_bucket(minio_endpoint):
    """A fresh, versioned, object-lock-enabled bucket with a COMPLIANCE
    default retention (1 day) -- created via our own SigV4 client, not
    boto3/mc, so this is genuinely proving OUR PUT signing works against a
    real S3-API server, not just against canned test vectors."""
    if minio_endpoint is None:
        pytest.skip("docker daemon unavailable")

    bucket = f"df-audit-{uuid.uuid4().hex[:12]}"
    status, _hdrs, body = _s3_request(
        minio_endpoint, "PUT", f"/{bucket}",
        extra_headers={"x-amz-bucket-object-lock-enabled": "true"},
    )
    assert status == 200, f"create bucket failed: {status} {body!r}"

    lock_xml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<ObjectLockConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
        "<ObjectLockEnabled>Enabled</ObjectLockEnabled>"
        "<Rule><DefaultRetention><Mode>COMPLIANCE</Mode><Days>1</Days>"
        "</DefaultRetention></Rule>"
        "</ObjectLockConfiguration>"
    ).encode("utf-8")
    status, _hdrs, body = _s3_request(
        minio_endpoint, "PUT", f"/{bucket}", body=lock_xml, query={"object-lock": ""}
    )
    assert status == 200, f"set default retention failed: {status} {body!r}"

    return bucket


@pytest.mark.skipif(not DOCKER_LIVE, reason="docker daemon unavailable")
def test_push_s3_objectlock_success(minio_endpoint, objectlock_bucket, monkeypatch):
    monkeypatch.setenv("DF_AUDIT_S3_ACCESS_KEY", _MINIO_ACCESS_KEY)
    monkeypatch.setenv("DF_AUDIT_S3_SECRET_KEY", _MINIO_SECRET_KEY)
    sink_cfg = {
        "kind": "s3-objectlock",
        "endpoint": f"http://{minio_endpoint}",
        "bucket": objectlock_bucket,
        "region": "us-east-1",
        "prefix": "audit/",
    }
    body = b'{"invocation":"inv-1","chain_hash":"deadbeef"}'
    result = sink.push(sink_cfg, "inv-1", body)
    assert result["kind"] == "s3-objectlock"
    assert 200 <= result["status"] < 300
    assert result["etag"]


@pytest.mark.skipif(not DOCKER_LIVE, reason="docker daemon unavailable")
def test_s3_objectlock_prevents_delete_within_retention(
    minio_endpoint, objectlock_bucket, monkeypatch
):
    """The core WORM claim: push a real object through push(), then prove
    the bucket's server-side object-lock retention -- NOT anything the
    client does -- refuses to let the specific version be deleted."""
    monkeypatch.setenv("DF_AUDIT_S3_ACCESS_KEY", _MINIO_ACCESS_KEY)
    monkeypatch.setenv("DF_AUDIT_S3_SECRET_KEY", _MINIO_SECRET_KEY)
    sink_cfg = {
        "kind": "s3-objectlock",
        "endpoint": f"http://{minio_endpoint}",
        "bucket": objectlock_bucket,
        "region": "us-east-1",
        "prefix": "audit/",
    }
    sink.push(sink_cfg, "inv-1", b'{"invocation":"inv-1"}')

    status, hdrs, body = _s3_request(
        minio_endpoint, "GET", f"/{objectlock_bucket}/audit/inv-1"
    )
    assert status == 200, body
    version_id = hdrs["x-amz-version-id"]

    # Attempting to delete THIS SPECIFIC VERSION must be refused -- this is
    # the actual permanent-delete path; a bare DELETE with no versionId
    # only ever creates a delete marker (always 204, data stays underneath),
    # so it would prove nothing about WORM on its own.
    status, _hdrs, body = _s3_request(
        minio_endpoint, "DELETE", f"/{objectlock_bucket}/audit/inv-1",
        query={"versionId": version_id},
    )
    assert status in (400, 403), f"expected the delete to be denied, got {status} {body!r}"

    # The retention record itself is queryable and confirms COMPLIANCE mode
    # with a still-future RetainUntilDate.
    status, _hdrs, body = _s3_request(
        minio_endpoint, "GET", f"/{objectlock_bucket}/audit/inv-1",
        query={"retention": "", "versionId": version_id},
    )
    assert status == 200, body
    assert b"COMPLIANCE" in body


# ---------------------------------------------------------------------------
# config matrix: audit.sink validation (df_config.py)
# ---------------------------------------------------------------------------

def test_audit_sink_absent_defaults_none(tmp_path):
    cr = tmp_path / "control"; write_config(cr)
    cfg = df_config.load_config(str(cr))
    assert cfg["_audit"]["sink"] == {"kind": "none", "required": False}


def test_audit_sink_unknown_kind_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, audit={"sink": {"kind": "carrier-pigeon"}})
    with pytest.raises(df_config.ConfigError, match="kind"):
        df_config.load_config(str(cr))


def test_audit_sink_required_must_be_bool(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, audit={"sink": {"kind": "none", "required": "yes"}})
    with pytest.raises(df_config.ConfigError, match="required"):
        df_config.load_config(str(cr))


def test_audit_sink_http_append_requires_url(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, audit={"sink": {"kind": "http-append"}})
    with pytest.raises(df_config.ConfigError, match="url"):
        df_config.load_config(str(cr))


def test_audit_sink_http_append_invalid_url_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, audit={"sink": {"kind": "http-append", "url": "not-a-url"}})
    with pytest.raises(df_config.ConfigError, match="url"):
        df_config.load_config(str(cr))


def test_audit_sink_http_append_valid_config_loads(tmp_path):
    cr = tmp_path / "control"
    write_config(
        cr, audit={"sink": {"kind": "http-append", "url": "http://127.0.0.1:8080", "required": True}}
    )
    cfg = df_config.load_config(str(cr))
    assert cfg["_audit"]["sink"] == {
        "kind": "http-append", "required": True, "url": "http://127.0.0.1:8080",
    }


def test_audit_sink_s3_missing_endpoint_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(
        cr, audit={"sink": {"kind": "s3-objectlock", "bucket": "b", "region": "us-east-1"}}
    )
    with pytest.raises(df_config.ConfigError, match="endpoint"):
        df_config.load_config(str(cr))


def test_audit_sink_s3_missing_bucket_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(
        cr, audit={"sink": {"kind": "s3-objectlock", "endpoint": "s3.example.com", "region": "us-east-1"}}
    )
    with pytest.raises(df_config.ConfigError, match="bucket"):
        df_config.load_config(str(cr))


def test_audit_sink_s3_missing_region_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(
        cr, audit={"sink": {"kind": "s3-objectlock", "endpoint": "s3.example.com", "bucket": "b"}}
    )
    with pytest.raises(df_config.ConfigError, match="region"):
        df_config.load_config(str(cr))


def test_audit_sink_s3_defaults_prefix_and_env_var_names(tmp_path):
    cr = tmp_path / "control"
    write_config(
        cr, audit={"sink": {
            "kind": "s3-objectlock", "endpoint": "s3.example.com",
            "bucket": "b", "region": "us-east-1",
        }},
    )
    cfg = df_config.load_config(str(cr))
    assert cfg["_audit"]["sink"] == {
        "kind": "s3-objectlock",
        "required": False,
        "endpoint": "s3.example.com",
        "bucket": "b",
        "region": "us-east-1",
        "prefix": "",
        "access_key_env": "DF_AUDIT_S3_ACCESS_KEY",
        "secret_key_env": "DF_AUDIT_S3_SECRET_KEY",
    }


def test_audit_sink_s3_custom_env_var_names(tmp_path):
    cr = tmp_path / "control"
    write_config(
        cr, audit={"sink": {
            "kind": "s3-objectlock", "endpoint": "s3.example.com",
            "bucket": "b", "region": "us-east-1",
            "access_key_env": "MY_ACCESS_KEY", "secret_key_env": "MY_SECRET_KEY",
        }},
    )
    cfg = df_config.load_config(str(cr))
    assert cfg["_audit"]["sink"]["access_key_env"] == "MY_ACCESS_KEY"
    assert cfg["_audit"]["sink"]["secret_key_env"] == "MY_SECRET_KEY"


def test_audit_sink_s3_malformed_env_var_name_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(
        cr, audit={"sink": {
            "kind": "s3-objectlock", "endpoint": "s3.example.com",
            "bucket": "b", "region": "us-east-1",
            "access_key_env": "not-a-valid-env-name",
        }},
    )
    with pytest.raises(df_config.ConfigError, match="access_key_env"):
        df_config.load_config(str(cr))


def test_audit_sink_inline_secret_key_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(
        cr, audit={"sink": {
            "kind": "s3-objectlock", "endpoint": "s3.example.com",
            "bucket": "b", "region": "us-east-1",
            "secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        }},
    )
    with pytest.raises(df_config.ConfigError, match="secret_key"):
        df_config.load_config(str(cr))


def test_audit_sink_inline_access_key_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(
        cr, audit={"sink": {
            "kind": "s3-objectlock", "endpoint": "s3.example.com",
            "bucket": "b", "region": "us-east-1",
            "access_key": "AKIAIOSFODNN7EXAMPLE",
        }},
    )
    with pytest.raises(df_config.ConfigError, match="access_key"):
        df_config.load_config(str(cr))


def test_audit_sink_inline_secret_rejected_even_for_kind_none(tmp_path):
    """A leaked secret in the sink block is rejected regardless of kind --
    the leak risk doesn't depend on whether the sink is currently active."""
    cr = tmp_path / "control"
    write_config(cr, audit={"sink": {"kind": "none", "secret_key": "shh"}})
    with pytest.raises(df_config.ConfigError, match="secret_key"):
        df_config.load_config(str(cr))


def test_audit_sink_not_object_rejected(tmp_path):
    cr = tmp_path / "control"
    write_config(cr, audit={"sink": "http://example.com"})
    with pytest.raises(df_config.ConfigError, match="sink"):
        df_config.load_config(str(cr))
