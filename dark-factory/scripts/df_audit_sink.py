"""Off-box append-only audit sink clients (M13 Task 2). Stdlib only --
including the AWS SigV4 signer (hashlib + hmac, no boto3).

``push(sink_cfg, key, body)`` ships one chain entry to a configured WORM
transport:

  http-append    PUT {url}/audit/{key} against a reference df_audit_receiver
                 (or any receiver honoring the same append-only contract):
                 201/200 -> {"kind","status","receipt"}. 409 -> SinkError
                 ("append-only" -- a duplicate key is a protocol violation,
                 not something to retry around). Any other status, or a
                 network failure/timeout, -> SinkError.

  s3-objectlock  PUT https://{endpoint}/{bucket}/{prefix}{key}, SigV4-signed.
                 2xx -> {"kind","status","etag"}. WORM here is NOT enforced
                 by this client -- it's enforced server-side by the bucket's
                 object-lock retention configuration, which the operator
                 sets when provisioning the bucket (see
                 references/audit.md). This client only knows how to sign
                 and PUT; against a bucket that isn't lock-enabled, a second
                 push to the same key would just overwrite it.

Credentials for s3-objectlock are NEVER read from sink_cfg as literal
values -- df_config's audit.sink validation refuses a config file that
carries an inline secret. push() resolves them from environment variables
NAMED by sink_cfg (``access_key_env``/``secret_key_env``, defaulting to
DF_AUDIT_S3_ACCESS_KEY/DF_AUDIT_S3_SECRET_KEY) at call time, and they never
appear in a returned dict, a SinkError message, or a log line.
"""
import datetime
import hashlib
import hmac
import json
import os
import urllib.error
import urllib.parse
import urllib.request

_DEFAULT_ACCESS_KEY_ENV = "DF_AUDIT_S3_ACCESS_KEY"
_DEFAULT_SECRET_KEY_ENV = "DF_AUDIT_S3_SECRET_KEY"


class SinkError(RuntimeError):
    pass


def push(sink_cfg: dict, key: str, body: bytes, *, timeout_s: int = 20) -> dict:
    kind = sink_cfg.get("kind", "none")
    if kind == "http-append":
        return _push_http_append(sink_cfg, key, body, timeout_s=timeout_s)
    if kind == "s3-objectlock":
        return _push_s3_objectlock(sink_cfg, key, body, timeout_s=timeout_s)
    raise SinkError(f"unknown or unpushable sink kind: {kind!r}")


def _push_http_append(sink_cfg: dict, key: str, body: bytes, *, timeout_s: int) -> dict:
    url = sink_cfg["url"].rstrip("/") + f"/audit/{urllib.parse.quote(key, safe='')}"
    req = urllib.request.Request(url, data=body, method="PUT")
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            status = resp.status
            resp_body = resp.read()
    except urllib.error.HTTPError as e:
        if e.code == 409:
            raise SinkError(
                f"sink already has an entry for {key} (append-only)"
            ) from None
        raise SinkError(
            f"http-append sink returned HTTP {e.code} for {key}"
        ) from None
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise SinkError(f"http-append sink unreachable: {e}") from None

    if status not in (200, 201):
        raise SinkError(f"http-append sink returned HTTP {status} for {key}")

    receipt = hashlib.sha256(body).hexdigest()
    try:
        parsed = json.loads(resp_body)
        if isinstance(parsed, dict) and parsed.get("receipt"):
            receipt = parsed["receipt"]
    except (json.JSONDecodeError, UnicodeDecodeError):
        pass  # fall back to the locally computed receipt

    return {"kind": "http-append", "status": status, "receipt": receipt}


def _split_endpoint(endpoint: str):
    """Return (scheme, host) for an s3-objectlock endpoint. A bare host
    defaults to https (the production case); an explicit http:// prefix is
    honored (local/test object stores, e.g. a MinIO container, that don't
    terminate TLS)."""
    if endpoint.startswith("http://") or endpoint.startswith("https://"):
        scheme, _, host = endpoint.partition("://")
        return scheme, host
    return "https", endpoint


def _push_s3_objectlock(sink_cfg: dict, key: str, body: bytes, *, timeout_s: int) -> dict:
    scheme, host = _split_endpoint(sink_cfg["endpoint"])
    bucket = sink_cfg["bucket"]
    region = sink_cfg["region"]
    prefix = sink_cfg.get("prefix", "")

    access_key_env = sink_cfg.get("access_key_env") or _DEFAULT_ACCESS_KEY_ENV
    secret_key_env = sink_cfg.get("secret_key_env") or _DEFAULT_SECRET_KEY_ENV
    access_key = os.environ.get(access_key_env)
    secret_key = os.environ.get(secret_key_env)
    if not access_key or not secret_key:
        raise SinkError(
            "s3-objectlock sink credentials missing: environment variables "
            f"{access_key_env!r} and {secret_key_env!r} must both be set"
        )

    object_path = f"{bucket}/{prefix}{key}"
    canonical_uri = "/" + "/".join(
        urllib.parse.quote(part, safe="-_.~") for part in object_path.split("/")
    )
    amz_date = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    headers = _sigv4_headers(
        "PUT",
        host,
        canonical_uri,
        body,
        access_key=access_key,
        secret_key=secret_key,
        region=region,
        service="s3",
        amz_date=amz_date,
    )

    url = f"{scheme}://{host}{canonical_uri}"
    req = urllib.request.Request(url, data=body, method="PUT", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            status = resp.status
            etag = resp.headers.get("ETag", "")
    except urllib.error.HTTPError as e:
        raise SinkError(
            f"s3-objectlock sink returned HTTP {e.code} for {key}"
        ) from None
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise SinkError(f"s3-objectlock sink unreachable: {e}") from None

    if not (200 <= status < 300):
        raise SinkError(f"s3-objectlock sink returned HTTP {status} for {key}")

    return {"kind": "s3-objectlock", "status": status, "etag": etag}


def _sigv4_headers(
    method: str,
    host: str,
    canonical_uri: str,
    payload: bytes,
    *,
    access_key: str,
    secret_key: str,
    region: str,
    service: str,
    amz_date: str,
    extra_headers: dict | None = None,
    canonical_querystring: str = "",
) -> dict:
    """Stdlib AWS Signature Version 4 (hashlib + hmac only -- no boto3).

    ``canonical_uri`` must already be percent-encoded (callers building it
    from arbitrary path segments should quote each segment, leaving '/' as
    the separator). ``amz_date`` is an ISO-8601 basic UTC timestamp
    (``YYYYMMDDTHHMMSSZ``); its first 8 characters become the credential
    scope's date. Returns the full header dict to attach to the HTTP
    request -- ``host``, ``x-amz-date``, ``x-amz-content-sha256``, any
    ``extra_headers`` (lower-cased), and ``Authorization``.

    Verified against the published AWS "Example: GET Object" and
    "Example: PUT Object" signature-calculation walkthroughs (AWS S3 API
    docs, "Signature Calculations for the Authorization Header" -- fixed
    access/secret example keys, bucket ``examplebucket``, timestamp
    ``20130524T000000Z``); see test_audit_sink.py for the pinned vectors.
    """
    extra_headers = extra_headers or {}
    payload_hash = hashlib.sha256(payload).hexdigest()

    headers = {
        "host": host,
        "x-amz-content-sha256": payload_hash,
        "x-amz-date": amz_date,
    }
    headers.update({k.lower(): v for k, v in extra_headers.items()})

    signed_header_names = sorted(headers)
    canonical_headers = "".join(f"{k}:{headers[k]}\n" for k in signed_header_names)
    signed_headers = ";".join(signed_header_names)

    canonical_request = "\n".join(
        [
            method,
            canonical_uri,
            canonical_querystring,
            canonical_headers,
            signed_headers,
            payload_hash,
        ]
    )
    canonical_request_hash = hashlib.sha256(
        canonical_request.encode("utf-8")
    ).hexdigest()

    date_stamp = amz_date[:8]
    credential_scope = f"{date_stamp}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join(
        ["AWS4-HMAC-SHA256", amz_date, credential_scope, canonical_request_hash]
    )

    def _hmac(key: bytes, msg: str) -> bytes:
        return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

    k_date = _hmac(("AWS4" + secret_key).encode("utf-8"), date_stamp)
    k_region = _hmac(k_date, region)
    k_service = _hmac(k_region, service)
    k_signing = _hmac(k_service, "aws4_request")

    signature = hmac.new(
        k_signing, string_to_sign.encode("utf-8"), hashlib.sha256
    ).hexdigest()

    authorization = (
        f"AWS4-HMAC-SHA256 Credential={access_key}/{credential_scope},"
        f"SignedHeaders={signed_headers},Signature={signature}"
    )

    result = dict(headers)
    result["Authorization"] = authorization
    return result
