"""Reference append-only (WORM) audit sink receiver (M13 Task 2). Stdlib only.

    PUT /audit/<key>   body bytes stored under --store-dir/<key>.
                        new key  -> 201 + {"receipt": sha256(body).hexdigest()}
                        known key -> 409 (no overwrite, ever)
    GET /audit/<key>   stored bytes, or 404 if unknown.
    (anything else, including DELETE) -> 405: there is no code path in this
    handler that deletes or replaces a stored entry. That absence IS the
    append-only guarantee -- proven by test_audit_sink.py, not merely
    asserted here.

Runnable standalone:

    python df_audit_receiver.py --port 8080 --store-dir /var/lib/df-audit

`serve(store_dir, port=0) -> (httpd, port)` starts the same server on a
background daemon thread for tests (ephemeral port when port=0). Callers
should call ``httpd.shutdown(); httpd.server_close()`` when done.

Honesty note (see references/audit.md): this receiver demonstrates the
http-append WIRE PROTOCOL -- new-key-only PUT, no delete/overwrite route. It
is not, by itself, a hardened production trust boundary: it has no
authentication, runs unencrypted HTTP, and storing it on the SAME box as the
runner it's auditing means a local attacker who can reach both loses nothing
by attacking the receiver instead of the local chain file. The genuine
off-box guarantee requires this receiver (or the s3-objectlock sink) to live
in a different trust domain -- a separate host/account the runner cannot
otherwise touch.
"""
import argparse
import hashlib
import http.server
import json
import os
import re
import threading

_KEY_RE = re.compile(r"^[A-Za-z0-9._-]{1,200}$")
_PREFIX = "/audit/"


def _key_from_path(path: str):
    """Return the sanitized key for a /audit/<key> path, or None if the path
    doesn't match the route or the key looks unsafe (path traversal, empty,
    slashes, etc.)."""
    if not path.startswith(_PREFIX):
        return None
    key = path[len(_PREFIX):]
    if not key or not _KEY_RE.match(key):
        return None
    return key


class _Handler(http.server.BaseHTTPRequestHandler):
    server_version = "df-audit-receiver/1"
    protocol_version = "HTTP/1.1"

    def _send_json(self, status, obj):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_PUT(self):
        key = _key_from_path(self.path)
        if key is None:
            self._send_json(404, {"error": "not found"})
            return

        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length) if length else b""

        path = os.path.join(self.server.store_dir, key)
        if os.path.exists(path):
            self._send_json(
                409, {"error": f"key already exists (append-only): {key}"}
            )
            return
        try:
            # O_EXCL: even a concurrent racing PUT to the same key loses to
            # the filesystem, not to a check-then-write TOCTOU gap -- the
            # loser gets FileExistsError, never a silent overwrite.
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            self._send_json(
                409, {"error": f"key already exists (append-only): {key}"}
            )
            return
        with os.fdopen(fd, "wb") as f:
            f.write(body)

        receipt = hashlib.sha256(body).hexdigest()
        self._send_json(201, {"receipt": receipt})

    def do_GET(self):
        key = _key_from_path(self.path)
        if key is None:
            self._send_json(404, {"error": "not found"})
            return
        path = os.path.join(self.server.store_dir, key)
        if not os.path.isfile(path):
            self._send_json(404, {"error": "not found"})
            return
        with open(path, "rb") as f:
            body = f.read()
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_DELETE(self):
        # No delete route, ever -- append-only means append-only. 405, not a
        # soft "not implemented"; this is a deliberate refusal.
        self._send_json(
            405, {"error": "method not allowed (append-only receiver, no delete)"}
        )

    def log_message(self, format, *args):  # noqa: A002 (stdlib signature)
        pass  # keep test/CLI output quiet; nothing here is security-relevant


class _Server(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, addr, store_dir):
        self.store_dir = store_dir
        super().__init__(addr, _Handler)


def serve(store_dir: str, port: int = 0):
    """Start the receiver on a background daemon thread. Returns
    ``(httpd, port)`` -- port is the actual bound port (useful when
    port=0 requests an ephemeral one). Caller owns shutdown:
    ``httpd.shutdown(); httpd.server_close()``."""
    os.makedirs(store_dir, exist_ok=True)
    httpd = _Server(("127.0.0.1", port), store_dir)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd, httpd.server_address[1]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--store-dir", required=True)
    args = ap.parse_args()

    os.makedirs(args.store_dir, exist_ok=True)
    httpd = _Server(("0.0.0.0", args.port), args.store_dir)
    print(
        f"df_audit_receiver: listening on :{args.port}, store={args.store_dir}"
    )
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
