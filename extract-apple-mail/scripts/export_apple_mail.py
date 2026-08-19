#!/usr/bin/env python3
"""Export Apple Mail into a private, resumable, wiki-ready local archive."""

from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import email
import hashlib
import html
import json
import mailbox
import os
import platform
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import uuid
from email import policy
from email.message import Message
from email.parser import BytesParser
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple


SCHEMA_VERSION = 1
SCRIPT_DIR = Path(__file__).resolve().parent
SKILL_DIR = SCRIPT_DIR.parent
BRIDGE = SCRIPT_DIR / "apple_mail_bridge.js"
TEMPLATE_DIR = SKILL_DIR / "assets" / "archive-template"
MAIL_APP = Path("/System/Applications/Mail.app")
ARCHIVE_MARKER = Path("state/archive.json")
DB_RELATIVE = Path("state/export.sqlite3")
SYNC_COMPONENTS = {
    "dropbox",
    "onedrive",
    "google drive",
    "mobile documents",
    "icloud drive",
}


class ExportError(RuntimeError):
    """Expected user-facing export error."""


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def run_id(prefix: str) -> str:
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{prefix}-{stamp}-{uuid.uuid4().hex[:8]}"


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def private_dir(path: Path) -> None:
    if path.exists():
        if not path.is_dir():
            raise ExportError(f"Expected directory but found another file type: {path}")
        return
    path.mkdir(parents=True, exist_ok=False)
    os.chmod(path, 0o700)


def private_file(path: Path) -> None:
    os.chmod(path, 0o600)


def atomic_write_bytes(path: Path, data: bytes, *, overwrite: bool = True) -> None:
    private_dir(path.parent)
    if path.exists() and not overwrite:
        raise ExportError(f"Refusing to overwrite immutable file: {path}")
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    temp_path = Path(temp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        private_file(temp_path)
        os.replace(temp_path, path)
        private_file(path)
    finally:
        with contextlib.suppress(FileNotFoundError):
            temp_path.unlink()


def atomic_write_text(path: Path, text: str, *, overwrite: bool = True) -> None:
    atomic_write_bytes(path, text.encode("utf-8"), overwrite=overwrite)


def atomic_write_json(path: Path, value: Any, *, overwrite: bool = True) -> None:
    atomic_write_text(
        path,
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        overwrite=overwrite,
    )


def append_ndjson(path: Path, record: Dict[str, Any]) -> None:
    private_dir(path.parent)
    with path.open("ab") as handle:
        handle.write((canonical_json(record) + "\n").encode("utf-8"))
        handle.flush()
        os.fsync(handle.fileno())
    private_file(path)


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ExportError(f"Could not read JSON {path}: {exc}") from exc


def read_ndjson(path: Path) -> Iterator[Dict[str, Any]]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, 1):
                if not line.strip():
                    continue
                try:
                    value = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ExportError(f"Invalid NDJSON at {path}:{line_number}: {exc}") from exc
                if not isinstance(value, dict):
                    raise ExportError(f"Expected object at {path}:{line_number}")
                yield value
    except OSError as exc:
        raise ExportError(f"Could not read {path}: {exc}") from exc


def nearest_existing(path: Path) -> Path:
    current = path
    while not current.exists() and current != current.parent:
        current = current.parent
    return current


def git_ancestor(path: Path) -> Optional[Path]:
    current = nearest_existing(path.resolve())
    for candidate in (current, *current.parents):
        if (candidate / ".git").exists():
            return candidate
    return None


def destination_risks(archive: Path) -> List[str]:
    resolved = archive.expanduser().resolve()
    risks: List[str] = []
    if resolved == SKILL_DIR or SKILL_DIR in resolved.parents:
        risks.append("destination is inside the skill package")
    git_root = git_ancestor(resolved)
    if git_root is not None:
        risks.append(f"destination is inside Git worktree {git_root}")
    lowered_parts = {part.lower() for part in resolved.parts}
    matched = sorted(lowered_parts.intersection(SYNC_COMPONENTS))
    if matched:
        risks.append(f"destination appears cloud-synced ({', '.join(matched)})")
    return risks


def ensure_safe_destination(archive: Path, allow_unsafe: bool) -> List[str]:
    risks = destination_risks(archive)
    if risks and not allow_unsafe:
        detail = "; ".join(risks)
        raise ExportError(
            f"Unsafe archive destination {archive}: {detail}. "
            "Choose a private non-Git path or explicitly pass --allow-unsafe-destination."
        )
    return risks


def require_archive(archive: Path) -> Dict[str, Any]:
    marker = archive / ARCHIVE_MARKER
    if not marker.is_file():
        raise ExportError(f"Archive is not initialized: {archive}")
    value = read_json(marker)
    if value.get("schema_version") != SCHEMA_VERSION:
        raise ExportError(f"Unsupported archive schema in {marker}")
    return value


def connect_db(archive: Path, *, readonly: bool = False) -> sqlite3.Connection:
    db_path = archive / DB_RELATIVE
    if readonly:
        uri = f"file:{db_path.resolve()}?mode=ro"
        connection = sqlite3.connect(uri, uri=True)
    else:
        connection = sqlite3.connect(str(db_path))
    connection.row_factory = sqlite3.Row
    return connection


def initialize_db(archive: Path) -> None:
    db_path = archive / DB_RELATIVE
    with sqlite3.connect(str(db_path)) as connection:
        connection.executescript(
            """
            PRAGMA journal_mode=WAL;
            PRAGMA foreign_keys=ON;
            CREATE TABLE IF NOT EXISTS snapshots (
                snapshot_id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                record_path TEXT NOT NULL,
                message_count INTEGER NOT NULL,
                attachment_count INTEGER NOT NULL,
                estimated_bytes INTEGER NOT NULL,
                status TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS instances (
                snapshot_id TEXT NOT NULL,
                instance_key TEXT NOT NULL,
                sequence INTEGER NOT NULL,
                account_id TEXT NOT NULL,
                mailbox_path TEXT NOT NULL,
                library_id TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                attempts INTEGER NOT NULL DEFAULT 0,
                source_id TEXT,
                error TEXT,
                completed_at TEXT,
                PRIMARY KEY (snapshot_id, instance_key),
                FOREIGN KEY (snapshot_id) REFERENCES snapshots(snapshot_id)
            );
            CREATE TABLE IF NOT EXISTS sources (
                source_id TEXT PRIMARY KEY,
                relative_path TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS runs (
                run_id TEXT PRIMARY KEY,
                snapshot_id TEXT NOT NULL,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                exported_count INTEGER NOT NULL DEFAULT 0,
                failed_count INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL
            );
            """
        )
    private_file(db_path)


def call_bridge(
    operation: str,
    request: Dict[str, Any],
    *,
    timeout: int,
    temp_parent: Optional[Path] = None,
) -> Dict[str, Any]:
    parent = str(temp_parent) if temp_parent else None
    with tempfile.TemporaryDirectory(prefix="apple-mail-bridge-", dir=parent) as temp:
        temp_dir = Path(temp)
        request_path = temp_dir / "request.json"
        result_path = temp_dir / "result.json"
        atomic_write_json(request_path, request)
        command = [
            "/usr/bin/osascript",
            "-l",
            "JavaScript",
            str(BRIDGE),
            operation,
            str(request_path),
            str(result_path),
        ]
        try:
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as exc:
            raise ExportError(f"Apple Mail bridge timed out during {operation}") from exc
        if completed.returncode != 0:
            stderr = completed.stderr.strip() or completed.stdout.strip()
            raise ExportError(f"Apple Mail bridge failed during {operation}: {stderr}")
        if not result_path.is_file():
            raise ExportError(f"Apple Mail bridge produced no result for {operation}")
        value = read_json(result_path)
        if value.get("schema_version") != SCHEMA_VERSION:
            raise ExportError(f"Unsupported bridge result schema for {operation}")
        return value


def copy_template(archive: Path) -> None:
    for source in sorted(TEMPLATE_DIR.rglob("*")):
        relative = source.relative_to(TEMPLATE_DIR)
        destination = archive / relative
        if source.is_dir():
            private_dir(destination)
        elif source.is_file():
            atomic_write_bytes(destination, source.read_bytes(), overwrite=False)


def command_preflight(args: argparse.Namespace) -> int:
    archive = args.archive.expanduser().resolve()
    risks = ensure_safe_destination(archive, args.allow_unsafe_destination)
    errors: List[str] = []
    if platform.system() != "Darwin":
        errors.append("Apple Mail extraction requires macOS")
    if sys.version_info < (3, 9):
        errors.append("Python 3.9 or newer is required")
    if not MAIL_APP.exists():
        errors.append(f"Mail app not found at {MAIL_APP}")
    if not Path("/usr/bin/osascript").exists():
        errors.append("/usr/bin/osascript is unavailable")
    if not BRIDGE.is_file():
        errors.append(f"Bridge script is missing: {BRIDGE}")

    disk_parent = nearest_existing(archive.parent)
    disk = shutil.disk_usage(disk_parent)
    mail_result: Optional[Dict[str, Any]] = None
    if not errors:
        try:
            mail_result = call_bridge("preflight", {"schema_version": 1}, timeout=args.timeout)
        except ExportError as exc:
            errors.append(str(exc))
    report = {
        "schema_version": SCHEMA_VERSION,
        "checked_at": utc_now(),
        "status": "ok" if not errors else "failed",
        "archive": str(archive),
        "destination_risks": risks,
        "free_bytes": disk.free,
        "python": platform.python_version(),
        "macos": platform.mac_ver()[0],
        "mail": mail_result,
        "disclosure": "Mail may download uncached messages or attachments during export.",
        "errors": errors,
    }
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0 if not errors else 1


def command_inventory(args: argparse.Namespace) -> int:
    archive = args.archive.expanduser().resolve()
    ensure_safe_destination(archive, args.allow_unsafe_destination)
    result = call_bridge("inventory", {"schema_version": 1}, timeout=args.timeout)
    output = args.output.expanduser().resolve()
    atomic_write_json(output, result)
    summary = {
        "status": "ok",
        "output": str(output),
        "mailbox_count": len(result.get("mailboxes", [])),
        "message_count_sum": sum(int(m.get("message_count", 0)) for m in result.get("mailboxes", [])),
        "note": "Parent and smart/view mailboxes can overlap; selection preserves instances.",
    }
    print(json.dumps(summary, indent=2))
    return 0


def command_init_archive(args: argparse.Namespace) -> int:
    archive = args.archive.expanduser().resolve()
    risks = ensure_safe_destination(archive, args.allow_unsafe_destination)
    if not args.yes:
        raise ExportError("Refusing to initialize without explicit --yes")
    marker = archive / ARCHIVE_MARKER
    if marker.exists():
        require_archive(archive)
        print(json.dumps({"status": "already_initialized", "archive": str(archive)}, indent=2))
        return 0
    if archive.exists() and any(archive.iterdir()):
        raise ExportError(f"Refusing to initialize non-empty directory: {archive}")

    private_dir(archive)
    for relative in (
        "raw/email",
        "wiki",
        "manifests/selections",
        "manifests/snapshots",
        "state/staging",
        "reports",
    ):
        private_dir(archive / relative)
    copy_template(archive)
    marker_value = {
        "schema_version": SCHEMA_VERSION,
        "created_at": utc_now(),
        "archive_id": uuid.uuid4().hex,
        "destination_risks_accepted": risks,
    }
    atomic_write_json(marker, marker_value, overwrite=False)
    initialize_db(archive)
    print(json.dumps({"status": "initialized", "archive": str(archive)}, indent=2))
    return 0


def mailbox_selector(account_id: str, path: Sequence[str]) -> str:
    return str(account_id) + "\x1f" + "\x1f".join(str(part) for part in path)


def validate_selection(inventory: Dict[str, Any], selection: Dict[str, Any]) -> Dict[str, Any]:
    if inventory.get("schema_version") != SCHEMA_VERSION:
        raise ExportError("Inventory schema is unsupported")
    if selection.get("schema_version") != SCHEMA_VERSION:
        raise ExportError("Selection schema is unsupported")
    known = {record.get("selector") for record in inventory.get("mailboxes", [])}
    if selection.get("all") is True:
        return {"schema_version": 1, "all": True}
    selected = selection.get("mailboxes")
    if not isinstance(selected, list) or not selected:
        raise ExportError("Selection must contain all=true or a non-empty mailboxes list")
    normalized = []
    for record in selected:
        account_id = record.get("account_id")
        path = record.get("path")
        if not isinstance(account_id, str) or not isinstance(path, list) or not all(
            isinstance(part, str) for part in path
        ):
            raise ExportError("Each selected mailbox needs account_id and a string path list")
        selector = mailbox_selector(account_id, path)
        if selector not in known:
            raise ExportError(f"Selected mailbox is not in inventory: {account_id} / {'/'.join(path)}")
        normalized.append({"account_id": account_id, "path": path})
    return {"schema_version": 1, "mailboxes": normalized}


def instance_key(snapshot_id: str, record: Dict[str, Any]) -> str:
    material = [
        snapshot_id,
        record.get("account_id"),
        record.get("mailbox_path"),
        record.get("message", {}).get("library_id"),
        record.get("sequence"),
    ]
    return sha256_bytes(canonical_json(material).encode("utf-8"))


def command_snapshot(args: argparse.Namespace) -> int:
    archive = args.archive.expanduser().resolve()
    require_archive(archive)
    inventory = read_json(args.inventory.expanduser().resolve())
    selection = validate_selection(inventory, read_json(args.selection.expanduser().resolve()))
    snapshot_id = run_id("snapshot")
    staging_records = archive / "state" / "staging" / f"{snapshot_id}.bridge.ndjson"
    atomic_write_text(staging_records, "")
    request = {
        "schema_version": SCHEMA_VERSION,
        "snapshot_id": snapshot_id,
        "selection": selection,
        "records_path": str(staging_records),
    }
    bridge_result = call_bridge(
        "snapshot",
        request,
        timeout=args.timeout,
        temp_parent=archive / "state" / "staging",
    )
    final_path = archive / "manifests" / "snapshots" / f"{snapshot_id}.ndjson"
    fd, temp_name = tempfile.mkstemp(prefix=f".{snapshot_id}.", dir=str(final_path.parent))
    os.close(fd)
    temp_path = Path(temp_name)
    rows: List[Tuple[Any, ...]] = []
    actual_count = 0
    try:
        with temp_path.open("w", encoding="utf-8", newline="\n") as handle:
            for record in read_ndjson(staging_records):
                key = instance_key(snapshot_id, record)
                record["instance_key"] = key
                handle.write(canonical_json(record) + "\n")
                message = record.get("message", {})
                rows.append(
                    (
                        snapshot_id,
                        key,
                        int(record.get("sequence", actual_count + 1)),
                        str(record.get("account_id", "")),
                        canonical_json(record.get("mailbox_path", [])),
                        str(message.get("library_id", "")),
                    )
                )
                actual_count += 1
            handle.flush()
            os.fsync(handle.fileno())
        private_file(temp_path)
        if final_path.exists():
            raise ExportError(f"Snapshot already exists: {final_path}")
        os.replace(temp_path, final_path)
        private_file(final_path)
    finally:
        with contextlib.suppress(FileNotFoundError):
            temp_path.unlink()

    if actual_count != int(bridge_result.get("message_count", -1)):
        raise ExportError("Bridge snapshot count does not match written snapshot records")
    selection_path = archive / "manifests" / "selections" / f"{snapshot_id}.json"
    atomic_write_json(selection_path, selection, overwrite=False)
    atomic_write_json(archive / "manifests" / "mailboxes.json", inventory)

    with connect_db(archive) as connection:
        connection.execute(
            """
            INSERT INTO snapshots
            (snapshot_id, created_at, record_path, message_count, attachment_count,
             estimated_bytes, status)
            VALUES (?, ?, ?, ?, ?, ?, 'pending')
            """,
            (
                snapshot_id,
                utc_now(),
                str(final_path.relative_to(archive)),
                actual_count,
                int(bridge_result.get("mail_attachment_count", 0)),
                int(bridge_result.get("estimated_message_bytes", 0)),
            ),
        )
        connection.executemany(
            """
            INSERT INTO instances
            (snapshot_id, instance_key, sequence, account_id, mailbox_path, library_id)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            rows,
        )
    summary = dict(bridge_result)
    summary["records_path"] = str(final_path)
    summary["selection_path"] = str(selection_path)
    free_bytes = shutil.disk_usage(archive).free
    estimated_bytes = int(bridge_result.get("estimated_message_bytes", 0))
    recommended_free_bytes = estimated_bytes * 2 + 1024 * 1024 * 1024
    summary["free_bytes"] = free_bytes
    summary["recommended_free_bytes"] = recommended_free_bytes
    summary["disk_space_ok"] = free_bytes >= recommended_free_bytes
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0


def decode_header_value(message: Message, name: str) -> str:
    value = message.get(name, "")
    try:
        return str(value)
    except Exception:
        return ""


class _HTMLText(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: List[str] = []
        self.external_images: List[str] = []

    def handle_data(self, data: str) -> None:
        if data.strip():
            self.parts.append(data)

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        if tag.lower() == "img":
            source = dict(attrs).get("src")
            if source and source.lower().startswith(("http://", "https://")):
                self.external_images.append(source)
        if tag.lower() in {"p", "div", "br", "li", "tr", "h1", "h2", "h3", "h4"}:
            self.parts.append("\n")

    def text(self) -> str:
        value = " ".join(self.parts)
        value = re.sub(r"[ \t]+\n", "\n", value)
        value = re.sub(r"\n[ \t]+", "\n", value)
        value = re.sub(r"\n{3,}", "\n\n", value)
        return value.strip()


def safe_filename(name: Optional[str], ordinal: int, mime_type: str) -> str:
    raw = Path((name or "").replace("\\", "/")).name
    raw = re.sub(r"[\x00-\x1f\x7f]", "_", raw)
    raw = re.sub(r"[^A-Za-z0-9._()\- \u0080-\uffff]", "_", raw).strip(" .")
    if not raw:
        extension = {
            "message/rfc822": ".eml",
            "text/plain": ".txt",
            "text/html": ".html",
            "application/pdf": ".pdf",
        }.get(mime_type, ".bin")
        raw = f"attachment{extension}"
    if len(raw) > 140:
        suffix = Path(raw).suffix[:20]
        raw = raw[: 140 - len(suffix)] + suffix
    return f"{ordinal:04d}-{raw}"


def part_bytes(part: Message) -> bytes:
    if part.get_content_type() == "message/rfc822":
        payload = part.get_payload()
        if isinstance(payload, list):
            return b"\n".join(item.as_bytes(policy=policy.default) for item in payload)
    decoded = part.get_payload(decode=True)
    if decoded is not None:
        return decoded
    payload = part.get_payload()
    if isinstance(payload, str):
        charset = part.get_content_charset() or "utf-8"
        return payload.encode(charset, errors="replace")
    return b""


def readable_part(part: Message) -> str:
    try:
        value = part.get_content()
        return value if isinstance(value, str) else str(value)
    except Exception:
        data = part.get_payload(decode=True) or b""
        return data.decode(part.get_content_charset() or "utf-8", errors="replace")


def parse_message(raw: bytes) -> Tuple[Message, str, str, List[str], List[Dict[str, Any]]]:
    message = BytesParser(policy=policy.default).parsebytes(raw)
    plain_parts: List[str] = []
    html_parts: List[str] = []
    external_images: List[str] = []
    attachments: List[Dict[str, Any]] = []
    ordinal = 0

    for part in message.walk():
        content_type = part.get_content_type()
        disposition = part.get_content_disposition()
        filename = part.get_filename()
        file_bearing = bool(filename) or disposition == "attachment" or (
            disposition == "inline"
            and (content_type not in {"text/plain", "text/html"} or bool(part.get("Content-ID")))
        ) or content_type == "message/rfc822"
        if file_bearing:
            ordinal += 1
            payload = part_bytes(part)
            attachments.append(
                {
                    "ordinal": ordinal,
                    "original_filename": filename or "",
                    "safe_filename": safe_filename(filename, ordinal, content_type),
                    "mime_type": content_type,
                    "disposition": disposition or ("inline" if part.get("Content-ID") else "attachment"),
                    "content_id": str(part.get("Content-ID", "")).strip("<>"),
                    "data": payload,
                    "size": len(payload),
                    "sha256": sha256_bytes(payload),
                    "extraction_method": "mime-decode",
                    "mail_attachment_ids": [],
                }
            )
            continue
        if part.is_multipart():
            continue
        if content_type == "text/plain":
            plain_parts.append(readable_part(part))
        elif content_type == "text/html":
            html_value = readable_part(part)
            html_parts.append(html_value)
            parser = _HTMLText()
            with contextlib.suppress(Exception):
                parser.feed(html_value)
                external_images.extend(parser.external_images)

    plain = "\n\n".join(value.strip() for value in plain_parts if value.strip())
    html_body = "\n\n".join(value for value in html_parts if value.strip())
    if not plain and html_body:
        parser = _HTMLText()
        with contextlib.suppress(Exception):
            parser.feed(html_body)
            plain = parser.text()
            external_images.extend(parser.external_images)
    return message, plain, html_body, sorted(set(external_images)), attachments


def normalized_attachment_name(name: str) -> str:
    return Path((name or "").replace("\\", "/")).name.casefold()


def reconcile_mail_attachments(
    mime_attachments: List[Dict[str, Any]],
    mail_attachments: Sequence[Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[str]]:
    all_attachments = list(mime_attachments)
    checks: List[Dict[str, Any]] = []
    errors: List[str] = []
    used: set[int] = set()

    for mail_item in mail_attachments:
        name = normalized_attachment_name(str(mail_item.get("name", "")))
        size = int(mail_item.get("file_size", 0) or 0)
        match: Optional[int] = None
        for index, candidate in enumerate(all_attachments):
            if index in used:
                continue
            candidate_name = normalized_attachment_name(candidate.get("original_filename", ""))
            candidate_size = int(candidate.get("size", 0) or 0)
            if name and candidate_name == name and not (size > 0 and candidate_size == 0):
                match = index
                break
            if not name and size == int(candidate.get("size", -1)):
                match = index
                break
        if match is not None:
            used.add(match)
            identifier = str(mail_item.get("mail_attachment_id", ""))
            if identifier:
                all_attachments[match]["mail_attachment_ids"].append(identifier)
            checks.append(
                {
                    "mail_attachment_id": identifier,
                    "name": mail_item.get("name", ""),
                    "status": "matched-mime",
                    "attachment_ordinal": all_attachments[match]["ordinal"],
                    "downloaded": bool(mail_item.get("downloaded", False)),
                    "save_error": mail_item.get("save_error"),
                }
            )
            continue

        saved_path_value = mail_item.get("saved_path")
        saved_path = Path(saved_path_value) if saved_path_value else None
        if saved_path and saved_path.is_file():
            data = saved_path.read_bytes()
            ordinal = len(all_attachments) + 1
            content_type = str(mail_item.get("mime_type") or "application/octet-stream")
            item = {
                "ordinal": ordinal,
                "original_filename": str(mail_item.get("name", "")),
                "safe_filename": safe_filename(str(mail_item.get("name", "")), ordinal, content_type),
                "mime_type": content_type,
                "disposition": "attachment",
                "content_id": "",
                "data": data,
                "size": len(data),
                "sha256": sha256_bytes(data),
                "extraction_method": "mail-save",
                "mail_attachment_ids": [str(mail_item.get("mail_attachment_id", ""))],
            }
            all_attachments.append(item)
            checks.append(
                {
                    "mail_attachment_id": mail_item.get("mail_attachment_id", ""),
                    "name": mail_item.get("name", ""),
                    "status": "extracted-mail-save",
                    "attachment_ordinal": ordinal,
                    "downloaded": bool(mail_item.get("downloaded", False)),
                    "save_error": mail_item.get("save_error"),
                }
            )
        else:
            error = (
                f"Mail attachment unavailable: {mail_item.get('name') or '<unnamed>'}; "
                f"{mail_item.get('save_error') or 'no saved payload'}"
            )
            errors.append(error)
            checks.append(
                {
                    "mail_attachment_id": mail_item.get("mail_attachment_id", ""),
                    "name": mail_item.get("name", ""),
                    "status": "missing",
                    "downloaded": bool(mail_item.get("downloaded", False)),
                    "save_error": mail_item.get("save_error"),
                }
            )
    return all_attachments, checks, errors


def markdown_source(message: Message, body: str, attachments: Sequence[Dict[str, Any]]) -> str:
    subject = decode_header_value(message, "Subject") or "(no subject)"
    lines = [
        f"# {subject}",
        "",
        f"- **Message-ID:** {decode_header_value(message, 'Message-ID')}",
        f"- **Date:** {decode_header_value(message, 'Date')}",
        f"- **From:** {decode_header_value(message, 'From')}",
        f"- **To:** {decode_header_value(message, 'To')}",
        f"- **Cc:** {decode_header_value(message, 'Cc')}",
        "",
        "## Body",
        "",
        body or "_No readable text body was extracted. Consult `message.eml`._",
        "",
        "## Attachments",
        "",
    ]
    if attachments:
        for item in attachments:
            label = item.get("original_filename") or item["safe_filename"]
            lines.append(f"- [{label}](attachments/{item['safe_filename']})")
    else:
        lines.append("_None._")
    lines.extend(
        [
            "",
            "## Mailbox memberships",
            "",
            "Filter `../../../../manifests/message-instances.ndjson` by this source's "
            "`source_id`; memberships remain instance-level so identical messages can be "
            "deduplicated without losing mailbox provenance.",
            "",
            "## Provenance",
            "",
            "This is a deterministic view of `message.eml`, not an LLM summary.",
            "",
        ]
    )
    return "\n".join(lines)


def relative_source_dir(source_id: str) -> Path:
    return Path("raw") / "email" / source_id[:2] / source_id


def verify_existing_source(archive: Path, source_id: str) -> Dict[str, Any]:
    directory = archive / relative_source_dir(source_id)
    raw_path = directory / "message.eml"
    metadata_path = directory / "metadata.json"
    if not raw_path.is_file() or not metadata_path.is_file():
        raise ExportError(f"Existing source is incomplete: {directory}")
    if sha256_file(raw_path) != source_id:
        raise ExportError(f"Existing immutable source hash mismatch: {raw_path}")
    metadata = read_json(metadata_path)
    if metadata.get("source_id") != source_id:
        raise ExportError(f"Existing source metadata mismatch: {metadata_path}")
    for item in metadata.get("attachments", []):
        path = directory / item["relative_path"]
        if not path.is_file() or sha256_file(path) != item.get("sha256"):
            raise ExportError(f"Existing attachment mismatch: {path}")
    return metadata


def ingest_raw_message(
    archive: Path,
    raw: bytes,
    mail_attachments: Sequence[Dict[str, Any]],
) -> Tuple[str, Dict[str, Any], bool]:
    source_id = sha256_bytes(raw)
    final_dir = archive / relative_source_dir(source_id)
    if final_dir.exists():
        metadata = verify_existing_source(archive, source_id)
        _, checks, errors = reconcile_mail_attachments(
            [dict(item, data=b"") for item in metadata.get("attachments", [])],
            mail_attachments,
        )
        unexpected_fallbacks = [
            check for check in checks if check.get("status") == "extracted-mail-save"
        ]
        if unexpected_fallbacks:
            errors.append(
                "Existing immutable source does not contain every currently declared Mail attachment"
            )
        if errors:
            raise ExportError("; ".join(errors))
        return source_id, metadata, False

    message, body, html_body, external_images, mime_attachments = parse_message(raw)
    attachments, mail_checks, attachment_errors = reconcile_mail_attachments(
        mime_attachments, mail_attachments
    )
    if attachment_errors:
        raise ExportError("; ".join(attachment_errors))

    private_dir(final_dir.parent)
    finalize_staging = archive / "state" / "staging" / "finalize"
    private_dir(finalize_staging)
    temp_dir = finalize_staging / f"{source_id}-{uuid.uuid4().hex}"
    private_dir(temp_dir)
    try:
        atomic_write_bytes(temp_dir / "message.eml", raw, overwrite=False)
        attachment_dir = temp_dir / "attachments"
        private_dir(attachment_dir)
        serializable_attachments: List[Dict[str, Any]] = []
        for item in attachments:
            data = item.pop("data")
            target = attachment_dir / item["safe_filename"]
            atomic_write_bytes(target, data, overwrite=False)
            serialized = dict(item)
            serialized["relative_path"] = f"attachments/{item['safe_filename']}"
            serializable_attachments.append(serialized)

        encrypted = False
        for part in message.walk():
            content_type = part.get_content_type()
            if content_type == "multipart/encrypted":
                encrypted = True
            elif content_type in {"application/pkcs7-mime", "application/x-pkcs7-mime"}:
                if str(part.get_param("smime-type") or "").lower() != "signed-data":
                    encrypted = True
        metadata = {
            "schema_version": SCHEMA_VERSION,
            "source_id": source_id,
            "message_sha256": source_id,
            "message_size": len(raw),
            "subject": decode_header_value(message, "Subject"),
            "from": decode_header_value(message, "From"),
            "to": decode_header_value(message, "To"),
            "cc": decode_header_value(message, "Cc"),
            "bcc": decode_header_value(message, "Bcc"),
            "date": decode_header_value(message, "Date"),
            "message_id": decode_header_value(message, "Message-ID"),
            "top_level_mime_type": message.get_content_type(),
            "encrypted": encrypted,
            "parser_defects": [type(defect).__name__ for defect in message.defects],
            "body": {
                "preferred": "text/plain" if body else ("text/html-derived" if html_body else "none"),
                "plain_character_count": len(body),
                "html_character_count": len(html_body),
            },
            "external_image_urls": external_images,
            "attachments": serializable_attachments,
            "mail_attachment_checks": mail_checks,
            "created_at": utc_now(),
        }
        atomic_write_json(temp_dir / "metadata.json", metadata, overwrite=False)
        atomic_write_text(
            temp_dir / "source.md",
            markdown_source(message, body, serializable_attachments),
            overwrite=False,
        )
        if final_dir.exists():
            raise ExportError(f"Source appeared concurrently: {final_dir}")
        os.rename(temp_dir, final_dir)
        os.chmod(final_dir, 0o700)
        return source_id, metadata, True
    except Exception as exc:
        raise ExportError(f"{exc}; preserved finalize staging at {temp_dir}") from exc


def snapshot_path(archive: Path, snapshot_id: str) -> Path:
    path = archive / "manifests" / "snapshots" / f"{snapshot_id}.ndjson"
    if not path.is_file():
        raise ExportError(f"Snapshot not found: {snapshot_id}")
    return path


def load_snapshot_index(archive: Path, snapshot_id: str) -> Dict[str, Dict[str, Any]]:
    return {record["instance_key"]: record for record in read_ndjson(snapshot_path(archive, snapshot_id))}


def append_source_manifests(
    archive: Path,
    source_id: str,
    metadata: Dict[str, Any],
    *,
    manifest_index: Dict[Tuple[str, int], Dict[str, Any]],
) -> None:
    for attachment in metadata.get("attachments", []):
        key = (source_id, int(attachment["ordinal"]))
        record = {
            "schema_version": SCHEMA_VERSION,
            "source_id": source_id,
            **attachment,
        }
        existing = manifest_index.get(key)
        if existing:
            if existing.get("sha256") != record.get("sha256"):
                raise ExportError(f"Attachment manifest conflicts for {source_id}:{key[1]}")
            continue
        append_ndjson(archive / "manifests" / "attachments.ndjson", record)
        manifest_index[key] = record


def load_attachment_manifest_index(archive: Path) -> Dict[Tuple[str, int], Dict[str, Any]]:
    path = archive / "manifests" / "attachments.ndjson"
    index: Dict[Tuple[str, int], Dict[str, Any]] = {}
    if not path.exists():
        return index
    for record in read_ndjson(path):
        key = (str(record.get("source_id", "")), int(record.get("ordinal", -1)))
        existing = index.get(key)
        if existing and existing.get("sha256") != record.get("sha256"):
            raise ExportError(f"Conflicting attachment manifest entries for {key}")
        index[key] = record
    return index


def load_instance_manifest_index(
    archive: Path, snapshot_id: str
) -> Dict[str, Dict[str, Any]]:
    path = archive / "manifests" / "message-instances.ndjson"
    index: Dict[str, Dict[str, Any]] = {}
    if not path.exists():
        return index
    for record in read_ndjson(path):
        if record.get("snapshot_id") != snapshot_id:
            continue
        key = str(record.get("instance_key", ""))
        existing = index.get(key)
        if existing and existing.get("source_id") != record.get("source_id"):
            raise ExportError(f"Conflicting instance manifest entries for {key}")
        index[key] = record
    return index


def append_instance_manifest(
    archive: Path,
    record: Dict[str, Any],
    manifest_index: Dict[str, Dict[str, Any]],
) -> None:
    key = str(record["instance_key"])
    existing = manifest_index.get(key)
    if existing:
        if existing.get("source_id") != record.get("source_id"):
            raise ExportError(f"Instance manifest conflicts for {key}")
        return
    append_ndjson(archive / "manifests" / "message-instances.ndjson", record)
    manifest_index[key] = record


def export_snapshot(
    archive: Path,
    snapshot_id: str,
    *,
    limit: Optional[int],
    batch_size: int,
    timeout: int,
    cleanup_staging: bool,
) -> Dict[str, Any]:
    require_archive(archive)
    index = load_snapshot_index(archive, snapshot_id)
    with connect_db(archive) as connection:
        row = connection.execute(
            "SELECT * FROM snapshots WHERE snapshot_id = ?", (snapshot_id,)
        ).fetchone()
        if row is None:
            raise ExportError(f"Snapshot is not registered: {snapshot_id}")
        pending = connection.execute(
            """
            SELECT instance_key FROM instances
            WHERE snapshot_id = ? AND status != 'complete'
            ORDER BY sequence
            """,
            (snapshot_id,),
        ).fetchall()
    keys = [row["instance_key"] for row in pending]
    if limit is not None:
        keys = keys[:limit]

    current_run = run_id("export")
    started = utc_now()
    with connect_db(archive) as connection:
        connection.execute(
            "INSERT INTO runs (run_id, snapshot_id, started_at, status) VALUES (?, ?, ?, 'running')",
            (current_run, snapshot_id, started),
        )
    run_stage = archive / "state" / "staging" / current_run
    private_dir(run_stage)
    exported_count = 0
    failed_count = 0
    failures: List[Dict[str, str]] = []
    attachment_manifest_index = load_attachment_manifest_index(archive)
    instance_manifest_index = load_instance_manifest_index(archive, snapshot_id)

    for offset in range(0, len(keys), batch_size):
        batch_keys = keys[offset : offset + batch_size]
        batch_dir = run_stage / f"batch-{offset // batch_size + 1:06d}"
        private_dir(batch_dir)
        request_items = []
        for key in batch_keys:
            record = index[key]
            item_dir = batch_dir / key
            private_dir(item_dir)
            saved_dir = item_dir / "mail-attachments"
            private_dir(saved_dir)
            expected_count = len(record.get("message", {}).get("attachments", []))
            attachment_targets = []
            for attachment_index in range(expected_count):
                target = saved_dir / f"{attachment_index + 1:04d}.bin"
                attachment_targets.append(str(target))
            request_items.append(
                {
                    "instance_key": key,
                    "mailbox_selector": record["mailbox_selector"],
                    "library_id": record["message"]["library_id"],
                    "source_path": str(item_dir / "message.eml"),
                    "attachment_targets": attachment_targets,
                }
            )
        result = call_bridge(
            "export",
            {"schema_version": 1, "items": request_items},
            timeout=timeout,
            temp_parent=archive / "state" / "staging",
        )
        by_key = {entry.get("instance_key"): entry for entry in result.get("results", [])}

        for key in batch_keys:
            snapshot_record = index[key]
            entry = by_key.get(key)
            error: Optional[str] = None
            try:
                if not entry or entry.get("status") != "exported":
                    raise ExportError((entry or {}).get("error", "bridge_result_missing"))
                source_path_value = entry.get("source_path")
                if not source_path_value:
                    raise ExportError("bridge source path missing")
                source_path_value = Path(source_path_value)
                if not source_path_value.is_file():
                    raise ExportError("bridge source file missing")
                raw = source_path_value.read_bytes()
                source_id, metadata, _ = ingest_raw_message(
                    archive, raw, entry.get("mail_attachments", [])
                )
                if metadata.get("encrypted") and not metadata.get("attachments"):
                    raise ExportError(
                        "Encrypted source was preserved, but attachment completeness "
                        "cannot be proven without an exposed decrypted attachment"
                    )
                append_source_manifests(
                    archive,
                    source_id,
                    metadata,
                    manifest_index=attachment_manifest_index,
                )
                instance_record = {
                    "schema_version": SCHEMA_VERSION,
                    "snapshot_id": snapshot_id,
                    "instance_key": key,
                    "sequence": snapshot_record.get("sequence"),
                    "account_id": snapshot_record.get("account_id"),
                    "account_name": snapshot_record.get("account_name"),
                    "mailbox_path": snapshot_record.get("mailbox_path"),
                    "library_id": snapshot_record.get("message", {}).get("library_id"),
                    "source_id": source_id,
                    "exported_at": utc_now(),
                    "mail_state": entry.get("current_message", {}),
                }
                append_instance_manifest(
                    archive, instance_record, instance_manifest_index
                )
                with connect_db(archive) as connection:
                    connection.execute(
                        """
                        UPDATE instances SET status='complete', attempts=attempts+1,
                        source_id=?, error=NULL, completed_at=?
                        WHERE snapshot_id=? AND instance_key=?
                        """,
                        (source_id, utc_now(), snapshot_id, key),
                    )
                    connection.execute(
                        """
                        INSERT OR IGNORE INTO sources (source_id, relative_path, created_at)
                        VALUES (?, ?, ?)
                        """,
                        (source_id, str(relative_source_dir(source_id)), utc_now()),
                    )
                exported_count += 1
            except Exception as exc:
                error = str(exc)
                failed_count += 1
                failures.append({"instance_key": key, "error": error})
                with connect_db(archive) as connection:
                    connection.execute(
                        """
                        UPDATE instances SET status='failed', attempts=attempts+1, error=?
                        WHERE snapshot_id=? AND instance_key=?
                        """,
                        (error, snapshot_id, key),
                    )
            if cleanup_staging:
                item_dir = batch_dir / key
                if item_dir.is_dir() and run_stage in item_dir.parents:
                    shutil.rmtree(item_dir)

    with connect_db(archive) as connection:
        counts = connection.execute(
            """
            SELECT status, COUNT(*) AS count FROM instances
            WHERE snapshot_id=? GROUP BY status
            """,
            (snapshot_id,),
        ).fetchall()
        status_counts = {row["status"]: row["count"] for row in counts}
        remaining = sum(
            count for status, count in status_counts.items() if status != "complete"
        )
        snapshot_status = "complete" if remaining == 0 else "partial"
        connection.execute(
            "UPDATE snapshots SET status=? WHERE snapshot_id=?",
            (snapshot_status, snapshot_id),
        )
        connection.execute(
            """
            UPDATE runs SET finished_at=?, exported_count=?, failed_count=?, status=?
            WHERE run_id=?
            """,
            (utc_now(), exported_count, failed_count, snapshot_status, current_run),
        )
    report = {
        "schema_version": SCHEMA_VERSION,
        "run_id": current_run,
        "snapshot_id": snapshot_id,
        "started_at": started,
        "finished_at": utc_now(),
        "status": snapshot_status,
        "attempted": len(keys),
        "exported": exported_count,
        "failed": failed_count,
        "snapshot_status_counts": status_counts,
        "failures": failures,
        "staging_path": None if cleanup_staging else str(run_stage),
    }
    atomic_write_json(archive / "reports" / f"{current_run}.json", report, overwrite=False)
    return report


def command_export(args: argparse.Namespace) -> int:
    report = export_snapshot(
        args.archive.expanduser().resolve(),
        args.snapshot,
        limit=args.limit,
        batch_size=args.batch_size,
        timeout=args.timeout,
        cleanup_staging=args.cleanup_staging,
    )
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0 if report["failed"] == 0 else 1


def mbox_files(input_path: Path) -> List[Path]:
    if input_path.is_file():
        return [input_path]
    if not input_path.is_dir():
        raise ExportError(f"Mbox input does not exist: {input_path}")
    candidates = sorted(path for path in input_path.rglob("mbox") if path.is_file())
    if not candidates:
        candidates = sorted(path for path in input_path.rglob("*.mbox") if path.is_file())
    if not candidates:
        raise ExportError(f"No mbox data files found under {input_path}")
    return candidates


def message_summary_from_parsed(message: Message, raw_size: int) -> Dict[str, Any]:
    mime_attachments = []
    for part in message.walk():
        if part.is_multipart():
            continue
        if part.get_filename() or part.get_content_disposition() in {"attachment", "inline"}:
            mime_attachments.append(
                {
                    "name": part.get_filename() or "",
                    "mime_type": part.get_content_type(),
                    "file_size": len(part_bytes(part)),
                    "downloaded": True,
                    "mail_attachment_id": "",
                }
            )
    return {
        "library_id": "",
        "message_id": decode_header_value(message, "Message-ID"),
        "subject": decode_header_value(message, "Subject"),
        "sender": decode_header_value(message, "From"),
        "date_sent": decode_header_value(message, "Date"),
        "date_received": None,
        "message_size": raw_size,
        "attachments": mime_attachments,
    }


def command_import_mbox(args: argparse.Namespace) -> int:
    archive = args.archive.expanduser().resolve()
    require_archive(archive)
    inputs = mbox_files(args.input.expanduser().resolve())
    snapshot_id = run_id("mbox")
    snapshot_file = archive / "manifests" / "snapshots" / f"{snapshot_id}.ndjson"
    records: List[Tuple[Dict[str, Any], bytes]] = []
    sequence = 0
    for mbox_path in inputs:
        box = mailbox.mbox(str(mbox_path), create=False)
        try:
            for key in box.iterkeys():
                raw = box.get_bytes(key, from_=False)
                parsed = BytesParser(policy=policy.default).parsebytes(raw)
                sequence += 1
                relative_box = str(mbox_path.relative_to(args.input.expanduser().resolve())) if args.input.expanduser().resolve().is_dir() else mbox_path.name
                record = {
                    "schema_version": SCHEMA_VERSION,
                    "snapshot_id": snapshot_id,
                    "sequence": sequence,
                    "account_id": "mbox-import",
                    "account_name": "Mbox import",
                    "mailbox_path": [relative_box],
                    "mailbox_selector": mailbox_selector("mbox-import", [relative_box]),
                    "classification": "mbox",
                    "mailbox_ordinal": int(key) + 1 if str(key).isdigit() else sequence,
                    "message": message_summary_from_parsed(parsed, len(raw)),
                }
                record["message"]["library_id"] = f"{relative_box}:{key}"
                record["instance_key"] = instance_key(snapshot_id, record)
                records.append((record, raw))
        finally:
            box.close()

    with snapshot_file.open("w", encoding="utf-8", newline="\n") as handle:
        for record, _ in records:
            handle.write(canonical_json(record) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    private_file(snapshot_file)
    with connect_db(archive) as connection:
        connection.execute(
            """
            INSERT INTO snapshots VALUES (?, ?, ?, ?, ?, ?, 'pending')
            """,
            (
                snapshot_id,
                utc_now(),
                str(snapshot_file.relative_to(archive)),
                len(records),
                sum(len(r["message"]["attachments"]) for r, _ in records),
                sum(len(raw) for _, raw in records),
            ),
        )
        connection.executemany(
            """
            INSERT INTO instances
            (snapshot_id, instance_key, sequence, account_id, mailbox_path, library_id)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    snapshot_id,
                    record["instance_key"],
                    record["sequence"],
                    record["account_id"],
                    canonical_json(record["mailbox_path"]),
                    record["message"]["library_id"],
                )
                for record, _ in records
            ],
        )

    failures: List[Dict[str, str]] = []
    attachment_manifest_index = load_attachment_manifest_index(archive)
    instance_manifest_index = load_instance_manifest_index(archive, snapshot_id)
    for record, raw in records:
        key = record["instance_key"]
        try:
            source_id, metadata, _ = ingest_raw_message(archive, raw, [])
            if metadata.get("encrypted") and not metadata.get("attachments"):
                raise ExportError(
                    "Encrypted source was preserved, but attachment completeness "
                    "cannot be proven from this mbox message"
                )
            append_source_manifests(
                archive,
                source_id,
                metadata,
                manifest_index=attachment_manifest_index,
            )
            append_instance_manifest(
                archive,
                {
                    "schema_version": 1,
                    "snapshot_id": snapshot_id,
                    "instance_key": key,
                    "sequence": record["sequence"],
                    "account_id": record["account_id"],
                    "account_name": record["account_name"],
                    "mailbox_path": record["mailbox_path"],
                    "library_id": record["message"]["library_id"],
                    "source_id": source_id,
                    "exported_at": utc_now(),
                    "mail_state": record["message"],
                },
                instance_manifest_index,
            )
            with connect_db(archive) as connection:
                connection.execute(
                    """
                    UPDATE instances SET status='complete', attempts=1, source_id=?,
                    completed_at=? WHERE snapshot_id=? AND instance_key=?
                    """,
                    (source_id, utc_now(), snapshot_id, key),
                )
                connection.execute(
                    "INSERT OR IGNORE INTO sources VALUES (?, ?, ?)",
                    (source_id, str(relative_source_dir(source_id)), utc_now()),
                )
        except Exception as exc:
            failures.append({"instance_key": key, "error": str(exc)})
            with connect_db(archive) as connection:
                connection.execute(
                    """
                    UPDATE instances SET status='failed', attempts=1, error=?
                    WHERE snapshot_id=? AND instance_key=?
                    """,
                    (str(exc), snapshot_id, key),
                )
    status = "complete" if not failures else "partial"
    with connect_db(archive) as connection:
        connection.execute(
            "UPDATE snapshots SET status=? WHERE snapshot_id=?", (status, snapshot_id)
        )
    report = {
        "schema_version": 1,
        "snapshot_id": snapshot_id,
        "status": status,
        "message_count": len(records),
        "failed": len(failures),
        "failures": failures,
    }
    atomic_write_json(archive / "reports" / f"{snapshot_id}-import.json", report, overwrite=False)
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0 if not failures else 1


def command_status(args: argparse.Namespace) -> int:
    archive = args.archive.expanduser().resolve()
    require_archive(archive)
    with connect_db(archive, readonly=True) as connection:
        if args.snapshot:
            snapshot_rows = connection.execute(
                "SELECT * FROM snapshots WHERE snapshot_id=?", (args.snapshot,)
            ).fetchall()
        else:
            snapshot_rows = connection.execute(
                "SELECT * FROM snapshots ORDER BY created_at DESC"
            ).fetchall()
        snapshots = []
        for row in snapshot_rows:
            counts = connection.execute(
                """
                SELECT status, COUNT(*) AS count FROM instances
                WHERE snapshot_id=? GROUP BY status
                """,
                (row["snapshot_id"],),
            ).fetchall()
            snapshots.append(
                {
                    **dict(row),
                    "instance_status": {item["status"]: item["count"] for item in counts},
                }
            )
    print(json.dumps({"schema_version": 1, "snapshots": snapshots}, indent=2))
    return 0


def add_archive_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--archive", type=Path, required=True, help="Explicit archive path")


def add_bridge_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--timeout", type=int, default=300, help="Bridge timeout in seconds")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Export Apple Mail into a private, verified local archive."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    preflight = subparsers.add_parser("preflight")
    add_archive_argument(preflight)
    add_bridge_options(preflight)
    preflight.add_argument("--allow-unsafe-destination", action="store_true")
    preflight.set_defaults(func=command_preflight)

    inventory = subparsers.add_parser("inventory")
    add_archive_argument(inventory)
    add_bridge_options(inventory)
    inventory.add_argument("--output", type=Path, required=True)
    inventory.add_argument("--allow-unsafe-destination", action="store_true")
    inventory.set_defaults(func=command_inventory)

    init_archive = subparsers.add_parser("init-archive")
    add_archive_argument(init_archive)
    init_archive.add_argument("--yes", action="store_true")
    init_archive.add_argument("--allow-unsafe-destination", action="store_true")
    init_archive.set_defaults(func=command_init_archive)

    snapshot = subparsers.add_parser("snapshot")
    add_archive_argument(snapshot)
    add_bridge_options(snapshot)
    snapshot.add_argument("--inventory", type=Path, required=True)
    snapshot.add_argument("--selection", type=Path, required=True)
    snapshot.set_defaults(func=command_snapshot)

    for name in ("export", "resume"):
        export = subparsers.add_parser(name)
        add_archive_argument(export)
        add_bridge_options(export)
        export.add_argument("--snapshot", required=True)
        export.add_argument("--limit", type=int, default=None if name == "resume" else 10)
        export.add_argument("--batch-size", type=int, default=25)
        export.add_argument(
            "--cleanup-staging",
            action="store_true",
            help="Delete generated bridge staging after each item; use only after approval",
        )
        export.set_defaults(func=command_export)

    import_mbox = subparsers.add_parser("import-mbox")
    add_archive_argument(import_mbox)
    import_mbox.add_argument("--input", type=Path, required=True)
    import_mbox.set_defaults(func=command_import_mbox)

    status = subparsers.add_parser("status")
    add_archive_argument(status)
    status.add_argument("--snapshot")
    status.set_defaults(func=command_status)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if hasattr(args, "batch_size") and args.batch_size < 1:
        parser.error("--batch-size must be positive")
    if hasattr(args, "limit") and args.limit is not None and args.limit < 1:
        parser.error("--limit must be positive")
    try:
        return int(args.func(args))
    except ExportError as exc:
        print(json.dumps({"status": "failed", "error": str(exc)}, indent=2), file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print(json.dumps({"status": "interrupted"}), file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
