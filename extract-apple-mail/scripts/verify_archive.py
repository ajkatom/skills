#!/usr/bin/env python3
"""Independent, read-only verifier for an extract-apple-mail archive."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import sys
from collections import Counter, defaultdict
from email import policy
from email.parser import BytesParser
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Sequence, Tuple


SCHEMA_VERSION = 1


class VerificationError(RuntimeError):
    """Invalid or unreadable archive."""


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise VerificationError(f"Could not read JSON {path}: {exc}") from exc


def read_ndjson(path: Path) -> Iterator[Dict[str, Any]]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, 1):
                if not line.strip():
                    continue
                try:
                    value = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise VerificationError(
                        f"Invalid NDJSON at {path}:{line_number}: {exc}"
                    ) from exc
                if not isinstance(value, dict):
                    raise VerificationError(f"Expected object at {path}:{line_number}")
                yield value
    except OSError as exc:
        raise VerificationError(f"Could not read {path}: {exc}") from exc


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def latest_snapshot(archive: Path) -> str:
    paths = sorted((archive / "manifests" / "snapshots").glob("*.ndjson"))
    if not paths:
        raise VerificationError("Archive has no snapshots")
    return paths[-1].stem


def source_dir(archive: Path, source_id: str) -> Path:
    return archive / "raw" / "email" / source_id[:2] / source_id


def safe_attachment_path(directory: Path, relative: str) -> Optional[Path]:
    candidate = directory / relative
    if candidate.is_symlink():
        return None
    try:
        resolved = candidate.resolve(strict=True)
        root = directory.resolve(strict=True)
    except OSError:
        return None
    if root != resolved and root not in resolved.parents:
        return None
    return resolved


def normalized_name(name: str) -> str:
    return Path((name or "").replace("\\", "/")).name.casefold()


def mail_attachment_matches(
    mail_item: Dict[str, Any], extracted: Sequence[Dict[str, Any]]
) -> bool:
    name = normalized_name(str(mail_item.get("name", "")))
    size = int(mail_item.get("file_size", 0) or 0)
    for item in extracted:
        extracted_name = normalized_name(str(item.get("original_filename", "")))
        extracted_size = int(item.get("size", 0) or 0)
        if name and name == extracted_name and not (size > 0 and extracted_size == 0):
            return True
        if not name and size == int(item.get("size", -1)):
            return True
    return False


def db_status(archive: Path, snapshot_id: str) -> Dict[str, int]:
    db_path = archive / "state" / "export.sqlite3"
    if not db_path.is_file():
        return {}
    uri = f"file:{db_path.resolve()}?mode=ro"
    try:
        with sqlite3.connect(uri, uri=True) as connection:
            rows = connection.execute(
                """
                SELECT status, COUNT(*) FROM instances
                WHERE snapshot_id=? GROUP BY status
                """,
                (snapshot_id,),
            ).fetchall()
        return {str(status): int(count) for status, count in rows}
    except sqlite3.Error:
        return {}


def verify(args: argparse.Namespace) -> Tuple[Dict[str, Any], int]:
    archive = args.archive.expanduser().resolve()
    marker = archive / "state" / "archive.json"
    if not marker.is_file():
        raise VerificationError(f"Not an initialized archive: {archive}")
    marker_value = read_json(marker)
    if marker_value.get("schema_version") != SCHEMA_VERSION:
        raise VerificationError("Unsupported archive schema")

    snapshot_id = args.snapshot or latest_snapshot(archive)
    snapshot_file = archive / "manifests" / "snapshots" / f"{snapshot_id}.ndjson"
    snapshot_records = list(read_ndjson(snapshot_file))
    snapshot_keys = [str(record.get("instance_key", "")) for record in snapshot_records]
    errors: List[Dict[str, Any]] = []
    warnings: List[Dict[str, Any]] = []

    empty_keys = [index + 1 for index, key in enumerate(snapshot_keys) if not key]
    if empty_keys:
        errors.append({"code": "snapshot_instance_key_missing", "sequences": empty_keys})
    duplicate_snapshot_keys = sorted(
        key for key, count in Counter(snapshot_keys).items() if key and count != 1
    )
    if duplicate_snapshot_keys:
        errors.append(
            {"code": "snapshot_instance_key_duplicate", "instance_keys": duplicate_snapshot_keys}
        )

    instance_file = archive / "manifests" / "message-instances.ndjson"
    instance_records = list(read_ndjson(instance_file)) if instance_file.exists() else []
    scoped_instances = [
        record for record in instance_records if record.get("snapshot_id") == snapshot_id
    ]
    instances_by_key: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for record in scoped_instances:
        instances_by_key[str(record.get("instance_key", ""))].append(record)
    for key, records in sorted(instances_by_key.items()):
        if len(records) != 1:
            errors.append(
                {
                    "code": "completed_instance_manifest_duplicate",
                    "instance_key": key,
                    "count": len(records),
                }
            )

    completed = {
        key: records[0] for key, records in instances_by_key.items() if len(records) == 1
    }
    missing_keys = [key for key in snapshot_keys if key and key not in completed]
    unexpected_keys = sorted(set(completed).difference(snapshot_keys))
    if unexpected_keys:
        errors.append(
            {"code": "unexpected_completed_instances", "instance_keys": unexpected_keys}
        )

    attachment_manifest_file = archive / "manifests" / "attachments.ndjson"
    attachment_manifest_records = (
        list(read_ndjson(attachment_manifest_file)) if attachment_manifest_file.exists() else []
    )
    attachment_manifest: Dict[Tuple[str, int], List[Dict[str, Any]]] = defaultdict(list)
    for item in attachment_manifest_records:
        attachment_manifest[
            (str(item.get("source_id", "")), int(item.get("ordinal", -1)))
        ].append(item)

    snapshot_by_key = {
        str(record.get("instance_key")): record for record in snapshot_records
    }
    verified_sources: Dict[str, Dict[str, Any]] = {}
    verified_attachment_count = 0

    for key, instance in completed.items():
        source_id = str(instance.get("source_id", ""))
        if len(source_id) != 64 or any(char not in "0123456789abcdef" for char in source_id):
            errors.append(
                {"code": "invalid_source_id", "instance_key": key, "source_id": source_id}
            )
            continue
        directory = source_dir(archive, source_id)
        raw_path = directory / "message.eml"
        metadata_path = directory / "metadata.json"
        markdown_path = directory / "source.md"
        for required in (raw_path, metadata_path, markdown_path):
            if not required.is_file() or required.is_symlink():
                errors.append(
                    {
                        "code": "source_file_missing_or_symlink",
                        "instance_key": key,
                        "path": str(required),
                    }
                )
        if not raw_path.is_file() or raw_path.is_symlink():
            continue
        actual_hash = sha256_file(raw_path)
        if actual_hash != source_id:
            errors.append(
                {
                    "code": "message_hash_mismatch",
                    "instance_key": key,
                    "expected": source_id,
                    "actual": actual_hash,
                }
            )
            continue
        try:
            parsed = BytesParser(policy=policy.default).parsebytes(raw_path.read_bytes())
        except Exception as exc:
            errors.append(
                {"code": "eml_parse_failed", "instance_key": key, "error": str(exc)}
            )
            continue
        if parsed.defects:
            warnings.append(
                {
                    "code": "eml_parser_defects",
                    "source_id": source_id,
                    "defects": [type(defect).__name__ for defect in parsed.defects],
                }
            )
        if source_id in verified_sources:
            metadata = verified_sources[source_id]
        else:
            if not metadata_path.is_file():
                continue
            metadata = read_json(metadata_path)
            verified_sources[source_id] = metadata
            if metadata.get("schema_version") != SCHEMA_VERSION:
                errors.append({"code": "metadata_schema", "source_id": source_id})
            if metadata.get("source_id") != source_id:
                errors.append({"code": "metadata_source_id", "source_id": source_id})
            if metadata.get("message_sha256") != source_id:
                errors.append({"code": "metadata_message_hash", "source_id": source_id})
            if int(metadata.get("message_size", -1)) != raw_path.stat().st_size:
                errors.append({"code": "metadata_message_size", "source_id": source_id})

            checks = metadata.get("mail_attachment_checks", [])
            if metadata.get("encrypted") and not metadata.get("attachments"):
                errors.append(
                    {
                        "code": "encrypted_attachment_completeness_unproven",
                        "source_id": source_id,
                    }
                )
            missing_checks = [check for check in checks if check.get("status") == "missing"]
            if missing_checks:
                errors.append(
                    {
                        "code": "mail_attachment_missing",
                        "source_id": source_id,
                        "count": len(missing_checks),
                    }
                )
            for attachment in metadata.get("attachments", []):
                ordinal = int(attachment.get("ordinal", -1))
                relative = str(attachment.get("relative_path", ""))
                path = safe_attachment_path(directory, relative)
                if path is None or not path.is_file():
                    errors.append(
                        {
                            "code": "attachment_path_invalid",
                            "source_id": source_id,
                            "ordinal": ordinal,
                            "path": relative,
                        }
                    )
                    continue
                actual_attachment_hash = sha256_file(path)
                if actual_attachment_hash != attachment.get("sha256"):
                    errors.append(
                        {
                            "code": "attachment_hash_mismatch",
                            "source_id": source_id,
                            "ordinal": ordinal,
                        }
                    )
                if path.stat().st_size != int(attachment.get("size", -1)):
                    errors.append(
                        {
                            "code": "attachment_size_mismatch",
                            "source_id": source_id,
                            "ordinal": ordinal,
                        }
                    )
                manifest_matches = attachment_manifest.get((source_id, ordinal), [])
                if len(manifest_matches) != 1:
                    errors.append(
                        {
                            "code": "attachment_manifest_count",
                            "source_id": source_id,
                            "ordinal": ordinal,
                            "count": len(manifest_matches),
                        }
                    )
                elif manifest_matches[0].get("sha256") != attachment.get("sha256"):
                    errors.append(
                        {
                            "code": "attachment_manifest_hash",
                            "source_id": source_id,
                            "ordinal": ordinal,
                        }
                    )
                verified_attachment_count += 1

        snapshot_record = snapshot_by_key.get(key, {})
        if snapshot_record.get("classification") != "mbox":
            snapshot_message = snapshot_record.get("message", {})
            current_message = instance.get("mail_state", {})
            snapshot_declared = snapshot_message.get("attachments", [])
            declared = current_message.get("attachments", [])
            if len(snapshot_declared) != len(declared):
                errors.append(
                    {
                        "code": "instance_mail_attachment_count_changed",
                        "instance_key": key,
                        "snapshot_count": len(snapshot_declared),
                        "export_count": len(declared),
                    }
                )
            extracted = metadata.get("attachments", [])
            for mail_item in list(snapshot_declared) + list(declared):
                if not mail_attachment_matches(mail_item, extracted):
                    errors.append(
                        {
                            "code": "instance_mail_attachment_unmatched",
                            "instance_key": key,
                            "name": mail_item.get("name", ""),
                        }
                    )
            for state_name in (
                "read_status",
                "flagged_status",
                "deleted_status",
                "junk_mail_status",
            ):
                if snapshot_message.get(state_name) != current_message.get(state_name):
                    errors.append(
                        {
                            "code": "message_state_changed",
                            "instance_key": key,
                            "field": state_name,
                            "snapshot": snapshot_message.get(state_name),
                            "export": current_message.get(state_name),
                        }
                    )

    db_counts = db_status(archive, snapshot_id)
    report = {
        "schema_version": SCHEMA_VERSION,
        "archive": str(archive),
        "snapshot_id": snapshot_id,
        "snapshot_instances": len(snapshot_records),
        "completed_instances": len(completed),
        "missing_instances": len(missing_keys),
        "unexpected_instances": len(unexpected_keys),
        "unique_sources": len(verified_sources),
        "verified_attachments": verified_attachment_count,
        "state_counts": db_counts,
        "errors": errors,
        "warnings": warnings,
    }

    if errors:
        status = "failed"
        exit_code = 1
    elif missing_keys:
        status = "partial"
        exit_code = 0 if args.allow_partial and len(completed) > 0 else 1
    else:
        status = "complete"
        exit_code = 0
    report["status"] = status
    if missing_keys:
        report["missing_instance_keys"] = missing_keys
    return report, exit_code


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--snapshot", help="Snapshot ID; defaults to newest")
    parser.add_argument(
        "--allow-partial",
        action="store_true",
        help="Exit zero for an internally valid non-empty completed subset",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Optional explicit report path; otherwise remain read-only and print JSON",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        report, exit_code = verify(args)
    except VerificationError as exc:
        print(json.dumps({"status": "failed", "error": str(exc)}, indent=2), file=sys.stderr)
        return 2
    output = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.output:
        path = args.output.expanduser().resolve()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(output, encoding="utf-8")
        os.chmod(path, 0o600)
    print(output, end="")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
