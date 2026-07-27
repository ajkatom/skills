from __future__ import annotations

import importlib.util
import json
import mailbox
import os
import tempfile
import unittest
from unittest import mock
from email.message import EmailMessage
from email import policy
from pathlib import Path
from typing import Optional


SKILL_DIR = Path(__file__).resolve().parents[1]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


exporter = load_module("export_apple_mail", SKILL_DIR / "scripts" / "export_apple_mail.py")
verifier = load_module("verify_archive", SKILL_DIR / "scripts" / "verify_archive.py")


def base_message(
    subject: str = "Hello", message_id: Optional[str] = "<one@example.com>"
) -> EmailMessage:
    message = EmailMessage(policy=policy.default)
    message["From"] = "Séndér <sender@example.com>"
    message["To"] = "Recipient <recipient@example.com>"
    message["Date"] = "Fri, 25 Jul 2026 12:00:00 -1000"
    message["Subject"] = subject
    if message_id is not None:
        message["Message-ID"] = message_id
    message.set_content("Plain body\n")
    message.add_alternative(
        '<html><body><p>HTML body</p><img src="https://example.com/remote.png"></body></html>',
        subtype="html",
    )
    return message


def attachment_message() -> EmailMessage:
    message = base_message("Unicode ✓ and attachments", None)
    message.add_attachment(b"pdf bytes", maintype="application", subtype="pdf", filename="résumé.pdf")
    message.add_attachment(b"first", maintype="application", subtype="octet-stream", filename="same.bin")
    message.add_attachment(b"second", maintype="application", subtype="octet-stream", filename="same.bin")
    message.add_attachment(b"", maintype="application", subtype="octet-stream", filename="../../escape.bin")
    message.add_attachment(
        b"\x89PNG\r\n",
        maintype="image",
        subtype="png",
        filename="inline.png",
        disposition="inline",
        cid="<image-1>",
    )
    nested = EmailMessage()
    nested["From"] = "nested@example.com"
    nested["To"] = "recipient@example.com"
    nested["Subject"] = "Nested"
    nested.set_content("Nested body")
    message.add_attachment(nested)
    return message


class ArchiveCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="extract-apple-mail-test-")
        self.root = Path(self.temp.name)
        self.archive = self.root / "archive"
        result = exporter.main(
            ["init-archive", "--archive", str(self.archive), "--yes"]
        )
        self.assertEqual(result, 0)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def create_mbox(self, messages, package: bool = False) -> Path:
        if package:
            destination = self.root / "Apple Export.mbox"
            destination.mkdir()
            path = destination / "mbox"
        else:
            path = self.root / "mailbox"
        box = mailbox.mbox(path, create=True)
        try:
            for message in messages:
                box.add(message)
            box.flush()
        finally:
            box.close()
        return destination if package else path

    def import_messages(self, messages: list[EmailMessage], package: bool = False) -> str:
        source = self.create_mbox(messages, package=package)
        result = exporter.main(
            ["import-mbox", "--archive", str(self.archive), "--input", str(source)]
        )
        self.assertEqual(result, 0)
        snapshots = sorted((self.archive / "manifests" / "snapshots").glob("*.ndjson"))
        self.assertEqual(len(snapshots), 1)
        return snapshots[0].stem

    def verify(self, snapshot: str, allow_partial: bool = False):
        args = type(
            "Args",
            (),
            {
                "archive": self.archive,
                "snapshot": snapshot,
                "allow_partial": allow_partial,
                "output": None,
            },
        )()
        return verifier.verify(args)

    def register_live_snapshot(self, message: EmailMessage):
        raw = message.as_bytes(policy=policy.default)
        parsed = exporter.BytesParser(policy=policy.default).parsebytes(raw)
        snapshot = "snapshot-test-resume"
        summary = exporter.message_summary_from_parsed(parsed, len(raw))
        summary["library_id"] = "42"
        record = {
            "schema_version": 1,
            "snapshot_id": snapshot,
            "sequence": 1,
            "account_id": "A",
            "account_name": "Test",
            "mailbox_path": ["Inbox"],
            "mailbox_selector": exporter.mailbox_selector("A", ["Inbox"]),
            "classification": "account",
            "mailbox_ordinal": 1,
            "message": summary,
        }
        record["instance_key"] = exporter.instance_key(snapshot, record)
        snapshot_path = self.archive / "manifests" / "snapshots" / f"{snapshot}.ndjson"
        exporter.atomic_write_text(snapshot_path, exporter.canonical_json(record) + "\n")
        with exporter.connect_db(self.archive) as connection:
            connection.execute(
                "INSERT INTO snapshots VALUES (?, ?, ?, ?, ?, ?, 'pending')",
                (
                    snapshot,
                    exporter.utc_now(),
                    str(snapshot_path.relative_to(self.archive)),
                    1,
                    len(summary["attachments"]),
                    len(raw),
                ),
            )
            connection.execute(
                """
                INSERT INTO instances
                (snapshot_id, instance_key, sequence, account_id, mailbox_path, library_id)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    snapshot,
                    record["instance_key"],
                    1,
                    "A",
                    exporter.canonical_json(["Inbox"]),
                    "42",
                ),
            )
        return snapshot, record, raw

    def test_mbox_package_attachment_matrix_and_verifier(self) -> None:
        snapshot = self.import_messages([attachment_message()], package=True)
        report, code = self.verify(snapshot)
        self.assertEqual(code, 0, report)
        self.assertEqual(report["status"], "complete")
        self.assertEqual(report["snapshot_instances"], 1)
        self.assertEqual(report["verified_attachments"], 6)
        source_dirs = list((self.archive / "raw" / "email").glob("*/*"))
        self.assertEqual(len(source_dirs), 1)
        metadata = json.loads((source_dirs[0] / "metadata.json").read_text())
        names = [item["safe_filename"] for item in metadata["attachments"]]
        self.assertEqual(len(names), len(set(names)))
        self.assertTrue(any(name.endswith("escape.bin") for name in names))
        for item in metadata["attachments"]:
            attachment = (source_dirs[0] / item["relative_path"]).resolve()
            self.assertIn(source_dirs[0].resolve(), attachment.parents)
        self.assertIn("https://example.com/remote.png", metadata["external_image_urls"])
        self.assertEqual(metadata["message_id"], "")

    def test_duplicate_message_id_and_raw_content_deduplicate(self) -> None:
        one = base_message("Duplicate", "<duplicate@example.com>")
        raw = one.as_bytes(policy=policy.default)
        source = self.create_mbox([raw, raw])
        result = exporter.main(
            ["import-mbox", "--archive", str(self.archive), "--input", str(source)]
        )
        self.assertEqual(result, 0)
        snapshot = next((self.archive / "manifests" / "snapshots").glob("*.ndjson")).stem
        report, code = self.verify(snapshot)
        self.assertEqual(code, 0, report)
        self.assertEqual(report["completed_instances"], 2)
        self.assertEqual(report["unique_sources"], 1)

    def test_attachment_tampering_is_detected(self) -> None:
        snapshot = self.import_messages([attachment_message()])
        source_dir = next((self.archive / "raw" / "email").glob("*/*"))
        attachment = next((source_dir / "attachments").iterdir())
        attachment.write_bytes(b"tampered")
        report, code = self.verify(snapshot)
        self.assertEqual(code, 1)
        self.assertEqual(report["status"], "failed")
        self.assertIn("attachment_hash_mismatch", {item["code"] for item in report["errors"]})

    def test_encrypted_source_is_preserved_and_flagged(self) -> None:
        raw = (SKILL_DIR / "tests" / "fixtures" / "encrypted.eml").read_bytes()
        source_id, metadata, created = exporter.ingest_raw_message(self.archive, raw, [])
        self.assertTrue(created)
        self.assertTrue(metadata["encrypted"])
        self.assertTrue((self.archive / exporter.relative_source_dir(source_id) / "message.eml").is_file())

    def test_encrypted_mbox_stays_incomplete_but_preserves_raw(self) -> None:
        raw = (SKILL_DIR / "tests" / "fixtures" / "encrypted.eml").read_bytes()
        source = self.create_mbox([raw])
        result = exporter.main(
            ["import-mbox", "--archive", str(self.archive), "--input", str(source)]
        )
        self.assertEqual(result, 1)
        source_dirs = list((self.archive / "raw" / "email").glob("*/*"))
        self.assertEqual(len(source_dirs), 1)
        self.assertTrue((source_dirs[0] / "message.eml").is_file())
        status = exporter.read_json(
            next((self.archive / "reports").glob("*-import.json"))
        )
        self.assertEqual(status["status"], "partial")
        self.assertEqual(status["failed"], 1)

    def test_malformed_source_parses_without_fabrication(self) -> None:
        raw = (SKILL_DIR / "tests" / "fixtures" / "malformed.eml").read_bytes()
        source_id, metadata, created = exporter.ingest_raw_message(self.archive, raw, [])
        self.assertTrue(created)
        self.assertEqual(metadata["source_id"], source_id)
        self.assertTrue(metadata["parser_defects"])

    def test_unavailable_mail_attachment_is_a_hard_failure(self) -> None:
        _, checks, errors = exporter.reconcile_mail_attachments(
            [],
            [
                {
                    "mail_attachment_id": "missing",
                    "name": "remote.pdf",
                    "mime_type": "application/pdf",
                    "file_size": 123,
                    "downloaded": False,
                    "saved_path": None,
                    "save_error": "not downloaded",
                }
            ],
        )
        self.assertEqual(checks[0]["status"], "missing")
        self.assertEqual(len(errors), 1)

    def test_unsafe_git_destination_is_rejected(self) -> None:
        git_root = self.root / "repo"
        (git_root / ".git").mkdir(parents=True)
        unsafe = git_root / "archive"
        with self.assertRaises(exporter.ExportError):
            exporter.ensure_safe_destination(unsafe, False)

    def test_private_permissions_and_status(self) -> None:
        mode = os.stat(self.archive).st_mode & 0o777
        self.assertEqual(mode, 0o700)
        result = exporter.main(["status", "--archive", str(self.archive)])
        self.assertEqual(result, 0)

    def test_existing_parent_directory_permissions_are_not_changed(self) -> None:
        existing = self.root
        with mock.patch.object(exporter.os, "chmod") as chmod:
            exporter.private_dir(existing)
        chmod.assert_not_called()

    def test_failed_export_resumes_without_duplicate_manifests(self) -> None:
        snapshot, record, raw = self.register_live_snapshot(attachment_message())

        def failed_bridge(operation, request, **_):
            self.assertEqual(operation, "export")
            return {
                "schema_version": 1,
                "results": [
                    {
                        "instance_key": request["items"][0]["instance_key"],
                        "status": "failed",
                        "error": "simulated interruption",
                    }
                ],
            }

        def successful_bridge(operation, request, **_):
            self.assertEqual(operation, "export")
            item = request["items"][0]
            Path(item["source_path"]).write_bytes(raw)
            mail_attachments = []
            for attachment in record["message"]["attachments"]:
                mail_attachments.append(
                    {
                        "mail_attachment_id": attachment.get("mail_attachment_id", ""),
                        "name": attachment["name"],
                        "mime_type": attachment["mime_type"],
                        "file_size": attachment["file_size"],
                        "downloaded": True,
                        "saved_path": None,
                        "save_error": None,
                    }
                )
            return {
                "schema_version": 1,
                "results": [
                    {
                        "instance_key": item["instance_key"],
                        "status": "exported",
                        "source_path": item["source_path"],
                        "current_message": record["message"],
                        "mail_attachments": mail_attachments,
                    }
                ],
            }

        with mock.patch.object(exporter, "call_bridge", side_effect=failed_bridge):
            first = exporter.export_snapshot(
                self.archive,
                snapshot,
                limit=None,
                batch_size=25,
                timeout=30,
                cleanup_staging=False,
            )
        self.assertEqual(first["failed"], 1)

        with mock.patch.object(exporter, "call_bridge", side_effect=successful_bridge):
            second = exporter.export_snapshot(
                self.archive,
                snapshot,
                limit=None,
                batch_size=25,
                timeout=30,
                cleanup_staging=False,
            )
        self.assertEqual(second["status"], "complete")
        report, code = self.verify(snapshot)
        self.assertEqual(code, 0, report)

        instance_lines = [
            json.loads(line)
            for line in (self.archive / "manifests" / "message-instances.ndjson")
            .read_text()
            .splitlines()
            if line.strip()
        ]
        self.assertEqual(len(instance_lines), 1)

        third = exporter.export_snapshot(
            self.archive,
            snapshot,
            limit=None,
            batch_size=25,
            timeout=30,
            cleanup_staging=False,
        )
        self.assertEqual(third["attempted"], 0)
        instance_lines_after = [
            line
            for line in (self.archive / "manifests" / "message-instances.ndjson")
            .read_text()
            .splitlines()
            if line.strip()
        ]
        self.assertEqual(len(instance_lines_after), 1)


class SelectionCase(unittest.TestCase):
    def test_selection_validation_and_all(self) -> None:
        record = {
            "account_id": "A",
            "path": ["Inbox"],
            "selector": exporter.mailbox_selector("A", ["Inbox"]),
        }
        inventory = {"schema_version": 1, "mailboxes": [record]}
        selected = exporter.validate_selection(
            inventory,
            {"schema_version": 1, "mailboxes": [{"account_id": "A", "path": ["Inbox"]}]},
        )
        self.assertEqual(selected["mailboxes"][0]["path"], ["Inbox"])
        self.assertTrue(
            exporter.validate_selection(inventory, {"schema_version": 1, "all": True})["all"]
        )


if __name__ == "__main__":
    unittest.main()
