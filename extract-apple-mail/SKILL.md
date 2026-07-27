---
name: extract-apple-mail
description: Export Apple Mail messages and attachments into a private, verified, resumable local archive that is ready for an Obsidian or Karpathy-style LLM wiki. Use when an agent needs to inventory Apple Mail accounts or mailboxes, back up selected or all mail, preserve raw .eml sources and attachments, import Apple .mbox exports, resume an interrupted mail export, or prove an email archive is complete without uploading private mail to a model or service.
---

# Extract Apple Mail

Export Apple Mail through its public scripting interface. Preserve immutable raw
sources, create deterministic Markdown source views, and verify the result with a
separate read-only judge.

## Non-negotiable boundaries

- Keep all mail local. Do not send message content, metadata, or attachments to an
  LLM, API, embedding service, or network tool.
- Never read `~/Library/Mail`, Mail databases, or `.emlx` internals.
- Never modify, move, delete, flag, or mark messages read.
- Treat Mail downloading an uncached attachment as disclosed local cache activity.
- Never write an archive into this skill repository or another Git worktree unless
  the user explicitly accepts `--allow-unsafe-destination`.
- Never report completion unless the independent verifier returns `complete`.
- Treat inaccessible, encrypted, moved, or unavailable messages and attachments as
  failures. Preserve what is available; do not guess.

Read [references/operating-principles.md](references/operating-principles.md)
before running an export. Read [references/macos-permissions.md](references/macos-permissions.md)
when preflight reports an Automation or Mail error. Read
[references/archive-schema.md](references/archive-schema.md) when consuming or
repairing an archive. Read [references/verification.md](references/verification.md)
before declaring a pilot or full export successful.

## Workflow

Use `python3 scripts/export_apple_mail.py --help` for the exact CLI.

1. **Preflight.** Choose an explicit, private archive path outside Git and cloud-sync
   folders. Run `preflight`. State the eval criteria: Mail is reachable, Automation
   is allowed, the destination is safe, and disk space is reported.
2. **Inventory.** Run `inventory` to a temporary JSON file. Show mailbox selectors
   and counts. Ask the user which mailboxes to select, or whether to use `--all`.
   Do not initialize the archive yet.
3. **Checkpoint.** Save a schema-v1 selection JSON file and show the selected
   mailbox count and estimated message count. Wait for explicit approval to create
   the archive and permit temporary-file cleanup.
4. **Initialize.** Run `init-archive --yes`. This copies the model-neutral `AGENT.md`
   and empty wiki template and creates private state directories.
5. **Snapshot.** Run `snapshot` with the inventory and selection. This freezes a
   point-in-time list; later arrivals belong to a later snapshot. Show message,
   attachment, and byte estimates before continuing.
6. **Pilot.** Run `export --limit 10`, then run the independent verifier with
   `--allow-partial`. Show exported counts, errors, and a few paths. Wait for a steer.
7. **Complete.** Run `resume` without a limit. Export in bounded batches and commit
   state after each message.
8. **Verify.** Run `scripts/verify_archive.py --archive <path> --snapshot <id>`.
   Require status `complete`, zero missing snapshot instances, zero attachment
   failures, valid MIME parsing, and matching hashes.
9. **Checkpoint and learn.** Report exact totals or the retry list. Store run-specific
   facts in `reports/`. Propose any durable instruction change separately; do not
   silently rewrite the skill.

## Core commands

```bash
python3 scripts/export_apple_mail.py preflight --archive /private/path/mail-archive
python3 scripts/export_apple_mail.py inventory --archive /private/path/mail-archive --output /tmp/mailboxes.json
python3 scripts/export_apple_mail.py init-archive --archive /private/path/mail-archive --yes
python3 scripts/export_apple_mail.py snapshot --archive /private/path/mail-archive --inventory /tmp/mailboxes.json --selection /tmp/selection.json
python3 scripts/export_apple_mail.py export --archive /private/path/mail-archive --snapshot <snapshot-id> --limit 10 --cleanup-staging
python3 scripts/verify_archive.py --archive /private/path/mail-archive --snapshot <snapshot-id> --allow-partial
python3 scripts/export_apple_mail.py resume --archive /private/path/mail-archive --snapshot <snapshot-id> --cleanup-staging
python3 scripts/verify_archive.py --archive /private/path/mail-archive --snapshot <snapshot-id>
```

Use `import-mbox` when the user has exported mailboxes through Mail's
**Mailbox → Export Mailbox** command or Automation is unavailable.

## Selection format

Use one of:

```json
{"schema_version": 1, "all": true}
```

```json
{
  "schema_version": 1,
  "mailboxes": [
    {"account_id": "ACCOUNT-ID", "path": ["Inbox"]}
  ]
}
```

Keep the inventory-generated `account_id` and path components exact. Smart Mailboxes
and local views can duplicate messages; preserve each selected mailbox instance while
deduplicating identical raw source bytes by SHA-256.

## Done

Call the selected snapshot done only when the default verifier exits `0` and reports:

- `snapshot_instances == completed_instances`;
- every manifest instance resolves to an immutable `.eml`;
- every expected file-bearing MIME part or Mail-declared attachment is present;
- every recorded size and SHA-256 hash matches;
- every `.eml` parses; and
- there are no missing, failed, or unclassified records.

An `--allow-partial` pilot can prove the exported subset is internally valid, but its
status remains `partial`; never describe it as a complete archive.
