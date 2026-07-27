# Archive schema

The archive is private, local, and versioned with `schema_version: 1`.

```text
mail-archive/
├── AGENT.md
├── raw/email/<first-two-hash-chars>/<sha256>/
│   ├── message.eml
│   ├── metadata.json
│   ├── source.md
│   └── attachments/
├── wiki/
│   ├── index.md
│   └── log.md
├── manifests/
│   ├── mailboxes.json
│   ├── selections/
│   ├── snapshots/
│   ├── message-instances.ndjson
│   └── attachments.ndjson
├── state/export.sqlite3
└── reports/<run-id>.json
```

## Identity and immutability

- Compute `source_id` as SHA-256 over the bytes stored in `message.eml`.
- Store one raw source directory per `source_id`.
- Preserve a separate message-instance record for every selected mailbox occurrence.
- Identify snapshot instances with a SHA-256 over snapshot ID, account ID, mailbox
  path, Mail library ID, and ordinal. Do not rely on the RFC `Message-ID`; it can be
  absent or duplicated.
- Never overwrite a raw source. If it already exists, recompute and compare its hash.
- Store changing mailbox membership only in manifests, not in immutable metadata.

## Source metadata

`metadata.json` contains:

- schema and source IDs;
- decoded subject, sender, recipients, dates, and RFC Message-ID;
- top-level MIME type and encryption indicators;
- SHA-256 and size of `message.eml`;
- deterministic body-selection information;
- embedded external image URLs;
- an attachment array with original and safe filenames, disposition, content ID,
  MIME type, extraction method, size, hash, and relative path;
- Mail-declared attachment metadata and its match or failure status.

`source.md` is a deterministic view, not an LLM summary. It contains provenance,
headers, the preferred readable body, and relative links to attachments.

## Manifests

- `mailboxes.json` is the inventory used for selection.
- `snapshots/<snapshot-id>.ndjson` is the frozen point-in-time message list.
- `message-instances.ndjson` is append-only and maps completed snapshot instances to
  source IDs and mailbox paths.
- `attachments.ndjson` is append-only and records attachment hashes per source.
- `reports/` contains machine-readable preflight, export, and verification reports.

The SQLite database is resumable operational state. JSON, NDJSON, `.eml`, and Markdown
are the portable contract.

## Wiki boundary

Treat `raw/` as immutable truth. Let an LLM own `wiki/`. Read `AGENT.md` before
ingesting sources. Cite relative `raw/.../source.md` paths from wiki claims. Update
`wiki/index.md` and append to `wiki/log.md` on every later ingest.
