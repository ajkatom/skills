# Extract Apple Mail Skill — Design Spec

**Date:** 2026-07-25
**Target:** `extract-apple-mail/`
**Runtime:** macOS, Python 3.9+ standard library, JXA through `osascript`

## Goal

Export a point-in-time snapshot of user-selected Apple Mail mailboxes, including
every locally accessible attachment, into a private and independently verified
local archive. Preserve immutable sources for later compilation into a
Karpathy-style Markdown wiki without uploading mail to a model or service.

Definition of done for a snapshot:

- every frozen message instance has one completed manifest record;
- every instance resolves to a SHA-256-addressed `.eml`;
- every Mail-declared or file-bearing MIME attachment has a valid extracted file;
- every source and attachment hash matches;
- every `.eml` parses; and
- the independent verifier exits `0` with status `complete`.

## Locked decisions

1. **Skill boundary:** extract and stage only. Do not synthesize the wiki.
2. **Selection:** inventory first, then accept explicit mailbox selectors or
   `all=true`. “All” means the frozen snapshot; later arrivals need another run.
3. **Mail access:** use Mail's public Apple Events/JXA scripting interface. Never
   parse `~/Library/Mail`, SQLite databases, or `.emlx` internals.
4. **Fallback:** import Apple-supported `.mbox` exports through Python's standard
   `mailbox` and `email` modules.
5. **Identity:** hash stored `.eml` bytes for source identity. Preserve mailbox
   instances separately because RFC Message-ID can be absent or duplicated.
6. **Privacy:** require an explicit archive path, private permissions, and a
   destination outside Git/cloud-sync by default. Use no credentials or APIs.
7. **Immutability:** never overwrite raw sources. Validate and reuse an existing
   source only when its hash and attachments still match.
8. **Verification:** keep export and judge code separate. Export success alone is
   never proof of completeness.

## Components

### `SKILL.md`

Drive the human-in-the-loop sequence: preflight → inventory → selection checkpoint
→ initialization → snapshot checkpoint → ten-message pilot → verification
checkpoint → resume → full verification. Load detailed references only when needed.

### `scripts/apple_mail_bridge.js`

Address `/System/Applications/Mail.app` explicitly. Exchange versioned JSON files
with Python. Recursively enumerate account and top-level local/view mailboxes,
snapshot message metadata, and export raw message source plus Mail attachment-save
fallbacks. Never mutate message state.

### `scripts/export_apple_mail.py`

Provide `preflight`, `inventory`, `init-archive`, `snapshot`, `export`, `resume`,
`import-mbox`, and `status`. Use SQLite for operational resumability and JSON/NDJSON
for the portable contract. Finalize sources atomically, commit instance state after
each message, and make manifest writes idempotent across crashes.

### `scripts/verify_archive.py`

Remain read-only unless the user supplies an explicit `--output`. Recount snapshot
instances, reject duplicate or missing instance manifests, recompute hashes,
reparse MIME, confine attachment paths, compare Mail-declared attachments, check
attachment manifests, and inspect SQLite state as supporting evidence.

## Archive contract

```text
archive/
├── AGENT.md
├── raw/email/<prefix>/<source-id>/{message.eml,metadata.json,source.md,attachments/}
├── wiki/{index.md,log.md}
├── manifests/{mailboxes.json,selections/,snapshots/,message-instances.ndjson,attachments.ndjson}
├── state/{archive.json,export.sqlite3,staging/}
└── reports/
```

`raw/` is immutable evidence. `wiki/` starts with headers only and is owned by a
future LLM. `AGENT.md` defines source citation, index/log maintenance, contradiction
handling, and human checkpoints.

## Failure behavior

- A bridge timeout, moved message, unavailable source, or missing attachment marks
  that instance failed and leaves the snapshot partial.
- A failed instance remains resumable; a later `resume` retries it.
- An encrypted message is preserved. If Mail cannot expose an attachment or
  decrypted payload, verification remains non-complete.
- Remote HTML images not embedded in MIME are recorded as external URLs, not
  attachments.
- Smart/local views may overlap physical mailboxes. Preserve selected instances and
  deduplicate only raw bytes.
- Staging cleanup is opt-in with `--cleanup-staging` after explicit approval.

## Tests

Use standard-library `unittest` fixtures for:

- text, HTML, Unicode, missing/duplicate Message-ID;
- duplicate instances and content-addressed deduplication;
- repeated names, traversal names, inline, zero-byte, nested `.eml`, and malformed
  MIME attachments;
- Apple `.mbox` package discovery;
- simulated failed export followed by successful idempotent resume;
- encrypted source preservation;
- unsafe Git destination rejection; and
- tamper detection by the independent verifier.

Compile the JXA bridge with `osacompile`, compile both Python scripts, run the full
unit suite, run a fixture through the standalone verifier, and run the skill
`quick_validate.py`. A live acceptance run requires user-approved Automation access
and a controlled Mail mailbox; it is intentionally separate from unit tests.
