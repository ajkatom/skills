# Verification contract

Use `scripts/verify_archive.py` as the independent judge. Do not infer success from an
export command returning zero.

## Full acceptance

The default verifier exits `0` only when:

1. the snapshot exists and parses;
2. every snapshot instance has exactly one completed instance manifest;
3. every referenced source directory exists;
4. the SHA-256 of `message.eml` equals its source ID and metadata hash;
5. every `.eml` parses;
6. every metadata attachment stays within its source directory and matches recorded
   size and SHA-256;
7. every Mail-declared attachment is matched or explicitly extracted through Mail;
8. no source metadata contains a missing attachment;
9. attachment manifests agree with metadata; and
10. no failed or pending snapshot instances remain.

Status is `complete`, `partial`, or `failed`. Default exit codes:

- `0`: complete
- `1`: partial or integrity/completeness failure
- `2`: invalid arguments, schema, or unreadable archive

`--allow-partial` returns `0` only when the completed subset has no integrity errors.
The JSON status remains `partial`.

## Pilot rubric

For a ten-message pilot:

- at least one exported instance exists;
- every exported source and attachment passes hashes;
- zero integrity errors occur;
- remaining snapshot instances are reported as pending, not lost; and
- a human samples subjects, dates, senders, bodies, and attachments in Apple Mail.

## Live full-archive rubric

Select all canonical account and local mailboxes needed by the user. Smart views may
duplicate instances. Freeze the snapshot before exporting.

Require:

- snapshot count equals completed instance count;
- zero failed or pending instances;
- zero missing Mail-declared or MIME file-bearing attachments;
- a manual cross-account sample opens correctly; and
- a second incremental snapshot captures mail that arrived after the first snapshot.
