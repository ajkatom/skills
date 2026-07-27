# Operating principles

Operate through **Spec → Verification → Environment** in a tight,
human-in-the-loop improvement loop.

## Spec

- Aim at the outcome: a complete, private, independently verified Apple Mail archive
  that can later feed a maintained Markdown wiki.
- Work in the smallest reviewable bucket: preflight, inventory, selection, snapshot,
  pilot, full export, verification.
- Stop at each checkpoint and show concrete output before expanding scope.
- Resolve ambiguity before touching Mail or creating an archive.

## Verification

- State checkable criteria before each bucket.
- Verify against counts, hashes, MIME structure, and Apple Mail attachment metadata.
- Use `verify_archive.py` as a separate judge pass.
- Compare a human-reviewed sample with Apple Mail.
- Never call a partial, encrypted-unavailable, or attachment-missing export complete.

## Environment

- Keep the knowledge base in `<archive>/wiki`.
- Keep immutable truth in `<archive>/raw`.
- Keep schemas and durable operating rules in `<archive>/AGENT.md` and this skill's
  `references/`.
- Extend this skill only after a real run proves a durable macOS or Mail quirk.
- Reuse the bundled CLI and bridge before writing ad hoc scripts.

## Always

- Define eval criteria before a bucket.
- Work in small increments with a checkpoint between them.
- Verify before calling work done.
- Preserve exact Mail inventory selectors and snapshot IDs.
- Keep archives outside Git and cloud-synced folders by default.
- Use private directory and file permissions.
- Keep secrets in the user's designated secrets store; this skill needs no secrets.

## Ask first

- Create an archive or copy the `AGENT.md`/wiki templates.
- Permit Mail to download uncached messages or attachments.
- Expand from a pilot to the full snapshot.
- Use an unsafe destination override.
- Delete temporary or archive data.
- Commit, push, publish, send, or modify saved skill instructions.

## Never

- Store credentials in selection files, manifests, logs, or scripts.
- Read Mail's private database or filesystem internals.
- Modify message flags, mailboxes, or server state.
- Upload mail to a model or third party.
- Fabricate missing bodies, headers, or attachments.
- Mark work complete without a passing full verifier.
- Push a large multi-step change without checkpoints.
