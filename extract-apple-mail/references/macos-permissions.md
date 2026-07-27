# macOS and Apple Mail permissions

## Requirements

- macOS with `/System/Applications/Mail.app`
- Python 3.9 or newer
- `/usr/bin/osascript`
- At least one account or local mailbox visible in Mail
- Enough free disk for raw `.eml` files plus separately extracted attachments

No Python packages, API keys, Full Disk Access, or direct Mail-database access are
required.

## Automation permission

The first bridge call may make macOS ask whether the terminal or agent host can control
Mail. Approve only if the displayed application is the expected local host.

If permission was denied:

1. Open **System Settings → Privacy & Security → Automation**.
2. Find the terminal or agent application.
3. Enable access to **Mail**.
4. Keep Mail open and fully synchronized.
5. Rerun `preflight`.

Do not bypass Automation by reading `~/Library/Mail`.

## Downloads and synchronization

Reading raw source and saving an attachment may cause Mail to download data from the
configured mail server into its local cache. This does not send mail or change message
flags, but it is real local/network activity and must be disclosed before export.

If an attachment is unavailable:

- keep the raw source when available;
- record the attachment failure;
- rerun after Mail finishes synchronizing and the network is available; and
- keep verification non-complete until the attachment passes.

## Encrypted mail

If Mail exposes decrypted MIME and attachments, export them normally. If it exposes
only encrypted S/MIME payload or cannot access a key, preserve the raw encrypted
message and report the attachment as unavailable. Never infer or fabricate plaintext.

## Official fallback

Use Mail's **Mailbox → Export Mailbox** command to create `.mbox` packages, then run
`import-mbox`. This fallback remains local and uses Python's standard-library mbox and
email parsers.
