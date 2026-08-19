#!/usr/bin/osascript -l JavaScript

/*
 * JSON-file bridge between Python and Apple Mail's public scripting interface.
 * Run with:
 *   osascript -l JavaScript apple_mail_bridge.js <operation> <request.json> <result.json>
 *
 * The bridge never reads ~/Library/Mail and never mutates message state.
 */

ObjC.import("Foundation");

var SCHEMA_VERSION = 1;
var Mail = Application("/System/Applications/Mail.app");

function unwrap(value) {
  try {
    return ObjC.unwrap(value);
  } catch (_) {
    return value;
  }
}

function stringify(value, fallback) {
  if (value === null || value === undefined) return fallback || "";
  try {
    return String(unwrap(value));
  } catch (_) {
    return fallback || "";
  }
}

function safe(callable, fallback) {
  try {
    var value = callable();
    return value === undefined || value === null ? fallback : value;
  } catch (_) {
    return fallback;
  }
}

function isoDate(value) {
  if (!value) return null;
  try {
    return value.toISOString();
  } catch (_) {
    return stringify(value, null);
  }
}

function readText(path) {
  var error = Ref();
  var value = $.NSString.stringWithContentsOfFileEncodingError(
    $(path),
    $.NSUTF8StringEncoding,
    error
  );
  if (!value) throw new Error("Could not read " + path + ": " + stringify(error[0]));
  return ObjC.unwrap(value);
}

function writeText(path, text) {
  var error = Ref();
  var value = $.NSString.stringWithString(String(text));
  var ok = value.writeToFileAtomicallyEncodingError(
    $(path),
    true,
    $.NSUTF8StringEncoding,
    error
  );
  if (!ok) throw new Error("Could not write " + path + ": " + stringify(error[0]));
}

function appendLine(handle, record) {
  var text = JSON.stringify(record) + "\n";
  var data = $.NSString.stringWithString(text).dataUsingEncoding($.NSUTF8StringEncoding);
  handle.writeData(data);
}

function selectorKey(accountId, path) {
  return String(accountId) + "\u001f" + path.join("\u001f");
}

function getRecipients(message, propertyName) {
  var recipients = safe(function () { return message[propertyName](); }, []);
  return recipients.map(function (recipient) {
    return {
      name: stringify(safe(function () { return recipient.name(); }, "")),
      address: stringify(safe(function () { return recipient.address(); }, ""))
    };
  });
}

function attachmentMetadata(attachment, ordinal) {
  return {
    ordinal: ordinal,
    mail_attachment_id: stringify(safe(function () { return attachment.id(); }, "")),
    name: stringify(safe(function () { return attachment.name(); }, "")),
    mime_type: stringify(safe(function () { return attachment.mimeType(); }, "")),
    file_size: Number(safe(function () { return attachment.fileSize(); }, 0)) || 0,
    downloaded: Boolean(safe(function () { return attachment.downloaded(); }, false))
  };
}

function messageMetadata(message) {
  var attachments = safe(function () { return message.mailAttachments(); }, []);
  return {
    library_id: stringify(safe(function () { return message.id(); }, "")),
    message_id: stringify(safe(function () { return message.messageId(); }, "")),
    subject: stringify(safe(function () { return message.subject(); }, "")),
    sender: stringify(safe(function () { return message.sender(); }, "")),
    reply_to: stringify(safe(function () { return message.replyTo(); }, "")),
    date_sent: isoDate(safe(function () { return message.dateSent(); }, null)),
    date_received: isoDate(safe(function () { return message.dateReceived(); }, null)),
    message_size: Number(safe(function () { return message.messageSize(); }, 0)) || 0,
    read_status: Boolean(safe(function () { return message.readStatus(); }, false)),
    flagged_status: Boolean(safe(function () { return message.flaggedStatus(); }, false)),
    deleted_status: Boolean(safe(function () { return message.deletedStatus(); }, false)),
    junk_mail_status: Boolean(safe(function () { return message.junkMailStatus(); }, false)),
    was_forwarded: Boolean(safe(function () { return message.wasForwarded(); }, false)),
    was_replied_to: Boolean(safe(function () { return message.wasRepliedTo(); }, false)),
    to: getRecipients(message, "toRecipients"),
    cc: getRecipients(message, "ccRecipients"),
    bcc: getRecipients(message, "bccRecipients"),
    attachments: attachments.map(function (attachment, index) {
      return attachmentMetadata(attachment, index + 1);
    })
  };
}

function collectMailboxes() {
  var records = [];
  var objects = {};
  var seen = {};

  function visit(mailbox, accountId, accountName, path, classification) {
    var name = stringify(safe(function () { return mailbox.name(); }, ""));
    var nextPath = path.concat([name]);
    var key = selectorKey(accountId, nextPath);
    if (seen[key]) return;
    seen[key] = true;
    objects[key] = mailbox;
    records.push({
      account_id: accountId,
      account_name: accountName,
      path: nextPath,
      selector: key,
      classification: classification,
      message_count: Number(safe(function () { return mailbox.messages().length; }, 0)) || 0,
      unread_count: Number(safe(function () { return mailbox.unreadCount(); }, 0)) || 0
    });
    var children = safe(function () { return mailbox.mailboxes(); }, []);
    children.forEach(function (child) {
      visit(child, accountId, accountName, nextPath, classification);
    });
  }

  var accounts = safe(function () { return Mail.accounts(); }, []);
  accounts.forEach(function (account) {
    var accountId = stringify(safe(function () { return account.id(); }, ""));
    var accountName = stringify(safe(function () { return account.name(); }, accountId));
    var roots = safe(function () { return account.mailboxes(); }, []);
    roots.forEach(function (mailbox) {
      visit(mailbox, accountId, accountName, [], "account");
    });
  });

  var localRoots = safe(function () { return Mail.mailboxes(); }, []);
  localRoots.forEach(function (mailbox) {
    var account = safe(function () { return mailbox.account(); }, null);
    var accountId = account ? stringify(safe(function () { return account.id(); }, "")) : "local";
    var accountName = account
      ? stringify(safe(function () { return account.name(); }, accountId))
      : "On My Mac / view";
    var classification = account ? "account" : "local-or-view";
    visit(mailbox, accountId || "local", accountName, [], classification);
  });

  return {records: records, objects: objects};
}

function operationPreflight() {
  return {
    schema_version: SCHEMA_VERSION,
    status: "ok",
    mail_name: stringify(Mail.name()),
    mail_version: stringify(Mail.version()),
    account_count: safe(function () { return Mail.accounts().length; }, 0)
  };
}

function operationSelfTest(request) {
  if (request.append_path) {
    writeText(request.append_path, "");
    var handle = $.NSFileHandle.fileHandleForWritingAtPath($(request.append_path));
    if (!handle) throw new Error("Could not open self-test append path");
    appendLine(handle, {schema_version: SCHEMA_VERSION, status: "ok"});
    handle.closeFile;
  }
  return {
    schema_version: SCHEMA_VERSION,
    status: "ok",
    tested_at: new Date().toISOString()
  };
}

function operationInventory() {
  var inventory = collectMailboxes().records;
  inventory.sort(function (a, b) {
    return (a.account_name + "\u001f" + a.path.join("\u001f"))
      .localeCompare(b.account_name + "\u001f" + b.path.join("\u001f"));
  });
  return {
    schema_version: SCHEMA_VERSION,
    generated_at: new Date().toISOString(),
    mail_version: stringify(Mail.version()),
    mailboxes: inventory
  };
}

function selectedKeys(request, inventory) {
  if (request.all === true) {
    var all = {};
    inventory.forEach(function (record) { all[record.selector] = true; });
    return all;
  }
  var chosen = {};
  (request.mailboxes || []).forEach(function (record) {
    chosen[selectorKey(record.account_id, record.path)] = true;
  });
  return chosen;
}

function operationSnapshot(request) {
  var collected = collectMailboxes();
  var wanted = selectedKeys(request.selection, collected.records);
  var outputPath = request.records_path;
  writeText(outputPath, "");
  var handle = $.NSFileHandle.fileHandleForWritingAtPath($(outputPath));
  if (!handle) throw new Error("Could not open snapshot records path " + outputPath);

  var messageCount = 0;
  var attachmentCount = 0;
  var estimatedBytes = 0;
  var selectedMailboxCount = 0;
  try {
    collected.records.forEach(function (mailboxRecord) {
      if (!wanted[mailboxRecord.selector]) return;
      selectedMailboxCount += 1;
      var mailbox = collected.objects[mailboxRecord.selector];
      var messages = safe(function () { return mailbox.messages(); }, []);
      messages.forEach(function (message, ordinal) {
        var metadata = messageMetadata(message);
        var record = {
          schema_version: SCHEMA_VERSION,
          snapshot_id: request.snapshot_id,
          sequence: messageCount + 1,
          account_id: mailboxRecord.account_id,
          account_name: mailboxRecord.account_name,
          mailbox_path: mailboxRecord.path,
          mailbox_selector: mailboxRecord.selector,
          classification: mailboxRecord.classification,
          mailbox_ordinal: ordinal + 1,
          message: metadata
        };
        appendLine(handle, record);
        messageCount += 1;
        attachmentCount += metadata.attachments.length;
        estimatedBytes += metadata.message_size;
      });
    });
  } finally {
    handle.closeFile;
  }

  return {
    schema_version: SCHEMA_VERSION,
    snapshot_id: request.snapshot_id,
    selected_mailbox_count: selectedMailboxCount,
    message_count: messageCount,
    mail_attachment_count: attachmentCount,
    estimated_message_bytes: estimatedBytes,
    records_path: outputPath
  };
}

function operationExport(request) {
  var collected = collectMailboxes();
  var grouped = {};
  (request.items || []).forEach(function (item) {
    if (!grouped[item.mailbox_selector]) grouped[item.mailbox_selector] = [];
    grouped[item.mailbox_selector].push(item);
  });
  var results = [];

  Object.keys(grouped).forEach(function (mailboxSelector) {
    var mailbox = collected.objects[mailboxSelector];
    if (!mailbox) {
      grouped[mailboxSelector].forEach(function (item) {
        results.push({instance_key: item.instance_key, status: "failed", error: "mailbox_not_found"});
      });
      return;
    }

    var byId = {};
    safe(function () { return mailbox.messages(); }, []).forEach(function (message) {
      byId[stringify(safe(function () { return message.id(); }, ""))] = message;
    });

    grouped[mailboxSelector].forEach(function (item) {
      var message = byId[String(item.library_id)];
      if (!message) {
        results.push({instance_key: item.instance_key, status: "failed", error: "message_not_found"});
        return;
      }

      try {
        var source = stringify(message.source(), "");
        if (!source) throw new Error("empty_message_source");
        writeText(item.source_path, source);
        var current = messageMetadata(message);
        var mailAttachments = safe(function () { return message.mailAttachments(); }, []);
        var saved = [];
        mailAttachments.forEach(function (attachment, index) {
          var target = item.attachment_targets[index];
          var entry = attachmentMetadata(attachment, index + 1);
          entry.saved_path = null;
          entry.save_error = null;
          if (!target) {
            entry.save_error = "missing_attachment_target";
          } else {
            try {
              Mail.save(attachment, {in: Path(target)});
              entry.saved_path = target;
            } catch (error) {
              entry.save_error = String(error);
            }
          }
          saved.push(entry);
        });
        results.push({
          instance_key: item.instance_key,
          status: "exported",
          source_path: item.source_path,
          current_message: current,
          mail_attachments: saved
        });
      } catch (error) {
        results.push({
          instance_key: item.instance_key,
          status: "failed",
          error: String(error)
        });
      }
    });
  });

  return {
    schema_version: SCHEMA_VERSION,
    exported_at: new Date().toISOString(),
    results: results
  };
}

function run(argv) {
  if (argv.length !== 3) {
    throw new Error("Expected: <operation> <request.json> <result.json>");
  }
  var operation = argv[0];
  var request = JSON.parse(readText(argv[1]));
  var result;
  if (operation === "selftest") result = operationSelfTest(request);
  else if (operation === "preflight") result = operationPreflight(request);
  else if (operation === "inventory") result = operationInventory(request);
  else if (operation === "snapshot") result = operationSnapshot(request);
  else if (operation === "export") result = operationExport(request);
  else throw new Error("Unsupported operation: " + operation);
  writeText(argv[2], JSON.stringify(result, null, 2) + "\n");
  return JSON.stringify({status: "ok", operation: operation});
}
