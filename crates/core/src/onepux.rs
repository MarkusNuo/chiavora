//! `export.data` is the one member held whole, in a `Zeroizing` buffer; attachments stream.

use std::io::{Read, Seek, Write};

use zeroize::Zeroizing;

use crate::attachment::MAX_ATTACHMENT_BYTES;
use crate::import::{
    attachment_refusal, parse_json, AttachmentHandle, ImportError, ImportReport, Imported,
    ImportedItem, ItemBuilder, Node, Outcome, PreserveReason, RecordReport, RefusalReason,
    SourceFormat, FIELD_NOTES, FIELD_PASSWORD, FIELD_TOTP,
};
use crate::model::{FIELD_TITLE, FIELD_URL, FIELD_USERNAME};
use crate::wrap::ItemKind;
use crate::zip::{self, Archive, Entry, ONE_PUX_LIMITS};

const EXPORT_DATA: &str = "export.data";
const FILES_PREFIX: &str = "files/";
const DOCUMENT_SEPARATOR: &str = "__";

fn category(uuid: &str) -> (&'static str, Option<ItemKind>) {
    match uuid {
        "001" => ("Login", Some(ItemKind::Login)),
        "002" => ("Credit Card", Some(ItemKind::Card)),
        "003" => ("Secure Note", Some(ItemKind::Note)),
        "004" => ("Identity", Some(ItemKind::Identity)),
        "005" => ("Password", Some(ItemKind::Login)),
        "006" => ("Document", Some(ItemKind::Note)),
        "100" => ("Software License", Some(ItemKind::Note)),
        "101" => ("Bank Account", None),
        "102" => ("Database", Some(ItemKind::Login)),
        "103" => ("Driver License", Some(ItemKind::Identity)),
        "104" => ("Outdoor License", None),
        "105" => ("Membership", None),
        "106" => ("Passport", Some(ItemKind::Identity)),
        "107" => ("Reward Program", None),
        "108" => ("Social Security Number", Some(ItemKind::Identity)),
        "109" => ("Wireless Router", Some(ItemKind::Login)),
        "110" => ("Server", Some(ItemKind::Login)),
        "111" => ("Email Account", Some(ItemKind::Login)),
        "112" => ("API Credential", Some(ItemKind::Login)),
        "113" => ("Medical Record", Some(ItemKind::Note)),
        "114" => ("SSH Key", Some(ItemKind::SshKey)),
        _ => ("unknown category", None),
    }
}

pub fn parse<R: Read + Seek>(reader: R) -> Result<(Archive<R>, Imported), ImportError> {
    let mut archive = zip::parse(reader, &ONE_PUX_LIMITS)?;
    let mut report = ImportReport::new(SourceFormat::OnePux);
    for entry in archive.entries() {
        if let Some(refusal) = entry.refusal() {
            report.push_refusal(None, entry.index(), RefusalReason::Zip(refusal.clone()));
        }
    }
    let Some(data_index) = archive.find(EXPORT_DATA) else {
        return Err(ImportError::MissingMember);
    };
    let root = {
        let bytes = archive.read_entry_to_vec(data_index)?;
        parse_json(&bytes)?
    };
    let Some(accounts) = root.get("accounts").and_then(Node::as_list) else {
        return Err(ImportError::NotTheExpectedShape);
    };

    let documents = document_index(archive.entries());
    let mut items = Vec::new();
    let mut index = 0_usize;
    for account in accounts {
        for vault in account.list_of("vaults") {
            for item in vault.list_of("items") {
                let (imported, line) =
                    map_item(item, index, archive.entries(), &documents, &mut report)?;
                items.push(imported);
                report.push_record(line);
                index += 1;
            }
        }
    }
    Ok((archive, Imported { items, report }))
}

/// Refuses before the first byte if its declared size is over the policy limit.
pub fn read_attachment<R: Read + Seek>(
    archive: &mut Archive<R>,
    handle: &AttachmentHandle,
    sink: &mut dyn Write,
) -> Result<u64, ImportError> {
    if handle.declared_len() > MAX_ATTACHMENT_BYTES {
        return Err(ImportError::AttachmentTooLarge {
            max: MAX_ATTACHMENT_BYTES,
        });
    }
    archive
        .read_entry(handle.entry(), sink)
        .map_err(ImportError::from)
}

fn document_index(entries: &[Entry]) -> Vec<(Zeroizing<String>, usize)> {
    entries
        .iter()
        .filter_map(|e| {
            let rest = e.name().strip_prefix(FILES_PREFIX)?;
            let id = match rest.split_once(DOCUMENT_SEPARATOR) {
                Some((id, _)) => id,
                None => rest,
            };
            Some((Zeroizing::new(id.to_owned()), e.index()))
        })
        .collect()
}

struct Context<'a> {
    index: usize,
    entries: &'a [Entry],
    documents: &'a [(Zeroizing<String>, usize)],
    report: &'a mut ImportReport,
}

fn model(index: usize) -> impl Fn(crate::model::ModelError) -> ImportError {
    move |error| ImportError::Model { at: index, error }
}

fn map_item(
    item: &Node,
    index: usize,
    entries: &[Entry],
    documents: &[(Zeroizing<String>, usize)],
    report: &mut ImportReport,
) -> Result<(ImportedItem, RecordReport), ImportError> {
    let Some(pairs) = item.as_object() else {
        let mut b = ItemBuilder::new(ItemKind::Note);
        b.preserved("item", "raw", item.render().as_bytes())
            .map_err(model(index))?;
        return b.finish(
            index,
            "not an object",
            Outcome::PreservedAsNote(PreserveReason::Malformed),
        );
    };
    let uuid = item.str_or_empty("categoryUuid");
    let (name, mapped) = category(uuid);
    let (kind, outcome) = match mapped {
        Some(kind) => (kind, Outcome::Mapped(kind)),
        None => (
            ItemKind::Note,
            Outcome::PreservedAsNote(PreserveReason::UnknownType),
        ),
    };
    let mut b = ItemBuilder::new(kind);
    let mut cx = Context {
        index,
        entries,
        documents,
        report,
    };

    for (key, value) in pairs {
        match key.as_str() {
            "categoryUuid" => {}
            "uuid" => put(&mut b, index, "uuid", "source id", value)?,
            "createdAt" => put(&mut b, index, "createdAt", "created", value)?,
            "updatedAt" => put(&mut b, index, "updatedAt", "updated", value)?,
            "state" => match value.as_str() {
                Some("active") => {}
                Some("archived") => b.tag("archived"),
                _ => keep(&mut b, index, "state", "state", value)?,
            },
            "trashed" => {
                if matches!(value, Node::Bool(true)) {
                    b.tag("trashed");
                }
            }
            "favIndex" => {
                if !matches!(value, Node::Number(n) if n.as_str() == "0") && !value.is_empty() {
                    b.tag("favourite");
                }
            }
            "overview" => map_overview(&mut b, index, value)?,
            "details" => map_details(&mut b, &mut cx, value)?,
            other => keep(&mut b, index, &format!("item.{other}"), other, value)?,
        }
    }

    let source_type = if uuid.is_empty() {
        name.to_owned()
    } else {
        format!("{name} ({uuid})")
    };
    b.finish(index, &source_type, outcome)
}

fn next_url_name(b: &ItemBuilder) -> String {
    if !b.has_field(FIELD_URL) {
        return FIELD_URL.to_owned();
    }
    for n in 2_u32.. {
        let candidate = format!("{FIELD_URL} {n}");
        if !b.has_field(&candidate) {
            return candidate;
        }
    }
    FIELD_URL.to_owned()
}

fn put(
    b: &mut ItemBuilder,
    index: usize,
    from: &str,
    to: &str,
    value: &Node,
) -> Result<(), ImportError> {
    if value.is_empty() {
        return Ok(());
    }
    b.field(from, to, value.text().as_bytes())
        .map_err(model(index))
}

fn keep(
    b: &mut ItemBuilder,
    index: usize,
    from: &str,
    to: &str,
    value: &Node,
) -> Result<(), ImportError> {
    if value.is_empty() {
        return Ok(());
    }
    b.preserved(from, to, value.text().as_bytes())
        .map_err(model(index))
}

fn map_overview(b: &mut ItemBuilder, index: usize, overview: &Node) -> Result<(), ImportError> {
    let Some(pairs) = overview.as_object() else {
        return keep(b, index, "item.overview", "overview", overview);
    };
    for (key, value) in pairs {
        match key.as_str() {
            "title" => put(b, index, "overview.title", FIELD_TITLE, value)?,
            "url" => put(b, index, "overview.url", FIELD_URL, value)?,
            "urls" => {
                for (i, entry) in value.items().iter().enumerate() {
                    let from = format!("overview.urls[{i}]");
                    let Some(url) = entry.get("url") else {
                        keep(b, index, &from, "url entry", entry)?;
                        continue;
                    };
                    let to = if let Some(existing) = b.name_of_value(url.text().as_bytes()) {
                        existing.to_owned()
                    } else {
                        let to = next_url_name(b);
                        put(b, index, &format!("{from}.url"), &to, url)?;
                        to
                    };
                    for (k, v) in entry.pairs() {
                        if k != "url" {
                            keep(b, index, &format!("{from}.{k}"), &format!("{to} {k}"), v)?;
                        }
                    }
                }
            }
            "tags" => {
                for tag in value.items() {
                    if let Some(t) = tag.as_str() {
                        b.tag(t);
                    } else {
                        keep(b, index, "overview.tags", "tag", tag)?;
                    }
                }
            }
            other => keep(b, index, &format!("overview.{other}"), other, value)?,
        }
    }
    Ok(())
}

fn map_details(
    b: &mut ItemBuilder,
    cx: &mut Context<'_>,
    details: &Node,
) -> Result<(), ImportError> {
    let index = cx.index;
    let Some(pairs) = details.as_object() else {
        return keep(b, index, "item.details", "details", details);
    };
    for (key, value) in pairs {
        match key.as_str() {
            "loginFields" => {
                for (i, field) in value.items().iter().enumerate() {
                    let from = format!("details.loginFields[{i}]");
                    let Some(v) = field.get("value") else {
                        keep(b, index, &from, "login field", field)?;
                        continue;
                    };
                    let to = match field.str_or_empty("designation") {
                        "username" => FIELD_USERNAME.to_owned(),
                        "password" => FIELD_PASSWORD.to_owned(),
                        _ => {
                            let name = field.str_or_empty("name");
                            if name.is_empty() {
                                let id = field.str_or_empty("id");
                                if id.is_empty() {
                                    format!("login field {}", i + 1)
                                } else {
                                    id.to_owned()
                                }
                            } else {
                                name.to_owned()
                            }
                        }
                    };
                    put(b, index, &from, &to, v)?;
                }
            }
            "notesPlain" => put(b, index, "details.notesPlain", FIELD_NOTES, value)?,
            "password" => put(b, index, "details.password", FIELD_PASSWORD, value)?,
            "sections" => {
                for (i, section) in value.items().iter().enumerate() {
                    map_section(b, cx, i, section)?;
                }
            }
            "passwordHistory" => {
                for (i, past) in value.items().iter().enumerate() {
                    let n = i + 1;
                    if let Some(v) = past.get("value") {
                        keep(
                            b,
                            index,
                            &format!("details.passwordHistory[{i}].value"),
                            &format!("password history {n}"),
                            v,
                        )?;
                    }
                    if let Some(t) = past.get("time") {
                        keep(
                            b,
                            index,
                            &format!("details.passwordHistory[{i}].time"),
                            &format!("password history {n} time"),
                            t,
                        )?;
                    }
                }
            }
            "documentAttributes" => {
                attach(
                    b,
                    cx,
                    "details.documentAttributes",
                    value.str_or_empty("documentId"),
                    value.str_or_empty("fileName"),
                )?;
                for (k, v) in value.pairs() {
                    if k != "documentId" && k != "fileName" {
                        keep(
                            b,
                            index,
                            &format!("details.documentAttributes.{k}"),
                            &format!("document {k}"),
                            v,
                        )?;
                    }
                }
            }
            other => keep(b, index, &format!("details.{other}"), other, value)?,
        }
    }
    Ok(())
}

fn map_section(
    b: &mut ItemBuilder,
    cx: &mut Context<'_>,
    i: usize,
    section: &Node,
) -> Result<(), ImportError> {
    let index = cx.index;
    let section_title = {
        let t = section.str_or_empty("title");
        if t.is_empty() {
            section.str_or_empty("name")
        } else {
            t
        }
    };
    let Some(pairs) = section.as_object() else {
        return keep(
            b,
            index,
            &format!("details.sections[{i}]"),
            "section",
            section,
        );
    };
    for (key, value) in pairs {
        match key.as_str() {
            "title" | "name" => {}
            "fields" => {
                for (j, field) in value.items().iter().enumerate() {
                    let from = format!("details.sections[{i}].fields[{j}]");
                    let field_title = {
                        let t = field.str_or_empty("title");
                        if t.is_empty() {
                            field.str_or_empty("id")
                        } else {
                            t
                        }
                    };
                    let name = if section_title.is_empty() {
                        field_title.to_owned()
                    } else if field_title.is_empty() {
                        section_title.to_owned()
                    } else {
                        format!("{section_title}/{field_title}")
                    };
                    let Some(value) = field.get("value") else {
                        keep(b, index, &from, &name, field)?;
                        continue;
                    };
                    map_section_value(b, cx, &from, &name, value)?;
                    for (k, v) in field.pairs() {
                        if !matches!(
                            k,
                            "title"
                                | "id"
                                | "value"
                                | "guarded"
                                | "multiline"
                                | "dontGenerate"
                                | "inputTraits"
                                | "clipboardFilter"
                        ) {
                            keep(b, index, &format!("{from}.{k}"), &format!("{name} {k}"), v)?;
                        }
                    }
                }
            }
            other => keep(
                b,
                index,
                &format!("details.sections[{i}].{other}"),
                &format!("{section_title} {other}"),
                value,
            )?,
        }
    }
    Ok(())
}

/// A section field's `value` is an object with one key naming its kind.
fn map_section_value(
    b: &mut ItemBuilder,
    cx: &mut Context<'_>,
    from: &str,
    name: &str,
    value: &Node,
) -> Result<(), ImportError> {
    let index = cx.index;
    let Some(pairs) = value.as_object() else {
        return put(b, index, from, name, value);
    };
    let [(kind, inner)] = pairs else {
        return keep(b, index, from, name, value);
    };
    match kind.as_str() {
        "totp" => {
            let to = if b.has_field(FIELD_TOTP) {
                name
            } else {
                FIELD_TOTP
            };
            put(b, index, from, to, inner)
        }
        "file" => {
            attach(
                b,
                cx,
                from,
                inner.str_or_empty("documentId"),
                inner.str_or_empty("fileName"),
            )?;
            for (k, v) in inner.pairs() {
                if k != "documentId" && k != "fileName" {
                    keep(
                        b,
                        index,
                        &format!("{from}.file.{k}"),
                        &format!("{name} {k}"),
                        v,
                    )?;
                }
            }
            Ok(())
        }
        "address" => {
            for (k, v) in inner.pairs() {
                put(
                    b,
                    index,
                    &format!("{from}.address.{k}"),
                    &format!("{name}/{k}"),
                    v,
                )?;
            }
            Ok(())
        }
        "sshKey" => {
            let plain = b.kind() == ItemKind::SshKey;
            for (k, v) in inner.pairs() {
                if k == "metadata" {
                    for (mk, mv) in v.pairs() {
                        let to = if plain {
                            mk.to_owned()
                        } else {
                            format!("{name}/{mk}")
                        };
                        put(b, index, &format!("{from}.sshKey.metadata.{mk}"), &to, mv)?;
                    }
                } else {
                    let to = if plain {
                        k.to_owned()
                    } else {
                        format!("{name}/{k}")
                    };
                    put(b, index, &format!("{from}.sshKey.{k}"), &to, v)?;
                }
            }
            Ok(())
        }
        "concealed" | "string" | "url" | "email" | "phone" | "menu" | "gender" | "monthYear"
        | "date" | "creditCardNumber" | "creditCardType" | "reference" => {
            put(b, index, from, name, inner)
        }
        _ => keep(b, index, from, name, inner),
    }
}

fn attach(
    b: &mut ItemBuilder,
    cx: &mut Context<'_>,
    from: &str,
    document_id: &str,
    file_name: &str,
) -> Result<(), ImportError> {
    let index = cx.index;
    let Some(&(_, entry_index)) = cx
        .documents
        .iter()
        .find(|(id, _)| id.as_str() == document_id)
    else {
        let what = if file_name.is_empty() {
            "attachment"
        } else {
            file_name
        };
        return b
            .preserved(
                from,
                &format!("{what} (missing from archive)"),
                document_id.as_bytes(),
            )
            .map_err(model(index));
    };
    let Some(entry) = cx.entries.get(entry_index) else {
        return Ok(());
    };
    let name = if file_name.is_empty() {
        entry.name()
    } else {
        file_name
    };
    match attachment_refusal(entry.refusal(), entry.uncompressed_len()) {
        Some(reason) => {
            b.attachment_refused(from, &reason);
            cx.report.push_refusal(Some(index), entry_index, reason);
        }
        None => b.attachment(
            from,
            AttachmentHandle::new(index, entry_index, name, entry.uncompressed_len()),
        ),
    }
    Ok(())
}
