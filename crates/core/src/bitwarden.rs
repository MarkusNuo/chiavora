//! Read whole, up to `MAX_DOCUMENT_BYTES`, into a `Zeroizing` buffer (§3.3).

use std::io::{BufRead, Read};

use zeroize::Zeroizing;

use crate::import::{
    parse_json, ImportError, ImportReport, Imported, ImportedItem, ItemBuilder, Node, Outcome,
    PreserveReason, RecordReport, SourceFormat, FIELD_NOTES, FIELD_PASSWORD, FIELD_TOTP,
    MAX_DOCUMENT_BYTES,
};
use crate::model::{FIELD_TITLE, FIELD_URL, FIELD_USERNAME};
use crate::wrap::ItemKind;

fn item_type(node: &Node) -> (&'static str, Option<ItemKind>) {
    match node.get("type").map(Node::text) {
        Some(t) if t.as_str() == "1" => ("Login", Some(ItemKind::Login)),
        Some(t) if t.as_str() == "2" => ("Secure Note", Some(ItemKind::Note)),
        Some(t) if t.as_str() == "3" => ("Card", Some(ItemKind::Card)),
        Some(t) if t.as_str() == "4" => ("Identity", Some(ItemKind::Identity)),
        Some(t) if t.as_str() == "5" => ("SSH Key", Some(ItemKind::SshKey)),
        _ => ("unknown type", None),
    }
}

pub fn parse<R: BufRead>(mut reader: R) -> Result<Imported, ImportError> {
    // R1: at most one byte past MAX_DOCUMENT_BYTES is read, and that byte is the refusal.
    let mut bytes: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
    reader
        .by_ref()
        .take(MAX_DOCUMENT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_DOCUMENT_BYTES {
        return Err(ImportError::DocumentTooLarge {
            max: MAX_DOCUMENT_BYTES,
        });
    }
    let root = parse_json(&bytes)?;
    drop(bytes);

    if matches!(root.get("encrypted"), Some(Node::Bool(true))) {
        return Err(ImportError::EncryptedExport);
    }
    let Some(items) = root.get("items").and_then(Node::as_list) else {
        return Err(ImportError::NotTheExpectedShape);
    };

    let folders = names_by_id(root.list_of("folders"));
    let collections = names_by_id(root.list_of("collections"));
    let mut report = ImportReport::new(SourceFormat::Bitwarden);
    let mut out = Vec::new();
    for (index, item) in items.iter().enumerate() {
        let (imported, line) = map_item(item, index, &folders, &collections)?;
        out.push(imported);
        report.push_record(line);
    }
    Ok(Imported { items: out, report })
}

fn names_by_id(list: &[Node]) -> Vec<(Zeroizing<String>, Zeroizing<String>)> {
    list.iter()
        .filter_map(|n| {
            let id = n.str_or_empty("id");
            let name = n.str_or_empty("name");
            if id.is_empty() {
                None
            } else {
                Some((
                    Zeroizing::new(id.to_owned()),
                    Zeroizing::new(name.to_owned()),
                ))
            }
        })
        .collect()
}

fn name_for<'a>(table: &'a [(Zeroizing<String>, Zeroizing<String>)], id: &str) -> Option<&'a str> {
    table
        .iter()
        .find(|(k, _)| k.as_str() == id)
        .map(|(_, v)| v.as_str())
}

fn model(index: usize) -> impl Fn(crate::model::ModelError) -> ImportError {
    move |error| ImportError::Model { at: index, error }
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

fn map_item(
    item: &Node,
    index: usize,
    folders: &[(Zeroizing<String>, Zeroizing<String>)],
    collections: &[(Zeroizing<String>, Zeroizing<String>)],
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
    let (name, mapped) = item_type(item);
    let (kind, outcome) = match mapped {
        Some(kind) => (kind, Outcome::Mapped(kind)),
        None => (
            ItemKind::Note,
            Outcome::PreservedAsNote(PreserveReason::UnknownType),
        ),
    };
    let mut b = ItemBuilder::new(kind);
    for (key, value) in pairs {
        match key.as_str() {
            "type" => {}
            "id" => put(&mut b, index, "id", "source id", value)?,
            "name" => put(&mut b, index, "name", FIELD_TITLE, value)?,
            "notes" => put(&mut b, index, "notes", FIELD_NOTES, value)?,
            "favorite" => {
                if matches!(value, Node::Bool(true)) {
                    b.tag("favourite");
                }
            }
            "deletedDate" => {
                if !value.is_empty() {
                    b.tag("trashed");
                    keep(&mut b, index, "deletedDate", "deleted", value)?;
                }
            }
            "creationDate" => put(&mut b, index, "creationDate", "created", value)?,
            "revisionDate" => put(&mut b, index, "revisionDate", "updated", value)?,
            "folderId" => match value.as_str().and_then(|id| name_for(folders, id)) {
                Some(folder) => b.tag(folder),
                None => keep(&mut b, index, "folderId", "folder id", value)?,
            },
            "collectionIds" => {
                for (i, id) in value.items().iter().enumerate() {
                    match id.as_str().and_then(|id| name_for(collections, id)) {
                        Some(collection) => b.tag(collection),
                        None => keep(
                            &mut b,
                            index,
                            &format!("collectionIds[{i}]"),
                            "collection id",
                            id,
                        )?,
                    }
                }
            }
            "login" => map_login(&mut b, index, value)?,
            "card" => map_flat(
                &mut b,
                index,
                "card",
                value,
                &[
                    ("cardholderName", "cardholder"),
                    ("number", "number"),
                    ("code", "cvv"),
                ],
            )?,
            "identity" => map_flat(&mut b, index, "identity", value, &[])?,
            "sshKey" => map_flat(&mut b, index, "sshKey", value, &[])?,
            "secureNote" => {
                // `{"type": 0}` carries nothing a note needs; any other key is kept.
                for (k, v) in value.pairs() {
                    if k != "type" {
                        keep(&mut b, index, &format!("secureNote.{k}"), k, v)?;
                    }
                }
            }
            "fields" => map_fields(&mut b, index, value)?,
            "passwordHistory" => map_history(&mut b, index, value)?,
            other => keep(&mut b, index, &format!("item.{other}"), other, value)?,
        }
    }
    b.finish(index, name, outcome)
}

fn map_fields(b: &mut ItemBuilder, index: usize, value: &Node) -> Result<(), ImportError> {
    for (i, field) in value.items().iter().enumerate() {
        let from = format!("fields[{i}]");
        let Some(v) = field.get("value") else {
            keep(b, index, &from, "field", field)?;
            continue;
        };
        let n = field.str_or_empty("name");
        let to = if n.is_empty() {
            format!("field {}", i + 1)
        } else {
            n.to_owned()
        };
        if field.str_or_empty("type") == "3"
            || matches!(field.get("type"), Some(Node::Number(t)) if t.as_str() == "3")
        {
            keep(
                b,
                index,
                &format!("{from}.linkedId"),
                &format!("{to} (linked)"),
                field.get("linkedId").map_or(&Node::Null, |l| l),
            )?;
        } else {
            put(b, index, &from, &to, v)?;
        }
    }
    Ok(())
}

fn map_history(b: &mut ItemBuilder, index: usize, value: &Node) -> Result<(), ImportError> {
    for (i, past) in value.items().iter().enumerate() {
        let n = i + 1;
        if let Some(v) = past.get("password") {
            keep(
                b,
                index,
                &format!("passwordHistory[{i}].password"),
                &format!("password history {n}"),
                v,
            )?;
        }
        if let Some(t) = past.get("lastUsedDate") {
            keep(
                b,
                index,
                &format!("passwordHistory[{i}].lastUsedDate"),
                &format!("password history {n} time"),
                t,
            )?;
        }
    }
    Ok(())
}

fn map_login(b: &mut ItemBuilder, index: usize, login: &Node) -> Result<(), ImportError> {
    for (key, value) in login.pairs() {
        match key {
            "username" => put(b, index, "login.username", FIELD_USERNAME, value)?,
            "password" => put(b, index, "login.password", FIELD_PASSWORD, value)?,
            "totp" => put(b, index, "login.totp", FIELD_TOTP, value)?,
            "uris" => {
                for (i, entry) in value.items().iter().enumerate() {
                    let from = format!("login.uris[{i}]");
                    let Some(uri) = entry.get("uri") else {
                        keep(b, index, &from, "uri entry", entry)?;
                        continue;
                    };
                    let to = if let Some(existing) = b.name_of_value(uri.text().as_bytes()) {
                        existing.to_owned()
                    } else {
                        let to = next_url_name(b);
                        put(b, index, &format!("{from}.uri"), &to, uri)?;
                        to
                    };
                    for (k, v) in entry.pairs() {
                        if k != "uri" {
                            keep(b, index, &format!("{from}.{k}"), &format!("{to} {k}"), v)?;
                        }
                    }
                }
            }
            other => keep(b, index, &format!("login.{other}"), other, value)?,
        }
    }
    Ok(())
}

fn map_flat(
    b: &mut ItemBuilder,
    index: usize,
    from: &str,
    object: &Node,
    renames: &[(&str, &str)],
) -> Result<(), ImportError> {
    if object.as_object().is_none() {
        return keep(b, index, from, from, object);
    }
    for (key, value) in object.pairs() {
        let to = renames
            .iter()
            .find(|(k, _)| *k == key)
            .map_or(key, |(_, v)| *v);
        put(b, index, &format!("{from}.{key}"), to, value)?;
    }
    Ok(())
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
