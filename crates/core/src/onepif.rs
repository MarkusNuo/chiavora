//! Read line by line, each record bounded by [`MAX_RECORD_BYTES`]; the file is never held whole.

use std::io::{BufRead, Read};

use zeroize::Zeroizing;

use crate::import::{
    parse_json, ImportError, ImportReport, Imported, ImportedItem, ItemBuilder, Node, Outcome,
    PreserveReason, RecordReport, SourceFormat, FIELD_NOTES, FIELD_PASSWORD, FIELD_TOTP,
    MAX_RECORD_BYTES,
};
use crate::model::{FIELD_TITLE, FIELD_URL, FIELD_USERNAME};
use crate::wrap::ItemKind;

const SEPARATOR_PREFIX: &[u8] = b"***";
const BOM: &[u8] = b"\xEF\xBB\xBF";

fn type_name(name: &str) -> (&'static str, Option<ItemKind>) {
    match name {
        "webforms.WebForm" => ("Login", Some(ItemKind::Login)),
        "passwords.Password" => ("Password", Some(ItemKind::Login)),
        "securenotes.SecureNote" => ("Secure Note", Some(ItemKind::Note)),
        "wallet.financial.CreditCard" => ("Credit Card", Some(ItemKind::Card)),
        "identities.Identity" => ("Identity", Some(ItemKind::Identity)),
        "wallet.government.Passport" => ("Passport", Some(ItemKind::Identity)),
        "wallet.government.DriversLicense" => ("Driver License", Some(ItemKind::Identity)),
        "wallet.government.SsnUS" => ("Social Security Number", Some(ItemKind::Identity)),
        "wallet.computer.UnixServer" => ("Server", Some(ItemKind::Login)),
        "wallet.computer.Database" => ("Database", Some(ItemKind::Login)),
        "wallet.computer.Router" => ("Wireless Router", Some(ItemKind::Login)),
        "wallet.computer.License" => ("Software License", Some(ItemKind::Note)),
        "wallet.onlineservices.Email"
        | "wallet.onlineservices.GenericAccount"
        | "wallet.onlineservices.ISP"
        | "wallet.onlineservices.FTP"
        | "wallet.onlineservices.InstantMessenger"
        | "wallet.onlineservices.AmazonS3"
        | "wallet.onlineservices.DotMac"
        | "wallet.onlineservices.iTunes" => ("Online Service", Some(ItemKind::Login)),
        "wallet.financial.BankAccountUS" => ("Bank Account", None),
        "wallet.membership.Membership" => ("Membership", None),
        "wallet.membership.RewardProgram" => ("Reward Program", None),
        "wallet.government.HuntingLicense" => ("Outdoor License", None),
        _ => ("unknown type", None),
    }
}

pub fn parse<R: BufRead>(mut reader: R) -> Result<Imported, ImportError> {
    let mut report = ImportReport::new(SourceFormat::OnePif);
    let mut items = Vec::new();
    let mut line: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
    let mut index = 0_usize;
    let mut first = true;
    let limit = MAX_RECORD_BYTES as u64 + 1;
    loop {
        line.clear();
        let read = reader.by_ref().take(limit).read_until(b'\n', &mut line)?;
        if read == 0 {
            break;
        }
        if line.len() > MAX_RECORD_BYTES {
            return Err(ImportError::RecordTooLong {
                at: index,
                max: MAX_RECORD_BYTES,
            });
        }
        let mut text: &[u8] = &line;
        if first {
            first = false;
            if let Some(rest) = text.strip_prefix(BOM) {
                text = rest;
            }
        }
        let text = trim(text);
        if text.is_empty() || text.starts_with(SEPARATOR_PREFIX) {
            continue;
        }
        let (imported, record) = match parse_json(text) {
            Ok(node) => map_record(&node, index)?,
            Err(_) => raw_line(text, index)?,
        };
        items.push(imported);
        report.push_record(record);
        index += 1;
    }
    Ok(Imported { items, report })
}

fn trim(mut bytes: &[u8]) -> &[u8] {
    while let Some((&first, rest)) = bytes.split_first() {
        if matches!(first, b' ' | b'\t' | b'\r' | b'\n') {
            bytes = rest;
        } else {
            break;
        }
    }
    while let Some((&last, rest)) = bytes.split_last() {
        if matches!(last, b' ' | b'\t' | b'\r' | b'\n') {
            bytes = rest;
        } else {
            break;
        }
    }
    bytes
}

fn model(index: usize) -> impl Fn(crate::model::ModelError) -> ImportError {
    move |error| ImportError::Model { at: index, error }
}

fn raw_line(text: &[u8], index: usize) -> Result<(ImportedItem, RecordReport), ImportError> {
    let mut b = ItemBuilder::new(ItemKind::Note);
    b.preserved("line", "raw", text).map_err(model(index))?;
    b.finish(
        index,
        "not JSON",
        Outcome::PreservedAsNote(PreserveReason::Malformed),
    )
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

fn map_record(record: &Node, index: usize) -> Result<(ImportedItem, RecordReport), ImportError> {
    let Some(pairs) = record.as_object() else {
        let mut b = ItemBuilder::new(ItemKind::Note);
        b.preserved("record", "raw", record.render().as_bytes())
            .map_err(model(index))?;
        return b.finish(
            index,
            "not an object",
            Outcome::PreservedAsNote(PreserveReason::Malformed),
        );
    };
    let type_str = record.str_or_empty("typeName");
    let (name, mapped) = type_name(type_str);
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
            "typeName" => {}
            "uuid" => put(&mut b, index, "uuid", "source id", value)?,
            "title" => put(&mut b, index, "title", FIELD_TITLE, value)?,
            "location" => put(&mut b, index, "location", FIELD_URL, value)?,
            "createdAt" => put(&mut b, index, "createdAt", "created", value)?,
            "updatedAt" => put(&mut b, index, "updatedAt", "updated", value)?,
            "trashed" => {
                if matches!(value, Node::Bool(true)) {
                    b.tag("trashed");
                }
            }
            "faveIndex" => {
                if !value.is_empty() && !matches!(value, Node::Number(n) if n.as_str() == "0") {
                    b.tag("favourite");
                }
            }
            "openContents" => map_open(&mut b, index, value)?,
            "secureContents" => map_secure(&mut b, index, value)?,
            other => keep(&mut b, index, &format!("record.{other}"), other, value)?,
        }
    }
    let source_type = if type_str.is_empty() {
        name.to_owned()
    } else {
        format!("{name} ({type_str})")
    };
    b.finish(index, &source_type, outcome)
}

fn map_open(b: &mut ItemBuilder, index: usize, open: &Node) -> Result<(), ImportError> {
    let Some(pairs) = open.as_object() else {
        return keep(b, index, "record.openContents", "openContents", open);
    };
    for (key, value) in pairs {
        match key.as_str() {
            "tags" => {
                for tag in value.items() {
                    if let Some(t) = tag.as_str() {
                        b.tag(t);
                    } else {
                        keep(b, index, "openContents.tags", "tag", tag)?;
                    }
                }
            }
            "faveIndex" => {
                if !value.is_empty() && !matches!(value, Node::Number(n) if n.as_str() == "0") {
                    b.tag("favourite");
                }
            }
            other => keep(b, index, &format!("openContents.{other}"), other, value)?,
        }
    }
    Ok(())
}

fn map_secure(b: &mut ItemBuilder, index: usize, secure: &Node) -> Result<(), ImportError> {
    let Some(pairs) = secure.as_object() else {
        return keep(b, index, "record.secureContents", "secureContents", secure);
    };
    for (key, value) in pairs {
        match key.as_str() {
            "fields" => {
                for (i, field) in value.items().iter().enumerate() {
                    let from = format!("secureContents.fields[{i}]");
                    let Some(v) = field.get("value") else {
                        keep(b, index, &from, "form field", field)?;
                        continue;
                    };
                    let to = match field.str_or_empty("designation") {
                        "username" => FIELD_USERNAME.to_owned(),
                        "password" => FIELD_PASSWORD.to_owned(),
                        _ => {
                            let n = field.str_or_empty("name");
                            if n.is_empty() {
                                format!("form field {}", i + 1)
                            } else {
                                n.to_owned()
                            }
                        }
                    };
                    put(b, index, &from, &to, v)?;
                }
            }
            "password" => put(b, index, "secureContents.password", FIELD_PASSWORD, value)?,
            "notesPlain" => put(b, index, "secureContents.notesPlain", FIELD_NOTES, value)?,
            "URLs" => {
                for (i, entry) in value.items().iter().enumerate() {
                    let from = format!("secureContents.URLs[{i}]");
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
            "sections" => {
                for (i, section) in value.items().iter().enumerate() {
                    map_section(b, index, i, section)?;
                }
            }
            other => keep(b, index, &format!("secureContents.{other}"), other, value)?,
        }
    }
    Ok(())
}

fn map_section(
    b: &mut ItemBuilder,
    index: usize,
    i: usize,
    section: &Node,
) -> Result<(), ImportError> {
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
            &format!("secureContents.sections[{i}]"),
            "section",
            section,
        );
    };
    for (key, value) in pairs {
        match key.as_str() {
            "title" | "name" => {}
            "fields" => {
                for (j, field) in value.items().iter().enumerate() {
                    let from = format!("secureContents.sections[{i}].fields[{j}]");
                    let field_title = {
                        let t = field.str_or_empty("t");
                        if t.is_empty() {
                            field.str_or_empty("n")
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
                    let Some(v) = field.get("v") else {
                        keep(b, index, &from, &name, field)?;
                        continue;
                    };
                    let kind = field.str_or_empty("k");
                    let is_totp = kind == "TOTP" || field.str_or_empty("n").starts_with("TOTP_");
                    if is_totp {
                        let to = if b.has_field(FIELD_TOTP) {
                            name.as_str()
                        } else {
                            FIELD_TOTP
                        };
                        put(b, index, &from, to, v)?;
                    } else if kind == "address" {
                        for (ak, av) in v.pairs() {
                            put(
                                b,
                                index,
                                &format!("{from}.v.{ak}"),
                                &format!("{name}/{ak}"),
                                av,
                            )?;
                        }
                    } else {
                        put(b, index, &from, &name, v)?;
                    }
                }
            }
            other => keep(
                b,
                index,
                &format!("secureContents.sections[{i}].{other}"),
                &format!("{section_title} {other}"),
                value,
            )?,
        }
    }
    Ok(())
}
