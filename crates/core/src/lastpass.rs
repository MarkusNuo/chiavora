//! Columns are mapped by header name, since the set varies by version.

use std::io::BufRead;

use zeroize::Zeroizing;

use crate::csv::{self, column, row_has_columns, Header, Row};
use crate::import::{
    ImportError, ImportReport, Imported, ImportedItem, ItemBuilder, Outcome, PreserveReason,
    RecordReport, SourceFormat, FIELD_NOTES, FIELD_PASSWORD, FIELD_TOTP,
};
use crate::model::{FIELD_TITLE, FIELD_URL, FIELD_USERNAME};
use crate::wrap::ItemKind;

const SECURE_NOTE_URL: &str = "http://sn";
const REQUIRED_COLUMNS: [&str; 2] = ["url", "password"];
const KNOWN_COLUMNS: [&str; 8] = [
    "url", "username", "password", "totp", "extra", "name", "grouping", "fav",
];

fn template_kind(note_type: &str) -> Option<ItemKind> {
    match note_type.trim().to_ascii_lowercase().as_str() {
        "credit card" => Some(ItemKind::Card),
        "address" | "driver's license" | "drivers license" | "passport" | "social security" => {
            Some(ItemKind::Identity)
        }
        "server" | "database" | "email account" | "instant messenger" | "wi-fi password"
        | "wifi password" => Some(ItemKind::Login),
        "ssh key" => Some(ItemKind::SshKey),
        "generic" | "software license" | "health insurance" | "insurance" => Some(ItemKind::Note),
        _ => None,
    }
}

fn template_field(key: &str) -> &str {
    match key.trim().to_ascii_lowercase().as_str() {
        "username" => FIELD_USERNAME,
        "password" => FIELD_PASSWORD,
        "url" | "hostname" => FIELD_URL,
        "notes" => FIELD_NOTES,
        _ => key.trim(),
    }
}

pub fn parse<R: BufRead>(reader: R) -> Result<Imported, ImportError> {
    let mut report = ImportReport::new(SourceFormat::LastPass);
    let mut items = Vec::new();
    let mut header: Option<Header> = None;
    let mut index = 0_usize;
    csv::parse(reader, |_, row| {
        let Some(h) = header.as_ref() else {
            if row_has_columns(&row, &REQUIRED_COLUMNS) {
                header = Some(Header::from_row(&row));
            } else {
                let h = Header::positional(row.len());
                let (item, line) = map_row(&h, &row, index)?;
                items.push(item);
                report.push_record(line);
                index += 1;
                header = Some(h);
            }
            return Ok(());
        };
        if row.iter().all(|f| f.trim().is_empty()) {
            return Ok(());
        }
        let (item, line) = map_row(h, &row, index)?;
        items.push(item);
        report.push_record(line);
        index += 1;
        Ok(())
    })?;
    Ok(Imported { items, report })
}

fn model(index: usize) -> impl Fn(crate::model::ModelError) -> ImportError {
    move |error| ImportError::Model { at: index, error }
}

fn put(
    b: &mut ItemBuilder,
    index: usize,
    from: &str,
    to: &str,
    value: &str,
) -> Result<(), ImportError> {
    if value.is_empty() {
        return Ok(());
    }
    b.field(from, to, value.as_bytes()).map_err(model(index))
}

fn keep(
    b: &mut ItemBuilder,
    index: usize,
    from: &str,
    to: &str,
    value: &str,
) -> Result<(), ImportError> {
    if value.is_empty() {
        return Ok(());
    }
    b.preserved(from, to, value.as_bytes())
        .map_err(model(index))
}

fn positional_row(
    header: &Header,
    row: &Row,
    index: usize,
) -> Result<(ImportedItem, RecordReport), ImportError> {
    let mut b = ItemBuilder::new(ItemKind::Note);
    for (i, value) in row.iter().enumerate() {
        keep(
            &mut b,
            index,
            &format!("row[{i}]"),
            &header.name_at(i),
            value,
        )?;
    }
    b.finish(
        index,
        "row without a header",
        Outcome::PreservedAsNote(PreserveReason::Malformed),
    )
}

fn map_row(
    header: &Header,
    row: &Row,
    index: usize,
) -> Result<(ImportedItem, RecordReport), ImportError> {
    if header.index_of("url").is_none() {
        return positional_row(header, row, index);
    }

    let url = column(header, row, "url");
    let extra = column(header, row, "extra");
    let is_note = url.trim() == SECURE_NOTE_URL;

    let (mut b, source_type, outcome) = if is_note {
        match template(extra) {
            Some((note_type, _)) => {
                let kind = template_kind(note_type);
                let source_type = format!("Secure Note ({})", note_type.trim());
                match kind {
                    Some(kind) => (ItemBuilder::new(kind), source_type, Outcome::Mapped(kind)),
                    None => (
                        ItemBuilder::new(ItemKind::Note),
                        source_type,
                        Outcome::PreservedAsNote(PreserveReason::UnknownType),
                    ),
                }
            }
            None => (
                ItemBuilder::new(ItemKind::Note),
                "Secure Note".to_owned(),
                Outcome::Mapped(ItemKind::Note),
            ),
        }
    } else {
        (
            ItemBuilder::new(ItemKind::Login),
            "Login".to_owned(),
            Outcome::Mapped(ItemKind::Login),
        )
    };

    put(
        &mut b,
        index,
        "name",
        FIELD_TITLE,
        column(header, row, "name"),
    )?;
    if !is_note {
        put(&mut b, index, "url", FIELD_URL, url)?;
    }
    put(
        &mut b,
        index,
        "username",
        FIELD_USERNAME,
        column(header, row, "username"),
    )?;
    put(
        &mut b,
        index,
        "password",
        FIELD_PASSWORD,
        column(header, row, "password"),
    )?;
    put(
        &mut b,
        index,
        "totp",
        FIELD_TOTP,
        column(header, row, "totp"),
    )?;

    if is_note {
        match template(extra) {
            Some((_, body)) => map_template(&mut b, index, body)?,
            None => put(&mut b, index, "extra", FIELD_NOTES, extra)?,
        }
    } else {
        put(&mut b, index, "extra", FIELD_NOTES, extra)?;
    }

    let grouping = column(header, row, "grouping").trim();
    if !grouping.is_empty() {
        b.tag(grouping);
    }
    if matches!(column(header, row, "fav").trim(), "1" | "true") {
        b.tag("favourite");
    }
    for (i, value) in row.iter().enumerate() {
        let name = header.name_at(i);
        if !KNOWN_COLUMNS.contains(&name.as_str()) {
            keep(&mut b, index, &format!("row[{i}]"), &name, value)?;
        }
    }
    b.finish(index, &source_type, outcome)
}

fn template(extra: &str) -> Option<(&str, &str)> {
    let rest = extra.strip_prefix("NoteType:")?;
    match rest.split_once('\n') {
        Some((note_type, body)) => Some((note_type.trim_end_matches('\r'), body)),
        None => Some((rest, "")),
    }
}

fn map_template(b: &mut ItemBuilder, index: usize, body: &str) -> Result<(), ImportError> {
    let mut notes: Zeroizing<String> = Zeroizing::new(String::new());
    let mut rest = body;
    while !rest.is_empty() {
        let (line, after) = match rest.split_once('\n') {
            Some((l, a)) => (l.trim_end_matches('\r'), a),
            None => (rest.trim_end_matches('\r'), ""),
        };
        if let Some(remainder) = line.strip_prefix("Notes:") {
            notes.push_str(remainder);
            if !after.is_empty() {
                notes.push('\n');
                notes.push_str(after);
            }
            break;
        }
        match line.split_once(':') {
            Some((key, value)) if !key.trim().is_empty() => {
                put(
                    b,
                    index,
                    &format!("extra.{}", key.trim()),
                    template_field(key),
                    value,
                )?;
            }
            _ => {
                if !notes.is_empty() {
                    notes.push('\n');
                }
                notes.push_str(line);
            }
        }
        rest = after;
    }
    put(b, index, "extra.Notes", FIELD_NOTES, &notes)
}
