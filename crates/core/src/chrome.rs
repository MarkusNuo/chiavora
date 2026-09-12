use std::io::BufRead;

use crate::csv::{self, column, row_has_columns, Header, Row};
use crate::import::{
    ImportError, ImportReport, Imported, ImportedItem, ItemBuilder, Outcome, PreserveReason,
    RecordReport, SourceFormat, FIELD_PASSWORD,
};
use crate::model::{FIELD_TITLE, FIELD_URL, FIELD_USERNAME};
use crate::wrap::ItemKind;

const REQUIRED_COLUMNS: [&str; 3] = ["url", "username", "password"];
const MAPPED_COLUMNS: [&str; 4] = ["name", "url", "username", "password"];

pub fn parse<R: BufRead>(reader: R) -> Result<Imported, ImportError> {
    let mut report = ImportReport::new(SourceFormat::Chrome);
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

fn map_row(
    header: &Header,
    row: &Row,
    index: usize,
) -> Result<(ImportedItem, RecordReport), ImportError> {
    if header.index_of("url").is_none() {
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
        return b.finish(
            index,
            "row without a header",
            Outcome::PreservedAsNote(PreserveReason::Malformed),
        );
    }
    let mut b = ItemBuilder::new(ItemKind::Login);
    put(
        &mut b,
        index,
        "name",
        FIELD_TITLE,
        column(header, row, "name"),
    )?;
    put(&mut b, index, "url", FIELD_URL, column(header, row, "url"))?;
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
    for (i, value) in row.iter().enumerate() {
        let name = header.name_at(i);
        if !MAPPED_COLUMNS.contains(&name.as_str()) {
            keep(&mut b, index, &format!("row[{i}]"), &name, value)?;
        }
    }
    b.finish(index, "Login", Outcome::Mapped(ItemKind::Login))
}
