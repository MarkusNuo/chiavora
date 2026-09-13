//! Nothing from a foreign vault is dropped silently: an unmapped record becomes a secure note.

use core::fmt;

use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use zeroize::Zeroizing;

use crate::attachment::MAX_ATTACHMENT_BYTES;
use crate::model::{Item, ItemField, ModelError, FIELD_TITLE, MAX_FIELD_NAME_BYTES, MAX_TAG_BYTES};
use crate::wrap::ItemKind;
use crate::zip::ZipError;

pub const FIELD_PASSWORD: &str = "password";
pub const FIELD_NOTES: &str = "notes";
/// The field a TOTP secret lands in; it stays on the login (ADR-0003).
pub const FIELD_TOTP: &str = "totp";
pub const MAX_RECORD_BYTES: usize = 16 << 20;
pub const MAX_FIELDS_PER_RECORD: usize = 256;
/// The bound on a whole JSON document (Bitwarden), the same as a 1PUX member.
pub const MAX_DOCUMENT_BYTES: usize = 256 << 20;
const UNNAMED: &str = "field";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Durability {
    /// Every importer parses to completion first, and the caller writes through
    /// [`crate::store::Store::begin_bulk`].
    AllOrNothing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceFormat {
    OnePux,
    OnePif,
    Bitwarden,
    LastPass,
    Chrome,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Mapped(ItemKind),
    PreservedAsNote(PreserveReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreserveReason {
    UnknownType,
    Malformed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MoveKind {
    Mapped,
    Preserved,
    Renamed,
    Attachment,
    AttachmentRefused,
}

pub struct FieldMove {
    from: Zeroizing<String>,
    to: Zeroizing<String>,
    kind: MoveKind,
}

impl FieldMove {
    #[must_use]
    pub fn from(&self) -> &str {
        &self.from
    }

    #[must_use]
    pub fn to(&self) -> &str {
        &self.to
    }

    #[must_use]
    pub const fn kind(&self) -> MoveKind {
        self.kind
    }
}

impl fmt::Debug for FieldMove {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FieldMove({:?}, redacted)", self.kind)
    }
}

pub struct RecordReport {
    index: usize,
    title: Zeroizing<String>,
    source_type: Zeroizing<String>,
    outcome: Outcome,
    moves: Vec<FieldMove>,
}

impl RecordReport {
    #[must_use]
    pub const fn index(&self) -> usize {
        self.index
    }

    #[must_use]
    pub fn title(&self) -> &str {
        &self.title
    }

    #[must_use]
    pub fn source_type(&self) -> &str {
        &self.source_type
    }

    #[must_use]
    pub const fn outcome(&self) -> Outcome {
        self.outcome
    }

    #[must_use]
    pub fn moves(&self) -> &[FieldMove] {
        &self.moves
    }
}

impl fmt::Debug for RecordReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RecordReport(#{}, {:?}, {} moves, redacted)",
            self.index,
            self.outcome,
            self.moves.len()
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefusalReason {
    Zip(ZipError),
    /// Refused before any of it is read.
    AttachmentTooLarge {
        max: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryRefusal {
    record: Option<usize>,
    entry: usize,
    reason: RefusalReason,
}

impl EntryRefusal {
    #[must_use]
    pub const fn record(&self) -> Option<usize> {
        self.record
    }

    #[must_use]
    pub const fn entry(&self) -> usize {
        self.entry
    }

    #[must_use]
    pub const fn reason(&self) -> &RefusalReason {
        &self.reason
    }
}

pub struct ImportReport {
    format: SourceFormat,
    records: Vec<RecordReport>,
    refusals: Vec<EntryRefusal>,
}

impl ImportReport {
    pub(crate) const fn new(format: SourceFormat) -> Self {
        Self {
            format,
            records: Vec::new(),
            refusals: Vec::new(),
        }
    }

    #[must_use]
    pub const fn format(&self) -> SourceFormat {
        self.format
    }

    #[must_use]
    pub const fn durability(&self) -> Durability {
        Durability::AllOrNothing
    }

    #[must_use]
    pub fn records(&self) -> &[RecordReport] {
        &self.records
    }

    #[must_use]
    pub fn refusals(&self) -> &[EntryRefusal] {
        &self.refusals
    }

    #[must_use]
    pub fn mapped(&self) -> usize {
        self.records
            .iter()
            .filter(|r| matches!(r.outcome, Outcome::Mapped(_)))
            .count()
    }

    #[must_use]
    pub fn preserved(&self) -> usize {
        self.records.len() - self.mapped()
    }

    pub(crate) fn push_record(&mut self, record: RecordReport) {
        self.records.push(record);
    }

    pub(crate) fn push_refusal(
        &mut self,
        record: Option<usize>,
        entry: usize,
        reason: RefusalReason,
    ) {
        self.refusals.push(EntryRefusal {
            record,
            entry,
            reason,
        });
    }
}

impl fmt::Debug for ImportReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ImportReport({:?}, {} records, {} mapped, {} preserved, {} refusals, redacted)",
            self.format,
            self.records.len(),
            self.mapped(),
            self.preserved(),
            self.refusals.len()
        )
    }
}

/// An attachment not yet read; the caller streams it with `onepux::read_attachment`.
pub struct AttachmentHandle {
    record: usize,
    entry: usize,
    file_name: Zeroizing<String>,
    declared_len: u64,
}

impl AttachmentHandle {
    pub(crate) fn new(record: usize, entry: usize, file_name: &str, declared_len: u64) -> Self {
        Self {
            record,
            entry,
            file_name: Zeroizing::new(file_name.to_owned()),
            declared_len,
        }
    }

    #[must_use]
    pub const fn record(&self) -> usize {
        self.record
    }

    #[must_use]
    pub const fn entry(&self) -> usize {
        self.entry
    }

    /// The file name the source gave it, which is content.
    #[must_use]
    pub fn file_name(&self) -> &str {
        &self.file_name
    }

    /// The declared uncompressed length, already under [`MAX_ATTACHMENT_BYTES`].
    #[must_use]
    pub const fn declared_len(&self) -> u64 {
        self.declared_len
    }
}

impl fmt::Debug for AttachmentHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "AttachmentHandle(record {}, entry {}, {} bytes, name redacted)",
            self.record, self.entry, self.declared_len
        )
    }
}

#[derive(Debug)]
pub struct ImportedItem {
    pub item: Item,
    pub attachments: Vec<AttachmentHandle>,
}

#[derive(Debug)]
pub struct Imported {
    pub items: Vec<ImportedItem>,
    /// `report.records().len() == items.len()`, always.
    pub report: ImportReport,
}

/// Positions and bounds; never content.
#[derive(Debug)]
pub enum ImportError {
    Zip(ZipError),
    Io(std::io::ErrorKind),
    MissingMember,
    Json {
        /// 1-based line.
        line: usize,
        /// 1-based column.
        column: usize,
    },
    NotTheExpectedShape,
    RecordTooLong {
        /// 0-based record index.
        at: usize,
        max: usize,
    },
    Model {
        /// 0-based record index.
        at: usize,
        error: ModelError,
    },
    AttachmentTooLarge {
        max: u64,
    },
    EncryptedExport,
    TooManyFields {
        /// 0-based row index.
        at: usize,
        max: usize,
    },
    DocumentTooLarge {
        max: usize,
    },
}

impl fmt::Display for ImportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Zip(e) => write!(f, "archive: {e}"),
            Self::Io(kind) => write!(f, "i/o: {kind:?}"),
            Self::MissingMember => f.write_str("the archive has no export.data"),
            Self::Json { line, column } => {
                write!(f, "JSON did not parse at line {line}, column {column}")
            }
            Self::NotTheExpectedShape => {
                f.write_str("the document root is not the shape this format promises")
            }
            Self::RecordTooLong { at, max } => write!(f, "record {at} is longer than {max} bytes"),
            Self::Model { at, error } => {
                write!(f, "record {at} was refused by the item model: {error}")
            }
            Self::AttachmentTooLarge { max } => {
                write!(f, "attachment declares more than {max} bytes")
            }
            Self::EncryptedExport => {
                f.write_str("the export is encrypted; nothing in it can be read")
            }
            Self::TooManyFields { at, max } => write!(f, "row {at} has more than {max} fields"),
            Self::DocumentTooLarge { max } => write!(f, "the document is longer than {max} bytes"),
        }
    }
}

impl core::error::Error for ImportError {}

impl From<ZipError> for ImportError {
    fn from(e: ZipError) -> Self {
        Self::Zip(e)
    }
}

impl From<std::io::Error> for ImportError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.kind())
    }
}

/// Numbers are kept as text, since one may be a card number. `serde_json`'s own scratch
/// buffer for escaped strings is cleared but not zeroized.
pub enum Node {
    Null,
    Bool(bool),
    Number(Zeroizing<String>),
    Text(Zeroizing<String>),
    List(Vec<Node>),
    /// An object, in document order, duplicates kept.
    Object(Vec<(Zeroizing<String>, Node)>),
}

impl fmt::Debug for Node {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Null => f.write_str("Node::Null"),
            Self::Bool(b) => write!(f, "Node::Bool({b})"),
            Self::Number(_) => f.write_str("Node::Number(redacted)"),
            Self::Text(t) => write!(f, "Node::Text({} bytes, redacted)", t.len()),
            Self::List(l) => write!(f, "Node::List({} items)", l.len()),
            Self::Object(o) => write!(f, "Node::Object({} keys)", o.len()),
        }
    }
}

impl Node {
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Node> {
        match self {
            Self::Object(pairs) => pairs
                .iter()
                .find(|(k, _)| k.as_str() == key)
                .map(|(_, v)| v),
            _ => None,
        }
    }

    #[must_use]
    pub fn str_of(&self, key: &str) -> Option<&str> {
        self.get(key).and_then(Node::as_str)
    }

    #[must_use]
    pub fn str_or_empty(&self, key: &str) -> &str {
        match self.get(key) {
            Some(Node::Text(t)) => t,
            _ => "",
        }
    }

    #[must_use]
    pub fn list_of(&self, key: &str) -> &[Node] {
        match self.get(key) {
            Some(Node::List(l)) => l,
            _ => &[],
        }
    }

    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Text(t) => Some(t),
            _ => None,
        }
    }

    #[must_use]
    pub fn items(&self) -> &[Node] {
        match self {
            Self::List(l) => l,
            _ => &[],
        }
    }

    #[must_use]
    pub fn as_list(&self) -> Option<&[Node]> {
        match self {
            Self::List(l) => Some(l),
            _ => None,
        }
    }

    pub fn pairs(&self) -> impl Iterator<Item = (&str, &Node)> {
        self.as_object()
            .into_iter()
            .flatten()
            .map(|(k, v)| (k.as_str(), v))
    }

    #[must_use]
    pub fn as_object(&self) -> Option<&[(Zeroizing<String>, Node)]> {
        match self {
            Self::Object(o) => Some(o),
            _ => None,
        }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        match self {
            Self::Null => true,
            Self::Text(t) => t.is_empty(),
            Self::List(l) => l.is_empty(),
            Self::Object(o) => o.is_empty(),
            Self::Bool(_) | Self::Number(_) => false,
        }
    }

    #[must_use]
    pub fn text(&self) -> Zeroizing<String> {
        match self {
            Self::Null => Zeroizing::new(String::new()),
            Self::Bool(b) => Zeroizing::new(b.to_string()),
            Self::Number(n) | Self::Text(n) => n.clone(),
            Self::List(_) | Self::Object(_) => self.render(),
        }
    }

    #[must_use]
    pub fn render(&self) -> Zeroizing<String> {
        let mut out = Zeroizing::new(String::new());
        self.render_into(&mut out);
        out
    }

    fn render_into(&self, out: &mut String) {
        match self {
            Self::Null => out.push_str("null"),
            Self::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Self::Number(n) => out.push_str(n),
            Self::Text(t) => push_json_string(out, t),
            Self::List(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    item.render_into(out);
                }
                out.push(']');
            }
            Self::Object(pairs) => {
                out.push('{');
                for (i, (k, v)) in pairs.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    push_json_string(out, k);
                    out.push(':');
                    v.render_into(out);
                }
                out.push('}');
            }
        }
    }
}

fn push_json_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if u32::from(c) < 0x20 => {
                out.push_str("\\u00");
                let code = u32::from(c);
                out.push(hex_digit(code >> 4));
                out.push(hex_digit(code & 0xF));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn hex_digit(nibble: u32) -> char {
    match nibble & 0xF {
        0 => '0',
        1 => '1',
        2 => '2',
        3 => '3',
        4 => '4',
        5 => '5',
        6 => '6',
        7 => '7',
        8 => '8',
        9 => '9',
        10 => 'a',
        11 => 'b',
        12 => 'c',
        13 => 'd',
        14 => 'e',
        _ => 'f',
    }
}

impl<'de> Deserialize<'de> for Node {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(NodeVisitor)
    }
}

struct NodeVisitor;

impl<'de> Visitor<'de> for NodeVisitor {
    type Value = Node;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("any JSON value")
    }

    fn visit_unit<E: de::Error>(self) -> Result<Node, E> {
        Ok(Node::Null)
    }

    fn visit_none<E: de::Error>(self) -> Result<Node, E> {
        Ok(Node::Null)
    }

    fn visit_some<D: Deserializer<'de>>(self, d: D) -> Result<Node, D::Error> {
        Node::deserialize(d)
    }

    fn visit_bool<E: de::Error>(self, b: bool) -> Result<Node, E> {
        Ok(Node::Bool(b))
    }

    fn visit_i64<E: de::Error>(self, n: i64) -> Result<Node, E> {
        Ok(Node::Number(Zeroizing::new(n.to_string())))
    }

    fn visit_u64<E: de::Error>(self, n: u64) -> Result<Node, E> {
        Ok(Node::Number(Zeroizing::new(n.to_string())))
    }

    fn visit_f64<E: de::Error>(self, n: f64) -> Result<Node, E> {
        Ok(Node::Number(Zeroizing::new(n.to_string())))
    }

    fn visit_str<E: de::Error>(self, s: &str) -> Result<Node, E> {
        Ok(Node::Text(Zeroizing::new(s.to_owned())))
    }

    fn visit_string<E: de::Error>(self, s: String) -> Result<Node, E> {
        Ok(Node::Text(Zeroizing::new(s)))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Node, A::Error> {
        let mut items = Vec::new();
        while let Some(item) = seq.next_element::<Node>()? {
            items.push(item);
        }
        Ok(Node::List(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Node, A::Error> {
        let mut pairs = Vec::new();
        while let Some(key) = map.next_key::<String>()? {
            let value = map.next_value::<Node>()?;
            pairs.push((Zeroizing::new(key), value));
        }
        Ok(Node::Object(pairs))
    }
}

pub fn parse_json(bytes: &[u8]) -> Result<Node, ImportError> {
    serde_json::from_slice::<Node>(bytes).map_err(|e| ImportError::Json {
        line: e.line(),
        column: e.column(),
    })
}

pub struct ItemBuilder {
    kind: ItemKind,
    fields: Vec<ItemField>,
    tags: Vec<Zeroizing<String>>,
    moves: Vec<FieldMove>,
    attachments: Vec<AttachmentHandle>,
}

impl fmt::Debug for ItemBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ItemBuilder({:?}, {} fields, {} tags, {} attachments, redacted)",
            self.kind,
            self.fields.len(),
            self.tags.len(),
            self.attachments.len()
        )
    }
}

impl ItemBuilder {
    #[must_use]
    pub const fn new(kind: ItemKind) -> Self {
        Self {
            kind,
            fields: Vec::new(),
            tags: Vec::new(),
            moves: Vec::new(),
            attachments: Vec::new(),
        }
    }

    #[must_use]
    pub const fn kind(&self) -> ItemKind {
        self.kind
    }

    #[must_use]
    pub fn has_field(&self, name: &str) -> bool {
        self.fields.iter().any(|f| f.name().as_str() == name)
    }

    #[must_use]
    pub fn name_of_value(&self, value: &[u8]) -> Option<&str> {
        self.fields
            .iter()
            .find(|f| f.value() == value)
            .map(|f| f.name().as_str())
    }

    pub fn field(&mut self, from: &str, to: &str, value: &[u8]) -> Result<(), ModelError> {
        self.add(from, to, value, MoveKind::Mapped)
    }

    pub fn preserved(&mut self, from: &str, to: &str, value: &[u8]) -> Result<(), ModelError> {
        self.add(from, to, value, MoveKind::Preserved)
    }

    fn add(
        &mut self,
        from: &str,
        to: &str,
        value: &[u8],
        kind: MoveKind,
    ) -> Result<(), ModelError> {
        let wanted = if to.is_empty() { UNNAMED } else { to };
        let bounded = bounded(wanted, MAX_FIELD_NAME_BYTES);
        let unique = self.unique(&bounded);
        let kind = if unique.as_str() == to {
            kind
        } else {
            MoveKind::Renamed
        };
        self.fields.push(ItemField::new(&unique, value.to_vec())?);
        self.moves.push(FieldMove {
            from: Zeroizing::new(from.to_owned()),
            to: unique,
            kind,
        });
        Ok(())
    }

    fn unique(&self, name: &str) -> Zeroizing<String> {
        if !self.has_field(name) {
            return Zeroizing::new(name.to_owned());
        }
        for n in 2_u32.. {
            let suffix = format!(" ({n})");
            let head = bounded(name, MAX_FIELD_NAME_BYTES.saturating_sub(suffix.len()));
            let candidate = format!("{head}{suffix}");
            if !self.has_field(&candidate) {
                return Zeroizing::new(candidate);
            }
        }
        Zeroizing::new(name.to_owned())
    }

    pub fn tag(&mut self, tag: &str) {
        let bounded = bounded(tag, MAX_TAG_BYTES);
        if bounded.is_empty() || self.tags.iter().any(|t| t.as_str() == bounded) {
            return;
        }
        self.tags.push(Zeroizing::new(bounded));
    }

    pub fn attachment(&mut self, from: &str, handle: AttachmentHandle) {
        self.moves.push(FieldMove {
            from: Zeroizing::new(from.to_owned()),
            to: handle.file_name.clone(),
            kind: MoveKind::Attachment,
        });
        self.attachments.push(handle);
    }

    /// The record's line for a refused attachment; the refusal itself is in the report.
    pub fn attachment_refused(&mut self, from: &str, reason: &RefusalReason) {
        let why = match reason {
            RefusalReason::Zip(e) => format!("refused: {e}"),
            RefusalReason::AttachmentTooLarge { max } => format!("refused: over {max} bytes"),
        };
        self.moves.push(FieldMove {
            from: Zeroizing::new(from.to_owned()),
            to: Zeroizing::new(why),
            kind: MoveKind::AttachmentRefused,
        });
    }

    pub fn finish(
        mut self,
        index: usize,
        source_type: &str,
        outcome: Outcome,
    ) -> Result<(ImportedItem, RecordReport), ImportError> {
        if !self.has_field(FIELD_TITLE) {
            self.fields.push(
                ItemField::new(FIELD_TITLE, Vec::new())
                    .map_err(|error| ImportError::Model { at: index, error })?,
            );
        }
        let title = self
            .fields
            .iter()
            .find(|f| f.name().as_str() == FIELD_TITLE)
            .map_or_else(String::new, |f| {
                String::from_utf8_lossy(f.value()).into_owned()
            });
        let tag_refs: Vec<&str> = self.tags.iter().map(|t| t.as_str()).collect();
        let item = Item::new(self.kind, self.fields, &tag_refs)
            .map_err(|error| ImportError::Model { at: index, error })?;
        Ok((
            ImportedItem {
                item,
                attachments: self.attachments,
            },
            RecordReport {
                index,
                title: Zeroizing::new(title),
                source_type: Zeroizing::new(source_type.to_owned()),
                outcome,
                moves: self.moves,
            },
        ))
    }
}

fn bounded(name: &str, max: usize) -> String {
    if name.len() <= max {
        return name.to_owned();
    }
    let mut end = max;
    while end > 0 && !name.is_char_boundary(end) {
        end -= 1;
    }
    name.get(..end).map_or_else(String::new, str::to_owned)
}

#[must_use]
pub fn attachment_refusal(
    zip_refusal: Option<&ZipError>,
    declared_len: u64,
) -> Option<RefusalReason> {
    if let Some(e) = zip_refusal {
        return Some(RefusalReason::Zip(e.clone()));
    }
    if declared_len > MAX_ATTACHMENT_BYTES {
        return Some(RefusalReason::AttachmentTooLarge {
            max: MAX_ATTACHMENT_BYTES,
        });
    }
    None
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
mod tests {
    use super::*;

    #[test]
    fn render_escapes_what_json_requires() {
        let node = Node::Object(vec![(
            Zeroizing::new("k\"ey".to_owned()),
            Node::List(vec![
                Node::Text(Zeroizing::new("a\nb\\c\u{1}".to_owned())),
                Node::Number(Zeroizing::new("42".to_owned())),
                Node::Bool(true),
                Node::Null,
            ]),
        )]);
        assert_eq!(
            node.render().as_str(),
            "{\"k\\\"ey\":[\"a\\nb\\\\c\\u0001\",42,true,null]}"
        );
    }

    #[test]
    fn parse_json_keeps_order_duplicates_and_numbers_as_text() {
        let node = parse_json(br#"{"b":1,"a":"x","b":2.5,"n":null}"#).unwrap();
        let pairs = node.as_object().unwrap();
        let keys: Vec<&str> = pairs.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys, ["b", "a", "b", "n"]);
        assert_eq!(node.get("b").unwrap().text().as_str(), "1");
        assert_eq!(pairs[2].1.text().as_str(), "2.5");
        assert!(node.get("n").unwrap().is_empty());
    }

    #[test]
    fn a_json_error_names_a_position_only() {
        let err = parse_json(b"{\"secret\": \"hunter2\" oops").unwrap_err();
        let text = err.to_string();
        assert!(matches!(err, ImportError::Json { .. }));
        assert!(!text.contains("hunter2"), "{text}");
    }

    #[test]
    fn names_are_bounded_and_made_unique_and_both_are_recorded() {
        let mut b = ItemBuilder::new(ItemKind::Note);
        b.field("f1", "dup", b"1").unwrap();
        b.field("f2", "dup", b"2").unwrap();
        let long = "x".repeat(300);
        b.field("f3", &long, b"3").unwrap();
        let (item, report) = b
            .finish(0, "test", Outcome::Mapped(ItemKind::Note))
            .unwrap();
        let names: Vec<&str> = item.item.fields().map(|f| f.name().as_str()).collect();
        assert_eq!(names, ["dup", "dup (2)", &"x".repeat(256), "title"]);
        let kinds: Vec<MoveKind> = report.moves().iter().map(FieldMove::kind).collect();
        assert_eq!(
            kinds,
            [MoveKind::Mapped, MoveKind::Renamed, MoveKind::Renamed]
        );
    }

    #[test]
    fn debug_is_redacted_everywhere() {
        let mut b = ItemBuilder::new(ItemKind::Login);
        b.field("password", "password", b"hunter2-canary").unwrap();
        b.field("title", "title", b"title-canary").unwrap();
        let (item, report) = b
            .finish(0, "type-canary", Outcome::Mapped(ItemKind::Login))
            .unwrap();
        let mut full = ImportReport::new(SourceFormat::OnePux);
        full.push_record(report);
        let rendered = format!(
            "{full:?} {item:?} {:?}",
            Node::Text(Zeroizing::new("text-canary".to_owned()))
        );
        for canary in [
            "hunter2-canary",
            "title-canary",
            "type-canary",
            "text-canary",
        ] {
            assert!(!rendered.contains(canary), "{rendered}");
        }
    }
}
