//! The encrypted `CHVX` backup, and plaintext for leaving the product.

use core::fmt;
use std::io::{Read, Seek, SeekFrom, Write};

use chiavora_protocol::{Field, Record, Tag, WireError};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::derive::{derive_export_key, DeriveError};
use crate::import::{Node, FIELD_PASSWORD};
use crate::model::{Item, FIELD_TITLE, FIELD_URL, FIELD_USERNAME};
use crate::secret::{kind::Muk, Secret};
use crate::store::{Store, StoreError};
use crate::wrap::ItemKind;

pub const MAGIC: &[u8; 4] = b"CHVX";
pub const VERSION: u16 = 1;
pub const MAX_ENTRY_BYTES: usize = 16 << 20;

const MAC_LEN: usize = 32;
const KIND_END: u8 = 0x00;
const KIND_RECORD: u8 = 0x01;
const KIND_CHUNK: u8 = 0x02;

type HmacSha256 = Hmac<Sha256>;

pub mod tag {
    use chiavora_protocol::Tag;

    pub const VAULT_ID: Tag = 1;
    pub const GENERATION: Tag = 2;
    pub const HIGH_WATER_MARK: Tag = 3;
    pub const RECORDS: Tag = 4;
    pub const CHUNKS: Tag = 5;
    pub const ITEM_ID: Tag = 6;
    pub const VERSION: Tag = 7;
    pub const BYTES: Tag = 8;
    pub const ATTACHMENT_ID: Tag = 9;
    pub const CHUNK_INDEX: Tag = 10;
}

/// Positions and counts; never content.
#[derive(Debug)]
pub enum ExportError {
    Store(StoreError),
    Derive(DeriveError),
    Wire(WireError),
    Io(std::io::ErrorKind),
    /// The MAC construction refused the key length (R1: propagated).
    MacKeyLength,
    BadMagic,
    UnsupportedVersion {
        version: u16,
    },
    Truncated {
        at: u64,
    },
    EntryTooLarge {
        at: u64,
        max: usize,
    },
    UnknownEntryKind {
        at: u64,
        kind: u8,
    },
    MissingField {
        at: u64,
        tag: Tag,
    },
    Malformed {
        at: u64,
    },
    MacMismatch,
    CountMismatch {
        declared: u64,
        found: u64,
    },
    TrailingBytes {
        at: u64,
    },
    StoreNotFresh,
    Vanished {
        at: u64,
    },
}

impl fmt::Display for ExportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(e) => write!(f, "store: {e}"),
            Self::Derive(e) => write!(f, "key derivation: {e}"),
            Self::Wire(e) => write!(f, "record: {e}"),
            Self::Io(kind) => write!(f, "i/o: {kind:?}"),
            Self::MacKeyLength => f.write_str("the MAC refused the Export Key's length"),
            Self::BadMagic => f.write_str("not a CHVX export"),
            Self::UnsupportedVersion { version } => write!(
                f,
                "container version {version} is not readable by this build"
            ),
            Self::Truncated { at } => {
                write!(f, "the file ends at byte {at}, before its structure does")
            }
            Self::EntryTooLarge { at, max } => {
                write!(f, "the entry at byte {at} declares more than {max} bytes")
            }
            Self::UnknownEntryKind { at, kind } => {
                write!(f, "unknown entry kind {kind:#04x} at byte {at}")
            }
            Self::MissingField { at, tag } => {
                write!(f, "the record at byte {at} lacks field {tag}")
            }
            Self::Malformed { at } => write!(f, "the record at byte {at} is malformed"),
            Self::MacMismatch => f.write_str(
                "the file's MAC does not match: tampered, truncated, or not this vault's",
            ),
            Self::CountMismatch { declared, found } => write!(
                f,
                "the header declares {declared} entries, the file holds {found}"
            ),
            Self::TrailingBytes { at } => write!(f, "bytes after the MAC, from byte {at}"),
            Self::StoreNotFresh => f.write_str("the destination store already holds this vault"),
            Self::Vanished { at } => write!(
                f,
                "item {at} vanished from the store between listing and reading"
            ),
        }
    }
}

impl core::error::Error for ExportError {}

impl From<StoreError> for ExportError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}

impl From<DeriveError> for ExportError {
    fn from(e: DeriveError) -> Self {
        Self::Derive(e)
    }
}

impl From<WireError> for ExportError {
    fn from(e: WireError) -> Self {
        Self::Wire(e)
    }
}

impl From<std::io::Error> for ExportError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.kind())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Summary {
    pub records: u64,
    pub chunks: u64,
    pub bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    vault_id: Vec<u8>,
    generation: u64,
    high_water_mark: Option<u64>,
    records: u64,
    chunks: u64,
}

impl Header {
    #[must_use]
    pub fn vault_id(&self) -> &[u8] {
        &self.vault_id
    }

    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    #[must_use]
    pub const fn high_water_mark(&self) -> Option<u64> {
        self.high_water_mark
    }

    #[must_use]
    pub const fn records(&self) -> u64 {
        self.records
    }

    #[must_use]
    pub const fn chunks(&self) -> u64 {
        self.chunks
    }
}

struct Tee<W: Write> {
    sink: W,
    mac: HmacSha256,
    bytes: u64,
}

impl<W: Write> Write for Tee<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.sink.write_all(buf)?;
        self.mac.update(buf);
        self.bytes = self.bytes.saturating_add(buf.len() as u64);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.sink.flush()
    }
}

fn new_mac(muk: &Secret<Muk>) -> Result<HmacSha256, ExportError> {
    let key = derive_export_key(muk)?;
    <HmacSha256 as Mac>::new_from_slice(key.expose()).map_err(|_| ExportError::MacKeyLength)
}

fn framed<W: Write>(out: &mut W, kind: Option<u8>, bytes: &[u8]) -> Result<(), ExportError> {
    if let Some(kind) = kind {
        out.write_all(&[kind])?;
    }
    let len = u32::try_from(bytes.len()).map_err(|_| ExportError::EntryTooLarge {
        at: 0,
        max: MAX_ENTRY_BYTES,
    })?;
    out.write_all(&len.to_le_bytes())?;
    out.write_all(bytes)?;
    Ok(())
}

fn u64_field(tag: Tag, value: u64) -> Result<Field, WireError> {
    Field::new(tag, value.to_le_bytes().to_vec())
}

pub fn write<W: Write>(
    store: &Store,
    vault_id: &[u8],
    muk: &Secret<Muk>,
    sink: W,
) -> Result<Summary, ExportError> {
    let mut out = Tee {
        sink,
        mac: new_mac(muk)?,
        bytes: 0,
    };
    let items = store.list(vault_id)?;
    let mut chunk_total: u64 = 0;
    let mut attachments: Vec<(Vec<u8>, Vec<Vec<u8>>)> = Vec::new();
    for (item_id, _) in &items {
        let ids = store.list_attachments(vault_id, item_id)?;
        for attachment_id in &ids {
            let count = store.list_chunks(vault_id, item_id, attachment_id)?.len();
            chunk_total = chunk_total.saturating_add(count as u64);
        }
        attachments.push((item_id.clone(), ids));
    }

    out.write_all(MAGIC)?;
    out.write_all(&VERSION.to_le_bytes())?;
    let mut header = vec![
        Field::new(tag::VAULT_ID, vault_id.to_vec())?,
        u64_field(tag::GENERATION, store.generation())?,
    ];
    if let Some(hwm) = store.high_water_mark(vault_id) {
        header.push(u64_field(tag::HIGH_WATER_MARK, hwm)?);
    }
    header.push(u64_field(tag::RECORDS, items.len() as u64)?);
    header.push(u64_field(tag::CHUNKS, chunk_total)?);
    framed(&mut out, None, &Record::new(header).encode()?)?;

    for (position, (item_id, _)) in items.iter().enumerate() {
        let raw = store
            .get_raw(vault_id, item_id)?
            .ok_or(ExportError::Vanished {
                at: position as u64,
            })?;
        let record = Record::new(vec![
            Field::new(tag::ITEM_ID, item_id.clone())?,
            u64_field(tag::VERSION, raw.version)?,
            Field::new(tag::BYTES, raw.bytes)?,
        ]);
        framed(&mut out, Some(KIND_RECORD), &record.encode()?)?;
    }
    let mut chunks_written: u64 = 0;
    for (item_id, ids) in &attachments {
        for attachment_id in ids {
            for index in store.list_chunks(vault_id, item_id, attachment_id)? {
                let bytes = store
                    .get_chunk_raw(vault_id, item_id, attachment_id, index)?
                    .ok_or(ExportError::Vanished { at: chunks_written })?;
                let record = Record::new(vec![
                    Field::new(tag::ITEM_ID, item_id.clone())?,
                    Field::new(tag::ATTACHMENT_ID, attachment_id.clone())?,
                    Field::new(tag::CHUNK_INDEX, index.to_le_bytes().to_vec())?,
                    Field::new(tag::BYTES, bytes)?,
                ]);
                framed(&mut out, Some(KIND_CHUNK), &record.encode()?)?;
                chunks_written = chunks_written.saturating_add(1);
            }
        }
    }
    out.write_all(&[KIND_END])?;
    let Tee {
        mut sink,
        mac,
        bytes,
    } = out;
    let trailer = mac.finalize().into_bytes();
    sink.write_all(&trailer)?;
    sink.flush()?;
    Ok(Summary {
        records: items.len() as u64,
        chunks: chunks_written,
        bytes: bytes.saturating_add(MAC_LEN as u64),
    })
}

struct Framed<R: Read> {
    reader: R,
    mac: HmacSha256,
    at: u64,
}

impl<R: Read> Framed<R> {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), ExportError> {
        self.reader.read_exact(buf).map_err(|e| {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                ExportError::Truncated { at: self.at }
            } else {
                ExportError::Io(e.kind())
            }
        })?;
        self.mac.update(buf);
        self.at = self.at.saturating_add(buf.len() as u64);
        Ok(())
    }

    fn u8(&mut self) -> Result<u8, ExportError> {
        let mut b = [0_u8; 1];
        self.fill(&mut b)?;
        let [byte] = b;
        Ok(byte)
    }

    fn u16(&mut self) -> Result<u16, ExportError> {
        let mut b = [0_u8; 2];
        self.fill(&mut b)?;
        Ok(u16::from_le_bytes(b))
    }

    fn u32(&mut self) -> Result<u32, ExportError> {
        let mut b = [0_u8; 4];
        self.fill(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }

    fn entry(&mut self) -> Result<(u64, Vec<u8>), ExportError> {
        let at = self.at;
        let len = usize::try_from(self.u32()?).map_err(|_| ExportError::EntryTooLarge {
            at,
            max: MAX_ENTRY_BYTES,
        })?;
        if len > MAX_ENTRY_BYTES {
            return Err(ExportError::EntryTooLarge {
                at,
                max: MAX_ENTRY_BYTES,
            });
        }
        // R1: len was bounded by MAX_ENTRY_BYTES just above.
        let mut bytes = vec![0_u8; len];
        self.fill(&mut bytes)?;
        Ok((at, bytes))
    }
}

fn field_bytes(record: &Record, tag: Tag, at: u64) -> Result<&[u8], ExportError> {
    record
        .field(tag)
        .map(Field::value)
        .ok_or(ExportError::MissingField { at, tag })
}

fn field_u64(record: &Record, tag: Tag, at: u64) -> Result<u64, ExportError> {
    let bytes = field_bytes(record, tag, at)?;
    let array: [u8; 8] = bytes
        .try_into()
        .map_err(|_| ExportError::Malformed { at })?;
    Ok(u64::from_le_bytes(array))
}

fn field_u32(record: &Record, tag: Tag, at: u64) -> Result<u32, ExportError> {
    let bytes = field_bytes(record, tag, at)?;
    let array: [u8; 4] = bytes
        .try_into()
        .map_err(|_| ExportError::Malformed { at })?;
    Ok(u32::from_le_bytes(array))
}

fn read_header(record: &Record, at: u64) -> Result<Header, ExportError> {
    Ok(Header {
        vault_id: field_bytes(record, tag::VAULT_ID, at)?.to_vec(),
        generation: field_u64(record, tag::GENERATION, at)?,
        high_water_mark: match record.field(tag::HIGH_WATER_MARK) {
            Some(_) => Some(field_u64(record, tag::HIGH_WATER_MARK, at)?),
            None => None,
        },
        records: field_u64(record, tag::RECORDS, at)?,
        chunks: field_u64(record, tag::CHUNKS, at)?,
    })
}

fn pass<R: Read>(
    reader: R,
    muk: &Secret<Muk>,
    mut store: Option<&mut Store>,
) -> Result<(Header, Summary), ExportError> {
    let mut input = Framed {
        reader,
        mac: new_mac(muk)?,
        at: 0,
    };
    let mut magic = [0_u8; 4];
    input.fill(&mut magic)?;
    if &magic != MAGIC {
        return Err(ExportError::BadMagic);
    }
    let version = input.u16()?;
    if version != VERSION {
        return Err(ExportError::UnsupportedVersion { version });
    }
    let (at, header_bytes) = input.entry()?;
    let header = read_header(&Record::decode(&header_bytes)?, at)?;

    let mut records: u64 = 0;
    let mut chunks: u64 = 0;
    loop {
        let kind_at = input.at;
        let kind = input.u8()?;
        match kind {
            KIND_END => break,
            KIND_RECORD => {
                let (at, bytes) = input.entry()?;
                let record = Record::decode(&bytes)?;
                let item_id = field_bytes(&record, tag::ITEM_ID, at)?;
                let version = field_u64(&record, tag::VERSION, at)?;
                let payload = field_bytes(&record, tag::BYTES, at)?;
                if let Some(store) = store.as_deref_mut() {
                    store.put_raw(&header.vault_id, item_id, version, payload)?;
                }
                records = records.saturating_add(1);
            }
            KIND_CHUNK => {
                let (at, bytes) = input.entry()?;
                let record = Record::decode(&bytes)?;
                let item_id = field_bytes(&record, tag::ITEM_ID, at)?;
                let attachment_id = field_bytes(&record, tag::ATTACHMENT_ID, at)?;
                let index = field_u32(&record, tag::CHUNK_INDEX, at)?;
                let payload = field_bytes(&record, tag::BYTES, at)?;
                if let Some(store) = store.as_deref_mut() {
                    store.put_chunk_raw(
                        &header.vault_id,
                        item_id,
                        attachment_id,
                        index,
                        payload,
                    )?;
                }
                chunks = chunks.saturating_add(1);
            }
            other => {
                return Err(ExportError::UnknownEntryKind {
                    at: kind_at,
                    kind: other,
                })
            }
        }
    }
    let at = finish(input)?;
    if records != header.records {
        return Err(ExportError::CountMismatch {
            declared: header.records,
            found: records,
        });
    }
    if chunks != header.chunks {
        return Err(ExportError::CountMismatch {
            declared: header.chunks,
            found: chunks,
        });
    }
    Ok((
        header,
        Summary {
            records,
            chunks,
            bytes: at.saturating_add(MAC_LEN as u64),
        },
    ))
}

fn finish<R: Read>(input: Framed<R>) -> Result<u64, ExportError> {
    let Framed {
        mut reader,
        mac,
        at,
    } = input;
    let mut trailer = [0_u8; MAC_LEN];
    reader.read_exact(&mut trailer).map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            ExportError::Truncated { at }
        } else {
            ExportError::Io(e.kind())
        }
    })?;
    mac.verify_slice(&trailer)
        .map_err(|_| ExportError::MacMismatch)?;
    let mut extra = [0_u8; 1];
    if reader.read(&mut extra)? != 0 {
        return Err(ExportError::TrailingBytes {
            at: at.saturating_add(MAC_LEN as u64),
        });
    }
    Ok(at)
}

pub fn verify<R: Read + Seek>(mut reader: R, muk: &Secret<Muk>) -> Result<Header, ExportError> {
    reader.seek(SeekFrom::Start(0))?;
    let (header, _) = pass(&mut reader, muk, None)?;
    Ok(header)
}

pub fn restore<R: Read + Seek>(
    mut reader: R,
    muk: &Secret<Muk>,
    store: &mut Store,
) -> Result<Summary, ExportError> {
    let header = verify(&mut reader, muk)?;
    if !store.list(&header.vault_id)?.is_empty() {
        return Err(ExportError::StoreNotFresh);
    }
    reader.seek(SeekFrom::Start(0))?;
    let (header, summary) = pass(&mut reader, muk, Some(store))?;

    // After the commit: the rollback anchor lives outside SQLite, so a rolled-back
    // write must not have advanced it.
    if let Some(hwm) = header.high_water_mark {
        store.set_high_water_mark(&header.vault_id, hwm)?;
    }
    Ok(summary)
}

/// Chrome's CSV format, lossy by design; [`everything_json`] is the complete plaintext.
pub fn logins_csv<W: Write>(items: &[Item], mut sink: W) -> Result<usize, ExportError> {
    sink.write_all(b"name,url,username,password\n")?;
    let mut line: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
    let mut written = 0_usize;
    for item in items.iter().filter(|i| i.kind() == ItemKind::Login) {
        line.clear();
        for (i, name) in [FIELD_TITLE, FIELD_URL, FIELD_USERNAME, FIELD_PASSWORD]
            .iter()
            .enumerate()
        {
            if i > 0 {
                line.push(b',');
            }
            let value = match item.field(name) {
                Some(field) => field.value(),
                None => &[],
            };
            csv_quote(&mut line, value);
        }
        line.push(b'\n');
        sink.write_all(&line)?;
        written += 1;
    }
    sink.flush()?;
    Ok(written)
}

/// RFC 4180 quoting.
fn csv_quote(out: &mut Vec<u8>, value: &[u8]) {
    let needs_quotes = value
        .iter()
        .any(|&b| matches!(b, b',' | b'"' | b'\n' | b'\r'));
    if !needs_quotes {
        out.extend_from_slice(value);
        return;
    }
    out.push(b'"');
    for &b in value {
        if b == b'"' {
            out.push(b'"');
        }
        out.push(b);
    }
    out.push(b'"');
}

pub fn everything_json<W: Write>(items: &[Item], mut sink: W) -> Result<usize, ExportError> {
    let document = Node::List(items.iter().map(item_node).collect());
    let text = document.render();
    sink.write_all(text.as_bytes())?;
    sink.write_all(b"\n")?;
    sink.flush()?;
    Ok(items.len())
}

fn item_node(item: &Item) -> Node {
    let fields = item
        .fields()
        .map(|f| {
            (
                Zeroizing::new(f.name().as_str().to_owned()),
                text_or_hex(f.value()),
            )
        })
        .collect();
    let tags = item
        .tags()
        .map(|t| Node::Text(Zeroizing::new(t.as_str().to_owned())))
        .collect();
    let unknown = item
        .unknown_fields()
        .map(|f| {
            Node::Object(vec![
                (
                    Zeroizing::new("tag".to_owned()),
                    Node::Number(Zeroizing::new(f.tag().to_string())),
                ),
                (Zeroizing::new("hex".to_owned()), Node::Text(hex(f.value()))),
            ])
        })
        .collect();
    Node::Object(vec![
        (
            Zeroizing::new("kind".to_owned()),
            Node::Text(Zeroizing::new(item.kind().tag().to_owned())),
        ),
        (
            Zeroizing::new("schemaVersion".to_owned()),
            Node::Number(Zeroizing::new(item.schema_version().to_string())),
        ),
        (Zeroizing::new("fields".to_owned()), Node::Object(fields)),
        (Zeroizing::new("tags".to_owned()), Node::List(tags)),
        (
            Zeroizing::new("unknownFields".to_owned()),
            Node::List(unknown),
        ),
    ])
}

fn text_or_hex(bytes: &[u8]) -> Node {
    match core::str::from_utf8(bytes) {
        Ok(text) => Node::Text(Zeroizing::new(text.to_owned())),
        Err(_) => Node::Object(vec![(
            Zeroizing::new("hex".to_owned()),
            Node::Text(hex(bytes)),
        )]),
    }
}

fn hex(bytes: &[u8]) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(bytes.len() * 2));
    for &b in bytes {
        out.push(hex_digit(b >> 4));
        out.push(hex_digit(b & 0xF));
    }
    out
}

fn hex_digit(nibble: u8) -> char {
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
    fn csv_quoting_follows_rfc_4180() {
        let mut out = Vec::new();
        csv_quote(&mut out, b"plain");
        out.push(b'|');
        csv_quote(&mut out, b"has, comma");
        out.push(b'|');
        csv_quote(&mut out, b"has \"quotes\"\nand a newline");
        assert_eq!(
            out,
            b"plain|\"has, comma\"|\"has \"\"quotes\"\"\nand a newline\"".to_vec()
        );
    }

    #[test]
    fn hex_is_lower_case_and_two_digits_per_byte() {
        assert_eq!(hex(&[0x00, 0x0f, 0xa5, 0xff]).as_str(), "000fa5ff");
    }
}
