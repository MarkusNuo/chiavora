//! The zip container a 1PUX export arrives in. Nothing is truncated or skipped.

use std::io::{Read, Seek, SeekFrom, Write};
use std::sync::OnceLock;

use miniz_oxide::inflate::stream::{inflate, InflateState};
use miniz_oxide::{DataFormat, MZError, MZFlush, MZStatus};
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub max_entries: usize,
    pub max_entry_bytes: u64,
    pub max_total_bytes: u64,
    /// `uncompressed / max(compressed, 1)`, per member.
    pub max_ratio: u64,
}

/// Real JSON compresses 5 to 20 : 1, so a ratio of 100 refuses nothing legitimate.
pub const ONE_PUX_LIMITS: Limits = Limits {
    max_entries: 10_000,
    max_entry_bytes: 256 << 20,
    max_total_bytes: 4 << 30,
    max_ratio: 100,
};

pub const MAX_CENTRAL_DIRECTORY_BYTES: u64 = 64 << 20;

const EOCD_SIGNATURE: [u8; 4] = [0x50, 0x4b, 0x05, 0x06];
const CENTRAL_SIGNATURE: [u8; 4] = [0x50, 0x4b, 0x01, 0x02];
const LOCAL_SIGNATURE: [u8; 4] = [0x50, 0x4b, 0x03, 0x04];
const EOCD_LEN: usize = 22;
const CENTRAL_FIXED_LEN: usize = 46;
const LOCAL_FIXED_LEN: usize = 30;
const MAX_COMMENT_LEN: u64 = 0xFFFF;
const ZIP64_MARKER_32: u32 = 0xFFFF_FFFF;
const ZIP64_MARKER_16: u16 = 0xFFFF;
const METHOD_STORED: u16 = 0;
const METHOD_DEFLATE: u16 = 8;
const FLAG_ENCRYPTED: u16 = 0x0001;
const FLAG_STRONG_ENCRYPTION: u16 = 0x0040;
const MADE_BY_UNIX: u16 = 3;
const UNIX_MODE_TYPE_MASK: u32 = 0o170_000;
const UNIX_MODE_SYMLINK: u32 = 0o120_000;
const BLOCK: usize = 64 << 10;

/// No variant carries a member name or content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZipError {
    NoEndOfCentralDirectory,
    Malformed {
        at: u64,
    },
    CentralDirectoryTooLarge {
        max: u64,
    },
    Zip64Unsupported {
        at: u64,
    },
    TooManyEntries {
        max: usize,
    },
    EntryTooLarge {
        entry: usize,
        max: u64,
    },
    TotalTooLarge {
        entry: usize,
        max: u64,
    },
    RatioTooHigh {
        entry: usize,
        max: u64,
    },
    PathTraversal {
        entry: usize,
    },
    Symlink {
        entry: usize,
    },
    NestedArchive {
        entry: usize,
    },
    Encrypted {
        entry: usize,
    },
    UnsupportedMethod {
        entry: usize,
        method: u16,
    },
    SizeMismatch {
        entry: usize,
    },
    CrcMismatch {
        entry: usize,
    },
    Inflate {
        entry: usize,
    },
    Refused {
        entry: usize,
    },
    NoSuchEntry {
        entry: usize,
    },
    IsDirectory {
        entry: usize,
    },
    TooLargeForTarget {
        bytes: u64,
    },
    /// The kind only, so no path is named.
    Io(std::io::ErrorKind),
}

impl core::fmt::Display for ZipError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoEndOfCentralDirectory => {
                f.write_str("no end-of-central-directory record: not a zip archive, or truncated")
            }
            Self::Malformed { at } => write!(f, "malformed zip structure at byte {at}"),
            Self::CentralDirectoryTooLarge { max } => {
                write!(f, "central directory larger than {max} bytes")
            }
            Self::Zip64Unsupported { at } => write!(f, "zip64 marker at byte {at}; not supported"),
            Self::TooManyEntries { max } => write!(f, "more than {max} entries"),
            Self::EntryTooLarge { entry, max } => {
                write!(f, "entry {entry} declares more than {max} bytes")
            }
            Self::TotalTooLarge { entry, max } => {
                write!(
                    f,
                    "entry {entry} takes the archive past {max} bytes in total"
                )
            }
            Self::RatioTooHigh { entry, max } => {
                write!(
                    f,
                    "entry {entry} declares a compression ratio above {max}:1"
                )
            }
            Self::PathTraversal { entry } => {
                write!(f, "entry {entry} has a name that escapes the archive")
            }
            Self::Symlink { entry } => write!(f, "entry {entry} is a symbolic link"),
            Self::NestedArchive { entry } => write!(f, "entry {entry} is itself an archive"),
            Self::Encrypted { entry } => write!(f, "entry {entry} is encrypted"),
            Self::UnsupportedMethod { entry, method } => {
                write!(
                    f,
                    "entry {entry} uses compression method {method}, not stored or deflate"
                )
            }
            Self::SizeMismatch { entry } => {
                write!(f, "entry {entry} did not inflate to its declared size")
            }
            Self::CrcMismatch { entry } => write!(f, "entry {entry} failed its CRC-32 check"),
            Self::Inflate { entry } => write!(f, "entry {entry} is not a valid deflate stream"),
            Self::Refused { entry } => {
                write!(f, "entry {entry} was refused when the archive was read")
            }
            Self::NoSuchEntry { entry } => write!(f, "no entry {entry}"),
            Self::IsDirectory { entry } => write!(f, "entry {entry} is a directory"),
            Self::TooLargeForTarget { bytes } => {
                write!(f, "{bytes} bytes does not fit this target's address space")
            }
            Self::Io(kind) => write!(f, "i/o: {kind:?}"),
        }
    }
}

impl core::error::Error for ZipError {}

impl From<std::io::Error> for ZipError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.kind())
    }
}

pub struct Entry {
    index: usize,
    name: Zeroizing<String>,
    method: u16,
    flags: u16,
    crc32: u32,
    compressed_len: u64,
    uncompressed_len: u64,
    local_header_offset: u64,
    made_by: u16,
    external_attributes: u32,
    refusal: Option<ZipError>,
}

/// Redacted: the name is a foreign vault's plaintext.
impl core::fmt::Debug for Entry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Entry(#{}, {} -> {} bytes, method {}, {}, name redacted)",
            self.index,
            self.compressed_len,
            self.uncompressed_len,
            self.method,
            if self.refusal.is_some() {
                "refused"
            } else {
                "readable"
            }
        )
    }
}

impl Entry {
    #[must_use]
    pub const fn index(&self) -> usize {
        self.index
    }

    /// The member name, lossily decoded as UTF-8; an attachment's file name is content.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub const fn compressed_len(&self) -> u64 {
        self.compressed_len
    }

    #[must_use]
    pub const fn uncompressed_len(&self) -> u64 {
        self.uncompressed_len
    }

    #[must_use]
    pub const fn refusal(&self) -> Option<&ZipError> {
        self.refusal.as_ref()
    }

    #[must_use]
    pub fn is_directory(&self) -> bool {
        self.name.ends_with('/') && self.uncompressed_len == 0
    }
}

pub struct Archive<R> {
    reader: R,
    entries: Vec<Entry>,
}

impl<R> core::fmt::Debug for Archive<R> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Archive({} entries)", self.entries.len())
    }
}

pub fn parse<R: Read + Seek>(mut reader: R, limits: &Limits) -> Result<Archive<R>, ZipError> {
    let Directory {
        offset: cd_offset,
        size: cd_size,
        entries: entries_total,
    } = read_end_of_central_directory(&mut reader)?;

    reader.seek(SeekFrom::Start(cd_offset))?;
    // R1: cd_size was bounded by MAX_CENTRAL_DIRECTORY_BYTES when it was read.
    let mut directory = Zeroizing::new(vec![0_u8; to_usize(cd_size)?]);
    reader.read_exact(&mut directory)?;

    // R1: reserved up to limits.max_entries only; entries past it are parsed and refused.
    let mut entries = Vec::with_capacity(usize::from(entries_total).min(limits.max_entries));
    let mut cursor = 0_usize;
    let mut running_total: u64 = 0;
    let mut total_exceeded = false;
    for index in 0..usize::from(entries_total) {
        let at = cd_offset + cursor as u64;
        let record = directory
            .get(cursor..)
            .filter(|r| r.len() >= CENTRAL_FIXED_LEN)
            .ok_or(ZipError::Malformed { at })?;
        if record.get(..4) != Some(&CENTRAL_SIGNATURE) {
            return Err(ZipError::Malformed { at });
        }
        let made_by = le_u16(record, 4);
        let flags = le_u16(record, 8);
        let method = le_u16(record, 10);
        let crc32 = le_u32(record, 16);
        let compressed = le_u32(record, 20);
        let uncompressed = le_u32(record, 24);
        let name_len = usize::from(le_u16(record, 28));
        let extra_len = usize::from(le_u16(record, 30));
        let comment_len = usize::from(le_u16(record, 32));
        let external_attributes = le_u32(record, 38);
        let local_header_offset = le_u32(record, 42);
        let name_bytes = record
            .get(CENTRAL_FIXED_LEN..CENTRAL_FIXED_LEN + name_len)
            .ok_or(ZipError::Malformed { at })?;
        let record_len = CENTRAL_FIXED_LEN + name_len + extra_len + comment_len;
        if record.len() < record_len {
            return Err(ZipError::Malformed { at });
        }
        let name = Zeroizing::new(String::from_utf8_lossy(name_bytes).into_owned());
        cursor += record_len;

        let mut entry = Entry {
            index,
            name,
            method,
            flags,
            crc32,
            compressed_len: u64::from(compressed),
            uncompressed_len: u64::from(uncompressed),
            local_header_offset: u64::from(local_header_offset),
            made_by,
            external_attributes,
            refusal: None,
        };

        // Recorded on the entry rather than aborting, so the rest stays readable.
        entry.refusal = if compressed == ZIP64_MARKER_32 {
            Some(ZipError::Zip64Unsupported { at: at + 20 })
        } else if uncompressed == ZIP64_MARKER_32 {
            Some(ZipError::Zip64Unsupported { at: at + 24 })
        } else if local_header_offset == ZIP64_MARKER_32 {
            Some(ZipError::Zip64Unsupported { at: at + 42 })
        } else if entry.local_header_offset >= cd_offset {
            Some(ZipError::Malformed { at: at + 42 })
        } else {
            None
        };

        if entry.refusal.is_none() && !entry.is_directory() {
            entry.refusal = first_refusal(
                &entry,
                index,
                limits,
                &mut running_total,
                &mut total_exceeded,
            );
        }
        entries.push(entry);
    }

    Ok(Archive { reader, entries })
}

struct Directory {
    offset: u64,
    size: u64,
    entries: u16,
}

fn read_end_of_central_directory<R: Read + Seek>(reader: &mut R) -> Result<Directory, ZipError> {
    let len = reader.seek(SeekFrom::End(0))?;
    if len < EOCD_LEN as u64 {
        return Err(ZipError::NoEndOfCentralDirectory);
    }
    let tail_len = len.min(EOCD_LEN as u64 + MAX_COMMENT_LEN);
    let tail_start = len - tail_len;
    reader.seek(SeekFrom::Start(tail_start))?;
    // R1: tail_len is at most EOCD_LEN + MAX_COMMENT_LEN, a bound the format sets.
    let mut tail = Zeroizing::new(vec![0_u8; to_usize(tail_len)?]);
    reader.read_exact(&mut tail)?;

    let eocd_rel = find_eocd(&tail).ok_or(ZipError::NoEndOfCentralDirectory)?;
    let eocd_abs = tail_start + eocd_rel as u64;
    let eocd = tail
        .get(eocd_rel..)
        .ok_or(ZipError::Malformed { at: eocd_abs })?;

    let disk = le_u16(eocd, 4);
    let cd_disk = le_u16(eocd, 6);
    let entries_here = le_u16(eocd, 8);
    let entries_total = le_u16(eocd, 10);
    let cd_size = le_u32(eocd, 12);
    let cd_offset = le_u32(eocd, 16);
    if disk != 0 || cd_disk != 0 || entries_here != entries_total {
        return Err(ZipError::Malformed { at: eocd_abs + 4 });
    }
    if entries_total == ZIP64_MARKER_16 {
        return Err(ZipError::Zip64Unsupported { at: eocd_abs + 10 });
    }
    if cd_size == ZIP64_MARKER_32 {
        return Err(ZipError::Zip64Unsupported { at: eocd_abs + 12 });
    }
    if cd_offset == ZIP64_MARKER_32 {
        return Err(ZipError::Zip64Unsupported { at: eocd_abs + 16 });
    }
    let cd_size = u64::from(cd_size);
    let cd_offset = u64::from(cd_offset);
    if cd_size > MAX_CENTRAL_DIRECTORY_BYTES {
        return Err(ZipError::CentralDirectoryTooLarge {
            max: MAX_CENTRAL_DIRECTORY_BYTES,
        });
    }
    if !matches!(cd_offset.checked_add(cd_size), Some(end) if end <= eocd_abs) {
        return Err(ZipError::Malformed { at: eocd_abs + 12 });
    }
    Ok(Directory {
        offset: cd_offset,
        size: cd_size,
        entries: entries_total,
    })
}

fn first_refusal(
    entry: &Entry,
    index: usize,
    limits: &Limits,
    running_total: &mut u64,
    total_exceeded: &mut bool,
) -> Option<ZipError> {
    if index >= limits.max_entries {
        return Some(ZipError::TooManyEntries {
            max: limits.max_entries,
        });
    }
    if entry.flags & (FLAG_ENCRYPTED | FLAG_STRONG_ENCRYPTION) != 0 {
        return Some(ZipError::Encrypted { entry: index });
    }
    if entry.method != METHOD_STORED && entry.method != METHOD_DEFLATE {
        return Some(ZipError::UnsupportedMethod {
            entry: index,
            method: entry.method,
        });
    }
    if escapes_the_root(&entry.name) {
        return Some(ZipError::PathTraversal { entry: index });
    }
    if entry.made_by >> 8 == MADE_BY_UNIX
        && (entry.external_attributes >> 16) & UNIX_MODE_TYPE_MASK == UNIX_MODE_SYMLINK
    {
        return Some(ZipError::Symlink { entry: index });
    }
    if names_an_archive(&entry.name) {
        return Some(ZipError::NestedArchive { entry: index });
    }
    if entry.uncompressed_len > limits.max_entry_bytes {
        return Some(ZipError::EntryTooLarge {
            entry: index,
            max: limits.max_entry_bytes,
        });
    }
    if entry.uncompressed_len > limits.max_ratio.saturating_mul(entry.compressed_len.max(1)) {
        return Some(ZipError::RatioTooHigh {
            entry: index,
            max: limits.max_ratio,
        });
    }
    if entry.method == METHOD_STORED && entry.compressed_len != entry.uncompressed_len {
        return Some(ZipError::SizeMismatch { entry: index });
    }
    *running_total = running_total.saturating_add(entry.uncompressed_len);
    if *total_exceeded || *running_total > limits.max_total_bytes {
        *total_exceeded = true;
        return Some(ZipError::TotalTooLarge {
            entry: index,
            max: limits.max_total_bytes,
        });
    }
    None
}

fn escapes_the_root(name: &str) -> bool {
    if name.contains('\0') || name.starts_with('/') || name.starts_with('\\') {
        return true;
    }
    let mut chars = name.chars();
    if let (Some(first), Some(':')) = (chars.next(), chars.next()) {
        if first.is_ascii_alphabetic() {
            return true;
        }
    }
    name.split(['/', '\\']).any(|segment| segment == "..")
}

fn names_an_archive(name: &str) -> bool {
    match name.rsplit_once('.') {
        Some((_, ext)) => ext.eq_ignore_ascii_case("zip") || ext.eq_ignore_ascii_case("1pux"),
        None => false,
    }
}

fn find_eocd(tail: &[u8]) -> Option<usize> {
    let eocd_len = EOCD_LEN;
    if tail.len() < eocd_len {
        return None;
    }
    (0..=tail.len() - eocd_len).rev().find(|&at| {
        tail.get(at..at + 4) == Some(&EOCD_SIGNATURE)
            && tail
                .get(at..)
                .is_some_and(|rec| at + eocd_len + usize::from(le_u16(rec, 20)) == tail.len())
    })
}

impl<R: Read + Seek> Archive<R> {
    #[must_use]
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    #[must_use]
    pub fn find(&self, name: &str) -> Option<usize> {
        self.entries.iter().position(|e| e.name.as_str() == name)
    }

    pub fn read_entry(&mut self, index: usize, sink: &mut dyn Write) -> Result<u64, ZipError> {
        let entry = self.readable(index)?;
        let (method, crc32, compressed_len, uncompressed_len, header_at) = (
            entry.method,
            entry.crc32,
            entry.compressed_len,
            entry.uncompressed_len,
            entry.local_header_offset,
        );

        self.reader.seek(SeekFrom::Start(header_at))?;
        let mut header = [0_u8; LOCAL_FIXED_LEN];
        self.reader.read_exact(&mut header)?;
        if header.get(..4) != Some(&LOCAL_SIGNATURE) {
            return Err(ZipError::Malformed { at: header_at });
        }
        let name_len = u64::from(le_u16(&header, 26));
        let extra_len = u64::from(le_u16(&header, 28));
        let data_at = header_at + LOCAL_FIXED_LEN as u64 + name_len + extra_len;
        self.reader.seek(SeekFrom::Start(data_at))?;

        let mut out = Output {
            sink,
            crc: Crc32::new(),
            written: 0,
            declared: uncompressed_len,
            entry: index,
            first_block: true,
        };
        match method {
            METHOD_STORED => copy_stored(&mut self.reader, compressed_len, &mut out)?,
            _ => inflate_deflate(&mut self.reader, compressed_len, &mut out, index)?,
        }
        if out.written != uncompressed_len {
            return Err(ZipError::SizeMismatch { entry: index });
        }
        if out.crc.finish() != crc32 {
            return Err(ZipError::CrcMismatch { entry: index });
        }
        Ok(out.written)
    }

    pub fn read_entry_to_vec(&mut self, index: usize) -> Result<Zeroizing<Vec<u8>>, ZipError> {
        // R1: the refusal is checked before the capacity is reserved.
        let declared = self.readable(index)?.uncompressed_len;
        let mut out = Zeroizing::new(Vec::with_capacity(to_usize(declared)?));
        self.read_entry(index, &mut *out)?;
        Ok(out)
    }

    /// Every read goes through here.
    fn readable(&self, index: usize) -> Result<&Entry, ZipError> {
        let entry = self
            .entries
            .get(index)
            .ok_or(ZipError::NoSuchEntry { entry: index })?;
        if entry.refusal.is_some() {
            return Err(ZipError::Refused { entry: index });
        }
        if entry.is_directory() {
            return Err(ZipError::IsDirectory { entry: index });
        }
        Ok(entry)
    }
}

struct Output<'a> {
    sink: &'a mut dyn Write,
    crc: Crc32,
    written: u64,
    declared: u64,
    entry: usize,
    first_block: bool,
}

impl Output<'_> {
    fn push(&mut self, block: &[u8]) -> Result<(), ZipError> {
        if block.is_empty() {
            return Ok(());
        }
        if self.first_block {
            self.first_block = false;
            if block.get(..4) == Some(&LOCAL_SIGNATURE) {
                return Err(ZipError::NestedArchive { entry: self.entry });
            }
        }
        self.written = self.written.saturating_add(block.len() as u64);
        if self.written > self.declared {
            return Err(ZipError::SizeMismatch { entry: self.entry });
        }
        self.crc.update(block);
        self.sink.write_all(block)?;
        Ok(())
    }
}

fn copy_stored<R: Read>(
    reader: &mut R,
    mut remaining: u64,
    out: &mut Output<'_>,
) -> Result<(), ZipError> {
    let mut buf = Zeroizing::new(vec![0_u8; BLOCK]);
    while remaining > 0 {
        let want = to_usize(remaining.min(BLOCK as u64))?;
        let block = buf.get_mut(..want).ok_or(ZipError::Malformed { at: 0 })?;
        reader.read_exact(block)?;
        out.push(block)?;
        remaining -= want as u64;
    }
    Ok(())
}

fn inflate_deflate<R: Read>(
    reader: &mut R,
    mut remaining: u64,
    out: &mut Output<'_>,
    entry: usize,
) -> Result<(), ZipError> {
    let mut state = InflateState::new_boxed(DataFormat::Raw);
    let mut input = Zeroizing::new(vec![0_u8; BLOCK]);
    let mut output = Zeroizing::new(vec![0_u8; BLOCK]);
    let mut in_len = 0_usize;
    let mut in_pos = 0_usize;
    loop {
        if in_pos == in_len {
            if remaining == 0 {
                return Err(ZipError::SizeMismatch { entry });
            }
            in_len = to_usize(remaining.min(BLOCK as u64))?;
            in_pos = 0;
            let block = input.get_mut(..in_len).ok_or(ZipError::Inflate { entry })?;
            reader.read_exact(block)?;
            remaining -= in_len as u64;
        }
        let pending = input
            .get(in_pos..in_len)
            .ok_or(ZipError::Inflate { entry })?;
        let result = inflate(&mut state, pending, &mut output, MZFlush::None);
        in_pos += result.bytes_consumed;
        let produced = output
            .get(..result.bytes_written)
            .ok_or(ZipError::Inflate { entry })?;
        out.push(produced)?;
        match result.status {
            Ok(MZStatus::StreamEnd) => break,
            Ok(_) | Err(MZError::Buf) => {
                if result.bytes_consumed == 0
                    && result.bytes_written == 0
                    && in_pos == in_len
                    && remaining == 0
                {
                    return Err(ZipError::SizeMismatch { entry });
                }
            }
            Err(_) => return Err(ZipError::Inflate { entry }),
        }
    }
    if in_pos != in_len || remaining != 0 {
        return Err(ZipError::SizeMismatch { entry });
    }
    Ok(())
}

fn to_usize(n: u64) -> Result<usize, ZipError> {
    usize::try_from(n).map_err(|_| ZipError::TooLargeForTarget { bytes: n })
}

fn le_u16(bytes: &[u8], at: usize) -> u16 {
    match (bytes.get(at), bytes.get(at + 1)) {
        (Some(&a), Some(&b)) => u16::from_le_bytes([a, b]),
        _ => 0,
    }
}

fn le_u32(bytes: &[u8], at: usize) -> u32 {
    match (
        bytes.get(at),
        bytes.get(at + 1),
        bytes.get(at + 2),
        bytes.get(at + 3),
    ) {
        (Some(&a), Some(&b), Some(&c), Some(&d)) => u32::from_le_bytes([a, b, c, d]),
        _ => 0,
    }
}

/// CRC-32 (IEEE): an integrity check on inflated bytes, not cryptography.
struct Crc32(u32);

impl Crc32 {
    const fn new() -> Self {
        Self(0xFFFF_FFFF)
    }

    fn update(&mut self, bytes: &[u8]) {
        let table = crc_table();
        for &byte in bytes {
            let [low, _, _, _] = (self.0 ^ u32::from(byte)).to_le_bytes();
            let index = usize::from(low);
            // R1: `index` is at most 255 and the table has 256 entries, so `get` cannot miss.
            self.0 = table.get(index).copied().unwrap_or(0) ^ (self.0 >> 8);
        }
    }

    fn finish(self) -> u32 {
        self.0 ^ 0xFFFF_FFFF
    }
}

fn crc_table() -> &'static [u32; 256] {
    static TABLE: OnceLock<[u32; 256]> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut table = [0_u32; 256];
        for (i, slot) in (0_u32..).zip(&mut table) {
            let mut c = i;
            for _ in 0..8 {
                c = if c & 1 != 0 {
                    0xEDB8_8320 ^ (c >> 1)
                } else {
                    c >> 1
                };
            }
            *slot = c;
        }
        table
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_matches_the_check_value() {
        let mut crc = Crc32::new();
        crc.update(b"123456789");
        assert_eq!(crc.finish(), 0xCBF4_3926);
    }

    #[test]
    fn traversal_shapes_are_refused_by_name() {
        for bad in [
            "../x", "a/../b", "/abs", "\\abs", "C:x", "c:/x", "a\0b", "a\\..\\b",
        ] {
            assert!(escapes_the_root(bad), "{bad:?} should be refused");
        }
        for ok in ["files/a.png", "export.data", "a..b/c", "..a", "dir/"] {
            assert!(!escapes_the_root(ok), "{ok:?} should be accepted");
        }
    }

    #[test]
    fn nested_archives_are_refused_by_name() {
        assert!(names_an_archive("inner.ZIP"));
        assert!(names_an_archive("files/other.1pux"));
        assert!(!names_an_archive("files/report.zipx.pdf"));
    }

    #[test]
    fn an_empty_reader_is_not_an_archive() {
        let r = std::io::Cursor::new(Vec::<u8>::new());
        assert!(matches!(
            parse(r, &ONE_PUX_LIMITS).map(|_| ()),
            Err(ZipError::NoEndOfCentralDirectory)
        ));
    }
}
