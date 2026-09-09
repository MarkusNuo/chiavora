//! The versioned TLV envelope client and server share (`docs/security-design.md` §3).

#![allow(clippy::module_name_repetitions)]

use core::fmt;

/// Distinct from the AAD encoder's `CHV1`.
pub const WIRE_MAGIC: &[u8; 4] = b"CHVR";

pub const WIRE_VERSION: u16 = 1;

/// The tag's meaning belongs to the item model (`chiavora_core::model`), not here.
pub type Tag = u16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    tag: Tag,
    value: Vec<u8>,
}

impl Field {
    pub fn new(tag: Tag, value: Vec<u8>) -> Result<Self, WireError> {
        if u32::try_from(value.len()).is_err() {
            return Err(WireError::FieldTooLong);
        }
        Ok(Self { tag, value })
    }

    #[must_use]
    pub const fn tag(&self) -> Tag {
        self.tag
    }

    #[must_use]
    pub fn value(&self) -> &[u8] {
        &self.value
    }
}

/// There is no setter and no constructor taking a version, so an older client
/// cannot rewrite a newer record as an older one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    version: u16,
    fields: Vec<Field>,
}

impl Record {
    #[must_use]
    pub const fn new(fields: Vec<Field>) -> Self {
        Self {
            version: WIRE_VERSION,
            fields,
        }
    }

    #[must_use]
    pub const fn version(&self) -> u16 {
        self.version
    }

    /// A newer version may give a known field a new meaning, so a caller that does
    /// more than preserve bytes should check this before editing.
    #[must_use]
    pub const fn is_from_a_newer_version(&self) -> bool {
        self.version > WIRE_VERSION
    }

    #[must_use]
    pub fn fields(&self) -> &[Field] {
        &self.fields
    }

    #[must_use]
    pub fn field(&self, tag: Tag) -> Option<&Field> {
        self.fields.iter().find(|f| f.tag == tag)
    }

    pub fn with_field(&self, tag: Tag, value: Vec<u8>) -> Result<Self, WireError> {
        let replacement = Field::new(tag, value)?;
        let mut fields = self.fields.clone();
        match fields.iter_mut().find(|f| f.tag == tag) {
            Some(existing) => *existing = replacement,
            None => fields.push(replacement),
        }
        Ok(Self {
            version: self.version,
            fields,
        })
    }

    /// ```text
    /// "CHVR" || u16le(version) || u32le(fieldCount)
    ///        || fieldCount × ( u16le(tag) || u32le(len) || value )
    /// ```
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        let count = u32::try_from(self.fields.len()).map_err(|_| WireError::TooManyFields)?;
        let mut out = Vec::new();
        out.extend_from_slice(WIRE_MAGIC);
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(&count.to_le_bytes());
        for field in &self.fields {
            out.extend_from_slice(&field.tag.to_le_bytes());
            // `Field::new` rejects anything longer, so this cannot fail.
            let len = u32::try_from(field.value.len()).map_err(|_| WireError::FieldTooLong)?;
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice(&field.value);
        }
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(bytes);
        if r.take(WIRE_MAGIC.len())? != WIRE_MAGIC.as_slice() {
            return Err(WireError::BadMagic);
        }
        let version = r.u16()?;
        let count = r.u32()?;
        let mut fields = Vec::new();
        for _ in 0..count {
            let tag = r.u16()?;
            let len = r.u32()? as usize;
            fields.push(Field {
                tag,
                value: r.take(len)?.to_vec(),
            });
        }
        r.finish()?;
        Ok(Self { version, fields })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    BadMagic,
    Truncated,
    /// Refused so two byte strings cannot decode alike.
    TrailingBytes,
    FieldTooLong,
    TooManyFields,
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::BadMagic => f.write_str("not a CHVR wire record"),
            Self::Truncated => f.write_str("wire record ended inside a field"),
            Self::TrailingBytes => f.write_str("trailing bytes after a complete wire record"),
            Self::FieldTooLong => f.write_str("a wire field exceeds u32::MAX bytes"),
            Self::TooManyFields => f.write_str("a wire record has more than u32::MAX fields"),
        }
    }
}

impl core::error::Error for WireError {}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        let end = self.at.checked_add(n).ok_or(WireError::Truncated)?;
        let slice = self.bytes.get(self.at..end).ok_or(WireError::Truncated)?;
        self.at = end;
        Ok(slice)
    }

    fn u16(&mut self) -> Result<u16, WireError> {
        let raw: [u8; 2] = self.take(2)?.try_into().map_err(|_| WireError::Truncated)?;
        Ok(u16::from_le_bytes(raw))
    }

    fn u32(&mut self) -> Result<u32, WireError> {
        let raw: [u8; 4] = self.take(4)?.try_into().map_err(|_| WireError::Truncated)?;
        Ok(u32::from_le_bytes(raw))
    }

    const fn finish(&self) -> Result<(), WireError> {
        if self.at == self.bytes.len() {
            Ok(())
        } else {
            Err(WireError::TrailingBytes)
        }
    }
}
