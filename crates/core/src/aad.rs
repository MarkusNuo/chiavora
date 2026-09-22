//! The one canonical AAD encoder and its decoder (I3, §2.2).

const MAGIC: &[u8; 4] = b"CHV1";

pub const RECORD_ITEM_PAYLOAD: u8 = 0x01;
pub const RECORD_ATTACHMENT_CHUNK: u8 = 0x02;
pub const RECORD_MANIFEST_ROOT: u8 = 0x03;
pub const RECORD_MANIFEST_SEGMENT: u8 = 0x04;
pub const RECORD_WRAPPED_ITEM_KEY: u8 = 0x05;
pub const RECORD_SEALED_VAULT_KEY: u8 = 0x06;
pub const RECORD_WRAPPED_AUTOFILL_KEY: u8 = 0x07;

pub const ALL_RECORD_TYPES: [u8; 7] = [
    RECORD_ITEM_PAYLOAD,
    RECORD_ATTACHMENT_CHUNK,
    RECORD_MANIFEST_ROOT,
    RECORD_MANIFEST_SEGMENT,
    RECORD_WRAPPED_ITEM_KEY,
    RECORD_SEALED_VAULT_KEY,
    RECORD_WRAPPED_AUTOFILL_KEY,
];

pub const WRAP_PURPOSE_VAULT: u8 = 0x01;
pub const WRAP_PURPOSE_AUTOFILL: u8 = 0x02;

pub const MAX_PREFIX_LEN: u8 = 64;

/// Constructing a variant is the only way to produce AAD: no function takes raw bytes (R2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AadFields {
    ItemPayload {
        vault_id: Vec<u8>,
        item_id: Vec<u8>,
        version: u64,
        content_type: Vec<u8>,
    },
    /// Bound so a chunk cannot be reordered or moved to another attachment.
    AttachmentChunk {
        vault_id: Vec<u8>,
        item_id: Vec<u8>,
        version: u64,
        attachment_id: Vec<u8>,
        chunk_index: u32,
        chunk_count: u32,
        content_type: Vec<u8>,
    },
    ManifestRoot {
        vault_id: Vec<u8>,
        manifest_seq: u64,
        vault_key_epoch: u32,
        segment_count: u32,
    },
    ManifestSegment {
        vault_id: Vec<u8>,
        segment_seq: u64,
        vault_key_epoch: u32,
        /// Prefix length in bits, `0..=64`.
        prefix_len: u8,
        /// Prefix in the most-significant `prefix_len` bits; low bits zero.
        prefix_bits: u64,
    },
    /// In this encoder so I3 covers it.
    WrappedItemKey {
        vault_id: Vec<u8>,
        item_id: Vec<u8>,
        wrap_purpose: u8,
    },
    /// Used as HPKE's `info`, so a mismatch never derives the right key (`docs/adr/0009`).
    SealedVaultKey {
        vault_id: Vec<u8>,
        vault_key_epoch: u32,
        recipient_public_key: Vec<u8>,
    },

    WrappedAutofillKey {
        vault_id: Vec<u8>,
        vault_key_epoch: u32,
    },
}

impl AadFields {
    #[must_use]
    pub const fn record_type(&self) -> u8 {
        match *self {
            Self::ItemPayload { .. } => RECORD_ITEM_PAYLOAD,
            Self::AttachmentChunk { .. } => RECORD_ATTACHMENT_CHUNK,
            Self::ManifestRoot { .. } => RECORD_MANIFEST_ROOT,
            Self::ManifestSegment { .. } => RECORD_MANIFEST_SEGMENT,
            Self::WrappedItemKey { .. } => RECORD_WRAPPED_ITEM_KEY,
            Self::SealedVaultKey { .. } => RECORD_SEALED_VAULT_KEY,
            Self::WrappedAutofillKey { .. } => RECORD_WRAPPED_AUTOFILL_KEY,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AadError {
    FieldTooLong,
    PrefixLenTooLarge,
    PrefixBitsNotCanonical,
    BadMagic,
    UnknownRecordType(u8),
    UnknownWrapPurpose(u8),
    Truncated,
    TrailingBytes,
}

impl core::fmt::Display for AadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::FieldTooLong => f.write_str("an AAD field exceeds u32::MAX bytes"),
            Self::PrefixLenTooLarge => {
                f.write_str("prefixLen exceeds 64, which prefixBits cannot represent")
            }
            Self::PrefixBitsNotCanonical => {
                f.write_str("prefixBits has a non-zero bit below the prefixLen boundary")
            }
            Self::BadMagic => f.write_str("not a CHV1 AAD string"),
            Self::UnknownRecordType(t) => {
                write!(f, "unknown AAD record type {t:#04x}")
            }
            Self::UnknownWrapPurpose(p) => {
                write!(f, "unknown AAD wrap purpose {p:#04x}")
            }
            Self::Truncated => f.write_str("AAD string ended inside a field"),
            Self::TrailingBytes => f.write_str("trailing bytes after a complete AAD record"),
        }
    }
}

impl core::error::Error for AadError {}

const fn check_wrap_purpose(wrap_purpose: u8) -> Result<(), AadError> {
    if wrap_purpose == WRAP_PURPOSE_VAULT || wrap_purpose == WRAP_PURPOSE_AUTOFILL {
        Ok(())
    } else {
        Err(AadError::UnknownWrapPurpose(wrap_purpose))
    }
}

/// Public so the manifest checks its segment prefixes with the same implementation (§2.2).
pub const fn check_prefix(prefix_len: u8, prefix_bits: u64) -> Result<(), AadError> {
    if prefix_len > MAX_PREFIX_LEN {
        return Err(AadError::PrefixLenTooLarge);
    }
    // A shift by 64 would overflow, so a full-width prefix gets an empty mask.
    let unused = MAX_PREFIX_LEN - prefix_len;
    let mask = if unused == 0 {
        0_u64
    } else {
        u64::MAX >> prefix_len
    };
    if prefix_bits & mask != 0 {
        return Err(AadError::PrefixBitsNotCanonical);
    }
    Ok(())
}

fn put_var(out: &mut Vec<u8>, field: &[u8]) -> Result<(), AadError> {
    let len = u32::try_from(field.len()).map_err(|_| AadError::FieldTooLong)?;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(field);
    Ok(())
}

fn put_common(
    out: &mut Vec<u8>,
    record_type: u8,
    vault_id: &[u8],
    item_id: &[u8],
    version: u64,
) -> Result<(), AadError> {
    out.extend_from_slice(MAGIC);
    out.push(record_type);
    put_var(out, vault_id)?;
    put_var(out, item_id)?;
    out.extend_from_slice(&version.to_le_bytes());
    Ok(())
}
pub fn encode(fields: &AadFields) -> Result<Vec<u8>, AadError> {
    let mut out = Vec::new();
    match *fields {
        AadFields::ItemPayload {
            ref vault_id,
            ref item_id,
            version,
            ref content_type,
        } => {
            put_common(&mut out, RECORD_ITEM_PAYLOAD, vault_id, item_id, version)?;
            put_var(&mut out, content_type)?;
        }
        AadFields::AttachmentChunk {
            ref vault_id,
            ref item_id,
            version,
            ref attachment_id,
            chunk_index,
            chunk_count,
            ref content_type,
        } => {
            put_common(
                &mut out,
                RECORD_ATTACHMENT_CHUNK,
                vault_id,
                item_id,
                version,
            )?;
            put_var(&mut out, attachment_id)?;
            out.extend_from_slice(&chunk_index.to_le_bytes());
            out.extend_from_slice(&chunk_count.to_le_bytes());
            put_var(&mut out, content_type)?;
        }
        AadFields::ManifestRoot {
            ref vault_id,
            manifest_seq,
            vault_key_epoch,
            segment_count,
        } => {
            out.extend_from_slice(MAGIC);
            out.push(RECORD_MANIFEST_ROOT);
            put_var(&mut out, vault_id)?;
            out.extend_from_slice(&manifest_seq.to_le_bytes());
            out.extend_from_slice(&vault_key_epoch.to_le_bytes());
            out.extend_from_slice(&segment_count.to_le_bytes());
        }
        AadFields::ManifestSegment {
            ref vault_id,
            segment_seq,
            vault_key_epoch,
            prefix_len,
            prefix_bits,
        } => {
            check_prefix(prefix_len, prefix_bits)?;
            out.extend_from_slice(MAGIC);
            out.push(RECORD_MANIFEST_SEGMENT);
            put_var(&mut out, vault_id)?;
            out.extend_from_slice(&segment_seq.to_le_bytes());
            out.extend_from_slice(&vault_key_epoch.to_le_bytes());
            out.push(prefix_len);
            out.extend_from_slice(&prefix_bits.to_le_bytes());
        }
        AadFields::WrappedItemKey {
            ref vault_id,
            ref item_id,
            wrap_purpose,
        } => {
            check_wrap_purpose(wrap_purpose)?;
            out.extend_from_slice(MAGIC);
            out.push(RECORD_WRAPPED_ITEM_KEY);
            put_var(&mut out, vault_id)?;
            put_var(&mut out, item_id)?;
            out.push(wrap_purpose);
        }
        AadFields::SealedVaultKey {
            ref vault_id,
            vault_key_epoch,
            ref recipient_public_key,
        } => {
            out.extend_from_slice(MAGIC);
            out.push(RECORD_SEALED_VAULT_KEY);
            put_var(&mut out, vault_id)?;
            out.extend_from_slice(&vault_key_epoch.to_le_bytes());
            put_var(&mut out, recipient_public_key)?;
        }
        AadFields::WrappedAutofillKey {
            ref vault_id,
            vault_key_epoch,
        } => {
            out.extend_from_slice(MAGIC);
            out.push(RECORD_WRAPPED_AUTOFILL_KEY);
            put_var(&mut out, vault_id)?;
            out.extend_from_slice(&vault_key_epoch.to_le_bytes());
        }
    }
    Ok(out)
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], AadError> {
        let end = self.at.checked_add(n).ok_or(AadError::Truncated)?;
        let slice = self.bytes.get(self.at..end).ok_or(AadError::Truncated)?;
        self.at = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, AadError> {
        self.take(1)?.first().copied().ok_or(AadError::Truncated)
    }

    fn u32(&mut self) -> Result<u32, AadError> {
        let raw: [u8; 4] = self.take(4)?.try_into().map_err(|_| AadError::Truncated)?;
        Ok(u32::from_le_bytes(raw))
    }

    fn u64(&mut self) -> Result<u64, AadError> {
        let raw: [u8; 8] = self.take(8)?.try_into().map_err(|_| AadError::Truncated)?;
        Ok(u64::from_le_bytes(raw))
    }

    fn var(&mut self) -> Result<Vec<u8>, AadError> {
        let len = self.u32()? as usize;
        Ok(self.take(len)?.to_vec())
    }

    const fn finish(&self) -> Result<(), AadError> {
        if self.at == self.bytes.len() {
            Ok(())
        } else {
            Err(AadError::TrailingBytes)
        }
    }
}

/// Nothing in the product needs it; it is the inverse that proves `encode` injective.
pub fn decode(bytes: &[u8]) -> Result<AadFields, AadError> {
    let mut r = Reader::new(bytes);
    if r.take(MAGIC.len())? != MAGIC.as_slice() {
        return Err(AadError::BadMagic);
    }
    let record_type = r.u8()?;
    let fields = match record_type {
        RECORD_ITEM_PAYLOAD => AadFields::ItemPayload {
            vault_id: r.var()?,
            item_id: r.var()?,
            version: r.u64()?,
            content_type: r.var()?,
        },
        RECORD_ATTACHMENT_CHUNK => {
            let vault_id = r.var()?;
            let item_id = r.var()?;
            let version = r.u64()?;
            let attachment_id = r.var()?;
            let chunk_index = r.u32()?;
            let chunk_count = r.u32()?;
            let content_type = r.var()?;
            AadFields::AttachmentChunk {
                vault_id,
                item_id,
                version,
                attachment_id,
                chunk_index,
                chunk_count,
                content_type,
            }
        }
        RECORD_MANIFEST_ROOT => AadFields::ManifestRoot {
            vault_id: r.var()?,
            manifest_seq: r.u64()?,
            vault_key_epoch: r.u32()?,
            segment_count: r.u32()?,
        },
        RECORD_MANIFEST_SEGMENT => {
            let vault_id = r.var()?;
            let segment_seq = r.u64()?;
            let vault_key_epoch = r.u32()?;
            let prefix_len = r.u8()?;
            let prefix_bits = r.u64()?;
            check_prefix(prefix_len, prefix_bits)?;
            AadFields::ManifestSegment {
                vault_id,
                segment_seq,
                vault_key_epoch,
                prefix_len,
                prefix_bits,
            }
        }
        RECORD_WRAPPED_ITEM_KEY => {
            let vault_id = r.var()?;
            let item_id = r.var()?;
            let wrap_purpose = r.u8()?;
            check_wrap_purpose(wrap_purpose)?;
            AadFields::WrappedItemKey {
                vault_id,
                item_id,
                wrap_purpose,
            }
        }
        RECORD_SEALED_VAULT_KEY => {
            let vault_id = r.var()?;
            let vault_key_epoch = r.u32()?;
            let recipient_public_key = r.var()?;
            AadFields::SealedVaultKey {
                vault_id,
                vault_key_epoch,
                recipient_public_key,
            }
        }
        RECORD_WRAPPED_AUTOFILL_KEY => {
            let vault_id = r.var()?;
            let vault_key_epoch = r.u32()?;
            AadFields::WrappedAutofillKey {
                vault_id,
                vault_key_epoch,
            }
        }
        other => return Err(AadError::UnknownRecordType(other)),
    };
    r.finish()?;
    Ok(fields)
}
