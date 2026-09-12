//! Attachments are streamed in sealed chunks, so the plaintext never sits in memory whole.

use std::io::{Read, Write};

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use chiavora_protocol::{Field, Record, Tag, WireError};

use crate::aad::{self, AadError, AadFields, RECORD_ATTACHMENT_CHUNK};
use crate::item::{self, ItemError, SealedPayload};
use crate::nonce::{FreshNonce, NonceError, NONCE_LEN};
use crate::secret::{kind::ItemKey, Secret};
use crate::store::{Store, StoreError};

/// The length of every chunk but the last, in bytes; changing it is a new format.
pub const CHUNK_LEN: usize = 1 << 20;

/// A policy no stored record depends on.
pub const MAX_ATTACHMENT_BYTES: u64 = 100 << 20;

pub const MAX_CONTENT_TYPE_BYTES: usize = 256;

// The policy limit in chunks must fit the AAD's `u32 chunkCount`.
const _: () = assert!(MAX_ATTACHMENT_BYTES.div_ceil(CHUNK_LEN as u64) <= u32::MAX as u64);

/// Additive only.
pub mod tag {
    use chiavora_protocol::Tag;

    pub const AAD: Tag = 1;
    pub const NONCE: Tag = 2;
    pub const CIPHERTEXT: Tag = 3;
}

/// No variant carries content, a content type or an identifier.
#[derive(Debug)]
pub enum AttachmentError {
    TooLarge {
        max: u64,
    },
    Empty,
    ContentTypeTooLong {
        max: usize,
    },
    LengthMismatch {
        declared: u64,
        read: u64,
    },
    ChunkLength {
        at: u32,
    },
    ChunkMissing {
        at: u32,
    },
    ChunkBinding {
        at: u32,
    },
    ExtraChunks,
    /// The OS message never names content.
    Io(std::io::Error),
    Store(StoreError),
    Payload(ItemError),
    Aad(AadError),
    Wire(WireError),
    Nonce(NonceError),
    NotAnAttachmentChunk,
    MissingField {
        tag: Tag,
    },
    RepeatedField {
        at: usize,
    },
    Malformed {
        at: usize,
    },
}

impl core::fmt::Display for AttachmentError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooLarge { max } => write!(f, "the attachment exceeds the limit of {max} bytes"),
            Self::Empty => f.write_str("an attachment cannot be empty"),
            Self::ContentTypeTooLong { max } => {
                write!(f, "the content type exceeds the bound of {max} bytes")
            }
            Self::LengthMismatch { declared, read } => write!(
                f,
                "the source produced {read} bytes but {declared} were declared; nothing was kept"
            ),
            Self::ChunkLength { at } => {
                write!(f, "chunk {at} is not the length its position requires")
            }
            Self::ChunkMissing { at } => write!(f, "chunk {at} is missing from the store"),
            Self::ChunkBinding { at } => write!(
                f,
                "chunk {at} is bound to a different attachment or version"
            ),
            Self::ExtraChunks => {
                f.write_str("the store holds more chunks than the attachment declares")
            }
            Self::Io(e) => write!(f, "i/o: {e}"),
            Self::Store(e) => write!(f, "{e}"),
            Self::Payload(e) => write!(f, "{e}"),
            Self::Aad(e) => write!(f, "{e}"),
            Self::Wire(e) => write!(f, "{e}"),
            Self::Nonce(e) => write!(f, "{e}"),
            Self::NotAnAttachmentChunk => {
                f.write_str("the stored record's AAD is not an attachment chunk")
            }
            Self::MissingField { tag } => write!(f, "the chunk record has no field with tag {tag}"),
            Self::RepeatedField { at } => write!(f, "field {at} repeats a header"),
            Self::Malformed { at } => write!(f, "field {at} is not shaped as its tag requires"),
        }
    }
}

impl core::error::Error for AttachmentError {}

impl From<std::io::Error> for AttachmentError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<StoreError> for AttachmentError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}
impl From<ItemError> for AttachmentError {
    fn from(e: ItemError) -> Self {
        Self::Payload(e)
    }
}
impl From<AadError> for AttachmentError {
    fn from(e: AadError) -> Self {
        Self::Aad(e)
    }
}
impl From<WireError> for AttachmentError {
    fn from(e: WireError) -> Self {
        Self::Wire(e)
    }
}
impl From<NonceError> for AttachmentError {
    fn from(e: NonceError) -> Self {
        Self::Nonce(e)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct AttachmentRef<'a> {
    pub vault_id: &'a [u8],
    pub item_id: &'a [u8],
    pub version: u64,
    pub attachment_id: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredChunk {
    fields: AadFields,
    payload: SealedPayload,
}

impl StoredChunk {
    pub fn new(fields: AadFields, payload: SealedPayload) -> Result<Self, AttachmentError> {
        if fields.record_type() != RECORD_ATTACHMENT_CHUNK {
            return Err(AttachmentError::NotAnAttachmentChunk);
        }
        Ok(Self { fields, payload })
    }

    #[must_use]
    pub const fn fields(&self) -> &AadFields {
        &self.fields
    }

    #[must_use]
    pub const fn payload(&self) -> &SealedPayload {
        &self.payload
    }

    /// `SHA-256(AAD ‖ nonce ‖ ciphertext ‖ tag)`, the per-chunk digest under
    /// the manifest's `chunkDigestRoot`.
    pub fn digest(&self) -> Result<[u8; 32], AttachmentError> {
        let mut hasher = Sha256::new();
        hasher.update(aad::encode(&self.fields)?);
        hasher.update(self.payload.nonce());
        hasher.update(self.payload.ciphertext());
        Ok(hasher.finalize().into())
    }

    pub fn encode(&self) -> Result<Vec<u8>, AttachmentError> {
        let fields = vec![
            Field::new(tag::AAD, aad::encode(&self.fields)?)?,
            Field::new(tag::NONCE, self.payload.nonce().to_vec())?,
            Field::new(tag::CIPHERTEXT, self.payload.ciphertext().to_vec())?,
        ];
        Ok(Record::new(fields).encode()?)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, AttachmentError> {
        fn once<T>(slot: &mut Option<T>, value: T, at: usize) -> Result<(), AttachmentError> {
            if slot.replace(value).is_some() {
                return Err(AttachmentError::RepeatedField { at });
            }
            Ok(())
        }
        let record = Record::decode(bytes)?;
        let mut aad_bytes: Option<Vec<u8>> = None;
        let mut nonce: Option<[u8; NONCE_LEN]> = None;
        let mut ciphertext: Option<Vec<u8>> = None;
        for (at, field) in record.fields().iter().enumerate() {
            let v = field.value();
            match field.tag() {
                tag::AAD => once(&mut aad_bytes, v.to_vec(), at)?,
                tag::NONCE => once(
                    &mut nonce,
                    v.try_into()
                        .map_err(|_| AttachmentError::Malformed { at })?,
                    at,
                )?,
                tag::CIPHERTEXT => once(&mut ciphertext, v.to_vec(), at)?,
                // A newer build's field; the store keeps the original bytes.
                _ => {}
            }
        }
        let fields =
            aad::decode(&aad_bytes.ok_or(AttachmentError::MissingField { tag: tag::AAD })?)?;
        if fields.record_type() != RECORD_ATTACHMENT_CHUNK {
            return Err(AttachmentError::NotAnAttachmentChunk);
        }
        let payload = SealedPayload::from_stored_parts(
            nonce.ok_or(AttachmentError::MissingField { tag: tag::NONCE })?,
            ciphertext.ok_or(AttachmentError::MissingField {
                tag: tag::CIPHERTEXT,
            })?,
        );
        Ok(Self { fields, payload })
    }
}

fn chunk_count_for(declared: u64) -> Result<u32, AttachmentError> {
    let chunks = declared.div_ceil(CHUNK_LEN as u64);
    // Cannot fail within the policy limit, but propagated rather than assumed.
    u32::try_from(chunks).map_err(|_| AttachmentError::TooLarge {
        max: MAX_ATTACHMENT_BYTES,
    })
}

fn chunk_fields(at: AttachmentRef<'_>, content_type: &[u8], index: u32, count: u32) -> AadFields {
    AadFields::AttachmentChunk {
        vault_id: at.vault_id.to_vec(),
        item_id: at.item_id.to_vec(),
        version: at.version,
        attachment_id: at.attachment_id.to_vec(),
        chunk_index: index,
        chunk_count: count,
        content_type: content_type.to_vec(),
    }
}

/// `declared_len` must be exact, since `chunkCount` is in every chunk's AAD.
pub fn seal_attachment(
    store: &mut Store,
    item_key: &Secret<ItemKey>,
    at: AttachmentRef<'_>,
    content_type: &[u8],
    declared_len: u64,
    mut source: impl Read,
) -> Result<u32, AttachmentError> {
    if declared_len == 0 {
        return Err(AttachmentError::Empty);
    }
    if declared_len > MAX_ATTACHMENT_BYTES {
        return Err(AttachmentError::TooLarge {
            max: MAX_ATTACHMENT_BYTES,
        });
    }
    if content_type.len() > MAX_CONTENT_TYPE_BYTES {
        return Err(AttachmentError::ContentTypeTooLong {
            max: MAX_CONTENT_TYPE_BYTES,
        });
    }
    let count = chunk_count_for(declared_len)?;

    // Start clean, so a chunk left by an earlier attempt cannot pass as current.
    store.delete_attachment(at.vault_id, at.item_id, at.attachment_id)?;

    let mut buffer = Zeroizing::new(vec![0_u8; CHUNK_LEN]);
    let mut total: u64 = 0;
    let result = (|| -> Result<(), AttachmentError> {
        for index in 0..count {
            let remaining = declared_len.saturating_sub(total);
            let want = usize::try_from(remaining.min(CHUNK_LEN as u64))
                .map_err(|_| AttachmentError::ChunkLength { at: index })?;
            let chunk = buffer
                .get_mut(..want)
                .ok_or(AttachmentError::ChunkLength { at: index })?;
            read_exact_or_short(&mut source, chunk).map_err(|read| {
                AttachmentError::LengthMismatch {
                    declared: declared_len,
                    read: total.saturating_add(read),
                }
            })?;
            total = total.saturating_add(want as u64);

            let fields = chunk_fields(at, content_type, index, count);
            let payload = item::seal_chunk(item_key, FreshNonce::generate()?, &fields, chunk)?;
            let encoded = StoredChunk::new(fields, payload)?.encode()?;
            store.put_chunk_raw(at.vault_id, at.item_id, at.attachment_id, index, &encoded)?;
        }
        let mut probe = [0_u8; 1];
        if source.read(&mut probe)? != 0 {
            return Err(AttachmentError::LengthMismatch {
                declared: declared_len,
                read: total.saturating_add(1),
            });
        }
        Ok(())
    })();

    if let Err(e) = result {
        // The cleanup's own error is secondary to the reason for it.
        let _ = store.delete_attachment(at.vault_id, at.item_id, at.attachment_id);
        return Err(e);
    }
    Ok(count)
}

/// Fills `buf` exactly, or returns how many bytes were read before the source ran dry.
fn read_exact_or_short(source: &mut impl Read, buf: &mut [u8]) -> Result<(), u64> {
    let mut filled = 0_usize;
    while let Some(tail) = buf.get_mut(filled..).filter(|tail| !tail.is_empty()) {
        let n = source.read(tail).map_err(|_| filled as u64)?;
        if n == 0 {
            return Err(filled as u64);
        }
        filled = filled.saturating_add(n);
    }
    Ok(())
}

pub fn open_attachment(
    store: &Store,
    item_key: &Secret<ItemKey>,
    at: AttachmentRef<'_>,
    mut sink: impl Write,
) -> Result<u64, AttachmentError> {
    let indices = store.list_chunks(at.vault_id, at.item_id, at.attachment_id)?;
    let first = store
        .get_chunk_raw(at.vault_id, at.item_id, at.attachment_id, 0)?
        .ok_or(AttachmentError::ChunkMissing { at: 0 })?;
    let first = StoredChunk::decode(&first)?;
    let AadFields::AttachmentChunk {
        chunk_count: count, ..
    } = *first.fields()
    else {
        return Err(AttachmentError::NotAnAttachmentChunk);
    };
    if indices.iter().any(|&index| index >= count) {
        return Err(AttachmentError::ExtraChunks);
    }

    let mut total: u64 = 0;
    for index in 0..count {
        let raw = store
            .get_chunk_raw(at.vault_id, at.item_id, at.attachment_id, index)?
            .ok_or(AttachmentError::ChunkMissing { at: index })?;
        let chunk = StoredChunk::decode(&raw)?;
        // The AEAD would refuse a mismatch too; checking here names the reason.
        let AadFields::AttachmentChunk {
            vault_id,
            item_id,
            version,
            attachment_id,
            chunk_index,
            chunk_count,
            ..
        } = chunk.fields()
        else {
            return Err(AttachmentError::NotAnAttachmentChunk);
        };
        if vault_id != at.vault_id
            || item_id != at.item_id
            || *version != at.version
            || attachment_id != at.attachment_id
            || *chunk_index != index
            || *chunk_count != count
        {
            return Err(AttachmentError::ChunkBinding { at: index });
        }
        let plaintext =
            Zeroizing::new(item::open_chunk(item_key, chunk.payload(), chunk.fields())?);
        let is_last = index.saturating_add(1) == count;
        let ok_len = if is_last {
            !plaintext.is_empty() && plaintext.len() <= CHUNK_LEN
        } else {
            plaintext.len() == CHUNK_LEN
        };
        if !ok_len {
            return Err(AttachmentError::ChunkLength { at: index });
        }
        sink.write_all(&plaintext)?;
        total = total.saturating_add(plaintext.len() as u64);
    }
    sink.flush()?;
    Ok(total)
}
