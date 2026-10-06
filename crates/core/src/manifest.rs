//! The §2.5 vault manifest. Every byte comes from the server, so this is a parser first.

use core::fmt;

use chiavora_protocol::{Field, Record, Tag, WireError};
use sha2::{Digest, Sha256};

use crate::aad::{self, AadError, AadFields};
use crate::item::{self, ItemError, SealedPayload};
use crate::nonce::FreshNonce;
use crate::secret::{kind::VaultKey, Secret};
use crate::store::{RollbackProtection, Store, StoreError};

pub const TARGET_ENTRIES_PER_SEGMENT: usize = 256;

pub const SPLIT_AT_ENTRIES: usize = 512;

const KEYSPACE: u128 = 1 << 64;

pub mod root_tag {
    use chiavora_protocol::Tag;

    pub const SEGMENT: Tag = 1;
}

pub mod segment_tag {
    use chiavora_protocol::Tag;

    pub const ENTRY: Tag = 1;
}

pub mod root_entry_tag {
    use chiavora_protocol::Tag;

    pub const PREFIX_LEN: Tag = 1;
    pub const PREFIX_BITS: Tag = 2;
    pub const DIGEST: Tag = 3;
    pub const SEGMENT_SEQ: Tag = 4;
}

pub mod entry_tag {
    use chiavora_protocol::Tag;

    pub const ITEM_ID: Tag = 1;
    pub const CURRENT_VERSION: Tag = 2;
    pub const CIPHERTEXT_DIGEST: Tag = 3;
    pub const TOMBSTONE: Tag = 4;
    pub const ATTACHMENT: Tag = 5;
}

pub mod attachment_tag {
    use chiavora_protocol::Tag;

    pub const ATTACHMENT_ID: Tag = 1;
    pub const CHUNK_COUNT: Tag = 2;
    pub const CHUNK_DIGEST_ROOT: Tag = 3;
    pub const TOTAL_SIZE: Tag = 4;
}

/// No variant carries any of the input: a count or a tag, never bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestError {
    Aad(AadError),
    Wire(WireError),
    /// Carries no payload, so `ManifestError` stays `Copy` and `Eq`.
    StoreRefused,
    Sealed(ItemError),
    NonCanonicalPrefix(AadError),
    NotAManifestRoot,
    NotAManifestSegment,
    SegmentCountDisagrees {
        declared: u32,
        present: usize,
    },
    PrefixSetHasGap {
        from: u64,
        through: u64,
    },
    PrefixSetOverlaps {
        at: u64,
    },
    UnexpectedField {
        expected: Tag,
    },
    BadFieldLength {
        tag: Tag,
    },
    NotABoolean,
    TrailingFields,
    TooManySegments,
    RootBelowHighWaterMark {
        offered: u64,
        mark: u64,
    },
    SegmentNotInRoot {
        prefix_len: u8,
    },
    SegmentListedNotDelivered {
        prefix_len: u8,
    },
    SegmentDigestMismatch,
    ItemVersionRollback {
        delivered: u64,
        current: u64,
    },
    CiphertextDigestMismatch,
    ItemListedNotDelivered,
    ItemDeliveredNotListed,
    HighWaterMarkRewound,
    ConflictNeedsResolution,
    NoManifestToRotate,
    EpochNotSuccessive {
        current: u32,
        offered: u32,
    },
    RotationChangedAnEntry,
    NonceUnavailable,
    TransportFailed,
}

impl fmt::Display for ManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Aad(e) => write!(f, "manifest AAD: {e}"),
            Self::Wire(e) => write!(f, "manifest framing: {e}"),
            Self::Sealed(e) => write!(f, "manifest record: {e}"),
            Self::StoreRefused => f.write_str("the local store refused a sync write"),
            Self::NonCanonicalPrefix(e) => {
                write!(f, "non-canonical segment prefix, so I6b fails: {e}")
            }
            Self::NotAManifestRoot => f.write_str("not a 0x03 manifest root"),
            Self::NotAManifestSegment => f.write_str("not a 0x04 manifest segment"),
            Self::SegmentCountDisagrees { declared, present } => write!(
                f,
                "the manifest root's AAD declares {declared} segments and its body carries {present}"
            ),
            Self::PrefixSetHasGap { from, through } => write!(
                f,
                "the segment prefixes do not tile the keyspace: {from:#018x}..={through:#018x} \
                 is in no segment"
            ),
            Self::PrefixSetOverlaps { at } => write!(
                f,
                "the segment prefixes overlap: {at:#018x} is in more than one segment"
            ),
            Self::UnexpectedField { expected } => {
                write!(f, "a manifest record is missing field {expected}")
            }
            Self::BadFieldLength { tag } => {
                write!(f, "manifest field {tag} is the wrong length")
            }
            Self::NotABoolean => f.write_str("a tombstone byte is neither 0 nor 1"),
            Self::TrailingFields => f.write_str("trailing fields after a complete manifest record"),
            Self::TooManySegments => {
                f.write_str("a root would carry more segments than u32 can count")
            }
            Self::RootBelowHighWaterMark { offered, mark } => write!(
                f,
                "the manifest root offers manifestSeq {offered}, below the {mark} this device \
                 has accepted: a vault-wide rollback"
            ),
            Self::SegmentNotInRoot { prefix_len } => write!(
                f,
                "the root vouches for no segment at prefix length {prefix_len}"
            ),
            Self::SegmentListedNotDelivered { prefix_len } => write!(
                f,
                "the root names a segment at prefix length {prefix_len} that the server did not deliver"
            ),
            Self::SegmentDigestMismatch => {
                f.write_str("the segment's digest is not the one the root vouches for")
            }
            Self::ItemVersionRollback { delivered, current } => write!(
                f,
                "an item arrived at version {delivered}, below the {current} the manifest \
                 vouches for: a replayed item"
            ),
            Self::CiphertextDigestMismatch => f.write_str(
                "an item's ciphertext is not the one its manifest entry vouches for: a \
                 substitution at an unchanged version",
            ),
            Self::ItemListedNotDelivered => {
                f.write_str("the manifest lists an item the server did not deliver")
            }
            Self::ItemDeliveredNotListed => {
                f.write_str("the server delivered an item no segment lists")
            }
            Self::NoManifestToRotate => {
                f.write_str("this vault has no manifest to rotate")
            }
            Self::EpochNotSuccessive { current, offered } => write!(
                f,
                "a rotation offered vaultKeyEpoch {offered}, which is not one above {current}"
            ),
            Self::RotationChangedAnEntry => f.write_str(
                "a rotation's re-sealed manifest did not open to what it was built from",
            ),
            Self::ConflictNeedsResolution => f.write_str(
                "two devices advanced the same item to the same version with different                  contents: both are kept and the conflict is resolved, never discarded",
            ),
            Self::NonceUnavailable => {
                f.write_str("the platform CSPRNG refused a nonce, so nothing was sealed")
            }
            Self::TransportFailed => f.write_str("the manifest transport failed"),
            Self::HighWaterMarkRewound => f.write_str(
                "the on-disk high-water mark went backwards, which no honest client does",
            ),
        }
    }
}

impl core::error::Error for ManifestError {}

impl From<AadError> for ManifestError {
    fn from(e: AadError) -> Self {
        Self::Aad(e)
    }
}

impl From<WireError> for ManifestError {
    fn from(e: WireError) -> Self {
        Self::Wire(e)
    }
}

impl From<ItemError> for ManifestError {
    fn from(e: ItemError) -> Self {
        Self::Sealed(e)
    }
}

impl From<crate::nonce::NonceError> for ManifestError {
    fn from(_: crate::nonce::NonceError) -> Self {
        Self::NonceUnavailable
    }
}

/// A segment prefix that has passed §2.2's canonicalisation rules. It has no
/// infallible constructor, and [`tiles_exactly`] takes nothing else.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct CanonicalPrefix {
    bits: u64,
    len: u8,
}

impl CanonicalPrefix {
    pub const fn new(len: u8, bits: u64) -> Result<Self, ManifestError> {
        match aad::check_prefix(len, bits) {
            Ok(()) => Ok(Self { bits, len }),
            Err(e) => Err(ManifestError::NonCanonicalPrefix(e)),
        }
    }

    #[must_use]
    pub const fn bit_len(&self) -> u8 {
        self.len
    }

    #[must_use]
    pub const fn bits(&self) -> u64 {
        self.bits
    }

    const fn span(&self) -> u128 {
        1_u128 << (64 - self.len as u32)
    }

    #[must_use]
    pub const fn contains(&self, hash: u64) -> bool {
        // A shift by 64 is undefined, and every hash is under the empty prefix.
        if self.len == 0 {
            return true;
        }
        (hash >> (64 - self.len as u32)) == (self.bits >> (64 - self.len as u32))
    }
}

/// Big-endian so a prefix matches the front of the digest (§2.5). Read the other way,
/// every root would still tile while items landed in the wrong segments.
#[must_use]
pub fn hash_item_id(item_id: &[u8]) -> u64 {
    let digest: [u8; 32] = Sha256::digest(item_id).into();
    // Destructured rather than sliced, so there is no fallible step.
    let [b0, b1, b2, b3, b4, b5, b6, b7, ..] = digest;
    u64::from_be_bytes([b0, b1, b2, b3, b4, b5, b6, b7])
}

/// I6b. Takes only [`CanonicalPrefix`], since non-canonical prefixes could hide a range.
pub fn tiles_exactly(prefixes: &[CanonicalPrefix]) -> Result<(), ManifestError> {
    // Sorted by `bits` (the field order), so coverage is one walk over aligned ranges.
    let mut sorted: Vec<CanonicalPrefix> = prefixes.to_vec();
    sorted.sort_unstable();

    let mut next: u128 = 0;
    for prefix in &sorted {
        let start = u128::from(prefix.bits());
        if start < next {
            return Err(ManifestError::PrefixSetOverlaps { at: prefix.bits() });
        }
        if start > next {
            return Err(ManifestError::PrefixSetHasGap {
                from: truncate(next),
                through: truncate(start - 1),
            });
        }
        next = next.saturating_add(prefix.span());
    }
    if next < KEYSPACE {
        return Err(ManifestError::PrefixSetHasGap {
            from: truncate(next),
            through: u64::MAX,
        });
    }
    Ok(())
}

fn truncate(position: u128) -> u64 {
    // R1: a gap is only reported below `KEYSPACE`, so the fallback is unreachable.
    u64::try_from(position).unwrap_or(u64::MAX)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootEntry {
    prefix: CanonicalPrefix,
    digest: [u8; 32],
    segment_seq: u64,
}

impl RootEntry {
    #[must_use]
    pub const fn new(prefix: CanonicalPrefix, digest: [u8; 32], segment_seq: u64) -> Self {
        Self {
            prefix,
            digest,
            segment_seq,
        }
    }

    #[must_use]
    pub const fn prefix(&self) -> CanonicalPrefix {
        self.prefix
    }

    /// SHA-256 over the whole stored segment record, `AAD ‖ nonce ‖ ciphertext ‖ tag`.
    #[must_use]
    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    #[must_use]
    pub const fn segment_seq(&self) -> u64 {
        self.segment_seq
    }

    fn encode(&self) -> Result<Vec<u8>, ManifestError> {
        let fields = vec![
            Field::new(root_entry_tag::PREFIX_LEN, vec![self.prefix.bit_len()])?,
            Field::new(
                root_entry_tag::PREFIX_BITS,
                self.prefix.bits().to_le_bytes().to_vec(),
            )?,
            Field::new(root_entry_tag::DIGEST, self.digest.to_vec())?,
            Field::new(
                root_entry_tag::SEGMENT_SEQ,
                self.segment_seq.to_le_bytes().to_vec(),
            )?,
        ];
        Ok(Record::new(fields).encode()?)
    }

    fn decode(bytes: &[u8]) -> Result<Self, ManifestError> {
        let record = Record::decode(bytes)?;
        let mut r = Fields::new(record.fields());
        let len = r.u8(root_entry_tag::PREFIX_LEN)?;
        let bits = r.u64(root_entry_tag::PREFIX_BITS)?;
        let digest = r.digest(root_entry_tag::DIGEST)?;
        let segment_seq = r.u64(root_entry_tag::SEGMENT_SEQ)?;
        r.finish()?;
        Ok(Self {
            prefix: CanonicalPrefix::new(len, bits)?,
            digest,
            segment_seq,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachmentEntry {
    attachment_id: Vec<u8>,
    chunk_count: u32,
    chunk_digest_root: [u8; 32],
    total_size: u64,
}

impl AttachmentEntry {
    #[must_use]
    pub const fn new(
        attachment_id: Vec<u8>,
        chunk_count: u32,
        chunk_digest_root: [u8; 32],
        total_size: u64,
    ) -> Self {
        Self {
            attachment_id,
            chunk_count,
            chunk_digest_root,
            total_size,
        }
    }

    #[must_use]
    pub fn attachment_id(&self) -> &[u8] {
        &self.attachment_id
    }

    #[must_use]
    pub const fn chunk_count(&self) -> u32 {
        self.chunk_count
    }

    /// SHA-256 over the ordered concatenation of the per-chunk digests; not a
    /// Merkle tree, despite the name.
    #[must_use]
    pub const fn chunk_digest_root(&self) -> &[u8; 32] {
        &self.chunk_digest_root
    }

    #[must_use]
    pub const fn total_size(&self) -> u64 {
        self.total_size
    }

    fn encode(&self) -> Result<Vec<u8>, ManifestError> {
        let fields = vec![
            Field::new(attachment_tag::ATTACHMENT_ID, self.attachment_id.clone())?,
            Field::new(
                attachment_tag::CHUNK_COUNT,
                self.chunk_count.to_le_bytes().to_vec(),
            )?,
            Field::new(
                attachment_tag::CHUNK_DIGEST_ROOT,
                self.chunk_digest_root.to_vec(),
            )?,
            Field::new(
                attachment_tag::TOTAL_SIZE,
                self.total_size.to_le_bytes().to_vec(),
            )?,
        ];
        Ok(Record::new(fields).encode()?)
    }

    fn decode(bytes: &[u8]) -> Result<Self, ManifestError> {
        let record = Record::decode(bytes)?;
        let mut r = Fields::new(record.fields());
        let attachment_id = r.bytes(attachment_tag::ATTACHMENT_ID)?.to_vec();
        let chunk_count = r.u32(attachment_tag::CHUNK_COUNT)?;
        let chunk_digest_root = r.digest(attachment_tag::CHUNK_DIGEST_ROOT)?;
        let total_size = r.u64(attachment_tag::TOTAL_SIZE)?;
        r.finish()?;
        Ok(Self {
            attachment_id,
            chunk_count,
            chunk_digest_root,
            total_size,
        })
    }
}

/// A tombstone is a presence: an item that vanishes without one is an attack,
/// not a delete (I6e).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    item_id: Vec<u8>,
    current_version: u64,
    ciphertext_digest: [u8; 32],
    tombstone: bool,
    attachments: Vec<AttachmentEntry>,
}

impl Entry {
    #[must_use]
    pub const fn new(
        item_id: Vec<u8>,
        current_version: u64,
        ciphertext_digest: [u8; 32],
        tombstone: bool,
        attachments: Vec<AttachmentEntry>,
    ) -> Self {
        Self {
            item_id,
            current_version,
            ciphertext_digest,
            tombstone,
            attachments,
        }
    }

    #[must_use]
    pub fn item_id(&self) -> &[u8] {
        &self.item_id
    }

    #[must_use]
    pub const fn current_version(&self) -> u64 {
        self.current_version
    }

    /// SHA-256 over the payload record only, excluding the wrapped Item Keys (§2.5).
    #[must_use]
    pub const fn ciphertext_digest(&self) -> &[u8; 32] {
        &self.ciphertext_digest
    }

    #[must_use]
    pub const fn tombstone(&self) -> bool {
        self.tombstone
    }

    #[must_use]
    pub fn attachments(&self) -> &[AttachmentEntry] {
        &self.attachments
    }

    fn encode(&self) -> Result<Vec<u8>, ManifestError> {
        let mut fields = vec![
            Field::new(entry_tag::ITEM_ID, self.item_id.clone())?,
            Field::new(
                entry_tag::CURRENT_VERSION,
                self.current_version.to_le_bytes().to_vec(),
            )?,
            Field::new(
                entry_tag::CIPHERTEXT_DIGEST,
                self.ciphertext_digest.to_vec(),
            )?,
            Field::new(entry_tag::TOMBSTONE, vec![u8::from(self.tombstone)])?,
        ];
        for attachment in &self.attachments {
            fields.push(Field::new(entry_tag::ATTACHMENT, attachment.encode()?)?);
        }
        Ok(Record::new(fields).encode()?)
    }

    fn decode(bytes: &[u8]) -> Result<Self, ManifestError> {
        let record = Record::decode(bytes)?;
        let mut r = Fields::new(record.fields());
        let item_id = r.bytes(entry_tag::ITEM_ID)?.to_vec();
        let current_version = r.u64(entry_tag::CURRENT_VERSION)?;
        let ciphertext_digest = r.digest(entry_tag::CIPHERTEXT_DIGEST)?;
        let tombstone = match r.u8(entry_tag::TOMBSTONE)? {
            0 => false,
            1 => true,
            _ => return Err(ManifestError::NotABoolean),
        };
        let mut attachments = Vec::new();
        while let Some(value) = r.next_if(entry_tag::ATTACHMENT) {
            attachments.push(AttachmentEntry::decode(value)?);
        }
        r.finish()?;
        Ok(Self {
            item_id,
            current_version,
            ciphertext_digest,
            tombstone,
            attachments,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestRoot {
    fields: AadFields,
    segments: Vec<RootEntry>,
}

impl ManifestRoot {
    pub fn new(fields: AadFields, segments: Vec<RootEntry>) -> Result<Self, ManifestError> {
        let AadFields::ManifestRoot { segment_count, .. } = fields else {
            return Err(ManifestError::NotAManifestRoot);
        };
        // Compared, never used to size anything: it arrives before the tag is checked.
        if usize::try_from(segment_count) != Ok(segments.len()) {
            return Err(ManifestError::SegmentCountDisagrees {
                declared: segment_count,
                present: segments.len(),
            });
        }
        Ok(Self { fields, segments })
    }

    #[must_use]
    pub const fn fields(&self) -> &AadFields {
        &self.fields
    }

    #[must_use]
    pub const fn manifest_seq(&self) -> u64 {
        match self.fields {
            AadFields::ManifestRoot { manifest_seq, .. } => manifest_seq,
            // Unreachable: `new` refuses anything else.
            _ => 0,
        }
    }

    #[must_use]
    pub const fn vault_key_epoch(&self) -> u32 {
        match self.fields {
            AadFields::ManifestRoot {
                vault_key_epoch, ..
            } => vault_key_epoch,
            _ => 0,
        }
    }

    #[must_use]
    pub fn segments(&self) -> &[RootEntry] {
        &self.segments
    }

    pub fn check_tiles(&self) -> Result<(), ManifestError> {
        let prefixes: Vec<CanonicalPrefix> = self.segments.iter().map(RootEntry::prefix).collect();
        tiles_exactly(&prefixes)
    }

    #[must_use]
    pub fn segment_for(&self, hash: u64) -> Option<&RootEntry> {
        self.segments
            .iter()
            .filter(|entry| entry.prefix().contains(hash))
            .max_by_key(|entry| entry.prefix().bit_len())
    }

    pub fn encode_body(&self) -> Result<Vec<u8>, ManifestError> {
        let mut fields = Vec::new();
        for segment in &self.segments {
            fields.push(Field::new(root_tag::SEGMENT, segment.encode()?)?);
        }
        Ok(Record::new(fields).encode()?)
    }

    pub fn decode(fields: AadFields, bytes: &[u8]) -> Result<Self, ManifestError> {
        let record = Record::decode(bytes)?;
        let mut segments = Vec::new();
        let mut r = Fields::new(record.fields());
        while let Some(value) = r.next_if(root_tag::SEGMENT) {
            segments.push(RootEntry::decode(value)?);
        }
        r.finish()?;
        Self::new(fields, segments)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestSegment {
    fields: AadFields,
    entries: Vec<Entry>,
}

impl ManifestSegment {
    pub fn new(fields: AadFields, entries: Vec<Entry>) -> Result<Self, ManifestError> {
        if !matches!(fields, AadFields::ManifestSegment { .. }) {
            return Err(ManifestError::NotAManifestSegment);
        }
        Ok(Self { fields, entries })
    }

    #[must_use]
    pub const fn fields(&self) -> &AadFields {
        &self.fields
    }

    #[must_use]
    pub const fn segment_seq(&self) -> u64 {
        match self.fields {
            AadFields::ManifestSegment { segment_seq, .. } => segment_seq,
            _ => 0,
        }
    }

    #[must_use]
    pub const fn vault_key_epoch(&self) -> u32 {
        match self.fields {
            AadFields::ManifestSegment {
                vault_key_epoch, ..
            } => vault_key_epoch,
            _ => 0,
        }
    }

    pub const fn prefix(&self) -> Result<CanonicalPrefix, ManifestError> {
        match self.fields {
            AadFields::ManifestSegment {
                prefix_len,
                prefix_bits,
                ..
            } => CanonicalPrefix::new(prefix_len, prefix_bits),
            _ => Err(ManifestError::NotAManifestSegment),
        }
    }

    #[must_use]
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    #[must_use]
    pub fn is_over_split_bound(&self) -> bool {
        self.entries.len() >= SPLIT_AT_ENTRIES
    }

    pub fn encode_body(&self) -> Result<Vec<u8>, ManifestError> {
        let mut fields = Vec::new();
        for entry in &self.entries {
            fields.push(Field::new(segment_tag::ENTRY, entry.encode()?)?);
        }
        Ok(Record::new(fields).encode()?)
    }

    pub fn decode(fields: AadFields, bytes: &[u8]) -> Result<Self, ManifestError> {
        let record = Record::decode(bytes)?;
        let mut entries = Vec::new();
        let mut r = Fields::new(record.fields());
        while let Some(value) = r.next_if(segment_tag::ENTRY) {
            entries.push(Entry::decode(value)?);
        }
        r.finish()?;
        Self::new(fields, entries)
    }
}

/// A reordering is refused, since digests are taken over bytes.
struct Fields<'a> {
    fields: &'a [Field],
    at: usize,
}

impl<'a> Fields<'a> {
    const fn new(fields: &'a [Field]) -> Self {
        Self { fields, at: 0 }
    }

    fn next_if(&mut self, tag: Tag) -> Option<&'a [u8]> {
        let field = self.fields.get(self.at)?;
        if field.tag() == tag {
            self.at += 1;
            return Some(field.value());
        }
        None
    }

    fn bytes(&mut self, tag: Tag) -> Result<&'a [u8], ManifestError> {
        self.next_if(tag)
            .ok_or(ManifestError::UnexpectedField { expected: tag })
    }

    fn fixed<const N: usize>(&mut self, tag: Tag) -> Result<[u8; N], ManifestError> {
        let value = self.bytes(tag)?;
        <[u8; N]>::try_from(value).map_err(|_| ManifestError::BadFieldLength { tag })
    }

    fn u8(&mut self, tag: Tag) -> Result<u8, ManifestError> {
        let [byte] = self.fixed::<1>(tag)?;
        Ok(byte)
    }

    fn u32(&mut self, tag: Tag) -> Result<u32, ManifestError> {
        Ok(u32::from_le_bytes(self.fixed::<4>(tag)?))
    }

    fn u64(&mut self, tag: Tag) -> Result<u64, ManifestError> {
        Ok(u64::from_le_bytes(self.fixed::<8>(tag)?))
    }

    fn digest(&mut self, tag: Tag) -> Result<[u8; 32], ManifestError> {
        self.fixed::<32>(tag)
    }

    const fn finish(&self) -> Result<(), ManifestError> {
        if self.at == self.fields.len() {
            Ok(())
        } else {
            Err(ManifestError::TrailingFields)
        }
    }
}

pub mod stored_tag {
    use chiavora_protocol::Tag;

    pub const AAD: Tag = 1;
    pub const NONCE: Tag = 2;
    pub const CIPHERTEXT: Tag = 3;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredManifest {
    fields: AadFields,
    payload: SealedPayload,
}

impl StoredManifest {
    pub fn new(fields: AadFields, payload: SealedPayload) -> Result<Self, ManifestError> {
        if !matches!(
            fields,
            AadFields::ManifestRoot { .. } | AadFields::ManifestSegment { .. }
        ) {
            return Err(ManifestError::NotAManifestRoot);
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

    pub fn digest(&self) -> Result<[u8; 32], ManifestError> {
        let mut hasher = Sha256::new();
        hasher.update(aad::encode(&self.fields)?);
        hasher.update(self.payload.nonce());
        // The AEAD tag is already appended to the ciphertext.
        hasher.update(self.payload.ciphertext());
        Ok(hasher.finalize().into())
    }

    pub fn encode(&self) -> Result<Vec<u8>, ManifestError> {
        let fields = vec![
            Field::new(stored_tag::AAD, aad::encode(&self.fields)?)?,
            Field::new(stored_tag::NONCE, self.payload.nonce().to_vec())?,
            Field::new(stored_tag::CIPHERTEXT, self.payload.ciphertext().to_vec())?,
        ];
        Ok(Record::new(fields).encode()?)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ManifestError> {
        let record = Record::decode(bytes)?;
        let mut r = Fields::new(record.fields());
        let aad_bytes = r.bytes(stored_tag::AAD)?;
        let nonce = r.fixed::<24>(stored_tag::NONCE)?;
        let ciphertext = r.bytes(stored_tag::CIPHERTEXT)?.to_vec();
        r.finish()?;
        Self::new(
            aad::decode(aad_bytes)?,
            SealedPayload::from_stored_parts(nonce, ciphertext),
        )
    }
}

pub fn seal_root(
    vault_key: &Secret<VaultKey>,
    nonce: FreshNonce,
    root: &ManifestRoot,
) -> Result<StoredManifest, ManifestError> {
    let body = root.encode_body()?;
    let payload = item::seal_record(
        vault_key,
        nonce,
        root.fields(),
        &body,
        aad::RECORD_MANIFEST_ROOT,
    )?;
    StoredManifest::new(root.fields().clone(), payload)
}

pub fn seal_segment(
    vault_key: &Secret<VaultKey>,
    nonce: FreshNonce,
    segment: &ManifestSegment,
) -> Result<StoredManifest, ManifestError> {
    let body = segment.encode_body()?;
    let payload = item::seal_record(
        vault_key,
        nonce,
        segment.fields(),
        &body,
        aad::RECORD_MANIFEST_SEGMENT,
    )?;
    StoredManifest::new(segment.fields().clone(), payload)
}

pub fn open_root(
    vault_key: &Secret<VaultKey>,
    stored: &StoredManifest,
) -> Result<ManifestRoot, ManifestError> {
    if !matches!(stored.fields(), AadFields::ManifestRoot { .. }) {
        return Err(ManifestError::NotAManifestRoot);
    }
    let body = item::open_record(
        vault_key,
        stored.payload(),
        stored.fields(),
        aad::RECORD_MANIFEST_ROOT,
    )?;
    ManifestRoot::decode(stored.fields().clone(), &body)
}

pub fn open_segment(
    vault_key: &Secret<VaultKey>,
    stored: &StoredManifest,
) -> Result<ManifestSegment, ManifestError> {
    if !matches!(stored.fields(), AadFields::ManifestSegment { .. }) {
        return Err(ManifestError::NotAManifestSegment);
    }
    let body = item::open_record(
        vault_key,
        stored.payload(),
        stored.fields(),
        aad::RECORD_MANIFEST_SEGMENT,
    )?;
    ManifestSegment::decode(stored.fields().clone(), &body)
}

impl ManifestRoot {
    pub fn check_not_rolled_back(&self, mark: Option<u64>) -> Result<(), ManifestError> {
        if let Some(mark) = mark {
            let offered = self.manifest_seq();
            if offered < mark {
                return Err(ManifestError::RootBelowHighWaterMark { offered, mark });
            }
        }
        Ok(())
    }

    /// I6a then I6b, before any segment is read, since a gap would hide every item in it.
    pub fn accept(&self, mark: Option<u64>) -> Result<(), ManifestError> {
        self.check_not_rolled_back(mark)?;
        self.check_tiles()
    }

    pub fn vouched_digest(&self, prefix: CanonicalPrefix) -> Result<&[u8; 32], ManifestError> {
        self.segments()
            .iter()
            .find(|entry| entry.prefix() == prefix)
            .map(RootEntry::digest)
            .ok_or(ManifestError::SegmentNotInRoot {
                prefix_len: prefix.bit_len(),
            })
    }

    /// I6b. Takes the stored record, since the digest is over it.
    pub fn accept_segment(&self, stored: &StoredManifest) -> Result<(), ManifestError> {
        let AadFields::ManifestSegment {
            prefix_len,
            prefix_bits,
            ..
        } = *stored.fields()
        else {
            return Err(ManifestError::NotAManifestSegment);
        };
        let prefix = CanonicalPrefix::new(prefix_len, prefix_bits)?;
        let vouched = *self.vouched_digest(prefix)?;
        if stored.digest()? != vouched {
            return Err(ManifestError::SegmentDigestMismatch);
        }
        Ok(())
    }
}

impl Entry {
    /// I6c, then I6d: the version is checked first, since it names a replay.
    pub fn accept_item(&self, version: u64, digest: &[u8; 32]) -> Result<(), ManifestError> {
        if version < self.current_version() {
            return Err(ManifestError::ItemVersionRollback {
                delivered: version,
                current: self.current_version(),
            });
        }
        if digest != self.ciphertext_digest() {
            return Err(ManifestError::CiphertextDigestMismatch);
        }
        Ok(())
    }
}

impl ManifestSegment {
    #[must_use]
    pub fn entry(&self, item_id: &[u8]) -> Option<&Entry> {
        self.entries().iter().find(|e| e.item_id() == item_id)
    }

    /// I6e, both ways. A tombstoned entry must be absent from `delivered`.
    pub fn reconcile(&self, delivered: &[&[u8]]) -> Result<(), ManifestError> {
        for entry in self.entries() {
            let present = delivered.iter().any(|id| *id == entry.item_id());
            if entry.tombstone() {
                if present {
                    return Err(ManifestError::ItemDeliveredNotListed);
                }
            } else if !present {
                return Err(ManifestError::ItemListedNotDelivered);
            }
        }
        for id in delivered {
            if self.entry(id).is_none() {
                return Err(ManifestError::ItemDeliveredNotListed);
            }
        }
        Ok(())
    }
}

/// Without a platform anchor, a whole-file rewind of the local store goes unseen, and
/// I6f is only as good as the mark.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncPosture {
    rollback: RollbackProtection,
}

impl SyncPosture {
    #[must_use]
    pub fn of(store: &Store) -> Self {
        Self {
            rollback: store.rollback_protection(),
        }
    }

    #[must_use]
    pub const fn detects_local_rewind(&self) -> bool {
        matches!(self.rollback, RollbackProtection::Anchored)
    }

    #[must_use]
    pub const fn rollback_protection(&self) -> RollbackProtection {
        self.rollback
    }
}

/// I6f: raises the mark after a root is accepted.
pub fn advance_high_water_mark(
    store: &mut Store,
    vault_id: &[u8],
    root: &ManifestRoot,
) -> Result<(), ManifestError> {
    match store.set_high_water_mark(vault_id, root.manifest_seq()) {
        Ok(()) => Ok(()),
        Err(StoreError::HighWaterMarkDecrease { .. }) => Err(ManifestError::HighWaterMarkRewound),
        Err(_) => Err(ManifestError::StoreRefused),
    }
}

impl CanonicalPrefix {
    pub fn split(self) -> Result<(Self, Self), ManifestError> {
        let longer = self.bit_len().saturating_add(1);
        // A length of 65 is left for `Self::new` to refuse, the one home of the rule.
        let bit = 64_u32
            .checked_sub(u32::from(longer))
            .map_or(0, |shift| 1_u64 << shift);
        Ok((
            Self::new(longer, self.bits())?,
            Self::new(longer, self.bits() | bit)?,
        ))
    }
}

impl ManifestSegment {
    pub fn owns(&self, hash: u64) -> Result<bool, ManifestError> {
        Ok(self.prefix()?.contains(hash))
    }

    /// `segment_seq` is the sequence the write lands at. The caller writes both halves
    /// and the new root in one CAS write.
    pub fn split(&self, segment_seq: u64) -> Result<(Self, Self), ManifestError> {
        let (low, high) = self.prefix()?.split()?;
        let AadFields::ManifestSegment {
            ref vault_id,
            vault_key_epoch,
            ..
        } = *self.fields()
        else {
            return Err(ManifestError::NotAManifestSegment);
        };

        let mut low_entries = Vec::new();
        let mut high_entries = Vec::new();
        for entry in self.entries() {
            let hash = hash_item_id(entry.item_id());
            if high.contains(hash) {
                high_entries.push(entry.clone());
            } else {
                low_entries.push(entry.clone());
            }
        }

        let make = |prefix: CanonicalPrefix, entries: Vec<Entry>| {
            Self::new(
                AadFields::ManifestSegment {
                    vault_id: vault_id.clone(),
                    segment_seq,
                    vault_key_epoch,
                    prefix_len: prefix.bit_len(),
                    prefix_bits: prefix.bits(),
                },
                entries,
            )
        };
        Ok((make(low, low_entries)?, make(high, high_entries)?))
    }
}

impl ManifestRoot {
    pub fn with_split(
        &self,
        splitting: CanonicalPrefix,
        low: (&StoredManifest, CanonicalPrefix),
        high: (&StoredManifest, CanonicalPrefix),
        manifest_seq: u64,
    ) -> Result<Self, ManifestError> {
        if !self
            .segments()
            .iter()
            .any(|entry| entry.prefix() == splitting)
        {
            return Err(ManifestError::SegmentNotInRoot {
                prefix_len: splitting.bit_len(),
            });
        }

        let mut entries: Vec<RootEntry> = self
            .segments()
            .iter()
            .filter(|entry| entry.prefix() != splitting)
            .cloned()
            .collect();
        entries.push(RootEntry::new(low.1, low.0.digest()?, manifest_seq));
        entries.push(RootEntry::new(high.1, high.0.digest()?, manifest_seq));

        let count = u32::try_from(entries.len()).map_err(|_| ManifestError::TooManySegments)?;
        let AadFields::ManifestRoot {
            ref vault_id,
            vault_key_epoch,
            ..
        } = *self.fields()
        else {
            return Err(ManifestError::NotAManifestRoot);
        };
        let root = Self::new(
            AadFields::ManifestRoot {
                vault_id: vault_id.clone(),
                manifest_seq,
                vault_key_epoch,
                segment_count: count,
            },
            entries,
        )?;
        root.check_tiles()?;
        Ok(root)
    }
}

const CONFLICT_DOMAIN: &[u8] = b"chiavora-conflict|";

/// Derived rather than random, so two devices resolving the same conflict create one
/// copy, not two.
#[must_use]
pub fn conflict_item_id(losing_item_id: &[u8], losing_digest: &[u8; 32]) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update(CONFLICT_DOMAIN);
    hasher.update(losing_item_id);
    hasher.update(losing_digest);
    let digest: [u8; 32] = hasher.finalize().into();
    // Destructured rather than sliced, so there is no fallible step.
    let [b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15, ..] = digest;
    [
        b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15,
    ]
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConflictingVersion {
    item_id: Vec<u8>,
    version: u64,
    ciphertext_digest: [u8; 32],
}

impl ConflictingVersion {
    #[must_use]
    pub const fn new(item_id: Vec<u8>, version: u64, ciphertext_digest: [u8; 32]) -> Self {
        Self {
            item_id,
            version,
            ciphertext_digest,
        }
    }

    #[must_use]
    pub fn item_id(&self) -> &[u8] {
        &self.item_id
    }

    #[must_use]
    pub const fn version(&self) -> u64 {
        self.version
    }

    #[must_use]
    pub const fn ciphertext_digest(&self) -> &[u8; 32] {
        &self.ciphertext_digest
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution {
    SameEdit,
    Conflict {
        primary: ConflictingVersion,
        copy: ConflictingVersion,
        copy_item_id: [u8; 16],
    },
}

/// The §2.5 tiebreak. Symmetric in its arguments, so every device reaches the same
/// answer without coordination.
#[must_use]
pub fn resolve(a: &ConflictingVersion, b: &ConflictingVersion) -> Resolution {
    if a.ciphertext_digest() == b.ciphertext_digest() {
        return Resolution::SameEdit;
    }
    // `[u8; 32]`'s `Ord` is lexicographic, most-significant byte first.
    let (primary, copy) = if a.ciphertext_digest() < b.ciphertext_digest() {
        (a, b)
    } else {
        (b, a)
    };
    Resolution::Conflict {
        primary: primary.clone(),
        copy: copy.clone(),
        copy_item_id: conflict_item_id(copy.item_id(), copy.ciphertext_digest()),
    }
}
