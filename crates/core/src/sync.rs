use crate::manifest::{
    seal_root, seal_segment, CanonicalPrefix, ConflictingVersion, Entry, ManifestError,
    ManifestRoot, ManifestSegment, Resolution, RootEntry, StoredManifest,
};
use crate::nonce::FreshNonce;
use crate::secret::{kind::VaultKey, Secret};
use crate::store::Store;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CasRefused {
    pub current_manifest_seq: u64,
}

/// What the server must provide for §2.5 (clauses C1–C8 in `docs/crypto.md`).
/// Everything crossing it is bytes, so a server cannot re-encode a record
/// without breaking its digest (C4).
pub trait ManifestTransport {
    fn fetch_root(&mut self) -> Result<Option<Vec<u8>>, ManifestError>;

    fn fetch_segment(&mut self, prefix: CanonicalPrefix) -> Result<Option<Vec<u8>>, ManifestError>;

    /// C1: writes the root and its segments iff the root's `manifestSeq` is
    /// exactly `current + 1`. C2: they land together or not at all.
    fn compare_and_swap(&mut self, root: &[u8], segments: &[Vec<u8>]) -> Result<(), CasRefused>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagedEdit {
    item_id: Vec<u8>,
    version: u64,
    ciphertext_digest: [u8; 32],
    tombstone: bool,
}

impl StagedEdit {
    #[must_use]
    pub const fn new(
        item_id: Vec<u8>,
        version: u64,
        ciphertext_digest: [u8; 32],
        tombstone: bool,
    ) -> Self {
        Self {
            item_id,
            version,
            ciphertext_digest,
            tombstone,
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

    fn as_entry(&self) -> Entry {
        Entry::new(
            self.item_id.clone(),
            self.version,
            self.ciphertext_digest,
            self.tombstone,
            Vec::new(),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Uploaded {
    Written {
        manifest_seq: u64,
    },
    /// Someone else wrote first; the caller refetches, rebases and retries.
    LostRace {
        observed: u64,
    },
}

/// Re-seals the losing side of a conflict under the copy's own `itemId`. The
/// item identity is in the payload's AAD, so the old record will not open under
/// the new id, and the sync engine holds no Item Key to seal a new one.
pub trait ConflictCopySealer {
    /// Seals and stores the losing version's plaintext under `copy_item_id`, and
    /// returns the new record's `ciphertextDigest`, not `losing`'s.
    fn seal_conflict_copy(
        &mut self,
        losing: &ConflictingVersion,
        copy_item_id: &[u8; 16],
    ) -> Result<[u8; 32], ManifestError>;
}

struct PendingCopy {
    losing: ConflictingVersion,
    copy_item_id: [u8; 16],
    /// The losing side's flag, so a losing deletion becomes a deleted copy.
    tombstone: bool,
}

fn merge_edit(
    entries: &mut Vec<Entry>,
    edit: &StagedEdit,
) -> Result<Option<PendingCopy>, ManifestError> {
    let Some(at) = entries.iter().position(|e| e.item_id() == edit.item_id()) else {
        entries.push(edit.as_entry());
        return Ok(None);
    };
    let Some(theirs) = entries.get(at) else {
        return Err(ManifestError::ItemDeliveredNotListed);
    };
    let their_version = theirs.current_version();
    let their_tombstone = theirs.tombstone();
    let theirs = ConflictingVersion::new(
        theirs.item_id().to_vec(),
        their_version,
        *theirs.ciphertext_digest(),
    );

    if edit.version() > their_version {
        let replacement = edit.as_entry();
        if let Some(slot) = entries.get_mut(at) {
            *slot = replacement;
        }
        return Ok(None);
    }
    if edit.version() < their_version {
        return Ok(None);
    }

    let mine = ConflictingVersion::new(
        edit.item_id().to_vec(),
        edit.version(),
        edit.ciphertext_digest,
    );
    match crate::manifest::resolve(&mine, &theirs) {
        Resolution::SameEdit => Ok(None),
        Resolution::Conflict {
            primary,
            copy,
            copy_item_id,
        } => {
            // The digests differ in a conflict, so this names one side.
            let mine_won = primary.ciphertext_digest() == &edit.ciphertext_digest;
            if mine_won {
                let replacement = edit.as_entry();
                if let Some(slot) = entries.get_mut(at) {
                    *slot = replacement;
                }
            }
            let tombstone = if mine_won {
                their_tombstone
            } else {
                edit.tombstone
            };
            Ok(Some(PendingCopy {
                losing: copy,
                copy_item_id,
                tombstone,
            }))
        }
    }
}

fn fetch_and_verify(
    transport: &mut impl ManifestTransport,
    vault_key: &Secret<VaultKey>,
    store: &Store,
    vault_id: &[u8],
    whole: CanonicalPrefix,
) -> Result<(u64, Vec<Entry>), ManifestError> {
    let Some(bytes) = transport.fetch_root()? else {
        return Ok((0, Vec::new()));
    };
    let stored_root = StoredManifest::decode(&bytes)?;
    let root = crate::manifest::open_root(vault_key, &stored_root)?;
    root.accept(store.high_water_mark(vault_id))?;

    let entries = match transport.fetch_segment(whole)? {
        None => Vec::new(),
        Some(segment_bytes) => {
            let stored_segment = StoredManifest::decode(&segment_bytes)?;
            root.accept_segment(&stored_segment)?;
            crate::manifest::open_segment(vault_key, &stored_segment)?
                .entries()
                .to_vec()
        }
    };
    Ok((root.manifest_seq(), entries))
}

/// Uploads staged edits by §2.5. Conflicts are refused; [`upload_resolving`] resolves them.
pub fn upload(
    transport: &mut impl ManifestTransport,
    vault_key: &Secret<VaultKey>,
    store: &mut Store,
    vault_id: &[u8],
    staged: &[StagedEdit],
) -> Result<Uploaded, ManifestError> {
    upload_inner(transport, vault_key, store, vault_id, staged, None)
}

/// As [`upload`], but a conflict's loser becomes a copy that lands in the same CAS write,
/// so the losing edit is never absent from the manifest.
pub fn upload_resolving(
    transport: &mut impl ManifestTransport,
    vault_key: &Secret<VaultKey>,
    store: &mut Store,
    vault_id: &[u8],
    staged: &[StagedEdit],
    sealer: &mut impl ConflictCopySealer,
) -> Result<Uploaded, ManifestError> {
    upload_inner(transport, vault_key, store, vault_id, staged, Some(sealer))
}

fn upload_inner(
    transport: &mut impl ManifestTransport,
    vault_key: &Secret<VaultKey>,
    store: &mut Store,
    vault_id: &[u8],
    staged: &[StagedEdit],
    mut sealer: Option<&mut dyn ConflictCopySealer>,
) -> Result<Uploaded, ManifestError> {
    let whole = CanonicalPrefix::new(0, 0)?;

    let (latest_seq, mut entries) = fetch_and_verify(transport, vault_key, store, vault_id, whole)?;

    let mut pending: Vec<PendingCopy> = Vec::new();
    for edit in staged {
        if let Some(copy) = merge_edit(&mut entries, edit)? {
            pending.push(copy);
        }
    }

    for copy in pending {
        let Some(sealer) = sealer.as_deref_mut() else {
            return Err(ManifestError::ConflictNeedsResolution);
        };
        if entries.iter().any(|e| e.item_id() == copy.copy_item_id) {
            continue;
        }
        let digest = sealer.seal_conflict_copy(&copy.losing, &copy.copy_item_id)?;
        entries.push(Entry::new(
            copy.copy_item_id.to_vec(),
            1,
            digest,
            copy.tombstone,
            Vec::new(),
        ));
    }
    let next = latest_seq.saturating_add(1);
    let segment = ManifestSegment::new(
        crate::aad::AadFields::ManifestSegment {
            vault_id: vault_id.to_vec(),
            segment_seq: next,
            vault_key_epoch: 1,
            prefix_len: 0,
            prefix_bits: 0,
        },
        entries,
    )?;
    let sealed_segment = seal_segment(vault_key, FreshNonce::generate()?, &segment)?;
    let root = ManifestRoot::new(
        crate::aad::AadFields::ManifestRoot {
            vault_id: vault_id.to_vec(),
            manifest_seq: next,
            vault_key_epoch: 1,
            segment_count: 1,
        },
        vec![RootEntry::new(whole, sealed_segment.digest()?, next)],
    )?;
    let sealed_root = seal_root(vault_key, FreshNonce::generate()?, &root)?;

    match transport.compare_and_swap(&sealed_root.encode()?, &[sealed_segment.encode()?]) {
        Ok(()) => {
            crate::manifest::advance_high_water_mark(store, vault_id, &root)?;
            Ok(Uploaded::Written { manifest_seq: next })
        }
        Err(CasRefused {
            current_manifest_seq,
        }) => Ok(Uploaded::LostRace {
            observed: current_manifest_seq,
        }),
    }
}
