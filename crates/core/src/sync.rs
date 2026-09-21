use crate::manifest::{
    seal_root, seal_segment, CanonicalPrefix, Entry, ManifestError, ManifestRoot, ManifestSegment,
    RootEntry, StoredManifest,
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

fn merge_edit(entries: &mut Vec<Entry>, edit: &StagedEdit) -> Result<(), ManifestError> {
    let existing = entries.iter().position(|e| e.item_id() == edit.item_id());
    match existing {
        None => entries.push(edit.as_entry()),
        Some(at) => {
            let Some(theirs) = entries.get(at) else {
                return Err(ManifestError::ItemDeliveredNotListed);
            };
            if edit.version() > theirs.current_version() {
                let replacement = edit.as_entry();
                if let Some(slot) = entries.get_mut(at) {
                    *slot = replacement;
                }
            } else if edit.version() < theirs.current_version() {
            } else if theirs.ciphertext_digest() != &edit.ciphertext_digest {
                return Err(ManifestError::ConflictNeedsResolution);
            }
        }
    }
    Ok(())
}

/// Uploads staged edits by §2.5. Conflicts are refused; [`upload_resolving`] resolves them.
pub fn upload(
    transport: &mut impl ManifestTransport,
    vault_key: &Secret<VaultKey>,
    store: &mut Store,
    vault_id: &[u8],
    staged: &[StagedEdit],
) -> Result<Uploaded, ManifestError> {
    let whole = CanonicalPrefix::new(0, 0)?;

    let latest_seq;
    let mut entries: Vec<Entry>;
    match transport.fetch_root()? {
        None => {
            latest_seq = 0;
            entries = Vec::new();
        }
        Some(bytes) => {
            let stored_root = StoredManifest::decode(&bytes)?;
            let root = crate::manifest::open_root(vault_key, &stored_root)?;
            root.accept(store.high_water_mark(vault_id))?;
            latest_seq = root.manifest_seq();

            entries = match transport.fetch_segment(whole)? {
                None => Vec::new(),
                Some(segment_bytes) => {
                    let stored_segment = StoredManifest::decode(&segment_bytes)?;
                    root.accept_segment(&stored_segment)?;
                    crate::manifest::open_segment(vault_key, &stored_segment)?
                        .entries()
                        .to_vec()
                }
            };
        }
    }

    for edit in staged {
        merge_edit(&mut entries, edit)?;
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
