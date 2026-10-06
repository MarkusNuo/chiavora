//! Every member must be able to read the new sealed Vault Key first; this module cannot check that.

use crate::aad::AadFields;
use crate::manifest::{
    open_root, open_segment, seal_root, seal_segment, CanonicalPrefix, Entry, ManifestError,
    ManifestRoot, ManifestSegment, RootEntry, StoredManifest,
};
use crate::nonce::FreshNonce;
use crate::secret::{kind::VaultKey, Secret};
use crate::store::Store;
use crate::sync::{CasRefused, ManifestTransport};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rewrapped {
    AlreadyCurrent,
    Rewrapped,
}

/// An item already at the target epoch must return [`Rewrapped::AlreadyCurrent`], not an
/// error, or an interrupted rotation cannot resume.
pub trait WrapRotator {
    /// Any error aborts the rotation before the manifest write.
    fn rewrap(&mut self, item_id: &[u8]) -> Result<Rewrapped, ManifestError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rotated {
    Complete {
        manifest_seq: u64,
        vault_key_epoch: u32,
        rewrapped: usize,
        already_current: usize,
    },
    /// The re-wraps stand, so a retry is cheap.
    LostRace {
        /// The `manifestSeq` the server reported when it refused (C3).
        observed: u64,
    },
}

struct OpenSegment {
    prefix: CanonicalPrefix,
    entries: Vec<Entry>,
}

fn open_all_segments(
    transport: &mut impl ManifestTransport,
    old_key: &Secret<VaultKey>,
    root: &ManifestRoot,
) -> Result<Vec<OpenSegment>, ManifestError> {
    let mut out = Vec::with_capacity(root.segments().len());
    for entry in root.segments() {
        let prefix = entry.prefix();
        let Some(bytes) = transport.fetch_segment(prefix)? else {
            return Err(ManifestError::SegmentListedNotDelivered {
                prefix_len: prefix.bit_len(),
            });
        };
        let stored = StoredManifest::decode(&bytes)?;
        root.accept_segment(&stored)?;
        let segment = open_segment(old_key, &stored)?;
        out.push(OpenSegment {
            prefix,
            entries: segment.entries().to_vec(),
        });
    }
    Ok(out)
}

/// The server keeps the previous epoch's sealed Vault Key until a client releases it (C7).
pub fn rotate(
    transport: &mut impl ManifestTransport,
    old_key: &Secret<VaultKey>,
    new_key: &Secret<VaultKey>,
    new_epoch: u32,
    store: &mut Store,
    vault_id: &[u8],
    rotator: &mut impl WrapRotator,
) -> Result<Rotated, ManifestError> {
    let Some(bytes) = transport.fetch_root()? else {
        return Err(ManifestError::NoManifestToRotate);
    };
    let stored_root = StoredManifest::decode(&bytes)?;
    let root = open_root(old_key, &stored_root)?;
    root.accept(store.high_water_mark(vault_id))?;

    // Exactly one above: a skipped epoch would be a sealed Vault Key nobody ever releases.
    if new_epoch != root.vault_key_epoch().saturating_add(1) {
        return Err(ManifestError::EpochNotSuccessive {
            current: root.vault_key_epoch(),
            offered: new_epoch,
        });
    }

    let segments = open_all_segments(transport, old_key, &root)?;

    // Re-wrap before anything is written, in a fixed order so a resume covers the same ground.
    let mut rewrapped = 0_usize;
    let mut already_current = 0_usize;
    for segment in &segments {
        for entry in &segment.entries {
            match rotator.rewrap(entry.item_id())? {
                Rewrapped::Rewrapped => rewrapped += 1,
                Rewrapped::AlreadyCurrent => already_current += 1,
            }
        }
    }

    // I6f: `latest + 1`, never reset.
    let next = root.manifest_seq().saturating_add(1);
    let segment_count =
        u32::try_from(segments.len()).map_err(|_| ManifestError::TooManySegments)?;

    let mut sealed_segments = Vec::with_capacity(segments.len());
    let mut root_entries = Vec::with_capacity(segments.len());
    for segment in &segments {
        let rebuilt = ManifestSegment::new(
            AadFields::ManifestSegment {
                vault_id: vault_id.to_vec(),
                segment_seq: next,
                vault_key_epoch: new_epoch,
                prefix_len: segment.prefix.bit_len(),
                prefix_bits: segment.prefix.bits(),
            },
            // Carried across unchanged: rotation bumps no item version.
            segment.entries.clone(),
        )?;
        let sealed = seal_segment(new_key, FreshNonce::generate()?, &rebuilt)?;
        root_entries.push(RootEntry::new(segment.prefix, sealed.digest()?, next));
        sealed_segments.push(sealed);
    }

    let new_root = ManifestRoot::new(
        AadFields::ManifestRoot {
            vault_id: vault_id.to_vec(),
            manifest_seq: next,
            vault_key_epoch: new_epoch,
            segment_count,
        },
        root_entries,
    )?;
    let sealed_root = seal_root(new_key, FreshNonce::generate()?, &new_root)?;

    let encoded_segments = verify_round_trip(
        new_key,
        &sealed_root,
        &sealed_segments,
        &segments,
        next,
        new_epoch,
    )?;

    // One CAS write: root and every segment, together or not at all (C2).
    match transport.compare_and_swap(&sealed_root.encode()?, &encoded_segments) {
        Ok(()) => {
            crate::manifest::advance_high_water_mark(store, vault_id, &new_root)?;
            Ok(Rotated::Complete {
                manifest_seq: next,
                vault_key_epoch: new_epoch,
                rewrapped,
                already_current,
            })
        }
        Err(CasRefused {
            current_manifest_seq,
        }) => Ok(Rotated::LostRace {
            observed: current_manifest_seq,
        }),
    }
}

/// Returns the encoded segments, so the bytes checked are the bytes written.
fn verify_round_trip(
    new_key: &Secret<VaultKey>,
    sealed_root: &StoredManifest,
    sealed_segments: &[StoredManifest],
    original: &[OpenSegment],
    expected_seq: u64,
    expected_epoch: u32,
) -> Result<Vec<Vec<u8>>, ManifestError> {
    let root_bytes = sealed_root.encode()?;
    let reopened_root = open_root(new_key, &StoredManifest::decode(&root_bytes)?)?;
    if reopened_root.manifest_seq() != expected_seq
        || reopened_root.vault_key_epoch() != expected_epoch
    {
        return Err(ManifestError::RotationChangedAnEntry);
    }

    let mut encoded = Vec::with_capacity(sealed_segments.len());
    for (sealed, was) in sealed_segments.iter().zip(original.iter()) {
        let bytes = sealed.encode()?;
        let stored = StoredManifest::decode(&bytes)?;
        reopened_root.accept_segment(&stored)?;
        let reopened = open_segment(new_key, &stored)?;
        if reopened.entries() != was.entries.as_slice() {
            return Err(ManifestError::RotationChangedAnEntry);
        }
        encoded.push(bytes);
    }
    if encoded.len() != original.len() {
        return Err(ManifestError::RotationChangedAnEntry);
    }
    Ok(encoded)
}
