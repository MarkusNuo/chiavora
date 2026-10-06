//! The write path (§2.5): a client never writes from a stale base. Ordering comes from
//! `manifestSeq`, not the wall clock: `SystemTime` is not used here.

use std::time::Duration;

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
        served: u64,
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
        }) => {
            // The server cannot be below the root it just served.
            if current_manifest_seq < latest_seq {
                return Err(ManifestError::ServerReportedImpossibleSequence {
                    served: latest_seq,
                    reported: current_manifest_seq,
                });
            }
            Ok(Uploaded::LostRace {
                observed: current_manifest_seq,
                served: latest_seq,
            })
        }
    }
}

/// Equal jitter (half the backoff fixed, half drawn) keeps a floor under every wait,
/// so a refusing server is not hammered (§2.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    attempts: u32,
    // Milliseconds as `u32`, so the arithmetic in `wait_before` is total.
    base_millis: u32,
    cap_millis: u32,
}

impl RetryPolicy {
    const MAX_CAP_MILLIS: u32 = 60 * 60 * 1000;

    #[must_use]
    pub const fn standard() -> Self {
        Self {
            attempts: 5,
            base_millis: 200,
            cap_millis: 5_000,
        }
    }

    pub fn new(attempts: u32, base: Duration, cap: Duration) -> Result<Self, ManifestError> {
        let base_millis =
            u32::try_from(base.as_millis()).map_err(|_| ManifestError::UnusableRetryPolicy)?;
        let cap_millis =
            u32::try_from(cap.as_millis()).map_err(|_| ManifestError::UnusableRetryPolicy)?;
        if attempts == 0
            || base_millis == 0
            || cap_millis < base_millis
            || cap_millis > Self::MAX_CAP_MILLIS
        {
            return Err(ManifestError::UnusableRetryPolicy);
        }
        Ok(Self {
            attempts,
            base_millis,
            cap_millis,
        })
    }

    #[must_use]
    pub const fn attempts(&self) -> u32 {
        self.attempts
    }

    fn wait_before(&self, retry: u32) -> Result<Duration, ManifestError> {
        // Capped at 31 so the shift is defined.
        let shift = retry.saturating_sub(1).min(31);
        let factor = 1_u32 << shift;
        let backoff = self.base_millis.saturating_mul(factor).min(self.cap_millis);
        let half = backoff / 2;
        if half == 0 {
            return Ok(Duration::from_millis(u64::from(backoff)));
        }
        let drawn =
            crate::csprng::uniform_below(half).map_err(|_| ManifestError::NonceUnavailable)?;
        Ok(Duration::from_millis(u64::from(half) + u64::from(drawn)))
    }
}

pub trait Backoff {
    fn wait(&mut self, d: Duration);
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SleepingBackoff;

impl Backoff for SleepingBackoff {
    fn wait(&mut self, d: Duration) {
        std::thread::sleep(d);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncOutcome {
    Written {
        manifest_seq: u64,
        attempts: u32,
    },
    /// Someone else is winning: the reported sequence advanced at least once.
    Contended {
        attempts: u32,
        observed: u64,
    },
    /// Nobody is winning: the reported sequence never moved, so the writes are
    /// refused rather than beaten.
    ServerRefusing {
        attempts: u32,
        observed: u64,
    },
}

/// [`upload`] with §2.5's bounded retry. Tells contention from a refusing
/// server by whether the reported sequence advances, and refuses a server that
/// reports a sequence higher than the root it serves next.
pub fn upload_with_retry(
    transport: &mut impl ManifestTransport,
    vault_key: &Secret<VaultKey>,
    store: &mut Store,
    vault_id: &[u8],
    staged: &[StagedEdit],
    policy: RetryPolicy,
    backoff: &mut impl Backoff,
) -> Result<SyncOutcome, ManifestError> {
    let mut last_observed = 0_u64;
    let mut advanced = false;
    let mut previous: Option<u64> = None;

    for attempt in 1..=policy.attempts() {
        match upload(transport, vault_key, store, vault_id, staged)? {
            Uploaded::Written { manifest_seq } => {
                return Ok(SyncOutcome::Written {
                    manifest_seq,
                    attempts: attempt,
                })
            }
            Uploaded::LostRace { observed, served } => {
                // The server cannot serve a root below a sequence it already reported.
                if let Some(before) = previous {
                    if served < before {
                        return Err(ManifestError::ServerReportedImpossibleSequence {
                            served,
                            reported: before,
                        });
                    }
                    if observed > before {
                        advanced = true;
                    }
                }
                previous = Some(observed);
                last_observed = observed;
            }
        }

        if attempt < policy.attempts() {
            backoff.wait(policy.wait_before(attempt)?);
        }
    }

    if advanced {
        Ok(SyncOutcome::Contended {
            attempts: policy.attempts(),
            observed: last_observed,
        })
    } else {
        Ok(SyncOutcome::ServerRefusing {
            attempts: policy.attempts(),
            observed: last_observed,
        })
    }
}
