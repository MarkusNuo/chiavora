use crate::derive::{AccountIdentifiers, DeriveError, KdfParams};
use crate::device::KeystoreBacking;
use crate::secret::{
    kind::{AccountPassword, SecretKeyMaterial},
    Secret,
};
use crate::store::{RollbackAnchor, RollbackProtection, StoreError};
use crate::unlock::UnlockedVault;

/// Must live outside the app's data directory, or restoring an old database restores the
/// anchor with it.
pub trait AnchorStorage {
    fn read(&self) -> Result<Option<u64>, AnchorStorageError>;

    /// Records `generation` durably before returning.
    fn write(&self, generation: u64) -> Result<(), AnchorStorageError>;

    fn backing(&self) -> KeystoreBacking;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnchorStorageError {
    Unreadable,
    Unwritable,
}

impl core::fmt::Display for AnchorStorageError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Unreadable => "the device's rollback anchor could not be read",
            Self::Unwritable => "the device's rollback anchor could not be written",
        })
    }
}

impl std::error::Error for AnchorStorageError {}

/// Read once, in [`Self::load`], so an unreadable anchor refuses the open instead of
/// degrading to no anchor.
pub struct PlatformAnchor<S: AnchorStorage> {
    storage: S,
    latest: Option<u64>,
}

impl<S: AnchorStorage> core::fmt::Debug for PlatformAnchor<S> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PlatformAnchor")
            .field("latest", &self.latest)
            .field("backing", &self.storage.backing())
            .finish()
    }
}

impl<S: AnchorStorage> PlatformAnchor<S> {
    pub fn load(storage: S) -> Result<Self, AnchorStorageError> {
        let latest = storage.read()?;
        Ok(Self { storage, latest })
    }

    pub fn backing(&self) -> KeystoreBacking {
        self.storage.backing()
    }
}

impl<S: AnchorStorage> RollbackAnchor for PlatformAnchor<S> {
    fn latest(&self) -> Option<u64> {
        self.latest
    }

    fn advance(&mut self, generation: u64) -> Result<(), StoreError> {
        self.storage
            .write(generation)
            .map_err(|_| StoreError::AnchorFailed)?;
        self.latest = Some(generation);
        Ok(())
    }

    fn protection(&self) -> RollbackProtection {
        RollbackProtection::Anchored
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RestoreAcknowledgement {
    discarding_after: u64,
}

impl RestoreAcknowledgement {
    /// The user was shown `discarding_after` and agreed.
    #[must_use]
    pub const fn confirmed(discarding_after: u64) -> Self {
        Self { discarding_after }
    }

    #[must_use]
    pub const fn discarding_after(self) -> u64 {
        self.discarding_after
    }
}

#[derive(Debug)]
pub enum RestoreError {
    AcknowledgementStale {
        shown: u64,
        actual: u64,
    },
    NothingAnchored,
    NotARewind {
        stored: u64,
        anchor: u64,
    },
    Derive(DeriveError),
    /// A wrong password arrives here as [`StoreError::MetadataTampered`].
    Store(StoreError),
}

impl core::fmt::Display for RestoreError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::AcknowledgementStale { shown, actual } => write!(
                f,
                "the confirmation named generation {shown} but the device is at {actual}"
            ),
            Self::NothingAnchored => f.write_str("this device has no anchor for this store"),
            Self::NotARewind { stored, anchor } => write!(
                f,
                "the file is at generation {stored} and the device at {anchor}: not a rewind"
            ),
            Self::Derive(e) => write!(f, "{e}"),
            Self::Store(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for RestoreError {}

impl From<DeriveError> for RestoreError {
    fn from(e: DeriveError) -> Self {
        Self::Derive(e)
    }
}

impl From<StoreError> for RestoreError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}

/// Takes the password and Secret Key rather than a MUK or an [`UnlockedVault`], so a
/// biometric unlock cannot reach it.
pub fn restore_from_older_backup(
    path: &std::path::Path,
    mut anchor: Box<dyn RollbackAnchor>,
    password: &Secret<AccountPassword>,
    secret_key: &Secret<SecretKeyMaterial>,
    ids: AccountIdentifiers<'_>,
    params: KdfParams,
    acknowledgement: RestoreAcknowledgement,
) -> Result<UnlockedVault, RestoreError> {
    // Checked before the derivation, so a stale acknowledgement costs no Argon2id.
    let Some(latest) = anchor.latest() else {
        return Err(RestoreError::NothingAnchored);
    };
    if latest != acknowledgement.discarding_after() {
        return Err(RestoreError::AcknowledgementStale {
            shown: acknowledgement.discarding_after(),
            actual: latest,
        });
    }

    // A wrong password is not detected here; it yields a MUK that opens nothing.
    let vault = UnlockedVault::from_secrets(password, secret_key, ids, params)?;

    // The MAC is checked before the generation, so a wrong password cannot move the anchor.
    let store = vault.open_store_reanchoring(path, anchor_taken(&mut anchor))?;

    let stored = store.generation();
    if stored > latest {
        return Err(RestoreError::NotARewind {
            stored,
            anchor: latest,
        });
    }

    Ok(vault)
}

fn anchor_taken(anchor: &mut Box<dyn RollbackAnchor>) -> Box<dyn RollbackAnchor> {
    core::mem::replace(anchor, Box::new(Spent))
}

#[derive(Debug)]
struct Spent;

impl RollbackAnchor for Spent {
    fn latest(&self) -> Option<u64> {
        None
    }
    fn advance(&mut self, _generation: u64) -> Result<(), StoreError> {
        Err(StoreError::AnchorFailed)
    }
    fn protection(&self) -> RollbackProtection {
        RollbackProtection::IntegrityOnly
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    #[derive(Clone, Default)]
    struct Remembering {
        value: Rc<RefCell<Option<u64>>>,
        refuse_writes: bool,
    }

    impl AnchorStorage for Remembering {
        fn read(&self) -> Result<Option<u64>, AnchorStorageError> {
            Ok(*self.value.borrow())
        }
        fn write(&self, generation: u64) -> Result<(), AnchorStorageError> {
            if self.refuse_writes {
                return Err(AnchorStorageError::Unwritable);
            }
            *self.value.borrow_mut() = Some(generation);
            Ok(())
        }
        fn backing(&self) -> KeystoreBacking {
            KeystoreBacking::SecureElement
        }
    }

    #[test]
    fn a_platform_anchor_reports_anchored_where_the_stand_in_did_not() {
        let anchor = PlatformAnchor::load(Remembering::default()).expect("reads");
        assert_eq!(anchor.protection(), RollbackProtection::Anchored);
        assert_eq!(anchor.backing(), KeystoreBacking::SecureElement);
    }

    #[test]
    fn advancing_writes_through_before_the_cache_moves() {
        let storage = Remembering::default();
        let mut anchor = PlatformAnchor::load(storage.clone()).expect("reads");
        anchor.advance(7).expect("writes");
        assert_eq!(*storage.value.borrow(), Some(7), "durable first");
        assert_eq!(anchor.latest(), Some(7));
    }

    #[test]
    fn a_refused_write_leaves_the_cache_where_it_was() {
        let storage = Remembering {
            refuse_writes: true,
            ..Remembering::default()
        };
        let mut anchor = PlatformAnchor::load(storage).expect("reads");
        assert!(matches!(anchor.advance(7), Err(StoreError::AnchorFailed)));
        assert_eq!(anchor.latest(), None, "the cache did not move");
    }

    #[test]
    fn an_acknowledgement_carries_the_number_it_was_shown() {
        let ack = RestoreAcknowledgement::confirmed(41);
        assert_eq!(ack.discarding_after(), 41);
    }
}
