//! Sealed under a Keystore key: a plain number beside the database would be replaced with it.

use std::sync::Arc;

use chiavora_core::anchor::{
    restore_from_older_backup as core_restore, AnchorStorage, AnchorStorageError, PlatformAnchor,
    RestoreAcknowledgement, RestoreError,
};
use chiavora_core::derive::{AccountIdentifiers, KdfParams};
use chiavora_core::device::KeystoreBacking;
use chiavora_core::entry::{accept, PasswordField, SecretKeyField};
use chiavora_core::store::{RollbackAnchor, RollbackProtection};

use crate::vault::{backing_from, MobileVault, UnlockError};

#[uniffi::export(with_foreign)]
pub trait DeviceAnchorStorage: Send + Sync {
    /// `None` on first use. An unreadable value keeps the vault shut.
    fn read(&self) -> Result<Option<u64>, AnchorError>;

    /// Records `generation` durably before returning.
    fn write(&self, generation: u64) -> Result<(), AnchorError>;

    fn backing(&self) -> String;
}

/// Carries no platform message, which would name Keystore aliases.
#[derive(Debug, uniffi::Error)]
pub enum AnchorError {
    Unreadable,
    Unwritable,
}

impl core::fmt::Display for AnchorError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Unreadable => "the device's rollback anchor could not be read",
            Self::Unwritable => "the device's rollback anchor could not be written",
        })
    }
}

impl std::error::Error for AnchorError {}

struct Foreign(Arc<dyn DeviceAnchorStorage>);

impl AnchorStorage for Foreign {
    fn read(&self) -> Result<Option<u64>, AnchorStorageError> {
        self.0.read().map_err(|_| AnchorStorageError::Unreadable)
    }
    fn write(&self, generation: u64) -> Result<(), AnchorStorageError> {
        self.0
            .write(generation)
            .map_err(|_| AnchorStorageError::Unwritable)
    }
    fn backing(&self) -> KeystoreBacking {
        backing_from(&self.0.backing())
    }
}

fn load(storage: Arc<dyn DeviceAnchorStorage>) -> Result<Box<dyn RollbackAnchor>, UnlockError> {
    let anchor = PlatformAnchor::load(Foreign(storage)).map_err(|e| UnlockError::Keystore {
        reason: e.to_string(),
    })?;
    Ok(Box::new(anchor))
}

const fn label(protection: RollbackProtection) -> &'static str {
    match protection {
        RollbackProtection::Anchored => "Anchored",
        RollbackProtection::IntegrityOnly => "IntegrityOnly",
    }
}

#[uniffi::export]
impl MobileVault {
    #[allow(clippy::needless_pass_by_value)]
    pub fn rollback_protection(
        &self,
        path: String,
        storage: Arc<dyn DeviceAnchorStorage>,
    ) -> Result<String, UnlockError> {
        let anchor = load(storage)?;
        let store = self
            .open_store_at(std::path::Path::new(&path), anchor)
            .map_err(|e| UnlockError::Store {
                reason: e.to_string(),
            })?;
        Ok(label(store.rollback_protection()).to_owned())
    }
}

/// The one legitimate rewind. It takes the password and Secret Key, not a [`MobileVault`], so a
/// biometric unlock cannot reach it, and is refused unless the device is at `discarding_after`.
// Flat arguments: a `uniffi::Record` would put the password in a Kotlin data class.
#[allow(clippy::needless_pass_by_value, clippy::too_many_arguments)]
#[uniffi::export]
pub fn restore_from_older_backup(
    path: String,
    storage: Arc<dyn DeviceAnchorStorage>,
    password: Vec<u8>,
    secret_key: Vec<u8>,
    account_id: Vec<u8>,
    account_salt: Vec<u8>,
    memory_kib: u32,
    iterations: u32,
    discarding_after: u64,
) -> Result<Arc<MobileVault>, UnlockError> {
    let password = accept::<PasswordField>(password).map_err(|_| UnlockError::Rejected {
        entry_point: "password field".to_owned(),
    })?;
    let secret_key = accept::<SecretKeyField>(secret_key).map_err(|_| UnlockError::Rejected {
        entry_point: "Secret Key field".to_owned(),
    })?;
    let params = KdfParams::new(memory_kib, iterations).map_err(|e| UnlockError::Derivation {
        reason: e.to_string(),
    })?;
    let anchor = load(storage)?;

    let inner = core_restore(
        std::path::Path::new(&path),
        anchor,
        &password,
        &secret_key,
        AccountIdentifiers {
            account_id: &account_id,
            account_salt: &account_salt,
        },
        params,
        RestoreAcknowledgement::confirmed(discarding_after),
    )
    .map_err(|e| match e {
        RestoreError::Derive(inner) => UnlockError::Derivation {
            reason: inner.to_string(),
        },
        other => UnlockError::Store {
            reason: other.to_string(),
        },
    })?;

    Ok(MobileVault::wrapping(inner))
}
