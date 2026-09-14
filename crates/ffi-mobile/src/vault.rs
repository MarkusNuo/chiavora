//! A uniffi `Object`, so the MUK never becomes a Kotlin value (§3.3 requirement 2).

use std::sync::Arc;

use chiavora_core::derive::{AccountIdentifiers, KdfParams};
use chiavora_core::device::check_enrolment_backing;
use chiavora_core::device::{
    check_i8, DeviceKeyError, EntryProtection, KeystoreBacking, KeystoreEntry,
};
use chiavora_core::entry::{accept, PasswordField, SecretKeyField};
use chiavora_core::unlock::UnlockedVault;
use zeroize::Zeroizing;

#[derive(uniffi::Object)]
pub struct MobileVault {
    inner: UnlockedVault,
}

/// No variant carries key material, and there is no wrong-password variant: a wrong
/// password opens a vault that decrypts nothing, and the store then refuses.
#[derive(Debug, uniffi::Error)]
pub enum UnlockError {
    Store {
        reason: String,
    },

    Rejected {
        entry_point: String,
    },
    /// Including an Argon2id allocation failure; never retried weaker.
    Derivation {
        reason: String,
    },
    Keystore {
        reason: String,
    },
    /// The keystore entries are not protected as §2.4 requires (I8).
    DeviceKeys {
        reason: String,
    },
}

impl core::fmt::Display for UnlockError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Store { reason } => write!(f, "{reason}"),
            Self::Rejected { entry_point } => write!(f, "input refused at {entry_point}"),
            Self::Derivation { reason }
            | Self::Keystore { reason }
            | Self::DeviceKeys { reason } => f.write_str(reason),
        }
    }
}

impl std::error::Error for UnlockError {}

/// What the platform reported, so I8 is checked against what the device did, not only
/// against what Kotlin asked for.
#[derive(Debug, uniffi::Record)]
pub struct KeystoreReport {
    pub muk_backing: String,
    pub muk_invalidated_by_enrollment: bool,
    pub secret_key_backing: String,
    pub secret_key_invalidated_by_enrollment: bool,
}

pub(crate) fn backing_from(name: &str) -> KeystoreBacking {
    match name {
        "SecureElement" => KeystoreBacking::SecureElement,
        "TrustedExecutionEnvironment" => KeystoreBacking::TrustedExecutionEnvironment,
        // R1: an unknown platform string reads as software-only, never as hardware.
        _ => KeystoreBacking::SoftwareOnly,
    }
}

const fn protection_from(invalidated: bool) -> EntryProtection {
    if invalidated {
        EntryProtection::BiometricCurrentSet
    } else {
        EntryProtection::DeviceCredential
    }
}

/// I8 and its partner: the Secret Key's entry must not be biometric-bound, and the MUK's must be.
#[uniffi::export]
pub fn check_keystore_arrangement(report: &KeystoreReport) -> Result<(), UnlockError> {
    check_i8(
        KeystoreEntry::new(
            backing_from(&report.secret_key_backing),
            protection_from(report.secret_key_invalidated_by_enrollment),
        ),
        KeystoreEntry::new(
            backing_from(&report.muk_backing),
            protection_from(report.muk_invalidated_by_enrollment),
        ),
    )
    .map_err(|e: DeviceKeyError| UnlockError::DeviceKeys {
        reason: e.to_string(),
    })
}

#[uniffi::export]
impl MobileVault {
    // uniffi exports take owned values, so the identifiers cannot be slices.
    #[allow(clippy::needless_pass_by_value)]
    #[uniffi::constructor]
    pub fn from_secrets(
        password: Vec<u8>,
        secret_key: Vec<u8>,
        account_id: Vec<u8>,
        account_salt: Vec<u8>,
        memory_kib: u32,
        iterations: u32,
    ) -> Result<Arc<Self>, UnlockError> {
        let password = accept::<PasswordField>(password).map_err(|_| UnlockError::Rejected {
            entry_point: "password field".to_owned(),
        })?;
        let secret_key =
            accept::<SecretKeyField>(secret_key).map_err(|_| UnlockError::Rejected {
                entry_point: "Secret Key field".to_owned(),
            })?;
        let params =
            KdfParams::new(memory_kib, iterations).map_err(|e| UnlockError::Derivation {
                reason: e.to_string(),
            })?;

        let inner = UnlockedVault::from_secrets(
            &password,
            &secret_key,
            AccountIdentifiers {
                account_id: &account_id,
                account_salt: &account_salt,
            },
            params,
        )
        .map_err(|e| UnlockError::Derivation {
            reason: e.to_string(),
        })?;
        Ok(Arc::new(Self { inner }))
    }

    /// The bytes are wrapped in `Zeroizing` at once, and Kotlin overwrites its copy.
    #[uniffi::constructor]
    pub fn from_stored_muk(bytes: Vec<u8>) -> Result<Arc<Self>, UnlockError> {
        let inner = UnlockedVault::from_stored_muk(Zeroizing::new(bytes)).map_err(|e| {
            UnlockError::Keystore {
                reason: e.to_string(),
            }
        })?;
        Ok(Arc::new(Self { inner }))
    }

    #[must_use]
    pub fn muk_len(&self) -> u32 {
        u32::try_from(self.inner.muk_len()).unwrap_or(0)
    }
}

impl MobileVault {
    pub(crate) fn open_store_at(
        &self,
        path: &std::path::Path,
        anchor: Box<dyn chiavora_core::store::RollbackAnchor>,
    ) -> Result<chiavora_core::store::Store, chiavora_core::store::StoreError> {
        self.inner.open_store(path, anchor)
    }

    pub(crate) fn wrapping(inner: UnlockedVault) -> Arc<Self> {
        Arc::new(Self { inner })
    }
}

/// The MUK for the platform to wrap: on Android a Java API, so the plaintext must reach Kotlin.
/// It derives its own MUK, so a [`MobileVault`] is never a handle the key can be read out of.
#[allow(clippy::needless_pass_by_value)]
#[uniffi::export]
pub fn muk_for_device_wrapping(
    password: Vec<u8>,
    secret_key: Vec<u8>,
    account_id: Vec<u8>,
    account_salt: Vec<u8>,
    memory_kib: u32,
    iterations: u32,
    keystore_backing: String,
) -> Result<Vec<u8>, UnlockError> {
    // A software-only Keystore is refused before any MUK exists; password unlock is unaffected.
    check_enrolment_backing(backing_from(&keystore_backing)).map_err(|e| {
        UnlockError::DeviceKeys {
            reason: e.to_string(),
        }
    })?;

    let password = accept::<PasswordField>(password).map_err(|_| UnlockError::Rejected {
        entry_point: "password field".to_owned(),
    })?;
    let secret_key = accept::<SecretKeyField>(secret_key).map_err(|_| UnlockError::Rejected {
        entry_point: "Secret Key field".to_owned(),
    })?;
    let params = KdfParams::new(memory_kib, iterations).map_err(|e| UnlockError::Derivation {
        reason: e.to_string(),
    })?;
    chiavora_core::unlock::muk_for_device_wrapping(
        &password,
        &secret_key,
        AccountIdentifiers {
            account_id: &account_id,
            account_salt: &account_salt,
        },
        params,
    )
    .map(|bytes| bytes.to_vec())
    .map_err(|e| UnlockError::Derivation {
        reason: e.to_string(),
    })
}
