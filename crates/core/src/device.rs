//! `core` does not talk to a keystore: this is the contract a platform implements.

/// A fallback from `StrongBox` to the TEE is allowed, but is reported, never silent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeystoreBacking {
    SecureElement,
    TrustedExecutionEnvironment,
    SoftwareOnly,
}

impl KeystoreBacking {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::SecureElement => "secure element",
            Self::TrustedExecutionEnvironment => "trusted execution environment",
            Self::SoftwareOnly => "software only",
        }
    }

    #[must_use]
    pub const fn is_hardware_backed(self) -> bool {
        matches!(
            self,
            Self::SecureElement | Self::TrustedExecutionEnvironment
        )
    }
}

/// A type rather than a `bool`, so the two entries cannot be swapped at a call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryProtection {
    /// Biometric, invalidated when the biometric set changes; for the MUK's
    /// wrapping key only. Android: `setInvalidatedByBiometricEnrollment(true)`
    /// through `BiometricPrompt.CryptoObject`; iOS: `.biometryCurrentSet`.
    BiometricCurrentSet,
    /// Not tied to the biometric set; for the Secret Key (I8).
    DeviceCredential,
}

impl EntryProtection {
    #[must_use]
    pub const fn invalidated_by_biometric_enrollment(self) -> bool {
        matches!(self, Self::BiometricCurrentSet)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeystoreEntry {
    backing: KeystoreBacking,
    protection: EntryProtection,
}

impl KeystoreEntry {
    #[must_use]
    pub const fn new(backing: KeystoreBacking, protection: EntryProtection) -> Self {
        Self {
            backing,
            protection,
        }
    }

    #[must_use]
    pub const fn backing(&self) -> KeystoreBacking {
        self.backing
    }

    #[must_use]
    pub const fn protection(&self) -> EntryProtection {
        self.protection
    }
}

/// Length of a MUK, in bytes (§2.1).
const MUK_LEN: usize = 32;

/// Called on the enrolment path, before the MUK is handed out for wrapping.
pub const fn check_enrolment_backing(backing: KeystoreBacking) -> Result<(), DeviceKeyError> {
    if backing.is_hardware_backed() {
        Ok(())
    } else {
        Err(DeviceKeyError::SoftwareOnlyKeystore)
    }
}

/// On Android the bytes pass through a Java `byte[]` (a deviation recorded in
/// `docs/crypto.md`), which the Kotlin side overwrites; this side zeroizes.
pub fn muk_from_keystore(
    mut bytes: zeroize::Zeroizing<Vec<u8>>,
) -> Result<crate::secret::Secret<crate::secret::kind::Muk>, DeviceKeyError> {
    if bytes.len() != MUK_LEN {
        return Err(DeviceKeyError::WrongMukLength {
            expected: MUK_LEN,
            found: bytes.len(),
        });
    }
    // Moved, not copied, so no second MUK sits in memory.
    Ok(crate::secret::Secret::from_derived_bytes(core::mem::take(
        &mut *bytes,
    )))
}

/// I8, checked against what the device reported: the Secret Key's entry must
/// not be biometric-bound and the MUK's must be, so the check cannot pass on a
/// device where neither is configured.
pub const fn check_i8(
    secret_key_entry: KeystoreEntry,
    muk_entry: KeystoreEntry,
) -> Result<(), DeviceKeyError> {
    if secret_key_entry
        .protection()
        .invalidated_by_biometric_enrollment()
    {
        return Err(DeviceKeyError::SecretKeyIsBiometricBound);
    }
    if !muk_entry.protection().invalidated_by_biometric_enrollment() {
        return Err(DeviceKeyError::MukIsNotBiometricBound);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceKeyError {
    SoftwareOnlyKeystore,

    SecretKeyIsBiometricBound,
    MukIsNotBiometricBound,
    /// Carries the lengths, never the buffer.
    WrongMukLength {
        expected: usize,
        found: usize,
    },
}

impl core::fmt::Display for DeviceKeyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::SoftwareOnlyKeystore => f.write_str(
                "this device's keystore is software-only, so the vault key cannot be protected by hardware",
            ),
            Self::SecretKeyIsBiometricBound => f.write_str(
                "the Secret Key's keystore entry is bound to the biometric set (I8): a new \
                 fingerprint would destroy it and require the Emergency Kit",
            ),
            Self::MukIsNotBiometricBound => f.write_str(
                "the MUK's wrapping key is not bound to the biometric set: re-enrolling a \
                 fingerprint would leave it honouring a biometric the user has changed",
            ),
            Self::WrongMukLength { expected, found } => write!(
                f,
                "the keystore returned {found} bytes where a MUK is {expected}"
            ),
        }
    }
}

impl std::error::Error for DeviceKeyError {}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{check_i8, DeviceKeyError, EntryProtection, KeystoreBacking, KeystoreEntry};

    fn entry(protection: EntryProtection) -> KeystoreEntry {
        KeystoreEntry::new(KeystoreBacking::SecureElement, protection)
    }

    #[test]
    fn i8_holds_when_the_two_entries_are_protected_differently() {
        assert_eq!(
            check_i8(
                entry(EntryProtection::DeviceCredential),
                entry(EntryProtection::BiometricCurrentSet),
            ),
            Ok(())
        );
    }

    #[test]
    fn binding_the_secret_key_to_the_biometric_is_refused_by_name() {
        assert_eq!(
            check_i8(
                entry(EntryProtection::BiometricCurrentSet),
                entry(EntryProtection::BiometricCurrentSet),
            ),
            Err(DeviceKeyError::SecretKeyIsBiometricBound)
        );
    }

    #[test]
    fn the_muk_half_is_asserted_too_so_i8_cannot_pass_on_an_empty_device() {
        assert_eq!(
            check_i8(
                entry(EntryProtection::DeviceCredential),
                entry(EntryProtection::DeviceCredential),
            ),
            Err(DeviceKeyError::MukIsNotBiometricBound)
        );
    }

    #[test]
    fn a_keystore_buffer_of_the_wrong_length_is_refused_by_name() {
        let short = zeroize::Zeroizing::new(vec![0x11; 31]);
        assert_eq!(
            super::muk_from_keystore(short).unwrap_err(),
            DeviceKeyError::WrongMukLength {
                expected: 32,
                found: 31
            }
        );
        let long = zeroize::Zeroizing::new(vec![0x11; 33]);
        assert!(super::muk_from_keystore(long).is_err());
    }

    #[test]
    fn a_muk_sized_buffer_comes_back_branded() {
        let bytes = zeroize::Zeroizing::new(vec![0x4D; 32]);
        let muk = super::muk_from_keystore(bytes).expect("32 bytes is a MUK");
        assert_eq!(muk.expose().len(), 32);
    }

    #[test]
    fn no_device_key_error_carries_the_buffer() {
        let err = DeviceKeyError::WrongMukLength {
            expected: 32,
            found: 31,
        };
        let rendered = format!("{err}");
        assert!(rendered.contains("31") && rendered.contains("32"));
        assert!(!rendered.contains("0x11"));
    }

    #[test]
    fn software_only_is_a_named_variant_rather_than_an_absence() {
        assert!(!KeystoreBacking::SoftwareOnly.is_hardware_backed());
        assert!(KeystoreBacking::SecureElement.is_hardware_backed());
        assert!(KeystoreBacking::TrustedExecutionEnvironment.is_hardware_backed());
    }

    #[test]
    fn every_backing_has_a_label_that_does_not_editorialise() {
        for backing in [
            KeystoreBacking::SecureElement,
            KeystoreBacking::TrustedExecutionEnvironment,
            KeystoreBacking::SoftwareOnly,
        ] {
            let label = backing.label();
            assert!(!label.is_empty());
            for judgement in ["secure enough", "weak", "less secure", "insecure"] {
                assert!(
                    !label.contains(judgement),
                    "{label:?} editorialises: the screen states what the device has"
                );
            }
        }
    }
}
