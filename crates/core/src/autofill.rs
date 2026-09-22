//! Random per vault, so a password change does not force a re-wrap of every fillable item.

use crate::aad::{self, AadFields};
use crate::csprng;
use crate::keywrap::{self, KeyWrapError, WRAPPING_KEY_LEN};
use crate::nonce::NONCE_LEN;
use crate::secret::{
    kind::{AutofillKey, VaultKey},
    Secret,
};

/// Length of the Autofill Key, in bytes (§2.1: every key is 32 bytes).
const AUTOFILL_KEY_LEN: usize = WRAPPING_KEY_LEN;

#[derive(Debug, Clone, Copy)]
pub struct AutofillContext<'a> {
    pub vault_id: &'a [u8],
    /// Epoch of the Vault Key it is wrapped under (§2.5).
    pub vault_key_epoch: u32,
}

impl AutofillContext<'_> {
    fn aad(&self) -> Result<Vec<u8>, AutofillError> {
        aad::encode(&AadFields::WrappedAutofillKey {
            vault_id: self.vault_id.to_vec(),
            vault_key_epoch: self.vault_key_epoch,
        })
        .map_err(AutofillError::Aad)
    }
}

/// Not secret without the Vault Key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrappedAutofillKey {
    nonce: [u8; NONCE_LEN],
    ciphertext: Vec<u8>,
}

impl WrappedAutofillKey {
    #[must_use]
    pub const fn from_stored_parts(nonce: [u8; NONCE_LEN], ciphertext: Vec<u8>) -> Self {
        Self { nonce, ciphertext }
    }

    #[must_use]
    pub const fn nonce(&self) -> &[u8; NONCE_LEN] {
        &self.nonce
    }

    #[must_use]
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
}

/// No variant carries key material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutofillError {
    Csprng,
    BadVaultKeyLength,
    Aead,
    Aad(aad::AadError),
    BadAutofillKeyLength,
}

impl core::fmt::Display for AutofillError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::Csprng => f.write_str("the platform CSPRNG refused"),
            Self::BadVaultKeyLength => f.write_str("the Vault Key is not 32 bytes"),
            Self::Aead => f.write_str("the AEAD refused the wrapped Autofill Key"),
            Self::Aad(e) => write!(f, "the Autofill Key binding could not be encoded: {e}"),
            Self::BadAutofillKeyLength => {
                f.write_str("the unwrapped Autofill Key has an invalid length")
            }
        }
    }
}

impl core::error::Error for AutofillError {}

impl From<csprng::CsprngError> for AutofillError {
    fn from(_: csprng::CsprngError) -> Self {
        Self::Csprng
    }
}

impl From<KeyWrapError> for AutofillError {
    fn from(e: KeyWrapError) -> Self {
        match e {
            KeyWrapError::BadWrappingKeyLength => Self::BadVaultKeyLength,
            KeyWrapError::Aead => Self::Aead,
        }
    }
}

pub fn generate() -> Result<Secret<AutofillKey>, AutofillError> {
    let mut bytes = vec![0_u8; AUTOFILL_KEY_LEN];
    csprng::fill_bytes(&mut bytes)?;
    Ok(Secret::from_derived_bytes(bytes))
}

pub fn wrap(
    autofill_key: &Secret<AutofillKey>,
    vault_key: &Secret<VaultKey>,
    ctx: AutofillContext<'_>,
) -> Result<WrappedAutofillKey, AutofillError> {
    let (nonce, ciphertext) = keywrap::seal(autofill_key.expose(), vault_key, &ctx.aad()?)?;
    Ok(WrappedAutofillKey { nonce, ciphertext })
}

pub fn unwrap(
    wrapped: &WrappedAutofillKey,
    vault_key: &Secret<VaultKey>,
    ctx: AutofillContext<'_>,
) -> Result<Secret<AutofillKey>, AutofillError> {
    let plaintext = keywrap::open(
        wrapped.nonce(),
        wrapped.ciphertext(),
        vault_key,
        &ctx.aad()?,
    )?;
    if plaintext.len() != AUTOFILL_KEY_LEN {
        return Err(AutofillError::BadAutofillKeyLength);
    }
    Ok(Secret::from_derived_bytes(plaintext.to_vec()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn vault_key(fill: u8) -> Secret<VaultKey> {
        Secret::from_derived_bytes(vec![fill; 32])
    }

    fn ctx(vault: &'static [u8], epoch: u32) -> AutofillContext<'static> {
        AutofillContext {
            vault_id: vault,
            vault_key_epoch: epoch,
        }
    }

    #[test]
    fn a_wrapped_autofill_key_round_trips() {
        let key = generate().unwrap();
        let wrapped = wrap(&key, &vault_key(0x11), ctx(b"vault-1", 1)).unwrap();
        let recovered = unwrap(&wrapped, &vault_key(0x11), ctx(b"vault-1", 1)).unwrap();
        assert_eq!(recovered.expose(), key.expose());
    }

    #[test]
    fn two_draws_differ() {
        assert_ne!(
            generate().unwrap().expose(),
            generate().unwrap().expose(),
            "a fresh Autofill Key is drawn, not a constant"
        );
    }

    #[test]
    fn a_transplanted_wrap_does_not_open() {
        let key = generate().unwrap();
        let wrapped = wrap(&key, &vault_key(0x11), ctx(b"vault-1", 1)).unwrap();

        assert_eq!(
            unwrap(&wrapped, &vault_key(0x11), ctx(b"vault-2", 1)).err(),
            Some(AutofillError::Aead),
            "a wrap moved to another vault does not open"
        );
        assert_eq!(
            unwrap(&wrapped, &vault_key(0x11), ctx(b"vault-1", 2)).err(),
            Some(AutofillError::Aead),
            "a wrap moved across a rotation does not open"
        );
        assert_eq!(
            unwrap(&wrapped, &vault_key(0x22), ctx(b"vault-1", 1)).err(),
            Some(AutofillError::Aead),
            "another vault's Vault Key does not open it"
        );
    }

    #[test]
    fn the_autofill_binding_is_not_an_item_key_binding() {
        let autofill = aad::encode(&AadFields::WrappedAutofillKey {
            vault_id: b"vault-1".to_vec(),
            vault_key_epoch: 1,
        })
        .unwrap();
        let item = aad::encode(&AadFields::WrappedItemKey {
            vault_id: b"vault-1".to_vec(),
            item_id: Vec::new(),
            wrap_purpose: aad::WRAP_PURPOSE_AUTOFILL,
        })
        .unwrap();
        assert_ne!(
            autofill, item,
            "the empty-itemId wrapped Item Key is the exact shape 0x07 exists \
             to keep distinct"
        );
    }

    #[test]
    fn a_short_vault_key_is_refused_rather_than_padded() {
        let key = generate().unwrap();
        let short: Secret<VaultKey> = Secret::from_derived_bytes(vec![0x11; 16]);
        assert_eq!(
            wrap(&key, &short, ctx(b"vault-1", 1)).err(),
            Some(AutofillError::BadVaultKeyLength)
        );
    }
}
