//! Bound to the keypair epoch, so a wrap from before a rotation does not open.

use zeroize::Zeroizing;

use crate::aad::{self, AadFields};
use crate::keywrap::{self, KeyWrapError, WRAPPING_KEY_LEN};
use crate::nonce::NONCE_LEN;
use crate::seal::{AccountKeypair, SealError};
use crate::secret::{kind::Muk, Secret};

#[derive(Debug, Clone, Copy)]
pub struct AccountKeyContext<'a> {
    pub account_id: &'a [u8],
    /// Epoch of the account keypair (§2.2), changed by keypair rotation.
    pub account_key_epoch: u32,
}

impl AccountKeyContext<'_> {
    fn aad(&self) -> Result<Vec<u8>, AccountKeyError> {
        aad::encode(&AadFields::WrappedAccountKey {
            account_id: self.account_id.to_vec(),
            account_key_epoch: self.account_key_epoch,
        })
        .map_err(AccountKeyError::Aad)
    }
}

/// Not secret without the MUK.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrappedAccountKey {
    nonce: [u8; NONCE_LEN],
    ciphertext: Vec<u8>,
}

impl WrappedAccountKey {
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
pub enum AccountKeyError {
    BadMukLength,
    Aead,
    Aad(aad::AadError),
    BadPrivateKey,
}

impl core::fmt::Display for AccountKeyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::BadMukLength => f.write_str("the MUK is not 32 bytes"),
            Self::Aead => f.write_str("the AEAD refused the wrapped account private key"),
            Self::Aad(e) => write!(f, "the account key binding could not be encoded: {e}"),
            Self::BadPrivateKey => {
                f.write_str("the unwrapped account private key is not a valid X25519 key")
            }
        }
    }
}

impl core::error::Error for AccountKeyError {}

impl From<KeyWrapError> for AccountKeyError {
    fn from(e: KeyWrapError) -> Self {
        match e {
            KeyWrapError::BadWrappingKeyLength => Self::BadMukLength,
            KeyWrapError::Aead => Self::Aead,
        }
    }
}

impl From<SealError> for AccountKeyError {
    fn from(_: SealError) -> Self {
        Self::BadPrivateKey
    }
}

pub fn wrap(
    keypair: &AccountKeypair,
    muk: &Secret<Muk>,
    ctx: AccountKeyContext<'_>,
) -> Result<WrappedAccountKey, AccountKeyError> {
    let private: &Zeroizing<[u8; WRAPPING_KEY_LEN]> = keypair.private_for_wrapping();
    let (nonce, ciphertext) = keywrap::seal(private.as_slice(), muk, &ctx.aad()?)?;
    Ok(WrappedAccountKey { nonce, ciphertext })
}

pub fn unwrap(
    wrapped: &WrappedAccountKey,
    muk: &Secret<Muk>,
    ctx: AccountKeyContext<'_>,
) -> Result<AccountKeypair, AccountKeyError> {
    let private = keywrap::open(wrapped.nonce(), wrapped.ciphertext(), muk, &ctx.aad()?)?;
    Ok(AccountKeypair::from_private(&private)?)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn muk(fill: u8) -> Secret<Muk> {
        Secret::from_derived_bytes(vec![fill; 32])
    }

    fn ctx(account: &'static [u8], epoch: u32) -> AccountKeyContext<'static> {
        AccountKeyContext {
            account_id: account,
            account_key_epoch: epoch,
        }
    }

    #[test]
    fn a_wrapped_account_key_round_trips_to_the_same_public_key() {
        let keypair = AccountKeypair::generate().unwrap();
        let public = *keypair.public();

        let wrapped = wrap(&keypair, &muk(0x11), ctx(b"account-1", 1)).unwrap();
        let recovered = unwrap(&wrapped, &muk(0x11), ctx(b"account-1", 1)).unwrap();

        // The public key is derived from the private half, so this compares both.
        assert_eq!(recovered.public(), &public);
    }

    #[test]
    fn a_transplanted_wrap_does_not_open() {
        let keypair = AccountKeypair::generate().unwrap();
        let wrapped = wrap(&keypair, &muk(0x11), ctx(b"account-1", 1)).unwrap();

        assert_eq!(
            unwrap(&wrapped, &muk(0x11), ctx(b"account-2", 1)).err(),
            Some(AccountKeyError::Aead),
            "another account's wrap does not open"
        );
        assert_eq!(
            unwrap(&wrapped, &muk(0x11), ctx(b"account-1", 2)).err(),
            Some(AccountKeyError::Aead),
            "a wrap from before a keypair rotation does not open -- the case \
             the epoch exists for, and the one a MUK change would not catch"
        );
        assert_eq!(
            unwrap(&wrapped, &muk(0x22), ctx(b"account-1", 1)).err(),
            Some(AccountKeyError::Aead),
            "another MUK does not open it"
        );
    }

    #[test]
    fn a_keypair_rotation_under_an_unchanged_muk_is_still_refused() {
        let old = AccountKeypair::generate().unwrap();
        let wrapped_at_epoch_1 = wrap(&old, &muk(0x11), ctx(b"account-1", 1)).unwrap();

        assert_eq!(
            unwrap(&wrapped_at_epoch_1, &muk(0x11), ctx(b"account-1", 2)).err(),
            Some(AccountKeyError::Aead)
        );
    }

    #[test]
    fn a_short_muk_is_refused_rather_than_padded() {
        let keypair = AccountKeypair::generate().unwrap();
        let short: Secret<Muk> = Secret::from_derived_bytes(vec![0x11; 16]);
        assert_eq!(
            wrap(&keypair, &short, ctx(b"account-1", 1)).err(),
            Some(AccountKeyError::BadMukLength)
        );
    }
}
