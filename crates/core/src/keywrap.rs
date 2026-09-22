//! The caller passes the AAD; this module never decides what is bound (§2.2).

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use crate::nonce::{FreshNonce, StoredNonce, NONCE_LEN};
use crate::secret::{Secret, SecretKind};

/// Length of a wrapping key, in bytes (§2.1).
pub(crate) const WRAPPING_KEY_LEN: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyWrapError {
    BadWrappingKeyLength,
    Aead,
}

fn cipher<K: SecretKind>(key: &Secret<K>) -> Result<XChaCha20Poly1305, KeyWrapError> {
    let bytes = key.expose();
    if bytes.len() != WRAPPING_KEY_LEN {
        return Err(KeyWrapError::BadWrappingKeyLength);
    }
    Ok(XChaCha20Poly1305::new(Key::from_slice(bytes)))
}

pub(crate) fn seal<K: SecretKind>(
    plaintext: &[u8],
    key: &Secret<K>,
    aad: &[u8],
) -> Result<([u8; NONCE_LEN], Vec<u8>), KeyWrapError> {
    let chacha = cipher(key)?;
    let nonce = FreshNonce::generate().map_err(|_| KeyWrapError::Aead)?;
    let ciphertext = chacha
        .encrypt(
            XNonce::from_slice(nonce.as_nonce().as_bytes()),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| KeyWrapError::Aead)?;
    Ok((*nonce.as_nonce().as_bytes(), ciphertext))
}

pub(crate) fn open<K: SecretKind>(
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
    key: &Secret<K>,
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, KeyWrapError> {
    let chacha = cipher(key)?;
    let stored = StoredNonce::from_stored_bytes(*nonce);
    let plaintext = chacha
        .decrypt(
            XNonce::from_slice(stored.as_nonce().as_bytes()),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| KeyWrapError::Aead)?;
    Ok(Zeroizing::new(plaintext))
}
