//! The AAD is always built by [`crate::aad::encode`]; no function here accepts AAD bytes.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};

use crate::aad::{self, AadError, AadFields};
use crate::nonce::{FreshNonce, StoredNonce, NONCE_LEN};
use crate::secret::{kind::ItemKey, Secret};

/// Length of an Item Key, in bytes (§2.1: every derived key is 32 bytes).
const ITEM_KEY_LEN: usize = 32;

/// The nonce is raw bytes, so a record read back cannot feed an encrypt path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedPayload {
    nonce: [u8; NONCE_LEN],
    ciphertext: Vec<u8>,
}

impl SealedPayload {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ItemError {
    BadItemKeyLength,
    Aead,
    Aad(AadError),
    WrongRecordType(u8),
}

impl core::fmt::Display for ItemError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::BadItemKeyLength => f.write_str("the Item Key is not 32 bytes"),
            Self::Aead => f.write_str("the AEAD refused the item payload"),
            Self::Aad(e) => write!(f, "the item AAD could not be encoded: {e}"),
            Self::WrongRecordType(t) => write!(
                f,
                "an item payload must be bound as record type 0x01, got {t:#04x}"
            ),
        }
    }
}

impl core::error::Error for ItemError {}

fn prepare(
    item_key: &Secret<ItemKey>,
    fields: &AadFields,
) -> Result<(XChaCha20Poly1305, Vec<u8>), ItemError> {
    let bytes = item_key.expose();
    if bytes.len() != ITEM_KEY_LEN {
        return Err(ItemError::BadItemKeyLength);
    }
    let record_type = fields.record_type();
    if record_type != aad::RECORD_ITEM_PAYLOAD {
        return Err(ItemError::WrongRecordType(record_type));
    }
    let encoded = aad::encode(fields).map_err(ItemError::Aad)?;
    Ok((XChaCha20Poly1305::new(Key::from_slice(bytes)), encoded))
}

// By value so the nonce is consumed; a reference would let a caller reuse it.
#[allow(clippy::needless_pass_by_value)]

pub fn seal(
    item_key: &Secret<ItemKey>,
    nonce: FreshNonce,
    fields: &AadFields,
    plaintext: &[u8],
) -> Result<SealedPayload, ItemError> {
    let (aead, encoded_aad) = prepare(item_key, fields)?;
    let nonce_bytes = *nonce.as_nonce().as_bytes();
    let ciphertext = aead
        .encrypt(
            XNonce::from_slice(&nonce_bytes),
            Payload {
                msg: plaintext,
                aad: &encoded_aad,
            },
        )
        .map_err(|_| ItemError::Aead)?;
    Ok(SealedPayload {
        nonce: nonce_bytes,
        ciphertext,
    })
}

pub fn open(
    item_key: &Secret<ItemKey>,
    sealed: &SealedPayload,
    fields: &AadFields,
) -> Result<Vec<u8>, ItemError> {
    let (aead, encoded_aad) = prepare(item_key, fields)?;
    let nonce = StoredNonce::from_stored_bytes(*sealed.nonce());
    aead.decrypt(
        XNonce::from_slice(nonce.as_nonce().as_bytes()),
        Payload {
            msg: sealed.ciphertext(),
            aad: &encoded_aad,
        },
    )
    .map_err(|_| ItemError::Aead)
}
