//! `decode` parses bytes another build or a local attacker may have written.

use sha2::{Digest, Sha256};

use chiavora_protocol::{Field, Record, Tag, WireError};

use crate::aad::{self, AadError, AadFields};
use crate::item::SealedPayload;
use crate::nonce::NONCE_LEN;
use crate::wrap::{AnyWrapSet, ItemKind, WrapError, WrappedKey};

/// The record's tags; additive only.
pub mod tag {
    use chiavora_protocol::Tag;

    pub const AAD: Tag = 1;
    pub const NONCE: Tag = 2;
    pub const CIPHERTEXT: Tag = 3;
    pub const VAULT_WRAP_NONCE: Tag = 4;
    pub const VAULT_WRAP_CIPHERTEXT: Tag = 5;
    pub const AUTOFILL_WRAP_NONCE: Tag = 6;
    pub const AUTOFILL_WRAP_CIPHERTEXT: Tag = 7;
}

/// No variant carries record bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoredRecordError {
    Wire(WireError),
    Aad(AadError),
    Wrap(WrapError),
    MissingField {
        tag: Tag,
    },
    RepeatedField {
        at: usize,
    },
    Malformed {
        at: usize,
    },
    NotAnItemPayload,
    /// The AAD's `contentType` names no item kind this build knows; the bytes
    /// stay in the store untouched.
    UnknownKind,
}

impl core::fmt::Display for StoredRecordError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Wire(e) => write!(f, "{e}"),
            Self::Aad(e) => write!(f, "{e}"),
            Self::Wrap(e) => write!(f, "{e}"),
            Self::MissingField { tag } => write!(f, "the record has no field with tag {tag}"),
            Self::RepeatedField { at } => write!(f, "field {at} repeats a header"),
            Self::Malformed { at } => write!(f, "field {at} is not shaped as its tag requires"),
            Self::NotAnItemPayload => f.write_str("the record's AAD is not an item payload"),
            Self::UnknownKind => f.write_str(
                "no item kind this build knows has that tag; the record is preserved, not opened",
            ),
        }
    }
}

impl core::error::Error for StoredRecordError {}

impl From<WireError> for StoredRecordError {
    fn from(e: WireError) -> Self {
        Self::Wire(e)
    }
}
impl From<AadError> for StoredRecordError {
    fn from(e: AadError) -> Self {
        Self::Aad(e)
    }
}
impl From<WrapError> for StoredRecordError {
    fn from(e: WrapError) -> Self {
        Self::Wrap(e)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredRecord {
    fields: AadFields,
    payload: SealedPayload,
    wraps: AnyWrapSet,
}

impl StoredRecord {
    pub fn new(
        fields: AadFields,
        payload: SealedPayload,
        wraps: AnyWrapSet,
    ) -> Result<Self, StoredRecordError> {
        if fields.record_type() != aad::RECORD_ITEM_PAYLOAD {
            return Err(StoredRecordError::NotAnItemPayload);
        }
        Ok(Self {
            fields,
            payload,
            wraps,
        })
    }

    #[must_use]
    pub const fn fields(&self) -> &AadFields {
        &self.fields
    }

    #[must_use]
    pub const fn payload(&self) -> &SealedPayload {
        &self.payload
    }

    #[must_use]
    pub const fn wraps(&self) -> &AnyWrapSet {
        &self.wraps
    }

    pub fn kind(&self) -> Result<ItemKind, StoredRecordError> {
        kind_of(&self.fields)
    }

    /// `SHA-256(AAD ‖ nonce ‖ ciphertext ‖ tag)`, the `ciphertextDigest` of §2.5.
    /// The wraps are not hashed, so a Vault Key rotation changes no digest.
    pub fn ciphertext_digest(&self) -> Result<[u8; 32], StoredRecordError> {
        let mut hasher = Sha256::new();
        hasher.update(aad::encode(&self.fields)?);
        hasher.update(self.payload.nonce());
        // The AEAD tag is already appended to the ciphertext.
        hasher.update(self.payload.ciphertext());
        Ok(hasher.finalize().into())
    }

    pub fn encode(&self) -> Result<Vec<u8>, StoredRecordError> {
        let mut fields = vec![
            Field::new(tag::AAD, aad::encode(&self.fields)?)?,
            Field::new(tag::NONCE, self.payload.nonce().to_vec())?,
            Field::new(tag::CIPHERTEXT, self.payload.ciphertext().to_vec())?,
            Field::new(
                tag::VAULT_WRAP_NONCE,
                self.wraps.vault_wrap().nonce().to_vec(),
            )?,
            Field::new(
                tag::VAULT_WRAP_CIPHERTEXT,
                self.wraps.vault_wrap().ciphertext().to_vec(),
            )?,
        ];
        if let Some(autofill) = self.wraps.autofill_wrap() {
            fields.push(Field::new(
                tag::AUTOFILL_WRAP_NONCE,
                autofill.nonce().to_vec(),
            )?);
            fields.push(Field::new(
                tag::AUTOFILL_WRAP_CIPHERTEXT,
                autofill.ciphertext().to_vec(),
            )?);
        }
        Ok(Record::new(fields).encode()?)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, StoredRecordError> {
        fn once<T>(slot: &mut Option<T>, value: T, at: usize) -> Result<(), StoredRecordError> {
            if slot.replace(value).is_some() {
                return Err(StoredRecordError::RepeatedField { at });
            }
            Ok(())
        }
        fn nonce_of(bytes: &[u8], at: usize) -> Result<[u8; NONCE_LEN], StoredRecordError> {
            bytes
                .try_into()
                .map_err(|_| StoredRecordError::Malformed { at })
        }

        let record = Record::decode(bytes)?;

        let mut aad_bytes: Option<Vec<u8>> = None;
        let mut nonce: Option<[u8; NONCE_LEN]> = None;
        let mut ciphertext: Option<Vec<u8>> = None;
        let mut vault_nonce: Option<[u8; NONCE_LEN]> = None;
        let mut vault_ct: Option<Vec<u8>> = None;
        let mut autofill_nonce: Option<[u8; NONCE_LEN]> = None;
        let mut autofill_ct: Option<Vec<u8>> = None;

        for (at, field) in record.fields().iter().enumerate() {
            let v = field.value();
            match field.tag() {
                tag::AAD => once(&mut aad_bytes, v.to_vec(), at)?,
                tag::NONCE => once(&mut nonce, nonce_of(v, at)?, at)?,
                tag::CIPHERTEXT => once(&mut ciphertext, v.to_vec(), at)?,
                tag::VAULT_WRAP_NONCE => once(&mut vault_nonce, nonce_of(v, at)?, at)?,
                tag::VAULT_WRAP_CIPHERTEXT => once(&mut vault_ct, v.to_vec(), at)?,
                tag::AUTOFILL_WRAP_NONCE => once(&mut autofill_nonce, nonce_of(v, at)?, at)?,
                tag::AUTOFILL_WRAP_CIPHERTEXT => once(&mut autofill_ct, v.to_vec(), at)?,
                // A newer build's field; the store keeps the original bytes, so nothing is lost.
                _ => {}
            }
        }

        let fields =
            aad::decode(&aad_bytes.ok_or(StoredRecordError::MissingField { tag: tag::AAD })?)?;
        if fields.record_type() != aad::RECORD_ITEM_PAYLOAD {
            return Err(StoredRecordError::NotAnItemPayload);
        }
        let payload = SealedPayload::from_stored_parts(
            nonce.ok_or(StoredRecordError::MissingField { tag: tag::NONCE })?,
            ciphertext.ok_or(StoredRecordError::MissingField {
                tag: tag::CIPHERTEXT,
            })?,
        );
        let vault = WrappedKey::from_stored_parts(
            vault_nonce.ok_or(StoredRecordError::MissingField {
                tag: tag::VAULT_WRAP_NONCE,
            })?,
            vault_ct.ok_or(StoredRecordError::MissingField {
                tag: tag::VAULT_WRAP_CIPHERTEXT,
            })?,
        );
        let autofill = match (autofill_nonce, autofill_ct) {
            (None, None) => None,
            (Some(n), Some(c)) => Some(WrappedKey::from_stored_parts(n, c)),
            // Half an Autofill wrap is neither present nor absent.
            (Some(_), None) => {
                return Err(StoredRecordError::MissingField {
                    tag: tag::AUTOFILL_WRAP_CIPHERTEXT,
                })
            }
            (None, Some(_)) => {
                return Err(StoredRecordError::MissingField {
                    tag: tag::AUTOFILL_WRAP_NONCE,
                })
            }
        };

        let wraps = kind_of(&fields)?.wraps_from_stored_parts(vault, autofill)?;
        Ok(Self {
            fields,
            payload,
            wraps,
        })
    }
}

fn kind_of(fields: &AadFields) -> Result<ItemKind, StoredRecordError> {
    let AadFields::ItemPayload { content_type, .. } = fields else {
        return Err(StoredRecordError::NotAnItemPayload);
    };
    let tag = core::str::from_utf8(content_type).map_err(|_| StoredRecordError::UnknownKind)?;
    ItemKind::from_tag(tag).ok_or(StoredRecordError::UnknownKind)
}
