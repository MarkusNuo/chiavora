//! Item Key wraps (§2.2, `docs/adr/0003`).

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use subtle::ConstantTimeEq;

use crate::aad::{self, AadFields, WRAP_PURPOSE_AUTOFILL, WRAP_PURPOSE_VAULT};
use crate::nonce::{FreshNonce, StoredNonce, NONCE_LEN};
use crate::secret::{
    kind::{AutofillKey, ItemKey, VaultKey},
    Secret, SecretKind,
};

const WRAPPING_KEY_LEN: usize = 32;

/// What a wrapped Item Key is bound to: the `0x05` record's fields (§2.2).
#[derive(Debug, Clone, Copy)]
pub struct WrapContext<'a> {
    pub vault_id: &'a [u8],
    pub item_id: &'a [u8],
}

impl WrapContext<'_> {
    fn aad(&self, wrap_purpose: u8) -> Result<Vec<u8>, WrapError> {
        aad::encode(&AadFields::WrappedItemKey {
            vault_id: self.vault_id.to_vec(),
            item_id: self.item_id.to_vec(),
            wrap_purpose,
        })
        .map_err(WrapError::Aad)
    }
}

/// Not secret, so it has a real `Debug`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrappedKey {
    nonce: [u8; NONCE_LEN],
    ciphertext: Vec<u8>,
}

impl WrappedKey {
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
pub enum WrapError {
    BadWrappingKeyLength,
    Aead,
    Aad(aad::AadError),
    BadItemKeyLength,
    I7Disagreement,
}

impl core::fmt::Display for WrapError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::BadWrappingKeyLength => f.write_str("a wrapping key is not 32 bytes"),
            Self::Aead => f.write_str("the AEAD refused the wrapped key"),
            Self::Aad(e) => write!(f, "the wrap binding could not be encoded: {e}"),
            Self::BadItemKeyLength => f.write_str("the unwrapped Item Key has an invalid length"),
            Self::I7Disagreement => f.write_str(
                "I7 violated: the Vault-Key and Autofill-Key wraps yielded different Item Keys",
            ),
        }
    }
}

impl core::error::Error for WrapError {}

fn cipher<K: SecretKind>(key: &Secret<K>) -> Result<XChaCha20Poly1305, WrapError> {
    let bytes = key.expose();
    if bytes.len() != WRAPPING_KEY_LEN {
        return Err(WrapError::BadWrappingKeyLength);
    }
    Ok(XChaCha20Poly1305::new(Key::from_slice(bytes)))
}

fn wrap_one<K: SecretKind>(
    item_key: &Secret<ItemKey>,
    key: &Secret<K>,
    ctx: WrapContext<'_>,
    purpose: u8,
) -> Result<WrappedKey, WrapError> {
    let aead = cipher(key)?;
    // I2: the only nonce source, and taken by value so it cannot be reused.
    let nonce = FreshNonce::generate().map_err(|_| WrapError::Aead)?;
    let encoded_aad = ctx.aad(purpose)?;
    let ciphertext = aead
        .encrypt(
            XNonce::from_slice(nonce.as_nonce().as_bytes()),
            Payload {
                msg: item_key.expose(),
                aad: &encoded_aad,
            },
        )
        .map_err(|_| WrapError::Aead)?;
    Ok(WrappedKey {
        nonce: *nonce.as_nonce().as_bytes(),
        ciphertext,
    })
}

fn unwrap_one<K: SecretKind>(
    wrapped: &WrappedKey,
    key: &Secret<K>,
    ctx: WrapContext<'_>,
    purpose: u8,
) -> Result<Secret<ItemKey>, WrapError> {
    let aead = cipher(key)?;
    let nonce = StoredNonce::from_stored_bytes(*wrapped.nonce());
    let encoded_aad = ctx.aad(purpose)?;
    let plaintext = aead
        .decrypt(
            XNonce::from_slice(nonce.as_nonce().as_bytes()),
            Payload {
                msg: wrapped.ciphertext(),
                aad: &encoded_aad,
            },
        )
        .map_err(|_| WrapError::Aead)?;
    if plaintext.len() != WRAPPING_KEY_LEN {
        return Err(WrapError::BadItemKeyLength);
    }
    Ok(Secret::from_derived_bytes(plaintext))
}

/// For kinds the autofill provider must not reach.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultOnly {
    vault: WrappedKey,
}

impl VaultOnly {
    pub fn wrap(
        item_key: &Secret<ItemKey>,
        vault_key: &Secret<VaultKey>,
        ctx: WrapContext<'_>,
    ) -> Result<Self, WrapError> {
        Ok(Self {
            vault: wrap_one(item_key, vault_key, ctx, WRAP_PURPOSE_VAULT)?,
        })
    }

    #[must_use]
    pub const fn from_stored_parts(vault: WrappedKey) -> Self {
        Self { vault }
    }

    #[must_use]
    pub const fn vault_wrap(&self) -> &WrappedKey {
        &self.vault
    }

    pub fn unwrap(
        &self,
        vault_key: &Secret<VaultKey>,
        ctx: WrapContext<'_>,
    ) -> Result<Secret<ItemKey>, WrapError> {
        unwrap_one(&self.vault, vault_key, ctx, WRAP_PURPOSE_VAULT)
    }
}

/// For kinds the provider must reach, `login` and `TOTP`; I7 requires both wraps to agree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultAndAutofill {
    vault: WrappedKey,
    autofill: WrappedKey,
}

impl VaultAndAutofill {
    pub fn wrap(
        item_key: &Secret<ItemKey>,
        vault_key: &Secret<VaultKey>,
        autofill_key: &Secret<AutofillKey>,
        ctx: WrapContext<'_>,
    ) -> Result<Self, WrapError> {
        Ok(Self {
            vault: wrap_one(item_key, vault_key, ctx, WRAP_PURPOSE_VAULT)?,
            autofill: wrap_one(item_key, autofill_key, ctx, WRAP_PURPOSE_AUTOFILL)?,
        })
    }

    /// Reconstructs the set from storage; nothing has checked I7 yet.
    #[must_use]
    pub const fn from_stored_parts(vault: WrappedKey, autofill: WrappedKey) -> Self {
        Self { vault, autofill }
    }

    #[must_use]
    pub const fn vault_wrap(&self) -> &WrappedKey {
        &self.vault
    }

    #[must_use]
    pub const fn autofill_wrap(&self) -> &WrappedKey {
        &self.autofill
    }

    pub fn unwrap(
        &self,
        vault_key: &Secret<VaultKey>,
        autofill_key: &Secret<AutofillKey>,
        ctx: WrapContext<'_>,
    ) -> Result<Secret<ItemKey>, WrapError> {
        let from_vault = unwrap_one(&self.vault, vault_key, ctx, WRAP_PURPOSE_VAULT)?;
        let from_autofill = unwrap_one(&self.autofill, autofill_key, ctx, WRAP_PURPOSE_AUTOFILL)?;
        // Constant time, because this compares key material.
        if from_vault.expose().ct_eq(from_autofill.expose()).into() {
            Ok(from_vault)
        } else {
            Err(WrapError::I7Disagreement)
        }
    }

    /// The provider has no Vault Key, so it cannot check I7; the app, which
    /// writes items, does.
    pub fn unwrap_for_provider(
        &self,
        autofill_key: &Secret<AutofillKey>,
        ctx: WrapContext<'_>,
    ) -> Result<Secret<ItemKey>, WrapError> {
        unwrap_one(&self.autofill, autofill_key, ctx, WRAP_PURPOSE_AUTOFILL)
    }
}

mod sealed {
    pub trait Sealed {}
}

pub trait ItemType: sealed::Sealed {
    type Wraps;
    /// This type's name, which is also the tag it is stored under.
    const NAME: &'static str;
    const PROVIDER_READABLE: bool;
}

/// `ItemKind` comes from the same list, so the runtime dispatch cannot disagree with the types.
macro_rules! item_type {
    ($(#[doc = $doc:literal] $name:ident => $label:literal, $wraps:ty, $readable:literal;)+) => {
        $(
            #[doc = $doc]
            #[derive(Debug, Clone, Copy)]
            pub struct $name;
            impl sealed::Sealed for $name {}
            impl ItemType for $name {
                type Wraps = $wraps;
                const NAME: &'static str = $label;
                const PROVIDER_READABLE: bool = $readable;
            }
        )+
    };
}

item_type! {
    #[doc = "A login item, fillable and therefore double-wrapped (`docs/adr/0003`)."]
    Login => "login", VaultAndAutofill, true;
    #[doc = "A standalone TOTP item, fillable and therefore double-wrapped."]
    Totp => "TOTP", VaultAndAutofill, true;
    #[doc = "A secure note, not fillable and wrapped under the Vault Key only."]
    Note => "note", VaultOnly, false;
    #[doc = "A payment card, not fillable and wrapped under the Vault Key only."]
    Card => "card", VaultOnly, false;
    #[doc = "An identity, not fillable and wrapped under the Vault Key only."]
    Identity => "identity", VaultOnly, false;
    #[doc = "An SSH key, not fillable and wrapped under the Vault Key only."]
    SshKey => "SSH key", VaultOnly, false;
}
