//! Signup: the §2.2 key hierarchy, built once.

use chiavora_protocol::{Field, Record, WireError};

use crate::aad::{
    RECORD_SEALED_VAULT_KEY, RECORD_WRAPPED_ACCOUNT_KEY, RECORD_WRAPPED_AUTOFILL_KEY,
};
use crate::account_key::{self, AccountKeyContext, AccountKeyError, WrappedAccountKey};
use crate::autofill::{self, AutofillContext, AutofillError, WrappedAutofillKey};
use crate::csprng;
use crate::nonce::NONCE_LEN;
use crate::seal::{self, AccountKeypair, SealContext, SealError, SealedVaultKey};
use crate::secret::{
    kind::{AutofillKey, Muk, VaultKey},
    Secret,
};
use crate::store::{Store, StoreError};

/// The epoch a freshly provisioned key carries: 1, not 0, so that a first provisioning
/// raises the high-water mark rather than looking like a rewind.
pub const FIRST_EPOCH: u32 = 1;

mod tag {
    use chiavora_protocol::Tag;

    pub const ENCAPSULATED: Tag = 1;
    pub const NONCE: Tag = 2;
    pub const CIPHERTEXT: Tag = 3;
}

/// No variant carries key material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProvisionError {
    /// A new Vault Key would make every existing item unreadable.
    AlreadyProvisioned,
    Incomplete {
        record_type: u8,
    },
    Csprng,
    Store {
        reason: String,
    },
    Seal {
        reason: String,
    },
    Autofill {
        reason: String,
    },
    AccountKey {
        reason: String,
    },
    Malformed,
}

impl core::fmt::Display for ProvisionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::AlreadyProvisioned => f.write_str("this vault is already provisioned"),
            Self::Incomplete { record_type } => write!(
                f,
                "this vault is half-provisioned: record type {record_type:#04x} is missing"
            ),
            Self::Csprng => f.write_str("the platform CSPRNG refused"),
            Self::Store { reason }
            | Self::Seal { reason }
            | Self::Autofill { reason }
            | Self::AccountKey { reason } => f.write_str(reason),
            Self::Malformed => f.write_str("a stored provisioning record is malformed"),
        }
    }
}

impl core::error::Error for ProvisionError {}

impl From<csprng::CsprngError> for ProvisionError {
    fn from(_: csprng::CsprngError) -> Self {
        Self::Csprng
    }
}

impl From<StoreError> for ProvisionError {
    fn from(e: StoreError) -> Self {
        Self::Store {
            reason: e.to_string(),
        }
    }
}

impl From<SealError> for ProvisionError {
    fn from(e: SealError) -> Self {
        Self::Seal {
            reason: e.to_string(),
        }
    }
}

impl From<AutofillError> for ProvisionError {
    fn from(e: AutofillError) -> Self {
        Self::Autofill {
            reason: e.to_string(),
        }
    }
}

impl From<AccountKeyError> for ProvisionError {
    fn from(e: AccountKeyError) -> Self {
        Self::AccountKey {
            reason: e.to_string(),
        }
    }
}

impl From<WireError> for ProvisionError {
    fn from(_: WireError) -> Self {
        Self::Malformed
    }
}

pub struct Provisioning {
    pub vault_id: Vec<u8>,
    pub account: AccountKeypair,
    pub sealed_vault_key: SealedVaultKey,
    pub vault_key_epoch: u32,
    pub autofill_key: Secret<AutofillKey>,
}

impl core::fmt::Debug for Provisioning {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Provisioning(epoch {}, <keys>)", self.vault_key_epoch)
    }
}

fn encode_two(
    a_tag: chiavora_protocol::Tag,
    a: &[u8],
    b: &[u8],
) -> Result<Vec<u8>, ProvisionError> {
    Ok(Record::new(vec![
        Field::new(a_tag, a.to_vec())?,
        Field::new(tag::CIPHERTEXT, b.to_vec())?,
    ])
    .encode()?)
}

fn decode_two(
    bytes: &[u8],
    a_tag: chiavora_protocol::Tag,
) -> Result<(Vec<u8>, Vec<u8>), ProvisionError> {
    let record = Record::decode(bytes)?;
    let mut first = None;
    let mut ciphertext = None;
    for field in record.fields() {
        // R1: an unknown tag is refused rather than skipped.
        let slot = if field.tag() == a_tag {
            &mut first
        } else if field.tag() == tag::CIPHERTEXT {
            &mut ciphertext
        } else {
            return Err(ProvisionError::Malformed);
        };
        if slot.replace(field.value().to_vec()).is_some() {
            return Err(ProvisionError::Malformed);
        }
    }
    match (first, ciphertext) {
        (Some(a), Some(b)) => Ok((a, b)),
        _ => Err(ProvisionError::Malformed),
    }
}

fn nonce_array(bytes: &[u8]) -> Result<[u8; NONCE_LEN], ProvisionError> {
    bytes.try_into().map_err(|_| ProvisionError::Malformed)
}

/// Whether this vault, not the account, has been provisioned. The account keypair is
/// shared by all of the account's vaults and must never be replaced by a second one.
pub fn is_provisioned(store: &Store, vault_id: &[u8]) -> Result<bool, ProvisionError> {
    Ok(store
        .latest_provisioning_epoch(RECORD_SEALED_VAULT_KEY, vault_id)?
        .is_some())
}

fn account_keypair(
    store: &mut Store,
    muk: &Secret<Muk>,
    account_id: &[u8],
) -> Result<AccountKeypair, ProvisionError> {
    if let Some(epoch) = store.account_key_epoch(account_id) {
        let bytes = store
            .get_provisioning(RECORD_WRAPPED_ACCOUNT_KEY, account_id, epoch)?
            .ok_or(ProvisionError::Incomplete {
                record_type: RECORD_WRAPPED_ACCOUNT_KEY,
            })?;
        let (nonce, ciphertext) = decode_two(&bytes, tag::NONCE)?;
        return Ok(account_key::unwrap(
            &WrappedAccountKey::from_stored_parts(nonce_array(&nonce)?, ciphertext),
            muk,
            AccountKeyContext {
                account_id,
                account_key_epoch: epoch,
            },
        )?);
    }

    let account = AccountKeypair::generate()?;
    let wrapped = account_key::wrap(
        &account,
        muk,
        AccountKeyContext {
            account_id,
            account_key_epoch: FIRST_EPOCH,
        },
    )?;
    store.put_provisioning(
        RECORD_WRAPPED_ACCOUNT_KEY,
        account_id,
        FIRST_EPOCH,
        &encode_two(tag::NONCE, wrapped.nonce(), wrapped.ciphertext())?,
    )?;
    Ok(account)
}

pub fn provision(
    store: &mut Store,
    muk: &Secret<Muk>,
    account_id: &[u8],
    vault_id: &[u8],
) -> Result<Provisioning, ProvisionError> {
    if is_provisioned(store, vault_id)? {
        return Err(ProvisionError::AlreadyProvisioned);
    }

    // The account key is written first, so a crash never leaves a seal that nothing opens.
    let account = account_keypair(store, muk, account_id)?;

    let mut vault_bytes = vec![0_u8; 32];
    csprng::fill_bytes(&mut vault_bytes)?;
    let vault_key: Secret<VaultKey> = Secret::from_derived_bytes(vault_bytes);
    let sealed_vault_key = seal::seal_vault_key(
        &vault_key,
        SealContext {
            vault_id,
            vault_key_epoch: FIRST_EPOCH,
            recipient_public_key: account.public(),
        },
    )?;

    let autofill_key = autofill::generate()?;
    let wrapped_autofill = autofill::wrap(
        &autofill_key,
        &vault_key,
        AutofillContext {
            vault_id,
            vault_key_epoch: FIRST_EPOCH,
        },
    )?;

    store.put_provisioning(
        RECORD_SEALED_VAULT_KEY,
        vault_id,
        FIRST_EPOCH,
        &encode_two(
            tag::ENCAPSULATED,
            sealed_vault_key.encapsulated(),
            sealed_vault_key.ciphertext(),
        )?,
    )?;
    store.put_provisioning(
        RECORD_WRAPPED_AUTOFILL_KEY,
        vault_id,
        FIRST_EPOCH,
        &encode_two(
            tag::NONCE,
            wrapped_autofill.nonce(),
            wrapped_autofill.ciphertext(),
        )?,
    )?;

    Ok(Provisioning {
        vault_id: vault_id.to_vec(),
        account,
        sealed_vault_key,
        vault_key_epoch: FIRST_EPOCH,
        autofill_key,
    })
}

/// Draws the vault identifier here so nothing above `core` has to store one.
pub fn provision_first_vault(
    store: &mut Store,
    muk: &Secret<Muk>,
    account_id: &[u8],
) -> Result<Provisioning, ProvisionError> {
    let mut vault_id = vec![0_u8; 16];
    csprng::fill_bytes(&mut vault_id)?;
    provision(store, muk, account_id, &vault_id)
}

pub fn vault_ids(store: &Store) -> Result<Vec<Vec<u8>>, ProvisionError> {
    Ok(store.provisioning_owners(RECORD_SEALED_VAULT_KEY)?)
}

pub fn load(
    store: &Store,
    muk: &Secret<Muk>,
    account_id: &[u8],
    vault_id: &[u8],
) -> Result<Provisioning, ProvisionError> {
    // The epoch comes from the MAC'd metadata, never from the table's unauthenticated column.
    let account_key_epoch =
        store
            .account_key_epoch(account_id)
            .ok_or(ProvisionError::Incomplete {
                record_type: RECORD_WRAPPED_ACCOUNT_KEY,
            })?;

    let account_bytes = store
        .get_provisioning(RECORD_WRAPPED_ACCOUNT_KEY, account_id, account_key_epoch)?
        .ok_or(ProvisionError::Incomplete {
            record_type: RECORD_WRAPPED_ACCOUNT_KEY,
        })?;
    let (nonce, ciphertext) = decode_two(&account_bytes, tag::NONCE)?;
    let account = account_key::unwrap(
        &WrappedAccountKey::from_stored_parts(nonce_array(&nonce)?, ciphertext),
        muk,
        AccountKeyContext {
            account_id,
            account_key_epoch,
        },
    )?;

    let vault_key_epoch = store
        .latest_provisioning_epoch(RECORD_SEALED_VAULT_KEY, vault_id)?
        .ok_or(ProvisionError::Incomplete {
            record_type: RECORD_SEALED_VAULT_KEY,
        })?;
    let sealed_bytes = store
        .get_provisioning(RECORD_SEALED_VAULT_KEY, vault_id, vault_key_epoch)?
        .ok_or(ProvisionError::Incomplete {
            record_type: RECORD_SEALED_VAULT_KEY,
        })?;
    let (encapsulated, ciphertext) = decode_two(&sealed_bytes, tag::ENCAPSULATED)?;
    let sealed_vault_key = SealedVaultKey::from_stored_parts(encapsulated, ciphertext);

    // Opened only to unwrap the Autofill Key, and dropped on return.
    let vault_key = seal::open_vault_key(
        &sealed_vault_key,
        &account,
        SealContext {
            vault_id,
            vault_key_epoch,
            recipient_public_key: account.public(),
        },
    )?;

    let autofill_bytes = store
        .get_provisioning(RECORD_WRAPPED_AUTOFILL_KEY, vault_id, vault_key_epoch)?
        .ok_or(ProvisionError::Incomplete {
            record_type: RECORD_WRAPPED_AUTOFILL_KEY,
        })?;
    let (nonce, ciphertext) = decode_two(&autofill_bytes, tag::NONCE)?;
    let autofill_key = autofill::unwrap(
        &WrappedAutofillKey::from_stored_parts(nonce_array(&nonce)?, ciphertext),
        &vault_key,
        AutofillContext {
            vault_id,
            vault_key_epoch,
        },
    )?;

    Ok(Provisioning {
        vault_id: vault_id.to_vec(),
        account,
        sealed_vault_key,
        vault_key_epoch,
        autofill_key,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::store::Unanchored;

    const ACCOUNT: &[u8] = b"account-1";
    const VAULT: &[u8] = b"vault-1";

    fn muk(fill: u8) -> Secret<Muk> {
        Secret::from_derived_bytes(vec![fill; 32])
    }

    fn store() -> Store {
        Store::open_in_memory(&muk(0x4D), Box::new(Unanchored)).unwrap()
    }

    #[test]
    fn provisioning_then_loading_recovers_the_same_keys() {
        let mut store = store();
        let made = provision(&mut store, &muk(0x11), ACCOUNT, VAULT).unwrap();
        let loaded = load(&store, &muk(0x11), ACCOUNT, VAULT).unwrap();

        assert_eq!(loaded.account.public(), made.account.public());
        assert_eq!(loaded.autofill_key.expose(), made.autofill_key.expose());
        assert_eq!(loaded.vault_key_epoch, made.vault_key_epoch);
    }

    #[test]
    fn provisioning_twice_is_refused_rather_than_overwriting_the_vault_key() {
        let mut store = store();
        provision(&mut store, &muk(0x11), ACCOUNT, VAULT).unwrap();
        assert_eq!(
            provision(&mut store, &muk(0x11), ACCOUNT, VAULT).err(),
            Some(ProvisionError::AlreadyProvisioned)
        );
    }

    #[test]
    fn another_muk_loads_nothing() {
        let mut store = store();
        provision(&mut store, &muk(0x11), ACCOUNT, VAULT).unwrap();
        assert!(
            matches!(
                load(&store, &muk(0x22), ACCOUNT, VAULT),
                Err(ProvisionError::AccountKey { .. })
            ),
            "a wrong MUK must fail at the account key's AEAD"
        );
    }

    #[test]
    fn a_missing_record_is_named_by_its_record_type() {
        let store = store();
        assert_eq!(
            load(&store, &muk(0x11), ACCOUNT, VAULT).err(),
            Some(ProvisionError::Incomplete {
                record_type: RECORD_WRAPPED_ACCOUNT_KEY
            })
        );
    }

    #[test]
    fn two_vaults_of_one_account_share_the_keypair_and_not_the_vault_key() {
        let mut store = store();
        let first = provision(&mut store, &muk(0x11), ACCOUNT, b"vault-a").unwrap();
        let second = provision(&mut store, &muk(0x11), ACCOUNT, b"vault-b").unwrap();

        assert_eq!(
            first.account.public(),
            second.account.public(),
            "the account keypair is the account's, so a second vault reuses it"
        );
        assert_ne!(
            first.autofill_key.expose(),
            second.autofill_key.expose(),
            "but the Autofill Key is per vault, which is what makes a shared \
             vault's Autofill Key reachable by its members and nobody else"
        );
    }

    #[test]
    fn create_lock_restart_unlock_read_through_provisioning() {
        use crate::model::{Item, ItemField};
        use crate::store::Unanchored;
        use crate::vault::OpenVault;
        use crate::wrap::ItemKind;

        let dir = std::env::temp_dir().join(format!(
            "chiavora-provision-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("vault.db");

        let item = Item::new(
            ItemKind::Login,
            vec![
                ItemField::new("title", b"Example".to_vec()).unwrap(),
                ItemField::new("username", b"ada".to_vec()).unwrap(),
                ItemField::new("password", b"hunter2".to_vec()).unwrap(),
            ],
            &[],
        )
        .unwrap();

        let item_id = {
            let mut store = Store::open(&path, &muk(0x4D), Box::new(Unanchored)).unwrap();
            let p = provision(&mut store, &muk(0x11), ACCOUNT, VAULT).unwrap();
            let mut vault = OpenVault::new(
                &mut store,
                VAULT.to_vec(),
                p.vault_key_epoch,
                p.sealed_vault_key,
                &p.account,
                &p.autofill_key,
            );
            let id = crate::vault::new_item_id().unwrap();
            vault.create(&id, ItemKind::Login, &item).unwrap();
            id
        };
        // Every key above was dropped with its block; a new Store opens the same file.
        let read_back = {
            let mut store = Store::open(&path, &muk(0x4D), Box::new(Unanchored)).unwrap();
            let p = load(&store, &muk(0x11), ACCOUNT, VAULT).unwrap();
            let vault = OpenVault::new(
                &mut store,
                VAULT.to_vec(),
                p.vault_key_epoch,
                p.sealed_vault_key,
                &p.account,
                &p.autofill_key,
            );
            vault.read(&item_id).unwrap()
        };

        assert_eq!(
            read_back.field("password").map(ItemField::value),
            Some(&b"hunter2"[..]),
            "the item did not survive the restart"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_first_vaults_identifier_is_drawn_here_and_read_back_from_the_store() {
        let mut store = store();
        let made = provision_first_vault(&mut store, &muk(0x11), ACCOUNT).unwrap();

        assert_eq!(
            vault_ids(&store).unwrap(),
            vec![made.vault_id.clone()],
            "the store is what remembers which vault exists"
        );
        let loaded = load(&store, &muk(0x11), ACCOUNT, &made.vault_id).unwrap();
        assert_eq!(loaded.vault_id, made.vault_id);
    }

    #[test]
    fn two_signups_draw_different_vault_identifiers() {
        let mut a = store();
        let mut b = store();
        assert_ne!(
            provision_first_vault(&mut a, &muk(0x11), ACCOUNT)
                .unwrap()
                .vault_id,
            provision_first_vault(&mut b, &muk(0x11), ACCOUNT)
                .unwrap()
                .vault_id
        );
    }

    #[test]
    fn a_record_with_an_unexpected_tag_is_refused() {
        let bytes = Record::new(vec![
            Field::new(tag::NONCE, vec![0; NONCE_LEN]).unwrap(),
            Field::new(tag::CIPHERTEXT, vec![1, 2, 3]).unwrap(),
            Field::new(99, vec![4]).unwrap(),
        ])
        .encode()
        .unwrap();
        assert_eq!(
            decode_two(&bytes, tag::NONCE).err(),
            Some(ProvisionError::Malformed)
        );
    }
}
