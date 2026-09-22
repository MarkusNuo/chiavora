//! A screen gets items, never the `Store`, the Vault Key or an Item Key.

use crate::aad::AadFields;
use crate::csprng;
use crate::item;
use crate::model::{Item, ModelError, FIELD_TITLE, FIELD_USERNAME};
use crate::nonce::{FreshNonce, NonceError};
use crate::seal::{self, AccountKeypair, SealContext, SealError, SealedVaultKey};
use crate::secret::{
    kind::{AutofillKey, ItemKey, VaultKey},
    Secret,
};
use crate::store::{Store, StoreError};
use crate::stored_record::{StoredRecord, StoredRecordError};
use crate::wrap::{ItemKind, VaultKeys, WrapContext, WrapError};

/// Length of an Item Key (§2.2).
const ITEM_KEY_LEN: usize = 32;

/// No variant carries plaintext, key material or a ciphertext.
#[derive(Debug)]
pub enum VaultError {
    Store(StoreError),
    Seal(SealError),
    Wrap(WrapError),
    Record(StoredRecordError),
    Model(ModelError),
    Payload,
    Csprng,
    /// No item with that identifier: a stale screen, not a damaged store.
    NoSuchItem,
}

impl core::fmt::Display for VaultError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Store(e) => write!(f, "{e}"),
            Self::Seal(e) => write!(f, "{e}"),
            Self::Wrap(e) => write!(f, "{e}"),
            Self::Record(e) => write!(f, "{e}"),
            Self::Model(e) => write!(f, "{e}"),
            Self::Payload => f.write_str("the item did not open"),
            Self::Csprng => f.write_str("the platform CSPRNG failed"),
            Self::NoSuchItem => f.write_str("no item with that identifier"),
        }
    }
}

impl core::error::Error for VaultError {}

macro_rules! from_error {
    ($($from:ty => $variant:ident;)+) => {
        $(impl From<$from> for VaultError {
            fn from(e: $from) -> Self {
                Self::$variant(e)
            }
        })+
    };
}

from_error! {
    StoreError => Store;
    SealError => Seal;
    WrapError => Wrap;
    StoredRecordError => Record;
    ModelError => Model;
}

impl From<NonceError> for VaultError {
    fn from(_: NonceError) -> Self {
        // A nonce fails to generate only when the CSPRNG refuses.
        Self::Csprng
    }
}

impl From<csprng::CsprngError> for VaultError {
    fn from(_: csprng::CsprngError) -> Self {
        Self::Csprng
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemSummary {
    pub item_id: Vec<u8>,
    pub version: u64,
    pub kind: ItemKind,
    pub title: String,
    pub username: String,
}

/// The Vault Key exists only inside each method that needs it.
pub struct OpenVault<'a> {
    store: &'a mut Store,
    vault_id: Vec<u8>,
    vault_key_epoch: u32,
    sealed_vault_key: SealedVaultKey,
    account: &'a AccountKeypair,
    /// The Autofill Key, needed to wrap `login` and `TOTP` items (ADR-0003).
    autofill_key: &'a Secret<AutofillKey>,
}

impl core::fmt::Debug for OpenVault<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("OpenVault(<sealed>)")
    }
}

impl<'a> OpenVault<'a> {
    #[must_use]
    pub fn new(
        store: &'a mut Store,
        vault_id: Vec<u8>,
        vault_key_epoch: u32,
        sealed_vault_key: SealedVaultKey,
        account: &'a AccountKeypair,
        autofill_key: &'a Secret<AutofillKey>,
    ) -> Self {
        Self {
            store,
            vault_id,
            vault_key_epoch,
            sealed_vault_key,
            account,
            autofill_key,
        }
    }

    /// Unseals the Vault Key for one operation; the caller drops it.
    fn vault_key(&self) -> Result<Secret<VaultKey>, VaultError> {
        Ok(seal::open_vault_key(
            &self.sealed_vault_key,
            self.account,
            SealContext {
                vault_id: &self.vault_id,
                vault_key_epoch: self.vault_key_epoch,
                recipient_public_key: self.account.public(),
            },
        )?)
    }

    /// One unreadable item fails the whole list; it is never skipped.
    pub fn list(&self) -> Result<Vec<ItemSummary>, VaultError> {
        let vault_key = self.vault_key()?;
        let mut out = Vec::new();
        for (item_id, version) in self.store.list(&self.vault_id)? {
            let item = self.open_one(&item_id, &vault_key)?;
            let kind = self.stored(&item_id)?.kind()?;
            out.push(ItemSummary {
                title: field_text(&item, FIELD_TITLE),
                username: field_text(&item, FIELD_USERNAME),
                item_id,
                version,
                kind,
            });
        }
        Ok(out)
    }

    pub fn read(&self, item_id: &[u8]) -> Result<Item, VaultError> {
        let vault_key = self.vault_key()?;
        self.open_one(item_id, &vault_key)
    }

    pub fn create(
        &mut self,
        item_id: &[u8],
        kind: ItemKind,
        item: &Item,
    ) -> Result<u64, VaultError> {
        self.put(item_id, kind, item, 1)
    }

    pub fn update(
        &mut self,
        item_id: &[u8],
        kind: ItemKind,
        item: &Item,
    ) -> Result<u64, VaultError> {
        let current = self
            .store
            .get_raw(&self.vault_id, item_id)?
            .ok_or(VaultError::NoSuchItem)?;
        self.put(item_id, kind, item, current.version.saturating_add(1))
    }

    pub fn delete(&mut self, item_id: &[u8]) -> Result<(), VaultError> {
        if self.store.delete(&self.vault_id, item_id)? {
            Ok(())
        } else {
            Err(VaultError::NoSuchItem)
        }
    }

    fn put(
        &mut self,
        item_id: &[u8],
        kind: ItemKind,
        item: &Item,
        version: u64,
    ) -> Result<u64, VaultError> {
        let vault_key = self.vault_key()?;

        // A fresh Item Key per write, not per item, so no two versions share a key.
        let mut key_bytes = vec![0_u8; ITEM_KEY_LEN];
        csprng::fill_bytes(&mut key_bytes)?;
        let item_key = Secret::<ItemKey>::from_derived_bytes(key_bytes);

        let fields = AadFields::ItemPayload {
            vault_id: self.vault_id.clone(),
            item_id: item_id.to_vec(),
            version,
            content_type: kind.tag().as_bytes().to_vec(),
        };
        let payload = item::seal(
            &item_key,
            FreshNonce::generate()?,
            &fields,
            &item.to_bytes()?,
        )
        .map_err(|_| VaultError::Payload)?;

        let wraps = kind.wrap(
            &item_key,
            VaultKeys {
                vault: &vault_key,
                autofill: self.autofill_key,
            },
            WrapContext {
                vault_id: &self.vault_id,
                item_id,
            },
        )?;

        let record = StoredRecord::new(fields, payload, wraps)?;
        self.store
            .put_raw(&self.vault_id, item_id, version, &record.encode()?)?;
        Ok(version)
    }

    fn stored(&self, item_id: &[u8]) -> Result<StoredRecord, VaultError> {
        let raw = self
            .store
            .get_raw(&self.vault_id, item_id)?
            .ok_or(VaultError::NoSuchItem)?;
        Ok(StoredRecord::decode(&raw.bytes)?)
    }

    fn open_one(&self, item_id: &[u8], vault_key: &Secret<VaultKey>) -> Result<Item, VaultError> {
        let record = self.stored(item_id)?;
        let ctx = WrapContext {
            vault_id: &self.vault_id,
            item_id,
        };
        // I7 on every read: a double-wrapped key opens only if both copies agree.
        let item_key = record.wraps().unwrap(
            VaultKeys {
                vault: vault_key,
                autofill: self.autofill_key,
            },
            ctx,
        )?;
        let plaintext = item::open(&item_key, record.payload(), record.fields())
            .map_err(|_| VaultError::Payload)?;
        Ok(Item::from_bytes(&plaintext)?)
    }
}

/// A store key for a new item: 16 random bytes, drawn here because the callers are above
/// the FFI boundary and have no good randomness of their own.
pub fn new_item_id() -> Result<Vec<u8>, VaultError> {
    let mut id = vec![0_u8; 16];
    csprng::fill_bytes(&mut id)?;
    Ok(id)
}

/// Lossy on purpose: a title that is not UTF-8 should not refuse the whole list.
fn field_text(item: &Item, name: &str) -> String {
    // R1: a display string from an authenticated item; a missing field is a blank row.
    item.field(name)
        .map(|f| String::from_utf8_lossy(f.value()).into_owned())
        .unwrap_or_default()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::model::ItemField;

    const VAULT: &[u8] = b"vault-1";

    fn muk() -> Secret<crate::secret::kind::Muk> {
        Secret::<crate::secret::kind::Muk>::from_derived_bytes(vec![0x11; 32])
    }

    fn autofill() -> Secret<AutofillKey> {
        Secret::<AutofillKey>::from_derived_bytes(vec![0x33; 32])
    }

    fn login(title: &str, username: &str) -> Item {
        Item::new(
            ItemKind::Login,
            vec![
                ItemField::new(FIELD_TITLE, title.as_bytes().to_vec()).unwrap(),
                ItemField::new(FIELD_USERNAME, username.as_bytes().to_vec()).unwrap(),
                ItemField::new("password", b"hunter2".to_vec()).unwrap(),
            ],
            &[],
        )
        .unwrap()
    }

    struct Fixture {
        account: AccountKeypair,
        autofill: Secret<AutofillKey>,
        sealed: SealedVaultKey,
    }

    impl Fixture {
        fn new() -> Self {
            let account = AccountKeypair::generate().unwrap();
            let vault_key = seal::generate_vault_key().unwrap();
            let sealed = seal::seal_vault_key(
                &vault_key,
                SealContext {
                    vault_id: VAULT,
                    vault_key_epoch: 0,
                    recipient_public_key: account.public(),
                },
            )
            .unwrap();
            Self {
                account,
                autofill: autofill(),
                sealed,
            }
        }

        fn open<'a>(&'a self, store: &'a mut Store) -> OpenVault<'a> {
            OpenVault::new(
                store,
                VAULT.to_vec(),
                0,
                self.sealed.clone(),
                &self.account,
                &self.autofill,
            )
        }
    }

    #[test]
    fn create_then_read_round_trips_an_item() {
        let f = Fixture::new();
        let mut store = Store::open_in_memory(&muk(), Box::new(crate::store::Unanchored)).unwrap();
        let mut vault = f.open(&mut store);

        vault
            .create(b"item-1", ItemKind::Login, &login("Example", "ada"))
            .unwrap();
        let back = vault.read(b"item-1").unwrap();
        assert_eq!(
            back.field(FIELD_USERNAME).map(ItemField::value),
            Some(b"ada".as_slice())
        );
        assert_eq!(
            back.field("password").map(ItemField::value),
            Some(b"hunter2".as_slice())
        );
    }

    #[test]
    fn the_list_shows_title_and_username_and_nothing_else() {
        let f = Fixture::new();
        let mut store = Store::open_in_memory(&muk(), Box::new(crate::store::Unanchored)).unwrap();
        let mut vault = f.open(&mut store);

        vault
            .create(b"item-1", ItemKind::Login, &login("Example", "ada"))
            .unwrap();
        vault
            .create(b"item-2", ItemKind::Login, &login("Other", "grace"))
            .unwrap();

        let rows = vault.list().unwrap();
        let shown: Vec<(&str, &str)> = rows
            .iter()
            .map(|r| (r.title.as_str(), r.username.as_str()))
            .collect();
        assert_eq!(shown, vec![("Example", "ada"), ("Other", "grace")]);
        let debug = format!("{rows:?}");
        assert!(!debug.contains("hunter2"), "{debug}");
    }

    #[test]
    fn update_advances_the_version_and_delete_removes() {
        let f = Fixture::new();
        let mut store = Store::open_in_memory(&muk(), Box::new(crate::store::Unanchored)).unwrap();
        let mut vault = f.open(&mut store);

        assert_eq!(
            vault
                .create(b"item-1", ItemKind::Login, &login("Example", "ada"))
                .unwrap(),
            1
        );
        assert_eq!(
            vault
                .update(b"item-1", ItemKind::Login, &login("Example", "grace"))
                .unwrap(),
            2
        );
        assert_eq!(
            vault
                .read(b"item-1")
                .unwrap()
                .field(FIELD_USERNAME)
                .map(ItemField::value),
            Some(b"grace".as_slice())
        );

        vault.delete(b"item-1").unwrap();
        assert!(matches!(vault.read(b"item-1"), Err(VaultError::NoSuchItem)));
    }

    #[test]
    fn updating_or_deleting_something_absent_is_named_rather_than_absorbed() {
        let f = Fixture::new();
        let mut store = Store::open_in_memory(&muk(), Box::new(crate::store::Unanchored)).unwrap();
        let mut vault = f.open(&mut store);
        assert!(matches!(
            vault.update(b"ghost", ItemKind::Login, &login("x", "y")),
            Err(VaultError::NoSuchItem)
        ));
        assert!(matches!(
            vault.delete(b"ghost"),
            Err(VaultError::NoSuchItem)
        ));
    }

    #[test]
    fn a_vault_opened_with_another_account_key_reads_nothing() {
        let f = Fixture::new();
        let mut store = Store::open_in_memory(&muk(), Box::new(crate::store::Unanchored)).unwrap();
        f.open(&mut store)
            .create(b"item-1", ItemKind::Login, &login("Example", "ada"))
            .unwrap();

        let stranger = AccountKeypair::generate().unwrap();
        let autofill = autofill();
        let mut vault = OpenVault::new(
            &mut store,
            VAULT.to_vec(),
            0,
            f.sealed.clone(),
            &stranger,
            &autofill,
        );
        assert!(matches!(
            vault.read(b"item-1"),
            Err(VaultError::Seal(SealError::Open))
        ));
        let _ = &mut vault;
    }

    #[test]
    fn each_write_draws_a_fresh_item_key() {
        let f = Fixture::new();
        let mut store = Store::open_in_memory(&muk(), Box::new(crate::store::Unanchored)).unwrap();
        let mut vault = f.open(&mut store);

        vault
            .create(b"item-1", ItemKind::Login, &login("Example", "ada"))
            .unwrap();
        let first = store.get_raw(VAULT, b"item-1").unwrap().unwrap().bytes;
        let mut vault = f.open(&mut store);
        vault
            .update(b"item-1", ItemKind::Login, &login("Example", "ada"))
            .unwrap();
        let second = store.get_raw(VAULT, b"item-1").unwrap().unwrap().bytes;
        assert_ne!(first, second);
    }
}
