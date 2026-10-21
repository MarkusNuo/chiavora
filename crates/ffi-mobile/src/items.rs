//! `listItems` returns the two strings a row displays, so no other decrypted field reaches Kotlin.

use std::sync::Arc;

use chiavora_core::model::{Item, ItemField as CoreField};
use chiavora_core::provision::{ProvisionError, Provisioning as CoreProvisioning};
use chiavora_core::vault::{OpenVault, VaultError};
use chiavora_core::wrap::ItemKind;

use crate::anchor::DeviceAnchorStorage;
use crate::vault::MobileVault;

/// No variant carries a field value.
#[derive(Debug, uniffi::Error)]
pub enum ItemError {
    NotProvisioned {
        reason: String,
    },
    Provisioning {
        reason: String,
    },
    Store {
        reason: String,
    },
    Vault {
        reason: String,
    },
    UnknownKind {
        /// A kind tag is not user data.
        tag: String,
    },
    BadField {
        reason: String,
    },
}

impl core::fmt::Display for ItemError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotProvisioned { reason }
            | Self::Provisioning { reason }
            | Self::Store { reason }
            | Self::Vault { reason }
            | Self::BadField { reason } => f.write_str(reason),
            Self::UnknownKind { tag } => write!(f, "'{tag}' is not an item kind"),
        }
    }
}

impl std::error::Error for ItemError {}

#[derive(Debug, uniffi::Record)]
pub struct ItemSummary {
    pub item_id: String,
    pub version: u64,
    pub kind: String,
    pub title: String,
    pub username: String,
}

#[derive(uniffi::Record)]
pub struct ItemField {
    pub name: String,
    pub value: String,
    pub concealed: bool,
}

/// Redacted, so a log line never carries a field value.
impl core::fmt::Debug for ItemField {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "ItemField({:?}, {} bytes, redacted)",
            self.name,
            self.value.len()
        )
    }
}

#[derive(Debug, uniffi::Record)]
pub struct ItemDetail {
    pub item_id: String,
    pub kind: String,
    pub fields: Vec<ItemField>,
}

/// Everything else, including a name this build does not know, is concealed.
const SHOWN_IN_CLEAR: [&str; 5] = ["title", "username", "url", "email", "website"];

fn is_concealed(name: &str) -> bool {
    !SHOWN_IN_CLEAR.contains(&name)
}

fn only_vault(store: &chiavora_core::store::Store) -> Result<Vec<u8>, ItemError> {
    let mut ids = chiavora_core::provision::vault_ids(store).map_err(|e| ItemError::Store {
        reason: e.to_string(),
    })?;
    match ids.len() {
        0 => Err(ItemError::NotProvisioned {
            reason: "this device has no vault yet".to_owned(),
        }),
        1 => Ok(ids.remove(0)),
        n => Err(ItemError::Provisioning {
            reason: format!(
                "this device has {n} vaults and the app has no screen that chooses one"
            ),
        }),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, b| {
        use core::fmt::Write as _;
        // R1: writing to a `String` cannot fail.
        let _ = write!(out, "{b:02x}");
        out
    })
}

fn unhex(text: &str) -> Result<Vec<u8>, ItemError> {
    if text.len() % 2 != 0 {
        return Err(ItemError::Vault {
            reason: "an item identifier must be an even number of hex digits".to_owned(),
        });
    }
    let bytes: Vec<u8> = text.as_bytes().chunks(2).try_fold(
        Vec::with_capacity(text.len() / 2),
        |mut out, pair| {
            let digits = core::str::from_utf8(pair).map_err(|_| ItemError::Vault {
                reason: "an item identifier must be hex".to_owned(),
            })?;
            out.push(
                u8::from_str_radix(digits, 16).map_err(|_| ItemError::Vault {
                    reason: "an item identifier must be hex".to_owned(),
                })?,
            );
            Ok::<_, ItemError>(out)
        },
    )?;
    Ok(bytes)
}

fn kind_from(tag: &str) -> Result<ItemKind, ItemError> {
    ItemKind::from_tag(tag).ok_or_else(|| ItemError::UnknownKind {
        tag: tag.to_owned(),
    })
}

fn item_from(kind: ItemKind, fields: &[ItemField]) -> Result<Item, ItemError> {
    let converted = fields
        .iter()
        .map(|field| CoreField::new(&field.name, field.value.clone().into_bytes()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| ItemError::BadField {
            reason: e.to_string(),
        })?;
    Item::new(kind, converted, &[]).map_err(|e| ItemError::BadField {
        reason: e.to_string(),
    })
}

impl MobileVault {
    fn load_provisioning_from(
        &self,
        store: &chiavora_core::store::Store,
        account_id: &[u8],
        vault_id: &[u8],
    ) -> Result<CoreProvisioning, ItemError> {
        self.load_provisioning(store, account_id, vault_id)
            .map_err(|e| match e {
                ProvisionError::Incomplete { .. } => ItemError::NotProvisioned {
                    reason: e.to_string(),
                },
                other => ItemError::Provisioning {
                    reason: other.to_string(),
                },
            })
    }

    /// Opened per operation, so the rollback check runs every time rather than once at unlock.
    fn with_store<T>(
        &self,
        path: &str,
        storage: Arc<dyn DeviceAnchorStorage>,
        account_id: &[u8],
        body: impl FnOnce(&mut OpenVault<'_>) -> Result<T, VaultError>,
    ) -> Result<T, ItemError> {
        let anchor = crate::anchor::load(storage).map_err(|e| ItemError::Store {
            reason: e.to_string(),
        })?;
        let mut store = self
            .open_store_at(std::path::Path::new(path), anchor)
            .map_err(|e| ItemError::Store {
                reason: e.to_string(),
            })?;
        let vault_id = only_vault(&store)?;
        let p = self.load_provisioning_from(&store, account_id, &vault_id)?;
        let mut vault = OpenVault::new(
            &mut store,
            vault_id,
            p.vault_key_epoch,
            p.sealed_vault_key,
            &p.account,
            &p.autofill_key,
        );
        body(&mut vault).map_err(|e| ItemError::Vault {
            reason: e.to_string(),
        })
    }

    fn detail_from(item_id: &str, item: &Item) -> ItemDetail {
        ItemDetail {
            item_id: item_id.to_owned(),
            kind: item.kind().tag().to_owned(),
            fields: item
                .fields()
                .map(|field| {
                    let name = field.name().as_str().to_owned();
                    ItemField {
                        concealed: is_concealed(&name),
                        // Lossy: a non-UTF-8 field is damage, not a reason to hide the item.
                        value: String::from_utf8_lossy(field.value()).into_owned(),
                        name,
                    }
                })
                .collect(),
        }
    }
}

#[uniffi::export]
impl MobileVault {
    /// Signup: builds §2.2's hierarchy for this account and vault, all of it kept in `core`.
    #[allow(clippy::needless_pass_by_value)]
    pub fn provision_account(
        &self,
        path: String,
        storage: Arc<dyn DeviceAnchorStorage>,
        account_id: Vec<u8>,
    ) -> Result<(), ItemError> {
        let anchor = crate::anchor::load(storage).map_err(|e| ItemError::Store {
            reason: e.to_string(),
        })?;
        let mut store = self
            .open_store_at(std::path::Path::new(&path), anchor)
            .map_err(|e| ItemError::Store {
                reason: e.to_string(),
            })?;
        self.provision_first_vault(&mut store, &account_id)
            .map(|_| ())
            .map_err(|e| ItemError::Provisioning {
                reason: e.to_string(),
            })
    }

    #[allow(clippy::needless_pass_by_value)]
    pub fn is_provisioned(
        &self,
        path: String,
        storage: Arc<dyn DeviceAnchorStorage>,
    ) -> Result<bool, ItemError> {
        let anchor = crate::anchor::load(storage).map_err(|e| ItemError::Store {
            reason: e.to_string(),
        })?;
        let store = self
            .open_store_at(std::path::Path::new(&path), anchor)
            .map_err(|e| ItemError::Store {
                reason: e.to_string(),
            })?;
        Ok(!chiavora_core::provision::vault_ids(&store)
            .map_err(|e| ItemError::Store {
                reason: e.to_string(),
            })?
            .is_empty())
    }

    #[allow(clippy::needless_pass_by_value)]
    pub fn list_items(
        &self,
        path: String,
        storage: Arc<dyn DeviceAnchorStorage>,
        account_id: Vec<u8>,
    ) -> Result<Vec<ItemSummary>, ItemError> {
        self.with_store(&path, storage, &account_id, |vault| {
            Ok(vault
                .list()?
                .into_iter()
                .map(|row| ItemSummary {
                    item_id: hex(&row.item_id),
                    version: row.version,
                    kind: row.kind.tag().to_owned(),
                    title: row.title,
                    username: row.username,
                })
                .collect())
        })
    }

    #[allow(clippy::needless_pass_by_value)]
    pub fn read_item(
        &self,
        path: String,
        storage: Arc<dyn DeviceAnchorStorage>,
        account_id: Vec<u8>,
        item_id: String,
    ) -> Result<ItemDetail, ItemError> {
        let raw = unhex(&item_id)?;
        let item = self.with_store(&path, storage, &account_id, |vault| vault.read(&raw))?;
        Ok(Self::detail_from(&item_id, &item))
    }

    #[allow(clippy::needless_pass_by_value)]
    pub fn create_item(
        &self,
        path: String,
        storage: Arc<dyn DeviceAnchorStorage>,
        account_id: Vec<u8>,
        kind: String,
        fields: Vec<ItemField>,
    ) -> Result<String, ItemError> {
        let kind = kind_from(&kind)?;
        let item = item_from(kind, &fields)?;
        let id = self.with_store(&path, storage, &account_id, |vault| {
            let id = chiavora_core::vault::new_item_id()?;
            vault.create(&id, kind, &item)?;
            Ok(id)
        })?;
        Ok(hex(&id))
    }

    // Flat arguments: a `uniffi::Record` would put field values in a Kotlin data class.
    #[allow(clippy::needless_pass_by_value, clippy::too_many_arguments)]
    pub fn update_item(
        &self,
        path: String,
        storage: Arc<dyn DeviceAnchorStorage>,
        account_id: Vec<u8>,
        item_id: String,
        kind: String,
        fields: Vec<ItemField>,
    ) -> Result<u64, ItemError> {
        let raw = unhex(&item_id)?;
        let kind = kind_from(&kind)?;
        let item = item_from(kind, &fields)?;
        self.with_store(&path, storage, &account_id, |vault| {
            vault.update(&raw, kind, &item)
        })
    }

    #[allow(clippy::needless_pass_by_value)]
    pub fn delete_item(
        &self,
        path: String,
        storage: Arc<dyn DeviceAnchorStorage>,
        account_id: Vec<u8>,
        item_id: String,
    ) -> Result<(), ItemError> {
        let raw = unhex(&item_id)?;
        self.with_store(&path, storage, &account_id, |vault| vault.delete(&raw))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips() {
        let bytes = vec![0x00, 0x0f, 0xa5, 0xff];
        assert_eq!(hex(&bytes), "000fa5ff");
        assert_eq!(unhex("000fa5ff").unwrap(), bytes);
    }

    #[test]
    fn a_malformed_identifier_is_named_rather_than_truncated() {
        assert!(unhex("abc").is_err(), "an odd digit count is refused");
        assert!(unhex("zz").is_err(), "a non-hex digit is refused");
    }

    #[test]
    fn an_unrecognised_field_is_concealed() {
        assert!(is_concealed("password"));
        assert!(is_concealed("recoveryCodeFromSomeFutureItemKind"));
        assert!(!is_concealed("title"));
        assert!(!is_concealed("username"));
    }

    #[test]
    fn an_unknown_kind_is_refused_by_name() {
        assert!(kind_from("login").is_ok());
        assert!(matches!(
            kind_from("passport"),
            Err(ItemError::UnknownKind { .. })
        ));
    }
}
