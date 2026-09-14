//! The two ways in are separate functions because they prove different things.

use zeroize::Zeroizing;

use crate::derive::{derive_muk, derive_root_key, AccountIdentifiers, DeriveError, KdfParams};
use crate::device::{muk_from_keystore, DeviceKeyError};
use crate::secret::{
    kind::{AccountPassword, Muk, SecretKeyMaterial},
    Secret,
};

/// No accessor: a new capability is a method here, so the key stays in `core`.
pub struct UnlockedVault {
    muk: Secret<Muk>,
}

impl core::fmt::Debug for UnlockedVault {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("UnlockedVault(<locked>)")
    }
}

impl UnlockedVault {
    /// There is no wrong-password error: a wrong password derives a MUK that
    /// opens nothing, which surfaces when the store's metadata MAC fails.
    /// Never retry a failed derivation weaker.
    pub fn from_secrets(
        password: &Secret<AccountPassword>,
        secret_key: &Secret<SecretKeyMaterial>,
        ids: AccountIdentifiers<'_>,
        params: KdfParams,
    ) -> Result<Self, DeriveError> {
        let root_key = derive_root_key(password, secret_key, ids, params)?;
        Ok(Self {
            muk: derive_muk(&root_key)?,
        })
    }

    pub fn from_stored_muk(bytes: Zeroizing<Vec<u8>>) -> Result<Self, DeviceKeyError> {
        Ok(Self {
            muk: muk_from_keystore(bytes)?,
        })
    }

    pub fn open_store(
        &self,
        path: &std::path::Path,
        anchor: Box<dyn crate::store::RollbackAnchor>,
    ) -> Result<crate::store::Store, crate::store::StoreError> {
        crate::store::Store::open(path, &self.muk, anchor)
    }

    /// Crate-private so that only [`crate::anchor::restore_from_older_backup`], which requires
    /// the password, can rewind a vault.
    pub(crate) fn open_store_reanchoring(
        &self,
        path: &std::path::Path,
        anchor: Box<dyn crate::store::RollbackAnchor>,
    ) -> Result<crate::store::Store, crate::store::StoreError> {
        crate::store::Store::open_with_policy(
            path,
            &self.muk,
            anchor,
            crate::store::RewindPolicy::AcceptAndReanchor,
        )
    }

    /// The MUK's length, the only thing observable about the key.
    #[must_use]
    pub fn muk_len(&self) -> usize {
        self.muk.expose().len()
    }
}

/// Derives from the secrets rather than reading an [`UnlockedVault`], so a vault never gives
/// up its key (§2.4).
pub fn muk_for_device_wrapping(
    password: &Secret<AccountPassword>,
    secret_key: &Secret<SecretKeyMaterial>,
    ids: AccountIdentifiers<'_>,
    params: KdfParams,
) -> Result<Zeroizing<Vec<u8>>, DeriveError> {
    let root_key = derive_root_key(password, secret_key, ids, params)?;
    let muk = derive_muk(&root_key)?;
    Ok(Zeroizing::new(muk.expose().to_vec()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::UnlockedVault;
    use crate::derive::{AccountIdentifiers, KdfParams, I4_FLOOR_ITERATIONS, I4_FLOOR_MEMORY_KIB};
    use crate::entry::{accept, PasswordField, SecretKeyField};
    use zeroize::Zeroizing;

    fn ids() -> ([u8; 16], [u8; 32]) {
        ([0x1D; 16], [0x5A; 32])
    }

    fn floor() -> KdfParams {
        KdfParams::new(I4_FLOOR_MEMORY_KIB, I4_FLOOR_ITERATIONS).unwrap()
    }

    fn unlock_with(password: &[u8]) -> UnlockedVault {
        let (account_id, account_salt) = ids();
        UnlockedVault::from_secrets(
            &accept::<PasswordField>(password.to_vec()).unwrap(),
            &accept::<SecretKeyField>(b"CHV1-0000-0000-0000-0000-0000-0000-00XV".to_vec()).unwrap(),
            AccountIdentifiers {
                account_id: &account_id,
                account_salt: &account_salt,
            },
            floor(),
        )
        .expect("the floor parameters allocate in a test")
    }

    #[test]
    fn the_two_secrets_produce_an_unlocked_vault() {
        assert_eq!(unlock_with(b"correct horse battery staple").muk_len(), 32);
    }

    #[test]
    fn a_stored_muk_of_the_wrong_length_is_refused() {
        // R1: refused, not padded.
        assert!(UnlockedVault::from_stored_muk(Zeroizing::new(vec![0x4D; 31])).is_err());
        assert!(UnlockedVault::from_stored_muk(Zeroizing::new(vec![0x4D; 32])).is_ok());
    }

    #[test]
    fn the_debug_of_an_unlocked_vault_says_nothing() {
        let vault = unlock_with(b"correct horse battery staple");
        let rendered = format!("{vault:?}");
        assert_eq!(rendered, "UnlockedVault(<locked>)");
        assert!(!rendered.contains("4d") && !rendered.contains("77"));
    }

    #[test]
    fn the_wrapping_export_agrees_with_the_vault_it_would_unlock() {
        let (account_id, account_salt) = ids();
        let bytes = super::muk_for_device_wrapping(
            &accept::<PasswordField>(b"correct horse battery staple".to_vec()).unwrap(),
            &accept::<SecretKeyField>(b"CHV1-0000-0000-0000-0000-0000-0000-00XV".to_vec()).unwrap(),
            AccountIdentifiers {
                account_id: &account_id,
                account_salt: &account_salt,
            },
            floor(),
        )
        .unwrap();
        assert_eq!(bytes.len(), 32);
        assert_eq!(
            UnlockedVault::from_stored_muk(bytes).unwrap().muk_len(),
            unlock_with(b"correct horse battery staple").muk_len()
        );
    }

    #[test]
    fn a_different_password_unlocks_a_different_vault() {
        // There is no wrong-password error, so the test compares the stores.
        let dir = std::env::temp_dir().join(format!(
            "chiavora-unlock-{}-{}.sqlite",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default()
        ));
        let _ = std::fs::remove_file(&dir);

        let right = unlock_with(b"correct horse battery staple");
        {
            let mut store = right
                .open_store(&dir, Box::new(crate::store::Unanchored))
                .expect("a fresh store opens");
            store.put_raw(b"vault-1", b"item", 1, b"payload").unwrap();
        }

        let wrong = unlock_with(b"correct horse battery stapl");
        let refused = wrong.open_store(&dir, Box::new(crate::store::Unanchored));
        assert!(
            refused.is_err(),
            "a wrong password opened the store; the MUK is not reaching the Store Key"
        );

        let _ = std::fs::remove_file(&dir);
    }
}
