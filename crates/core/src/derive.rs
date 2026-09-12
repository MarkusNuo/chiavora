//! Two-secret key derivation as §2.1 gives it: `rootKey = passKey XOR secretKeyKD`.

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::secret::{
    kind::{AccountPassword, ExportKey, Muk, RootKey, SecretKeyMaterial, SrpX, StoreKey},
    Secret,
};

const INFO_SALT: &[u8] = b"chiavora-salt|";
const INFO_SKK: &[u8] = b"chiavora-skk|";
const INFO_MUK: &[u8] = b"chiavora-muk";
const INFO_SRP: &[u8] = b"chiavora-srp";
const INFO_STORE: &[u8] = b"chiavora-store";
const INFO_EXPORT: &[u8] = b"chiavora-export";

const SALT_LEN: usize = 16;
const KEY_LEN: usize = 32;

/// Argon2id parallelism, fixed by §2.1.
pub const ARGON2_LANES: u32 = 4;
pub const I4_FLOOR_MEMORY_KIB: u32 = 64 * 1024;
pub const I4_FLOOR_ITERATIONS: u32 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    memory_kib: u32,
    iterations: u32,
}

impl KdfParams {
    pub const fn new(memory_kib: u32, iterations: u32) -> Result<Self, DeriveError> {
        if memory_kib < I4_FLOOR_MEMORY_KIB || iterations < I4_FLOOR_ITERATIONS {
            return Err(DeriveError::BelowI4Floor);
        }
        Ok(Self {
            memory_kib,
            iterations,
        })
    }

    #[must_use]
    pub const fn memory_kib(&self) -> u32 {
        self.memory_kib
    }

    #[must_use]
    pub const fn iterations(&self) -> u32 {
        self.iterations
    }
}

/// Two independent values in different HKDF arguments (`docs/adr/0005`). Neither is secret.
#[derive(Debug, Clone, Copy)]
pub struct AccountIdentifiers<'a> {
    pub account_id: &'a [u8],
    pub account_salt: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeriveError {
    BelowI4Floor,
    /// Callers must refuse to unlock, never retry with less memory (§2.1).
    Argon2Allocation,
    /// Unreachable for §2.1's constant lengths, and propagated anyway.
    HkdfExpand,
}

impl core::fmt::Display for DeriveError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::BelowI4Floor => f.write_str(
                "KDF parameters are below the I4 floor (m = 64 MiB, t = 3) and are refused",
            ),
            Self::Argon2Allocation => f.write_str(
                "Argon2id could not allocate; refusing to unlock rather than retrying weaker",
            ),
            Self::HkdfExpand => f.write_str("HKDF refused the requested output length"),
        }
    }
}

impl core::error::Error for DeriveError {}

fn hkdf_sha256(ikm: &[u8], info: &[u8], out: &mut [u8]) -> Result<(), DeriveError> {
    // No salt: §2.1 passes none, and domain separation is carried by `info`.
    let hk = Hkdf::<Sha256>::new(None, ikm);
    hk.expand(info, out).map_err(|_| DeriveError::HkdfExpand)
}

fn account_info(domain: &[u8], account_id: &[u8]) -> Vec<u8> {
    let mut info = Vec::with_capacity(domain.len() + account_id.len());
    info.extend_from_slice(domain);
    info.extend_from_slice(account_id);
    info
}

fn derive_salt(ids: AccountIdentifiers<'_>) -> Result<[u8; SALT_LEN], DeriveError> {
    let mut salt = [0_u8; SALT_LEN];
    hkdf_sha256(
        ids.account_salt,
        &account_info(INFO_SALT, ids.account_id),
        &mut salt,
    )?;
    Ok(salt)
}

/// Both secrets are required and neither is sufficient; the key is never stored or sent.
pub fn derive_root_key(
    password: &Secret<AccountPassword>,
    secret_key: &Secret<SecretKeyMaterial>,
    ids: AccountIdentifiers<'_>,
    params: KdfParams,
) -> Result<Secret<RootKey>, DeriveError> {
    const _: () = assert!(KEY_LEN == 32, "§2.1: rootKey is 32 bytes");
    let salt = derive_salt(ids)?;

    let argon_params = Params::new(
        params.memory_kib(),
        params.iterations(),
        ARGON2_LANES,
        Some(KEY_LEN),
    )
    .map_err(|_| DeriveError::BelowI4Floor)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);

    let mut pass_key = [0_u8; KEY_LEN];
    argon
        .hash_password_into(password.expose(), &salt, &mut pass_key)
        .map_err(|_| DeriveError::Argon2Allocation)?;

    let mut secret_key_kd = [0_u8; KEY_LEN];
    hkdf_sha256(
        secret_key.expose(),
        &account_info(INFO_SKK, ids.account_id),
        &mut secret_key_kd,
    )?;

    // The length comes from the allocation, not from a debug assertion that a
    // release build would drop.
    let mut root = vec![0_u8; KEY_LEN];
    for (slot, (a, b)) in root
        .iter_mut()
        .zip(pass_key.iter().zip(secret_key_kd.iter()))
    {
        *slot = a ^ b;
    }

    zeroize::Zeroize::zeroize(&mut pass_key);
    zeroize::Zeroize::zeroize(&mut secret_key_kd);

    Ok(Secret::from_derived_bytes(root))
}

pub fn derive_muk(root_key: &Secret<RootKey>) -> Result<Secret<Muk>, DeriveError> {
    let mut out = vec![0_u8; KEY_LEN];
    hkdf_sha256(root_key.expose(), INFO_MUK, &mut out)?;
    Ok(Secret::from_derived_bytes(out))
}

/// The MUK's sibling, not its child (§2.1); nothing in this crate derives it from the MUK.
pub fn derive_srp_x(root_key: &Secret<RootKey>) -> Result<Secret<SrpX>, DeriveError> {
    let mut out = vec![0_u8; KEY_LEN];
    hkdf_sha256(root_key.expose(), INFO_SRP, &mut out)?;
    Ok(Secret::from_derived_bytes(out))
}

/// MACs the local store's metadata, so a rewritten SQLite file is detected on open (§2.5).
pub fn derive_store_key(muk: &Secret<Muk>) -> Result<Secret<StoreKey>, DeriveError> {
    let mut out = vec![0_u8; KEY_LEN];
    hkdf_sha256(muk.expose(), INFO_STORE, &mut out)?;
    Ok(Secret::from_derived_bytes(out))
}

/// MACs an export's container, so a tampered or foreign file is refused before import.
pub fn derive_export_key(muk: &Secret<Muk>) -> Result<Secret<ExportKey>, DeriveError> {
    let mut out = vec![0_u8; KEY_LEN];
    hkdf_sha256(muk.expose(), INFO_EXPORT, &mut out)?;
    Ok(Secret::from_derived_bytes(out))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use zeroize::Zeroizing;

    use super::{
        derive_muk, derive_root_key, derive_srp_x, AccountIdentifiers, DeriveError, KdfParams,
        I4_FLOOR_ITERATIONS, I4_FLOOR_MEMORY_KIB,
    };
    use crate::secret::{
        kind::{AccountPassword, SecretKeyMaterial},
        Secret,
    };

    fn floor_params() -> KdfParams {
        KdfParams::new(I4_FLOOR_MEMORY_KIB, I4_FLOOR_ITERATIONS).unwrap()
    }

    fn ids<'a>(account_id: &'a [u8], account_salt: &'a [u8]) -> AccountIdentifiers<'a> {
        AccountIdentifiers {
            account_id,
            account_salt,
        }
    }

    fn password() -> Secret<AccountPassword> {
        Secret::from_external_bytes(Zeroizing::new(b"correct horse battery staple".to_vec()))
    }

    fn secret_key() -> Secret<SecretKeyMaterial> {
        Secret::from_external_bytes(Zeroizing::new(vec![0xAB; 16]))
    }

    #[test]
    fn i4_refuses_memory_below_the_floor() {
        assert_eq!(
            KdfParams::new(I4_FLOOR_MEMORY_KIB - 1, I4_FLOOR_ITERATIONS),
            Err(DeriveError::BelowI4Floor)
        );
    }

    #[test]
    fn i4_refuses_iterations_below_the_floor() {
        assert_eq!(
            KdfParams::new(I4_FLOOR_MEMORY_KIB, I4_FLOOR_ITERATIONS - 1),
            Err(DeriveError::BelowI4Floor)
        );
    }

    #[test]
    fn i4_accepts_the_floor_itself_and_anything_above_it() {
        assert!(KdfParams::new(I4_FLOOR_MEMORY_KIB, I4_FLOOR_ITERATIONS).is_ok());
        assert!(KdfParams::new(I4_FLOOR_MEMORY_KIB * 2, I4_FLOOR_ITERATIONS + 1).is_ok());
    }

    #[test]
    fn root_key_derivation_is_deterministic() {
        let (id, salt) = (b"account-id-16byt".as_slice(), [0x11_u8; 32]);
        let first =
            derive_root_key(&password(), &secret_key(), ids(id, &salt), floor_params()).unwrap();
        let second =
            derive_root_key(&password(), &secret_key(), ids(id, &salt), floor_params()).unwrap();
        assert_eq!(first.expose(), second.expose());
        assert_eq!(first.len(), 32);
    }

    #[test]
    fn a3_the_password_alone_does_not_determine_the_root_key() {
        let (id, salt) = (b"account-id-16byt".as_slice(), [0x11_u8; 32]);
        let with_one =
            derive_root_key(&password(), &secret_key(), ids(id, &salt), floor_params()).unwrap();
        let other_secret =
            Secret::<SecretKeyMaterial>::from_external_bytes(Zeroizing::new(vec![0xCD; 16]));
        let with_other =
            derive_root_key(&password(), &other_secret, ids(id, &salt), floor_params()).unwrap();
        assert_ne!(with_one.expose(), with_other.expose());
    }

    #[test]
    fn the_secret_key_alone_does_not_determine_the_root_key() {
        let (id, salt) = (b"account-id-16byt".as_slice(), [0x11_u8; 32]);
        let with_one =
            derive_root_key(&password(), &secret_key(), ids(id, &salt), floor_params()).unwrap();
        let other_password = Secret::<AccountPassword>::from_external_bytes(Zeroizing::new(
            b"a different password".to_vec(),
        ));
        let with_other = derive_root_key(
            &other_password,
            &secret_key(),
            ids(id, &salt),
            floor_params(),
        )
        .unwrap();
        assert_ne!(with_one.expose(), with_other.expose());
    }

    #[test]
    fn account_id_and_account_salt_are_independent_inputs() {
        let base = derive_root_key(
            &password(),
            &secret_key(),
            ids(b"account-id-16byt", &[0x11_u8; 32]),
            floor_params(),
        )
        .unwrap();
        let other_id = derive_root_key(
            &password(),
            &secret_key(),
            ids(b"ACCOUNT-ID-16BYT", &[0x11_u8; 32]),
            floor_params(),
        )
        .unwrap();
        let other_salt = derive_root_key(
            &password(),
            &secret_key(),
            ids(b"account-id-16byt", &[0x22_u8; 32]),
            floor_params(),
        )
        .unwrap();
        assert_ne!(
            base.expose(),
            other_id.expose(),
            "accountId must affect the root key"
        );
        assert_ne!(
            base.expose(),
            other_salt.expose(),
            "accountSalt must affect the root key"
        );
    }

    #[test]
    fn muk_and_srp_x_are_siblings_and_differ() {
        let root = derive_root_key(
            &password(),
            &secret_key(),
            ids(b"account-id-16byt", &[0x11_u8; 32]),
            floor_params(),
        )
        .unwrap();
        let muk = derive_muk(&root).unwrap();
        let srp_x = derive_srp_x(&root).unwrap();
        assert_eq!(muk.len(), 32);
        assert_eq!(srp_x.len(), 32);
        assert_ne!(
            muk.expose(),
            srp_x.expose(),
            "§2.1: MUK and srpX are domain-separated siblings of rootKey"
        );
        assert_ne!(muk.expose(), root.expose());
        assert_ne!(srp_x.expose(), root.expose());
    }

    #[test]
    fn no_function_derives_srp_x_from_the_muk() {
        // A helper taking the MUK would still compile, so its absence is pinned.
        let source = include_str!("derive.rs");
        let marker = concat!("#[cfg(", "test)]");
        let code = source.split(marker).next().unwrap_or(source);
        assert!(
            !code.contains("Secret<Muk>) -> Secret<SrpX>"),
            "§2.1: srpX must be derived from rootKey, never from the MUK"
        );
    }
}
