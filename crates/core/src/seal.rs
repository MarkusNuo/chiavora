//! HPKE sealing of the Vault Key to an account public key (RFC 9180, `docs/adr/0009`).

use zeroize::Zeroizing;

use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable};

use crate::aad::{self, AadError, AadFields};
use crate::csprng::{self, CsprngError};
use crate::secret::{kind::VaultKey, Secret};

/// Fixed by `docs/adr/0009`.
type Kem = X25519HkdfSha256;
type Kdf = HkdfSha256;
type Aead = ChaCha20Poly1305;

/// Length of a Vault Key, and of an X25519 scalar or point.
pub const VAULT_KEY_LEN: usize = 32;

/// No variant carries key material or ciphertext.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealError {
    Csprng,
    /// Unreachable for the fields built here.
    Aad(AadError),
    Seal,
    /// Wrong recipient, wrong context or damaged bytes, deliberately not distinguished.
    Open,
    BadKeyLength,
    NotAVaultKey,
}

impl core::fmt::Display for SealError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Csprng => f.write_str("the platform CSPRNG failed; refusing to seal"),
            Self::Aad(e) => write!(f, "{e}"),
            Self::Seal => f.write_str("HPKE refused to seal the Vault Key"),
            Self::Open => f.write_str("the sealed Vault Key did not open"),
            Self::BadKeyLength => f.write_str("a key was not 32 bytes"),
            Self::NotAVaultKey => f.write_str("the opened value was not a Vault Key"),
        }
    }
}

impl core::error::Error for SealError {}

impl From<CsprngError> for SealError {
    fn from(_: CsprngError) -> Self {
        Self::Csprng
    }
}

impl From<AadError> for SealError {
    fn from(e: AadError) -> Self {
        Self::Aad(e)
    }
}

pub struct AccountKeypair {
    private: Zeroizing<[u8; VAULT_KEY_LEN]>,
    public: [u8; VAULT_KEY_LEN],
}

impl core::fmt::Debug for AccountKeypair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The public half is not secret, but printing it invites printing both.
        f.write_str("AccountKeypair(<private>, <public>)")
    }
}

impl AccountKeypair {
    #[must_use]
    pub const fn public(&self) -> &[u8; VAULT_KEY_LEN] {
        &self.public
    }

    #[must_use]
    pub const fn private_for_wrapping(&self) -> &Zeroizing<[u8; VAULT_KEY_LEN]> {
        &self.private
    }

    pub fn from_private(private: &[u8]) -> Result<Self, SealError> {
        let bytes: [u8; VAULT_KEY_LEN] = private.try_into().map_err(|_| SealError::BadKeyLength)?;
        let sk = <Kem as KemTrait>::PrivateKey::from_bytes(&bytes)
            .map_err(|_| SealError::BadKeyLength)?;
        let pk = <Kem as KemTrait>::sk_to_pk(&sk);
        Ok(Self {
            private: Zeroizing::new(bytes),
            public: to_array(&pk.to_bytes())?,
        })
    }

    pub fn generate() -> Result<Self, SealError> {
        let mut ikm = Zeroizing::new([0_u8; VAULT_KEY_LEN]);
        csprng::fill_bytes(ikm.as_mut_slice())?;
        // `DeriveKeyPair` (RFC 9180 §7.1.3) takes keying material, not an RNG.
        let (sk, pk) = <Kem as KemTrait>::derive_keypair(ikm.as_slice());
        Ok(Self {
            private: Zeroizing::new(to_array(&sk.to_bytes())?),
            public: to_array(&pk.to_bytes())?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedVaultKey {
    encapsulated: Vec<u8>,
    ciphertext: Vec<u8>,
}

impl SealedVaultKey {
    #[must_use]
    pub fn encapsulated(&self) -> &[u8] {
        &self.encapsulated
    }

    #[must_use]
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// Rebuilds from stored parts; they are checked when the seal is opened.
    #[must_use]
    pub const fn from_stored_parts(encapsulated: Vec<u8>, ciphertext: Vec<u8>) -> Self {
        Self {
            encapsulated,
            ciphertext,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SealContext<'a> {
    pub vault_id: &'a [u8],
    pub vault_key_epoch: u32,
    pub recipient_public_key: &'a [u8],
}

impl SealContext<'_> {
    /// The `info` string, from the one canonical encoder (R2).
    fn info(&self) -> Result<Vec<u8>, SealError> {
        Ok(aad::encode(&AadFields::SealedVaultKey {
            vault_id: self.vault_id.to_vec(),
            vault_key_epoch: self.vault_key_epoch,
            recipient_public_key: self.recipient_public_key.to_vec(),
        })?)
    }
}

pub fn generate_vault_key() -> Result<Secret<VaultKey>, SealError> {
    let mut bytes = vec![0_u8; VAULT_KEY_LEN];
    csprng::fill_bytes(&mut bytes)?;
    Ok(Secret::<VaultKey>::from_derived_bytes(bytes))
}

pub fn seal_vault_key(
    vault_key: &Secret<VaultKey>,
    ctx: SealContext<'_>,
) -> Result<SealedVaultKey, SealError> {
    if vault_key.expose().len() != VAULT_KEY_LEN {
        return Err(SealError::BadKeyLength);
    }
    let info = ctx.info()?;
    let pk = <Kem as KemTrait>::PublicKey::from_bytes(ctx.recipient_public_key)
        .map_err(|_| SealError::BadKeyLength)?;

    let mut rng = CoreRng::new();
    // The AAD is empty on purpose: everything the seal binds is in `info`.
    let (encapped, ciphertext) = hpke::single_shot_seal::<Aead, Kdf, Kem, _>(
        &OpModeS::Base,
        &pk,
        &info,
        vault_key.expose(),
        &[],
        &mut rng,
    )
    .map_err(|_| SealError::Seal)?;
    rng.into_result()?;

    Ok(SealedVaultKey {
        encapsulated: encapped.to_bytes().to_vec(),
        ciphertext,
    })
}

pub fn open_vault_key(
    sealed: &SealedVaultKey,
    keypair: &AccountKeypair,
    ctx: SealContext<'_>,
) -> Result<Secret<VaultKey>, SealError> {
    let info = ctx.info()?;
    let sk = <Kem as KemTrait>::PrivateKey::from_bytes(keypair.private.as_slice())
        .map_err(|_| SealError::BadKeyLength)?;
    let encapped = <Kem as KemTrait>::EncappedKey::from_bytes(&sealed.encapsulated)
        .map_err(|_| SealError::BadKeyLength)?;

    let opened = hpke::single_shot_open::<Aead, Kdf, Kem>(
        &OpModeR::Base,
        &sk,
        &encapped,
        &info,
        &sealed.ciphertext,
        &[],
    )
    .map_err(|_| SealError::Open)?;

    if opened.len() != VAULT_KEY_LEN {
        return Err(SealError::NotAVaultKey);
    }
    Ok(Secret::<VaultKey>::from_derived_bytes(opened))
}

fn to_array(bytes: &[u8]) -> Result<[u8; VAULT_KEY_LEN], SealError> {
    bytes.try_into().map_err(|_| SealError::BadKeyLength)
}

/// `rand_core`'s `RngCore` over this crate's one CSPRNG call site (R3).
/// `RngCore::fill_bytes` cannot fail, so a CSPRNG failure is recorded and
/// [`Self::into_result`] is checked before a seal is returned; output computed
/// from the zero fill never reaches a caller.
struct CoreRng {
    failed: Option<CsprngError>,
}

impl CoreRng {
    const fn new() -> Self {
        Self { failed: None }
    }

    fn into_result(self) -> Result<(), SealError> {
        self.failed.map_or(Ok(()), |e| Err(e.into()))
    }
}

impl hpke::rand_core::RngCore for CoreRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0_u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }

    fn next_u64(&mut self) -> u64 {
        let mut b = [0_u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        // R1: not absorbed; the failure is recorded and checked before any seal is returned.
        if let Err(e) = csprng::fill_bytes(dest) {
            self.failed.get_or_insert(e);
            dest.fill(0);
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), hpke::rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl hpke::rand_core::CryptoRng for CoreRng {}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn ctx<'a>(vault: &'a [u8], epoch: u32, pk: &'a [u8]) -> SealContext<'a> {
        SealContext {
            vault_id: vault,
            vault_key_epoch: epoch,
            recipient_public_key: pk,
        }
    }

    #[test]
    fn a_vault_key_seals_to_its_own_public_key_and_opens_again() {
        let account = AccountKeypair::generate().unwrap();
        let vk = generate_vault_key().unwrap();
        let c = ctx(b"vault-1", 0, account.public());

        let sealed = seal_vault_key(&vk, c).unwrap();
        let opened = open_vault_key(&sealed, &account, c).unwrap();
        assert_eq!(opened.expose(), vk.expose());
    }

    #[test]
    fn the_seal_is_not_the_key_and_is_not_the_plaintext() {
        let account = AccountKeypair::generate().unwrap();
        let vk = generate_vault_key().unwrap();
        let sealed = seal_vault_key(&vk, ctx(b"v", 0, account.public())).unwrap();

        assert_ne!(sealed.ciphertext(), vk.expose());
        assert_eq!(sealed.encapsulated().len(), VAULT_KEY_LEN);
        assert!(sealed.ciphertext().len() > VAULT_KEY_LEN);
    }

    #[test]
    fn two_seals_of_one_key_differ() {
        let account = AccountKeypair::generate().unwrap();
        let vk = generate_vault_key().unwrap();
        let c = ctx(b"v", 0, account.public());
        assert_ne!(
            seal_vault_key(&vk, c).unwrap().ciphertext(),
            seal_vault_key(&vk, c).unwrap().ciphertext()
        );
    }

    #[test]
    fn a_seal_does_not_open_under_another_vault_id() {
        let account = AccountKeypair::generate().unwrap();
        let vk = generate_vault_key().unwrap();
        let sealed = seal_vault_key(&vk, ctx(b"vault-1", 0, account.public())).unwrap();
        assert!(matches!(
            open_vault_key(&sealed, &account, ctx(b"vault-2", 0, account.public())),
            Err(SealError::Open)
        ));
    }

    #[test]
    fn a_seal_does_not_open_under_another_epoch() {
        let account = AccountKeypair::generate().unwrap();
        let vk = generate_vault_key().unwrap();
        let sealed = seal_vault_key(&vk, ctx(b"v", 7, account.public())).unwrap();
        assert!(matches!(
            open_vault_key(&sealed, &account, ctx(b"v", 8, account.public())),
            Err(SealError::Open)
        ));
    }

    #[test]
    fn a_seal_does_not_open_for_another_member() {
        let alice = AccountKeypair::generate().unwrap();
        let bob = AccountKeypair::generate().unwrap();
        let vk = generate_vault_key().unwrap();
        let sealed = seal_vault_key(&vk, ctx(b"v", 0, alice.public())).unwrap();

        assert!(matches!(
            open_vault_key(&sealed, &bob, ctx(b"v", 0, alice.public())),
            Err(SealError::Open)
        ));
        assert!(matches!(
            open_vault_key(&sealed, &alice, ctx(b"v", 0, bob.public())),
            Err(SealError::Open)
        ));
    }

    #[test]
    fn a_damaged_ciphertext_refuses() {
        let account = AccountKeypair::generate().unwrap();
        let vk = generate_vault_key().unwrap();
        let c = ctx(b"v", 0, account.public());
        let sealed = seal_vault_key(&vk, c).unwrap();

        let mut bytes = sealed.ciphertext().to_vec();
        *bytes.first_mut().expect("a sealed ciphertext is not empty") ^= 1;
        let damaged = SealedVaultKey::from_stored_parts(sealed.encapsulated().to_vec(), bytes);
        assert!(matches!(
            open_vault_key(&damaged, &account, c),
            Err(SealError::Open)
        ));
    }

    #[test]
    fn a_keypair_rebuilt_from_its_private_key_opens_the_same_seals() {
        let account = AccountKeypair::generate().unwrap();
        let vk = generate_vault_key().unwrap();
        let c = ctx(b"v", 0, account.public());
        let sealed = seal_vault_key(&vk, c).unwrap();

        let rebuilt = AccountKeypair::from_private(account.private_for_wrapping().as_slice())
            .expect("a 32-byte private key rebuilds");
        assert_eq!(rebuilt.public(), account.public());
        assert_eq!(
            open_vault_key(&sealed, &rebuilt, c).unwrap().expose(),
            vk.expose()
        );
    }

    #[test]
    fn a_short_key_is_refused_rather_than_padded() {
        let account = AccountKeypair::generate().unwrap();
        assert!(matches!(
            AccountKeypair::from_private(&[0_u8; 31]),
            Err(SealError::BadKeyLength)
        ));
        let vk = Secret::<VaultKey>::from_derived_bytes(vec![0_u8; 16]);
        assert_eq!(
            seal_vault_key(&vk, ctx(b"v", 0, account.public())),
            Err(SealError::BadKeyLength)
        );
        let good = generate_vault_key().unwrap();
        assert_eq!(
            seal_vault_key(&good, ctx(b"v", 0, &[0_u8; 31])),
            Err(SealError::BadKeyLength)
        );
    }

    #[test]
    fn the_info_is_the_canonical_encoder_and_not_a_concatenation() {
        let c = ctx(b"vault-1", 3, &[0x11; 32]);
        let expected = aad::encode(&AadFields::SealedVaultKey {
            vault_id: b"vault-1".to_vec(),
            vault_key_epoch: 3,
            recipient_public_key: vec![0x11; 32],
        })
        .unwrap();
        assert_eq!(c.info().unwrap(), expected);
        assert_eq!(expected.first().copied(), Some(b'C'));
    }

    #[test]
    fn errors_name_the_refusal_and_carry_no_bytes() {
        for e in [
            SealError::Csprng,
            SealError::Seal,
            SealError::Open,
            SealError::BadKeyLength,
            SealError::NotAVaultKey,
        ] {
            let text = e.to_string();
            assert!(!text.is_empty());
            assert!(!text.contains("0x"), "{text}");
        }
    }
}
