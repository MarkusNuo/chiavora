//! The one AEAD nonce source (I2): every nonce is a fresh CSPRNG draw, never a counter.

use core::fmt;

/// Length of an XChaCha20-Poly1305 nonce, in bytes (192 bits, §2.2).
pub const NONCE_LEN: usize = 24;

/// The bytes of a nonce, whatever its provenance. It carries no provenance, so it is
/// not constructible from raw bytes and no encrypt path accepts it.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Nonce([u8; NONCE_LEN]);

impl Nonce {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; NONCE_LEN] {
        &self.0
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FreshNonce(Nonce);

impl FreshNonce {
    pub fn generate() -> Result<Self, NonceError> {
        let mut bytes = [0_u8; NONCE_LEN];
        getrandom::fill(&mut bytes).map_err(|_| NonceError::Csprng)?;
        Ok(Self(Nonce(bytes)))
    }

    #[must_use]
    pub const fn as_nonce(&self) -> &Nonce {
        &self.0
    }
}

/// For the decrypt path only; there is no conversion to [`FreshNonce`].
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct StoredNonce(Nonce);

impl StoredNonce {
    /// Safe on any bytes: wrong ones fail the AEAD tag check.
    #[must_use]
    pub const fn from_stored_bytes(bytes: [u8; NONCE_LEN]) -> Self {
        Self(Nonce(bytes))
    }

    #[must_use]
    pub const fn as_nonce(&self) -> &Nonce {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonceError {
    /// Refuse the operation; do not substitute.
    Csprng,
}

impl fmt::Display for NonceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Csprng => f.write_str("the platform CSPRNG failed to produce a nonce"),
        }
    }
}

impl core::error::Error for NonceError {}

impl fmt::Debug for Nonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Not secret, but the bytes add nothing to a log.
        write!(f, "Nonce({NONCE_LEN} bytes)")
    }
}

impl fmt::Debug for FreshNonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FreshNonce({NONCE_LEN} bytes)")
    }
}

impl fmt::Debug for StoredNonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "StoredNonce({NONCE_LEN} bytes)")
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{FreshNonce, StoredNonce, NONCE_LEN};

    fn code_without_tests() -> &'static str {
        let source = include_str!("nonce.rs");
        let marker = concat!("#[cfg(", "test)]");
        source.split(marker).next().unwrap_or(source)
    }

    #[test]
    fn i2_generate_is_the_only_fresh_nonce_source() {
        let draws = code_without_tests().matches("getrandom::fill").count();
        assert_eq!(
            draws, 1,
            "I2: expected exactly one CSPRNG call site, found {draws}"
        );
    }

    #[test]
    fn i2_no_counter_or_persistent_state_appears_in_this_module() {
        let code = code_without_tests();
        assert!(
            !code.contains("static mut"),
            "I2: a mutable static is nonce state"
        );
        assert!(
            !code.contains("AtomicU"),
            "I2: an atomic counter is nonce state"
        );
        assert!(
            !code.contains("Cell<"),
            "I2: interior mutability is nonce state"
        );
    }

    #[test]
    fn i2_no_path_converts_a_stored_nonce_into_a_fresh_one() {
        let code = code_without_tests();
        assert!(
            !code.contains("impl From<StoredNonce>"),
            "I2: a From<StoredNonce> impl would let a stored nonce reach encrypt"
        );
        let constructions = code.matches("Self(Nonce(bytes))").count();
        assert_eq!(
            constructions, 2,
            "I2: expected exactly two Nonce constructions — generate() and \
             from_stored_bytes() — found {constructions}"
        );
    }

    #[test]
    fn generated_nonces_are_the_right_length_and_do_not_repeat() {
        let first = FreshNonce::generate().unwrap();
        assert_eq!(first.as_nonce().as_bytes().len(), NONCE_LEN);

        let mut seen = std::collections::HashSet::new();
        for _ in 0_u16..1_000 {
            let nonce = FreshNonce::generate().unwrap();
            assert!(seen.insert(*nonce.as_nonce().as_bytes()), "nonce repeated");
        }
    }

    #[test]
    fn a_stored_nonce_round_trips_for_the_decrypt_path() {
        let fresh = FreshNonce::generate().unwrap();
        let stored = StoredNonce::from_stored_bytes(*fresh.as_nonce().as_bytes());
        assert_eq!(stored.as_nonce(), fresh.as_nonce());
    }

    #[test]
    fn debug_shows_only_the_length_and_the_provenance() {
        let fresh = FreshNonce::generate().unwrap();
        assert_eq!(format!("{fresh:?}"), "FreshNonce(24 bytes)");
        assert_eq!(format!("{:?}", fresh.as_nonce()), "Nonce(24 bytes)");
        let stored = StoredNonce::from_stored_bytes([0_u8; NONCE_LEN]);
        assert_eq!(format!("{stored:?}"), "StoredNonce(24 bytes)");
    }
}
