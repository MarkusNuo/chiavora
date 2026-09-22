//! A [`Secret`]'s bytes are reachable only through [`Secret::expose`].

use core::fmt;
use core::marker::PhantomData;

use zeroize::Zeroizing;

/// The platform may refuse (a `VirtualLock` quota, a capped `RLIMIT_MEMLOCK`),
/// so the outcome is recorded rather than turned into a failure to unlock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockState {
    Locked,
    /// The buffer is still zeroized on drop.
    Unlocked,
}

pub trait SecretKind: sealed::Sealed {
    const NAME: &'static str;

    /// Human-chosen material is never fingerprinted by [`crate::ffi_guard`], whose registry is
    /// not mlocked, so a hash of the password cannot reach swap.
    const LOW_ENTROPY: bool;
}

/// Only `Secret::from_external_bytes` builds one, and [`Secret::from_derived_bytes`] refuses it.
pub trait ExternalKind: SecretKind {}

/// Disjoint from [`ExternalKind`]: each brand declares exactly one provenance.
pub trait DerivedKind: SecretKind {}

mod sealed {
    pub trait Sealed {}
}

pub mod kind {
    use super::sealed::Sealed;
    use super::{DerivedKind, ExternalKind, SecretKind};

    /// No catch-all arm, so a new provenance fails to compile here.
    #[cfg(test)]
    macro_rules! construct_for_test {
        (ExternalKind, $name:ident, $bytes:expr) => {
            super::Secret::<$name>::from_external_bytes(zeroize::Zeroizing::new($bytes))
        };
        (DerivedKind, $name:ident, $bytes:expr) => {
            super::Secret::<$name>::from_derived_bytes($bytes)
        };
    }

    macro_rules! brand {
        ($(#[doc = $doc:literal] $name:ident => $label:literal, $origin:ident, $low_entropy:literal;)+) => {
            $(
                #[doc = $doc]
                #[derive(Debug, Clone, Copy)]
                pub struct $name;
                impl Sealed for $name {}
                impl SecretKind for $name {
                    const NAME: &'static str = $label;
                    const LOW_ENTROPY: bool = $low_entropy;
                }
                impl $origin for $name {}
            )+

            /// Generated per brand, so a new brand cannot miss its redaction check.
            #[cfg(test)]
            pub(crate) fn assert_every_brand_redacts_debug() {
                let plaintext = b"leak-me-if-you-can";
                $(
                    {
                        let rendered = format!(
                            "{:?}",
                            construct_for_test!($origin, $name, plaintext.to_vec())
                        );
                        assert!(
                            !rendered.contains("leak-me"),
                            "Debug leaked key material for brand {}: {rendered}",
                            <$name as SecretKind>::NAME
                        );
                        assert!(
                            rendered.contains(<$name as SecretKind>::NAME),
                            "Debug for brand {} does not name the brand: {rendered}",
                            <$name as SecretKind>::NAME
                        );
                    }
                )+
            }
        };
    }

    brand! {
        #[doc = "The account password, as the user typed it (§2.1)."]
        AccountPassword => "AccountPassword", ExternalKind, true;
        #[doc = "The 128-bit Secret Key from the Emergency Kit (§2.1)."]
        SecretKeyMaterial => "SecretKey", ExternalKind, false;
        #[doc = "`rootKey`, derived and never stored (§2.1)."]
        RootKey => "RootKey", DerivedKind, false;
        #[doc = "The Master Unlock Key, a domain-separated child of `rootKey` (§2.1)."]
        Muk => "MUK", DerivedKind, false;
        #[doc = "`srpX`, the MUK's sibling and the input to the SRP-6a verifier (§2.1, §2.3)."]
        SrpX => "srpX", DerivedKind, false;
        #[doc = "A Vault Key, which wraps Item Keys and is rotated on member removal (§2.2)."]
        VaultKey => "VaultKey", DerivedKind, false;
        #[doc = "An Item Key, one per item, which encrypts that item's payload (§2.2)."]
        ItemKey => "ItemKey", DerivedKind, false;
        #[doc = "The Autofill Key, which unwraps `login` and `TOTP` Item Keys only (§2.2, §3.3, ADR-0003)."]
        AutofillKey => "AutofillKey", DerivedKind, false;
        #[doc = "The Store Key, a child of the MUK that MACs the local store's metadata so a rewritten SQLite file is detected (§2.5, I6f)."]
        StoreKey => "StoreKey", DerivedKind, false;
        #[doc = "The Export Key, the Store Key's sibling, which MACs a native export's container so a tampered or foreign file is refused."]
        ExportKey => "ExportKey", DerivedKind, false;
        #[doc = "The SRP-6a private exponent `x` = SHA-256(`srpSalt` ‖ `srpX`), never to be substituted for its HKDF input `SrpX` (§2.3)."]
        SrpExponent => "SrpExponent", DerivedKind, false;
        #[doc = "An SRP-6a ephemeral private value, the client's `a` or the server's `b` (RFC 5054 §2.6)."]
        SrpEphemeralSecret => "SrpEphemeralSecret", DerivedKind, false;
        #[doc = "The SRP-6a premaster secret `S`, never used as a key directly (§2.3)."]
        SrpPremasterSecret => "SrpPremasterSecret", DerivedKind, false;
    }
}

pub struct Secret<K: SecretKind> {
    bytes: Zeroizing<Vec<u8>>,
    lock: LockState,
    kind: PhantomData<K>,
}

impl<K: SecretKind + DerivedKind> Secret<K> {
    /// Public because no crate above `core` can obtain such bytes, with one named exception:
    /// the stored MUK, which re-enters through [`crate::device::muk_from_keystore`].
    #[must_use]
    pub fn from_derived_bytes(bytes: Vec<u8>) -> Self {
        Self::from_parts(Zeroizing::new(bytes))
    }
}

impl<K: SecretKind + ExternalKind> Secret<K> {
    /// Crate-private, so [`crate::entry::accept`] is the only public way to brand raw input.
    #[must_use]
    pub(crate) fn from_external_bytes(bytes: Zeroizing<Vec<u8>>) -> Self {
        Self::from_parts(bytes)
    }
}

impl<K: SecretKind> Secret<K> {
    /// The one place a `Secret` is built.
    fn from_parts(bytes: Zeroizing<Vec<u8>>) -> Self {
        let lock = lock_buffer(&bytes);
        // The FFI guard keeps a hash, and nothing at all for a password.
        if !K::LOW_ENTROPY {
            crate::ffi_guard::register(&bytes);
        }
        Self {
            bytes,
            lock,
            kind: PhantomData,
        }
    }

    #[must_use]
    pub const fn lock_state(&self) -> LockState {
        self.lock
    }

    /// Length in bytes, which is not secret.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Borrows the raw bytes. Named to be greppable; do not clone the result or
    /// let it outlive the operation that needs it.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.bytes
    }
}

/// Redacted. There is deliberately no `Display`.
impl<K: SecretKind> fmt::Debug for Secret<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Secret<{}>(redacted, {} bytes)",
            K::NAME,
            self.bytes.len()
        )
    }
}

/// Deregisters the fingerprint while the bytes are still readable, before
/// `Zeroizing` wipes them.
impl<K: SecretKind> Drop for Secret<K> {
    fn drop(&mut self) {
        // Mirrors `from_parts`, or another `Secret` with the same bytes would
        // lose its registration.
        if !K::LOW_ENTROPY {
            crate::ffi_guard::deregister(&self.bytes);
        }
    }
}

fn lock_buffer(buffer: &[u8]) -> LockState {
    if buffer.is_empty() {
        // Nothing to lock, and the platform rejects a zero-length range.
        return LockState::Unlocked;
    }
    match region::lock(buffer.as_ptr(), buffer.len()) {
        // The guard unlocks on drop, so it is leaked to keep the lock for the
        // buffer's lifetime.
        Ok(guard) => {
            core::mem::forget(guard);
            LockState::Locked
        }
        Err(_) => LockState::Unlocked,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::kind::{ItemKey, Muk};
    use super::{LockState, Secret};

    #[test]
    fn only_the_brand_macro_grants_a_provenance() {
        let production = crate::scan::production(include_str!("secret.rs"));
        for provenance in ["ExternalKind", "DerivedKind"] {
            let needle = format!("impl {provenance} for ");
            let sites: Vec<&str> = production
                .match_indices(&needle)
                .map(|_| provenance)
                .collect();
            assert!(
                sites.is_empty(),
                "{provenance} is implemented by hand {} time(s) outside the \
                 `brand!` macro. Every brand takes its provenance as a macro \
                 argument so that exactly one applies; a hand-written impl can \
                 give a brand both, and the disjointness claim in \
                 `ExternalKind`'s docs stops holding.",
                sites.len()
            );
        }
        assert_eq!(
            production.matches("impl $origin for $name {}").count(),
            1,
            "the macro must grant provenance in exactly one place"
        );
    }

    #[test]
    fn i1a_debug_never_renders_the_bytes() {
        let secret = Secret::<Muk>::from_derived_bytes(b"super-secret-key-material".to_vec());
        let rendered = format!("{secret:?}");
        assert!(
            !rendered.contains("super-secret"),
            "Debug leaked key material: {rendered}"
        );
        assert!(
            rendered.contains("redacted"),
            "Debug should say it is redacted: {rendered}"
        );
        assert!(
            rendered.contains("MUK"),
            "Debug should name the brand: {rendered}"
        );
    }

    #[test]
    fn i1a_debug_of_every_brand_is_redacted() {
        super::kind::assert_every_brand_redacts_debug();
    }

    #[test]
    fn expose_returns_the_bytes_it_was_given() {
        let secret = Secret::<ItemKey>::from_derived_bytes(vec![1, 2, 3, 4]);
        assert_eq!(secret.expose(), &[1, 2, 3, 4]);
        assert_eq!(secret.len(), 4);
        assert!(!secret.is_empty());
    }

    #[test]
    fn lock_state_is_reported_rather_than_assumed() {
        let secret = Secret::<Muk>::from_derived_bytes(vec![0_u8; 32]);
        // The platform may refuse the lock, so either answer is fine.
        assert!(matches!(
            secret.lock_state(),
            LockState::Locked | LockState::Unlocked
        ));
    }

    #[test]
    fn an_empty_secret_reports_unlocked_and_does_not_panic() {
        let secret = Secret::<Muk>::from_derived_bytes(Vec::new());
        assert!(secret.is_empty());
        assert_eq!(secret.lock_state(), LockState::Unlocked);
    }
}
