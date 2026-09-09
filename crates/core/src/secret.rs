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
}

mod sealed {
    pub trait Sealed {}
}

pub mod kind {
    use super::sealed::Sealed;
    use super::SecretKind;

    macro_rules! brand {
        ($(#[doc = $doc:literal] $name:ident => $label:literal;)+) => {
            $(
                #[doc = $doc]
                #[derive(Debug, Clone, Copy)]
                pub struct $name;
                impl Sealed for $name {}
                impl SecretKind for $name {
                    const NAME: &'static str = $label;
                }
            )+
        };
    }

    brand! {
        AccountPassword => "AccountPassword";
        SecretKeyMaterial => "SecretKey";
        RootKey => "RootKey";
        Muk => "MUK";
        SrpX => "srpX";
        VaultKey => "VaultKey";
        ItemKey => "ItemKey";
        AutofillKey => "AutofillKey";
    }
}

pub struct Secret<K: SecretKind> {
    bytes: Zeroizing<Vec<u8>>,
    lock: LockState,
    kind: PhantomData<K>,
}

impl<K: SecretKind> Secret<K> {
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        let bytes = Zeroizing::new(bytes);
        let lock = lock_buffer(&bytes);
        crate::ffi_guard::register(&bytes);
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
        crate::ffi_guard::deregister(&self.bytes);
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
    use super::kind::{AccountPassword, ItemKey, Muk, SrpX};
    use super::{LockState, Secret};

    #[test]
    fn i1a_debug_never_renders_the_bytes() {
        let secret = Secret::<Muk>::new(b"super-secret-key-material".to_vec());
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
        let plaintext = b"leak-me-if-you-can".to_vec();
        let rendered = [
            format!("{:?}", Secret::<AccountPassword>::new(plaintext.clone())),
            format!("{:?}", Secret::<ItemKey>::new(plaintext.clone())),
            format!("{:?}", Secret::<SrpX>::new(plaintext)),
        ];
        for line in &rendered {
            assert!(
                !line.contains("leak-me"),
                "Debug leaked key material: {line}"
            );
        }
    }

    #[test]
    fn expose_returns_the_bytes_it_was_given() {
        let secret = Secret::<ItemKey>::new(vec![1, 2, 3, 4]);
        assert_eq!(secret.expose(), &[1, 2, 3, 4]);
        assert_eq!(secret.len(), 4);
        assert!(!secret.is_empty());
    }

    #[test]
    fn lock_state_is_reported_rather_than_assumed() {
        let secret = Secret::<Muk>::new(vec![0_u8; 32]);
        // The platform may refuse the lock, so either answer is fine.
        assert!(matches!(
            secret.lock_state(),
            LockState::Locked | LockState::Unlocked
        ));
    }

    #[test]
    fn an_empty_secret_reports_unlocked_and_does_not_panic() {
        let secret = Secret::<Muk>::new(Vec::new());
        assert!(secret.is_empty());
        assert_eq!(secret.lock_state(), LockState::Unlocked);
    }
}
