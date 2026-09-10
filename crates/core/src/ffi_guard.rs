//! Stops accidents only: transformed key material and the account password are not caught.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use sha2::{Digest, Sha256};

/// SHA-256 of a piece of live key material, so the registry holds no copy of it.
/// Only high-entropy material is registered, so a hash is no shortcut to the bytes.
type Fingerprint = [u8; 32];

/// The live fingerprints, counted: two `Secret`s can hold the same bytes, and the
/// first to drop must not deregister the other.
fn registry() -> &'static Mutex<HashMap<Fingerprint, usize>> {
    static REGISTRY: OnceLock<Mutex<HashMap<Fingerprint, usize>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

fn fingerprint(bytes: &[u8]) -> Fingerprint {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

pub(crate) fn register(bytes: &[u8]) {
    if bytes.is_empty() {
        // An empty secret would match every empty outgoing buffer.
        return;
    }
    if let Ok(mut map) = registry().lock() {
        *map.entry(fingerprint(bytes)).or_insert(0) += 1;
    }
}

pub(crate) fn deregister(bytes: &[u8]) {
    if bytes.is_empty() {
        return;
    }
    if let Ok(mut map) = registry().lock() {
        let key = fingerprint(bytes);
        if let Some(count) = map.get_mut(&key) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                map.remove(&key);
            }
        }
    }
}

/// Test-only: a public predicate over key material would be a confirmation oracle.
#[cfg(test)]
pub(crate) fn registered_count(bytes: &[u8]) -> usize {
    if bytes.is_empty() {
        return 0;
    }
    registry()
        .lock()
        .map_or(0, |m| m.get(&fingerprint(bytes)).copied().unwrap_or(0))
}

/// An autofill provider that has finished a fill should report zero.
#[must_use]
pub fn live_key_material_count() -> usize {
    registry().lock().map_or(0, |m| m.len())
}

/// Call it on every buffer leaving `core` through a binding.
/// Aborts rather than panics, because a panic can be caught.
pub fn assert_not_key_material(outgoing: &[u8]) {
    /// Key material is always 32 bytes (§2.1).
    const KEY_LEN: usize = 32;

    if outgoing.is_empty() {
        return;
    }
    let Ok(map) = registry().lock() else {
        // Fail closed: a poisoned registry must not disable the guard.
        abort_with("the FFI guard registry is poisoned; refusing to vouch for outgoing bytes");
    };
    if map.is_empty() {
        return;
    }

    if map.contains_key(&fingerprint(outgoing)) {
        drop(map);
        abort_with("live key material was passed to an FFI binding verbatim");
    }

    if outgoing.len() > KEY_LEN {
        for window in outgoing.windows(KEY_LEN) {
            if map.contains_key(&fingerprint(window)) {
                drop(map);
                abort_with("live key material was found inside a buffer passed to an FFI binding");
            }
        }
    }
}

fn abort_with(reason: &str) -> ! {
    use std::io::Write as _;

    // Straight to stderr, not the logger, and flushed by hand: `process::abort` flushes nothing.
    let mut err = std::io::stderr();
    let _ = writeln!(err, "chiavora: FATAL: I1(a) violated: {reason}");
    let _ = writeln!(
        err,
        "chiavora: aborting rather than continuing. This is a bug in Chiavora, not a"
    );
    let _ = writeln!(
        err,
        "chiavora: recoverable condition - see crates/core/src/ffi_guard.rs."
    );
    let _ = err.flush();
    std::process::abort()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{assert_not_key_material, register, registered_count};
    use crate::secret::{kind::Muk, Secret};

    // Bytes no other test holds: the registry is process-wide and keyed by content.
    fn distinct(marker: u8) -> Vec<u8> {
        vec![marker; 32]
    }

    #[test]
    fn a_secret_registers_while_live_and_deregisters_on_drop() {
        let bytes = distinct(0x5A);
        assert_eq!(registered_count(&bytes), 0, "clean start");
        {
            let _secret = Secret::<Muk>::from_derived_bytes(bytes.clone());
            assert_eq!(
                registered_count(&bytes),
                1,
                "a live Secret must be registered"
            );
        }
        assert_eq!(
            registered_count(&bytes),
            0,
            "dropping a Secret must deregister it"
        );
    }

    #[test]
    fn two_secrets_with_the_same_bytes_are_counted_not_deduplicated() {
        let bytes = distinct(0x11);
        let first = Secret::<Muk>::from_derived_bytes(bytes.clone());
        let second = Secret::<Muk>::from_derived_bytes(bytes.clone());
        assert_eq!(registered_count(&bytes), 2, "two registrations, one key");
        drop(first);
        assert_eq!(
            registered_count(&bytes),
            1,
            "still registered: `second` holds the same bytes"
        );
        drop(second);
        assert_eq!(registered_count(&bytes), 0);
    }

    #[test]
    fn an_unrelated_buffer_passes_the_guard() {
        let _secret = Secret::<Muk>::from_derived_bytes(distinct(0x77));
        assert_not_key_material(b"chiavora-ffi-node:ok");
        assert_not_key_material(&[]);
        assert_not_key_material(&vec![0x00; 4096]);
    }

    #[test]
    fn an_empty_secret_is_not_registered() {
        let _empty = Secret::<Muk>::from_derived_bytes(Vec::new());
        assert_eq!(registered_count(&[]), 0);
        assert_not_key_material(b"");
    }

    #[test]
    fn register_and_deregister_are_balanced() {
        let bytes = distinct(0x42);
        register(&bytes);
        register(&bytes);
        assert_eq!(registered_count(&bytes), 2);
        super::deregister(&bytes);
        assert_eq!(registered_count(&bytes), 1, "one drop, one deregistration");
        super::deregister(&bytes);
        assert_eq!(registered_count(&bytes), 0);
    }

    #[test]
    fn the_account_password_is_never_registered() {
        use crate::entry::{accept, PasswordField};

        let password = b"a-distinctive-password-for-this-test".to_vec();
        let secret = accept::<PasswordField>(password.clone()).expect("accepted");
        assert_eq!(
            registered_count(&password),
            0,
            "the account password must not be fingerprinted"
        );
        drop(secret);
        assert_eq!(registered_count(&password), 0);
    }
}
