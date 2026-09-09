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
    use super::{assert_not_key_material, live_key_material_count, register};
    use crate::secret::{kind::Muk, Secret};

    #[test]
    fn a_secret_registers_while_live_and_deregisters_on_drop() {
        let before = live_key_material_count();
        {
            let _secret = Secret::<Muk>::new(vec![0x5A; 32]);
            assert!(
                live_key_material_count() > before,
                "a live Secret must be registered"
            );
        }
        assert_eq!(
            live_key_material_count(),
            before,
            "dropping a Secret must deregister it"
        );
    }

    #[test]
    fn two_secrets_with_the_same_bytes_are_counted_not_deduplicated() {
        let before = live_key_material_count();
        let first = Secret::<Muk>::new(vec![0x11; 32]);
        let second = Secret::<Muk>::new(vec![0x11; 32]);
        assert_eq!(live_key_material_count(), before + 1, "one fingerprint");
        drop(first);
        assert_eq!(live_key_material_count(), before + 1);
        drop(second);
        assert_eq!(live_key_material_count(), before);
    }

    #[test]
    fn an_unrelated_buffer_passes_the_guard() {
        let _secret = Secret::<Muk>::new(vec![0x77; 32]);
        assert_not_key_material(b"chiavora-ffi-node:ok");
        assert_not_key_material(&[]);
        assert_not_key_material(&vec![0x00; 4096]);
    }

    #[test]
    fn an_empty_secret_is_not_registered() {
        let before = live_key_material_count();
        let _empty = Secret::<Muk>::new(Vec::new());
        assert_eq!(live_key_material_count(), before);
        assert_not_key_material(b"");
    }

    #[test]
    fn registering_the_same_bytes_directly_is_idempotent_in_effect() {
        let before = live_key_material_count();
        register(&[0x42; 32]);
        register(&[0x42; 32]);
        assert_eq!(live_key_material_count(), before + 1);
        super::deregister(&[0x42; 32]);
        super::deregister(&[0x42; 32]);
        assert_eq!(live_key_material_count(), before);
    }
}
