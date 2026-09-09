//! I2: an encrypt path takes a `FreshNonce`, so a `StoredNonce` read back from
//! a record must not compile there.
use chiavora_core::nonce::{FreshNonce, StoredNonce, NONCE_LEN};

/// Stands in for an encrypt function.
fn encrypt(_nonce: FreshNonce) {}

fn main() {
    let stored = StoredNonce::from_stored_bytes([0_u8; NONCE_LEN]);
    encrypt(stored);
}
