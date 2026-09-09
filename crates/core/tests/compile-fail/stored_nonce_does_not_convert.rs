//! I2: no conversion turns a `StoredNonce` into a `FreshNonce`.
use chiavora_core::nonce::{FreshNonce, StoredNonce, NONCE_LEN};

fn main() {
    let stored = StoredNonce::from_stored_bytes([0_u8; NONCE_LEN]);
    let _laundered: FreshNonce = stored.into();
}
