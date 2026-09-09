//! A `Nonce` cannot be built from raw bytes outside `core`.
use chiavora_core::nonce::{Nonce, NONCE_LEN};

fn main() {
    let _nonce = Nonce([0_u8; NONCE_LEN]);
}
