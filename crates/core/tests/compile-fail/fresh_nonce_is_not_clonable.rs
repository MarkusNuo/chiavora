//! A `FreshNonce` cannot be cloned.
use chiavora_core::nonce::FreshNonce;

fn main() {
    let nonce = FreshNonce::generate().unwrap();
    let _copy = nonce.clone();
}
