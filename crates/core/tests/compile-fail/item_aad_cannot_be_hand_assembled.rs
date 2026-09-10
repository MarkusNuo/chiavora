//! `seal` takes `AadFields`, so hand-assembled AAD bytes cannot be passed to it.
use chiavora_core::item::seal;
use chiavora_core::nonce::FreshNonce;
use chiavora_core::secret::{kind::ItemKey, Secret};

fn main() {
    let key = Secret::<ItemKey>::from_derived_bytes(vec![0; 32]);
    let nonce = FreshNonce::generate().unwrap();
    let hand_rolled: Vec<u8> = b"CHV1\x01v\x00i\x00".to_vec();
    let _ = seal(&key, nonce, &hand_rolled, b"plaintext");
}
