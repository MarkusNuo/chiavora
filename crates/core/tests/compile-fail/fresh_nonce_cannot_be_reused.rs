//! `seal` consumes its `FreshNonce`, so a second use of the same nonce is a move error.
use chiavora_core::aad::AadFields;
use chiavora_core::item::seal;
use chiavora_core::nonce::FreshNonce;
use chiavora_core::secret::{kind::ItemKey, Secret};

fn main() {
    let key = Secret::<ItemKey>::from_derived_bytes(vec![0; 32]);
    let fields = AadFields::ItemPayload {
        vault_id: b"v".to_vec(),
        item_id: b"i".to_vec(),
        version: 1,
        content_type: b"login".to_vec(),
    };
    let nonce = FreshNonce::generate().unwrap();
    let _first = seal(&key, nonce, &fields, b"plaintext one");
    let _second = seal(&key, nonce, &fields, b"plaintext two");
}
