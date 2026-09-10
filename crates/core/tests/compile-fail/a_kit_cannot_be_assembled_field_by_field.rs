//! A `Kit` cannot be built from a struct literal, which would skip `Kit::new`.

use chiavora_core::emergency_kit::Kit;

fn main() {
    let kit = Kit {
        account_id: [0; 16],
        account_salt: [0; 32],
        secret_key: unimplemented!(),
        checkpoint: None,
    };
    let _ = kit;
}
