//! The AAD encoder takes `AadFields`, never raw bytes.
use chiavora_core::aad::encode;

fn main() {
    let hand_rolled: Vec<u8> = b"CHV1\x01".to_vec();
    let _ = encode(&hand_rolled);
}
