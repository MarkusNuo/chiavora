//! The `csprng` module is private to `core`, so no other crate can draw randomness through it.

fn main() {
    let mut buf = [0_u8; 16];
    chiavora_core::csprng::fill_bytes(&mut buf).unwrap();
}
