//! `secret_key::decode` is private; a typed Secret Key enters through `entry::accept` only.

fn main() {
    let key = chiavora_core::secret_key::decode(b"CHV1-0000-0000-0000-0000-0000-0000-00XV");
    let _ = key;
}
