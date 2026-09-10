//! `secret_key::decode` is private; a typed Secret Key enters through `entry::accept` only.

fn main() {
    let key = chiavora_core::secret_key::decode(b"CHV1-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AA53");
    let _ = key;
}
