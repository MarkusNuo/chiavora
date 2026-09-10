//! `from_derived_bytes` refuses the `SecretKeyMaterial` brand; only `entry::accept` makes one.

use chiavora_core::secret::{kind::SecretKeyMaterial, Secret};

fn main() {
    let secret_key = Secret::<SecretKeyMaterial>::from_derived_bytes(vec![0xAB; 16]);
    let _ = secret_key;
}
