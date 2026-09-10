//! A `Secret` cannot be turned into a `Vec<u8>` that nothing zeroizes.
use chiavora_core::secret::{kind::Muk, Secret};

fn main() {
    let secret = Secret::<Muk>::from_derived_bytes(b"key material".to_vec());
    let _owned: Vec<u8> = secret.into();
}
