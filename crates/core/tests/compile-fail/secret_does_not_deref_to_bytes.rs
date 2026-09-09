//! A `Secret` does not deref to its bytes; reads go through `expose()`.
use chiavora_core::secret::{kind::Muk, Secret};

fn takes_bytes(_bytes: &[u8]) {}

fn main() {
    let secret = Secret::<Muk>::new(b"key material".to_vec());
    takes_bytes(&secret);
}
