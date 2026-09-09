//! A `Secret` cannot be cloned.
use chiavora_core::secret::{kind::Muk, Secret};

fn main() {
    let secret = Secret::<Muk>::new(b"key material".to_vec());
    let _copy = secret.clone();
}
