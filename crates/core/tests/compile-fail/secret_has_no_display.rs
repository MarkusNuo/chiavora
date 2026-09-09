//! A `Secret` has no `Display`, so `{}` cannot print it.
use chiavora_core::secret::{kind::Muk, Secret};

fn main() {
    let secret = Secret::<Muk>::new(b"key material".to_vec());
    println!("{secret}");
}
