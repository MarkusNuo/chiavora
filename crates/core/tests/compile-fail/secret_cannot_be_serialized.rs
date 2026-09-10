//! A `Secret` does not implement `Serialize`.
use chiavora_core::secret::{kind::Muk, Secret};

fn main() {
    let secret = Secret::<Muk>::from_derived_bytes(b"key material".to_vec());
    let _json = serde_json::to_string(&secret);
}
