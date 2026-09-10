//! `SecretKind` is sealed, so no crate outside `core` can add a kind of key material.
use chiavora_core::secret::SecretKind;

struct MyOwnKeyKind;

impl SecretKind for MyOwnKeyKind {
    const NAME: &'static str = "MyOwnKeyKind";
    // Every item is implemented, so the seal is the only error.
    const LOW_ENTROPY: bool = false;
}

fn main() {}
