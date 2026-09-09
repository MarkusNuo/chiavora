//! `SecretKind` is sealed, so no crate outside `core` can add a kind of key material.
use chiavora_core::secret::SecretKind;

struct MyOwnKeyKind;

impl SecretKind for MyOwnKeyKind {
    const NAME: &'static str = "MyOwnKeyKind";
}

fn main() {}
