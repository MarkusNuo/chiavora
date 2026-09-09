//! An item type declared `VaultOnly` cannot be used where `VaultAndAutofill` is required.
use chiavora_core::wrap::{ItemType, Note, VaultAndAutofill};

fn requires_double<T: ItemType<Wraps = VaultAndAutofill>>() -> &'static str {
    T::NAME
}

fn main() {
    let _ = requires_double::<Note>();
}
