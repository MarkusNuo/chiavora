//! `VaultAndAutofill::wrap` cannot be called without the Autofill Key.
use chiavora_core::secret::{
    kind::{ItemKey, VaultKey},
    Secret,
};
use chiavora_core::wrap::{VaultAndAutofill, WrapContext};

fn main() {
    let item_key = Secret::<ItemKey>::from_derived_bytes(vec![0; 32]);
    let vault_key = Secret::<VaultKey>::from_derived_bytes(vec![1; 32]);
    let ctx = WrapContext { vault_id: b"v", item_id: b"i" };
    let _ = VaultAndAutofill::wrap(&item_key, &vault_key, ctx);
}
