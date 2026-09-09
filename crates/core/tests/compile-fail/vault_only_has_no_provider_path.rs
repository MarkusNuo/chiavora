//! A `VaultOnly` wrap set has no `unwrap_for_provider`.
use chiavora_core::secret::{
    kind::{AutofillKey, ItemKey, VaultKey},
    Secret,
};
use chiavora_core::wrap::{VaultOnly, WrapContext};

fn main() {
    let item_key = Secret::<ItemKey>::new(vec![0; 32]);
    let vault_key = Secret::<VaultKey>::new(vec![1; 32]);
    let autofill_key = Secret::<AutofillKey>::new(vec![2; 32]);
    let ctx = WrapContext { vault_id: b"v", item_id: b"i" };
    let set = VaultOnly::wrap(&item_key, &vault_key, ctx).unwrap();
    let _ = set.unwrap_for_provider(&autofill_key, ctx);
}
