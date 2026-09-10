#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use proptest::prelude::*;

use chiavora_core::aad::AadFields;
use chiavora_core::item::{open, seal};
use chiavora_core::nonce::FreshNonce;
use chiavora_core::secret::{
    kind::{AutofillKey, ItemKey, VaultKey},
    Secret,
};
use chiavora_core::wrap::{VaultAndAutofill, VaultOnly, WrapContext};

fn item_key(bytes: Vec<u8>) -> Secret<ItemKey> {
    Secret::from_derived_bytes(bytes)
}

fn vault_key(bytes: Vec<u8>) -> Secret<VaultKey> {
    Secret::from_derived_bytes(bytes)
}

fn autofill_key(bytes: Vec<u8>) -> Secret<AutofillKey> {
    Secret::from_derived_bytes(bytes)
}

/// A generated 32-byte key, so an ignored key cannot go unnoticed.
fn key_bytes() -> impl Strategy<Value = Vec<u8>> {
    proptest::collection::vec(any::<u8>(), 32..=32)
}

fn item_fields() -> impl Strategy<Value = AadFields> {
    (
        proptest::collection::vec(any::<u8>(), 0..24),
        proptest::collection::vec(any::<u8>(), 0..24),
        any::<u64>(),
        proptest::collection::vec(any::<u8>(), 0..12),
    )
        .prop_map(
            |(vault_id, item_id, version, content_type)| AadFields::ItemPayload {
                vault_id,
                item_id,
                version,
                content_type,
            },
        )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn an_item_payload_round_trips(
        key in key_bytes(),
        fields in item_fields(),
        plaintext in proptest::collection::vec(any::<u8>(), 0..512),
    ) {
        let key = item_key(key);
        let nonce = FreshNonce::generate().expect("CSPRNG");
        let sealed = seal(&key, nonce, &fields, &plaintext).expect("seal");
        let opened = open(&key, &sealed, &fields).expect("open");
        prop_assert_eq!(opened, plaintext);
    }

    #[test]
    fn two_seals_of_one_plaintext_differ(
        key in key_bytes(),
        fields in item_fields(),
        plaintext in proptest::collection::vec(any::<u8>(), 1..128),
    ) {
        let key = item_key(key);
        let first = seal(&key, FreshNonce::generate().unwrap(), &fields, &plaintext).unwrap();
        let second = seal(&key, FreshNonce::generate().unwrap(), &fields, &plaintext).unwrap();
        prop_assert_ne!(first.ciphertext(), second.ciphertext());
    }

    #[test]
    fn a_flipped_ciphertext_bit_fails(
        key in key_bytes(),
        fields in item_fields(),
        plaintext in proptest::collection::vec(any::<u8>(), 1..128),
        index in 0_usize..128,
        bit in 0_u32..8,
    ) {
        let key = item_key(key);
        let sealed = seal(&key, FreshNonce::generate().unwrap(), &fields, &plaintext).unwrap();
        let mut bytes = sealed.ciphertext().to_vec();
        let at = index % bytes.len();
        if let Some(slot) = bytes.get_mut(at) {
            *slot ^= 1_u8 << bit;
        }
        let tampered = chiavora_core::item::SealedPayload::from_stored_parts(
            *sealed.nonce(),
            bytes,
        );
        prop_assert!(open(&key, &tampered, &fields).is_err());
    }

    #[test]
    fn another_key_does_not_open_it(
        first in key_bytes(),
        second in key_bytes(),
        fields in item_fields(),
        plaintext in proptest::collection::vec(any::<u8>(), 1..128),
    ) {
        prop_assume!(first != second);
        let sealed = seal(
            &item_key(first),
            FreshNonce::generate().unwrap(),
            &fields,
            &plaintext,
        )
        .unwrap();
        prop_assert!(open(&item_key(second), &sealed, &fields).is_err());
    }

    #[test]
    fn a_vault_only_wrap_round_trips(
        item in key_bytes(),
        vault in key_bytes(),
        vault_id in proptest::collection::vec(any::<u8>(), 0..16),
        item_id in proptest::collection::vec(any::<u8>(), 0..16),
    ) {
        let ctx = WrapContext { vault_id: &vault_id, item_id: &item_id };
        let original = item.clone();
        let set = VaultOnly::wrap(&item_key(item), &vault_key(vault.clone()), ctx)
            .expect("wrap");
        let recovered = set.unwrap(&vault_key(vault), ctx).expect("unwrap");
        prop_assert_eq!(recovered.expose(), original.as_slice());
    }

    #[test]
    fn a_double_wrap_round_trips(
        item in key_bytes(),
        vault in key_bytes(),
        autofill in key_bytes(),
        vault_id in proptest::collection::vec(any::<u8>(), 0..16),
        item_id in proptest::collection::vec(any::<u8>(), 0..16),
    ) {
        let ctx = WrapContext { vault_id: &vault_id, item_id: &item_id };
        let original = item.clone();
        let set = VaultAndAutofill::wrap(
            &item_key(item),
            &vault_key(vault.clone()),
            &autofill_key(autofill.clone()),
            ctx,
        )
        .expect("wrap");
        let recovered = set
            .unwrap(&vault_key(vault), &autofill_key(autofill.clone()), ctx)
            .expect("unwrap");
        prop_assert_eq!(recovered.expose(), original.as_slice());
        let via_provider = set
            .unwrap_for_provider(&autofill_key(autofill), ctx)
            .expect("provider unwrap");
        prop_assert_eq!(via_provider.expose(), original.as_slice());
    }

    #[test]
    fn a_wrap_does_not_transplant(
        item in key_bytes(),
        vault in key_bytes(),
        a in proptest::collection::vec(any::<u8>(), 1..16),
        b in proptest::collection::vec(any::<u8>(), 1..16),
    ) {
        prop_assume!(a != b);
        let sealed_ctx = WrapContext { vault_id: &a, item_id: &a };
        let other_ctx = WrapContext { vault_id: &b, item_id: &b };
        let set = VaultOnly::wrap(&item_key(item), &vault_key(vault.clone()), sealed_ctx)
            .expect("wrap");
        prop_assert!(set.unwrap(&vault_key(vault), other_ctx).is_err());
    }
}

#[test]
fn a_vault_only_wrap_survives_being_stored_and_reconstituted() {
    let item = item_key(vec![0x4D; 32]);
    let vault = vault_key(vec![0x11; 32]);
    let ctx = WrapContext {
        vault_id: b"vault-1",
        item_id: b"item-1",
    };

    let set = VaultOnly::wrap(&item, &vault, ctx).expect("wrap");
    let stored = set.vault_wrap().clone();
    let reconstituted = VaultOnly::from_stored_parts(stored);
    let recovered = reconstituted.unwrap(&vault, ctx).expect("unwrap");
    assert_eq!(recovered.expose(), item.expose());
}
