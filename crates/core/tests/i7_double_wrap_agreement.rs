#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use chiavora_core::secret::{
    kind::{AutofillKey, ItemKey, VaultKey},
    Secret,
};
use chiavora_core::wrap::{
    Card, Identity, ItemType, Login, Note, SshKey, Totp, VaultAndAutofill, VaultOnly, WrapContext,
    WrapError,
};

fn key32(fill: u8) -> Vec<u8> {
    vec![fill; 32]
}

fn item_key(fill: u8) -> Secret<ItemKey> {
    Secret::from_derived_bytes(key32(fill))
}

fn vault_key() -> Secret<VaultKey> {
    Secret::from_derived_bytes(key32(0x11))
}

fn autofill_key() -> Secret<AutofillKey> {
    Secret::from_derived_bytes(key32(0x22))
}

const VAULT_ID: &[u8] = b"vault-1";
const ITEM_ID: &[u8] = b"item-1";

fn ctx() -> WrapContext<'static> {
    WrapContext {
        vault_id: VAULT_ID,
        item_id: ITEM_ID,
    }
}

/// The error side only, since `Secret` has no `PartialEq` to compare a whole `Result` with.
fn err_of<T>(result: Result<T, WrapError>) -> Option<WrapError> {
    result.err()
}

#[test]
fn i7_agreeing_wraps_yield_the_item_key() {
    let original = item_key(0xAB);
    let set = VaultAndAutofill::wrap(&original, &vault_key(), &autofill_key(), ctx())
        .expect("wrapping under both keys must succeed");

    let recovered = set
        .unwrap(&vault_key(), &autofill_key(), ctx())
        .expect("agreeing wraps must unwrap");
    assert_eq!(recovered.expose(), original.expose());
}

#[test]
fn i7_the_provider_path_yields_the_same_key() {
    let original = item_key(0xAB);
    let set =
        VaultAndAutofill::wrap(&original, &vault_key(), &autofill_key(), ctx()).expect("must wrap");

    let via_provider = set
        .unwrap_for_provider(&autofill_key(), ctx())
        .expect("the Autofill Key alone must unwrap the autofill wrap");
    assert_eq!(via_provider.expose(), original.expose());
}

#[test]
fn i7_disagreeing_wraps_are_refused() {
    // `wrap` always agrees, so a disagreeing pair is assembled from stored parts.
    let honest = item_key(0xAB);
    let planted = item_key(0xCD);

    let good =
        VaultAndAutofill::wrap(&honest, &vault_key(), &autofill_key(), ctx()).expect("must wrap");
    let bad =
        VaultAndAutofill::wrap(&planted, &vault_key(), &autofill_key(), ctx()).expect("must wrap");

    let mixed =
        VaultAndAutofill::from_stored_parts(good.vault_wrap().clone(), bad.autofill_wrap().clone());

    assert_eq!(
        err_of(mixed.unwrap(&vault_key(), &autofill_key(), ctx())),
        Some(WrapError::I7Disagreement),
        "I7: a disagreeing pair must be refused"
    );
}

#[test]
fn i7_disagreement_is_refused_in_the_other_arrangement_too() {
    let honest = item_key(0xAB);
    let planted = item_key(0xCD);

    let good =
        VaultAndAutofill::wrap(&honest, &vault_key(), &autofill_key(), ctx()).expect("must wrap");
    let bad =
        VaultAndAutofill::wrap(&planted, &vault_key(), &autofill_key(), ctx()).expect("must wrap");

    let mixed =
        VaultAndAutofill::from_stored_parts(bad.vault_wrap().clone(), good.autofill_wrap().clone());

    assert_eq!(
        err_of(mixed.unwrap(&vault_key(), &autofill_key(), ctx())),
        Some(WrapError::I7Disagreement)
    );
}

#[test]
fn i7_refusal_returns_no_key_and_prefers_neither_path() {
    let honest = item_key(0xAB);
    let planted = item_key(0xCD);
    let good =
        VaultAndAutofill::wrap(&honest, &vault_key(), &autofill_key(), ctx()).expect("must wrap");
    let bad =
        VaultAndAutofill::wrap(&planted, &vault_key(), &autofill_key(), ctx()).expect("must wrap");
    let mixed =
        VaultAndAutofill::from_stored_parts(good.vault_wrap().clone(), bad.autofill_wrap().clone());

    match mixed.unwrap(&vault_key(), &autofill_key(), ctx()) {
        Err(WrapError::I7Disagreement) => {}
        Err(other) => panic!("I7 disagreement must be reported as such, got {other:?}"),
        Ok(key) => panic!(
            "I7: unwrap returned a key on disagreement. It matched the {} wrap.",
            if key.expose() == honest.expose() {
                "Vault-Key"
            } else if key.expose() == planted.expose() {
                "Autofill-Key"
            } else {
                "neither"
            }
        ),
    }
}

#[test]
fn a_tampered_wrap_fails_the_aead_before_i7_is_reached() {
    let original = item_key(0xAB);
    let set =
        VaultAndAutofill::wrap(&original, &vault_key(), &autofill_key(), ctx()).expect("must wrap");

    let mut bytes = set.autofill_wrap().ciphertext().to_vec();
    bytes[0] ^= 0x01;
    let tampered =
        chiavora_core::wrap::WrappedKey::from_stored_parts(*set.autofill_wrap().nonce(), bytes);
    let broken = VaultAndAutofill::from_stored_parts(set.vault_wrap().clone(), tampered);

    assert_eq!(
        err_of(broken.unwrap(&vault_key(), &autofill_key(), ctx())),
        Some(WrapError::Aead)
    );
}

#[test]
fn i7_fillable_types_name_the_double_wrap_and_the_others_do_not() {
    // Each call below only compiles for a type with that wrap set.
    fn requires_double<T: ItemType<Wraps = VaultAndAutofill>>() -> &'static str {
        T::NAME
    }
    fn requires_single<T: ItemType<Wraps = VaultOnly>>() -> &'static str {
        T::NAME
    }

    assert_eq!(requires_double::<Login>(), "login");
    assert_eq!(requires_double::<Totp>(), "TOTP");

    assert_eq!(requires_single::<Note>(), "note");
    assert_eq!(requires_single::<Card>(), "card");
    assert_eq!(requires_single::<Identity>(), "identity");
    assert_eq!(requires_single::<SshKey>(), "SSH key");
}

// Which item types the provider can read (ADR-0003), checked at compile time.
const _: () = assert!(Login::PROVIDER_READABLE);
const _: () = assert!(Totp::PROVIDER_READABLE);
const _: () = assert!(!Note::PROVIDER_READABLE);
const _: () = assert!(!Card::PROVIDER_READABLE);
const _: () = assert!(!Identity::PROVIDER_READABLE);
const _: () = assert!(!SshKey::PROVIDER_READABLE);

#[test]
fn provider_readability_is_checked_at_compile_time() {
    // The real checks are the `const` assertions above; this names them in the test list.
    assert_eq!(Login::NAME, "login");
    assert_eq!(SshKey::NAME, "SSH key");
}

#[test]
fn a_vault_only_item_has_no_autofill_wrap_to_offer() {
    // The absence is structural: `VaultOnly` has no autofill wrap and no method to reach one.
    let original = item_key(0x77);
    let set = VaultOnly::wrap(&original, &vault_key(), ctx()).expect("must wrap");
    let recovered = set.unwrap(&vault_key(), ctx()).expect("must unwrap");
    assert_eq!(recovered.expose(), original.expose());
}

#[test]
fn a_wrap_cannot_be_transplanted_to_another_item() {
    let original = item_key(0xAB);
    let set = VaultOnly::wrap(&original, &vault_key(), ctx()).expect("must wrap");

    let other_item = WrapContext {
        vault_id: VAULT_ID,
        item_id: b"item-2",
    };
    assert_eq!(
        err_of(set.unwrap(&vault_key(), other_item)),
        Some(WrapError::Aead)
    );

    let other_vault = WrapContext {
        vault_id: b"vault-2",
        item_id: ITEM_ID,
    };
    assert_eq!(
        err_of(set.unwrap(&vault_key(), other_vault)),
        Some(WrapError::Aead)
    );
}

#[test]
fn the_two_wraps_are_not_interchangeable_between_slots() {
    // Both wrap the same Item Key; the purpose byte in the AAD tells the slots apart.
    let original = item_key(0xAB);
    let set =
        VaultAndAutofill::wrap(&original, &vault_key(), &autofill_key(), ctx()).expect("must wrap");

    let swapped =
        VaultAndAutofill::from_stored_parts(set.autofill_wrap().clone(), set.vault_wrap().clone());
    assert_eq!(
        err_of(swapped.unwrap(&vault_key(), &autofill_key(), ctx())),
        Some(WrapError::Aead)
    );
}

#[test]
fn the_binding_is_length_prefixed() {
    let original = item_key(0xAB);
    let left = WrapContext {
        vault_id: b"ab",
        item_id: b"c",
    };
    let right = WrapContext {
        vault_id: b"a",
        item_id: b"bc",
    };

    let set = VaultOnly::wrap(&original, &vault_key(), left).expect("must wrap");
    assert_eq!(
        err_of(set.unwrap(&vault_key(), right)),
        Some(WrapError::Aead)
    );
}

#[test]
fn a_wrapping_key_of_the_wrong_length_is_refused() {
    let original = item_key(0xAB);
    let short = Secret::<VaultKey>::from_derived_bytes(vec![0x11; 16]);
    assert_eq!(
        err_of(VaultOnly::wrap(&original, &short, ctx())),
        Some(WrapError::BadWrappingKeyLength)
    );
}
