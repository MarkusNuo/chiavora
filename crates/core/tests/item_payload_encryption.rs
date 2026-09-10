#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use chiavora_core::aad::AadFields;
use chiavora_core::item::{open, seal, ItemError, SealedPayload};
use chiavora_core::nonce::FreshNonce;
use chiavora_core::secret::{kind::ItemKey, Secret};

fn item_key(fill: u8) -> Secret<ItemKey> {
    Secret::from_derived_bytes(vec![fill; 32])
}

fn fields(item_id: &[u8], version: u64) -> AadFields {
    AadFields::ItemPayload {
        vault_id: b"vault-1".to_vec(),
        item_id: item_id.to_vec(),
        version,
        content_type: b"login".to_vec(),
    }
}

fn err_of<T>(result: Result<T, ItemError>) -> Option<ItemError> {
    result.err()
}

#[test]
fn a_payload_round_trips() {
    let key = item_key(0xAB);
    let f = fields(b"item-1", 1);
    let plaintext = b"the item payload";

    let sealed = seal(&key, FreshNonce::generate().unwrap(), &f, plaintext).expect("must seal");
    let opened = open(&key, &sealed, &f).expect("must open");
    assert_eq!(opened, plaintext);
}

#[test]
fn tampered_aad_fails_decryption() {
    let key = item_key(0xAB);
    let f = fields(b"item-1", 1);
    let sealed = seal(&key, FreshNonce::generate().unwrap(), &f, b"payload").expect("must seal");

    let tampered = [
        (
            "vaultId",
            AadFields::ItemPayload {
                vault_id: b"vault-2".to_vec(),
                item_id: b"item-1".to_vec(),
                version: 1,
                content_type: b"login".to_vec(),
            },
        ),
        ("itemId", fields(b"item-2", 1)),
        ("version", fields(b"item-1", 2)),
        (
            "contentType",
            AadFields::ItemPayload {
                vault_id: b"vault-1".to_vec(),
                item_id: b"item-1".to_vec(),
                version: 1,
                content_type: b"note".to_vec(),
            },
        ),
    ];

    for (field, altered) in tampered {
        assert_eq!(
            err_of(open(&key, &sealed, &altered)),
            Some(ItemError::Aead),
            "decryption succeeded with a tampered {field}"
        );
    }
}

#[test]
fn a_ciphertext_moved_to_another_item_fails() {
    let key = item_key(0xAB);
    let sealed = seal(
        &key,
        FreshNonce::generate().unwrap(),
        &fields(b"item-1", 1),
        b"payload",
    )
    .expect("must seal");

    assert_eq!(
        err_of(open(&key, &sealed, &fields(b"item-2", 1))),
        Some(ItemError::Aead)
    );
}

#[test]
fn a_rolled_back_version_fails() {
    let key = item_key(0xAB);
    let sealed = seal(
        &key,
        FreshNonce::generate().unwrap(),
        &fields(b"item-1", 7),
        b"new password",
    )
    .expect("must seal");

    assert_eq!(
        err_of(open(&key, &sealed, &fields(b"item-1", 6))),
        Some(ItemError::Aead)
    );
}

#[test]
fn a_tampered_ciphertext_fails() {
    let key = item_key(0xAB);
    let f = fields(b"item-1", 1);
    let sealed = seal(&key, FreshNonce::generate().unwrap(), &f, b"payload").expect("must seal");

    let mut bytes = sealed.ciphertext().to_vec();
    bytes[0] ^= 0x01;
    let broken = SealedPayload::from_stored_parts(*sealed.nonce(), bytes);
    assert_eq!(err_of(open(&key, &broken, &f)), Some(ItemError::Aead));
}

#[test]
fn a_tampered_nonce_fails() {
    let key = item_key(0xAB);
    let f = fields(b"item-1", 1);
    let sealed = seal(&key, FreshNonce::generate().unwrap(), &f, b"payload").expect("must seal");

    let mut nonce = *sealed.nonce();
    nonce[0] ^= 0x01;
    let broken = SealedPayload::from_stored_parts(nonce, sealed.ciphertext().to_vec());
    assert_eq!(err_of(open(&key, &broken, &f)), Some(ItemError::Aead));
}

#[test]
fn the_wrong_item_key_fails() {
    let f = fields(b"item-1", 1);
    let sealed = seal(
        &item_key(0xAB),
        FreshNonce::generate().unwrap(),
        &f,
        b"payload",
    )
    .expect("must seal");
    assert_eq!(
        err_of(open(&item_key(0xCD), &sealed, &f)),
        Some(ItemError::Aead)
    );
}

#[test]
fn only_the_item_payload_record_type_is_accepted() {
    let key = item_key(0xAB);
    let wrong = [
        AadFields::ManifestRoot {
            vault_id: b"vault-1".to_vec(),
            manifest_seq: 1,
            vault_key_epoch: 0,
            segment_count: 1,
        },
        AadFields::WrappedItemKey {
            vault_id: b"vault-1".to_vec(),
            item_id: b"item-1".to_vec(),
            wrap_purpose: 0x01,
        },
    ];
    for f in wrong {
        let expected = ItemError::WrongRecordType(f.record_type());
        assert_eq!(
            err_of(seal(&key, FreshNonce::generate().unwrap(), &f, b"payload")),
            Some(expected)
        );
    }
}

#[test]
fn an_item_key_of_the_wrong_length_is_refused() {
    let short = Secret::<ItemKey>::from_derived_bytes(vec![0xAB; 16]);
    assert_eq!(
        err_of(seal(
            &short,
            FreshNonce::generate().unwrap(),
            &fields(b"item-1", 1),
            b"payload"
        )),
        Some(ItemError::BadItemKeyLength)
    );
}

#[test]
fn two_seals_of_the_same_plaintext_differ() {
    let key = item_key(0xAB);
    let f = fields(b"item-1", 1);
    let first = seal(&key, FreshNonce::generate().unwrap(), &f, b"same").expect("must seal");
    let second = seal(&key, FreshNonce::generate().unwrap(), &f, b"same").expect("must seal");

    assert_ne!(
        first.nonce(),
        second.nonce(),
        "each seal must draw a fresh nonce"
    );
    assert_ne!(
        first.ciphertext(),
        second.ciphertext(),
        "identical ciphertext means the nonce repeated"
    );
}

#[test]
fn a_seal_with_no_plaintext_round_trips() {
    let key = item_key(0xAB);
    let f = fields(b"item-1", 1);
    let sealed = seal(&key, FreshNonce::generate().unwrap(), &f, b"").expect("must seal");
    assert_eq!(
        open(&key, &sealed, &f).expect("must open"),
        Vec::<u8>::new()
    );
    assert_eq!(
        err_of(open(&key, &sealed, &fields(b"item-2", 1))),
        Some(ItemError::Aead),
        "an empty payload must still be bound to its AAD"
    );
}
