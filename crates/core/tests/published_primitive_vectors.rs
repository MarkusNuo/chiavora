//! Published reference vectors for the primitives ADR-0002 names.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::PathBuf;

use argon2::{Algorithm, Argon2, AssociatedData, ParamsBuilder, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

fn vector_file() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("vectors")
        .join("published_primitives.json");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
}

fn field_from(text: &str, from: usize, key: &str) -> String {
    let needle = format!("\"{key}\": \"");
    let rest = text.get(from..).expect("in bounds");
    let start = rest
        .find(&needle)
        .unwrap_or_else(|| panic!("no field {key} after byte {from}"))
        + needle.len();
    let tail = rest.get(start..).expect("in bounds");
    let end = tail.find('"').expect("closing quote");
    tail.get(..end).expect("in bounds").to_owned()
}

fn section(text: &str, name: &str) -> usize {
    text.find(&format!("\"{name}\": {{"))
        .unwrap_or_else(|| panic!("no section {name}"))
}

fn hex(value: &str) -> Vec<u8> {
    assert!(value.len() % 2 == 0, "odd-length hex: {value}");
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(value.get(i..i + 2).expect("hex pair"), 16).expect("hex"))
        .collect()
}

#[test]
fn the_vector_file_covers_every_primitive_adr_0002_names() {
    let text = vector_file();
    for primitive in [
        "hkdf_sha256",
        "chacha20poly1305",
        "hchacha20",
        "xchacha20poly1305",
        "x25519",
        "argon2id",
    ] {
        assert!(
            text.contains(&format!("\"{primitive}\": {{")),
            "the vector file has no section for {primitive}"
        );
    }
    assert_eq!(text.matches("\"source\":").count(), 6);
    assert_eq!(text.matches("\"evidence\":").count(), 6);
}

#[test]
fn hkdf_sha256_matches_rfc_5869() {
    let text = vector_file();
    let start = section(&text, "hkdf_sha256");

    // A.1: with salt and info.
    let ikm = hex(&field_from(&text, start, "ikm_hex"));
    let salt = hex(&field_from(&text, start, "salt_hex"));
    let info = hex(&field_from(&text, start, "info_hex"));
    let prk_expected = hex(&field_from(&text, start, "prk_hex"));
    let okm_expected = hex(&field_from(&text, start, "okm_hex"));

    let (prk, hk) = Hkdf::<Sha256>::extract(Some(&salt), &ikm);
    assert_eq!(prk.as_slice(), prk_expected.as_slice(), "RFC 5869 A.1 PRK");
    let mut okm = vec![0_u8; okm_expected.len()];
    hk.expand(&info, &mut okm).expect("expand");
    assert_eq!(okm, okm_expected, "RFC 5869 A.1 OKM");

    // A.3: zero-length salt and info, the shape `derive::hkdf_sha256` uses.
    let a3 = text
        .get(start..)
        .expect("in bounds")
        .find("A.3 zero-length")
        .expect("A.3 vector")
        + start;
    let zero_salt_ikm = hex(&field_from(&text, a3, "ikm_hex"));
    let zero_salt_prk = hex(&field_from(&text, a3, "prk_hex"));
    let expected_output = hex(&field_from(&text, a3, "okm_hex"));

    let hk_none = Hkdf::<Sha256>::new(None, &zero_salt_ikm);
    let mut derived = vec![0_u8; expected_output.len()];
    hk_none.expand(&[], &mut derived).expect("expand");
    assert_eq!(derived, expected_output, "RFC 5869 A.3 OKM");

    // `Hkdf::new(None, ..)` must equal extracting with a zero salt, as A.3's PRK pins.
    let (extracted, _) = Hkdf::<Sha256>::extract(Some(&[0_u8; 32]), &zero_salt_ikm);
    assert_eq!(
        extracted.as_slice(),
        zero_salt_prk.as_slice(),
        "RFC 5869 A.3 PRK"
    );
}

#[test]
fn chacha20poly1305_matches_rfc_8439() {
    let text = vector_file();
    let start = section(&text, "chacha20poly1305");
    let key = hex(&field_from(&text, start, "key_hex"));
    let nonce = hex(&field_from(&text, start, "nonce_hex"));
    let aad = hex(&field_from(&text, start, "aad_hex"));
    let plaintext = field_from(&text, start, "plaintext_utf8");
    let ciphertext = hex(&field_from(&text, start, "ciphertext_hex"));
    let tag = hex(&field_from(&text, start, "tag_hex"));

    let cipher = ChaCha20Poly1305::new(key.as_slice().into());
    let sealed = cipher
        .encrypt(
            nonce.as_slice().into(),
            Payload {
                msg: plaintext.as_bytes(),
                aad: &aad,
            },
        )
        .expect("encrypt");

    // The crate returns ciphertext||tag; the RFC lists them separately.
    let (got_ct, got_tag) = sealed.split_at(sealed.len() - 16);
    assert_eq!(got_ct, ciphertext.as_slice(), "RFC 8439 2.8.2 ciphertext");
    assert_eq!(got_tag, tag.as_slice(), "RFC 8439 2.8.2 tag");

    let opened = cipher
        .decrypt(
            nonce.as_slice().into(),
            Payload {
                msg: &sealed,
                aad: &aad,
            },
        )
        .expect("decrypt");
    assert_eq!(opened, plaintext.as_bytes());
}

#[test]
fn xchacha20poly1305_matches_the_composed_vector() {
    // Not a published vector: it is composed from the `HChaCha20` and RFC 8439 vectors.
    let text = vector_file();
    let start = section(&text, "xchacha20poly1305");
    let key = hex(&field_from(&text, start, "key_hex"));
    let nonce = hex(&field_from(&text, start, "nonce_hex"));
    let aad = hex(&field_from(&text, start, "aad_hex"));
    let plaintext = field_from(&text, start, "plaintext_utf8");
    let ciphertext = hex(&field_from(&text, start, "ciphertext_hex"));
    let tag = hex(&field_from(&text, start, "tag_hex"));

    assert_eq!(nonce.len(), 24, "§2.2: a 192-bit nonce");

    let cipher = XChaCha20Poly1305::new(key.as_slice().into());
    let sealed = cipher
        .encrypt(
            nonce.as_slice().into(),
            Payload {
                msg: plaintext.as_bytes(),
                aad: &aad,
            },
        )
        .expect("encrypt");
    let (got_ct, got_tag) = sealed.split_at(sealed.len() - 16);
    assert_eq!(
        got_ct,
        ciphertext.as_slice(),
        "XChaCha20-Poly1305 ciphertext"
    );
    assert_eq!(got_tag, tag.as_slice(), "XChaCha20-Poly1305 tag");
}

#[test]
fn a_tampered_aad_fails_the_published_vector() {
    let text = vector_file();
    let start = section(&text, "chacha20poly1305");
    let key = hex(&field_from(&text, start, "key_hex"));
    let nonce = hex(&field_from(&text, start, "nonce_hex"));
    let mut aad = hex(&field_from(&text, start, "aad_hex"));
    let plaintext = field_from(&text, start, "plaintext_utf8");

    let cipher = ChaCha20Poly1305::new(key.as_slice().into());
    let sealed = cipher
        .encrypt(
            nonce.as_slice().into(),
            Payload {
                msg: plaintext.as_bytes(),
                aad: &aad,
            },
        )
        .expect("encrypt");

    if let Some(first) = aad.first_mut() {
        *first ^= 0x01;
    }
    let opened = cipher.decrypt(
        nonce.as_slice().into(),
        Payload {
            msg: &sealed,
            aad: &aad,
        },
    );
    assert!(opened.is_err(), "a one-bit AAD change must fail the tag");
}

#[test]
fn x25519_matches_rfc_7748() {
    let text = vector_file();
    let start = section(&text, "x25519");
    let alice_private: [u8; 32] = hex(&field_from(&text, start, "alice_private_hex"))
        .try_into()
        .expect("32 bytes");
    let alice_public = hex(&field_from(&text, start, "alice_public_hex"));
    let bob_private: [u8; 32] = hex(&field_from(&text, start, "bob_private_hex"))
        .try_into()
        .expect("32 bytes");
    let bob_public = hex(&field_from(&text, start, "bob_public_hex"));
    let shared = hex(&field_from(&text, start, "shared_secret_hex"));

    let alice = StaticSecret::from(alice_private);
    let bob = StaticSecret::from(bob_private);

    // Each public key derives from its private key, so a mismatched pair cannot pass.
    assert_eq!(
        PublicKey::from(&alice).as_bytes().as_slice(),
        alice_public.as_slice(),
        "RFC 7748 Alice's public key"
    );
    assert_eq!(
        PublicKey::from(&bob).as_bytes().as_slice(),
        bob_public.as_slice(),
        "RFC 7748 Bob's public key"
    );

    let a_to_b = alice.diffie_hellman(&PublicKey::from(&bob));
    let b_to_a = bob.diffie_hellman(&PublicKey::from(&alice));
    assert_eq!(a_to_b.as_bytes().as_slice(), shared.as_slice());
    assert_eq!(b_to_a.as_bytes().as_slice(), shared.as_slice());
}

#[test]
fn argon2id_matches_rfc_9106() {
    let text = vector_file();
    let start = section(&text, "argon2id");
    let password = hex(&field_from(&text, start, "password_hex"));
    let salt = hex(&field_from(&text, start, "salt_hex"));
    let secret = hex(&field_from(&text, start, "secret_hex"));
    let associated = hex(&field_from(&text, start, "associated_data_hex"));
    let tag = hex(&field_from(&text, start, "tag_hex"));

    // Built directly: RFC 9106 uses m = 32 KiB, which `KdfParams::new` refuses under I4.
    let mut params = ParamsBuilder::new();
    params
        .m_cost(32)
        .t_cost(3)
        .p_cost(4)
        .output_len(tag.len())
        .data(AssociatedData::new(&associated).expect("associated data"));
    let params = params.build().expect("RFC 9106 parameters");

    let argon = Argon2::new_with_secret(&secret, Algorithm::Argon2id, Version::V0x13, params)
        .expect("argon2id with a secret");

    let mut out = vec![0_u8; tag.len()];
    argon
        .hash_password_into(&password, &salt, &mut out)
        .expect("hash");
    assert_eq!(out, tag, "RFC 9106 section 5.3 Argon2id tag");
}

#[test]
fn the_i4_floor_refuses_the_rfc_9106_parameters() {
    use chiavora_core::derive::{DeriveError, KdfParams};

    let refused = KdfParams::new(32, 3);
    assert!(
        matches!(refused, Err(DeriveError::BelowI4Floor)),
        "I4 must refuse m = 32 KiB; got {refused:?}"
    );
}
