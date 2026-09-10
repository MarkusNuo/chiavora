#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::PathBuf;

use chiavora_core::aad::AadError;
use chiavora_core::derive::DeriveError;
use chiavora_core::emergency_kit::{Field, KitError};
use chiavora_core::entry::EntryError;
use chiavora_core::generate::GenerateError;
use chiavora_core::item::ItemError;
use chiavora_core::nonce::NonceError;
use chiavora_core::secret_key::SecretKeyError;
use chiavora_core::wrap::WrapError;
use chiavora_protocol::WireError;

const CANARIES: [&str; 5] = [
    "CHV1-0000-0000",
    "0000000000000000000000000000",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "correct-horse-battery-staple",
    "5a5a5a5a5a5a5a5a",
];

fn assert_clean(what: &str, display: &str, debug: &str) {
    for canary in CANARIES {
        assert!(
            !display.contains(canary),
            "{what}: Display leaked {canary:?} — {display}"
        );
        assert!(
            !debug.contains(canary),
            "{what}: Debug leaked {canary:?} — {debug}"
        );
    }
    assert!(
        !display.is_empty(),
        "{what}: Display is empty, so a log line would say nothing"
    );
}

macro_rules! check {
    ($($value:expr),+ $(,)?) => {
        $(
            {
                let v = $value;
                assert_clean(stringify!($value), &format!("{v}"), &format!("{v:?}"));
            }
        )+
    };
}

#[test]
fn no_aad_error_variant_carries_key_material() {
    check!(
        AadError::FieldTooLong,
        AadError::PrefixLenTooLarge,
        AadError::PrefixBitsNotCanonical,
        AadError::BadMagic,
        AadError::UnknownRecordType(0x99),
        AadError::UnknownWrapPurpose(0x99),
        AadError::Truncated,
        AadError::TrailingBytes,
    );
}

#[test]
fn no_derive_error_variant_carries_key_material() {
    check!(
        DeriveError::BelowI4Floor,
        DeriveError::Argon2Allocation,
        DeriveError::HkdfExpand,
    );
}

#[test]
fn no_kit_error_variant_carries_key_material() {
    check!(
        Field::AccountId,
        Field::AccountSalt,
        Field::SecretKey,
        Field::Checkpoint,
        KitError::WrongHeader,
        KitError::WrongLength { expected: 122 },
        KitError::BadPresenceFlag,
        KitError::WrongFieldLength,
        KitError::Entry(EntryError::Empty),
    );
    for field in [
        Field::AccountId,
        Field::AccountSalt,
        Field::SecretKey,
        Field::Checkpoint,
    ] {
        for cause in [
            chiavora_core::base32::Base32Error::WrongLength { expected: 28 },
            chiavora_core::base32::Base32Error::InvalidCharacter { at: 3 },
            chiavora_core::base32::Base32Error::NonCanonicalTrailingBits,
            chiavora_core::base32::Base32Error::ChecksumMismatch,
        ] {
            let e = KitError::BadField { field, cause };
            assert_clean("KitError::BadField", &format!("{e}"), &format!("{e:?}"));
        }
    }
}

#[test]
fn no_entry_error_variant_carries_key_material() {
    check!(
        EntryError::Empty,
        EntryError::TooLong { max: 4096 },
        EntryError::NormalizationUndecided,
        EntryError::SurroundingWhitespace,
        EntryError::SecretKeyFormat(SecretKeyError::ChecksumMismatch),
    );
}

#[test]
fn no_generate_error_variant_carries_key_material() {
    check!(
        GenerateError::ZeroLength,
        GenerateError::NoClasses,
        GenerateError::AlphabetEmptyAfterExclusions,
        GenerateError::LengthBelowClassCount,
        GenerateError::Csprng,
        GenerateError::AlphabetTooLarge,
        GenerateError::AlphabetIndexOutOfRange,
    );
}

#[test]
fn no_item_or_wrap_error_variant_carries_key_material() {
    check!(
        ItemError::BadItemKeyLength,
        ItemError::Aead,
        ItemError::Aad(AadError::BadMagic),
        ItemError::WrongRecordType(0x04),
        WrapError::BadWrappingKeyLength,
        WrapError::Aead,
        WrapError::Aad(AadError::BadMagic),
        WrapError::BadItemKeyLength,
        WrapError::I7Disagreement,
    );
}

#[test]
fn no_nonce_secret_key_or_wire_error_variant_carries_key_material() {
    check!(
        NonceError::Csprng,
        SecretKeyError::WrongPrefix,
        SecretKeyError::WrongLength { expected: 28 },
        SecretKeyError::InvalidCharacter { at: 7 },
        SecretKeyError::NonCanonicalTrailingBits,
        SecretKeyError::ChecksumMismatch,
        SecretKeyError::Csprng,
        WireError::BadMagic,
        WireError::Truncated,
        WireError::TrailingBytes,
        WireError::FieldTooLong,
        WireError::TooManyFields,
        WireError::AmbiguousTag(0x1234),
    );
}

#[test]
fn no_base32_error_variant_carries_key_material() {
    check!(
        chiavora_core::base32::Base32Error::WrongLength { expected: 28 },
        chiavora_core::base32::Base32Error::InvalidCharacter { at: 3 },
        chiavora_core::base32::Base32Error::NonCanonicalTrailingBits,
        chiavora_core::base32::Base32Error::ChecksumMismatch,
    );
}

// `CsprngError` is crate-private, so its conversions are tested inside the crate.

#[test]
fn the_variant_lists_match_the_source() {
    const EXPECTED: [(&str, &str, usize); 12] = [
        ("core/src/aad.rs", "AadError", 8),
        ("core/src/base32.rs", "Base32Error", 4),
        ("core/src/derive.rs", "DeriveError", 3),
        ("core/src/emergency_kit.rs", "KitError", 6),
        ("core/src/emergency_kit.rs", "Field", 4),
        ("core/src/entry.rs", "EntryError", 5),
        ("core/src/generate.rs", "GenerateError", 7),
        ("core/src/item.rs", "ItemError", 4),
        ("core/src/nonce.rs", "NonceError", 1),
        ("core/src/secret_key.rs", "SecretKeyError", 6),
        ("core/src/wrap.rs", "WrapError", 5),
        ("protocol/src/lib.rs", "WireError", 6),
    ];

    let mut root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    root.pop();
    root.pop();

    for (file, name, expected) in EXPECTED {
        let path = root.join("crates").join(file);
        let src = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
        let code = src.split("#[cfg(test)]").next().unwrap_or(&src);

        let start = code
            .find(&format!("pub enum {name} {{"))
            .unwrap_or_else(|| panic!("{file}: no `pub enum {name}`"));
        let body = code
            .get(start..)
            .and_then(|rest| rest.split("\n}").next())
            .unwrap_or_default();

        // A variant is a line at four spaces of indent beginning with a capital.
        let count = body
            .lines()
            .filter(|line| {
                line.starts_with("    ")
                    && !line.starts_with("     ")
                    && line
                        .trim_start()
                        .chars()
                        .next()
                        .is_some_and(char::is_uppercase)
            })
            .count();

        assert_eq!(
            count, expected,
            "{name} in {file} has {count} variants; this file checks \
             {expected}. Add the new variant to the list above — I1 says *no* \
             error message carries key material, and a variant nobody renders \
             is a variant nobody checked."
        );
    }
}
