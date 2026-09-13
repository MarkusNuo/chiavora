#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::PathBuf;

use chiavora_core::aad::AadError;
use chiavora_core::attachment::AttachmentError;
use chiavora_core::derive::DeriveError;
use chiavora_core::emergency_kit::{Field, KitError};
use chiavora_core::entry::EntryError;
use chiavora_core::export::ExportError;
use chiavora_core::generate::GenerateError;
use chiavora_core::import::ImportError;
use chiavora_core::item::ItemError;
use chiavora_core::model::ModelError;
use chiavora_core::nonce::NonceError;
use chiavora_core::secret_key::SecretKeyError;
use chiavora_core::store::StoreError;
use chiavora_core::stored_record::StoredRecordError;
use chiavora_core::wrap::WrapError;
use chiavora_core::zip::ZipError;
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
        EntryError::NotUtf8,
        EntryError::ControlCharacter,
        EntryError::UnassignedCodePoint,
        EntryError::SecretKeyFormat(SecretKeyError::ChecksumMismatch),
        // Raised by input that is key material, so it must not describe the input.
        EntryError::PastedKeyMaterial,
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
        GenerateError::TooLong { max: 128 },
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
        WrapError::MissingAutofillWrap,
        WrapError::UnexpectedAutofillWrap,
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
fn no_model_error_variant_carries_key_material() {
    check!(
        ModelError::Empty,
        ModelError::TooLong { max: 256 },
        ModelError::NotText,
        ModelError::DuplicateField { at: 3 },
        ModelError::UnknownKind,
        ModelError::MissingHeader { tag: 2 },
        ModelError::RepeatedHeader { at: 2 },
        ModelError::Malformed { at: 4 },
        ModelError::UnsupportedSchemaVersion,
        ModelError::NameTooLongForWire,
        ModelError::Wire(WireError::Truncated),
    );
}

#[test]
fn no_store_error_variant_carries_key_material() {
    use chiavora_core::derive::DeriveError;
    check!(
        StoreError::Database(rusqlite::Error::QueryReturnedNoRows),
        StoreError::MetadataTampered,
        StoreError::MetadataRewound {
            stored: 3,
            anchor: 5
        },
        StoreError::MetadataMissing,
        StoreError::MetadataMalformed,
        StoreError::UnsupportedStoreSchema { found: 2 },
        StoreError::HighWaterMarkDecrease {
            current: 9,
            proposed: 8
        },
        StoreError::VersionOutOfRange,
        StoreError::Derive(DeriveError::HkdfExpand),
        StoreError::Wire(WireError::Truncated),
        StoreError::AnchorFailed,
        StoreError::MacKeyLength,
    );
}

#[test]
fn no_stored_record_error_variant_carries_key_material() {
    check!(
        StoredRecordError::Wire(WireError::Truncated),
        StoredRecordError::Aad(AadError::BadMagic),
        StoredRecordError::Wrap(WrapError::MissingAutofillWrap),
        StoredRecordError::MissingField { tag: 2 },
        StoredRecordError::RepeatedField { at: 1 },
        StoredRecordError::Malformed { at: 2 },
        StoredRecordError::NotAnItemPayload,
        StoredRecordError::UnknownKind,
    );
}

#[test]
fn no_attachment_error_variant_carries_key_material() {
    check!(
        AttachmentError::TooLarge { max: 100 << 20 },
        AttachmentError::Empty,
        AttachmentError::ContentTypeTooLong { max: 256 },
        AttachmentError::LengthMismatch {
            declared: 3,
            read: 2
        },
        AttachmentError::ChunkLength { at: 1 },
        AttachmentError::ChunkMissing { at: 2 },
        AttachmentError::ChunkBinding { at: 0 },
        AttachmentError::ExtraChunks,
        AttachmentError::Io(std::io::Error::other("a canary-free os message")),
        AttachmentError::Store(StoreError::MetadataTampered),
        AttachmentError::Payload(ItemError::Aead),
        AttachmentError::Aad(AadError::BadMagic),
        AttachmentError::Wire(WireError::Truncated),
        AttachmentError::Nonce(NonceError::Csprng),
        AttachmentError::NotAnAttachmentChunk,
        AttachmentError::MissingField { tag: 1 },
        AttachmentError::RepeatedField { at: 1 },
        AttachmentError::Malformed { at: 2 },
    );
}

#[test]
fn no_zip_or_import_error_variant_carries_key_material() {
    check!(
        ZipError::NoEndOfCentralDirectory,
        ZipError::Malformed { at: 7 },
        ZipError::CentralDirectoryTooLarge { max: 64 << 20 },
        ZipError::Zip64Unsupported { at: 9 },
        ZipError::TooManyEntries { max: 10_000 },
        ZipError::EntryTooLarge { entry: 1, max: 5 },
        ZipError::TotalTooLarge { entry: 2, max: 6 },
        ZipError::RatioTooHigh { entry: 3, max: 100 },
        ZipError::PathTraversal { entry: 4 },
        ZipError::Symlink { entry: 5 },
        ZipError::NestedArchive { entry: 6 },
        ZipError::Encrypted { entry: 7 },
        ZipError::UnsupportedMethod {
            entry: 8,
            method: 12
        },
        ZipError::SizeMismatch { entry: 9 },
        ZipError::CrcMismatch { entry: 10 },
        ZipError::Inflate { entry: 11 },
        ZipError::Refused { entry: 12 },
        ZipError::NoSuchEntry { entry: 13 },
        ZipError::IsDirectory { entry: 14 },
        ZipError::TooLargeForTarget { bytes: 1 },
        ZipError::Io(std::io::ErrorKind::Other),
        ImportError::Zip(ZipError::NoEndOfCentralDirectory),
        ImportError::Io(std::io::ErrorKind::UnexpectedEof),
        ImportError::MissingMember,
        ImportError::Json { line: 1, column: 2 },
        ImportError::NotTheExpectedShape,
        ImportError::RecordTooLong {
            at: 0,
            max: 16 << 20
        },
        ImportError::Model {
            at: 1,
            error: ModelError::UnknownKind
        },
        ImportError::AttachmentTooLarge { max: 100 << 20 },
        ImportError::EncryptedExport,
        ImportError::TooManyFields { at: 3, max: 256 },
        ImportError::DocumentTooLarge { max: 256 << 20 },
    );
}

#[test]
fn no_export_error_variant_carries_key_material() {
    check!(
        ExportError::Store(StoreError::MetadataTampered),
        ExportError::Derive(DeriveError::HkdfExpand),
        ExportError::Wire(WireError::Truncated),
        ExportError::Io(std::io::ErrorKind::Other),
        ExportError::MacKeyLength,
        ExportError::BadMagic,
        ExportError::UnsupportedVersion { version: 2 },
        ExportError::Truncated { at: 9 },
        ExportError::EntryTooLarge {
            at: 1,
            max: 16 << 20
        },
        ExportError::UnknownEntryKind { at: 2, kind: 7 },
        ExportError::MissingField { at: 3, tag: 6 },
        ExportError::Malformed { at: 4 },
        ExportError::MacMismatch,
        ExportError::CountMismatch {
            declared: 1,
            found: 0
        },
        ExportError::TrailingBytes { at: 5 },
        ExportError::StoreNotFresh,
        ExportError::Vanished { at: 0 },
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
    // The lists above are hand-written; a variant added without a row here fails.
    const EXPECTED: [(&str, &str, usize); 19] = [
        ("core/src/aad.rs", "AadError", 8),
        ("core/src/attachment.rs", "AttachmentError", 18),
        ("core/src/base32.rs", "Base32Error", 4),
        ("core/src/derive.rs", "DeriveError", 3),
        ("core/src/emergency_kit.rs", "KitError", 6),
        ("core/src/emergency_kit.rs", "Field", 4),
        ("core/src/entry.rs", "EntryError", 7),
        ("core/src/export.rs", "ExportError", 17),
        ("core/src/generate.rs", "GenerateError", 8),
        ("core/src/import.rs", "ImportError", 11),
        ("core/src/item.rs", "ItemError", 4),
        ("core/src/model.rs", "ModelError", 11),
        ("core/src/nonce.rs", "NonceError", 1),
        ("core/src/secret_key.rs", "SecretKeyError", 6),
        ("core/src/wrap.rs", "WrapError", 7),
        ("core/src/zip.rs", "ZipError", 21),
        ("core/src/store.rs", "StoreError", 12),
        ("core/src/stored_record.rs", "StoredRecordError", 8),
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
