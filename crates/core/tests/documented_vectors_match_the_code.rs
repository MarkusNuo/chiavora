#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::PathBuf;

use chiavora_core::aad::{self, AadFields, WRAP_PURPOSE_AUTOFILL, WRAP_PURPOSE_VAULT};
use chiavora_protocol::{Field, Record};

fn root() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p
}

fn read(rel: &str) -> String {
    let path = root().join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut acc, b| {
        let _ = write!(acc, "{b:02x}");
        acc
    })
}

fn documented_vectors() -> Vec<(&'static str, AadFields)> {
    vec![
        (
            "0x01 item payload",
            AadFields::ItemPayload {
                vault_id: b"ab".to_vec(),
                item_id: b"c".to_vec(),
                version: 1,
                content_type: b"login".to_vec(),
            },
        ),
        (
            "0x02 attachment chunk",
            AadFields::AttachmentChunk {
                vault_id: b"ab".to_vec(),
                item_id: b"c".to_vec(),
                version: 1,
                attachment_id: b"at".to_vec(),
                chunk_index: 0,
                chunk_count: 2,
                content_type: b"application/pdf".to_vec(),
            },
        ),
        (
            "0x03 manifest root",
            AadFields::ManifestRoot {
                vault_id: b"ab".to_vec(),
                manifest_seq: 7,
                vault_key_epoch: 1,
                segment_count: 4,
            },
        ),
        (
            "0x04 manifest segment",
            AadFields::ManifestSegment {
                vault_id: b"ab".to_vec(),
                segment_seq: 7,
                vault_key_epoch: 1,
                prefix_len: 2,
                prefix_bits: 0xC000_0000_0000_0000,
            },
        ),
        (
            "0x05 wrapped Item Key, vault purpose",
            AadFields::WrappedItemKey {
                vault_id: b"ab".to_vec(),
                item_id: b"c".to_vec(),
                wrap_purpose: WRAP_PURPOSE_VAULT,
            },
        ),
        (
            "0x06 sealed Vault Key",
            AadFields::SealedVaultKey {
                vault_id: b"ab".to_vec(),
                vault_key_epoch: 1,
                recipient_public_key: b"pk".to_vec(),
            },
        ),
        (
            "0x07 wrapped Autofill Key",
            AadFields::WrappedAutofillKey {
                vault_id: b"ab".to_vec(),
                vault_key_epoch: 1,
            },
        ),
        (
            "0x08 wrapped account private key",
            AadFields::WrappedAccountKey {
                account_id: b"ad".to_vec(),
                account_key_epoch: 1,
            },
        ),
    ]
}

#[test]
fn every_documented_aad_vector_is_what_the_encoder_produces() {
    let doc = read("docs/crypto.md");
    let mut missing = Vec::new();
    for (name, fields) in documented_vectors() {
        let encoded = aad::encode(&fields).unwrap_or_else(|e| panic!("{name}: {e}"));
        let rendered = hex(&encoded);
        if !doc.contains(&rendered) {
            missing.push(format!("{name}\n    {rendered}"));
        }
    }
    assert!(
        missing.is_empty(),
        "docs/crypto.md does not contain these encodings:\n  {}",
        missing.join("\n  ")
    );
}

#[test]
fn the_two_wrap_purposes_encode_differently_and_both_are_documented() {
    let vault = aad::encode(&AadFields::WrappedItemKey {
        vault_id: b"ab".to_vec(),
        item_id: b"c".to_vec(),
        wrap_purpose: WRAP_PURPOSE_VAULT,
    })
    .expect("vault wrap");
    let autofill = aad::encode(&AadFields::WrappedItemKey {
        vault_id: b"ab".to_vec(),
        item_id: b"c".to_vec(),
        wrap_purpose: WRAP_PURPOSE_AUTOFILL,
    })
    .expect("autofill wrap");
    assert_ne!(vault, autofill);

    let doc = read("docs/crypto.md");
    assert!(doc.contains(&hex(&autofill)), "{}", hex(&autofill));
}

#[test]
fn the_documented_wire_record_is_what_the_encoder_produces() {
    let record = Record::new(vec![
        Field::new(1, b"ab".to_vec()).expect("a short field"),
        Field::new(2, b"c".to_vec()).expect("a short field"),
    ]);
    let encoded = record.encode().expect("encodes");
    let doc = read("docs/crypto.md");
    assert!(
        doc.contains(&hex(&encoded)),
        "docs/crypto.md does not contain the documented wire record:\n  {}",
        hex(&encoded)
    );
}

#[test]
fn the_document_names_all_five_record_types() {
    let doc = read("docs/crypto.md");
    for phrase in [
        "`0x01`",
        "`0x02`",
        "`0x03`",
        "`0x04`",
        "`0x05`",
        "wrapPurpose",
    ] {
        assert!(
            doc.contains(phrase),
            "docs/crypto.md does not mention {phrase}"
        );
    }
}
