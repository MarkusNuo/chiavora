#![allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]

use chiavora_core::aad::{
    decode, encode, AadError, AadFields, MAX_PREFIX_LEN, RECORD_ATTACHMENT_CHUNK,
    RECORD_ITEM_PAYLOAD, RECORD_MANIFEST_ROOT, RECORD_MANIFEST_SEGMENT, RECORD_WRAPPED_ITEM_KEY,
    WRAP_PURPOSE_AUTOFILL, WRAP_PURPOSE_VAULT,
};
use proptest::prelude::{any, prop, ProptestConfig, Strategy};
use proptest::{prop_assert, prop_assert_eq, prop_assume, proptest};

/// Regression files are off: proptest cannot place them beside a test in `tests/`.
fn config() -> ProptestConfig {
    ProptestConfig {
        failure_persistence: None,
        ..ProptestConfig::default()
    }
}

fn var_field() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..24)
}

fn canonical_prefix() -> impl Strategy<Value = (u8, u64)> {
    (0_u8..=MAX_PREFIX_LEN, any::<u64>()).prop_map(|(len, bits)| {
        // A match, because `u64::MAX >> 64` overflows.
        let keep = match len {
            0 => 0,
            MAX_PREFIX_LEN => u64::MAX,
            n => !(u64::MAX >> n),
        };
        (len, bits & keep)
    })
}

fn item_payload() -> impl Strategy<Value = AadFields> {
    (var_field(), var_field(), any::<u64>(), var_field()).prop_map(
        |(vault_id, item_id, version, content_type)| AadFields::ItemPayload {
            vault_id,
            item_id,
            version,
            content_type,
        },
    )
}

fn attachment_chunk() -> impl Strategy<Value = AadFields> {
    (
        var_field(),
        var_field(),
        any::<u64>(),
        var_field(),
        any::<u32>(),
        any::<u32>(),
        var_field(),
    )
        .prop_map(
            |(
                vault_id,
                item_id,
                version,
                attachment_id,
                chunk_index,
                chunk_count,
                content_type,
            )| AadFields::AttachmentChunk {
                vault_id,
                item_id,
                version,
                attachment_id,
                chunk_index,
                chunk_count,
                content_type,
            },
        )
}

fn manifest_root() -> impl Strategy<Value = AadFields> {
    (var_field(), any::<u64>(), any::<u32>(), any::<u32>()).prop_map(
        |(vault_id, manifest_seq, vault_key_epoch, segment_count)| AadFields::ManifestRoot {
            vault_id,
            manifest_seq,
            vault_key_epoch,
            segment_count,
        },
    )
}

fn manifest_segment() -> impl Strategy<Value = AadFields> {
    (var_field(), any::<u64>(), any::<u32>(), canonical_prefix()).prop_map(
        |(vault_id, segment_seq, vault_key_epoch, (prefix_len, prefix_bits))| {
            AadFields::ManifestSegment {
                vault_id,
                segment_seq,
                vault_key_epoch,
                prefix_len,
                prefix_bits,
            }
        },
    )
}

fn wrapped_item_key() -> impl Strategy<Value = AadFields> {
    (
        var_field(),
        var_field(),
        prop::sample::select(vec![WRAP_PURPOSE_VAULT, WRAP_PURPOSE_AUTOFILL]),
    )
        .prop_map(
            |(vault_id, item_id, wrap_purpose)| AadFields::WrappedItemKey {
                vault_id,
                item_id,
                wrap_purpose,
            },
        )
}

fn any_record() -> impl Strategy<Value = AadFields> {
    prop::strategy::Union::new(vec![
        item_payload().boxed(),
        attachment_chunk().boxed(),
        manifest_root().boxed(),
        manifest_segment().boxed(),
        wrapped_item_key().boxed(),
    ])
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn i3_decode_after_encode_is_identity(fields in any_record()) {
        let bytes = encode(&fields).expect("canonical fields must encode");
        let round = decode(&bytes).expect("our own encoding must decode");
        prop_assert_eq!(fields, round);
    }

    #[test]
    fn i3_encode_after_decode_is_identity(fields in any_record()) {
        let bytes = encode(&fields).expect("canonical fields must encode");
        let round = decode(&bytes).expect("our own encoding must decode");
        let again = encode(&round).expect("decoded fields must re-encode");
        prop_assert_eq!(bytes, again);
    }
}

#[test]
fn i3_every_record_type_round_trips_at_least_once() {
    let cases = [
        AadFields::ItemPayload {
            vault_id: b"vault".to_vec(),
            item_id: b"item".to_vec(),
            version: 7,
            content_type: b"login".to_vec(),
        },
        AadFields::AttachmentChunk {
            vault_id: b"vault".to_vec(),
            item_id: b"item".to_vec(),
            version: 7,
            attachment_id: b"att".to_vec(),
            chunk_index: 2,
            chunk_count: 5,
            content_type: b"image/png".to_vec(),
        },
        AadFields::ManifestRoot {
            vault_id: b"vault".to_vec(),
            manifest_seq: 42,
            vault_key_epoch: 1,
            segment_count: 3,
        },
        AadFields::ManifestSegment {
            vault_id: b"vault".to_vec(),
            segment_seq: 41,
            vault_key_epoch: 1,
            prefix_len: 3,
            prefix_bits: 0xE000_0000_0000_0000,
        },
        AadFields::WrappedItemKey {
            vault_id: b"vault".to_vec(),
            item_id: b"item".to_vec(),
            wrap_purpose: WRAP_PURPOSE_VAULT,
        },
    ];
    let seen: Vec<u8> = cases.iter().map(AadFields::record_type).collect();

    assert_eq!(
        seen,
        vec![
            RECORD_ITEM_PAYLOAD,
            RECORD_ATTACHMENT_CHUNK,
            RECORD_MANIFEST_ROOT,
            RECORD_MANIFEST_SEGMENT,
            RECORD_WRAPPED_ITEM_KEY
        ]
    );
    for fields in cases {
        let bytes = encode(&fields).expect("must encode");
        assert_eq!(decode(&bytes).expect("must decode"), fields);
    }
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn i3_distinct_tuples_never_collide(a in any_record(), b in any_record()) {
        prop_assume!(a != b);
        let ea = encode(&a).expect("must encode");
        let eb = encode(&b).expect("must encode");
        prop_assert!(ea != eb, "I3 violated: distinct tuples produced identical AAD");
    }
}

#[test]
fn i3_the_footgun_the_design_names_does_not_collide() {
    // §2.2's example: under plain concatenation, ("ab", "c") and ("a", "bc") would collide.
    let left = AadFields::ItemPayload {
        vault_id: b"ab".to_vec(),
        item_id: b"c".to_vec(),
        version: 1,
        content_type: b"t".to_vec(),
    };
    let right = AadFields::ItemPayload {
        vault_id: b"a".to_vec(),
        item_id: b"bc".to_vec(),
        version: 1,
        content_type: b"t".to_vec(),
    };
    assert_ne!(
        encode(&left).expect("must encode"),
        encode(&right).expect("must encode"),
        "§2.2's canonicalisation footgun is not closed"
    );
}

#[test]
fn i3_record_types_do_not_collide_across_otherwise_identical_fields() {
    let root = AadFields::ManifestRoot {
        vault_id: b"v".to_vec(),
        manifest_seq: 1,
        vault_key_epoch: 0,
        segment_count: 0,
    };
    let segment = AadFields::ManifestSegment {
        vault_id: b"v".to_vec(),
        segment_seq: 1,
        vault_key_epoch: 0,
        prefix_len: 0,
        prefix_bits: 0,
    };
    assert_ne!(
        encode(&root).expect("must encode"),
        encode(&segment).expect("must encode")
    );
}

#[test]
fn i3_chunk_reorder_and_transplant_change_the_aad() {
    let base = AadFields::AttachmentChunk {
        vault_id: b"v".to_vec(),
        item_id: b"i".to_vec(),
        version: 1,
        attachment_id: b"a1".to_vec(),
        chunk_index: 0,
        chunk_count: 4,
        content_type: b"t".to_vec(),
    };
    let encoded = encode(&base).expect("must encode");

    let mut reordered = base.clone();
    if let AadFields::AttachmentChunk {
        ref mut chunk_index,
        ..
    } = reordered
    {
        *chunk_index = 1;
    }
    let mut transplanted = base.clone();
    if let AadFields::AttachmentChunk {
        ref mut attachment_id,
        ..
    } = transplanted
    {
        *attachment_id = b"a2".to_vec();
    }
    let mut recounted = base;
    if let AadFields::AttachmentChunk {
        ref mut chunk_count,
        ..
    } = recounted
    {
        *chunk_count = 5;
    }

    for (name, other) in [
        ("reordered within the attachment", reordered),
        ("transplanted between attachments", transplanted),
        ("chunk count altered", recounted),
    ] {
        assert_ne!(
            encoded,
            encode(&other).expect("must encode"),
            "AAD unchanged when a chunk was {name}"
        );
    }
}

#[test]
fn prefix_len_above_64_is_refused_on_encode() {
    // §2.2 canonicalisation rule 1. The u8 field permits 255; prefixBits is u64.
    for bad_len in [65_u8, 100, 255] {
        let fields = AadFields::ManifestSegment {
            vault_id: b"v".to_vec(),
            segment_seq: 1,
            vault_key_epoch: 0,
            prefix_len: bad_len,
            prefix_bits: 0,
        };
        assert_eq!(
            encode(&fields),
            Err(AadError::PrefixLenTooLarge),
            "len {bad_len}"
        );
    }
}

#[test]
fn prefix_bits_with_dirty_low_bits_is_refused_on_encode() {
    // §2.2 canonicalisation rule 2: at prefixLen = 1 this is the same segment as 0x8000…0000.
    let fields = AadFields::ManifestSegment {
        vault_id: b"v".to_vec(),
        segment_seq: 1,
        vault_key_epoch: 0,
        prefix_len: 1,
        prefix_bits: 0x8000_0000_0000_0001,
    };
    assert_eq!(encode(&fields), Err(AadError::PrefixBitsNotCanonical));
}

#[test]
fn prefix_len_zero_requires_prefix_bits_zero() {
    let ok = AadFields::ManifestSegment {
        vault_id: b"v".to_vec(),
        segment_seq: 1,
        vault_key_epoch: 0,
        prefix_len: 0,
        prefix_bits: 0,
    };
    assert!(encode(&ok).is_ok());

    let bad = AadFields::ManifestSegment {
        vault_id: b"v".to_vec(),
        segment_seq: 1,
        vault_key_epoch: 0,
        prefix_len: 0,
        prefix_bits: 1,
    };
    assert_eq!(encode(&bad), Err(AadError::PrefixBitsNotCanonical));
}

#[test]
fn prefix_len_64_permits_every_bit() {
    let fields = AadFields::ManifestSegment {
        vault_id: b"v".to_vec(),
        segment_seq: 1,
        vault_key_epoch: 0,
        prefix_len: MAX_PREFIX_LEN,
        prefix_bits: u64::MAX,
    };
    assert!(encode(&fields).is_ok());
}

#[test]
fn non_canonical_prefixes_are_refused_on_decode_too() {
    // Built by hand, since the encoder will not produce it.
    let mut bytes = encode(&AadFields::ManifestSegment {
        vault_id: b"v".to_vec(),
        segment_seq: 1,
        vault_key_epoch: 0,
        prefix_len: 1,
        prefix_bits: 0x8000_0000_0000_0000,
    })
    .expect("canonical segment must encode");

    // Last 8 bytes are prefix_bits little-endian; set the lowest bit.
    let n = bytes.len();
    bytes[n - 8] |= 1;
    assert_eq!(decode(&bytes), Err(AadError::PrefixBitsNotCanonical));

    // And an over-long prefix_len, one byte earlier.
    let mut bytes = encode(&AadFields::ManifestSegment {
        vault_id: b"v".to_vec(),
        segment_seq: 1,
        vault_key_epoch: 0,
        prefix_len: 1,
        prefix_bits: 0x8000_0000_0000_0000,
    })
    .expect("canonical segment must encode");
    let n = bytes.len();
    bytes[n - 9] = 65;
    assert_eq!(decode(&bytes), Err(AadError::PrefixLenTooLarge));
}

#[test]
fn decode_refuses_bad_magic_unknown_type_truncation_and_trailing_bytes() {
    assert_eq!(decode(b"XXXX\x01"), Err(AadError::BadMagic));
    assert_eq!(decode(b"CHV1\x09"), Err(AadError::UnknownRecordType(0x09)));
    assert_eq!(decode(b"CHV1"), Err(AadError::Truncated));

    let mut trailing = encode(&AadFields::ManifestRoot {
        vault_id: b"v".to_vec(),
        manifest_seq: 1,
        vault_key_epoch: 0,
        segment_count: 0,
    })
    .expect("must encode");
    trailing.push(0);
    assert_eq!(decode(&trailing), Err(AadError::TrailingBytes));
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn decode_never_panics_on_arbitrary_bytes(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
        let _ = decode(&bytes);
    }

    #[test]
    fn truncated_encodings_are_refused(fields in any_record(), cut in 0_usize..64) {
        let bytes = encode(&fields).expect("must encode");
        prop_assume!(cut < bytes.len());
        let truncated = &bytes[..cut];
        if let Ok(decoded) = decode(truncated) {
            prop_assert_eq!(
                encode(&decoded).expect("must re-encode"),
                truncated.to_vec(),
                "a truncated encoding decoded to fields that re-encode differently"
            );
        }
    }
}

#[test]
fn the_two_wrap_purposes_do_not_collide() {
    // If these collided, a wrap could be moved between the Vault-Key and Autofill-Key slots.
    let vault = AadFields::WrappedItemKey {
        vault_id: b"v".to_vec(),
        item_id: b"i".to_vec(),
        wrap_purpose: WRAP_PURPOSE_VAULT,
    };
    let autofill = AadFields::WrappedItemKey {
        vault_id: b"v".to_vec(),
        item_id: b"i".to_vec(),
        wrap_purpose: WRAP_PURPOSE_AUTOFILL,
    };
    assert_ne!(
        encode(&vault).expect("must encode"),
        encode(&autofill).expect("must encode")
    );
}

#[test]
fn an_undefined_wrap_purpose_is_refused_on_encode_and_decode() {
    for bad in [0x00_u8, 0x03, 0xFF] {
        let fields = AadFields::WrappedItemKey {
            vault_id: b"v".to_vec(),
            item_id: b"i".to_vec(),
            wrap_purpose: bad,
        };
        assert_eq!(
            encode(&fields),
            Err(AadError::UnknownWrapPurpose(bad)),
            "purpose {bad:#04x} must be refused on encode"
        );
    }

    // On decode, built by hand since the encoder will not produce it.
    let mut bytes = encode(&AadFields::WrappedItemKey {
        vault_id: b"v".to_vec(),
        item_id: b"i".to_vec(),
        wrap_purpose: WRAP_PURPOSE_VAULT,
    })
    .expect("must encode");
    let last = bytes.len() - 1;
    bytes[last] = 0x03;
    assert_eq!(decode(&bytes), Err(AadError::UnknownWrapPurpose(0x03)));
}

#[test]
fn a_wrapped_key_does_not_collide_with_the_payload_of_the_same_item() {
    let payload = AadFields::ItemPayload {
        vault_id: b"v".to_vec(),
        item_id: b"i".to_vec(),
        version: 0,
        content_type: Vec::new(),
    };
    let wrapped = AadFields::WrappedItemKey {
        vault_id: b"v".to_vec(),
        item_id: b"i".to_vec(),
        wrap_purpose: WRAP_PURPOSE_VAULT,
    };
    assert_ne!(
        encode(&payload).expect("must encode"),
        encode(&wrapped).expect("must encode")
    );
}

#[test]
fn the_wrapped_key_binding_is_length_prefixed() {
    let left = AadFields::WrappedItemKey {
        vault_id: b"ab".to_vec(),
        item_id: b"c".to_vec(),
        wrap_purpose: WRAP_PURPOSE_VAULT,
    };
    let right = AadFields::WrappedItemKey {
        vault_id: b"a".to_vec(),
        item_id: b"bc".to_vec(),
        wrap_purpose: WRAP_PURPOSE_VAULT,
    };
    assert_ne!(
        encode(&left).expect("must encode"),
        encode(&right).expect("must encode")
    );
}
