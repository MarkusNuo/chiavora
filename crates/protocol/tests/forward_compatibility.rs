#![allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]

use chiavora_protocol::{Field, Record, WireError, WIRE_MAGIC, WIRE_VERSION};
use proptest::prelude::{any, prop, ProptestConfig};
use proptest::{prop_assert_eq, proptest};

/// Regression files off: proptest cannot place them under `tests/` and warns on every run.
fn config() -> ProptestConfig {
    ProptestConfig {
        failure_persistence: None,
        ..ProptestConfig::default()
    }
}

const TAG_NONCE: u16 = 0x0001;
const TAG_CIPHERTEXT: u16 = 0x0002;

const TAG_FUTURE_A: u16 = 0x7F01;
const TAG_FUTURE_B: u16 = 0x7F02;

fn field(tag: u16, value: &[u8]) -> Field {
    Field::new(tag, value.to_vec()).expect("field must build")
}

fn record_from_the_future() -> Vec<u8> {
    // Hand-assembled, because this build cannot write a v2 record.
    let mut out = Vec::new();
    out.extend_from_slice(WIRE_MAGIC);
    out.extend_from_slice(&2_u16.to_le_bytes());
    out.extend_from_slice(&4_u32.to_le_bytes());
    for (tag, value) in [
        (TAG_NONCE, b"nonce-bytes-24-long-xxxx".as_slice()),
        (
            TAG_FUTURE_A,
            b"a field this build has never heard of".as_slice(),
        ),
        (TAG_CIPHERTEXT, b"ciphertext".as_slice()),
        (TAG_FUTURE_B, b"another one".as_slice()),
    ] {
        out.extend_from_slice(&tag.to_le_bytes());
        out.extend_from_slice(&u32::try_from(value.len()).unwrap().to_le_bytes());
        out.extend_from_slice(value);
    }
    out
}

#[test]
fn a_record_this_build_wrote_round_trips_byte_identically() {
    let original = Record::new(vec![
        field(TAG_NONCE, b"nonce"),
        field(TAG_CIPHERTEXT, b"ciphertext"),
    ]);
    let bytes = original.encode().expect("must encode");
    let decoded = Record::decode(&bytes).expect("must decode");
    assert_eq!(decoded, original);
    assert_eq!(decoded.encode().expect("must re-encode"), bytes);
}

#[test]
fn a_record_from_a_newer_version_round_trips_byte_identically() {
    let bytes = record_from_the_future();
    let decoded = Record::decode(&bytes).expect("a newer version must be readable");
    assert_eq!(
        decoded.encode().expect("must re-encode"),
        bytes,
        "re-encoding a newer record must be byte-identical"
    );
}

#[test]
fn unknown_fields_survive_a_decode_encode_round_trip() {
    let bytes = record_from_the_future();
    let decoded = Record::decode(&bytes).expect("must decode");

    assert_eq!(decoded.fields().len(), 4, "no field may be dropped");
    assert_eq!(
        decoded.field(TAG_FUTURE_A).map(Field::value),
        Some(b"a field this build has never heard of".as_slice())
    );
    assert_eq!(
        decoded.field(TAG_FUTURE_B).map(Field::value),
        Some(b"another one".as_slice())
    );
}

#[test]
fn unknown_fields_survive_an_edit_in_their_original_order() {
    let bytes = record_from_the_future();
    let decoded = Record::decode(&bytes).expect("must decode");

    let edited = decoded
        .with_field(TAG_CIPHERTEXT, b"a new ciphertext".to_vec())
        .expect("editing a known field must succeed");

    let tags: Vec<u16> = edited.fields().iter().map(Field::tag).collect();
    assert_eq!(
        tags,
        vec![TAG_NONCE, TAG_FUTURE_A, TAG_CIPHERTEXT, TAG_FUTURE_B],
        "field order must be preserved across an edit"
    );
    assert_eq!(
        edited.field(TAG_FUTURE_A).map(Field::value),
        Some(b"a field this build has never heard of".as_slice())
    );
    assert_eq!(
        edited.field(TAG_CIPHERTEXT).map(Field::value),
        Some(b"a new ciphertext".as_slice())
    );
}

#[test]
fn an_edit_that_adds_a_field_appends_rather_than_reordering() {
    let bytes = record_from_the_future();
    let decoded = Record::decode(&bytes).expect("must decode");
    let edited = decoded
        .with_field(0x0003, b"new".to_vec())
        .expect("must edit");

    let tags: Vec<u16> = edited.fields().iter().map(Field::tag).collect();
    assert_eq!(
        tags,
        vec![
            TAG_NONCE,
            TAG_FUTURE_A,
            TAG_CIPHERTEXT,
            TAG_FUTURE_B,
            0x0003
        ]
    );
}

#[test]
fn an_edit_carries_a_newer_version_forward_rather_than_lowering_it() {
    let bytes = record_from_the_future();
    let decoded = Record::decode(&bytes).expect("must decode");
    assert_eq!(decoded.version(), 2);
    assert!(decoded.is_from_a_newer_version());

    let edited = decoded
        .with_field(TAG_CIPHERTEXT, b"edited".to_vec())
        .expect("must edit");
    assert_eq!(
        edited.version(),
        2,
        "an older client must not rewrite a v2 record as v{WIRE_VERSION}"
    );
    assert!(edited.is_from_a_newer_version());
}

#[test]
fn a_record_this_build_writes_carries_this_builds_version() {
    let record = Record::new(vec![field(TAG_NONCE, b"nonce")]);
    assert_eq!(record.version(), WIRE_VERSION);
    assert!(!record.is_from_a_newer_version());
}

#[test]
fn the_parser_refuses_malformed_records() {
    assert_eq!(Record::decode(b"XXXX"), Err(WireError::BadMagic));
    assert_eq!(Record::decode(b"CHVR"), Err(WireError::Truncated));

    // A field length longer than the remaining bytes.
    let mut lying = Vec::new();
    lying.extend_from_slice(WIRE_MAGIC);
    lying.extend_from_slice(&1_u16.to_le_bytes());
    lying.extend_from_slice(&1_u32.to_le_bytes());
    lying.extend_from_slice(&TAG_NONCE.to_le_bytes());
    lying.extend_from_slice(&0xFFFF_FFFF_u32.to_le_bytes());
    assert_eq!(Record::decode(&lying), Err(WireError::Truncated));

    let mut trailing = Record::new(vec![field(TAG_NONCE, b"n")])
        .encode()
        .expect("must encode");
    trailing.push(0);
    assert_eq!(Record::decode(&trailing), Err(WireError::TrailingBytes));
}

#[test]
fn a_field_count_larger_than_the_body_is_refused() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(WIRE_MAGIC);
    bytes.extend_from_slice(&1_u16.to_le_bytes());
    bytes.extend_from_slice(&1000_u32.to_le_bytes());
    assert_eq!(Record::decode(&bytes), Err(WireError::Truncated));
}

#[test]
fn an_empty_record_round_trips() {
    let empty = Record::new(Vec::new());
    let bytes = empty.encode().expect("must encode");
    assert_eq!(Record::decode(&bytes).expect("must decode"), empty);
}

#[test]
fn a_zero_length_field_is_distinct_from_an_absent_one() {
    let present = Record::new(vec![field(TAG_NONCE, b"")]);
    let absent = Record::new(Vec::new());
    assert_ne!(
        present.encode().expect("must encode"),
        absent.encode().expect("must encode")
    );
    assert_eq!(
        Record::decode(&present.encode().unwrap())
            .unwrap()
            .fields()
            .len(),
        1
    );
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn decode_never_panics_on_arbitrary_bytes(
        bytes in prop::collection::vec(any::<u8>(), 0..512)
    ) {
        let _ = Record::decode(&bytes);
    }

    #[test]
    fn arbitrary_records_round_trip(
        raw in prop::collection::vec(
            (any::<u16>(), prop::collection::vec(any::<u8>(), 0..64)),
            0..12,
        )
    ) {
        let fields: Vec<Field> = raw
            .into_iter()
            .map(|(tag, value)| Field::new(tag, value).expect("field must build"))
            .collect();
        let record = Record::new(fields);
        let bytes = record.encode().expect("must encode");
        let decoded = Record::decode(&bytes).expect("must decode");
        prop_assert_eq!(&decoded, &record);
        prop_assert_eq!(decoded.encode().expect("must re-encode"), bytes);
    }

    #[test]
    fn an_edit_preserves_every_other_field(
        raw in prop::collection::vec(
            (0x1000_u16..0x2000, prop::collection::vec(any::<u8>(), 0..32)),
            1..8,
        ),
        replacement in prop::collection::vec(any::<u8>(), 0..32),
    ) {
        let fields: Vec<Field> = raw
            .into_iter()
            .map(|(tag, value)| Field::new(tag, value).expect("field must build"))
            .collect();
        let record = Record::new(fields);
        let target = record.fields()[0].tag();

        if record.count_with(target) > 1 {
            prop_assert_eq!(
                record.with_field(target, replacement).err(),
                Some(WireError::AmbiguousTag(target))
            );
            return Ok(());
        }

        let edited = record.with_field(target, replacement).expect("must edit");

        // Compared by position, because comparing by tag is ambiguous for a repeated tag.
        let before: Vec<u16> = record.fields().iter().map(Field::tag).collect();
        let after: Vec<u16> = edited.fields().iter().map(Field::tag).collect();
        prop_assert_eq!(before, after);
        for (original, result) in record.fields().iter().zip(edited.fields()) {
            if original.tag() != target {
                prop_assert_eq!(original.value(), result.value());
            }
        }
    }
}

#[test]
fn a_repeated_tag_is_legal_to_read_and_round_trips() {
    let record = Record::new(vec![
        field(TAG_FUTURE_A, b"first"),
        field(TAG_NONCE, b"nonce"),
        field(TAG_FUTURE_A, b"second"),
    ]);
    let bytes = record.encode().expect("must encode");
    let decoded = Record::decode(&bytes).expect("a repeated tag must be readable");

    assert_eq!(decoded, record);
    assert_eq!(decoded.encode().expect("must re-encode"), bytes);
    assert_eq!(decoded.count_with(TAG_FUTURE_A), 2);

    let values: Vec<&[u8]> = decoded
        .fields_with(TAG_FUTURE_A)
        .map(Field::value)
        .collect();
    assert_eq!(values, vec![b"first".as_slice(), b"second".as_slice()]);
}

#[test]
fn editing_a_repeated_tag_is_refused_rather_than_guessed_at() {
    let record = Record::new(vec![
        field(TAG_FUTURE_A, b"first"),
        field(TAG_FUTURE_A, b"second"),
    ]);
    assert_eq!(
        record
            .with_field(TAG_FUTURE_A, b"replacement".to_vec())
            .err(),
        Some(WireError::AmbiguousTag(TAG_FUTURE_A))
    );
    assert_eq!(record.count_with(TAG_FUTURE_A), 2);
}

#[test]
fn editing_an_unambiguous_tag_in_a_record_that_has_repeats_elsewhere_is_fine() {
    let record = Record::new(vec![
        field(TAG_FUTURE_A, b"first"),
        field(TAG_NONCE, b"nonce"),
        field(TAG_FUTURE_A, b"second"),
    ]);
    let edited = record
        .with_field(TAG_NONCE, b"new nonce".to_vec())
        .expect("an unambiguous tag must still be editable");

    assert_eq!(
        edited.field(TAG_NONCE).map(Field::value),
        Some(b"new nonce".as_slice())
    );
    assert_eq!(edited.count_with(TAG_FUTURE_A), 2);
    let values: Vec<&[u8]> = edited.fields_with(TAG_FUTURE_A).map(Field::value).collect();
    assert_eq!(values, vec![b"first".as_slice(), b"second".as_slice()]);
}
