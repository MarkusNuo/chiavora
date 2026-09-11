#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::PathBuf;

use chiavora_core::model::{migrate_forward, tag, Item, ItemField, ModelError, SCHEMA_VERSION};
use chiavora_core::wrap::ItemKind;
use chiavora_protocol::{Field, Record, Tag, WIRE_MAGIC, WIRE_VERSION};

const FUTURE_TAG: Tag = 0x7FF0;

fn root() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p
}

/// The `tag::FIELD` shape, `u16le(nameLen) ‖ name ‖ value`, built without the encoder.
fn field_bytes(name: &str, value: &[u8]) -> Vec<u8> {
    let mut out = u16::try_from(name.len()).unwrap().to_le_bytes().to_vec();
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(value);
    out
}

fn synthetic_v2_body() -> Record {
    Record::new(vec![
        Field::new(tag::SCHEMA_VERSION, 2_u16.to_le_bytes().to_vec()).unwrap(),
        Field::new(tag::KIND, b"login".to_vec()).unwrap(),
        Field::new(tag::FIELD, field_bytes("title", b"Example")).unwrap(),
        Field::new(
            FUTURE_TAG,
            b"something a v2 client knows and we do not".to_vec(),
        )
        .unwrap(),
        Field::new(tag::FIELD, field_bytes("username", b"ada")).unwrap(),
        Field::new(tag::TAG, b"work".to_vec()).unwrap(),
    ])
}

#[test]
fn a_newer_schema_is_read_and_reported_not_refused() {
    let item = Item::from_bytes(&synthetic_v2_body().encode().unwrap()).expect("readable");
    assert_eq!(item.schema_version(), 2);
    assert!(item.is_from_a_newer_schema());
    assert_eq!(item.kind(), ItemKind::Login);
    assert_eq!(item.fields().count(), 2);
    assert_eq!(item.unknown_fields().count(), 1);
}

#[test]
fn edit_and_re_encode_preserves_the_unknown_field_in_its_position() {
    let original = synthetic_v2_body();
    let mut item = Item::from_bytes(&original.encode().unwrap()).unwrap();

    item.set_field(ItemField::new("username", b"grace".to_vec()).unwrap());
    item.set_field(ItemField::new("password", b"hunter2".to_vec()).unwrap());

    let after = Record::decode(&item.to_bytes().unwrap()).unwrap();

    let tags: Vec<Tag> = after.fields().iter().map(Field::tag).collect();
    assert_eq!(
        tags,
        [
            tag::SCHEMA_VERSION,
            tag::KIND,
            tag::FIELD,
            FUTURE_TAG,
            tag::FIELD,
            tag::TAG,
            tag::FIELD // the appended `password`
        ],
        "field order changed across an edit"
    );
    assert_eq!(
        after.fields().get(3),
        original.fields().get(3),
        "the unknown field was not written back byte-for-byte"
    );

    assert_eq!(
        after.field(tag::SCHEMA_VERSION).unwrap().value(),
        &2_u16.to_le_bytes()[..],
        "the schema version was downgraded"
    );

    let again = Item::from_bytes(&after.encode().unwrap()).unwrap();
    assert_eq!(again.field("username").unwrap().value(), b"grace");
    assert_eq!(again.field("password").unwrap().value(), b"hunter2");
    assert_eq!(again.schema_version(), 2);
}

#[test]
fn removing_a_known_field_does_not_disturb_the_unknown_one() {
    let mut item = Item::from_bytes(&synthetic_v2_body().encode().unwrap()).unwrap();
    assert!(item.remove_field("title"));
    let after = Record::decode(&item.to_bytes().unwrap()).unwrap();
    let tags: Vec<Tag> = after.fields().iter().map(Field::tag).collect();
    assert_eq!(
        tags,
        [
            tag::SCHEMA_VERSION,
            tag::KIND,
            FUTURE_TAG,
            tag::FIELD,
            tag::TAG
        ]
    );
    assert_eq!(after.fields().get(2), synthetic_v2_body().fields().get(3));
}

#[test]
fn a_newer_wire_version_is_carried_forward_too() {
    // Hand-encoded, because `Record` has no constructor that takes a version.
    let inner = synthetic_v2_body();
    let count = u32::try_from(inner.fields().len()).unwrap();
    let mut bytes = WIRE_MAGIC.to_vec();
    bytes.extend_from_slice(&(WIRE_VERSION + 1).to_le_bytes());
    bytes.extend_from_slice(&count.to_le_bytes());
    for f in inner.fields() {
        bytes.extend_from_slice(&f.tag().to_le_bytes());
        bytes.extend_from_slice(&u32::try_from(f.value().len()).unwrap().to_le_bytes());
        bytes.extend_from_slice(f.value());
    }

    let mut item = Item::from_bytes(&bytes).expect("a newer wire version decodes");
    assert_eq!(item.wire_version(), WIRE_VERSION + 1);
    item.set_field(ItemField::new("password", b"hunter2".to_vec()).unwrap());
    let after = Record::decode(&item.to_bytes().unwrap()).unwrap();
    assert_eq!(
        after.version(),
        WIRE_VERSION + 1,
        "the wire version was downgraded"
    );
    assert!(after.is_from_a_newer_version());
}

#[test]
fn an_unknown_kind_is_refused_so_the_store_can_keep_it_opaque() {
    // A new kind decides the wrap count, so this build refuses it rather than guessing.
    let body = Record::new(vec![
        Field::new(tag::SCHEMA_VERSION, 2_u16.to_le_bytes().to_vec()).unwrap(),
        Field::new(tag::KIND, b"passkey".to_vec()).unwrap(),
    ]);
    let err = Item::from_bytes(&body.encode().unwrap()).unwrap_err();
    assert_eq!(err, ModelError::UnknownKind);
    assert!(Record::decode(&body.encode().unwrap()).is_ok());
}

#[test]
fn migrate_forward_leaves_a_newer_item_exactly_as_it_came() {
    let bytes = synthetic_v2_body().encode().unwrap();
    let item = Item::from_bytes(&bytes).unwrap();
    let migrated = migrate_forward(item).expect("a newer item is preserved, not migrated");
    assert_eq!(migrated.schema_version(), 2);
    assert_eq!(
        migrated.to_bytes().unwrap(),
        bytes,
        "preservation must be byte-exact"
    );
}

#[test]
fn no_error_from_a_malformed_body_carries_its_content() {
    const CANARY: &[u8] = b"correct-horse-battery-staple";
    let bodies: Vec<Record> = vec![
        // A FIELD too short to carry its declared name length.
        Record::new(vec![
            Field::new(tag::SCHEMA_VERSION, vec![1, 0]).unwrap(),
            Field::new(tag::KIND, b"note".to_vec()).unwrap(),
            Field::new(tag::FIELD, {
                let mut v = 200_u16.to_le_bytes().to_vec();
                v.extend_from_slice(CANARY);
                v
            })
            .unwrap(),
        ]),
        // A KIND that is not UTF-8, with the canary beside it.
        Record::new(vec![
            Field::new(tag::SCHEMA_VERSION, vec![1, 0]).unwrap(),
            Field::new(tag::KIND, vec![0xFF, 0xFE]).unwrap(),
            Field::new(tag::FIELD, field_bytes("password", CANARY)).unwrap(),
        ]),
        // A duplicate name, second occurrence carrying the canary.
        Record::new(vec![
            Field::new(tag::SCHEMA_VERSION, vec![1, 0]).unwrap(),
            Field::new(tag::KIND, b"note".to_vec()).unwrap(),
            Field::new(tag::FIELD, field_bytes("body", b"x")).unwrap(),
            Field::new(tag::FIELD, field_bytes("body", CANARY)).unwrap(),
        ]),
    ];
    for body in bodies {
        let err = Item::from_bytes(&body.encode().unwrap()).unwrap_err();
        let rendered = format!("{err} / {err:?}");
        assert!(
            !rendered.contains("correct-horse-battery-staple") && !rendered.contains("body"),
            "an error carried content: {rendered}"
        );
    }
}

#[test]
#[ignore = "writes fuzz/corpus/item_body_decode; run explicitly to regenerate the seeds"]
fn regenerate_item_body_corpus() {
    let dir = root().join("fuzz").join("corpus").join("item_body_decode");
    std::fs::create_dir_all(&dir).unwrap();

    let mut seeds: Vec<(String, Vec<u8>)> = Vec::new();

    for kind in ItemKind::ALL {
        let plain = Item::new(
            *kind,
            vec![
                ItemField::new("title", format!("A {}", kind.tag()).into_bytes()).unwrap(),
                ItemField::new("username", b"ada".to_vec()).unwrap(),
                ItemField::new("url", b"https://example.test".to_vec()).unwrap(),
            ],
            &[],
        )
        .unwrap();
        seeds.push((
            format!("seed-{}-plain", kind.tag().replace(' ', "_")),
            plain.to_bytes().unwrap(),
        ));
        let tagged = Item::new(
            *kind,
            vec![ItemField::new("title", b"T".to_vec()).unwrap()],
            &["work", "shared"],
        )
        .unwrap();
        seeds.push((
            format!("seed-{}-tagged", kind.tag().replace(' ', "_")),
            tagged.to_bytes().unwrap(),
        ));
    }
    seeds.push((
        "seed-v2-unknown-field".into(),
        synthetic_v2_body().encode().unwrap(),
    ));
    let mut edited = Item::from_bytes(&synthetic_v2_body().encode().unwrap()).unwrap();
    edited.set_field(ItemField::new("password", b"hunter2".to_vec()).unwrap());
    seeds.push(("seed-v2-edited".into(), edited.to_bytes().unwrap()));
    seeds.push((
        "seed-headers-only".into(),
        Item::new(ItemKind::Note, vec![], &[])
            .unwrap()
            .to_bytes()
            .unwrap(),
    ));

    assert!(seeds.len() >= 10, "R7: at least ten seeds");
    for (name, bytes) in seeds {
        std::fs::write(dir.join(name), bytes).unwrap();
    }
    let _ = SCHEMA_VERSION;
}
