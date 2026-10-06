#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::io::Cursor;
use std::path::PathBuf;

use chiavora_core::chrome;
use chiavora_core::export::{self, ExportError, MAX_ENTRY_BYTES};
use chiavora_core::import::{parse_json, FIELD_NOTES, FIELD_PASSWORD};
use chiavora_core::model::{Item, ItemField, FIELD_TITLE, FIELD_URL, FIELD_USERNAME};
use chiavora_core::secret::{kind::Muk, Secret};
use chiavora_core::store::{Store, Unanchored};
use chiavora_core::wrap::ItemKind;

const VAULT: &[u8] = b"vault-1";

fn muk() -> Secret<Muk> {
    Secret::<Muk>::from_derived_bytes(vec![0x4D; 32])
}

fn other_muk() -> Secret<Muk> {
    Secret::<Muk>::from_derived_bytes(vec![0x5E; 32])
}

fn opaque(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed | 1;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            u8::try_from(state & 0xFF).unwrap()
        })
        .collect()
}

fn populated() -> Store {
    let mut store = Store::open_in_memory(&muk(), Box::new(Unanchored)).unwrap();
    store.put_raw(VAULT, b"item-a", 3, &opaque(1, 700)).unwrap();
    store.put_raw(VAULT, b"item-b", 12, &opaque(2, 40)).unwrap();
    store
        .put_raw(VAULT, b"item-c", 1, &opaque(3, 9_000))
        .unwrap();
    for index in 0..3_u32 {
        store
            .put_chunk_raw(
                VAULT,
                b"item-b",
                b"att-1",
                index,
                &opaque(100 + u64::from(index), 1200),
            )
            .unwrap();
    }
    store.set_high_water_mark(VAULT, 77).unwrap();
    store
}

fn export_of(store: &Store) -> Vec<u8> {
    let mut out = Vec::new();
    export::write(store, VAULT, &muk(), &mut out).unwrap();
    out
}

fn fresh() -> Store {
    Store::open_in_memory(&muk(), Box::new(Unanchored)).unwrap()
}

#[test]
fn the_round_trip_is_byte_exact_including_records_this_build_cannot_decode() {
    let source = populated();
    let file = export_of(&source);

    let header = export::verify(Cursor::new(&file), &muk()).unwrap();
    assert_eq!(header.vault_id(), VAULT);
    assert_eq!(header.records(), 3);
    assert_eq!(header.chunks(), 3);
    assert_eq!(header.high_water_mark(), Some(77));

    let mut target = fresh();
    let summary = export::restore(Cursor::new(&file), &muk(), &mut target).unwrap();
    assert_eq!((summary.records, summary.chunks), (3, 3));
    assert_eq!(summary.bytes, file.len() as u64);

    assert_eq!(
        target.list(VAULT).unwrap(),
        source.list(VAULT).unwrap(),
        "same items at the same versions"
    );
    for (item_id, _) in source.list(VAULT).unwrap() {
        let before = source.get_raw(VAULT, &item_id).unwrap().unwrap();
        let after = target.get_raw(VAULT, &item_id).unwrap().unwrap();
        assert_eq!(after.version, before.version);
        assert_eq!(after.bytes, before.bytes, "byte for byte, decodable or not");
    }
    assert_eq!(
        target.list_attachments(VAULT, b"item-b").unwrap(),
        vec![b"att-1".to_vec()]
    );
    for index in 0..3_u32 {
        assert_eq!(
            target
                .get_chunk_raw(VAULT, b"item-b", b"att-1", index)
                .unwrap(),
            source
                .get_chunk_raw(VAULT, b"item-b", b"att-1", index)
                .unwrap(),
            "chunk {index} byte for byte"
        );
    }
    assert_eq!(
        target.high_water_mark(VAULT),
        Some(77),
        "the high-water mark travels"
    );
}

#[test]
fn an_empty_vault_exports_and_restores_as_empty() {
    let source = fresh();
    let file = export_of(&source);
    let header = export::verify(Cursor::new(&file), &muk()).unwrap();
    assert_eq!((header.records(), header.chunks()), (0, 0));
    let mut target = fresh();
    let summary = export::restore(Cursor::new(&file), &muk(), &mut target).unwrap();
    assert_eq!((summary.records, summary.chunks), (0, 0));
    assert!(
        target.list(VAULT).unwrap().is_empty(),
        "restoring an empty export put records into the target"
    );
}

fn refused(file: &[u8]) -> ExportError {
    let mut target = fresh();
    let err = export::restore(Cursor::new(file), &muk(), &mut target).unwrap_err();
    assert!(
        target.list(VAULT).unwrap().is_empty()
            && target
                .list_attachments(VAULT, b"item-b")
                .unwrap()
                .is_empty(),
        "a refused file must not have touched the store: {err:?}"
    );
    err
}

#[test]
fn a_tampered_truncated_or_foreign_file_is_refused_by_name_and_touches_no_store() {
    let file = export_of(&populated());

    let mut tampered = file.clone();
    let middle = tampered.len() / 2;
    tampered[middle] ^= 0x01;
    assert!(matches!(refused(&tampered), ExportError::MacMismatch));

    let mut truncated = file.clone();
    truncated.truncate(file.len() - 40);
    assert!(matches!(refused(&truncated), ExportError::Truncated { .. }));

    let mut no_mac = file.clone();
    no_mac.truncate(file.len() - 32);
    assert!(matches!(refused(&no_mac), ExportError::Truncated { .. }));

    let mut extra = file.clone();
    extra.push(0);
    assert!(matches!(refused(&extra), ExportError::TrailingBytes { .. }));

    let mut target = fresh();
    let err = export::restore(Cursor::new(&file), &other_muk(), &mut target).unwrap_err();
    assert!(matches!(err, ExportError::MacMismatch), "{err:?}");

    assert!(matches!(
        refused(b"PK\x03\x04 a zip, say"),
        ExportError::BadMagic
    ));
    let mut future = file.clone();
    future[4] = 9;
    assert!(matches!(
        refused(&future),
        ExportError::UnsupportedVersion { version: 9 }
    ));
}

#[test]
fn a_declared_length_over_the_bound_is_refused_before_any_reservation() {
    // The header's length prefix sits at bytes 6..10. Declare four gigabytes.
    let mut file = export_of(&populated());
    file[6..10].copy_from_slice(&0xFFFF_FFF0_u32.to_le_bytes());
    let err = export::verify(Cursor::new(&file), &muk()).unwrap_err();
    assert!(
        matches!(err, ExportError::EntryTooLarge { at: 6, max } if max == MAX_ENTRY_BYTES),
        "{err:?}"
    );
}

#[test]
fn a_restore_into_a_store_that_already_holds_the_vault_is_refused() {
    let file = export_of(&populated());
    let mut occupied = fresh();
    occupied.put_raw(VAULT, b"already-here", 1, b"x").unwrap();
    let err = export::restore(Cursor::new(&file), &muk(), &mut occupied).unwrap_err();
    assert!(matches!(err, ExportError::StoreNotFresh), "{err:?}");
    assert_eq!(occupied.list(VAULT).unwrap().len(), 1, "nothing was added");
}

#[test]
fn export_errors_and_headers_render_without_content() {
    let file = export_of(&populated());
    let header = export::verify(Cursor::new(&file), &muk()).unwrap();
    let rendered = format!("{header:?} {:?}", ExportError::MacMismatch);
    // The vault id is metadata and may appear; a record's bytes must not.
    let payload = opaque(1, 700);
    assert!(!rendered.contains(&format!("{payload:?}")));
    assert!(!rendered.contains("4D"), "{rendered}");
}

fn login(title: &str, url: &str, user: &str, pass: &str, notes: &str) -> Item {
    Item::new(
        ItemKind::Login,
        vec![
            ItemField::new(FIELD_TITLE, title.as_bytes().to_vec()).unwrap(),
            ItemField::new(FIELD_URL, url.as_bytes().to_vec()).unwrap(),
            ItemField::new(FIELD_USERNAME, user.as_bytes().to_vec()).unwrap(),
            ItemField::new(FIELD_PASSWORD, pass.as_bytes().to_vec()).unwrap(),
            ItemField::new(FIELD_NOTES, notes.as_bytes().to_vec()).unwrap(),
        ],
        &["work"],
    )
    .unwrap()
}

fn note(title: &str, body: &[u8]) -> Item {
    Item::new(
        ItemKind::Note,
        vec![
            ItemField::new(FIELD_TITLE, title.as_bytes().to_vec()).unwrap(),
            ItemField::new(FIELD_NOTES, body.to_vec()).unwrap(),
        ],
        &[],
    )
    .unwrap()
}

#[test]
fn the_logins_csv_reads_back_through_our_own_chrome_importer() {
    let items = vec![
        login(
            "Example, quoted",
            "https://example.test",
            "alice",
            "pass \"with\" quotes\nand newline",
            "notes are not in the CSV",
        ),
        note("Not a login", b"body"),
        login("Plain", "https://plain.test", "bob", "plain-pass", ""),
    ];
    let mut csv = Vec::new();
    let written = export::logins_csv(&items, &mut csv).unwrap();
    assert_eq!(written, 2, "logins only");
    assert!(csv.starts_with(b"name,url,username,password\n"));

    let imported = chrome::parse(Cursor::new(csv)).unwrap();
    assert_eq!(imported.items.len(), 2);
    let first = &imported.items[0].item;
    assert_eq!(
        first.field(FIELD_TITLE).unwrap().value(),
        b"Example, quoted"
    );
    assert_eq!(
        first.field(FIELD_URL).unwrap().value(),
        b"https://example.test"
    );
    assert_eq!(first.field(FIELD_USERNAME).unwrap().value(), b"alice");
    assert_eq!(
        first.field(FIELD_PASSWORD).unwrap().value(),
        b"pass \"with\" quotes\nand newline",
        "quotes and newlines survive the CSV both ways"
    );
    assert!(
        first.field(FIELD_NOTES).is_none(),
        "Chrome's layout has four columns; the JSON carries the notes"
    );
}

#[test]
fn the_json_carries_every_item_field_tag_and_unknown() {
    let items = vec![
        login(
            "Example",
            "https://example.test",
            "alice",
            "correct-horse-battery",
            "a note",
        ),
        note("Binary note", &[0xFF, 0xFE, 0x00, b'x']),
    ];
    let mut json = Vec::new();
    assert_eq!(export::everything_json(&items, &mut json).unwrap(), 2);
    let doc = parse_json(&json).unwrap();
    let list = doc.as_list().unwrap();
    assert_eq!(list.len(), 2);

    let first = &list[0];
    assert_eq!(first.str_or_empty("kind"), "login");
    assert_eq!(first.get("schemaVersion").unwrap().text().as_str(), "1");
    let fields = first.get("fields").unwrap();
    assert_eq!(fields.str_or_empty(FIELD_PASSWORD), "correct-horse-battery");
    assert_eq!(
        fields.str_or_empty(FIELD_NOTES),
        "a note",
        "the JSON keeps what the CSV cannot"
    );
    assert_eq!(first.list_of("tags").len(), 1);
    assert_eq!(first.list_of("tags")[0].text().as_str(), "work");
    assert!(first.list_of("unknownFields").is_empty());

    let second = &list[1];
    assert_eq!(second.str_or_empty("kind"), "note");
    let body = second.get("fields").unwrap().get(FIELD_NOTES).unwrap();
    assert_eq!(
        body.str_or_empty("hex"),
        "fffe0078",
        "a non-UTF-8 value is hex, not lossy text"
    );
}

#[test]
fn the_export_module_touches_no_filesystem() {
    let source = std::fs::read_to_string(root().join("crates/core/src/export.rs")).unwrap();
    for forbidden in [
        "std::fs",
        "fs::",
        "File::",
        "tempfile",
        "temp_dir",
        "OpenOptions",
    ] {
        assert!(
            !source.contains(forbidden),
            "export.rs mentions {forbidden:?}"
        );
    }
}

fn root() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p
}

#[test]
#[ignore = "writes fuzz/corpus/export_verify; run explicitly"]
fn regenerate_export_corpus() {
    let dir = root().join("fuzz").join("corpus").join("export_verify");
    std::fs::create_dir_all(&dir).unwrap();
    let full = export_of(&populated());
    let empty = export_of(&fresh());
    let mut variants: Vec<(&str, Vec<u8>)> =
        vec![("populated", full.clone()), ("empty", empty.clone())];
    let mut tampered = full.clone();
    tampered[full.len() / 2] ^= 1;
    variants.push(("tampered", tampered));
    let mut truncated = full.clone();
    truncated.truncate(full.len() - 40);
    variants.push(("truncated", truncated));
    let mut no_mac = full.clone();
    no_mac.truncate(full.len() - 32);
    variants.push(("no-mac", no_mac));
    let mut extra = full.clone();
    extra.push(0);
    variants.push(("trailing", extra));
    let mut future = full.clone();
    future[4] = 9;
    variants.push(("version-9", future));
    let mut huge = full.clone();
    huge[6..10].copy_from_slice(&0xFFFF_FFF0_u32.to_le_bytes());
    variants.push(("huge-length", huge));
    let mut unknown_kind = full.clone();
    // The first entry kind byte follows the header entry: 6 + 4 + header len.
    let header_len = u32::from_le_bytes([full[6], full[7], full[8], full[9]]) as usize;
    unknown_kind[10 + header_len] = 0x7E;
    variants.push(("unknown-kind", unknown_kind));
    variants.push(("magic-only", b"CHVX".to_vec()));
    variants.push(("bad-magic", b"CHVR\x01\x00".to_vec()));
    variants.push(("nothing", Vec::new()));
    for (name, bytes) in &variants {
        std::fs::write(dir.join(format!("seed-{name}.chvx")), bytes).unwrap();
    }
}
