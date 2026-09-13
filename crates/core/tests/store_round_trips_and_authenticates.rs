#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::PathBuf;

use chiavora_core::aad::{AadFields, RECORD_ITEM_PAYLOAD};
use chiavora_core::item::{open, seal};
use chiavora_core::model::{Item, ItemField};
use chiavora_core::nonce::FreshNonce;
use chiavora_core::secret::{
    kind::{AutofillKey, ItemKey, Muk, VaultKey},
    Secret,
};
use chiavora_core::store::{RollbackAnchor, RollbackProtection, Store, StoreError, Unanchored};
use chiavora_core::stored_record::StoredRecord;
use chiavora_core::wrap::{ItemKind, VaultKeys, WrapContext};
use chiavora_protocol::Record;

fn root() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p
}

struct TempDb(PathBuf);

impl TempDb {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "chiavora-store-{}-{}-{name}.sqlite",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default()
        ));
        let _ = std::fs::remove_file(&path);
        Self(path)
    }
}

impl Drop for TempDb {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn key32(fill: u8) -> Vec<u8> {
    vec![fill; 32]
}

fn muk() -> Secret<Muk> {
    Secret::<Muk>::from_derived_bytes(key32(0x4D))
}

#[derive(Clone, Default)]
struct SharedAnchor(std::sync::Arc<std::sync::Mutex<Option<u64>>>);

impl RollbackAnchor for SharedAnchor {
    fn latest(&self) -> Option<u64> {
        *self.0.lock().expect("anchor lock")
    }
    fn advance(&mut self, generation: u64) -> Result<(), StoreError> {
        *self.0.lock().expect("anchor lock") = Some(generation);
        Ok(())
    }
    fn protection(&self) -> RollbackProtection {
        RollbackProtection::Anchored
    }
}

#[test]
fn bytes_the_build_cannot_decode_round_trip_identically() {
    let garbage: Vec<u8> = (0..=255u8).cycle().take(1_000).collect();
    assert!(
        Record::decode(&garbage).is_err(),
        "the fixture must be undecodable"
    );

    let mut store = Store::open_in_memory(&muk(), Box::new(Unanchored)).unwrap();
    store
        .put_raw(b"vault-1", b"item-opaque", 42, &garbage)
        .unwrap();

    let back = store
        .get_raw(b"vault-1", b"item-opaque")
        .unwrap()
        .expect("stored");
    assert_eq!(
        back.bytes, garbage,
        "the store rewrote a record it cannot read"
    );
    assert_eq!(back.version, 42, "the version was derived rather than kept");
}

#[test]
fn an_upsert_replaces_bytes_and_version_together_and_delete_is_honest() {
    let mut store = Store::open_in_memory(&muk(), Box::new(Unanchored)).unwrap();
    store.put_raw(b"v", b"i", 1, b"first").unwrap();
    store.put_raw(b"v", b"i", 2, b"second").unwrap();
    let back = store.get_raw(b"v", b"i").unwrap().unwrap();
    assert_eq!((back.version, back.bytes.as_slice()), (2, &b"second"[..]));
    assert_eq!(store.list(b"v").unwrap(), vec![(b"i".to_vec(), 2)]);
    assert!(store.delete(b"v", b"i").unwrap());
    assert!(!store.delete(b"v", b"i").unwrap());
    assert!(store.get_raw(b"v", b"i").unwrap().is_none());
}

#[test]
fn a_flipped_byte_in_the_metadata_is_refused_on_open() {
    let db = TempDb::new("tamper");
    {
        let mut store = Store::open(&db.0, &muk(), Box::new(Unanchored)).unwrap();
        store.set_high_water_mark(b"vault-1", 7).unwrap();
    }
    {
        let conn = rusqlite::Connection::open(&db.0).unwrap();
        let body: Vec<u8> = conn
            .query_row("SELECT body FROM metadata WHERE id = 1", [], |r| r.get(0))
            .unwrap();
        let mut tampered = body;
        let last = tampered.len() - 1;
        if let Some(b) = tampered.get_mut(last) {
            *b ^= 0x01;
        }
        conn.execute(
            "UPDATE metadata SET body = ?1 WHERE id = 1",
            rusqlite::params![tampered],
        )
        .unwrap();
    }
    let err = Store::open(&db.0, &muk(), Box::new(Unanchored)).expect_err("refused");
    assert!(matches!(err, StoreError::MetadataTampered), "{err:?}");
}

#[test]
fn the_high_water_mark_survives_a_restart_and_never_decreases() {
    let db = TempDb::new("hwm");
    {
        let mut store = Store::open(&db.0, &muk(), Box::new(Unanchored)).unwrap();
        store.set_high_water_mark(b"vault-1", 7).unwrap();
        store.set_high_water_mark(b"vault-1", 9).unwrap();
        let err = store.set_high_water_mark(b"vault-1", 8).unwrap_err();
        assert!(matches!(
            err,
            StoreError::HighWaterMarkDecrease {
                current: 9,
                proposed: 8
            }
        ));
    }
    let store = Store::open(&db.0, &muk(), Box::new(Unanchored)).unwrap();
    assert_eq!(store.high_water_mark(b"vault-1"), Some(9));
    assert_eq!(store.high_water_mark(b"vault-2"), None);
}

#[test]
fn a_whole_file_rewind_is_caught_by_an_anchor_and_reported_as_undetectable_without_one() {
    let db = TempDb::new("rewind");
    let anchor = SharedAnchor::default();

    let earlier: Vec<u8>;
    {
        let mut store = Store::open(&db.0, &muk(), Box::new(anchor.clone())).unwrap();
        store.set_high_water_mark(b"vault-1", 3).unwrap();
        drop(store);
        earlier = std::fs::read(&db.0).unwrap();
        let mut store = Store::open(&db.0, &muk(), Box::new(anchor.clone())).unwrap();
        store.set_high_water_mark(b"vault-1", 5).unwrap();
    }
    let committed = anchor.latest().expect("the anchor saw the store");

    // Copy the older file back; every MAC inside it is valid.
    std::fs::write(&db.0, &earlier).unwrap();

    let err = Store::open(&db.0, &muk(), Box::new(anchor.clone()))
        .expect_err("a rewind must be refused when an anchor remembers");
    match err {
        StoreError::MetadataRewound { stored, anchor: a } => {
            assert!(stored < a);
            assert_eq!(a, committed);
        }
        other => panic!("expected MetadataRewound, got {other:?}"),
    }

    let store = Store::open(&db.0, &muk(), Box::new(Unanchored)).unwrap();
    assert_eq!(
        store.high_water_mark(b"vault-1"),
        Some(3),
        "the rewind took effect"
    );
    assert_eq!(
        store.rollback_protection(),
        RollbackProtection::IntegrityOnly,
        "an unanchored store must not claim to detect rewinds"
    );
}

#[test]
fn an_anchor_that_has_never_seen_the_store_trusts_the_first_generation() {
    let db = TempDb::new("tofu");
    {
        let mut store = Store::open(&db.0, &muk(), Box::new(Unanchored)).unwrap();
        store.set_high_water_mark(b"v", 4).unwrap();
    }
    let anchor = SharedAnchor::default();
    let store = Store::open(&db.0, &muk(), Box::new(anchor.clone())).unwrap();
    assert_eq!(anchor.latest(), Some(store.generation()));
    assert_eq!(store.rollback_protection(), RollbackProtection::Anchored);
}

#[test]
fn a_store_whose_metadata_row_was_deleted_does_not_open_as_fresh() {
    let db = TempDb::new("missing");
    {
        let mut store = Store::open(&db.0, &muk(), Box::new(Unanchored)).unwrap();
        store.put_raw(b"v", b"i", 1, b"bytes").unwrap();
    }
    {
        let conn = rusqlite::Connection::open(&db.0).unwrap();
        conn.execute("DELETE FROM metadata", []).unwrap();
    }
    let err = Store::open(&db.0, &muk(), Box::new(Unanchored)).expect_err("refused");
    assert!(matches!(err, StoreError::MetadataMissing), "{err:?}");
}

fn seal_login(vault: &Secret<VaultKey>, autofill: &Secret<AutofillKey>) -> (Vec<u8>, Vec<u8>) {
    let item = Item::new(
        ItemKind::Login,
        vec![
            ItemField::new("title", b"Example".to_vec()).unwrap(),
            ItemField::new("username", b"ada-lovelace-1815".to_vec()).unwrap(),
            ItemField::new("password", b"correct-horse-battery-staple".to_vec()).unwrap(),
        ],
        &["work"],
    )
    .unwrap();
    let plaintext = item.to_bytes().unwrap();

    let item_key = Secret::<ItemKey>::from_derived_bytes(key32(0x11));
    let fields = AadFields::ItemPayload {
        vault_id: b"vault-1".to_vec(),
        item_id: b"item-1".to_vec(),
        version: 1,
        content_type: ItemKind::Login.tag().as_bytes().to_vec(),
    };
    assert_eq!(fields.record_type(), RECORD_ITEM_PAYLOAD);
    let payload = seal(
        &item_key,
        FreshNonce::generate().unwrap(),
        &fields,
        &plaintext,
    )
    .unwrap();
    let wraps = ItemKind::Login
        .wrap(
            &item_key,
            VaultKeys { vault, autofill },
            WrapContext {
                vault_id: b"vault-1",
                item_id: b"item-1",
            },
        )
        .unwrap();
    let record = StoredRecord::new(fields, payload, wraps).unwrap();
    (record.encode().unwrap(), plaintext)
}

#[test]
fn create_lock_restart_unlock_read_round_trips_a_sealed_item() {
    let db = TempDb::new("gate");
    let vault = Secret::<VaultKey>::from_derived_bytes(key32(0x22));
    let autofill = Secret::<AutofillKey>::from_derived_bytes(key32(0x33));
    let (encoded, plaintext) = seal_login(&vault, &autofill);

    {
        let mut store = Store::open(&db.0, &muk(), Box::new(Unanchored)).unwrap();
        store.put_raw(b"vault-1", b"item-1", 1, &encoded).unwrap();
    }

    let store = Store::open(&db.0, &muk(), Box::new(Unanchored)).unwrap();
    let raw = store
        .get_raw(b"vault-1", b"item-1")
        .unwrap()
        .expect("stored");
    assert_eq!(
        raw.bytes, encoded,
        "the stored record changed across a restart"
    );

    let record = StoredRecord::decode(&raw.bytes).unwrap();
    assert_eq!(record.kind().unwrap(), ItemKind::Login);
    assert_eq!(record.wraps().wrap_count(), 2);

    let ctx = WrapContext {
        vault_id: b"vault-1",
        item_id: b"item-1",
    };
    let item_key = match record.wraps() {
        chiavora_core::wrap::AnyWrapSet::VaultAndAutofill(set) => {
            set.unwrap(&vault, &autofill, ctx).unwrap()
        }
        chiavora_core::wrap::AnyWrapSet::VaultOnly(_) => panic!("a login is double-wrapped"),
    };
    let opened = open(&item_key, record.payload(), record.fields()).unwrap();
    assert_eq!(opened, plaintext);

    let again = Item::from_bytes(&opened).unwrap();
    assert_eq!(
        again.field("password").unwrap().value(),
        b"correct-horse-battery-staple"
    );
}

#[test]
fn a_bulk_write_that_is_not_committed_leaves_the_store_exactly_as_it_was() {
    let db = TempDb::new("bulk-rollback");
    {
        let mut store = Store::open(&db.0, &muk(), Box::new(Unanchored)).unwrap();
        store
            .put_raw(b"vault-1", b"before", 1, b"already here")
            .unwrap();
    }

    {
        let mut store = Store::open(&db.0, &muk(), Box::new(Unanchored)).unwrap();
        let mut bulk = store.begin_bulk().unwrap();
        for n in 0..500 {
            bulk.store()
                .put_raw(b"vault-1", format!("item-{n}").as_bytes(), 1, b"imported")
                .unwrap();
        }
        bulk.store()
            .put_chunk_raw(b"vault-1", b"item-0", b"att", 0, b"chunk")
            .unwrap();
        // No commit: dropped here, so the transaction rolls back.
    }

    let store = Store::open(&db.0, &muk(), Box::new(Unanchored)).unwrap();
    let listed = store.list(b"vault-1").unwrap();
    assert_eq!(
        listed.len(),
        1,
        "the rolled-back import left records behind: {listed:?}"
    );
    assert_eq!(
        store.get_raw(b"vault-1", b"before").unwrap().unwrap().bytes,
        b"already here".to_vec(),
        "the record that was there before the import was disturbed"
    );
    assert!(
        store
            .list_attachments(b"vault-1", b"item-0")
            .unwrap()
            .is_empty(),
        "a rolled-back chunk survived"
    );
}

#[test]
fn a_committed_bulk_write_survives_a_restart() {
    let db = TempDb::new("bulk-commit");
    {
        let mut store = Store::open(&db.0, &muk(), Box::new(Unanchored)).unwrap();
        let mut bulk = store.begin_bulk().unwrap();
        for n in 0..500 {
            bulk.store()
                .put_raw(b"vault-1", format!("item-{n}").as_bytes(), 7, b"imported")
                .unwrap();
        }
        bulk.commit().unwrap();
        // Set after the commit: the mark advances the anchor, which lives outside SQLite.
        store.set_high_water_mark(b"vault-1", 42).unwrap();
    }

    let store = Store::open(&db.0, &muk(), Box::new(Unanchored)).unwrap();
    assert_eq!(store.list(b"vault-1").unwrap().len(), 500);
    assert_eq!(
        store
            .get_raw(b"vault-1", b"item-499")
            .unwrap()
            .unwrap()
            .version,
        7
    );
    assert_eq!(store.high_water_mark(b"vault-1"), Some(42));
}

#[test]
fn a_rolled_back_bulk_write_leaves_the_rollback_anchor_where_it_was() {
    // An anchor advanced inside a rolled-back write would claim a generation the
    // file never reached, and the next open would refuse the store as rewound.
    let db = TempDb::new("bulk-rollback-anchor");
    let anchor = SharedAnchor::default();

    {
        let mut store = Store::open(&db.0, &muk(), Box::new(anchor.clone())).unwrap();
        store
            .put_raw(b"vault-1", b"before", 1, b"already here")
            .unwrap();
        store.set_high_water_mark(b"vault-1", 10).unwrap();
    }
    let settled = anchor.latest().expect("the anchor has seen this store");

    {
        let mut store = Store::open(&db.0, &muk(), Box::new(anchor.clone())).unwrap();
        let mut bulk = store.begin_bulk().unwrap();
        for n in 0..200 {
            bulk.store()
                .put_raw(b"vault-1", format!("item-{n}").as_bytes(), 1, b"imported")
                .unwrap();
        }
    }

    assert_eq!(
        anchor.latest(),
        Some(settled),
        "a rolled-back bulk write moved the rollback anchor: it now claims          generation {:?} while the file is still at {settled}",
        anchor.latest()
    );

    let store = Store::open(&db.0, &muk(), Box::new(anchor.clone()))
        .expect("the store must still open after a failed import");
    assert_eq!(store.list(b"vault-1").unwrap().len(), 1);
    assert_eq!(store.high_water_mark(b"vault-1"), Some(10));
}

#[test]
fn advancing_the_anchor_inside_a_bulk_write_would_brick_the_store() {
    // Advance the anchor inside the transaction on purpose: a rollback cannot undo it.
    let db = TempDb::new("bulk-rollback-anchor-witness");
    let anchor = SharedAnchor::default();

    {
        let mut store = Store::open(&db.0, &muk(), Box::new(anchor.clone())).unwrap();
        store
            .put_raw(b"vault-1", b"before", 1, b"already here")
            .unwrap();
    }
    let settled = anchor.latest().expect("the anchor has seen this store");

    {
        let mut store = Store::open(&db.0, &muk(), Box::new(anchor.clone())).unwrap();
        let mut bulk = store.begin_bulk().unwrap();
        bulk.store()
            .put_raw(b"vault-1", b"imported", 1, b"imported")
            .unwrap();
        bulk.store().set_high_water_mark(b"vault-1", 10).unwrap();
    }

    assert!(
        anchor.latest() > Some(settled),
        "the anchor did not move, so this witness proves nothing"
    );

    let err = Store::open(&db.0, &muk(), Box::new(anchor.clone()))
        .expect_err("the store must refuse to open");
    assert!(
        matches!(err, StoreError::MetadataRewound { .. }),
        "expected the store to report a rewind, got {err:?}"
    );
}

#[test]
fn a_bulk_write_is_invisible_until_it_commits() {
    let db = TempDb::new("bulk-isolation");
    let mut store = Store::open(&db.0, &muk(), Box::new(Unanchored)).unwrap();
    let mut bulk = store.begin_bulk().unwrap();
    bulk.store()
        .put_raw(b"vault-1", b"pending", 1, b"not yet")
        .unwrap();

    let onlooker = Store::open(&db.0, &muk(), Box::new(Unanchored)).unwrap();
    assert!(
        onlooker.get_raw(b"vault-1", b"pending").unwrap().is_none(),
        "an uncommitted bulk write was visible to another reader"
    );
    drop(onlooker);
    bulk.commit().unwrap();

    let after = Store::open(&db.0, &muk(), Box::new(Unanchored)).unwrap();
    assert!(after.get_raw(b"vault-1", b"pending").unwrap().is_some());
}

#[test]
fn the_database_file_holds_no_plaintext() {
    let db = TempDb::new("canary");
    let vault = Secret::<VaultKey>::from_derived_bytes(key32(0x22));
    let autofill = Secret::<AutofillKey>::from_derived_bytes(key32(0x33));
    let (encoded, _) = seal_login(&vault, &autofill);
    {
        let mut store = Store::open(&db.0, &muk(), Box::new(Unanchored)).unwrap();
        store.put_raw(b"vault-1", b"item-1", 1, &encoded).unwrap();
        store.set_high_water_mark(b"vault-1", 1).unwrap();
    }
    let file = std::fs::read(&db.0).unwrap();
    // A canary must not be a substring of anything the store writes on purpose, such as the schema.
    for canary in [
        &b"correct-horse-battery-staple"[..],
        b"Example",
        b"ada-lovelace-1815",
        b"password",
        b"username",
    ] {
        assert!(
            !file.windows(canary.len()).any(|w| w == canary),
            "the database file contains {:?} in the clear",
            String::from_utf8_lossy(canary)
        );
    }
}

#[test]
fn the_digest_covers_the_payload_and_not_the_wraps() {
    let vault_a = Secret::<VaultKey>::from_derived_bytes(key32(0x22));
    let vault_b = Secret::<VaultKey>::from_derived_bytes(key32(0x23));
    let autofill = Secret::<AutofillKey>::from_derived_bytes(key32(0x33));
    let (a, _) = seal_login(&vault_a, &autofill);
    let (b, _) = seal_login(&vault_b, &autofill);
    let ra = StoredRecord::decode(&a).unwrap();
    let rb = StoredRecord::decode(&b).unwrap();
    // The nonces differ, so rebuild over `ra`'s payload with `rb`'s wraps.
    let rewrapped = StoredRecord::new(
        ra.fields().clone(),
        ra.payload().clone(),
        rb.wraps().clone(),
    )
    .unwrap();
    assert_eq!(
        rewrapped.ciphertext_digest().unwrap(),
        ra.ciphertext_digest().unwrap(),
        "re-wrapping changed the digest"
    );
    assert_ne!(
        rewrapped.encode().unwrap(),
        ra.encode().unwrap(),
        "the wraps did change"
    );
}

#[test]
fn a_login_stored_with_one_wrap_is_refused_not_downgraded() {
    let vault = Secret::<VaultKey>::from_derived_bytes(key32(0x22));
    let autofill = Secret::<AutofillKey>::from_derived_bytes(key32(0x33));
    let (encoded, _) = seal_login(&vault, &autofill);
    let record = Record::decode(&encoded).unwrap();
    let stripped: Vec<_> = record
        .fields()
        .iter()
        .filter(|f| f.tag() < chiavora_core::stored_record::tag::AUTOFILL_WRAP_NONCE)
        .cloned()
        .collect();
    let bytes = record.with_fields(stripped).encode().unwrap();
    let err = StoredRecord::decode(&bytes).unwrap_err();
    assert!(
        matches!(
            err,
            chiavora_core::stored_record::StoredRecordError::Wrap(
                chiavora_core::wrap::WrapError::MissingAutofillWrap
            )
        ),
        "{err:?}"
    );
}

#[test]
#[ignore = "writes fuzz/corpus/stored_record_decode; run explicitly to regenerate the seeds"]
fn regenerate_stored_record_corpus() {
    let dir = root()
        .join("fuzz")
        .join("corpus")
        .join("stored_record_decode");
    std::fs::create_dir_all(&dir).unwrap();
    let vault = Secret::<VaultKey>::from_derived_bytes(key32(0x22));
    let autofill = Secret::<AutofillKey>::from_derived_bytes(key32(0x33));
    let mut n = 0;
    for kind in ItemKind::ALL {
        for round in 0..2 {
            let item = Item::new(
                *kind,
                vec![ItemField::new("title", format!("T{round}").into_bytes()).unwrap()],
                &[],
            )
            .unwrap();
            let item_key = Secret::<ItemKey>::from_derived_bytes(key32(0x40 + n));
            let fields = AadFields::ItemPayload {
                vault_id: b"vault-1".to_vec(),
                item_id: format!("item-{n}").into_bytes(),
                version: u64::from(n),
                content_type: kind.tag().as_bytes().to_vec(),
            };
            let payload = seal(
                &item_key,
                FreshNonce::generate().unwrap(),
                &fields,
                &item.to_bytes().unwrap(),
            )
            .unwrap();
            let wraps = kind
                .wrap(
                    &item_key,
                    VaultKeys {
                        vault: &vault,
                        autofill: &autofill,
                    },
                    WrapContext {
                        vault_id: b"vault-1",
                        item_id: b"item-x",
                    },
                )
                .unwrap();
            let record = StoredRecord::new(fields, payload, wraps).unwrap();
            std::fs::write(
                dir.join(format!("seed-{}-{round}", kind.tag().replace(' ', "_"))),
                record.encode().unwrap(),
            )
            .unwrap();
            n += 1;
        }
    }
    assert!(n >= 10, "R7: at least ten seeds");
}
