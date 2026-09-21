#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use chiavora_core::aad::AadFields;
use chiavora_core::manifest::{
    advance_high_water_mark, open_root, seal_root, seal_segment, CanonicalPrefix, Entry,
    ManifestError, ManifestRoot, ManifestSegment, RootEntry, StoredManifest, SyncPosture,
};
use chiavora_core::nonce::FreshNonce;
use chiavora_core::secret::{
    kind::{Muk, VaultKey},
    Secret,
};
use chiavora_core::store::{RollbackProtection, Store, Unanchored};

const VAULT: &[u8] = b"vault-1";
const TOP_HALF: u64 = 0x8000_0000_0000_0000;

fn key() -> Secret<VaultKey> {
    Secret::<VaultKey>::from_derived_bytes(vec![0x22; 32])
}

fn store() -> Store {
    Store::open_in_memory(
        &Secret::<Muk>::from_derived_bytes(vec![0x4D; 32]),
        Box::new(Unanchored),
    )
    .expect("store")
}

fn digest(fill: u8) -> [u8; 32] {
    [fill; 32]
}

fn prefix(len: u8, bits: u64) -> CanonicalPrefix {
    CanonicalPrefix::new(len, bits).expect("canonical")
}

fn root_fields(segment_count: u32, manifest_seq: u64) -> AadFields {
    AadFields::ManifestRoot {
        vault_id: VAULT.to_vec(),
        manifest_seq,
        vault_key_epoch: 1,
        segment_count,
    }
}

fn segment_fields(prefix_len: u8, prefix_bits: u64, segment_seq: u64) -> AadFields {
    AadFields::ManifestSegment {
        vault_id: VAULT.to_vec(),
        segment_seq,
        vault_key_epoch: 1,
        prefix_len,
        prefix_bits,
    }
}

fn whole_keyspace_root(manifest_seq: u64, segment_digest: [u8; 32]) -> ManifestRoot {
    ManifestRoot::new(
        root_fields(1, manifest_seq),
        vec![RootEntry::new(prefix(0, 0), segment_digest, manifest_seq)],
    )
    .expect("a root")
}

fn segment_with(entries: Vec<Entry>) -> ManifestSegment {
    ManifestSegment::new(segment_fields(0, 0, 41), entries).expect("a segment")
}

fn sealed_segment(segment: &ManifestSegment) -> StoredManifest {
    seal_segment(&key(), FreshNonce::generate().expect("nonce"), segment).expect("seals")
}

#[test]
fn i6a_a_root_below_the_high_water_mark_is_refused() {
    let root = whole_keyspace_root(12, digest(1));
    assert!(
        matches!(
            root.check_not_rolled_back(Some(20)),
            Err(ManifestError::RootBelowHighWaterMark {
                offered: 12,
                mark: 20
            })
        ),
        "a vault-wide rollback must be refused and must name both numbers"
    );
}

#[test]
fn i6a_a_root_at_the_high_water_mark_is_accepted() {
    let root = whole_keyspace_root(20, digest(1));
    root.check_not_rolled_back(Some(20))
        .expect("equality is a re-fetch, not a rollback");
    root.check_not_rolled_back(Some(19))
        .expect("moving forward is the normal case");
    root.check_not_rolled_back(None)
        .expect("a vault this device has never synced has no mark to compare against");
}

#[test]
fn i6b_a_segment_the_root_does_not_vouch_for_is_refused() {
    let honest = segment_with(vec![Entry::new(
        b"item".to_vec(),
        1,
        digest(0x11),
        false,
        Vec::new(),
    )]);
    let stored = sealed_segment(&honest);
    let root = whole_keyspace_root(41, stored.digest().expect("digest"));
    root.accept_segment(&stored).expect("the honest one");

    let stale = segment_with(vec![Entry::new(
        b"item".to_vec(),
        1,
        digest(0x99),
        false,
        Vec::new(),
    )]);
    assert!(matches!(
        root.accept_segment(&sealed_segment(&stale)),
        Err(ManifestError::SegmentDigestMismatch)
    ));
}

#[test]
fn i6b_a_segment_at_a_prefix_the_root_never_names_is_refused() {
    let segment =
        ManifestSegment::new(segment_fields(1, TOP_HALF, 41), Vec::new()).expect("a segment");
    let stored =
        seal_segment(&key(), FreshNonce::generate().expect("nonce"), &segment).expect("seals");
    let root = whole_keyspace_root(41, digest(1));

    assert!(matches!(
        root.accept_segment(&stored),
        Err(ManifestError::SegmentNotInRoot { prefix_len: 1 })
    ));
}

#[test]
fn i6b_a_gapped_root_is_refused_before_any_item_is_read() {
    let root = ManifestRoot::new(
        root_fields(1, 41),
        vec![RootEntry::new(prefix(1, TOP_HALF), digest(1), 41)],
    )
    .expect("a root");

    match root.accept(Some(1)) {
        Err(ManifestError::PrefixSetHasGap { from, through }) => {
            assert_eq!(from, 0);
            assert_eq!(through, TOP_HALF - 1, "the hidden half is named");
        }
        other => panic!("a gapped root must be refused by accept, got {other:?}"),
    }
}

#[test]
fn i6a_is_checked_before_i6b_so_a_rolled_back_root_says_so() {
    let root = ManifestRoot::new(
        root_fields(1, 5),
        vec![RootEntry::new(prefix(1, TOP_HALF), digest(1), 5)],
    )
    .expect("a root");
    assert!(matches!(
        root.accept(Some(99)),
        Err(ManifestError::RootBelowHighWaterMark { .. })
    ));
}

#[test]
fn i6c_an_item_below_its_entrys_version_is_refused() {
    let entry = Entry::new(b"item".to_vec(), 7, digest(0x11), false, Vec::new());
    entry
        .accept_item(7, &digest(0x11))
        .expect("the current one");

    assert!(matches!(
        entry.accept_item(6, &digest(0x11)),
        Err(ManifestError::ItemVersionRollback {
            delivered: 6,
            current: 7
        })
    ));
}

#[test]
fn i6d_a_substituted_ciphertext_at_the_same_version_is_refused() {
    let entry = Entry::new(b"item".to_vec(), 7, digest(0x11), false, Vec::new());
    assert!(matches!(
        entry.accept_item(7, &digest(0x12)),
        Err(ManifestError::CiphertextDigestMismatch)
    ));
}

#[test]
fn i6c_is_reported_before_i6d_when_a_replay_fails_both() {
    let entry = Entry::new(b"item".to_vec(), 7, digest(0x11), false, Vec::new());
    assert!(
        matches!(
            entry.accept_item(6, &digest(0xAA)),
            Err(ManifestError::ItemVersionRollback { .. })
        ),
        "a replay is a replay, not a digest mismatch"
    );
}

#[test]
fn i6e_an_item_listed_but_not_delivered_is_refused() {
    let segment = segment_with(vec![
        Entry::new(b"here".to_vec(), 1, digest(1), false, Vec::new()),
        Entry::new(b"withheld".to_vec(), 1, digest(2), false, Vec::new()),
    ]);
    assert!(matches!(
        segment.reconcile(&[b"here".as_slice()]),
        Err(ManifestError::ItemListedNotDelivered)
    ));
}

#[test]
fn i6e_an_item_delivered_but_listed_nowhere_is_refused() {
    let segment = segment_with(vec![Entry::new(
        b"here".to_vec(),
        1,
        digest(1),
        false,
        Vec::new(),
    )]);
    assert!(matches!(
        segment.reconcile(&[b"here".as_slice(), b"stranger".as_slice()]),
        Err(ManifestError::ItemDeliveredNotListed)
    ));
}

#[test]
fn i6e_a_deletion_is_legitimate_only_because_of_its_tombstone() {
    let tombstoned = segment_with(vec![
        Entry::new(b"here".to_vec(), 1, digest(1), false, Vec::new()),
        Entry::new(b"deleted".to_vec(), 2, digest(2), true, Vec::new()),
    ]);
    tombstoned
        .reconcile(&[b"here".as_slice()])
        .expect("a tombstoned item is expected to be absent");

    let untombstoned = segment_with(vec![
        Entry::new(b"here".to_vec(), 1, digest(1), false, Vec::new()),
        Entry::new(b"deleted".to_vec(), 2, digest(2), false, Vec::new()),
    ]);
    assert!(
        matches!(
            untombstoned.reconcile(&[b"here".as_slice()]),
            Err(ManifestError::ItemListedNotDelivered)
        ),
        "the identical absence must be an attack without the tombstone"
    );
}

#[test]
fn i6e_a_tombstoned_item_that_is_nonetheless_delivered_is_refused() {
    let segment = segment_with(vec![Entry::new(
        b"deleted".to_vec(),
        2,
        digest(2),
        true,
        Vec::new(),
    )]);
    assert!(matches!(
        segment.reconcile(&[b"deleted".as_slice()]),
        Err(ManifestError::ItemDeliveredNotListed)
    ));
}

#[test]
fn i6e_an_unlisted_item_has_no_entry_to_find() {
    let segment = segment_with(vec![Entry::new(
        b"here".to_vec(),
        1,
        digest(1),
        false,
        Vec::new(),
    )]);
    assert!(segment.entry(b"here").is_some());
    assert!(segment.entry(b"stranger").is_none());
    assert!(
        segment.entry(b"here").is_some_and(|e| !e.tombstone()),
        "a tombstoned entry is still an entry, so the lookup must find one"
    );
}

#[test]
fn i6f_a_rewound_on_disk_high_water_mark_is_refused() {
    let mut store = store();
    let ahead = whole_keyspace_root(20, digest(1));
    advance_high_water_mark(&mut store, VAULT, &ahead).expect("first advance");
    assert_eq!(store.high_water_mark(VAULT), Some(20));

    let behind = whole_keyspace_root(19, digest(1));
    assert!(
        matches!(
            advance_high_water_mark(&mut store, VAULT, &behind),
            Err(ManifestError::HighWaterMarkRewound)
        ),
        "a decrease is I6f, not a database error"
    );
    assert_eq!(
        store.high_water_mark(VAULT),
        Some(20),
        "and the mark did not move"
    );
}

#[test]
fn i6f_a_sync_against_an_unanchored_store_reports_its_posture() {
    let store = store();
    let posture = SyncPosture::of(&store);

    assert_eq!(
        posture.rollback_protection(),
        RollbackProtection::IntegrityOnly,
        "an in-memory store has no anchor outside the file"
    );
    assert!(
        !posture.detects_local_rewind(),
        "and the sync layer must say so rather than imply I6f holds"
    );
}

#[test]
fn the_breached_password_rollback_scenario_is_refused() {
    let key = key();
    let mut store = store();
    let item = b"login-bank".as_slice();

    let breached = digest(0xB1);
    let rotated = digest(0x2A);

    let segment = segment_with(vec![Entry::new(
        item.to_vec(),
        2,
        rotated,
        false,
        Vec::new(),
    )]);
    let stored_segment = sealed_segment(&segment);
    let root = whole_keyspace_root(2, stored_segment.digest().expect("digest"));

    let stored_root =
        seal_root(&key, FreshNonce::generate().expect("nonce"), &root).expect("seals");
    let opened = open_root(&key, &stored_root).expect("opens");
    opened
        .accept(store.high_water_mark(VAULT))
        .expect("an honest root");
    opened.accept_segment(&stored_segment).expect("vouched for");
    advance_high_water_mark(&mut store, VAULT, &opened).expect("advance");

    let entry = segment.entry(item).expect("the entry");
    let refused = entry.accept_item(1, &breached);

    assert!(
        matches!(
            refused,
            Err(ManifestError::ItemVersionRollback {
                delivered: 1,
                current: 2
            })
        ),
        "the breached password must be refused before anything can fill it; got {refused:?}"
    );

    let old_root = whole_keyspace_root(1, stored_segment.digest().expect("digest"));
    assert!(matches!(
        old_root.accept(store.high_water_mark(VAULT)),
        Err(ManifestError::RootBelowHighWaterMark {
            offered: 1,
            mark: 2
        })
    ));
}

#[test]
fn an_honest_sync_is_accepted_end_to_end() {
    let key = key();
    let mut store = store();
    let item = b"login-bank".as_slice();
    let ciphertext_digest = digest(0x2A);

    let segment = segment_with(vec![Entry::new(
        item.to_vec(),
        2,
        ciphertext_digest,
        false,
        Vec::new(),
    )]);
    let stored_segment = sealed_segment(&segment);
    let root = whole_keyspace_root(2, stored_segment.digest().expect("digest"));
    let stored_root =
        seal_root(&key, FreshNonce::generate().expect("nonce"), &root).expect("seals");

    let opened = open_root(&key, &stored_root).expect("opens");
    opened.accept(store.high_water_mark(VAULT)).expect("root");
    opened.accept_segment(&stored_segment).expect("segment");
    segment.reconcile(&[item]).expect("reconciles");
    segment
        .entry(item)
        .expect("listed")
        .accept_item(2, &ciphertext_digest)
        .expect("item");
    advance_high_water_mark(&mut store, VAULT, &opened).expect("advance");

    assert_eq!(store.high_water_mark(VAULT), Some(2));
}
