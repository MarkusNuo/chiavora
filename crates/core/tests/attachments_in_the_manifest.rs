#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::collections::BTreeSet;

use chiavora_core::manifest::{
    chunk_digest_root, resolve, AttachmentEntry, ConflictingVersion, Entry, ManifestError,
    Resolution,
};
use sha2::{Digest, Sha256};

fn digest(fill: u8) -> [u8; 32] {
    [fill; 32]
}

fn attachment(id: &[u8], chunks: &[[u8; 32]]) -> AttachmentEntry {
    AttachmentEntry::new(
        id.to_vec(),
        u32::try_from(chunks.len()).expect("small"),
        chunk_digest_root(chunks),
        1024,
    )
}

#[test]
fn the_root_is_sha256_over_the_ordered_concatenation() {
    let chunks = [digest(0x01), digest(0x02), digest(0x03)];

    let mut by_hand = Sha256::new();
    by_hand.update(digest(0x01));
    by_hand.update(digest(0x02));
    by_hand.update(digest(0x03));
    let expected: [u8; 32] = by_hand.finalize().into();

    assert_eq!(chunk_digest_root(&chunks), expected);
}

#[test]
fn the_order_of_the_chunks_changes_the_root() {
    let forwards = [digest(0x01), digest(0x02)];
    let backwards = [digest(0x02), digest(0x01)];
    assert_ne!(chunk_digest_root(&forwards), chunk_digest_root(&backwards));
}

#[test]
fn an_attachment_with_no_chunks_is_not_a_special_case() {
    let empty: [[u8; 32]; 0] = [];
    let expected: [u8; 32] = Sha256::new().finalize().into();
    assert_eq!(chunk_digest_root(&empty), expected);
}

#[test]
fn appending_a_chunk_changes_the_root() {
    let two = [digest(0x01), digest(0x02)];
    let three = [digest(0x01), digest(0x02), digest(0x03)];
    assert_ne!(chunk_digest_root(&two), chunk_digest_root(&three));
}

#[test]
fn the_chunks_the_entry_vouches_for_are_accepted() {
    let chunks = [digest(0xA1), digest(0xA2), digest(0xA3)];
    attachment(b"receipt.pdf", &chunks)
        .accept_chunks(&chunks)
        .expect("its own chunks");
}

#[test]
fn a_withheld_chunk_is_refused_as_a_count_disagreement() {
    let chunks = [digest(0xA1), digest(0xA2), digest(0xA3)];
    let entry = attachment(b"receipt.pdf", &chunks);

    let out = entry.accept_chunks(&chunks[..2]);
    assert!(
        matches!(
            out,
            Err(ManifestError::AttachmentChunkCountDisagrees {
                declared: 3,
                delivered: 2
            })
        ),
        "{out:?}"
    );
}

#[test]
fn an_extra_chunk_is_refused_as_a_count_disagreement() {
    let chunks = [digest(0xA1), digest(0xA2)];
    let entry = attachment(b"receipt.pdf", &chunks);

    let out = entry.accept_chunks(&[digest(0xA1), digest(0xA2), digest(0xFF)]);
    assert!(
        matches!(
            out,
            Err(ManifestError::AttachmentChunkCountDisagrees {
                declared: 2,
                delivered: 3
            })
        ),
        "{out:?}"
    );
}

#[test]
fn a_replayed_chunk_is_refused_by_the_root() {
    let current = [digest(0xA1), digest(0xA2), digest(0xA3)];
    let entry = attachment(b"receipt.pdf", &current);

    // Yesterday's second chunk: the right count, the wrong bytes.
    let replayed = [digest(0xA1), digest(0x5E), digest(0xA3)];
    assert!(
        matches!(
            entry.accept_chunks(&replayed),
            Err(ManifestError::ChunkDigestRootMismatch)
        ),
        "a replayed chunk was accepted"
    );
}

#[test]
fn a_reordered_delivery_is_refused_by_the_root() {
    let current = [digest(0xA1), digest(0xA2), digest(0xA3)];
    let entry = attachment(b"receipt.pdf", &current);
    let shuffled = [digest(0xA3), digest(0xA2), digest(0xA1)];
    assert!(
        matches!(
            entry.accept_chunks(&shuffled),
            Err(ManifestError::ChunkDigestRootMismatch)
        ),
        "a reordered delivery was accepted"
    );
}

#[test]
fn the_three_indistinguishable_causes_share_one_name() {
    let current = [digest(0xA1), digest(0xA2)];
    let entry = attachment(b"receipt.pdf", &current);

    let replayed = [digest(0xA1), digest(0x5E)];
    let reordered = [digest(0xA2), digest(0xA1)];
    let stale = [digest(0x5D), digest(0x5E)];

    for case in [replayed, reordered, stale] {
        assert!(
            matches!(
                entry.accept_chunks(&case),
                Err(ManifestError::ChunkDigestRootMismatch)
            ),
            "{case:?} did not get the shared name"
        );
    }
}

#[test]
fn the_count_is_reported_before_the_root_when_a_delivery_fails_both() {
    let entry = attachment(b"receipt.pdf", &[digest(0xA1), digest(0xA2)]);
    let out = entry.accept_chunks(&[digest(0xFF)]);
    assert!(
        matches!(
            out,
            Err(ManifestError::AttachmentChunkCountDisagrees { .. })
        ),
        "a delivery that is both short and wrong reported the root: {out:?}"
    );
}

fn entry_with(attachments: Vec<AttachmentEntry>) -> Entry {
    Entry::new(b"item-1".to_vec(), 4, digest(0x11), false, attachments)
}

#[test]
fn an_entrys_whole_attachment_set_verifies() {
    let a = [digest(0xA1), digest(0xA2)];
    let b = [digest(0xB1)];
    let entry = entry_with(vec![attachment(b"a.pdf", &a), attachment(b"b.png", &b)]);

    entry
        .accept_attachments(&[
            (b"a.pdf".as_slice(), a.to_vec()),
            (b"b.png".as_slice(), b.to_vec()),
        ])
        .expect("its own set");
}

#[test]
fn an_attachment_the_entry_names_and_the_server_withholds_is_refused_by_name() {
    let a = [digest(0xA1)];
    let b = [digest(0xB1)];
    let entry = entry_with(vec![attachment(b"a.pdf", &a), attachment(b"b.png", &b)]);

    let out = entry.accept_attachments(&[(b"a.pdf".as_slice(), a.to_vec())]);
    assert!(
        matches!(out, Err(ManifestError::AttachmentListedNotDelivered)),
        "{out:?}"
    );
}

#[test]
fn an_attachment_the_entry_does_not_name_is_refused_by_name() {
    let a = [digest(0xA1)];
    let entry = entry_with(vec![attachment(b"a.pdf", &a)]);

    let out = entry.accept_attachments(&[
        (b"a.pdf".as_slice(), a.to_vec()),
        (b"ghost.pdf".as_slice(), vec![digest(0xCC)]),
    ]);
    assert!(
        matches!(out, Err(ManifestError::AttachmentDeliveredNotListed)),
        "{out:?}"
    );
}

#[derive(Default)]
struct RecordingFetcher {
    requested: BTreeSet<Vec<u8>>,
}

impl RecordingFetcher {
    fn fetch_for(&mut self, entry: &Entry) {
        for (id, _) in entry.referenced_attachments() {
            self.requested.insert(id.to_vec());
        }
    }
}

#[test]
fn only_chunks_the_current_entry_names_are_ever_requested() {
    let current = entry_with(vec![
        attachment(b"a.pdf", &[digest(0xA1)]),
        attachment(b"b.png", &[digest(0xB1)]),
    ]);
    // A previous version named a third attachment, now superseded.
    let superseded: BTreeSet<Vec<u8>> = [b"old.pdf".to_vec()].into_iter().collect();

    let mut fetcher = RecordingFetcher::default();
    fetcher.fetch_for(&current);

    let named: BTreeSet<Vec<u8>> = current
        .referenced_attachments()
        .into_iter()
        .map(|(id, _)| id.to_vec())
        .collect();

    assert!(
        fetcher.requested.is_subset(&named),
        "the client asked for something the current entry does not name"
    );
    assert!(
        fetcher.requested.is_disjoint(&superseded),
        "the client asked for a superseded attachment"
    );
    assert!(!fetcher.requested.is_empty(), "it asked for nothing at all");
}

#[test]
fn an_attachment_conflict_needs_no_attachment_level_rule() {
    let mine = ConflictingVersion::new(b"item-1".to_vec(), 4, digest(0xA1));
    let theirs = ConflictingVersion::new(b"item-1".to_vec(), 4, digest(0x5C));

    let on_a = resolve(&mine, &theirs);
    let on_b = resolve(&theirs, &mine);
    assert_eq!(on_a, on_b, "the two devices diverge");

    match on_a {
        Resolution::Conflict { primary, copy, .. } => {
            let kept = [*primary.ciphertext_digest(), *copy.ciphertext_digest()];
            assert!(
                kept.contains(&digest(0xA1)),
                "my attachment set was dropped"
            );
            assert!(
                kept.contains(&digest(0x5C)),
                "their attachment set was dropped"
            );
        }
        Resolution::SameEdit => panic!("different sets are different edits"),
    }
}

#[test]
fn each_version_keeps_the_attachment_set_it_wrote() {
    let a = [digest(0xA1)];
    let b = [digest(0xB1)];
    let primary = entry_with(vec![attachment(b"mine.pdf", &a)]);
    let copy = Entry::new(
        b"copy-1".to_vec(),
        1,
        digest(0x5C),
        false,
        vec![attachment(b"theirs.pdf", &b)],
    );

    assert_eq!(primary.attachments().len(), 1);
    assert_eq!(copy.attachments().len(), 1);
    assert_eq!(
        primary.attachments().first().expect("one").attachment_id(),
        b"mine.pdf"
    );
    assert_eq!(
        copy.attachments().first().expect("one").attachment_id(),
        b"theirs.pdf"
    );
    primary
        .accept_attachments(&[(b"mine.pdf".as_slice(), a.to_vec())])
        .expect("the primary's own set");
    copy.accept_attachments(&[(b"theirs.pdf".as_slice(), b.to_vec())])
        .expect("the copy's own set");
}
