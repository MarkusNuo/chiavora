#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use chiavora_core::aad::AadFields;
use chiavora_core::manifest::{seal_root, CanonicalPrefix, ManifestRoot, RootEntry};
use chiavora_core::n3::{compare, compare_with, DeviceMark, MarkComparison, N3Posture};
use chiavora_core::nonce::FreshNonce;
use chiavora_core::secret::{kind::VaultKey, Secret};

const VAULT: &[u8] = b"vault-1";

fn key() -> Secret<VaultKey> {
    Secret::<VaultKey>::from_derived_bytes(vec![0x22; 32])
}

fn mark(seq: u64, fill: u8) -> DeviceMark {
    let whole = CanonicalPrefix::new(0, 0).expect("whole");
    let root = ManifestRoot::new(
        AadFields::ManifestRoot {
            vault_id: VAULT.to_vec(),
            manifest_seq: seq,
            vault_key_epoch: 1,
            segment_count: 1,
        },
        vec![RootEntry::new(whole, [fill; 32], seq)],
    )
    .expect("root");
    let stored = seal_root(&key(), FreshNonce::generate().expect("nonce"), &root).expect("seals");
    DeviceMark::of(&root, &stored).expect("mark")
}

#[test]
fn the_same_sequence_and_the_same_root_agree() {
    let whole = CanonicalPrefix::new(0, 0).expect("whole");
    let root = ManifestRoot::new(
        AadFields::ManifestRoot {
            vault_id: VAULT.to_vec(),
            manifest_seq: 7,
            vault_key_epoch: 1,
            segment_count: 1,
        },
        vec![RootEntry::new(whole, [0x11; 32], 7)],
    )
    .expect("root");
    // One sealed record, two marks: two seals would differ by nonce and read as a fork.
    let stored = seal_root(&key(), FreshNonce::generate().expect("nonce"), &root).expect("seals");
    let a = DeviceMark::of(&root, &stored).expect("mark");
    let b = DeviceMark::of(&root, &stored).expect("mark");

    assert_eq!(compare(&a, &b), MarkComparison::Agree { manifest_seq: 7 });
}

#[test]
fn the_same_sequence_with_different_roots_is_a_fork() {
    assert_eq!(
        compare(&mark(7, 0x11), &mark(7, 0x99)),
        MarkComparison::Forked { manifest_seq: 7 }
    );
}

#[test]
fn different_sequences_report_which_is_behind() {
    assert_eq!(
        compare(&mark(9, 0x11), &mark(4, 0x22)),
        MarkComparison::Behind {
            ahead: 9,
            behind: 4
        }
    );
}

#[test]
fn the_comparison_is_symmetric_in_its_arguments() {
    for (x, y) in [
        (mark(7, 0x11), mark(7, 0x11)),
        (mark(7, 0x11), mark(7, 0x99)),
        (mark(9, 0x11), mark(4, 0x22)),
        (mark(4, 0x22), mark(9, 0x11)),
    ] {
        assert_eq!(
            compare(&x, &y),
            compare(&y, &x),
            "argument order changed the answer"
        );
    }
}

#[test]
fn a_freeze_and_a_forgotten_phone_are_the_same_outcome() {
    // A server holding device B at seq 4 while the vault really moved to 9.
    let frozen = compare(&mark(9, 0x11), &mark(4, 0x22));
    // Device B simply has not synced since seq 4. Same two numbers.
    let forgotten = compare(&mark(9, 0x11), &mark(4, 0x22));

    assert_eq!(
        frozen, forgotten,
        "the comparison distinguishes a freeze from a lag, which two marks cannot"
    );
    assert!(
        matches!(frozen, MarkComparison::Behind { .. }),
        "and the outcome is named Behind, not named after either explanation"
    );
}

#[test]
fn no_second_device_is_unverified_and_not_agreement() {
    let posture = compare_with(&mark(7, 0x11), None);
    assert_eq!(posture, N3Posture::Unverified);
    assert_ne!(
        posture,
        N3Posture::Compared(MarkComparison::Agree { manifest_seq: 7 }),
        "an absent comparison is being reported as a successful one"
    );
}

#[test]
fn a_reachable_device_yields_the_comparison() {
    let theirs = mark(7, 0x99);
    assert_eq!(
        compare_with(&mark(7, 0x11), Some(&theirs)),
        N3Posture::Compared(MarkComparison::Forked { manifest_seq: 7 })
    );
}

#[test]
fn a_mark_takes_both_halves_from_one_root() {
    let a = mark(7, 0x11);
    let b = mark(8, 0x11);
    assert_eq!(a.manifest_seq(), 7);
    assert_eq!(b.manifest_seq(), 8);
    assert_ne!(
        a.root_digest(),
        b.root_digest(),
        "two roots at different sequences produced one digest"
    );
}
