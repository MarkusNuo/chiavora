#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use chiavora_core::aad::AadFields;
use chiavora_core::manifest::{
    hash_item_id, open_root, open_segment, seal_root, seal_segment, CanonicalPrefix, Entry,
    ManifestError, ManifestRoot, ManifestSegment, RootEntry, StoredManifest,
};
use chiavora_core::nonce::FreshNonce;
use chiavora_core::secret::{kind::VaultKey, Secret};
use sha2::Digest;

const VAULT: &[u8] = b"vault-1";
const TOP_HALF: u64 = 0x8000_0000_0000_0000;

fn key() -> Secret<VaultKey> {
    Secret::<VaultKey>::from_derived_bytes(vec![0x22; 32])
}

fn prefix(len: u8, bits: u64) -> CanonicalPrefix {
    CanonicalPrefix::new(len, bits).expect("canonical")
}

fn segment_fields(prefix: CanonicalPrefix, seq: u64) -> AadFields {
    AadFields::ManifestSegment {
        vault_id: VAULT.to_vec(),
        segment_seq: seq,
        vault_key_epoch: 1,
        prefix_len: prefix.bit_len(),
        prefix_bits: prefix.bits(),
    }
}

fn root_fields(count: u32, seq: u64) -> AadFields {
    AadFields::ManifestRoot {
        vault_id: VAULT.to_vec(),
        manifest_seq: seq,
        vault_key_epoch: 1,
        segment_count: count,
    }
}

fn entry(n: usize) -> Entry {
    Entry::new(
        format!("item-{n:04}").into_bytes(),
        1,
        [u8::try_from(n % 251).expect("fits"); 32],
        false,
        Vec::new(),
    )
}

fn seal(segment: &ManifestSegment) -> StoredManifest {
    seal_segment(&key(), FreshNonce::generate().expect("nonce"), segment).expect("seals")
}

#[test]
fn hash_item_id_is_sha256s_top_64_bits_big_endian() {
    // SHA-256("") = e3b0c442 98fc1c14 9afbf4c8 996fb924 …
    assert_eq!(hash_item_id(b""), 0xe3b0_c442_98fc_1c14);
    // SHA-256("abc") = ba7816bf 8f01cfea 414140de 5dae2223 …
    assert_eq!(hash_item_id(b"abc"), 0xba78_16bf_8f01_cfea);
    // The shape these tests hash, taken from the digest rather than transcribed.
    let digest = sha2::Sha256::digest(b"item-0000");
    let top = digest.get(..8).expect("a digest is 32 bytes");
    assert_eq!(
        hash_item_id(b"item-0000"),
        u64::from_be_bytes(<[u8; 8]>::try_from(top).expect("eight bytes"))
    );
}

#[test]
fn the_first_digest_byte_is_the_most_significant_hash_byte() {
    for n in 0..64_usize {
        let id = format!("item-{n:04}").into_bytes();
        let digest = sha2::Sha256::digest(&id);
        let first = *digest.first().expect("a digest byte");
        assert_eq!(
            u8::try_from(hash_item_id(&id) >> 56).expect("top byte"),
            first,
            "a little-endian read would put the digest's LAST byte here, and \
             nothing would fail — items would just land in the wrong segments"
        );
    }
}

#[test]
fn no_assignment_path_takes_a_segment_count() {
    let source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("manifest.rs"),
    )
    .expect("manifest.rs");
    let code: String = source
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");

    for forbidden in ["% segment", "% count", "% self.segments", "rehash"] {
        assert!(
            !code.contains(forbidden),
            "`{forbidden}` in manifest.rs: §2.5 forbids assignment by modulus, \
             because doubling one moves most items at once"
        );
    }
}

fn oversized() -> ManifestSegment {
    let entries: Vec<Entry> = (0..600).map(entry).collect();
    ManifestSegment::new(segment_fields(prefix(0, 0), 1), entries).expect("a segment")
}

#[test]
fn a_segment_over_the_bound_reports_it() {
    assert!(oversized().is_over_split_bound());
    let small =
        ManifestSegment::new(segment_fields(prefix(0, 0), 1), vec![entry(1)]).expect("a segment");
    assert!(!small.is_over_split_bound());
}

#[test]
fn a_split_puts_every_entry_under_the_prefix_it_hashes_to() {
    let (low, high) = oversized().split(2).expect("splits");

    assert_eq!(low.prefix().expect("prefix").bit_len(), 1);
    assert_eq!(high.prefix().expect("prefix").bit_len(), 1);

    for segment in [&low, &high] {
        for e in segment.entries() {
            assert!(
                segment.owns(hash_item_id(e.item_id())).expect("owns"),
                "an entry is in a segment whose prefix its hash does not match"
            );
        }
    }

    assert_eq!(
        low.entries().len() + high.entries().len(),
        600,
        "a split moves entries, it does not lose or duplicate them"
    );
    // Both halves get some, or the test is not exercising a split at all.
    assert!(!low.entries().is_empty() && !high.entries().is_empty());
}

#[test]
fn a_split_at_64_bits_is_refused_rather_than_silently_doing_nothing() {
    let deep = ManifestSegment::new(segment_fields(prefix(64, u64::MAX), 1), Vec::new())
        .expect("a segment");
    assert!(
        matches!(
            deep.split(2),
            Err(ManifestError::NonCanonicalPrefix(
                chiavora_core::aad::AadError::PrefixLenTooLarge
            ))
        ),
        "a split that silently did nothing would loop"
    );
}

#[test]
fn a_split_leaves_every_other_segments_bytes_identical() {
    let bottom =
        ManifestSegment::new(segment_fields(prefix(1, 0), 1), vec![entry(1)]).expect("bottom");
    let top_entries: Vec<Entry> = (0..600)
        .map(entry)
        .filter(|e| prefix(1, TOP_HALF).contains(hash_item_id(e.item_id())))
        .collect();
    let top =
        ManifestSegment::new(segment_fields(prefix(1, TOP_HALF), 1), top_entries).expect("top");

    let stored_bottom = seal(&bottom);
    let stored_top = seal(&top);
    let before = ManifestRoot::new(
        root_fields(2, 1),
        vec![
            RootEntry::new(prefix(1, 0), stored_bottom.digest().expect("d"), 1),
            RootEntry::new(prefix(1, TOP_HALF), stored_top.digest().expect("d"), 1),
        ],
    )
    .expect("a root");

    let (low, high) = top.split(2).expect("splits");
    let stored_low = seal(&low);
    let stored_high = seal(&high);
    let after = before
        .with_split(
            prefix(1, TOP_HALF),
            (&stored_low, low.prefix().expect("p")),
            (&stored_high, high.prefix().expect("p")),
            2,
        )
        .expect("the new root");

    let before_bottom = before
        .segments()
        .iter()
        .find(|e| e.prefix() == prefix(1, 0))
        .expect("before");
    let after_bottom = after
        .segments()
        .iter()
        .find(|e| e.prefix() == prefix(1, 0))
        .expect("after");
    assert_eq!(before_bottom, after_bottom, "an untouched segment moved");

    assert_eq!(after.segments().len(), 3, "two became three");
    after.check_tiles().expect("the post-split root tiles");
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Interruption {
    BeforeWrite,
    WriteRefused,
    AfterWriteBeforeMark,
}

const ALL_INTERRUPTIONS: [Interruption; 3] = [
    Interruption::BeforeWrite,
    Interruption::WriteRefused,
    Interruption::AfterWriteBeforeMark,
];

#[test]
fn a_split_interrupted_at_every_step_leaves_an_authenticable_vault() {
    let key = key();
    let mut exercised = 0_usize;

    for point in ALL_INTERRUPTIONS {
        let whole = ManifestSegment::new(
            segment_fields(prefix(0, 0), 1),
            (0..600).map(entry).collect(),
        )
        .expect("a segment");
        let stored_whole = seal(&whole);
        let before = ManifestRoot::new(
            root_fields(1, 1),
            vec![RootEntry::new(
                prefix(0, 0),
                stored_whole.digest().expect("d"),
                1,
            )],
        )
        .expect("a root");

        let mut server_root = seal_root(&key, FreshNonce::generate().expect("n"), &before)
            .expect("seals")
            .encode()
            .expect("encodes");
        let mut server_segments = vec![stored_whole.encode().expect("encodes")];

        let (low, high) = whole.split(2).expect("splits");
        let stored_low = seal(&low);
        let stored_high = seal(&high);
        let after = before
            .with_split(
                prefix(0, 0),
                (&stored_low, low.prefix().expect("p")),
                (&stored_high, high.prefix().expect("p")),
                2,
            )
            .expect("the new root");
        let new_root_bytes = seal_root(&key, FreshNonce::generate().expect("n"), &after)
            .expect("seals")
            .encode()
            .expect("encodes");
        let new_segment_bytes = vec![
            stored_low.encode().expect("encodes"),
            stored_high.encode().expect("encodes"),
        ];

        match point {
            Interruption::BeforeWrite | Interruption::WriteRefused => {
                // Nothing lands: a refused write and a kill before writing leave the same vault.
            }
            Interruption::AfterWriteBeforeMark => {
                server_root = new_root_bytes;
                server_segments = new_segment_bytes;
            }
        }

        let root = open_root(
            &key,
            &StoredManifest::decode(&server_root).expect("decodes"),
        )
        .expect("the root opens");
        root.accept(None).expect("the root is authentic and tiles");

        assert_eq!(
            root.segments().len(),
            server_segments.len(),
            "{point:?}: the root vouches for a different number of segments \
             than the vault holds — a half-applied split"
        );

        for bytes in &server_segments {
            let stored = StoredManifest::decode(bytes).expect("decodes");
            root.accept_segment(&stored).unwrap_or_else(|e| {
                panic!("{point:?}: a segment the root does not vouch for: {e}")
            });
            let segment = open_segment(&key, &stored).expect("opens");
            for e in segment.entries() {
                assert!(
                    segment.owns(hash_item_id(e.item_id())).expect("owns"),
                    "{point:?}: an entry outside its segment's prefix"
                );
            }
        }

        let total: usize = server_segments
            .iter()
            .map(|b| {
                let stored = StoredManifest::decode(b).expect("decodes");
                open_segment(&key, &stored).expect("opens").entries().len()
            })
            .sum();
        assert_eq!(total, 600, "{point:?}: items were lost by the interruption");

        exercised += 1;
    }

    assert_eq!(
        exercised,
        ALL_INTERRUPTIONS.len(),
        "an interruption point vanished from the harness"
    );
    assert_eq!(exercised, 3, "the harness covers three points");
}
