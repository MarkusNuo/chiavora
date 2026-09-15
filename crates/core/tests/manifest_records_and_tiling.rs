//! The §2.5 manifest as a parser.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use chiavora_core::aad::{self, AadFields};
use chiavora_core::manifest::{
    attachment_tag, entry_tag, root_entry_tag, root_tag, segment_tag, AttachmentEntry,
    CanonicalPrefix, Entry, ManifestError, ManifestRoot, ManifestSegment, RootEntry,
};
use chiavora_protocol::{Field, Record};

const TOP_HALF: u64 = 0x8000_0000_0000_0000;

fn root_fields(segment_count: u32, manifest_seq: u64) -> AadFields {
    AadFields::ManifestRoot {
        vault_id: b"vault-1".to_vec(),
        manifest_seq,
        vault_key_epoch: 1,
        segment_count,
    }
}

fn segment_fields(prefix_len: u8, prefix_bits: u64, segment_seq: u64) -> AadFields {
    AadFields::ManifestSegment {
        vault_id: b"vault-1".to_vec(),
        segment_seq,
        vault_key_epoch: 1,
        prefix_len,
        prefix_bits,
    }
}

fn digest(fill: u8) -> [u8; 32] {
    [fill; 32]
}

fn prefix(len: u8, bits: u64) -> CanonicalPrefix {
    CanonicalPrefix::new(len, bits).expect("a canonical prefix")
}

/// One `manifest_decode` seed: `u16le(len) ‖ AAD bytes ‖ body bytes`. The
/// server chooses the AAD independently of the body, so the fuzzer does too.
fn seed(fields: &AadFields, body: &[u8]) -> Vec<u8> {
    let aad = aad::encode(fields).expect("aad encodes");
    let len = u16::try_from(aad.len()).expect("aad fits");
    let mut out = len.to_le_bytes().to_vec();
    out.extend_from_slice(&aad);
    out.extend_from_slice(body);
    out
}

/// A root body encoded by hand, so a test can plant a prefix the type system refuses.
fn root_body_from_raw(entries: &[(u8, u64, [u8; 32], u64)]) -> Vec<u8> {
    let mut fields = Vec::new();
    for (len, bits, dig, seq) in entries {
        let inner = Record::new(vec![
            Field::new(root_entry_tag::PREFIX_LEN, vec![*len]).expect("field"),
            Field::new(root_entry_tag::PREFIX_BITS, bits.to_le_bytes().to_vec()).expect("field"),
            Field::new(root_entry_tag::DIGEST, dig.to_vec()).expect("field"),
            Field::new(root_entry_tag::SEGMENT_SEQ, seq.to_le_bytes().to_vec()).expect("field"),
        ])
        .encode()
        .expect("inner record");
        fields.push(Field::new(root_tag::SEGMENT, inner).expect("field"));
    }
    Record::new(fields).encode().expect("root body")
}

#[test]
fn a_root_round_trips_through_its_body_encoding() {
    let segments = vec![
        RootEntry::new(prefix(1, 0), digest(0xA1), 7),
        RootEntry::new(prefix(1, TOP_HALF), digest(0xB2), 9),
    ];
    let root = ManifestRoot::new(root_fields(2, 41), segments).expect("a root");
    let body = root.encode_body().expect("encodes");
    let again = ManifestRoot::decode(root_fields(2, 41), &body).expect("decodes");

    assert_eq!(again, root);
    assert_eq!(again.manifest_seq(), 41, "manifestSeq is read from the AAD");
    assert_eq!(again.vault_key_epoch(), 1);
    assert_eq!(
        again.encode_body().expect("re-encodes"),
        body,
        "encode is not idempotent"
    );
}

#[test]
fn a_segment_round_trips_with_tombstones_and_attachments() {
    let entries = vec![
        Entry::new(b"item-live".to_vec(), 3, digest(0x11), false, Vec::new()),
        Entry::new(b"item-gone".to_vec(), 9, digest(0x22), true, Vec::new()),
        Entry::new(
            b"item-with-files".to_vec(),
            2,
            digest(0x33),
            false,
            vec![
                AttachmentEntry::new(b"att-1".to_vec(), 4, digest(0x44), 4 << 20),
                AttachmentEntry::new(b"att-2".to_vec(), 1, digest(0x55), 512),
            ],
        ),
    ];
    let segment = ManifestSegment::new(segment_fields(0, 0, 41), entries).expect("a segment");
    let body = segment.encode_body().expect("encodes");
    let again = ManifestSegment::decode(segment_fields(0, 0, 41), &body).expect("decodes");

    assert_eq!(again, segment);
    assert_eq!(again.segment_seq(), 41, "segmentSeq is read from the AAD");
    assert_eq!(again.prefix().expect("prefix").bit_len(), 0);
    assert!(again.entries().iter().any(Entry::tombstone));
    assert_eq!(
        again.encode_body().expect("re-encodes"),
        body,
        "encode is not idempotent"
    );
}

#[test]
fn i6b_a_prefix_longer_than_the_keyspace_is_refused() {
    assert!(matches!(
        CanonicalPrefix::new(65, 0),
        Err(ManifestError::NonCanonicalPrefix(
            aad::AadError::PrefixLenTooLarge
        ))
    ));
}

#[test]
fn i6b_a_prefix_with_bits_below_the_boundary_is_refused() {
    assert!(matches!(
        CanonicalPrefix::new(1, TOP_HALF | 1),
        Err(ManifestError::NonCanonicalPrefix(
            aad::AadError::PrefixBitsNotCanonical
        ))
    ));
    assert!(
        matches!(
            CanonicalPrefix::new(0, 1),
            Err(ManifestError::NonCanonicalPrefix(
                aad::AadError::PrefixBitsNotCanonical
            ))
        ),
        "at prefixLen 0 every bit is unused, so prefixBits must be zero"
    );
}

#[test]
fn i6b_a_root_that_would_tile_only_after_normalisation_is_refused_outright() {
    // Two encodings of the top half: the spans sum to the keyspace, the bottom half is uncovered.
    let hostile = root_body_from_raw(&[
        (1, TOP_HALF, digest(0xC1), 1),
        (1, TOP_HALF | 1, digest(0xC2), 1),
    ]);

    let span = 1_u128 << 63;
    assert_eq!(
        span + span,
        1_u128 << 64,
        "the sum-of-spans shortcut passes"
    );

    let refused = ManifestRoot::decode(root_fields(2, 1), &hostile);
    assert!(
        matches!(
            refused,
            Err(ManifestError::NonCanonicalPrefix(
                aad::AadError::PrefixBitsNotCanonical
            ))
        ),
        "a non-canonical prefix must fail I6b outright, never be normalised and \
         then tiled; got {refused:?}"
    );

    let normalised = [prefix(1, TOP_HALF), prefix(1, TOP_HALF)];
    assert!(
        matches!(
            chiavora_core::manifest::tiles_exactly(&normalised),
            Err(ManifestError::PrefixSetHasGap {
                from: 0,
                through: t
            }) if t == TOP_HALF - 1
        ),
        "normalising two encodings of one prefix hides the bottom half, and the          check must say which half"
    );
}

#[test]
fn i6b_a_single_segment_at_prefix_zero_tiles_the_keyspace() {
    let root = ManifestRoot::new(
        root_fields(1, 1),
        vec![RootEntry::new(prefix(0, 0), digest(1), 1)],
    )
    .expect("a root");
    assert!(root.check_tiles().is_ok(), "a new vault is one segment");
}

#[test]
fn i6b_a_split_keyspace_tiles_at_every_depth() {
    // 0xx, 10x, 110, 111 — four segments at three depths, no gap, no overlap.
    let quarter = 1_u64 << 62;
    let root = ManifestRoot::new(
        root_fields(4, 5),
        vec![
            RootEntry::new(prefix(1, 0), digest(1), 5),
            RootEntry::new(prefix(2, TOP_HALF), digest(2), 4),
            RootEntry::new(prefix(3, TOP_HALF | quarter), digest(3), 5),
            RootEntry::new(prefix(3, TOP_HALF | quarter | (quarter >> 1)), digest(4), 3),
        ],
    )
    .expect("a root");
    assert!(root.check_tiles().is_ok());
}

#[test]
fn i6b_a_gapped_prefix_set_names_the_range_no_segment_covers() {
    let root = ManifestRoot::new(
        root_fields(1, 1),
        vec![RootEntry::new(prefix(1, TOP_HALF), digest(1), 1)],
    )
    .expect("a root");
    match root.check_tiles() {
        Err(ManifestError::PrefixSetHasGap { from, through }) => {
            assert_eq!(from, 0);
            assert_eq!(through, TOP_HALF - 1, "the whole bottom half is hidden");
        }
        other => panic!("a gapped root must name its gap, got {other:?}"),
    }
}

#[test]
fn i6b_a_gap_at_the_top_of_the_keyspace_is_found_too() {
    let root = ManifestRoot::new(
        root_fields(1, 1),
        vec![RootEntry::new(prefix(1, 0), digest(1), 1)],
    )
    .expect("a root");
    match root.check_tiles() {
        Err(ManifestError::PrefixSetHasGap { from, through }) => {
            assert_eq!(from, TOP_HALF);
            assert_eq!(through, u64::MAX);
        }
        other => panic!("a gap that runs to the end must be found, got {other:?}"),
    }
}

#[test]
fn i6b_an_overlapping_prefix_set_names_a_doubly_covered_hash() {
    let root = ManifestRoot::new(
        root_fields(3, 1),
        vec![
            RootEntry::new(prefix(1, 0), digest(1), 1),
            RootEntry::new(prefix(1, TOP_HALF), digest(2), 1),
            RootEntry::new(prefix(2, TOP_HALF), digest(3), 1),
        ],
    )
    .expect("a root");
    assert!(matches!(
        root.check_tiles(),
        Err(ManifestError::PrefixSetOverlaps { at }) if at == TOP_HALF
    ));
}

#[test]
fn an_empty_root_does_not_tile() {
    let root = ManifestRoot::new(root_fields(0, 1), Vec::new()).expect("a root");
    assert!(
        matches!(
            root.check_tiles(),
            Err(ManifestError::PrefixSetHasGap {
                from: 0,
                through: u64::MAX
            })
        ),
        "a root with no segments hides every item, and must say so"
    );
}

#[test]
fn lookup_is_longest_prefix_match() {
    let quarter = 1_u64 << 62;
    let root = ManifestRoot::new(
        root_fields(3, 1),
        vec![
            RootEntry::new(prefix(1, 0), digest(1), 1),
            RootEntry::new(prefix(2, TOP_HALF), digest(2), 1),
            RootEntry::new(prefix(2, TOP_HALF | quarter), digest(3), 1),
        ],
    )
    .expect("a root");

    assert_eq!(
        root.segment_for(0).map(RootEntry::digest),
        Some(&digest(1)),
        "the bottom half"
    );
    assert_eq!(
        root.segment_for(TOP_HALF | quarter | 7)
            .map(RootEntry::digest),
        Some(&digest(3)),
        "the longest matching prefix wins"
    );
    assert_eq!(
        root.segment_for(u64::MAX).map(RootEntry::digest),
        Some(&digest(3))
    );
}

#[test]
fn a_root_whose_declared_count_disagrees_with_its_body_is_refused() {
    let segments = vec![RootEntry::new(prefix(0, 0), digest(1), 1)];
    assert!(matches!(
        ManifestRoot::new(root_fields(2, 1), segments.clone()),
        Err(ManifestError::SegmentCountDisagrees {
            declared: 2,
            present: 1
        })
    ));

    let body = ManifestRoot::new(root_fields(1, 1), segments)
        .expect("a root")
        .encode_body()
        .expect("encodes");
    assert!(matches!(
        ManifestRoot::decode(root_fields(9, 1), &body),
        Err(ManifestError::SegmentCountDisagrees {
            declared: 9,
            present: 1
        })
    ));
}

#[test]
fn a_root_aad_is_not_a_segment_aad() {
    assert!(matches!(
        ManifestRoot::new(segment_fields(0, 0, 1), Vec::new()),
        Err(ManifestError::NotAManifestRoot)
    ));
    assert!(matches!(
        ManifestSegment::new(root_fields(0, 1), Vec::new()),
        Err(ManifestError::NotAManifestSegment)
    ));
}

#[test]
fn a_tombstone_byte_that_is_neither_zero_nor_one_is_refused() {
    let inner = Record::new(vec![
        Field::new(entry_tag::ITEM_ID, b"item".to_vec()).expect("field"),
        Field::new(entry_tag::CURRENT_VERSION, 1_u64.to_le_bytes().to_vec()).expect("field"),
        Field::new(entry_tag::CIPHERTEXT_DIGEST, digest(7).to_vec()).expect("field"),
        Field::new(entry_tag::TOMBSTONE, vec![2]).expect("field"),
    ])
    .encode()
    .expect("inner");
    let body = Record::new(vec![Field::new(segment_tag::ENTRY, inner).expect("field")])
        .encode()
        .expect("body");

    assert!(matches!(
        ManifestSegment::decode(segment_fields(0, 0, 1), &body),
        Err(ManifestError::NotABoolean)
    ));
}

#[test]
fn a_reordered_record_is_refused_rather_than_accepted_as_a_second_encoding() {
    // `digest` before `version`: one logical entry, a second byte string.
    let inner = Record::new(vec![
        Field::new(entry_tag::ITEM_ID, b"item".to_vec()).expect("field"),
        Field::new(entry_tag::CIPHERTEXT_DIGEST, digest(7).to_vec()).expect("field"),
        Field::new(entry_tag::CURRENT_VERSION, 1_u64.to_le_bytes().to_vec()).expect("field"),
        Field::new(entry_tag::TOMBSTONE, vec![0]).expect("field"),
    ])
    .encode()
    .expect("inner");
    let body = Record::new(vec![Field::new(segment_tag::ENTRY, inner).expect("field")])
        .encode()
        .expect("body");

    assert!(matches!(
        ManifestSegment::decode(segment_fields(0, 0, 1), &body),
        Err(ManifestError::UnexpectedField {
            expected: entry_tag::CURRENT_VERSION
        })
    ));
}

#[test]
fn a_fixed_width_field_of_the_wrong_length_is_refused() {
    let inner = Record::new(vec![
        Field::new(root_entry_tag::PREFIX_LEN, vec![0]).expect("field"),
        Field::new(root_entry_tag::PREFIX_BITS, vec![0, 0, 0]).expect("field"),
        Field::new(root_entry_tag::DIGEST, digest(1).to_vec()).expect("field"),
        Field::new(root_entry_tag::SEGMENT_SEQ, 1_u64.to_le_bytes().to_vec()).expect("field"),
    ])
    .encode()
    .expect("inner");
    let body = Record::new(vec![Field::new(root_tag::SEGMENT, inner).expect("field")])
        .encode()
        .expect("body");

    assert!(matches!(
        ManifestRoot::decode(root_fields(1, 1), &body),
        Err(ManifestError::BadFieldLength {
            tag: root_entry_tag::PREFIX_BITS
        })
    ));
}

#[test]
fn an_unknown_trailing_field_is_refused() {
    let inner = Record::new(vec![
        Field::new(attachment_tag::ATTACHMENT_ID, b"a".to_vec()).expect("field"),
        Field::new(attachment_tag::CHUNK_COUNT, 1_u32.to_le_bytes().to_vec()).expect("field"),
        Field::new(attachment_tag::CHUNK_DIGEST_ROOT, digest(1).to_vec()).expect("field"),
        Field::new(attachment_tag::TOTAL_SIZE, 1_u64.to_le_bytes().to_vec()).expect("field"),
        Field::new(99, b"extra".to_vec()).expect("field"),
    ])
    .encode()
    .expect("inner");
    let entry = Record::new(vec![
        Field::new(entry_tag::ITEM_ID, b"item".to_vec()).expect("field"),
        Field::new(entry_tag::CURRENT_VERSION, 1_u64.to_le_bytes().to_vec()).expect("field"),
        Field::new(entry_tag::CIPHERTEXT_DIGEST, digest(7).to_vec()).expect("field"),
        Field::new(entry_tag::TOMBSTONE, vec![0]).expect("field"),
        Field::new(entry_tag::ATTACHMENT, inner).expect("field"),
    ])
    .encode()
    .expect("entry");
    let body = Record::new(vec![Field::new(segment_tag::ENTRY, entry).expect("field")])
        .encode()
        .expect("body");

    assert!(matches!(
        ManifestSegment::decode(segment_fields(0, 0, 1), &body),
        Err(ManifestError::TrailingFields)
    ));
}

struct Noise(u64);

impl Noise {
    fn new() -> Self {
        Self(0x2545_F491_4F6C_DD1D)
    }

    fn take(&mut self, len: usize) -> Vec<u8> {
        let mut out = Vec::new();
        while out.len() < len {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            out.extend_from_slice(&self.0.to_le_bytes());
        }
        out.truncate(len);
        out
    }

    fn digest32(&mut self) -> [u8; 32] {
        let mut d = [0_u8; 32];
        d.copy_from_slice(&self.take(32));
        d
    }
}

fn corpus_dir() -> std::path::PathBuf {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("fuzz")
        .join("corpus")
        .join("manifest_decode");
    std::fs::create_dir_all(&dir).expect("corpus dir");
    dir
}

fn write_root_seeds(noise: &mut Noise) -> usize {
    let dir = corpus_dir();
    let quarter = 1_u64 << 62;
    let shapes: [(&str, Vec<(u8, u64)>); 6] = [
        ("root-single", vec![(0, 0)]),
        ("root-split-1", vec![(1, 0), (1, TOP_HALF)]),
        (
            "root-split-2",
            vec![(1, 0), (2, TOP_HALF), (2, TOP_HALF | quarter)],
        ),
        (
            "root-split-3",
            vec![
                (1, 0),
                (2, TOP_HALF),
                (3, TOP_HALF | quarter),
                (3, TOP_HALF | quarter | (quarter >> 1)),
            ],
        ),
        ("root-deep-64", vec![(0, 0), (64, u64::MAX)]),
        ("root-empty", Vec::new()),
    ];

    let mut written = 0;
    for (name, entries) in shapes {
        let mut segments = Vec::new();
        for (i, (len, bits)) in entries.iter().enumerate() {
            let seq = 41 + u64::try_from(i).expect("small");
            segments.push(RootEntry::new(prefix(*len, *bits), noise.digest32(), seq));
        }
        let count = u32::try_from(segments.len()).expect("count");
        let fields = root_fields(count, 41);
        let root = ManifestRoot::new(fields.clone(), segments).expect("root");
        std::fs::write(
            dir.join(name),
            seed(&fields, &root.encode_body().expect("encodes")),
        )
        .expect("seed");
        written += 1;
    }
    written
}

fn write_segment_seeds(noise: &mut Noise) -> usize {
    let dir = corpus_dir();
    let mut written = 0;
    for (name, count, with_tombstones, with_attachments) in [
        ("segment-empty", 0_usize, false, false),
        ("segment-one", 1, false, false),
        ("segment-tombstones", 6, true, false),
        ("segment-attachments", 4, false, true),
        ("segment-wide", 40, true, true),
    ] {
        let mut entries = Vec::new();
        for i in 0..count {
            let n = u64::try_from(i).expect("small");
            let attachments = if with_attachments && i % 2 == 0 {
                vec![AttachmentEntry::new(
                    noise.take(12),
                    u32::try_from(i + 1).expect("count"),
                    noise.digest32(),
                    (n + 1) * 4096,
                )]
            } else {
                Vec::new()
            };
            entries.push(Entry::new(
                noise.take(16),
                n + 1,
                noise.digest32(),
                with_tombstones && i % 3 == 0,
                attachments,
            ));
        }
        let fields = segment_fields(0, 0, 41);
        let segment = ManifestSegment::new(fields.clone(), entries).expect("segment");
        std::fs::write(
            dir.join(name),
            seed(&fields, &segment.encode_body().expect("encodes")),
        )
        .expect("seed");
        written += 1;
    }
    written
}

fn write_malformed_seeds(noise: &mut Noise) -> usize {
    let dir = corpus_dir();
    let two = root_fields(2, 41);
    let valid = root_body_from_raw(&[(1, 0, digest(0x10), 1), (1, TOP_HALF, digest(0x20), 1)]);
    let mut trailing = valid.clone();
    trailing.extend_from_slice(&noise.take(5));

    let cases: [(&str, Vec<u8>); 5] = [
        (
            "root-truncated",
            seed(&two, valid.get(..valid.len() / 2).unwrap_or_default()),
        ),
        ("root-trailing", seed(&two, &trailing)),
        (
            "root-non-canonical-prefix",
            seed(
                &root_fields(1, 41),
                &root_body_from_raw(&[(1, TOP_HALF | 1, digest(0x30), 1)]),
            ),
        ),
        (
            "root-prefix-len-65",
            seed(
                &root_fields(1, 41),
                &root_body_from_raw(&[(65, 0, digest(0x40), 1)]),
            ),
        ),
        ("root-count-disagrees", seed(&root_fields(7, 41), &valid)),
    ];

    let mut written = 0;
    for (name, bytes) in cases {
        std::fs::write(dir.join(name), bytes).expect("seed");
        written += 1;
    }
    written
}

#[test]
fn regenerate_manifest_decode_corpus() {
    let mut noise = Noise::new();
    let written = write_root_seeds(&mut noise)
        + write_segment_seeds(&mut noise)
        + write_malformed_seeds(&mut noise);
    assert!(
        written >= 10,
        "R7: {written} seeds is not a corpus for a prefixed format"
    );
}

#[test]
fn the_canonicalisation_rule_is_not_reimplemented_in_the_manifest() {
    let source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("manifest.rs"),
    )
    .expect("manifest.rs");

    // The comments name the rule on purpose, so only code is scanned.
    let code: String = source
        .lines()
        .filter(|line| {
            let t = line.trim_start();
            !t.starts_with("//")
        })
        .collect::<Vec<_>>()
        .join("\n");

    assert_eq!(
        code.matches("aad::check_prefix").count(),
        1,
        "the one gateway to the rule is called exactly once, from \
         CanonicalPrefix::new"
    );

    // The mask idiom and the length bound would each be a second implementation.
    for forbidden in ["u64::MAX >>", "MAX_PREFIX_LEN", "PrefixBitsNotCanonical"] {
        assert!(
            !code.contains(forbidden),
            "`{forbidden}` appears in manifest.rs: §2.2's canonicalisation rule \
             belongs to aad::check_prefix and nowhere else"
        );
    }
}
