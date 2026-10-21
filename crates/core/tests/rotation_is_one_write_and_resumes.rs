#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::collections::BTreeMap;

use chiavora_core::aad::AadFields;
use chiavora_core::manifest::{
    open_root, open_segment, seal_root, seal_segment, CanonicalPrefix, Entry, ManifestError,
    ManifestRoot, ManifestSegment, RootEntry, StoredManifest,
};
use chiavora_core::nonce::FreshNonce;
use chiavora_core::rotation::{rotate, Rewrapped, Rotated, WrapRotator};
use chiavora_core::secret::{
    kind::{Muk, VaultKey},
    Secret,
};
use chiavora_core::store::{Store, Unanchored};
use chiavora_core::sync::{upload, CasRefused, ManifestTransport, StagedEdit, Uploaded};

const VAULT: &[u8] = b"vault-1";

fn key(fill: u8) -> Secret<VaultKey> {
    Secret::<VaultKey>::from_derived_bytes(vec![fill; 32])
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

struct Server {
    root: Option<Vec<u8>>,
    segments: Vec<Vec<u8>>,
    current_seq: u64,
    writes_accepted: usize,
    refuse: bool,
    cut: bool,
    withhold: Vec<u8>,
}

impl Server {
    const fn empty() -> Self {
        Self {
            root: None,
            segments: Vec::new(),
            current_seq: 0,
            writes_accepted: 0,
            refuse: false,
            cut: false,
            withhold: Vec::new(),
        }
    }

    fn seq_of(bytes: &[u8]) -> u64 {
        match StoredManifest::decode(bytes).expect("well-formed").fields() {
            AadFields::ManifestRoot { manifest_seq, .. } => *manifest_seq,
            _ => panic!("not a root"),
        }
    }

    /// `manifestSeq` and `vaultKeyEpoch` as a keyless client reads them, from the root's AAD.
    fn root_metadata(&self) -> Option<(u64, u32)> {
        let bytes = self.root.as_ref()?;
        match StoredManifest::decode(bytes).expect("well-formed").fields() {
            AadFields::ManifestRoot {
                manifest_seq,
                vault_key_epoch,
                ..
            } => Some((*manifest_seq, *vault_key_epoch)),
            _ => None,
        }
    }

    fn entries(&self, k: &Secret<VaultKey>) -> Vec<Entry> {
        let Some(root_bytes) = self.root.as_ref() else {
            return Vec::new();
        };
        let root = open_root(k, &StoredManifest::decode(root_bytes).expect("root")).expect("opens");
        let mut out = Vec::new();
        for bytes in &self.segments {
            let stored = StoredManifest::decode(bytes).expect("segment");
            root.accept_segment(&stored).expect("vouched for");
            out.extend(open_segment(k, &stored).expect("opens").entries().to_vec());
        }
        out
    }

    fn opens_under(&self, k: &Secret<VaultKey>) -> bool {
        self.root.as_ref().is_some_and(|bytes| {
            StoredManifest::decode(bytes)
                .ok()
                .and_then(|stored| open_root(k, &stored).ok())
                .is_some()
        })
    }
}

impl ManifestTransport for Server {
    fn fetch_root(&mut self) -> Result<Option<Vec<u8>>, ManifestError> {
        if self.cut {
            return Err(ManifestError::TransportFailed);
        }
        Ok(self.root.clone())
    }

    fn fetch_segment(&mut self, prefix: CanonicalPrefix) -> Result<Option<Vec<u8>>, ManifestError> {
        if self.cut {
            return Err(ManifestError::TransportFailed);
        }
        if self.withhold.contains(&prefix.bit_len()) {
            return Ok(None);
        }
        // The fixtures are one segment at length 0 or two at length 1.
        let want = prefix.bit_len();
        for bytes in &self.segments {
            let stored = StoredManifest::decode(bytes).expect("well-formed");
            if let AadFields::ManifestSegment {
                prefix_len,
                prefix_bits,
                ..
            } = stored.fields()
            {
                if *prefix_len == want && *prefix_bits == prefix.bits() {
                    return Ok(Some(bytes.clone()));
                }
            }
        }
        Ok(None)
    }

    fn compare_and_swap(&mut self, root: &[u8], segments: &[Vec<u8>]) -> Result<(), CasRefused> {
        if self.refuse || Self::seq_of(root) != self.current_seq + 1 {
            return Err(CasRefused {
                current_manifest_seq: self.current_seq,
            });
        }
        self.root = Some(root.to_vec());
        merge_segments(&mut self.segments, segments);
        self.current_seq = Self::seq_of(root);
        self.writes_accepted += 1;
        Ok(())
    }
}

/// Segments a split retires stay behind but are never served: the server cannot read the root.
fn merge_segments(store: &mut Vec<Vec<u8>>, written: &[Vec<u8>]) {
    for bytes in written {
        let key = prefix_key(bytes);
        store.retain(|existing| prefix_key(existing) != key);
        store.push(bytes.clone());
    }
}

/// `(prefixLen, prefixBits)` out of a stored segment's AAD.
fn prefix_key(bytes: &[u8]) -> (u8, u64) {
    match StoredManifest::decode(bytes).expect("well-formed").fields() {
        AadFields::ManifestSegment {
            prefix_len,
            prefix_bits,
            ..
        } => (*prefix_len, *prefix_bits),
        _ => panic!("not a segment"),
    }
}

/// The epoch each item's key is wrapped under, standing in for `wrap.rs`.
#[derive(Default, Clone, PartialEq, Eq, Debug)]
struct Wraps(BTreeMap<Vec<u8>, u32>);

impl Wraps {
    fn at(&self, item_id: &[u8]) -> u32 {
        self.0.get(item_id).copied().unwrap_or(1)
    }

    fn all_openable_by(&self, held: &[u32]) -> bool {
        self.0.values().all(|e| held.contains(e))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Injection {
    ProcessKilled,
    NetworkCut,
    ServerError,
}

impl Injection {
    const ALL: [Self; 3] = [Self::ProcessKilled, Self::NetworkCut, Self::ServerError];
}

struct Rotator<'a> {
    wraps: &'a mut Wraps,
    target: u32,
    calls: usize,
    abort_after: Option<(usize, Injection)>,
}

impl<'a> Rotator<'a> {
    fn new(wraps: &'a mut Wraps, target: u32) -> Self {
        Self {
            wraps,
            target,
            calls: 0,
            abort_after: None,
        }
    }

    fn aborting(wraps: &'a mut Wraps, target: u32, after: usize, how: Injection) -> Self {
        let mut r = Self::new(wraps, target);
        r.abort_after = Some((after, how));
        r
    }
}

impl WrapRotator for Rotator<'_> {
    fn rewrap(&mut self, item_id: &[u8]) -> Result<Rewrapped, ManifestError> {
        if let Some((after, how)) = self.abort_after {
            if self.calls >= after {
                // To rotation the three injections are one event.
                let _ = how;
                return Err(ManifestError::TransportFailed);
            }
        }
        self.calls += 1;
        if self.wraps.at(item_id) == self.target {
            return Ok(Rewrapped::AlreadyCurrent);
        }
        self.wraps.0.insert(item_id.to_vec(), self.target);
        Ok(Rewrapped::Rewrapped)
    }
}

fn vault_of(n: u8) -> (Server, Store, Wraps) {
    let mut server = Server::empty();
    let mut st = store();
    let staged: Vec<StagedEdit> = (0..n)
        .map(|i| StagedEdit::new(format!("item-{i}").into_bytes(), 1, digest(i), false))
        .collect();
    let out = upload(&mut server, &key(0x11), &mut st, VAULT, &staged).expect("seeds");
    assert_eq!(out, Uploaded::Written { manifest_seq: 1 });

    let mut wraps = Wraps::default();
    for i in 0..n {
        wraps.0.insert(format!("item-{i}").into_bytes(), 1);
    }
    (server, st, wraps)
}

fn two_segment_vault() -> (Server, Store, Wraps) {
    let k = key(0x11);
    let mut server = Server::empty();
    let halves = [
        (CanonicalPrefix::new(1, 0).expect("low"), b"left".to_vec()),
        (
            CanonicalPrefix::new(1, 1 << 63).expect("high"),
            b"right".to_vec(),
        ),
    ];

    let mut sealed = Vec::new();
    let mut root_entries = Vec::new();
    let mut wraps = Wraps::default();
    for (prefix, id) in &halves {
        let segment = ManifestSegment::new(
            AadFields::ManifestSegment {
                vault_id: VAULT.to_vec(),
                segment_seq: 1,
                vault_key_epoch: 1,
                prefix_len: prefix.bit_len(),
                prefix_bits: prefix.bits(),
            },
            vec![Entry::new(id.clone(), 3, digest(0x77), false, Vec::new())],
        )
        .expect("segment");
        let s = seal_segment(&k, FreshNonce::generate().expect("nonce"), &segment).expect("seals");
        root_entries.push(RootEntry::new(*prefix, s.digest().expect("digest"), 1));
        sealed.push(s.encode().expect("encodes"));
        wraps.0.insert(id.clone(), 1);
    }

    let root = ManifestRoot::new(
        AadFields::ManifestRoot {
            vault_id: VAULT.to_vec(),
            manifest_seq: 1,
            vault_key_epoch: 1,
            segment_count: 2,
        },
        root_entries,
    )
    .expect("root");
    server.root = Some(
        seal_root(&k, FreshNonce::generate().expect("nonce"), &root)
            .expect("seals")
            .encode()
            .expect("encodes"),
    );
    server.segments = sealed;
    server.current_seq = 1;

    let mut st = store();
    st.set_high_water_mark(VAULT, 1).expect("mark");
    (server, st, wraps)
}

#[test]
fn the_sequence_is_strictly_increasing_across_a_rotation() {
    let (mut server, mut st, mut wraps) = vault_of(4);
    let before = server.root_metadata().expect("root").0;

    let out = rotate(
        &mut server,
        &key(0x11),
        &key(0x22),
        2,
        &mut st,
        VAULT,
        &mut Rotator::new(&mut wraps, 2),
    )
    .expect("rotates");

    let (after, epoch) = server.root_metadata().expect("root");
    assert_eq!(after, before + 1, "the sequence did not advance by one");
    assert_eq!(epoch, 2);
    assert!(
        matches!(out, Rotated::Complete { manifest_seq, .. } if manifest_seq == after),
        "got {out:?}"
    );
    assert_eq!(st.high_water_mark(VAULT), Some(after));
}

#[test]
fn every_client_can_identify_the_authenticating_epoch() {
    let (mut server, mut st, mut wraps) = vault_of(3);
    let old = key(0x11);
    let new = key(0x22);

    assert_eq!(server.root_metadata().expect("root").1, 1);
    assert!(server.opens_under(&old));

    rotate(
        &mut server,
        &old,
        &new,
        2,
        &mut st,
        VAULT,
        &mut Rotator::new(&mut wraps, 2),
    )
    .expect("rotates");

    assert_eq!(
        server.root_metadata().expect("root").1,
        2,
        "the epoch a keyless client reads is still the old one"
    );
    assert!(server.opens_under(&new));
    assert!(
        !server.opens_under(&old),
        "the previous Vault Key still authenticates the root"
    );
}

#[test]
fn no_item_version_or_ciphertext_digest_changes() {
    let (mut server, mut st, mut wraps) = vault_of(5);
    let before = server.entries(&key(0x11));

    rotate(
        &mut server,
        &key(0x11),
        &key(0x22),
        2,
        &mut st,
        VAULT,
        &mut Rotator::new(&mut wraps, 2),
    )
    .expect("rotates");

    let after = server.entries(&key(0x22));
    assert_eq!(
        before, after,
        "rotation bumped a version or changed a ciphertext digest"
    );
    assert!(
        !before.is_empty(),
        "the comparison would be vacuous on nothing"
    );
}

#[test]
fn a_rotation_is_one_cas_write() {
    let (mut server, mut st, mut wraps) = vault_of(6);
    let before = server.writes_accepted;

    rotate(
        &mut server,
        &key(0x11),
        &key(0x22),
        2,
        &mut st,
        VAULT,
        &mut Rotator::new(&mut wraps, 2),
    )
    .expect("rotates");

    assert_eq!(
        server.writes_accepted - before,
        1,
        "rotation took more than one CAS write"
    );
    assert!(
        wraps.all_openable_by(&[2]),
        "an item was left under epoch 1"
    );
}

#[test]
fn rotation_re_encrypts_every_segment_the_root_names() {
    let (mut server, mut st, mut wraps) = two_segment_vault();
    let before = server.entries(&key(0x11));
    assert_eq!(before.len(), 2, "the fixture must have two segments");

    rotate(
        &mut server,
        &key(0x11),
        &key(0x22),
        2,
        &mut st,
        VAULT,
        &mut Rotator::new(&mut wraps, 2),
    )
    .expect("rotates");

    assert_eq!(server.segments.len(), 2);
    assert_eq!(
        server.entries(&key(0x22)),
        before,
        "one of the two segments did not come across"
    );
    for bytes in &server.segments {
        let stored = StoredManifest::decode(bytes).expect("segment");
        match stored.fields() {
            AadFields::ManifestSegment {
                vault_key_epoch, ..
            } => assert_eq!(*vault_key_epoch, 2, "a segment is still at epoch 1"),
            _ => panic!("not a segment"),
        }
    }
}

#[test]
fn an_epoch_that_is_not_exactly_one_above_is_refused_by_name() {
    for offered in [1_u32, 3, 7] {
        let (mut server, mut st, mut wraps) = vault_of(2);
        let out = rotate(
            &mut server,
            &key(0x11),
            &key(0x22),
            offered,
            &mut st,
            VAULT,
            &mut Rotator::new(&mut wraps, offered),
        );
        assert!(
            matches!(
                out,
                Err(ManifestError::EpochNotSuccessive {
                    current: 1,
                    offered: o
                }) if o == offered
            ),
            "epoch {offered} was accepted: {out:?}"
        );
        assert_eq!(server.writes_accepted, 1, "it wrote anyway");
    }
}

#[test]
fn a_vault_with_no_manifest_is_refused_rather_than_silently_rotated() {
    let mut server = Server::empty();
    let mut st = store();
    let mut wraps = Wraps::default();
    let out = rotate(
        &mut server,
        &key(0x11),
        &key(0x22),
        2,
        &mut st,
        VAULT,
        &mut Rotator::new(&mut wraps, 2),
    );
    assert!(
        matches!(out, Err(ManifestError::NoManifestToRotate)),
        "{out:?}"
    );
}

#[test]
fn a_segment_the_root_names_and_the_server_withholds_is_refused_by_name() {
    let (mut server, mut st, mut wraps) = two_segment_vault();
    server.withhold = vec![1];
    let out = rotate(
        &mut server,
        &key(0x11),
        &key(0x22),
        2,
        &mut st,
        VAULT,
        &mut Rotator::new(&mut wraps, 2),
    );
    assert!(
        matches!(
            out,
            Err(ManifestError::SegmentListedNotDelivered { prefix_len: 1 })
        ),
        "{out:?}"
    );
    assert!(
        wraps.all_openable_by(&[1]),
        "it re-wrapped against a manifest it could not verify"
    );
}

#[test]
fn a_lost_race_keeps_every_rewrap_and_the_retry_finds_them_done() {
    let (mut server, mut st, mut wraps) = vault_of(4);
    server.refuse = true;

    let out = rotate(
        &mut server,
        &key(0x11),
        &key(0x22),
        2,
        &mut st,
        VAULT,
        &mut Rotator::new(&mut wraps, 2),
    )
    .expect("a refused write is an outcome, not an error");
    assert!(matches!(out, Rotated::LostRace { observed: 1 }), "{out:?}");
    assert!(wraps.all_openable_by(&[2]), "the re-wraps were rolled back");

    server.refuse = false;
    let out = rotate(
        &mut server,
        &key(0x11),
        &key(0x22),
        2,
        &mut st,
        VAULT,
        &mut Rotator::new(&mut wraps, 2),
    )
    .expect("retries");
    assert!(
        matches!(
            out,
            Rotated::Complete {
                rewrapped: 0,
                already_current: 4,
                ..
            }
        ),
        "the retry redid work it did not need to: {out:?}"
    );
}

#[test]
fn every_interruption_point_under_all_three_injections() {
    const N: u8 = 5;
    let old = key(0x11);
    let new = key(0x22);

    for how in Injection::ALL {
        for point in 0..usize::from(N) {
            let (mut server, mut st, mut wraps) = vault_of(N);
            let writes_before = server.writes_accepted;

            let out = rotate(
                &mut server,
                &old,
                &new,
                2,
                &mut st,
                VAULT,
                &mut Rotator::aborting(&mut wraps, 2, point, how),
            );
            assert!(
                out.is_err(),
                "{how:?} at {point} did not abort the rotation: {out:?}"
            );

            assert_eq!(
                server.root_metadata().expect("root"),
                (1, 1),
                "{how:?} at {point}: the manifest moved before the walk finished"
            );
            assert!(
                server.opens_under(&old),
                "{how:?} at {point}: the vault no longer authenticates under the old key"
            );
            assert_eq!(
                server.writes_accepted, writes_before,
                "{how:?} at {point}: it wrote"
            );
            assert!(
                wraps.all_openable_by(&[1, 2]),
                "{how:?} at {point}: an item is under neither epoch"
            );

            let out = rotate(
                &mut server,
                &old,
                &new,
                2,
                &mut st,
                VAULT,
                &mut Rotator::new(&mut wraps, 2),
            )
            .expect("resumes");
            assert!(
                matches!(out, Rotated::Complete { already_current, .. } if already_current == point),
                "{how:?} at {point}: the resume did not find the work already done: {out:?}"
            );
            assert_eq!(server.root_metadata().expect("root"), (2, 2));
            assert!(wraps.all_openable_by(&[2]));
            assert_eq!(server.writes_accepted - writes_before, 1);
        }

        // The `(n+1)`-th point, every re-wrap done and the write not, is injected at the server.
        let (mut server, mut st, mut wraps) = vault_of(N);
        server.refuse = true;
        let out = rotate(
            &mut server,
            &old,
            &new,
            2,
            &mut st,
            VAULT,
            &mut Rotator::new(&mut wraps, 2),
        )
        .expect("a refused write is an outcome");
        assert!(matches!(out, Rotated::LostRace { .. }), "{how:?}: {out:?}");
        assert_eq!(server.root_metadata().expect("root"), (1, 1));
        assert!(server.opens_under(&old));
        assert!(wraps.all_openable_by(&[2]), "the re-wraps were rolled back");

        server.refuse = false;
        let out = rotate(
            &mut server,
            &old,
            &new,
            2,
            &mut st,
            VAULT,
            &mut Rotator::new(&mut wraps, 2),
        )
        .expect("resumes");
        assert!(
            matches!(out, Rotated::Complete { rewrapped: 0, already_current, .. }
                if already_current == usize::from(N)),
            "{how:?}: the resume redid the whole walk: {out:?}"
        );
    }
}

#[test]
fn a_completed_rotation_is_distinguishable_before_a_key_is_tried() {
    let (mut server, mut st, mut wraps) = vault_of(3);
    assert_eq!(
        server.root_metadata().expect("root").1,
        1,
        "a keyless client reads epoch 1 and knows a rotation to 2 is owed"
    );
    rotate(
        &mut server,
        &key(0x11),
        &key(0x22),
        2,
        &mut st,
        VAULT,
        &mut Rotator::new(&mut wraps, 2),
    )
    .expect("rotates");

    assert_eq!(
        server.root_metadata().expect("root").1,
        2,
        "and now reads 2, so it knows there is nothing to resume"
    );
    let out = rotate(
        &mut server,
        &key(0x11),
        &key(0x22),
        2,
        &mut st,
        VAULT,
        &mut Rotator::new(&mut wraps, 2),
    );
    assert!(
        out.is_err(),
        "a stale resume was accepted against a rotated vault: {out:?}"
    );
}

#[test]
fn the_end_state_is_the_same_wherever_it_was_interrupted() {
    const N: u8 = 4;
    let mut outcomes = Vec::new();
    for how in Injection::ALL {
        for point in 0..usize::from(N) {
            let (mut server, mut st, mut wraps) = vault_of(N);
            let _ = rotate(
                &mut server,
                &key(0x11),
                &key(0x22),
                2,
                &mut st,
                VAULT,
                &mut Rotator::aborting(&mut wraps, 2, point, how),
            );
            rotate(
                &mut server,
                &key(0x11),
                &key(0x22),
                2,
                &mut st,
                VAULT,
                &mut Rotator::new(&mut wraps, 2),
            )
            .expect("resumes");
            outcomes.push((
                server.entries(&key(0x22)),
                server.root_metadata().expect("root"),
                wraps.clone(),
            ));
        }
    }
    let first = outcomes.first().expect("at least one").clone();
    for (n, outcome) in outcomes.iter().enumerate() {
        assert_eq!(*outcome, first, "outcome {n} differs from the first");
    }
}

#[test]
fn a_cut_network_leaves_the_vault_exactly_as_it_was() {
    let (mut server, mut st, mut wraps) = vault_of(4);
    let before = (
        server.root_metadata(),
        wraps.clone(),
        server.writes_accepted,
    );
    server.cut = true;

    let out = rotate(
        &mut server,
        &key(0x11),
        &key(0x22),
        2,
        &mut st,
        VAULT,
        &mut Rotator::new(&mut wraps, 2),
    );
    assert!(
        matches!(out, Err(ManifestError::TransportFailed)),
        "{out:?}"
    );
    assert_eq!(
        (
            server.root_metadata(),
            wraps.clone(),
            server.writes_accepted
        ),
        before,
        "a rotation that could not read the manifest changed something"
    );

    server.cut = false;
    rotate(
        &mut server,
        &key(0x11),
        &key(0x22),
        2,
        &mut st,
        VAULT,
        &mut Rotator::new(&mut wraps, 2),
    )
    .expect("completes once the network is back");
    assert_eq!(server.root_metadata(), Some((2, 2)));
}

#[test]
fn a_member_without_the_new_sealed_vault_key_cannot_open_a_rewrapped_item() {
    // Rotation cannot check this precondition: authentication succeeds, unlock fails.
    let (mut server, mut st, mut wraps) = vault_of(3);
    let _ = rotate(
        &mut server,
        &key(0x11),
        &key(0x22),
        2,
        &mut st,
        VAULT,
        &mut Rotator::aborting(&mut wraps, 2, 2, Injection::ProcessKilled),
    );

    assert!(server.opens_under(&key(0x11)));
    assert!(
        !wraps.all_openable_by(&[1]),
        "the fixture did not actually re-wrap anything, so this asserts nothing"
    );
}
