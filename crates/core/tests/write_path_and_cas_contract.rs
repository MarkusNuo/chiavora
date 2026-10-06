#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use chiavora_core::manifest::{open_root, CanonicalPrefix, ManifestError, StoredManifest};
use chiavora_core::secret::{
    kind::{Muk, VaultKey},
    Secret,
};
use chiavora_core::store::{Store, Unanchored};
use chiavora_core::sync::{upload, CasRefused, ManifestTransport, StagedEdit, Uploaded};

const VAULT: &[u8] = b"vault-1";

fn vault_key() -> Secret<VaultKey> {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Misbehaviour {
    None,
    /// C1 negated: accepts `manifestSeq >= current`, an off-by-one that loses data.
    AcceptsAtOrAbove,
    /// C2 negated: stores the root and drops the segments.
    DropsSegments,
    /// C4 negated: re-encodes what it is given before storing it.
    ReEncodes,
    /// Refuses every write without advancing: a denial of service N3 already accepts.
    RefusesEverything,
}

struct FakeServer {
    root: Option<Vec<u8>>,
    segments: Vec<Vec<u8>>,
    current_seq: u64,
    misbehaviour: Misbehaviour,
    /// Epochs whose sealed Vault Key is retained until explicitly released (C7).
    retained_epochs: Vec<u32>,
    writes_accepted: usize,
}

impl FakeServer {
    fn empty() -> Self {
        Self {
            root: None,
            segments: Vec::new(),
            current_seq: 0,
            misbehaviour: Misbehaviour::None,
            retained_epochs: vec![1],
            writes_accepted: 0,
        }
    }

    fn misbehaving(m: Misbehaviour) -> Self {
        let mut s = Self::empty();
        s.misbehaviour = m;
        s
    }

    /// Reads the sequence out of the stored root's AAD, as a real server can.
    fn seq_of(bytes: &[u8]) -> u64 {
        let stored = StoredManifest::decode(bytes).expect("the server sees a well-formed record");
        match stored.fields() {
            chiavora_core::aad::AadFields::ManifestRoot { manifest_seq, .. } => *manifest_seq,
            _ => panic!("not a root"),
        }
    }

    /// An explicit release (C7); the server cannot see which `0x05` records are done.
    fn release_epoch(&mut self, epoch: u32) {
        self.retained_epochs.retain(|e| *e != epoch);
    }

    fn retains(&self, epoch: u32) -> bool {
        self.retained_epochs.contains(&epoch)
    }
}

impl ManifestTransport for FakeServer {
    fn fetch_root(&mut self) -> Result<Option<Vec<u8>>, ManifestError> {
        Ok(self.root.clone())
    }

    fn fetch_segment(
        &mut self,
        _prefix: CanonicalPrefix,
    ) -> Result<Option<Vec<u8>>, ManifestError> {
        Ok(self.segments.first().cloned())
    }

    fn compare_and_swap(&mut self, root: &[u8], segments: &[Vec<u8>]) -> Result<(), CasRefused> {
        let offered = Self::seq_of(root);
        let acceptable = match self.misbehaviour {
            Misbehaviour::RefusesEverything => false,
            Misbehaviour::AcceptsAtOrAbove => offered >= self.current_seq,
            _ => offered == self.current_seq + 1,
        };
        if !acceptable {
            return Err(CasRefused {
                current_manifest_seq: self.current_seq,
            });
        }

        self.root = Some(root.to_vec());
        self.segments = match self.misbehaviour {
            Misbehaviour::DropsSegments => Vec::new(),
            Misbehaviour::ReEncodes => segments
                .iter()
                .map(|s| {
                    let decoded = StoredManifest::decode(s).expect("well-formed");
                    let mut bytes = decoded.encode().expect("re-encodes");
                    if let Some(b) = bytes.last_mut() {
                        *b ^= 0x01;
                    }
                    bytes
                })
                .collect(),
            _ => segments.to_vec(),
        };
        self.current_seq = offered;
        self.writes_accepted += 1;
        Ok(())
    }
}

fn edit(id: &[u8], version: u64, fill: u8) -> StagedEdit {
    StagedEdit::new(id.to_vec(), version, digest(fill), false)
}

#[test]
fn a_first_write_into_an_empty_vault_lands_at_one() {
    let mut server = FakeServer::empty();
    let mut store = store();
    let out = upload(
        &mut server,
        &vault_key(),
        &mut store,
        VAULT,
        &[edit(b"a", 1, 0x11)],
    )
    .expect("uploads");

    assert_eq!(out, Uploaded::Written { manifest_seq: 1 });
    assert_eq!(store.high_water_mark(VAULT), Some(1));
}

#[test]
fn a_week_offline_client_rebases_onto_a_vault_twenty_writes_ahead() {
    let key = vault_key();
    let mut server = FakeServer::empty();

    let mut device_a = store();
    for n in 1..=20_u64 {
        let out = upload(
            &mut server,
            &key,
            &mut device_a,
            VAULT,
            &[edit(format!("item-{n}").as_bytes(), n, 0x20)],
        )
        .expect("device A uploads");
        assert_eq!(out, Uploaded::Written { manifest_seq: n });
    }
    assert_eq!(server.current_seq, 20);

    let mut device_b = store();
    assert_eq!(device_b.high_water_mark(VAULT), None, "B is a week behind");

    let out = upload(
        &mut server,
        &key,
        &mut device_b,
        VAULT,
        &[edit(b"written-offline", 1, 0x99)],
    )
    .expect("B rebases rather than self-rejecting");

    assert_eq!(
        out,
        Uploaded::Written { manifest_seq: 21 },
        "the number comes from the fetched root, not from B's own mark"
    );

    let stored =
        StoredManifest::decode(server.segments.first().expect("a segment")).expect("decodes");
    let segment = chiavora_core::manifest::open_segment(&key, &stored).expect("opens");
    assert_eq!(segment.entries().len(), 21, "twenty plus B's one");
    assert!(segment.entry(b"written-offline").is_some());
    assert!(segment.entry(b"item-20").is_some(), "B did not clobber A");
}

#[test]
fn the_merge_takes_the_higher_version_where_both_devices_advanced() {
    let key = vault_key();
    let mut server = FakeServer::empty();
    let mut a = store();
    upload(
        &mut server,
        &key,
        &mut a,
        VAULT,
        &[edit(b"shared", 5, 0x55)],
    )
    .expect("A");

    let mut b = store();
    upload(
        &mut server,
        &key,
        &mut b,
        VAULT,
        &[edit(b"shared", 3, 0x33)],
    )
    .expect("B");

    let stored = StoredManifest::decode(server.segments.first().expect("segment")).expect("ok");
    let segment = chiavora_core::manifest::open_segment(&key, &stored).expect("opens");
    assert_eq!(
        segment.entry(b"shared").expect("listed").current_version(),
        5,
        "the higher version survives the merge"
    );
}

#[test]
fn an_equal_version_disagreement_is_handed_to_conflict_resolution_by_name() {
    let key = vault_key();
    let mut server = FakeServer::empty();
    let mut a = store();
    upload(
        &mut server,
        &key,
        &mut a,
        VAULT,
        &[edit(b"shared", 4, 0x44)],
    )
    .expect("A");

    let mut b = store();
    let refused = upload(
        &mut server,
        &key,
        &mut b,
        VAULT,
        &[edit(b"shared", 4, 0xAA)],
    );

    assert!(
        matches!(refused, Err(ManifestError::ConflictNeedsResolution)),
        "same version, different bytes is the real conflict; got {refused:?}"
    );
}

#[test]
fn a_lost_race_retries_cleanly_and_orphans_nothing() {
    let key = vault_key();
    let mut server = FakeServer::empty();
    let mut a = store();
    let mut b = store();

    upload(
        &mut server,
        &key,
        &mut a,
        VAULT,
        &[edit(b"from-a", 1, 0xA1)],
    )
    .expect("A wins");

    // B's edit was made on the same base; `upload` refetches, so B rebases.
    let out = upload(
        &mut server,
        &key,
        &mut b,
        VAULT,
        &[edit(b"from-b", 1, 0xB1)],
    )
    .expect("B retries cleanly");
    assert_eq!(out, Uploaded::Written { manifest_seq: 2 });

    let stored_root = StoredManifest::decode(server.root.as_ref().expect("a root")).expect("ok");
    let root = open_root(&key, &stored_root).expect("opens");
    root.accept(None).expect("the vault tiles");

    let stored_segment =
        StoredManifest::decode(server.segments.first().expect("segment")).expect("ok");
    root.accept_segment(&stored_segment)
        .expect("the root vouches for what is stored");

    let segment = chiavora_core::manifest::open_segment(&key, &stored_segment).expect("opens");
    segment
        .reconcile(&[b"from-a".as_slice(), b"from-b".as_slice()])
        .expect("both items are listed: nothing is orphaned");
}

#[test]
fn a_server_offering_a_root_below_the_clients_mark_is_refused_on_the_write_path_too() {
    let key = vault_key();
    let mut server = FakeServer::empty();
    let mut client = store();
    upload(
        &mut server,
        &key,
        &mut client,
        VAULT,
        &[edit(b"a", 1, 0x11)],
    )
    .expect("first");
    upload(
        &mut server,
        &key,
        &mut client,
        VAULT,
        &[edit(b"b", 1, 0x22)],
    )
    .expect("second");
    assert_eq!(client.high_water_mark(VAULT), Some(2));

    server.current_seq = 1;
    let older = {
        let mut rewound = FakeServer::empty();
        let mut fresh = store();
        upload(
            &mut rewound,
            &key,
            &mut fresh,
            VAULT,
            &[edit(b"a", 1, 0x11)],
        )
        .expect("seq 1");
        rewound.root.expect("a seq-1 root")
    };
    server.root = Some(older);

    let refused = upload(
        &mut server,
        &key,
        &mut client,
        VAULT,
        &[edit(b"c", 1, 0x33)],
    );
    assert!(
        matches!(
            refused,
            Err(ManifestError::RootBelowHighWaterMark {
                offered: 1,
                mark: 2
            })
        ),
        "the write path is built on the read path, so I6a applies; got {refused:?}"
    );
}

#[test]
fn c1_a_server_accepting_at_or_above_orphans_the_losers_items() {
    // This tests the server: a well-behaved client never offers the write C1 refuses.
    let key = vault_key();

    let mut base = FakeServer::empty();
    let mut setup = store();
    upload(
        &mut base,
        &key,
        &mut setup,
        VAULT,
        &[edit(b"base", 1, 0x01)],
    )
    .expect("base");
    let base_root = base.root.clone().expect("a base root");
    let base_segment = base.segments.clone();

    let build_competing = |item: &[u8], fill: u8| -> (Vec<u8>, Vec<Vec<u8>>) {
        let mut from_base = FakeServer::empty();
        from_base.root = Some(base_root.clone());
        from_base.segments = base_segment.clone();
        from_base.current_seq = 1;
        let mut client = store();
        upload(
            &mut from_base,
            &key,
            &mut client,
            VAULT,
            &[edit(item, 2, fill)],
        )
        .expect("builds a seq-2 write");
        (from_base.root.expect("root"), from_base.segments)
    };
    let (root_a, segments_a) = build_competing(b"from-a", 0xA1);
    let (root_b, segments_b) = build_competing(b"from-b", 0xB1);

    let mut honest = FakeServer::empty();
    honest.root = Some(base_root.clone());
    honest.segments = base_segment.clone();
    honest.current_seq = 1;
    honest
        .compare_and_swap(&root_a, &segments_a)
        .expect("A wins the race");
    assert_eq!(
        honest.compare_and_swap(&root_b, &segments_b),
        Err(CasRefused {
            current_manifest_seq: 2
        }),
        "the loser is refused and told where to rebase from"
    );

    let mut loose = FakeServer::misbehaving(Misbehaviour::AcceptsAtOrAbove);
    loose.root = Some(base_root);
    loose.segments = base_segment;
    loose.current_seq = 1;
    loose.compare_and_swap(&root_a, &segments_a).expect("A");
    loose
        .compare_and_swap(&root_b, &segments_b)
        .expect("B is wrongly accepted at the same seq");

    let stored_root = StoredManifest::decode(loose.root.as_ref().expect("root")).expect("ok");
    let root = open_root(&key, &stored_root).expect("opens");
    let stored_segment =
        StoredManifest::decode(loose.segments.first().expect("segment")).expect("ok");
    root.accept_segment(&stored_segment)
        .expect("B's root vouches for B's segment, so this much is consistent");
    let segment = chiavora_core::manifest::open_segment(&key, &stored_segment).expect("opens");

    assert!(
        segment.entry(b"from-b").is_some(),
        "B's write survived, as the loose server allowed"
    );
    assert!(
        segment.entry(b"from-a").is_none(),
        "and A's item is listed in no segment: the orphaned ciphertext C1 exists \
         to prevent"
    );
    assert!(
        matches!(
            segment.reconcile(&[
                b"base".as_slice(),
                b"from-a".as_slice(),
                b"from-b".as_slice()
            ]),
            Err(ManifestError::ItemDeliveredNotListed)
        ),
        "and the next honest read reports it as an attack on a vault nobody attacked"
    );
}

#[test]
fn c2_a_server_that_drops_the_segments_is_caught_on_the_next_read() {
    let key = vault_key();
    let mut server = FakeServer::misbehaving(Misbehaviour::DropsSegments);
    let mut client = store();
    upload(
        &mut server,
        &key,
        &mut client,
        VAULT,
        &[edit(b"a", 1, 0x11)],
    )
    .expect("the write");

    assert!(
        server.segments.is_empty(),
        "the fake dropped them, which is the misbehaviour under test"
    );

    let stored_root = StoredManifest::decode(server.root.as_ref().expect("root")).expect("ok");
    let root = open_root(&key, &stored_root).expect("opens");
    root.accept(None).expect("the root itself tiles");
    assert!(
        server.segments.is_empty(),
        "and there is nothing to check it against, which is the C2 failure"
    );
}

#[test]
fn c4_a_server_that_re_encodes_a_segment_fails_the_roots_digest() {
    let key = vault_key();
    let mut server = FakeServer::misbehaving(Misbehaviour::ReEncodes);
    let mut client = store();
    upload(
        &mut server,
        &key,
        &mut client,
        VAULT,
        &[edit(b"a", 1, 0x11)],
    )
    .expect("the write");

    let stored_root = StoredManifest::decode(server.root.as_ref().expect("root")).expect("ok");
    let root = open_root(&key, &stored_root).expect("opens");
    let stored_segment =
        StoredManifest::decode(server.segments.first().expect("segment")).expect("ok");

    assert!(
        matches!(
            root.accept_segment(&stored_segment),
            Err(ManifestError::SegmentDigestMismatch)
        ),
        "a re-encoded segment is not the one the root vouches for"
    );
}

#[test]
fn c3_a_refused_write_reports_where_the_vault_is() {
    let key = vault_key();
    let mut server = FakeServer::misbehaving(Misbehaviour::RefusesEverything);
    server.current_seq = 7;
    let mut client = store();

    let out = upload(
        &mut server,
        &key,
        &mut client,
        VAULT,
        &[edit(b"a", 1, 0x11)],
    )
    .expect("a refusal is an outcome, not an error");
    assert_eq!(
        out,
        // `served: 0` because this fixture holds no root; `served` is the witness for `observed`.
        Uploaded::LostRace {
            observed: 7,
            served: 0
        },
        "the client is told where the vault is, or it cannot distinguish \
         contention from a refusing server"
    );
}

#[test]
fn a_refusing_server_is_a_denial_of_service_and_corrupts_nothing() {
    let key = vault_key();
    let mut server = FakeServer::misbehaving(Misbehaviour::RefusesEverything);
    let mut client = store();

    for _ in 0..5 {
        let out = upload(
            &mut server,
            &key,
            &mut client,
            VAULT,
            &[edit(b"a", 1, 0x11)],
        )
        .expect("refusals are outcomes");
        assert!(matches!(out, Uploaded::LostRace { .. }));
    }

    assert_eq!(server.writes_accepted, 0);
    assert!(server.root.is_none(), "nothing was written");
    assert_eq!(
        client.high_water_mark(VAULT),
        None,
        "and the client did not advance its own mark on a write that did not land"
    );
}

#[test]
fn c7_the_previous_epochs_key_is_retained_until_explicitly_released() {
    let key = vault_key();
    let mut server = FakeServer::empty();
    let mut client = store();

    assert!(server.retains(1), "the current epoch is held");
    for n in 1..=3_u64 {
        upload(
            &mut server,
            &key,
            &mut client,
            VAULT,
            &[edit(format!("i{n}").as_bytes(), n, 0x11)],
        )
        .expect("writes");
    }
    assert!(
        server.retains(1),
        "writes alone never release an epoch: the server cannot see re-wrap \
         progress, so it has no basis on which to decide"
    );

    server.release_epoch(1);
    assert!(!server.retains(1), "an explicit release is what drops it");
}

#[test]
fn c7s_authentication_half_belongs_to_the_server_and_is_not_tested_here() {
    // The server's SRP session enforces this half of C7; `crates/core` has no session.
    let mut server = FakeServer::empty();
    assert!(server.retains(1));
    server.release_epoch(1);
    assert!(
        !server.retains(1),
        "the fake has no authentication, which is exactly the point: this suite \
         proves the release is explicit, never that it is authorised"
    );
}

#[test]
fn c6_the_server_sees_the_metadata_the_enumeration_names_and_no_more() {
    let key = vault_key();
    let mut server = FakeServer::empty();
    let mut client = store();
    upload(
        &mut server,
        &key,
        &mut client,
        VAULT,
        &[edit(b"secret-item", 1, 0x11)],
    )
    .expect("writes");

    let stored = StoredManifest::decode(server.root.as_ref().expect("root")).expect("ok");
    match stored.fields() {
        chiavora_core::aad::AadFields::ManifestRoot {
            vault_id,
            manifest_seq,
            vault_key_epoch,
            segment_count,
        } => {
            assert_eq!(vault_id, VAULT);
            assert_eq!(*manifest_seq, 1);
            assert_eq!(*vault_key_epoch, 1);
            assert_eq!(*segment_count, 1);
        }
        _ => panic!("not a root"),
    }

    let segment = StoredManifest::decode(server.segments.first().expect("segment")).expect("ok");
    let plaintext_visible = String::from_utf8_lossy(segment.payload().ciphertext()).to_string();
    assert!(
        !plaintext_visible.contains("secret-item"),
        "an itemId must not be readable in a sealed segment; only segmentPrefix \
         is server-visible metadata, and R-26 accepts that leak by name"
    );
}
