#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::collections::BTreeSet;

use chiavora_core::aad::AadFields;
use chiavora_core::manifest::{
    hash_item_id, open_root, open_segment, CanonicalPrefix, ConflictingVersion, Entry,
    ManifestError, StoredManifest, SPLIT_AT_ENTRIES,
};
use chiavora_core::rotation::{rotate, Rewrapped, WrapRotator};
use chiavora_core::secret::{
    kind::{Muk, VaultKey},
    Secret,
};
use chiavora_core::store::{Store, Unanchored};
use chiavora_core::sync::{
    upload, upload_resolving, CasRefused, ConflictCopySealer, ManifestTransport, StagedEdit,
};

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

struct Server {
    root: Option<Vec<u8>>,
    segments: Vec<Vec<u8>>,
    current_seq: u64,
    fetched: Vec<(u8, u64)>,
    last_write_segments: usize,
    last_write_bytes: usize,
}

impl Server {
    const fn empty() -> Self {
        Self {
            root: None,
            segments: Vec::new(),
            current_seq: 0,
            fetched: Vec::new(),
            last_write_segments: 0,
            last_write_bytes: 0,
        }
    }

    fn seq_of(bytes: &[u8]) -> u64 {
        match StoredManifest::decode(bytes).expect("well-formed").fields() {
            AadFields::ManifestRoot { manifest_seq, .. } => *manifest_seq,
            _ => panic!("not a root"),
        }
    }

    fn root_of(&self, k: &Secret<VaultKey>) -> chiavora_core::manifest::ManifestRoot {
        let bytes = self.root.as_ref().expect("a root");
        open_root(k, &StoredManifest::decode(bytes).expect("root")).expect("opens")
    }

    fn entries(&self, k: &Secret<VaultKey>) -> Vec<Entry> {
        let root = self.root_of(k);
        let mut out = Vec::new();
        for entry in root.segments() {
            let want = (entry.prefix().bit_len(), entry.prefix().bits());
            let bytes = self
                .segments
                .iter()
                .find(|b| prefix_key(b) == want)
                .expect("the root names a segment the server has");
            let stored = StoredManifest::decode(bytes).expect("segment");
            root.accept_segment(&stored).expect("vouched for");
            out.extend(open_segment(k, &stored).expect("opens").entries().to_vec());
        }
        out
    }
}

impl ManifestTransport for Server {
    fn fetch_root(&mut self) -> Result<Option<Vec<u8>>, ManifestError> {
        Ok(self.root.clone())
    }

    fn fetch_segment(&mut self, prefix: CanonicalPrefix) -> Result<Option<Vec<u8>>, ManifestError> {
        let want = (prefix.bit_len(), prefix.bits());
        self.fetched.push(want);
        Ok(self
            .segments
            .iter()
            .find(|b| prefix_key(b) == want)
            .cloned())
    }

    fn compare_and_swap(&mut self, root: &[u8], segments: &[Vec<u8>]) -> Result<(), CasRefused> {
        let offered = Self::seq_of(root);
        if offered != self.current_seq + 1 {
            return Err(CasRefused {
                current_manifest_seq: self.current_seq,
            });
        }
        for bytes in segments {
            let want = prefix_key(bytes);
            self.segments
                .retain(|existing| prefix_key(existing) != want);
            self.segments.push(bytes.clone());
        }
        self.root = Some(root.to_vec());
        self.current_seq = offered;
        self.last_write_segments = segments.len();
        self.last_write_bytes = root.len() + segments.iter().map(Vec::len).sum::<usize>();
        Ok(())
    }
}

fn edit(id: &[u8], version: u64, fill: u8) -> StagedEdit {
    StagedEdit::new(id.to_vec(), version, digest(fill), false)
}

fn vault_of(n: usize) -> (Server, Store) {
    let mut server = Server::empty();
    let mut st = store();
    let staged: Vec<StagedEdit> = (0..n)
        .map(|i| {
            let mut d = [0_u8; 32];
            d[..8].copy_from_slice(&(i as u64).to_be_bytes());
            StagedEdit::new(format!("item-{i}").into_bytes(), 1, d, false)
        })
        .collect();
    upload(&mut server, &key(0x11), &mut st, VAULT, &staged).expect("seeds");
    (server, st)
}

#[test]
fn crossing_the_bound_splits_in_one_cas_write() {
    let k = key(0x11);
    let (mut server, mut st) = vault_of(SPLIT_AT_ENTRIES);
    assert_eq!(
        server.root_of(&k).segments().len(),
        1,
        "the seed should still be one segment"
    );

    // One more entry takes the segment over the bound.
    upload(
        &mut server,
        &k,
        &mut st,
        VAULT,
        &[edit(b"one-more", 1, 0x55)],
    )
    .expect("splits");

    let root = server.root_of(&k);
    assert_eq!(root.segments().len(), 2, "it did not split");
    assert_eq!(
        server.last_write_segments, 2,
        "a split writes both halves, and only them"
    );
    root.check_tiles().expect("the halves tile");
    assert_eq!(
        server.entries(&k).len(),
        SPLIT_AT_ENTRIES + 1,
        "an item was lost in the split"
    );
}

#[test]
fn every_entry_is_under_the_prefix_its_hash_selects() {
    let k = key(0x11);
    let (mut server, mut st) = vault_of(SPLIT_AT_ENTRIES);
    upload(
        &mut server,
        &k,
        &mut st,
        VAULT,
        &[edit(b"one-more", 1, 0x55)],
    )
    .expect("splits");

    let root = server.root_of(&k);
    for entry in root.segments() {
        let want = (entry.prefix().bit_len(), entry.prefix().bits());
        let bytes = server
            .segments
            .iter()
            .find(|b| prefix_key(b) == want)
            .expect("present");
        let stored = StoredManifest::decode(bytes).expect("segment");
        for item in open_segment(&k, &stored).expect("opens").entries() {
            assert!(
                entry.prefix().contains(hash_item_id(item.item_id())),
                "an entry sits under a prefix that does not own it"
            );
        }
    }
}

#[test]
fn an_ordinary_edit_rewrites_one_segment_and_the_root() {
    let k = key(0x11);
    let (mut server, mut st) = vault_of(SPLIT_AT_ENTRIES);
    upload(
        &mut server,
        &k,
        &mut st,
        VAULT,
        &[edit(b"one-more", 1, 0x55)],
    )
    .expect("splits");
    assert_eq!(server.root_of(&k).segments().len(), 2);

    upload(&mut server, &k, &mut st, VAULT, &[edit(b"item-0", 2, 0x66)]).expect("edits");
    assert_eq!(
        server.last_write_segments, 1,
        "an ordinary edit carried more than one segment"
    );
}

#[test]
fn an_untouched_segment_is_never_fetched() {
    let k = key(0x11);
    let (mut server, mut st) = vault_of(SPLIT_AT_ENTRIES);
    upload(
        &mut server,
        &k,
        &mut st,
        VAULT,
        &[edit(b"one-more", 1, 0x55)],
    )
    .expect("splits");

    let prefixes: BTreeSet<(u8, u64)> = server
        .root_of(&k)
        .segments()
        .iter()
        .map(|e| (e.prefix().bit_len(), e.prefix().bits()))
        .collect();
    assert_eq!(prefixes.len(), 2);

    server.fetched.clear();
    upload(&mut server, &k, &mut st, VAULT, &[edit(b"item-0", 2, 0x66)]).expect("edits");

    let asked: BTreeSet<(u8, u64)> = server.fetched.iter().copied().collect();
    assert_eq!(
        asked.len(),
        1,
        "the client fetched {asked:?} for a one-item edit"
    );
    assert!(asked.is_subset(&prefixes));
}

struct Sealer;

impl ConflictCopySealer for Sealer {
    fn seal_conflict_copy(
        &mut self,
        losing: &ConflictingVersion,
        _copy_item_id: &[u8; 16],
    ) -> Result<[u8; 32], ManifestError> {
        let mut d = *losing.ciphertext_digest();
        if let Some(b) = d.first_mut() {
            *b ^= 0xFF;
        }
        Ok(d)
    }
}

#[test]
fn a_conflict_copy_lands_in_the_segment_its_own_hash_selects() {
    let k = key(0x11);
    let (mut server, mut st) = vault_of(SPLIT_AT_ENTRIES);
    upload(
        &mut server,
        &k,
        &mut st,
        VAULT,
        &[edit(b"one-more", 1, 0x55)],
    )
    .expect("splits");

    // Find an item whose conflict copy hashes to the other side of the split.
    let root = server.root_of(&k);
    let (item, copy_id) = (0..SPLIT_AT_ENTRIES)
        .map(|i| {
            let id = format!("item-{i}").into_bytes();
            let copy = chiavora_core::manifest::conflict_item_id(&id, &digest(0xA1));
            (id, copy)
        })
        .find(|(id, copy)| {
            let a = root.segment_for(hash_item_id(id)).expect("owned").prefix();
            let b = root
                .segment_for(hash_item_id(copy))
                .expect("owned")
                .prefix();
            a != b
        })
        .expect("some item conflicts across the split");

    // The server's current digest for that item is low, so our 0xA1 loses.
    let current = server
        .entries(&k)
        .into_iter()
        .find(|e| e.item_id() == item)
        .expect("present");
    assert!(
        current.ciphertext_digest() < &digest(0xA1),
        "the fixture needs ours to be the losing side"
    );

    let staged = StagedEdit::new(item.clone(), current.current_version(), digest(0xA1), false);
    upload_resolving(&mut server, &k, &mut st, VAULT, &[staged], &mut Sealer).expect("resolves");

    assert_eq!(
        server.last_write_segments, 2,
        "the primary's segment and the copy's must land in one CAS write"
    );
    let entries = server.entries(&k);
    assert!(
        entries.iter().any(|e| e.item_id() == copy_id),
        "the copy is in no segment"
    );
    assert!(entries.iter().any(|e| e.item_id() == item));
}

struct Rotator {
    target: u32,
}

impl WrapRotator for Rotator {
    fn rewrap(&mut self, _item_id: &[u8]) -> Result<Rewrapped, ManifestError> {
        let _ = self.target;
        Ok(Rewrapped::Rewrapped)
    }
}

#[test]
fn an_edit_after_a_rotation_carries_the_rotated_epoch() {
    let old = key(0x11);
    let new = key(0x22);
    let (mut server, mut st) = vault_of(4);

    rotate(
        &mut server,
        &old,
        &new,
        2,
        &mut st,
        VAULT,
        &mut Rotator { target: 2 },
    )
    .expect("rotates");
    assert_eq!(server.root_of(&new).vault_key_epoch(), 2);

    upload(
        &mut server,
        &new,
        &mut st,
        VAULT,
        &[edit(b"item-0", 2, 0x66)],
    )
    .expect("edits");

    let root = server.root_of(&new);
    assert_eq!(
        root.vault_key_epoch(),
        2,
        "the edit wrote an epoch the vault is not at"
    );
    for bytes in &server.segments {
        match StoredManifest::decode(bytes).expect("segment").fields() {
            AadFields::ManifestSegment {
                vault_key_epoch, ..
            } => assert_eq!(*vault_key_epoch, 2, "a segment is still at epoch 1"),
            _ => panic!("not a segment"),
        }
    }
    assert_eq!(server.entries(&new).len(), 4);
}
