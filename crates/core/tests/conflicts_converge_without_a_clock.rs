#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use chiavora_core::aad::AadFields;
use chiavora_core::manifest::{
    conflict_item_id, hash_item_id, open_root, open_segment, resolve, CanonicalPrefix,
    ConflictingVersion, Entry, ManifestError, Resolution, StoredManifest,
};
use chiavora_core::secret::{
    kind::{Muk, VaultKey},
    Secret,
};
use chiavora_core::store::{Store, Unanchored};
use chiavora_core::sync::{
    upload, upload_resolving, CasRefused, ConflictCopySealer, ManifestTransport, StagedEdit,
    Uploaded,
};
use sha2::{Digest, Sha256};

const VAULT: &[u8] = b"vault-1";

fn digest(fill: u8) -> [u8; 32] {
    [fill; 32]
}

fn version(id: &[u8], v: u64, fill: u8) -> ConflictingVersion {
    ConflictingVersion::new(id.to_vec(), v, digest(fill))
}

#[test]
fn the_conflict_copys_id_is_the_first_16_bytes_of_the_domain_separated_hash() {
    let losing_id = b"item-bank";
    let losing_digest = digest(0xB1);

    let mut hasher = Sha256::new();
    hasher.update(b"chiavora-conflict|");
    hasher.update(losing_id);
    hasher.update(losing_digest);
    let expected: [u8; 32] = hasher.finalize().into();

    let got = conflict_item_id(losing_id, &losing_digest);
    assert_eq!(
        got.as_slice(),
        expected.get(..16).expect("a digest is 32 bytes"),
        "the copy's id is the first 16 bytes of the domain-separated hash"
    );
    assert_eq!(got.len(), 16, "128 bits, matching itemId's width");
}

#[test]
fn the_derivation_is_domain_separated_and_differs_from_the_bare_hash() {
    let id = b"item-bank";
    let d = digest(0xB1);

    let mut bare = Sha256::new();
    bare.update(id);
    bare.update(d);
    let bare: [u8; 32] = bare.finalize().into();

    assert_ne!(
        conflict_item_id(id, &d).as_slice(),
        bare.get(..16).expect("32 bytes"),
        "without the separator this derivation's output space would overlap \
         every other bare SHA-256 over an identifier and a digest in this system"
    );
}

#[test]
fn field_boundaries_do_not_run_together() {
    let a = conflict_item_id(b"ab", &digest(0x11));
    let b = conflict_item_id(b"a", &digest(0x11));
    assert_ne!(a, b);
}

#[test]
fn the_smaller_digest_is_the_surviving_primary() {
    let small = version(b"item", 4, 0x11);
    let large = version(b"item", 4, 0xFF);

    match resolve(&small, &large) {
        Resolution::Conflict { primary, copy, .. } => {
            assert_eq!(primary.ciphertext_digest(), &digest(0x11));
            assert_eq!(copy.ciphertext_digest(), &digest(0xFF));
        }
        other @ Resolution::SameEdit => panic!("expected a conflict, got {other:?}"),
    }
}

#[test]
fn the_comparison_is_unsigned_and_most_significant_byte_first() {
    let mut low = [0_u8; 32];
    let mut high = [0_u8; 32];
    low[0] = 0x7F;
    high[0] = 0x80; // would be "negative" if compared as i8
    low[31] = 0xFF; // and the last byte must not outweigh the first

    let a = ConflictingVersion::new(b"item".to_vec(), 4, low);
    let b = ConflictingVersion::new(b"item".to_vec(), 4, high);
    match resolve(&a, &b) {
        Resolution::Conflict { primary, .. } => {
            assert_eq!(
                primary.ciphertext_digest()[0],
                0x7F,
                "0x80 must not sort below 0x7F"
            );
        }
        other @ Resolution::SameEdit => panic!("expected a conflict, got {other:?}"),
    }
}

#[test]
fn resolve_is_symmetric_in_its_arguments() {
    for (x, y) in [(0x11_u8, 0xFF_u8), (0xFF, 0x11), (0x00, 0x01), (0x7F, 0x80)] {
        let a = version(b"item", 4, x);
        let b = version(b"item", 4, y);
        assert_eq!(
            resolve(&a, &b),
            resolve(&b, &a),
            "argument order changed the answer, so two devices would diverge"
        );
    }
}

#[test]
fn identical_digests_are_the_same_edit_and_not_a_conflict() {
    let a = version(b"item", 4, 0x42);
    let b = version(b"item", 4, 0x42);
    assert_eq!(resolve(&a, &b), Resolution::SameEdit);
}

#[test]
fn two_devices_resolving_independently_reach_the_same_answer() {
    let mine = version(b"login-bank", 7, 0xA1);
    let theirs = version(b"login-bank", 7, 0x5C);

    let on_a = resolve(&mine, &theirs);
    let on_b = resolve(&theirs, &mine);

    assert_eq!(
        on_a, on_b,
        "the two devices disagree, so they never converge"
    );

    match on_a {
        Resolution::Conflict {
            primary,
            copy,
            copy_item_id,
        } => {
            assert_eq!(
                primary.ciphertext_digest(),
                &digest(0x5C),
                "the smaller digest survives"
            );
            assert_eq!(
                copy_item_id,
                conflict_item_id(copy.item_id(), copy.ciphertext_digest()),
                "the copy's id is derived from the losing side, so both devices \
                 mint the same one"
            );
        }
        Resolution::SameEdit => panic!("these are different edits"),
    }
}

#[test]
fn both_versions_survive_resolution() {
    let mine = version(b"login-bank", 7, 0xA1);
    let theirs = version(b"login-bank", 7, 0x5C);

    match resolve(&mine, &theirs) {
        Resolution::Conflict { primary, copy, .. } => {
            let kept = [*primary.ciphertext_digest(), *copy.ciphertext_digest()];
            assert!(kept.contains(&digest(0xA1)), "my edit was discarded");
            assert!(kept.contains(&digest(0x5C)), "their edit was discarded");
        }
        other @ Resolution::SameEdit => panic!("expected a conflict, got {other:?}"),
    }
}

#[test]
fn a_conflict_of_a_conflict_copy_converges_with_no_special_case() {
    let first = resolve(
        &version(b"login-bank", 7, 0xA1),
        &version(b"login-bank", 7, 0x5C),
    );
    let Resolution::Conflict { copy_item_id, .. } = first else {
        panic!("generation 1 is a conflict");
    };

    let gen2_mine = ConflictingVersion::new(copy_item_id.to_vec(), 1, digest(0x33));
    let gen2_theirs = ConflictingVersion::new(copy_item_id.to_vec(), 1, digest(0x22));

    let on_a = resolve(&gen2_mine, &gen2_theirs);
    let on_b = resolve(&gen2_theirs, &gen2_mine);
    assert_eq!(on_a, on_b, "generation 2 diverges");

    match on_a {
        Resolution::Conflict {
            copy_item_id: second,
            ..
        } => {
            assert_ne!(
                second, copy_item_id,
                "the second-generation copy is its own item"
            );
            assert_eq!(second.len(), 16, "and the same width as any other itemId");
        }
        Resolution::SameEdit => panic!("generation 2 is a conflict"),
    }
}

#[test]
fn a_conflict_copy_hashes_independently_of_its_primary() {
    let mut differing = 0_usize;
    for n in 0..64_u8 {
        let mine = version(format!("item-{n}").as_bytes(), 1, 0xA1);
        let theirs = version(format!("item-{n}").as_bytes(), 1, 0x5C);
        if let Resolution::Conflict {
            primary,
            copy_item_id,
            ..
        } = resolve(&mine, &theirs)
        {
            // Top bit of each hash: the prefix a one-bit split would use.
            let primary_bit = hash_item_id(primary.item_id()) >> 63;
            let copy_bit = hash_item_id(&copy_item_id) >> 63;
            if primary_bit != copy_bit {
                differing += 1;
            }
        }
    }
    assert!(
        differing > 0,
        "over 64 conflicts, no copy landed on the other side of a one-bit \
         split — the derived id is not hashing independently"
    );
}

struct OneServer {
    root: Option<Vec<u8>>,
    segments: Vec<Vec<u8>>,
    current_seq: u64,
    writes_accepted: usize,
}

impl OneServer {
    const fn empty() -> Self {
        Self {
            root: None,
            segments: Vec::new(),
            current_seq: 0,
            writes_accepted: 0,
        }
    }

    fn seq_of(bytes: &[u8]) -> u64 {
        let stored = StoredManifest::decode(bytes).expect("well-formed");
        match stored.fields() {
            AadFields::ManifestRoot { manifest_seq, .. } => *manifest_seq,
            _ => panic!("not a root"),
        }
    }

    fn entries(&self, key: &Secret<VaultKey>) -> Vec<Entry> {
        let Some(root_bytes) = self.root.as_ref() else {
            return Vec::new();
        };
        let root =
            open_root(key, &StoredManifest::decode(root_bytes).expect("root")).expect("opens");
        let mut out = Vec::new();
        for entry in root.segments() {
            let want = (entry.prefix().bit_len(), entry.prefix().bits());
            let Some(bytes) = self.segments.iter().find(|b| prefix_key(b) == want) else {
                continue;
            };
            let stored = StoredManifest::decode(bytes).expect("well-formed");
            out.extend(
                open_segment(key, &stored)
                    .expect("opens")
                    .entries()
                    .to_vec(),
            );
        }
        out
    }

    fn entry(&self, key: &Secret<VaultKey>, id: &[u8]) -> Option<Entry> {
        self.entries(key).into_iter().find(|e| e.item_id() == id)
    }
}

impl ManifestTransport for OneServer {
    fn fetch_root(&mut self) -> Result<Option<Vec<u8>>, ManifestError> {
        Ok(self.root.clone())
    }

    fn fetch_segment(&mut self, prefix: CanonicalPrefix) -> Result<Option<Vec<u8>>, ManifestError> {
        let key = (prefix.bit_len(), prefix.bits());
        Ok(self.segments.iter().find(|b| prefix_key(b) == key).cloned())
    }

    fn compare_and_swap(&mut self, root: &[u8], segments: &[Vec<u8>]) -> Result<(), CasRefused> {
        let offered = Self::seq_of(root);
        if offered != self.current_seq + 1 {
            return Err(CasRefused {
                current_manifest_seq: self.current_seq,
            });
        }
        self.root = Some(root.to_vec());
        merge_segments(&mut self.segments, segments);
        self.current_seq = offered;
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

fn edit(id: &[u8], version: u64, fill: u8) -> StagedEdit {
    StagedEdit::new(id.to_vec(), version, digest(fill), false)
}

/// Stands in for re-sealing the loser under the copy's `itemId`; a flipped byte
/// models the fresh nonce, so the copy's digest is never the loser's.
#[derive(Default)]
struct RecordingSealer {
    calls: Vec<(Vec<u8>, [u8; 16])>,
    refuses: bool,
}

impl RecordingSealer {
    fn refusing() -> Self {
        Self {
            calls: Vec::new(),
            refuses: true,
        }
    }
}

impl ConflictCopySealer for RecordingSealer {
    fn seal_conflict_copy(
        &mut self,
        losing: &ConflictingVersion,
        copy_item_id: &[u8; 16],
    ) -> Result<[u8; 32], ManifestError> {
        if self.refuses {
            return Err(ManifestError::TransportFailed);
        }
        self.calls.push((losing.item_id().to_vec(), *copy_item_id));
        let mut resealed = *losing.ciphertext_digest();
        if let Some(b) = resealed.first_mut() {
            *b ^= 0xFF;
        }
        Ok(resealed)
    }
}

fn vault_holding(server: &mut OneServer, key: &Secret<VaultKey>, id: &[u8], fill: u8) {
    let mut other_device = store();
    upload(server, key, &mut other_device, VAULT, &[edit(id, 4, fill)]).expect("the other device");
}

#[test]
fn a_resolved_conflict_lands_as_one_cas_write_carrying_both_versions() {
    let key = vault_key();
    let mut server = OneServer::empty();
    vault_holding(&mut server, &key, b"login-bank", 0x5C);
    let before = server.writes_accepted;

    let mut me = store();
    let mut sealer = RecordingSealer::default();
    let out = upload_resolving(
        &mut server,
        &key,
        &mut me,
        VAULT,
        &[edit(b"login-bank", 4, 0xA1)],
        &mut sealer,
    )
    .expect("resolves and uploads");

    assert_eq!(out, Uploaded::Written { manifest_seq: 2 });
    assert_eq!(
        server.writes_accepted - before,
        1,
        "two writes leave a window in which one of the two passwords is in no \
         manifest at all"
    );

    let copy_id = conflict_item_id(b"login-bank", &digest(0xA1));
    assert!(
        server.entry(&key, b"login-bank").is_some(),
        "the primary is gone"
    );
    assert!(
        server.entry(&key, &copy_id).is_some(),
        "the copy is not in the manifest the single write produced"
    );
}

#[test]
fn the_smaller_digest_keeps_the_original_item_id() {
    let key = vault_key();
    let mut server = OneServer::empty();
    vault_holding(&mut server, &key, b"login-bank", 0x5C);

    let mut me = store();
    let mut sealer = RecordingSealer::default();
    upload_resolving(
        &mut server,
        &key,
        &mut me,
        VAULT,
        &[edit(b"login-bank", 4, 0xA1)],
        &mut sealer,
    )
    .expect("resolves");

    let primary = server.entry(&key, b"login-bank").expect("primary");
    assert_eq!(
        primary.ciphertext_digest(),
        &digest(0x5C),
        "0xA1 displaced the smaller digest from the original id"
    );
    assert_eq!(
        sealer.calls.len(),
        1,
        "the sealer is asked for exactly the losing side"
    );
}

#[test]
fn the_copys_entry_carries_the_resealed_digest_and_not_the_losers() {
    let key = vault_key();
    let mut server = OneServer::empty();
    vault_holding(&mut server, &key, b"login-bank", 0x5C);

    let mut me = store();
    let mut sealer = RecordingSealer::default();
    upload_resolving(
        &mut server,
        &key,
        &mut me,
        VAULT,
        &[edit(b"login-bank", 4, 0xA1)],
        &mut sealer,
    )
    .expect("resolves");

    let copy_id = conflict_item_id(b"login-bank", &digest(0xA1));
    let copy = server.entry(&key, &copy_id).expect("copy");
    assert_ne!(
        copy.ciphertext_digest(),
        &digest(0xA1),
        "the copy names the loser's record, which will not open under the \
         copy's own itemId"
    );
    assert_eq!(
        sealer.calls,
        vec![(b"login-bank".to_vec(), copy_id)],
        "the sealer must be told the id to seal under, not just the loser"
    );
    assert_eq!(
        copy.current_version(),
        1,
        "a copy is a new item's first version"
    );
}

#[test]
fn a_copy_is_placed_by_its_own_hash_which_can_differ_from_its_primarys() {
    let key = vault_key();

    // Find an item whose copy falls on the other side of a one-bit split.
    let (id, copy_id) = (0..64_u32)
        .map(|n| {
            let id = format!("item-{n}").into_bytes();
            let copy_id = conflict_item_id(&id, &digest(0xA1));
            (id, copy_id)
        })
        .find(|(id, copy_id)| hash_item_id(id) >> 63 != hash_item_id(copy_id) >> 63)
        .expect("some item conflicts across a one-bit split");

    let mut server = OneServer::empty();
    vault_holding(&mut server, &key, &id, 0x5C);
    let mut me = store();
    let mut sealer = RecordingSealer::default();
    upload_resolving(
        &mut server,
        &key,
        &mut me,
        VAULT,
        &[StagedEdit::new(id.clone(), 4, digest(0xA1), false)],
        &mut sealer,
    )
    .expect("resolves");

    assert!(server.entry(&key, &id).is_some());
    assert!(server.entry(&key, &copy_id).is_some());
    assert_ne!(
        hash_item_id(&id) >> 63,
        hash_item_id(&copy_id) >> 63,
        "the copy would follow its primary into the wrong half of a split"
    );
}

#[test]
fn resolving_a_conflict_whose_copy_already_exists_adds_nothing() {
    let key = vault_key();
    let mut server = OneServer::empty();
    vault_holding(&mut server, &key, b"login-bank", 0x5C);

    let mut me = store();
    let mut sealer = RecordingSealer::default();
    let staged = [edit(b"login-bank", 4, 0xA1)];
    upload_resolving(&mut server, &key, &mut me, VAULT, &staged, &mut sealer).expect("first");
    let after_first = server.entries(&key).len();

    upload_resolving(&mut server, &key, &mut me, VAULT, &staged, &mut sealer).expect("second");

    assert_eq!(
        server.entries(&key).len(),
        after_first,
        "a second copy of the same losing version"
    );
    assert_eq!(
        sealer.calls.len(),
        1,
        "the sealer was asked to re-seal a copy that already exists"
    );
}

#[test]
fn an_upload_that_cannot_reseal_still_refuses_rather_than_choosing() {
    let key = vault_key();
    let mut server = OneServer::empty();
    vault_holding(&mut server, &key, b"login-bank", 0x5C);
    let before = server.writes_accepted;

    let mut me = store();
    let refused = upload(
        &mut server,
        &key,
        &mut me,
        VAULT,
        &[edit(b"login-bank", 4, 0xA1)],
    );

    assert!(
        matches!(refused, Err(ManifestError::ConflictNeedsResolution)),
        "got {refused:?}"
    );
    assert_eq!(server.writes_accepted, before, "it wrote anyway");
}

#[test]
fn a_reseal_that_fails_writes_nothing_at_all() {
    let key = vault_key();
    let mut server = OneServer::empty();
    vault_holding(&mut server, &key, b"login-bank", 0x5C);
    let before = server.writes_accepted;

    let mut me = store();
    let mut sealer = RecordingSealer::refusing();
    let out = upload_resolving(
        &mut server,
        &key,
        &mut me,
        VAULT,
        &[edit(b"login-bank", 4, 0xA1)],
        &mut sealer,
    );

    assert!(out.is_err(), "got {out:?}");
    assert_eq!(
        server.writes_accepted, before,
        "the primary landed without its copy"
    );
}

#[test]
fn a_losing_deletion_survives_as_a_deleted_copy() {
    let key = vault_key();
    let mut server = OneServer::empty();
    vault_holding(&mut server, &key, b"login-bank", 0x5C);

    let mut me = store();
    let mut sealer = RecordingSealer::default();
    upload_resolving(
        &mut server,
        &key,
        &mut me,
        VAULT,
        // A delete at the same version, with the larger digest, so it loses.
        &[StagedEdit::new(
            b"login-bank".to_vec(),
            4,
            digest(0xA1),
            true,
        )],
        &mut sealer,
    )
    .expect("resolves");

    let copy = server
        .entry(&key, &conflict_item_id(b"login-bank", &digest(0xA1)))
        .expect("copy");
    assert!(copy.tombstone(), "the deletion was dropped, not copied");
    assert!(
        !server
            .entry(&key, b"login-bank")
            .expect("primary")
            .tombstone(),
        "the surviving edit was deleted by the losing side's flag"
    );
}

#[test]
fn two_devices_editing_offline_converge_on_one_vault_holding_both() {
    let key = vault_key();
    let mut server = OneServer::empty();

    let mut device_a = store();
    upload(
        &mut server,
        &key,
        &mut device_a,
        VAULT,
        &[edit(b"login-bank", 3, 0x01)],
    )
    .expect("base");

    upload(
        &mut server,
        &key,
        &mut device_a,
        VAULT,
        &[edit(b"login-bank", 4, 0x5C)],
    )
    .expect("device A");

    let mut device_b = store();
    let mut sealer = RecordingSealer::default();
    upload_resolving(
        &mut server,
        &key,
        &mut device_b,
        VAULT,
        &[edit(b"login-bank", 4, 0xA1)],
        &mut sealer,
    )
    .expect("device B");

    let entries = server.entries(&key);
    assert_eq!(entries.len(), 2, "one conflict, two items: {entries:?}");
    assert_eq!(
        server
            .entry(&key, b"login-bank")
            .expect("primary")
            .ciphertext_digest(),
        &digest(0x5C),
    );
    assert!(
        server
            .entry(&key, &conflict_item_id(b"login-bank", &digest(0xA1)))
            .is_some(),
        "device B's edit is in no item"
    );

    let settled = server.entries(&key);
    upload(&mut server, &key, &mut device_a, VAULT, &[]).expect("device A resyncs");
    assert_eq!(server.entries(&key), settled, "A re-decided the conflict");
}
