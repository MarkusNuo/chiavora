#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use chiavora_core::manifest::{
    conflict_item_id, hash_item_id, resolve, ConflictingVersion, Resolution,
};
use sha2::{Digest, Sha256};

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
