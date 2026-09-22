//! Vectors from `tools/srp_reference.py`; nothing external exists to check them.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use chiavora_core::secret::{kind::SrpX, Secret};
use chiavora_core::srp::{private_exponent, verifier, Group};

fn vectors() -> serde_json::Value {
    serde_json::from_str(include_str!("vectors/srp_derivation.json")).unwrap()
}

/// A field by path, without `Index` (the workspace denies `indexing_slicing`).
fn field<'a>(value: &'a serde_json::Value, path: &[&str]) -> &'a serde_json::Value {
    path.iter()
        .fold(value, |node, key| node.get(key).expect("field present"))
}

fn decode(hex: &str) -> Vec<u8> {
    hex.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = core::str::from_utf8(pair).expect("hex is ASCII");
            u8::from_str_radix(text, 16).expect("hex digit pair")
        })
        .collect()
}

#[test]
fn project_vectors_cover_the_x_derivation_and_verifier_at_4096_sha256() {
    let json = vectors();
    let cases = field(&json, &["vectors"]).as_array().unwrap();
    assert!(cases.len() >= 4, "the suite must keep its edge cases");

    let group = Group::RFC5054_4096;
    let mut saw_leading_zero = false;

    for case in cases {
        let name = field(case, &["name"]).as_str().unwrap();
        let srp_salt = decode(field(case, &["srp_salt"]).as_str().unwrap());
        let srp_x =
            Secret::<SrpX>::from_derived_bytes(decode(field(case, &["srp_x"]).as_str().unwrap()));
        let want_x = decode(field(case, &["x"]).as_str().unwrap());
        let want_v = decode(field(case, &["verifier"]).as_str().unwrap());

        let x = private_exponent(&srp_salt, &srp_x).unwrap();
        assert_eq!(
            x.expose(),
            want_x.as_slice(),
            "{name}: x = SHA-256(srpSalt || srpX)"
        );

        if want_x.first() == Some(&0) {
            saw_leading_zero = true;
        }

        let v = verifier(group, &x).unwrap();
        // Fixed-width, as stored; trimming would hide the leading-zero case.
        let mut got_v = vec![0_u8; want_v.len()];
        let bytes = v.to_be_bytes();
        let start = got_v.len().saturating_sub(bytes.len());
        for (slot, byte) in got_v.iter_mut().skip(start).zip(bytes.iter()) {
            *slot = *byte;
        }
        assert_eq!(got_v, want_v, "{name}: v = g^x mod N");
    }

    assert!(
        saw_leading_zero,
        "the suite must contain an x with a leading zero byte; that case is \
         searched for by tools/srp_reference.py and is where fixed-width \
         encoding goes wrong"
    );
}

#[test]
fn the_vector_file_states_that_nothing_external_checks_it() {
    let json = vectors();
    let checked = field(&json, &["checked_against"]).as_str().unwrap();
    assert!(
        checked.contains("NOTHING EXTERNAL"),
        "srp_derivation.json must state that no external source checks it"
    );
    assert!(
        checked.contains("sharing no code with crates/core"),
        "and must state what the evidence actually is: an independent \
         implementation written from the ADR"
    );
    let scope = field(&json, &["scope"]).as_str().unwrap();
    assert!(
        scope.contains("SHIPPING"),
        "and must state that this is the shipping configuration, which is what \
         distinguishes it from the Appendix B vectors"
    );
}
