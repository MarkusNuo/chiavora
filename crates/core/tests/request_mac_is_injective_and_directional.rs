#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use chiavora_core::request_mac::{
    body_hash, client_to_server_tag, decode, encode, server_to_client_tag, tags_match, MacError,
    RequestParts, BODY_HASH_LEN, MAC_FORMAT_VERSION, NONCE_LEN,
};
use chiavora_core::secret::{kind::SrpPremasterSecret, Secret};
use chiavora_core::srp::session_keys;

fn parts<'a>(
    method: &'a [u8],
    path: &'a [u8],
    hash: &'a [u8],
    stamp: i64,
    nonce: &'a [u8],
) -> RequestParts<'a> {
    RequestParts {
        method,
        path,
        body_hash: hash,
        timestamp: stamp,
        nonce,
    }
}

const HASH: [u8; BODY_HASH_LEN] = [0x11; BODY_HASH_LEN];
const NONCE: [u8; NONCE_LEN] = [0x22; NONCE_LEN];

#[test]
fn a_path_cannot_borrow_bytes_from_its_neighbour() {
    let split = encode(&parts(b"POST", b"/a", &HASH, 7, &NONCE)).unwrap();
    let joined = encode(&parts(b"POST", b"/a/b", &HASH, 7, &NONCE)).unwrap();

    assert_ne!(
        split, joined,
        "two different paths produced the same MAC input. This is the case the \
         length prefixes exist for: `POST /a/b` and `POST /a` with `/b` leading \
         the next field are different requests, and a MAC that authenticates \
         the wrong one authenticates it perfectly"
    );

    let moved = encode(&parts(b"POST/a", b"/b", &HASH, 7, &NONCE)).unwrap();
    assert_ne!(
        moved, joined,
        "moving the boundary between method and path must change the encoding"
    );
}

#[test]
fn every_encoding_decodes_back_to_what_produced_it() {
    let cases: Vec<(Vec<u8>, Vec<u8>, i64)> = vec![
        (b"GET".to_vec(), b"/".to_vec(), 0),
        (b"POST".to_vec(), b"/a/b".to_vec(), i64::MAX),
        (b"DELETE".to_vec(), b"/a".to_vec(), i64::MIN),
        (Vec::new(), Vec::new(), -1),
        (vec![0_u8; 300], vec![0xFF_u8; 300], 1_760_000_000),
        // Bytes that look like length prefixes, inside the data.
        (b"PO\x00ST".to_vec(), b"/a\x00\x00\x00\x04b".to_vec(), 42),
    ];

    for (method, path, stamp) in cases {
        let encoded = encode(&parts(&method, &path, &HASH, stamp, &NONCE)).unwrap();
        let back = decode(&encoded).unwrap();
        assert_eq!(back.method, method, "method round-trips");
        assert_eq!(back.path, path, "path round-trips");
        assert_eq!(back.body_hash, HASH, "body hash round-trips");
        assert_eq!(back.timestamp, stamp, "timestamp round-trips");
        assert_eq!(back.nonce, NONCE, "nonce round-trips");
    }
}

#[test]
fn no_two_distinct_requests_encode_alike() {
    let methods: [&[u8]; 5] = [b"", b"G", b"GET", b"GET/", b"POST"];
    let paths: [&[u8]; 6] = [b"", b"/", b"/a", b"/a/", b"/a/b", b"a/b"];
    let stamps = [i64::MIN, -1, 0, 1, i64::MAX];

    let mut seen: Vec<(Vec<u8>, String)> = Vec::new();
    for method in methods {
        for path in paths {
            for stamp in stamps {
                let encoded = encode(&parts(method, path, &HASH, stamp, &NONCE)).unwrap();
                let name = format!(
                    "{:?} {:?} {stamp}",
                    String::from_utf8_lossy(method),
                    String::from_utf8_lossy(path)
                );
                if let Some((_, other)) = seen.iter().find(|(bytes, _)| *bytes == encoded) {
                    panic!("{name} and {other} encode to the same bytes");
                }
                seen.push((encoded, name));
            }
        }
    }

    assert_eq!(
        seen.len(),
        methods.len() * paths.len() * stamps.len(),
        "the hunt must have drawn every combination; a loop that drew fewer \
         would report no collisions for the reason that is not evidence"
    );
}

#[test]
fn an_unknown_format_version_is_refused() {
    let mut encoded = encode(&parts(b"GET", b"/", &HASH, 1, &NONCE)).unwrap();
    assert_eq!(
        encoded.first().copied(),
        Some(MAC_FORMAT_VERSION),
        "the encoding must start with the version byte"
    );

    if let Some(first) = encoded.first_mut() {
        *first = MAC_FORMAT_VERSION.wrapping_add(1);
    }
    assert_eq!(
        decode(&encoded).unwrap_err(),
        MacError::Version,
        "a future version must be refused rather than parsed as this one"
    );
}

#[test]
fn a_truncated_or_wrong_width_encoding_is_refused() {
    let encoded = encode(&parts(b"GET", b"/a", &HASH, 1, &NONCE)).unwrap();

    for cut in [0, 1, 5, encoded.len() - 1] {
        assert!(
            decode(encoded.get(..cut).unwrap()).is_err(),
            "a {cut}-byte prefix must not decode"
        );
    }
    assert_eq!(
        decode(&[encoded.clone(), vec![0]].concat()).unwrap_err(),
        MacError::Truncated,
        "trailing bytes must be refused; an encoding with slack is two \
         encodings of the same request"
    );

    assert_eq!(
        encode(&parts(b"GET", b"/", &[0; BODY_HASH_LEN - 1], 1, &NONCE)).unwrap_err(),
        MacError::FieldLength
    );
    assert_eq!(
        encode(&parts(b"GET", b"/", &HASH, 1, &[0; NONCE_LEN + 1])).unwrap_err(),
        MacError::FieldLength
    );
}

#[test]
fn a_client_to_server_tag_does_not_verify_as_a_server_to_client_one() {
    let premaster = Secret::<SrpPremasterSecret>::from_derived_bytes(vec![0x5E; 512]);
    let keys = session_keys(&premaster).unwrap();
    let request = parts(b"POST", b"/v1/items", &HASH, 1_760_000_000, &NONCE);

    let c2s = client_to_server_tag(&keys.mac_client_to_server, &request).unwrap();
    let s2c = server_to_client_tag(&keys.mac_server_to_client, &request).unwrap();

    assert!(
        !tags_match(&c2s, &s2c),
        "the same request tagged in both directions produced the same tag, so a \
         reflected message verifies under the key that sent it — which is the \
         defect exists to close, and this is the first change in which \
         anything could reflect"
    );

    assert!(tags_match(
        &c2s,
        &client_to_server_tag(&keys.mac_client_to_server, &request).unwrap()
    ));
    assert!(tags_match(
        &s2c,
        &server_to_client_tag(&keys.mac_server_to_client, &request).unwrap()
    ));
}

#[test]
fn the_tag_covers_every_field() {
    let premaster = Secret::<SrpPremasterSecret>::from_derived_bytes(vec![0x5E; 512]);
    let key = session_keys(&premaster).unwrap().mac_client_to_server;
    let base = parts(b"POST", b"/v1/items", &HASH, 1_000, &NONCE);
    let baseline = client_to_server_tag(&key, &base).unwrap();

    let other_hash = [0x33_u8; BODY_HASH_LEN];
    let other_nonce = [0x44_u8; NONCE_LEN];
    let variants = [
        ("method", parts(b"GET", b"/v1/items", &HASH, 1_000, &NONCE)),
        ("path", parts(b"POST", b"/v1/item", &HASH, 1_000, &NONCE)),
        (
            "body hash",
            parts(b"POST", b"/v1/items", &other_hash, 1_000, &NONCE),
        ),
        (
            "timestamp",
            parts(b"POST", b"/v1/items", &HASH, 1_001, &NONCE),
        ),
        (
            "nonce",
            parts(b"POST", b"/v1/items", &HASH, 1_000, &other_nonce),
        ),
    ];

    for (field, variant) in variants {
        assert!(
            !tags_match(&baseline, &client_to_server_tag(&key, &variant).unwrap()),
            "changing the {field} did not change the tag, so the MAC does not \
             cover it. docs/security-design.md §2.3 names all five"
        );
    }
}

#[test]
fn tags_match_accepts_only_an_exact_equal_length_match() {
    let tag = vec![0x7E_u8; 32];
    assert!(tags_match(&tag, &tag.clone()));

    let mut last = tag.clone();
    *last.last_mut().unwrap() ^= 1;
    assert!(
        !tags_match(&tag, &last),
        "a final-byte difference must be caught"
    );

    assert!(
        !tags_match(&tag, tag.get(..31).unwrap()),
        "a prefix must not match"
    );
    assert!(!tags_match(&tag, &[]), "the empty tag must not match");
}

#[test]
fn the_body_hash_is_the_width_the_encoding_requires() {
    assert_eq!(body_hash(b"").len(), BODY_HASH_LEN);
    assert_eq!(body_hash(b"hello").len(), BODY_HASH_LEN);
    assert_ne!(body_hash(b"hello"), body_hash(b"hellp"));
    assert!(encode(&parts(b"GET", b"/", &body_hash(b"x"), 1, &NONCE)).is_ok());
}
