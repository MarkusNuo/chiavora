//! The proofs and key schedule at 4096-bit SHA-256, against vectors from `tools/srp_reference.py`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use chiavora_core::secret::{
    kind::{SrpEphemeralSecret, SrpX},
    Secret,
};
use chiavora_core::srp::{
    client_premaster, client_proof, client_public, private_exponent, proofs_match,
    server_premaster, server_proof, server_public, session_keys, verifier, Group, Sha256Hash,
    SrpError, SRP_SALT_LEN,
};
use crypto_bigint::BoxedUint;

fn vectors() -> serde_json::Value {
    serde_json::from_str(include_str!("vectors/srp_proofs.json")).unwrap()
}

/// The RFC 5054 group table, read from the vector file rather than from `srp.rs`.
fn groups() -> serde_json::Value {
    serde_json::from_str(include_str!("vectors/srp_groups.json")).unwrap()
}

/// A field by path, without `Index` (the workspace denies `indexing_slicing`).
fn field<'a>(value: &'a serde_json::Value, path: &[&str]) -> &'a serde_json::Value {
    path.iter()
        .fold(value, |node, key| node.get(key).expect("field present"))
}

fn text<'a>(value: &'a serde_json::Value, key: &str) -> &'a str {
    field(value, &[key]).as_str().expect("a string")
}

fn decode(hex: &str) -> Vec<u8> {
    hex.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digits = core::str::from_utf8(pair).expect("hex is ASCII");
            u8::from_str_radix(digits, 16).expect("a hex pair")
        })
        .collect()
}

/// Big-endian bytes at a fixed width; trimming would hide the short values.
fn fixed(value: &BoxedUint, width: usize) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let mut out = vec![0_u8; width];
    let start = out.len().saturating_sub(bytes.len());
    for (slot, byte) in out.iter_mut().skip(start).zip(bytes.iter()) {
        *slot = *byte;
    }
    out
}

#[test]
fn project_vectors_cover_m1_m2_and_the_key_schedule_at_4096_sha256() {
    let json = vectors();
    let cases = field(&json, &["vectors"]).as_array().unwrap();
    assert!(
        cases.len() >= 3,
        "the suite must keep its searched-for cases"
    );

    let group = Group::RFC5054_4096;
    // The padded width comes from the data, not from the module.
    let width = text(cases.first().expect("a case"), "A").len() / 2;
    assert_eq!(width, 512, "the 4096-bit group pads to 512 bytes");

    for case in cases {
        let name = text(case, "name");
        let identity = decode(text(case, "account_id"));
        let srp_salt = decode(text(case, "srp_salt"));
        let srp_x = Secret::<SrpX>::from_derived_bytes(decode(text(case, "srp_x")));

        let x = private_exponent(&srp_salt, &srp_x).unwrap();
        assert_eq!(x.expose(), decode(text(case, "x")), "{name}: x");

        let v = verifier(group, &x).unwrap();
        assert_eq!(
            fixed(&v, width),
            decode(text(case, "verifier")),
            "{name}: v"
        );

        let a = Secret::<SrpEphemeralSecret>::from_derived_bytes(decode(text(case, "a")));
        let b = Secret::<SrpEphemeralSecret>::from_derived_bytes(decode(text(case, "b")));

        let public_a = client_public(group, &a).unwrap();
        let public_b = server_public::<Sha256Hash>(group, &b, &v).unwrap();
        assert_eq!(
            fixed(&public_a, width),
            decode(text(case, "A")),
            "{name}: A"
        );
        assert_eq!(
            fixed(&public_b, width),
            decode(text(case, "B")),
            "{name}: B"
        );

        let client_s = client_premaster::<Sha256Hash>(group, &a, &x, &public_b).unwrap();
        let server_s = server_premaster::<Sha256Hash>(group, &b, &v, &public_a).unwrap();
        let want_s = decode(text(case, "S"));
        assert_eq!(client_s.expose(), want_s.as_slice(), "{name}: S (client)");
        assert_eq!(server_s.expose(), want_s.as_slice(), "{name}: S (server)");

        let keys = session_keys(&client_s).unwrap();
        assert_eq!(
            keys.session_key.expose(),
            decode(text(case, "K")),
            "{name}: K"
        );
        assert_eq!(
            keys.mac_client_to_server.expose(),
            decode(text(case, "mac_c2s")),
            "{name}: macC2S"
        );
        assert_eq!(
            keys.mac_server_to_client.expose(),
            decode(text(case, "mac_s2c")),
            "{name}: macS2C"
        );

        let m1 = client_proof::<Sha256Hash>(
            group,
            &identity,
            &srp_salt,
            &public_a,
            &public_b,
            &keys.session_key,
        )
        .unwrap();
        assert_eq!(m1, decode(text(case, "M1")), "{name}: M1");

        let m2 = server_proof::<Sha256Hash>(group, &public_a, &m1, &keys.session_key).unwrap();
        assert_eq!(m2, decode(text(case, "M2")), "{name}: M2");

        assert!(
            proofs_match(&m1, &decode(text(case, "M1"))),
            "{name}: M1 matches"
        );
        assert!(
            proofs_match(&m2, &decode(text(case, "M2"))),
            "{name}: M2 matches"
        );
    }
}

#[test]
fn the_suite_contains_a_short_a_and_a_short_b() {
    let json = vectors();
    let cases = field(&json, &["vectors"]).as_array().unwrap();

    let short_a = cases
        .iter()
        .filter(|case| text(case, "A").starts_with("00"))
        .count();
    let short_b = cases
        .iter()
        .filter(|case| text(case, "B").starts_with("00"))
        .count();

    assert!(
        short_a >= 1 && short_b >= 1,
        "the suite needs a short A and a short B; found {short_a} and {short_b}"
    );
}

#[test]
fn an_unpadded_transcript_disagrees_on_the_short_vectors() {
    use sha2::{Digest as _, Sha256};

    let json = vectors();
    let cases = field(&json, &["vectors"]).as_array().unwrap();
    let table = groups();
    let modulus_hex = text(field(&table, &["groups", "4096"]), "N");
    let generator = field(&table, &["groups", "4096"])
        .get("g")
        .and_then(serde_json::Value::as_u64)
        .expect("g");
    let width = modulus_hex.len() / 2;

    let mut witnessed = 0_usize;

    for case in cases {
        let name = text(case, "name");
        let padded_a = decode(text(case, "A"));
        let padded_b = decode(text(case, "B"));
        // The minimal big-endian encoding: what §2.6's bare `A` reads as.
        let bare_a: Vec<u8> = padded_a.iter().copied().skip_while(|b| *b == 0).collect();
        let bare_b: Vec<u8> = padded_b.iter().copied().skip_while(|b| *b == 0).collect();
        if bare_a.len() == padded_a.len() && bare_b.len() == padded_b.len() {
            continue; // nothing to disagree about on this vector
        }

        let identity = decode(text(case, "account_id"));
        let srp_salt = decode(text(case, "srp_salt"));
        let session_key = decode(text(case, "K"));

        let h_n = Sha256::digest(decode(modulus_hex));
        let mut padded_g = vec![0_u8; width];
        if let Some(slot) = padded_g.last_mut() {
            *slot = u8::try_from(generator).expect("g = 5 fits a byte");
        }
        let h_g = Sha256::digest(&padded_g);
        let group_xor: Vec<u8> = h_n.iter().zip(h_g.iter()).map(|(l, r)| l ^ r).collect();

        let mut unpadded = Sha256::new();
        unpadded.update(&group_xor);
        unpadded.update(Sha256::digest(&identity));
        unpadded.update(&srp_salt);
        unpadded.update(&bare_a);
        unpadded.update(&bare_b);
        unpadded.update(&session_key);

        assert_ne!(
            unpadded.finalize().to_vec(),
            decode(text(case, "M1")),
            "{name}: the unpadded transcript produced the same M1 as the padded one"
        );
        witnessed += 1;
    }

    assert!(
        witnessed >= 2,
        "both searched-for vectors must reach the comparison; {witnessed} did"
    );
}

#[test]
fn the_three_session_keys_differ_and_none_is_the_premaster_secret() {
    let json = vectors();
    let cases = field(&json, &["vectors"]).as_array().unwrap();
    let group = Group::RFC5054_4096;

    for case in cases {
        let name = text(case, "name");
        let srp_salt = decode(text(case, "srp_salt"));
        let srp_x = Secret::<SrpX>::from_derived_bytes(decode(text(case, "srp_x")));
        let exponent = private_exponent(&srp_salt, &srp_x).unwrap();
        let client_ephemeral =
            Secret::<SrpEphemeralSecret>::from_derived_bytes(decode(text(case, "a")));
        let server_ephemeral =
            Secret::<SrpEphemeralSecret>::from_derived_bytes(decode(text(case, "b")));
        let stored = verifier(group, &exponent).unwrap();
        let public_b = server_public::<Sha256Hash>(group, &server_ephemeral, &stored).unwrap();
        let premaster =
            client_premaster::<Sha256Hash>(group, &client_ephemeral, &exponent, &public_b).unwrap();

        let keys = session_keys(&premaster).unwrap();
        let session = keys.session_key.expose();
        let c2s = keys.mac_client_to_server.expose();
        let s2c = keys.mac_server_to_client.expose();

        assert_ne!(session, c2s, "{name}: K and macC2S are the same key");
        assert_ne!(session, s2c, "{name}: K and macS2C are the same key");
        assert_ne!(
            c2s, s2c,
            "{name}: the two directions share a MAC key, so a reflected message verifies"
        );
        for (label, key) in [("K", session), ("macC2S", c2s), ("macS2C", s2c)] {
            assert_ne!(
                key,
                premaster.expose(),
                "{name}: {label} is S itself rather than derived from it"
            );
        }
    }
}

#[test]
fn proofs_match_accepts_only_an_exact_equal_length_match() {
    let proof = vec![0xA5_u8; 32];

    assert!(proofs_match(&proof, &proof.clone()), "identical must match");

    let mut last_byte = proof.clone();
    *last_byte.last_mut().unwrap() ^= 0x01;
    assert!(
        !proofs_match(&proof, &last_byte),
        "a difference in the final byte must be caught"
    );

    let mut first_byte = proof.clone();
    *first_byte.first_mut().unwrap() ^= 0x01;
    assert!(!proofs_match(&proof, &first_byte), "first-byte difference");

    assert!(
        !proofs_match(&proof, proof.get(..31).unwrap()),
        "a prefix must not match"
    );
    assert!(!proofs_match(&proof, &[]), "the empty proof must not match");
    assert!(
        !proofs_match(&[], &proof),
        "and the empty proof must not be accepted *as* the subject either"
    );
}

#[test]
fn a_hostile_servers_wrong_length_salt_is_refused() {
    use sha2::{Digest as _, Sha256};

    let json = vectors();
    let case = field(&json, &["vectors"])
        .as_array()
        .unwrap()
        .first()
        .expect("a case");

    let group = Group::RFC5054_4096;
    let identity = decode(text(case, "account_id"));
    let srp_salt = decode(text(case, "srp_salt"));
    let srp_x = Secret::<SrpX>::from_derived_bytes(decode(text(case, "srp_x")));
    let x = private_exponent(&srp_salt, &srp_x).unwrap();
    let a = Secret::<SrpEphemeralSecret>::from_derived_bytes(decode(text(case, "a")));
    let b = Secret::<SrpEphemeralSecret>::from_derived_bytes(decode(text(case, "b")));
    let v = verifier(group, &x).unwrap();
    let public_a = client_public(group, &a).unwrap();
    let public_b = server_public::<Sha256Hash>(group, &b, &v).unwrap();
    let premaster = client_premaster::<Sha256Hash>(group, &a, &x, &public_b).unwrap();
    let keys = session_keys(&premaster).unwrap();

    let proof = |salt: &[u8]| {
        client_proof::<Sha256Hash>(
            group,
            &identity,
            salt,
            &public_a,
            &public_b,
            &keys.session_key,
        )
    };

    assert_eq!(
        srp_salt.len(),
        SRP_SALT_LEN,
        "the vector's salt is the fixed width"
    );
    assert!(
        proof(&srp_salt).is_ok(),
        "the correct width must be accepted"
    );

    for wrong in [
        vec![0_u8; SRP_SALT_LEN - 1],
        vec![0_u8; SRP_SALT_LEN + 1],
        Vec::new(),
        vec![0_u8; 1024],
    ] {
        assert_eq!(
            proof(&wrong),
            Err(SrpError::TranscriptFieldLength),
            "a {}-byte srpSalt must be refused",
            wrong.len()
        );
    }

    // Without the length check, a 31-byte salt would hash without complaint.
    let short = vec![0_u8; SRP_SALT_LEN - 1];
    let would_have_been = Sha256::digest(&short);
    assert_eq!(
        would_have_been.len(),
        32,
        "a wrong-length salt hashes without complaint, so the refusal must be explicit"
    );
}

#[test]
fn an_m1_of_the_wrong_width_is_refused() {
    let json = vectors();
    let case = field(&json, &["vectors"])
        .as_array()
        .unwrap()
        .first()
        .expect("a case");

    let group = Group::RFC5054_4096;
    let srp_salt = decode(text(case, "srp_salt"));
    let srp_x = Secret::<SrpX>::from_derived_bytes(decode(text(case, "srp_x")));
    let x = private_exponent(&srp_salt, &srp_x).unwrap();
    let a = Secret::<SrpEphemeralSecret>::from_derived_bytes(decode(text(case, "a")));
    let b = Secret::<SrpEphemeralSecret>::from_derived_bytes(decode(text(case, "b")));
    let v = verifier(group, &x).unwrap();
    let public_a = client_public(group, &a).unwrap();
    let public_b = server_public::<Sha256Hash>(group, &b, &v).unwrap();
    let premaster = client_premaster::<Sha256Hash>(group, &a, &x, &public_b).unwrap();
    let keys = session_keys(&premaster).unwrap();

    let m1 = decode(text(case, "M1"));
    assert!(
        server_proof::<Sha256Hash>(group, &public_a, &m1, &keys.session_key).is_ok(),
        "a genuine M1 must be accepted"
    );

    for wrong in [
        m1.get(..31).unwrap().to_vec(),
        [m1.clone(), vec![0_u8]].concat(),
        Vec::new(),
    ] {
        assert_eq!(
            server_proof::<Sha256Hash>(group, &public_a, &wrong, &keys.session_key),
            Err(SrpError::TranscriptFieldLength),
            "a {}-byte M1 must be refused",
            wrong.len()
        );
    }
}
