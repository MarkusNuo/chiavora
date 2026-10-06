#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use chiavora_core::secret::{
    kind::{SrpEphemeralSecret, SrpX},
    Secret,
};
use chiavora_core::srp::{
    client_premaster, client_proof, client_public, generate_ephemeral, private_exponent,
    proofs_match, scrambler, server_premaster, server_public, session_keys, verifier, Group,
    Sha256Hash, SrpError,
};
use crypto_bigint::{BoxedUint, NonZero, Resize as _};

const GROUP: Group = Group::RFC5054_4096;

fn modulus() -> BoxedUint {
    let hex = serde_json::from_str::<serde_json::Value>(include_str!("vectors/srp_groups.json"))
        .unwrap()
        .get("groups")
        .and_then(|g| g.get("4096"))
        .and_then(|g| g.get("N"))
        .and_then(|n| n.as_str())
        .expect("the published 4096-bit modulus")
        .to_owned();
    Option::from(BoxedUint::from_be_hex(&hex, 4096)).expect("valid hex")
}

struct Account {
    exponent: Secret<chiavora_core::secret::kind::SrpExponent>,
    verifier: BoxedUint,
    srp_salt: Vec<u8>,
}

fn account() -> Account {
    let srp_salt = vec![0x11_u8; 32];
    let srp_x = Secret::<SrpX>::from_derived_bytes(vec![0x22_u8; 32]);
    let exponent = private_exponent(&srp_salt, &srp_x).unwrap();
    let verifier = verifier(GROUP, &exponent).unwrap();
    Account {
        exponent,
        verifier,
        srp_salt,
    }
}

fn ephemeral(byte: u8) -> Secret<SrpEphemeralSecret> {
    Secret::<SrpEphemeralSecret>::from_derived_bytes(vec![byte; 32])
}

#[test]
fn a_zero_mod_n_is_refused_and_would_otherwise_hand_the_attacker_s() {
    let account = account();
    let b = ephemeral(0x33);
    let n = modulus();

    for hostile in [BoxedUint::zero_with_precision(4096), n.clone()] {
        // `Secret` has no `PartialEq`, so only the error is compared.
        assert_eq!(
            server_premaster::<Sha256Hash>(GROUP, &b, &account.verifier, &hostile).unwrap_err(),
            SrpError::PublicValueOutOfRange,
            "A ≡ 0 mod N must be refused"
        );
    }

    // What `server_premaster` would compute without the check.
    let nonzero = Option::<NonZero<BoxedUint>>::from(NonZero::new(n.clone())).unwrap();
    let server_public = server_public::<Sha256Hash>(GROUP, &b, &account.verifier).unwrap();
    let zero = BoxedUint::zero_with_precision(4096);
    let u = scrambler::<Sha256Hash>(GROUP, &zero, &server_public).unwrap();
    let v_to_u = {
        // v^u mod N by plain square-and-multiply, not the module's own arithmetic.
        let mut acc = BoxedUint::one_with_precision(4096);
        let mut base = account.verifier.clone();
        for bit in 0..u.bits_precision() {
            if bool::from(u.bit(bit)) {
                acc = acc.mul_mod(&base, &nonzero);
            }
            base = base.mul_mod(&base.clone(), &nonzero);
        }
        acc
    };
    let base = zero.mul_mod(&v_to_u, &nonzero);
    assert!(
        bool::from(base.is_zero()),
        "A · v^u must be zero when A is zero; if this ever fails the witness \
         below is checking something else"
    );
    // 0^b is 0 for every b > 0.
    assert!(
        bool::from(base.is_zero()),
        "with the refusal removed, S = 0 for every account and every b: the \
         attacker knows the session key without knowing the password"
    );
}

#[test]
fn b_zero_mod_n_is_refused_though_the_witness_is_weaker_than_for_a() {
    let account = account();
    let a = ephemeral(0x44);
    let n = modulus();

    for hostile in [BoxedUint::zero_with_precision(4096), n] {
        assert_eq!(
            client_premaster::<Sha256Hash>(GROUP, &a, &account.exponent, &hostile).unwrap_err(),
            SrpError::PublicValueOutOfRange,
            "B ≡ 0 mod N must be refused"
        );
    }
}

#[test]
fn a_public_value_that_is_a_multiple_of_n_is_refused() {
    let account = account();
    let a = ephemeral(0x55);
    let b = ephemeral(0x66);
    let n = modulus();

    let two_n = {
        // `try_resize`, because `resize` panics and the workspace denies `panic`.
        let room = n.bits_precision() + 64;
        let wide = n.clone().try_resize(room).expect("widening");
        let doubled = wide.clone();
        wide.wrapping_add(&doubled)
    };

    assert!(
        !bool::from(n.is_zero()) && !bool::from(two_n.is_zero()),
        "N and 2N are not literally zero, which is the whole reason a `!= 0` \
         check would let them through"
    );

    assert_eq!(
        client_premaster::<Sha256Hash>(GROUP, &a, &account.exponent, &two_n).unwrap_err(),
        SrpError::PublicValueOutOfRange,
        "B = 2N must be refused by the client"
    );
    assert_eq!(
        server_premaster::<Sha256Hash>(GROUP, &b, &account.verifier, &two_n).unwrap_err(),
        SrpError::PublicValueOutOfRange,
        "A = 2N must be refused by the server"
    );
}

#[test]
fn a_replayed_proof_fails_against_a_fresh_b_and_succeeds_against_a_reused_one() {
    let account = account();
    let identity = vec![0x77_u8; 16];
    let a = ephemeral(0x88);

    let proof_for = |b: &Secret<SrpEphemeralSecret>| {
        let public_a = client_public(GROUP, &a).unwrap();
        let public_b = server_public::<Sha256Hash>(GROUP, b, &account.verifier).unwrap();
        let premaster =
            client_premaster::<Sha256Hash>(GROUP, &a, &account.exponent, &public_b).unwrap();
        let keys = session_keys(&premaster).unwrap();
        client_proof::<Sha256Hash>(
            GROUP,
            &identity,
            &account.srp_salt,
            &public_a,
            &public_b,
            &keys.session_key,
        )
        .unwrap()
    };

    let first = generate_ephemeral().unwrap();
    let second = generate_ephemeral().unwrap();
    assert_ne!(
        first.expose(),
        second.expose(),
        "two draws from the CSPRNG must differ; if they do not, nothing below \
         means anything"
    );

    let earlier = proof_for(&first);
    let now = proof_for(&second);

    assert!(
        !proofs_match(&earlier, &now),
        "a proof from an earlier exchange must not verify against a fresh b"
    );

    // Reuse `b` and the replay works: this is what `crates/server` must prevent.
    let reused = proof_for(&first);
    assert!(
        proofs_match(&earlier, &reused),
        "with b reused, the earlier proof verifies exactly. This test passing \
         is the point: it is the statement of what crates/server must not do, \
         and if it ever stops holding then replay resistance rests on something \
         other than b's freshness and reasoning needs redoing"
    );
}

#[test]
fn generate_ephemeral_returns_a_different_value_each_time() {
    let draws: Vec<Vec<u8>> = (0..8)
        .map(|_| generate_ephemeral().unwrap().expose().to_vec())
        .collect();

    assert!(
        draws.iter().all(|d| d.len() == 32),
        "an ephemeral is 32 bytes, comfortably above RFC 5054 §2.5.1's 256-bit \
         floor"
    );
    assert!(
        draws.iter().all(|d| d.iter().any(|byte| *byte != 0)),
        "a draw of zeros would make B = k*v, the same for every login"
    );

    let mut unique = draws.clone();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(
        unique.len(),
        draws.len(),
        "eight draws produced a repeat, which from a 256-bit space means the \
         CSPRNG is not one"
    );
}
