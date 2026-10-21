#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use chiavora_core::entry::{accept, PasswordField, SecretKeyField};
use chiavora_core::srp::{
    client_premaster, client_proof, client_public, private_exponent, proofs_match, session_keys,
    verifier as compute_verifier, Group, Sha256Hash, SrpError, SRP_SALT_LEN, SRP_VERIFIER_LEN,
};
use chiavora_server::auth::{AuthRecord, AuthRecordError, PendingExchange};
use crypto_bigint::BoxedUint;

const ACCOUNT_ID: [u8; 16] = [0x5A; 16];
const ACCOUNT_SALT: [u8; 32] = [0x6B; 32];
const SRP_SALT: [u8; SRP_SALT_LEN] = [0x7D; SRP_SALT_LEN];
const SECRET_KEY: &str = "CHV1-000G-40R4-0M30-E209-185G-R38E-1WCH";

fn fixed(value: &BoxedUint) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let mut out = vec![0_u8; SRP_VERIFIER_LEN];
    let start = out.len().saturating_sub(bytes.len());
    for (slot, byte) in out.iter_mut().skip(start).zip(bytes.iter()) {
        *slot = *byte;
    }
    out
}

struct Client {
    record: AuthRecord,
    exponent: chiavora_core::secret::Secret<chiavora_core::secret::kind::SrpExponent>,
}

fn account() -> Client {
    let password = accept::<PasswordField>(b"correct horse battery staple".to_vec()).unwrap();
    let secret_key = accept::<SecretKeyField>(SECRET_KEY.as_bytes().to_vec()).unwrap();
    let params = chiavora_core::derive::KdfParams::new(64 * 1024, 3).unwrap();
    let ids = chiavora_core::derive::AccountIdentifiers {
        account_id: &ACCOUNT_ID,
        account_salt: &ACCOUNT_SALT,
    };
    let root_key =
        chiavora_core::derive::derive_root_key(&password, &secret_key, ids, params).unwrap();
    let srp_x = chiavora_core::derive::derive_srp_x(&root_key).unwrap();
    let exponent = private_exponent(&SRP_SALT, &srp_x).unwrap();
    let v = compute_verifier(Group::RFC5054_4096, &exponent).unwrap();
    Client {
        record: AuthRecord::new(&ACCOUNT_ID, &SRP_SALT, &fixed(&v)).unwrap(),
        exponent,
    }
}

#[test]
fn an_honest_login_verifies_and_both_sides_agree_on_the_keys() {
    let client = account();
    let a = chiavora_core::srp::generate_ephemeral().unwrap();
    let a_pub = client_public(Group::RFC5054_4096, &a).unwrap();

    let exchange = PendingExchange::begin(&client.record, &fixed(&a_pub)).unwrap();
    let b_pub = BoxedUint::from_be_slice(exchange.server_public(), 4096).unwrap();

    let premaster =
        client_premaster::<Sha256Hash>(Group::RFC5054_4096, &a, &client.exponent, &b_pub).unwrap();
    let keys = session_keys(&premaster).unwrap();
    let m1 = client_proof::<Sha256Hash>(
        Group::RFC5054_4096,
        &ACCOUNT_ID,
        &SRP_SALT,
        &a_pub,
        &b_pub,
        &keys.session_key,
    )
    .unwrap();

    let finished = exchange.finish(&m1).unwrap();

    assert_eq!(
        finished.keys.session_key.expose(),
        keys.session_key.expose(),
        "both sides must reach the same K"
    );
    assert_eq!(
        finished.keys.mac_client_to_server.expose(),
        keys.mac_client_to_server.expose(),
        "and the same client-to-server MAC key"
    );
    assert_ne!(
        finished.keys.mac_client_to_server.expose(),
        finished.keys.mac_server_to_client.expose(),
        "and the two directions must still differ"
    );

    let m2 = chiavora_core::srp::server_proof::<Sha256Hash>(
        Group::RFC5054_4096,
        &a_pub,
        &m1,
        &keys.session_key,
    )
    .unwrap();
    assert!(
        proofs_match(&finished.server_proof, &m2),
        "the client must be able to verify M2"
    );
}

#[test]
fn two_exchanges_for_one_account_do_not_share_a_b() {
    let client = account();
    let a = chiavora_core::srp::generate_ephemeral().unwrap();
    let a_pub = fixed(&client_public(Group::RFC5054_4096, &a).unwrap());

    let first = PendingExchange::begin(&client.record, &a_pub).unwrap();
    let second = PendingExchange::begin(&client.record, &a_pub).unwrap();

    assert_ne!(
        first.server_public(),
        second.server_public(),
        "two exchanges produced the same B, which means the same b"
    );
}

#[test]
fn a_proof_from_another_exchange_is_refused() {
    let client = account();
    let a = chiavora_core::srp::generate_ephemeral().unwrap();
    let a_pub_uint = client_public(Group::RFC5054_4096, &a).unwrap();
    let a_pub = fixed(&a_pub_uint);

    let proof_for = |exchange: &PendingExchange| {
        let b_pub = BoxedUint::from_be_slice(exchange.server_public(), 4096).unwrap();
        let premaster =
            client_premaster::<Sha256Hash>(Group::RFC5054_4096, &a, &client.exponent, &b_pub)
                .unwrap();
        let keys = session_keys(&premaster).unwrap();
        client_proof::<Sha256Hash>(
            Group::RFC5054_4096,
            &ACCOUNT_ID,
            &SRP_SALT,
            &a_pub_uint,
            &b_pub,
            &keys.session_key,
        )
        .unwrap()
    };

    let earlier = PendingExchange::begin(&client.record, &a_pub).unwrap();
    let stale = proof_for(&earlier);

    let current = PendingExchange::begin(&client.record, &a_pub).unwrap();
    assert_eq!(
        current.finish(&stale).unwrap_err(),
        AuthRecordError::Srp(SrpError::ProofMismatch),
        "a proof computed against an earlier B must not verify against a fresh one"
    );
}

#[test]
fn a_wrong_proof_is_refused_with_the_same_variant_a_replay_gets() {
    let client = account();
    let a = chiavora_core::srp::generate_ephemeral().unwrap();
    let a_pub = fixed(&client_public(Group::RFC5054_4096, &a).unwrap());

    let exchange = PendingExchange::begin(&client.record, &a_pub).unwrap();
    let nonsense = vec![0xAB_u8; 32];

    assert_eq!(
        exchange.finish(&nonsense).unwrap_err(),
        AuthRecordError::Srp(SrpError::ProofMismatch),
        "a wrong proof is refused with the same variant a replayed one gets"
    );
}

#[test]
fn a_zero_a_and_a_wrong_width_a_are_both_refused_at_the_door() {
    let client = account();

    let zero = vec![0_u8; SRP_VERIFIER_LEN];
    assert_eq!(
        PendingExchange::begin(&client.record, &zero).unwrap_err(),
        AuthRecordError::Srp(SrpError::PublicValueOutOfRange),
        "A ≡ 0 mod N must be refused before any key exists"
    );

    for wrong in [SRP_VERIFIER_LEN - 1, SRP_VERIFIER_LEN + 1, 0] {
        assert_eq!(
            PendingExchange::begin(&client.record, &vec![1_u8; wrong]).unwrap_err(),
            AuthRecordError::ClientPublicLength,
            "a {wrong}-byte A must be refused"
        );
    }
}
