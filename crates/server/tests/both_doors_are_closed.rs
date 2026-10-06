//! Known and unknown identifiers are indistinguishable in content, size, stability and work done.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use chiavora_core::srp::{
    client_premaster, client_proof, client_public, fake_credentials, generate_ephemeral,
    private_exponent, Group, Sha256Hash, SrpError, SRP_SALT_LEN, SRP_SEED_KEY_LEN,
    SRP_VERIFIER_LEN,
};
use chiavora_server::auth::{AuthRecordError, PendingExchange};
use chiavora_server::preauth::{resolve_credentials, Op, SeedKey};
use crypto_bigint::BoxedUint;

const SEED: [u8; SRP_SEED_KEY_LEN] = [0x4E; SRP_SEED_KEY_LEN];

type Exponent = chiavora_core::secret::Secret<chiavora_core::secret::kind::SrpExponent>;

/// The same length, so their traces compare like with like.
const KNOWN: &[u8] = b"ada@example.com";
const UNKNOWN: &[u8] = b"bob@example.com";

fn seed() -> SeedKey {
    SeedKey::new(SEED.to_vec()).unwrap()
}

struct Account {
    id: Vec<u8>,
    srp_salt: Vec<u8>,
    verifier: Vec<u8>,
    exponent: Exponent,
}

fn known_account() -> Account {
    let password =
        chiavora_core::entry::accept::<chiavora_core::entry::PasswordField>(b"hunter22".to_vec())
            .unwrap();
    let secret_key = chiavora_core::entry::accept::<chiavora_core::entry::SecretKeyField>(
        b"CHV1-000G-40R4-0M30-E209-185G-R38E-1WCH".to_vec(),
    )
    .unwrap();
    let account_id = vec![0x5A_u8; 16];
    let account_salt = vec![0x6B_u8; 32];
    let params = chiavora_core::derive::KdfParams::new(64 * 1024, 3).unwrap();
    let ids = chiavora_core::derive::AccountIdentifiers {
        account_id: &account_id,
        account_salt: &account_salt,
    };
    let root = chiavora_core::derive::derive_root_key(&password, &secret_key, ids, params).unwrap();
    let srp_x = chiavora_core::derive::derive_srp_x(&root).unwrap();
    let srp_salt = vec![0x7D_u8; SRP_SALT_LEN];
    let exponent = private_exponent(&srp_salt, &srp_x).unwrap();
    let v = chiavora_core::srp::verifier(Group::RFC5054_4096, &exponent).unwrap();

    let mut verifier = vec![0_u8; SRP_VERIFIER_LEN];
    let be = v.to_be_bytes();
    let start = verifier.len().saturating_sub(be.len());
    for (slot, byte) in verifier.iter_mut().skip(start).zip(be.iter()) {
        *slot = *byte;
    }

    Account {
        id: account_id,
        srp_salt,
        verifier,
        exponent,
    }
}

#[test]
fn the_known_and_unknown_paths_produce_an_identical_operation_trace() {
    let account = known_account();
    let seed = seed();

    let (_, known_trace) = resolve_credentials(
        &seed,
        KNOWN,
        Some((&account.id, &account.srp_salt, &account.verifier)),
    )
    .unwrap();
    let (_, unknown_trace) = resolve_credentials(&seed, UNKNOWN, None).unwrap();

    assert_eq!(
        known_trace, unknown_trace,
        "the two paths performed different work. timing dimension is \
         established by this being equal and by nothing else: a stopwatch was \
         refused because it would be green for reasons unrelated to the \
         property"
    );

    assert!(
        known_trace.len() >= 4,
        "a trace of {} entries is not evidence that two paths did the same \
         work; it is evidence that they both did almost nothing observable",
        known_trace.len()
    );
    assert!(
        known_trace
            .iter()
            .any(|op| matches!(op, Op::Fabricated { .. })),
        "the known path must also fabricate. If it stops, the unknown path \
         becomes the slower one and the oracle points the wrong way round"
    );
}

#[test]
fn the_trace_would_notice_a_difference() {
    let a = Op::Fabricated {
        seed_len: 32,
        identifier_len: 15,
    };
    let b = Op::Fabricated {
        seed_len: 32,
        identifier_len: 16,
    };
    assert_ne!(
        a, b,
        "two fabrications over different input lengths must not compare equal; \
         `Op` carries lengths precisely so that `the same operations` and `the \
         same operations on the same shapes` are different claims"
    );
    assert_ne!(
        Op::LookedUp { identifier_len: 15 },
        Op::BuiltRecord { account_id_len: 15 },
        "two different operations with the same number in them must not compare \
         equal"
    );

    let seed = seed();
    let (_, short) = resolve_credentials(&seed, b"a@b.c", None).unwrap();
    let (_, long) = resolve_credentials(&seed, b"much-longer@example.com", None).unwrap();
    assert_ne!(
        short, long,
        "the trace must distinguish inputs that genuinely differ, or it would \
         compare equal for everything and the test above would prove nothing"
    );
}

#[test]
fn a_known_and_an_unknown_identifier_yield_records_of_identical_shape() {
    let account = known_account();
    let seed = seed();

    let (real, _) = resolve_credentials(
        &seed,
        KNOWN,
        Some((&account.id, &account.srp_salt, &account.verifier)),
    )
    .unwrap();
    let (fabricated, _) = resolve_credentials(&seed, UNKNOWN, None).unwrap();

    assert_eq!(
        real.to_stored_bytes().len(),
        fabricated.to_stored_bytes().len(),
        "byte-length parity is size dimension, asserted mechanically"
    );
    assert_eq!(real.account_id().len(), fabricated.account_id().len());
    assert_eq!(real.srp_salt().len(), fabricated.srp_salt().len());
    assert_eq!(real.verifier().len(), fabricated.verifier().len());

    assert_ne!(real.srp_salt(), fabricated.srp_salt());
    assert_ne!(real.verifier(), fabricated.verifier());

    assert_eq!(real.srp_salt(), account.srp_salt.as_slice());
    assert_eq!(real.verifier(), account.verifier.as_slice());
    assert_eq!(real.account_id(), account.id.as_slice());
}

#[test]
fn the_fabricated_answer_is_stable_per_identifier_and_differs_between_them() {
    let seed = seed();

    let (first, _) = resolve_credentials(&seed, UNKNOWN, None).unwrap();
    let (second, _) = resolve_credentials(&seed, UNKNOWN, None).unwrap();
    assert_eq!(
        first.to_stored_bytes(),
        second.to_stored_bytes(),
        "two probes for the same unknown identifier must get the same answer; \
         a server that answered differently each time would be announcing that \
         it is fabricating"
    );

    let (other, _) = resolve_credentials(&seed, b"eve@example.com", None).unwrap();
    assert_ne!(
        first.to_stored_bytes(),
        other.to_stored_bytes(),
        "and two different unknown identifiers must not share an answer"
    );

    let other_seed = SeedKey::new(vec![0x9F; SRP_SEED_KEY_LEN]).unwrap();
    let (elsewhere, _) = resolve_credentials(&other_seed, UNKNOWN, None).unwrap();
    assert_ne!(
        first.to_stored_bytes(),
        elsewhere.to_stored_bytes(),
        "two deployments must not fabricate the same account"
    );
}

#[test]
fn the_fabricated_account_id_is_not_a_prefix_of_anything_transmitted() {
    let fake = fake_credentials(Group::RFC5054_4096, &SEED, UNKNOWN).unwrap();

    assert_eq!(fake.account_id.len(), 16, ": ACCOUNT_ID_LEN");
    assert!(
        !fake
            .verifier
            .windows(fake.account_id.len())
            .any(|w| w == fake.account_id.as_slice()),
        "the fabricated accountId appears inside the verifier. forbids \
         deriving it from x' precisely so that nothing transmitted carries it"
    );
    assert!(
        !fake
            .srp_salt
            .windows(fake.account_id.len())
            .any(|w| w == fake.account_id.as_slice()),
        "and it must not appear in the salt either, which is served openly"
    );
}

#[test]
fn an_unknown_identifier_gets_an_exchange_and_fails_the_way_a_wrong_password_does() {
    let account = known_account();
    let seed = seed();

    let attempt =
        |identifier: &[u8], stored: Option<(&[u8], &[u8], &[u8])>, exponent: &Exponent| {
            let (record, _) = resolve_credentials(&seed, identifier, stored).unwrap();
            let a = generate_ephemeral().unwrap();
            let a_pub = client_public(Group::RFC5054_4096, &a).unwrap();
            let mut a_bytes = vec![0_u8; SRP_VERIFIER_LEN];
            let be = a_pub.to_be_bytes();
            let start = a_bytes.len().saturating_sub(be.len());
            for (slot, byte) in a_bytes.iter_mut().skip(start).zip(be.iter()) {
                *slot = *byte;
            }

            let exchange = PendingExchange::begin(&record, &a_bytes).unwrap();
            let b_pub = BoxedUint::from_be_slice(exchange.server_public(), 4096).unwrap();

            let premaster =
                client_premaster::<Sha256Hash>(Group::RFC5054_4096, &a, exponent, &b_pub).unwrap();
            let keys = chiavora_core::srp::session_keys(&premaster).unwrap();
            let m1 = client_proof::<Sha256Hash>(
                Group::RFC5054_4096,
                record.account_id(),
                record.srp_salt(),
                &a_pub,
                &b_pub,
                &keys.session_key,
            )
            .unwrap();
            exchange.finish(&m1)
        };

    let stored = Some((
        account.id.as_slice(),
        account.srp_salt.as_slice(),
        account.verifier.as_slice(),
    ));

    assert_eq!(
        attempt(UNKNOWN, None, &account.exponent).unwrap_err(),
        AuthRecordError::Srp(SrpError::ProofMismatch),
        "an unknown identifier must reach proof verification and fail there. A \
         refusal that said `no such account` would undo the endpoint one round \
         trip later, which is the door §3.4 found"
    );

    let wrong_x =
        chiavora_core::secret::Secret::<chiavora_core::secret::kind::SrpX>::from_derived_bytes(
            vec![0xEE; 32],
        );
    let wrong_exponent = private_exponent(&account.srp_salt, &wrong_x).unwrap();
    assert_eq!(
        attempt(KNOWN, stored, &wrong_exponent).unwrap_err(),
        AuthRecordError::Srp(SrpError::ProofMismatch),
        "and a wrong password must fail identically; two distinguishable \
         failures are the oracle in a different costume"
    );

    // The positive control: a server that refused everybody would pass the above.
    assert!(
        attempt(KNOWN, stored, &account.exponent).is_ok(),
        "the right password on a real account must still succeed"
    );
}

#[test]
fn the_fabrication_is_not_inside_a_branch() {
    let source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/preauth.rs"),
    )
    .expect("preauth.rs");

    let body = source
        .split("pub fn resolve_credentials")
        .nth(1)
        .expect("resolve_credentials exists");
    let before_fabrication = body
        .split("fake_credentials(")
        .next()
        .expect("it calls fake_credentials");

    let code: String = before_fabrication
        .lines()
        .map(|line| line.split("//").next().unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n");

    for keyword in ["if ", "match ", "else"] {
        assert!(
            !code.contains(keyword),
            "`{keyword}` appears before the call to `fake_credentials`. \
             timing claim is that the unknown path does the same work as the \
             known one, and it rests on that call being unconditional: a \
             version that fabricated only on a lookup miss would make the \
             unknown path slower, which is the oracle pointing the wrong way \
             round and looks like an optimisation in review"
        );
    }

    // An empty split would contain no keyword and pass.
    assert!(
        code.contains("resolve_credentials") || code.len() > 200,
        "the scan read {} characters of function body; it is passing over \
         nothing",
        code.len()
    );
}

#[test]
fn the_branch_scan_would_notice_one() {
    let sees = |body: &str| -> bool {
        let before = body.split("fake_credentials(").next().unwrap_or("");
        let code: String = before
            .lines()
            .map(|line| line.split("//").next().unwrap_or(""))
            .collect::<Vec<_>>()
            .join("\n");
        ["if ", "match ", "else"]
            .iter()
            .any(|keyword| code.contains(keyword))
    };

    assert!(
        sees("let x = 1;\nif stored.is_none() {\n let f = fake_credentials(a, b, c)?;\n}"),
        "a fabrication inside an `if` must be caught"
    );
    assert!(
        !sees("let x = 1;\nlet f = fake_credentials(a, b, c)?;\nif stored.is_some() { }"),
        "a branch *after* the fabrication must not be caught; selection is \
         allowed and is what the constant-time select is for"
    );
    assert!(
        !sees("// if this were inside an if, the scan would fire\nlet f = fake_credentials(a, b, c)?;"),
        "a comment mentioning `if` must not fire it"
    );
}

#[test]
fn a_seed_key_of_the_wrong_width_is_refused() {
    assert!(SeedKey::new(vec![0; SRP_SEED_KEY_LEN]).is_ok());

    for wrong in [0, 1, SRP_SEED_KEY_LEN - 1, SRP_SEED_KEY_LEN + 1, 64] {
        assert_eq!(
            SeedKey::new(vec![0; wrong]).unwrap_err(),
            AuthRecordError::SeedKeyLength,
            "a {wrong}-byte seed key must be refused"
        );
    }

    let weak = SeedKey::new(vec![0; SRP_SEED_KEY_LEN]).unwrap();
    let (one, _) = resolve_credentials(&weak, b"a@example.com", None).unwrap();
    let (two, _) = resolve_credentials(&weak, b"b@example.com", None).unwrap();
    assert_ne!(
        one.to_stored_bytes(),
        two.to_stored_bytes(),
        "even a weak seed must give different identifiers different answers; if \
         it did not, the identifier is not reaching the HMAC"
    );
}

#[test]
fn the_seed_key_does_not_print_itself() {
    let seed = SeedKey::new(vec![0xC3; SRP_SEED_KEY_LEN]).unwrap();
    let rendered = format!("{seed:?}");
    assert!(
        !rendered.contains("c3") && !rendered.contains("C3") && !rendered.contains("195"),
        "SeedKey's Debug printed its bytes: {rendered}"
    );
    assert!(
        rendered.contains("redacted"),
        "and it must say that it is redacted rather than printing nothing, so a \
         reader of a log knows a value was withheld: {rendered}"
    );
}
