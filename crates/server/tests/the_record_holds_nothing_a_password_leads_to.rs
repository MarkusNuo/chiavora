//! An offline search against `v` itself remains possible, as in any SRP deployment.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use chiavora_core::derive::{
    derive_muk, derive_root_key, derive_srp_x, AccountIdentifiers, KdfParams,
};
use chiavora_core::entry::{accept, PasswordField, SecretKeyField};
use chiavora_core::srp::{private_exponent, verifier, Group, SRP_SALT_LEN, SRP_VERIFIER_LEN};
use chiavora_server::auth::{AuthRecord, AuthRecordError};

const ACCOUNT_ID: [u8; 16] = [0x5A; 16];
const ACCOUNT_SALT: [u8; 32] = [0x6B; 32];

const SECRET_KEY: &str = "CHV1-000G-40R4-0M30-E209-185G-R38E-1WCH";

struct Fixture {
    record: AuthRecord,
    needles: Vec<(&'static str, Vec<u8>)>,
}

fn fixture() -> Fixture {
    // Through the real entry points; these two brands have no other public constructor.
    let password = accept::<PasswordField>(b"correct horse battery staple".to_vec()).unwrap();
    let secret_key = accept::<SecretKeyField>(SECRET_KEY.as_bytes().to_vec()).unwrap();
    let params = KdfParams::new(64 * 1024, 3).unwrap();
    let ids = AccountIdentifiers {
        account_id: &ACCOUNT_ID,
        account_salt: &ACCOUNT_SALT,
    };

    let root_key = derive_root_key(&password, &secret_key, ids, params).unwrap();
    let muk = derive_muk(&root_key).unwrap();
    let srp_x = derive_srp_x(&root_key).unwrap();

    let srp_salt = vec![0x7D_u8; SRP_SALT_LEN];
    let exponent = private_exponent(&srp_salt, &srp_x).unwrap();
    let v = verifier(Group::RFC5054_4096, &exponent).unwrap();

    let mut verifier_bytes = vec![0_u8; SRP_VERIFIER_LEN];
    let be = v.to_be_bytes();
    let start = verifier_bytes.len().saturating_sub(be.len());
    for (slot, byte) in verifier_bytes.iter_mut().skip(start).zip(be.iter()) {
        *slot = *byte;
    }

    let record = AuthRecord::new(&ACCOUNT_ID, &srp_salt, &verifier_bytes).unwrap();

    Fixture {
        record,
        needles: vec![
            ("the password", b"correct horse battery staple".to_vec()),
            ("the Secret Key", secret_key.expose().to_vec()),
            ("rootKey", root_key.expose().to_vec()),
            ("the MUK", muk.expose().to_vec()),
            ("srpX", srp_x.expose().to_vec()),
            ("x", exponent.expose().to_vec()),
        ],
    }
}

#[test]
fn the_stored_bytes_contain_no_password_and_nothing_it_derives_to() {
    let fixture = fixture();
    let stored = fixture.record.to_stored_bytes();

    let mut found: Vec<&str> = Vec::new();
    for (name, needle) in &fixture.needles {
        assert!(
            !needle.is_empty(),
            "{name} is empty, so searching for it proves nothing"
        );
        if stored
            .windows(needle.len())
            .any(|window| window == needle.as_slice())
        {
            found.push(name);
        }
    }

    assert!(
        found.is_empty(),
        "the server's authentication record contains {found:?}"
    );
}

#[test]
fn the_search_would_notice_x_in_the_record() {
    let fixture = fixture();
    let (_, x) = fixture
        .needles
        .iter()
        .find(|(name, _)| *name == "x")
        .expect("x is one of the needles");

    // `x` stored where `v` belongs, padded like a real verifier.
    let mut wrong = vec![0_u8; SRP_VERIFIER_LEN];
    let start = wrong.len() - x.len();
    for (slot, byte) in wrong.iter_mut().skip(start).zip(x.iter()) {
        *slot = *byte;
    }

    let planted = AuthRecord::new(&ACCOUNT_ID, &[0x7D; SRP_SALT_LEN], &wrong).unwrap();
    let stored = planted.to_stored_bytes();

    assert!(
        stored.windows(x.len()).any(|window| window == x.as_slice()),
        "the search must find `x` when it is present"
    );
}

#[test]
fn a_field_of_the_wrong_width_is_refused_and_the_error_names_which() {
    let ok_salt = [0x7D_u8; SRP_SALT_LEN];
    let ok_v = [0x11_u8; SRP_VERIFIER_LEN];

    assert_eq!(
        AuthRecord::new(&[0_u8; 15], &ok_salt, &ok_v).unwrap_err(),
        AuthRecordError::AccountIdLength
    );
    assert_eq!(
        AuthRecord::new(&ACCOUNT_ID, &[0_u8; SRP_SALT_LEN - 1], &ok_v).unwrap_err(),
        AuthRecordError::SaltLength
    );
    assert_eq!(
        AuthRecord::new(&ACCOUNT_ID, &ok_salt, &[0_u8; SRP_VERIFIER_LEN - 1]).unwrap_err(),
        AuthRecordError::VerifierLength
    );
    assert_eq!(
        AuthRecord::new(&ACCOUNT_ID, &ok_salt, &[0_u8; SRP_VERIFIER_LEN + 1]).unwrap_err(),
        AuthRecordError::VerifierLength
    );
    assert!(AuthRecord::new(&ACCOUNT_ID, &ok_salt, &ok_v).is_ok());

    let distinct = [
        AuthRecordError::AccountIdLength,
        AuthRecordError::SaltLength,
        AuthRecordError::VerifierLength,
    ];
    for (index, left) in distinct.iter().enumerate() {
        for right in distinct.iter().skip(index + 1) {
            assert_ne!(left, right, "the variants must be distinguishable");
        }
    }
}

#[test]
fn the_stored_form_is_the_three_fields_and_no_more() {
    let fixture = fixture();
    let stored = fixture.record.to_stored_bytes();

    assert_eq!(
        stored.len(),
        16 + SRP_SALT_LEN + SRP_VERIFIER_LEN,
        "the stored form must be exactly the three fixed-width fields"
    );
    assert_eq!(
        stored.get(..16).unwrap(),
        fixture.record.account_id(),
        "accountId first"
    );
    assert_eq!(
        stored.get(16..16 + SRP_SALT_LEN).unwrap(),
        fixture.record.srp_salt(),
        "then srpSalt"
    );
    assert_eq!(
        stored.get(16 + SRP_SALT_LEN..).unwrap(),
        fixture.record.verifier(),
        "then the verifier"
    );
}
