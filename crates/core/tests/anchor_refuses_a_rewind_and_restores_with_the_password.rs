#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use chiavora_core::anchor::{restore_from_older_backup, RestoreAcknowledgement, RestoreError};
use chiavora_core::derive::{
    AccountIdentifiers, KdfParams, I4_FLOOR_ITERATIONS, I4_FLOOR_MEMORY_KIB,
};
use chiavora_core::entry::{accept, PasswordField, SecretKeyField};
use chiavora_core::secret::{
    kind::{AccountPassword, SecretKeyMaterial},
    Secret,
};
use chiavora_core::store::{RollbackAnchor, RollbackProtection, StoreError};
use chiavora_core::unlock::UnlockedVault;

const ACCOUNT_ID: &[u8] = b"0123456789abcdef";
const ACCOUNT_SALT: &[u8] = b"0123456789abcdef0123456789abcdef";
const VAULT: &[u8] = b"vault-0000000001";

struct TempDb(std::path::PathBuf);

impl TempDb {
    fn new(tag: &str) -> Self {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "chiavora-anchor-{tag}-{}-{:?}.db",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_file(&path);
        Self(path)
    }
}

impl Drop for TempDb {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// A settable stand-in for a Keystore entry; setting it ahead of the file stages a rewind.
#[derive(Clone, Default)]
struct SharedAnchor(std::sync::Arc<std::sync::Mutex<Option<u64>>>);

impl SharedAnchor {
    fn set(&self, generation: u64) {
        *self.0.lock().expect("anchor lock") = Some(generation);
    }
    fn get(&self) -> Option<u64> {
        *self.0.lock().expect("anchor lock")
    }
}

impl RollbackAnchor for SharedAnchor {
    fn latest(&self) -> Option<u64> {
        self.get()
    }
    fn advance(&mut self, generation: u64) -> Result<(), StoreError> {
        self.set(generation);
        Ok(())
    }
    fn protection(&self) -> RollbackProtection {
        RollbackProtection::Anchored
    }
}

fn password(text: &str) -> Secret<AccountPassword> {
    accept::<PasswordField>(text.as_bytes().to_vec()).expect("a valid password")
}

fn secret_key() -> Secret<SecretKeyMaterial> {
    accept::<SecretKeyField>(b"CHV1-0000-0000-0000-0000-0000-0000-00XV".to_vec())
        .expect("a valid Secret Key")
}

fn ids() -> AccountIdentifiers<'static> {
    AccountIdentifiers {
        account_id: ACCOUNT_ID,
        account_salt: ACCOUNT_SALT,
    }
}

fn params() -> KdfParams {
    KdfParams::new(I4_FLOOR_MEMORY_KIB, I4_FLOOR_ITERATIONS).expect("the I4 floor")
}

fn seed(path: &std::path::Path, anchor: &SharedAnchor, writes: u64) -> u64 {
    let vault = UnlockedVault::from_secrets(
        &password("correct horse battery staple"),
        &secret_key(),
        ids(),
        params(),
    )
    .expect("the derivation");
    let mut store = vault
        .open_store(path, Box::new(anchor.clone()))
        .expect("a fresh store opens");
    for n in 0..writes {
        // The generation moves with the metadata, not with the record.
        store
            .put_raw(VAULT, format!("item-{n:016}").as_bytes(), n, b"payload")
            .expect("a write");
        store
            .set_high_water_mark(VAULT, n + 1)
            .expect("a metadata write");
    }
    store.generation()
}

#[test]
fn an_ordinary_open_refuses_a_file_behind_the_anchor() {
    let db = TempDb::new("refuse");
    let anchor = SharedAnchor::default();
    let generation = seed(&db.0, &anchor, 2);

    anchor.set(generation + 5);

    let vault = UnlockedVault::from_secrets(
        &password("correct horse battery staple"),
        &secret_key(),
        ids(),
        params(),
    )
    .expect("the derivation");
    let refused = vault.open_store(&db.0, Box::new(anchor.clone()));

    match refused {
        Err(StoreError::MetadataRewound { stored, anchor: at }) => {
            assert_eq!(stored, generation);
            assert_eq!(at, generation + 5);
        }
        other => panic!("expected MetadataRewound, got {other:?}"),
    }
    assert_eq!(
        anchor.get(),
        Some(generation + 5),
        "a refused open must not move the anchor"
    );
}

#[test]
fn a_restore_costs_the_password_and_moves_the_anchor_back() {
    let db = TempDb::new("restore");
    let anchor = SharedAnchor::default();
    let generation = seed(&db.0, &anchor, 2);
    anchor.set(generation + 5);

    let vault = restore_from_older_backup(
        &db.0,
        Box::new(anchor.clone()),
        &password("correct horse battery staple"),
        &secret_key(),
        ids(),
        params(),
        RestoreAcknowledgement::confirmed(generation + 5),
    )
    .expect("the restore");

    assert_eq!(vault.muk_len(), 32, "the vault comes back unlocked");
    assert_eq!(
        anchor.get(),
        Some(generation),
        "the anchor is back at the file's generation"
    );

    let reopened = UnlockedVault::from_secrets(
        &password("correct horse battery staple"),
        &secret_key(),
        ids(),
        params(),
    )
    .expect("the derivation")
    .open_store(&db.0, Box::new(anchor.clone()));
    assert!(reopened.is_ok(), "the restored store opens: {reopened:?}");
}

#[test]
fn a_wrong_password_cannot_move_the_anchor_by_one_generation() {
    let db = TempDb::new("wrongpw");
    let anchor = SharedAnchor::default();
    let generation = seed(&db.0, &anchor, 2);
    anchor.set(generation + 5);

    let refused = restore_from_older_backup(
        &db.0,
        Box::new(anchor.clone()),
        &password("not the right password at all"),
        &secret_key(),
        ids(),
        params(),
        RestoreAcknowledgement::confirmed(generation + 5),
    );

    // A wrong password fails as tampering: the metadata does not authenticate under its key.
    match refused {
        Err(RestoreError::Store(StoreError::MetadataTampered)) => {}
        other => panic!("expected MetadataTampered inside RestoreError, got {other:?}"),
    }
    assert_eq!(
        anchor.get(),
        Some(generation + 5),
        "the anchor did not move"
    );
}

#[test]
fn a_confirmation_that_names_the_wrong_generation_is_refused() {
    let db = TempDb::new("stale");
    let anchor = SharedAnchor::default();
    let generation = seed(&db.0, &anchor, 2);
    anchor.set(generation + 5);

    let refused = restore_from_older_backup(
        &db.0,
        Box::new(anchor.clone()),
        &password("correct horse battery staple"),
        &secret_key(),
        ids(),
        params(),
        RestoreAcknowledgement::confirmed(generation + 2),
    );

    match refused {
        Err(RestoreError::AcknowledgementStale { shown, actual }) => {
            assert_eq!(shown, generation + 2);
            assert_eq!(actual, generation + 5);
        }
        other => panic!("expected AcknowledgementStale, got {other:?}"),
    }
    assert_eq!(anchor.get(), Some(generation + 5), "nothing moved");
}

#[test]
fn a_stale_confirmation_is_refused_before_the_derivation_is_paid_for() {
    // Argon2id at the I4 floor takes hundreds of milliseconds, so 50 ms is a loose ceiling.
    let db = TempDb::new("order");
    let anchor = SharedAnchor::default();
    anchor.set(9);

    let started = std::time::Instant::now();
    let refused = restore_from_older_backup(
        &db.0,
        Box::new(anchor.clone()),
        &password("correct horse battery staple"),
        &secret_key(),
        ids(),
        params(),
        RestoreAcknowledgement::confirmed(3),
    );
    let elapsed = started.elapsed();

    assert!(matches!(
        refused,
        Err(RestoreError::AcknowledgementStale { .. })
    ));
    assert!(
        elapsed < std::time::Duration::from_millis(50),
        "the stale check ran after the derivation: {elapsed:?}"
    );
}

#[test]
fn a_device_with_no_anchor_has_nothing_to_restore() {
    let db = TempDb::new("noanchor");
    let anchor = SharedAnchor::default();

    let refused = restore_from_older_backup(
        &db.0,
        Box::new(anchor),
        &password("correct horse battery staple"),
        &secret_key(),
        ids(),
        params(),
        RestoreAcknowledgement::confirmed(0),
    );
    assert!(matches!(refused, Err(RestoreError::NothingAnchored)));
}

#[test]
fn the_store_reports_anchored_when_it_has_a_real_anchor() {
    let db = TempDb::new("reports");
    let anchor = SharedAnchor::default();
    seed(&db.0, &anchor, 1);

    let store = UnlockedVault::from_secrets(
        &password("correct horse battery staple"),
        &secret_key(),
        ids(),
        params(),
    )
    .expect("the derivation")
    .open_store(&db.0, Box::new(anchor))
    .expect("opens");
    assert_eq!(store.rollback_protection(), RollbackProtection::Anchored);
}
