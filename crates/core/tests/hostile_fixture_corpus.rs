#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::fs;
use std::path::{Path, PathBuf};

use chiavora_core::aad::{encode, AadFields, WRAP_PURPOSE_VAULT};
use chiavora_core::derive::KdfParams;
use chiavora_core::item::{open, seal};
use chiavora_core::nonce::FreshNonce;
use chiavora_core::secret::{
    kind::{AutofillKey, ItemKey, VaultKey},
    Secret,
};
use chiavora_core::wrap::{VaultAndAutofill, VaultOnly, WrapContext};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Fixture {
    attacks: String,
    why: String,
    expect: String,
    kind: String,
    #[serde(default)]
    mutation: Option<String>,
    #[serde(default)]
    seal_as: Option<Binding>,
    #[serde(default)]
    open_as: Option<Binding>,
    #[serde(default)]
    plaintext: Option<String>,
    #[serde(default)]
    item: Option<ItemRef>,
    #[serde(default)]
    memory_kib: Option<u32>,
    #[serde(default)]
    iterations: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct Binding {
    vault_id: String,
    item_id: String,
    version: u64,
    content_type: String,
}

#[derive(Debug, Deserialize)]
struct ItemRef {
    vault_id: String,
    item_id: String,
}

impl Binding {
    fn fields(&self) -> AadFields {
        AadFields::ItemPayload {
            vault_id: self.vault_id.clone().into_bytes(),
            item_id: self.item_id.clone().into_bytes(),
            version: self.version,
            content_type: self.content_type.clone().into_bytes(),
        }
    }
}

enum Outcome {
    Refused(String),
    Accepted,
}

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/hostile")
}

fn item_key(fill: u8) -> Secret<ItemKey> {
    Secret::from_derived_bytes(vec![fill; 32])
}

fn apply_item_payload(f: &Fixture) -> Outcome {
    let seal_as = f
        .seal_as
        .as_ref()
        .expect("item-payload fixture needs seal_as");
    let open_as = f
        .open_as
        .as_ref()
        .expect("item-payload fixture needs open_as");
    let plaintext = f.plaintext.clone().unwrap_or_default();

    let key = item_key(0xAB);
    let sealed = seal(
        &key,
        FreshNonce::generate().expect("CSPRNG"),
        &seal_as.fields(),
        plaintext.as_bytes(),
    )
    .expect("sealing under a canonical binding must succeed");

    match open(&key, &sealed, &open_as.fields()) {
        Ok(_) => Outcome::Accepted,
        Err(e) => Outcome::Refused(e.to_string()),
    }
}

fn apply_wrapped_key(f: &Fixture) -> Outcome {
    let item = f.item.as_ref().expect("wrapped-key fixture needs item");
    let mutation = f
        .mutation
        .as_deref()
        .expect("wrapped-key fixture needs mutation");
    let vault_id = item.vault_id.clone().into_bytes();
    let item_id = item.item_id.clone().into_bytes();
    let ctx = WrapContext {
        vault_id: &vault_id,
        item_id: &item_id,
    };

    let vault_key = Secret::<VaultKey>::from_derived_bytes(vec![0x11; 32]);
    let autofill_key = Secret::<AutofillKey>::from_derived_bytes(vec![0x22; 32]);

    let result = match mutation {
        "swap-slots" => {
            let set = VaultAndAutofill::wrap(&item_key(0xAB), &vault_key, &autofill_key, ctx)
                .expect("must wrap");
            let swapped = VaultAndAutofill::from_stored_parts(
                set.autofill_wrap().clone(),
                set.vault_wrap().clone(),
            );
            swapped.unwrap(&vault_key, &autofill_key, ctx).map(|_| ())
        }
        "transplant-item" => {
            let set = VaultOnly::wrap(&item_key(0xAB), &vault_key, ctx).expect("must wrap");
            let other_id = b"item-elsewhere".to_vec();
            let elsewhere = WrapContext {
                vault_id: &vault_id,
                item_id: &other_id,
            };
            set.unwrap(&vault_key, elsewhere).map(|_| ())
        }
        "disagreeing-keys" => {
            let honest = VaultAndAutofill::wrap(&item_key(0xAB), &vault_key, &autofill_key, ctx)
                .expect("must wrap");
            let planted = VaultAndAutofill::wrap(&item_key(0xCD), &vault_key, &autofill_key, ctx)
                .expect("must wrap");
            let mixed = VaultAndAutofill::from_stored_parts(
                honest.vault_wrap().clone(),
                planted.autofill_wrap().clone(),
            );
            mixed.unwrap(&vault_key, &autofill_key, ctx).map(|_| ())
        }
        other => panic!("unknown wrapped-key mutation {other:?}"),
    };

    match result {
        Ok(()) => Outcome::Accepted,
        Err(e) => Outcome::Refused(e.to_string()),
    }
}

fn apply_aad_bytes(f: &Fixture) -> Outcome {
    let mutation = f
        .mutation
        .as_deref()
        .expect("aad-bytes fixture needs mutation");

    let canonical_segment = AadFields::ManifestSegment {
        vault_id: b"vault-1".to_vec(),
        segment_seq: 1,
        vault_key_epoch: 0,
        prefix_len: 1,
        prefix_bits: 0x8000_0000_0000_0000,
    };
    let canonical_wrap = AadFields::WrappedItemKey {
        vault_id: b"vault-1".to_vec(),
        item_id: b"item-1".to_vec(),
        wrap_purpose: WRAP_PURPOSE_VAULT,
    };

    let bytes = match mutation {
        "dirty-prefix-low-bits" => {
            let mut b = encode(&canonical_segment).expect("must encode");
            let n = b.len();
            b[n - 8] |= 1; // prefix_bits is the trailing u64, little-endian
            b
        }
        "prefix-len-65" => {
            let mut b = encode(&canonical_segment).expect("must encode");
            let n = b.len();
            b[n - 9] = 65; // the prefix_len byte sits just before prefix_bits
            b
        }
        "wrap-purpose-3" => {
            let mut b = encode(&canonical_wrap).expect("must encode");
            let n = b.len();
            b[n - 1] = 0x03;
            b
        }
        "append-byte" => {
            let mut b = encode(&canonical_wrap).expect("must encode");
            b.push(0);
            b
        }
        "record-type-9" => {
            let mut b = encode(&canonical_wrap).expect("must encode");
            b[4] = 0x09; // the recordType byte, straight after "CHV1"
            b
        }
        other => panic!("unknown aad-bytes mutation {other:?}"),
    };

    match chiavora_core::aad::decode(&bytes) {
        Ok(_) => Outcome::Accepted,
        Err(e) => Outcome::Refused(e.to_string()),
    }
}

fn apply_kdf_params(f: &Fixture) -> Outcome {
    let memory_kib = f.memory_kib.expect("kdf-params fixture needs memory_kib");
    let iterations = f.iterations.expect("kdf-params fixture needs iterations");
    match KdfParams::new(memory_kib, iterations) {
        Ok(_) => Outcome::Accepted,
        Err(e) => Outcome::Refused(e.to_string()),
    }
}

fn apply_manifest_read(f: &Fixture) -> Outcome {
    use chiavora_core::manifest::{
        advance_high_water_mark, CanonicalPrefix, Entry, ManifestError, ManifestRoot,
        ManifestSegment, RootEntry,
    };
    use chiavora_core::secret::kind::{Muk, VaultKey};
    use chiavora_core::store::{Store, Unanchored};

    const VAULT: &[u8] = b"vault-1";
    const ITEM: &[u8] = b"login-bank";

    let vault_key = Secret::<VaultKey>::from_derived_bytes(vec![0x22; 32]);
    let root_fields = |count: u32, seq: u64| AadFields::ManifestRoot {
        vault_id: VAULT.to_vec(),
        manifest_seq: seq,
        vault_key_epoch: 1,
        segment_count: count,
    };
    let segment_fields = |seq: u64| AadFields::ManifestSegment {
        vault_id: VAULT.to_vec(),
        segment_seq: seq,
        vault_key_epoch: 1,
        prefix_len: 0,
        prefix_bits: 0,
    };
    let whole = match CanonicalPrefix::new(0, 0) {
        Ok(p) => p,
        Err(e) => return Outcome::Refused(e.to_string()),
    };
    let current = Entry::new(ITEM.to_vec(), 2, [0x2A; 32], false, Vec::new());
    let segment = match ManifestSegment::new(segment_fields(2), vec![current.clone()]) {
        Ok(s) => s,
        Err(e) => return Outcome::Refused(e.to_string()),
    };
    let sealed = match chiavora_core::manifest::seal_segment(
        &vault_key,
        FreshNonce::generate().expect("nonce"),
        &segment,
    ) {
        Ok(s) => s,
        Err(e) => return Outcome::Refused(e.to_string()),
    };
    let digest = match sealed.digest() {
        Ok(d) => d,
        Err(e) => return Outcome::Refused(e.to_string()),
    };
    let root = match ManifestRoot::new(root_fields(1, 2), vec![RootEntry::new(whole, digest, 2)]) {
        Ok(r) => r,
        Err(e) => return Outcome::Refused(e.to_string()),
    };

    let outcome: Result<(), ManifestError> = match f.mutation.as_deref().unwrap_or_default() {
        "rewound-root" => {
            ManifestRoot::new(root_fields(1, 1), vec![RootEntry::new(whole, digest, 1)])
                .and_then(|old| old.accept(Some(2)))
        }

        "stale-segment" => {
            let old = ManifestSegment::new(
                segment_fields(1),
                vec![Entry::new(ITEM.to_vec(), 1, [0xB1; 32], false, Vec::new())],
            );
            old.and_then(|old| {
                chiavora_core::manifest::seal_segment(
                    &vault_key,
                    FreshNonce::generate().expect("nonce"),
                    &old,
                )
            })
            .and_then(|stale| root.accept_segment(&stale))
        }

        "replayed-item-version" => current.accept_item(1, &[0xB1; 32]),

        "substituted-ciphertext" => current.accept_item(2, &[0x99; 32]),

        "untombstoned-deletion" => segment.reconcile(&[]),

        "rewound-high-water-mark" => {
            let mut store = match Store::open_in_memory(
                &Secret::<Muk>::from_derived_bytes(vec![0x4D; 32]),
                Box::new(Unanchored),
            ) {
                Ok(s) => s,
                Err(e) => return Outcome::Refused(e.to_string()),
            };
            advance_high_water_mark(&mut store, VAULT, &root).and_then(|()| {
                ManifestRoot::new(root_fields(1, 1), vec![RootEntry::new(whole, digest, 1)])
                    .and_then(|old| advance_high_water_mark(&mut store, VAULT, &old))
            })
        }

        other => panic!("unknown manifest-read mutation {other:?}"),
    };

    match outcome {
        Ok(()) => Outcome::Accepted,
        Err(e) => Outcome::Refused(e.to_string()),
    }
}

fn apply(f: &Fixture) -> Outcome {
    match f.kind.as_str() {
        "item-payload" => apply_item_payload(f),
        "wrapped-key" => apply_wrapped_key(f),
        "aad-bytes" => apply_aad_bytes(f),
        "kdf-params" => apply_kdf_params(f),
        "manifest-read" => apply_manifest_read(f),
        other => panic!("unknown fixture kind {other:?}"),
    }
}

/// The corpus only grows; raise this when fixtures are added.
const MINIMUM_FIXTURES: usize = 20;

#[test]
fn every_hostile_fixture_is_refused_and_names_its_invariant() {
    let dir = fixture_dir();
    let mut applied = 0_usize;
    let mut failures: Vec<String> = Vec::new();

    let mut entries: Vec<PathBuf> = fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", dir.display()))
        .map(|e| e.expect("dir entry").path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    entries.sort();

    for path in entries {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("<unnamed>")
            .to_owned();
        let raw = fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {name}: {e}"));
        let fixture: Fixture =
            serde_json::from_str(&raw).unwrap_or_else(|e| panic!("cannot parse {name}: {e}"));

        assert!(
            !fixture.attacks.trim().is_empty(),
            "{name} does not name the invariant it attacks"
        );
        assert!(
            !fixture.why.trim().is_empty(),
            "{name} does not say what the attack achieves"
        );

        let outcome = apply(&fixture);
        applied += 1;

        let ok = matches!(
            (fixture.expect.as_str(), &outcome),
            ("refused", Outcome::Refused(_)) | ("accepted", Outcome::Accepted)
        );

        if !ok {
            failures.push(format!(
                "\nFIXTURE FAILED: {name}\n  attacks:  {}\n  why:      {}\n  expected: {}\n  got:      {}",
                fixture.attacks,
                fixture.why,
                fixture.expect,
                match &outcome {
                    Outcome::Refused(reason) => format!("refused ({reason})"),
                    Outcome::Accepted => "accepted".to_owned(),
                }
            ));
        }
    }

    assert!(
        applied >= MINIMUM_FIXTURES,
        "the hostile corpus has shrunk: applied {applied}, minimum {MINIMUM_FIXTURES}. \
         §5 requires it to accumulate — a deleted fixture takes its invariant's \
         coverage with it."
    );

    assert!(
        failures.is_empty(),
        "{} hostile fixture(s) did not behave as stated:{}",
        failures.len(),
        failures.join("")
    );
}

#[test]
fn the_corpus_covers_every_invariant_the_core_can_reach() {
    let dir = fixture_dir();
    let mut attacked = Vec::new();
    for entry in fs::read_dir(&dir).expect("fixture dir") {
        let path = entry.expect("dir entry").path();
        if path.extension().is_some_and(|x| x == "json") {
            let raw = fs::read_to_string(&path).expect("read fixture");
            let f: Fixture = serde_json::from_str(&raw).expect("parse fixture");
            attacked.push(f.attacks);
        }
    }
    let joined = attacked.join(" | ");

    for invariant in ["I3", "I4", "I7"] {
        assert!(
            joined.contains(invariant),
            "no hostile fixture attacks {invariant}; corpus covers: {joined}"
        );
    }

    assert!(
        joined.contains("I6b"),
        "no fixture attacks I6b's canonicality precondition; corpus covers: {joined}"
    );

    // I1(a) and I2 are type constraints, covered by `tests/compile-fail/`.
}
