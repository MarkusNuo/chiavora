#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::PathBuf;

use chiavora_core::secret::{
    kind::{AutofillKey, ItemKey, VaultKey},
    Secret,
};
use chiavora_core::wrap::{AnyWrapSet, ItemKind, ItemType, VaultKeys, WrapContext};

fn root() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p
}

/// The stored tags, written out by hand on purpose: they are an on-disk format (the row's
/// type and the `0x01` AAD's `contentType`), so a rename in the macro must fail here.
const STORED_TAGS: [&str; 6] = ["login", "TOTP", "note", "card", "identity", "SSH key"];

fn key32(fill: u8) -> Vec<u8> {
    vec![fill; 32]
}

#[test]
fn the_stored_tags_are_pinned_against_a_hand_written_list() {
    let from_code: Vec<&str> = ItemKind::ALL.iter().map(|k| k.tag()).collect();
    assert_eq!(
        from_code, STORED_TAGS,
        "an item kind's stored tag changed, which changes the on-disk format"
    );
}

#[test]
fn every_kind_round_trips_through_its_tag() {
    for kind in ItemKind::ALL {
        assert_eq!(
            ItemKind::from_tag(kind.tag()),
            Some(*kind),
            "{} does not round-trip",
            kind.tag()
        );
    }
    assert_eq!(ItemKind::from_tag("no-such-kind"), None);
    // Case-sensitive: a stored tag is a format, so one kind has one spelling.
    assert_eq!(ItemKind::from_tag("totp"), None);
    assert_eq!(ItemKind::from_tag("Login"), None);
}

#[test]
fn the_wrap_count_matches_what_the_type_names() {
    use chiavora_core::wrap::{
        Card, Identity, Login, Note, SshKey, Totp, VaultAndAutofill, VaultOnly, WrapSet,
    };

    assert_eq!(
        ItemKind::Login.wrap_count(),
        <<Login as ItemType>::Wraps as WrapSet>::WRAP_COUNT
    );
    assert_eq!(
        ItemKind::Totp.wrap_count(),
        <<Totp as ItemType>::Wraps as WrapSet>::WRAP_COUNT
    );
    assert_eq!(
        ItemKind::Note.wrap_count(),
        <<Note as ItemType>::Wraps as WrapSet>::WRAP_COUNT
    );
    assert_eq!(
        ItemKind::Card.wrap_count(),
        <<Card as ItemType>::Wraps as WrapSet>::WRAP_COUNT
    );
    assert_eq!(
        ItemKind::Identity.wrap_count(),
        <<Identity as ItemType>::Wraps as WrapSet>::WRAP_COUNT
    );
    assert_eq!(
        ItemKind::SshKey.wrap_count(),
        <<SshKey as ItemType>::Wraps as WrapSet>::WRAP_COUNT
    );

    assert_eq!(<VaultOnly as WrapSet>::WRAP_COUNT, 1);
    assert_eq!(<VaultAndAutofill as WrapSet>::WRAP_COUNT, 2);
}

#[test]
fn provider_readability_agrees_with_the_wrap_count() {
    for kind in ItemKind::ALL {
        assert_eq!(
            kind.provider_readable(),
            kind.wrap_count() == 2,
            "{}: provider_readable is {} but it stores {} wraps",
            kind.tag(),
            kind.provider_readable(),
            kind.wrap_count()
        );
    }
}

#[test]
fn a_login_gets_two_wraps_and_a_note_gets_one_through_the_dispatch() {
    // Through `ItemKind::wrap`, because the dispatch is what is under test.
    let item_key = Secret::<ItemKey>::from_derived_bytes(key32(0x4D));
    let vault = Secret::<VaultKey>::from_derived_bytes(key32(0x11));
    let autofill = Secret::<AutofillKey>::from_derived_bytes(key32(0x22));
    let keys = VaultKeys {
        vault: &vault,
        autofill: &autofill,
    };
    let ctx = WrapContext {
        vault_id: b"vault-1",
        item_id: b"item-1",
    };

    for kind in ItemKind::ALL {
        let set = kind.wrap(&item_key, keys, ctx).expect("wraps");
        assert_eq!(
            set.wrap_count(),
            kind.wrap_count(),
            "{}: the dispatch produced a set with a different wrap count",
            kind.tag()
        );
        match (kind, &set) {
            (ItemKind::Login | ItemKind::Totp, AnyWrapSet::VaultAndAutofill(_))
            | (_, AnyWrapSet::VaultOnly(_)) => {}
            _ => panic!("{} produced the wrong wrap set", kind.tag()),
        }
    }
}

#[test]
fn no_hand_written_branch_chooses_a_wrap_set() {
    // A source scan: outside `wrap.rs`, a module naming both wrap sets is choosing between them.
    let mut offenders: Vec<String> = Vec::new();
    let dir = root().join("crates").join("core").join("src");
    for entry in std::fs::read_dir(&dir).expect("crates/core/src is readable") {
        let path = entry.expect("a directory entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_owned();
        if name == "wrap.rs" {
            continue;
        }
        let source = std::fs::read_to_string(&path).expect("a source file");
        // Comments stripped, so prose about the rule does not trip it.
        let code: String = source
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        let code = code
            .split(concat!("#[cfg(", "test)]"))
            .next()
            .unwrap_or(&code);
        if code.contains("VaultOnly") && code.contains("VaultAndAutofill") {
            offenders.push(name);
        }
    }
    assert!(
        offenders.is_empty(),
        "these modules name both wrap sets outside wrap.rs: {offenders:?}"
    );
}
