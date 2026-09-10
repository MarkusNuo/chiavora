#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::PathBuf;

use chiavora_core::entry::{accept, EntryPoint as _, EntryStatus, PasswordField, REGISTRY};

fn repo_root() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p
}

fn read(rel: &str) -> String {
    let path = repo_root().join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
}

fn unwrap_lines(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[test]
fn the_registry_reproduces_the_gate_sentence_verbatim() {
    let phrases: Vec<&str> = REGISTRY.iter().map(|r| r.gate_phrase).collect();
    let (last, leading) = phrases.split_last().expect("the registry is never empty");
    let expected = format!(
        "the gate names every entry point: {}, and {last}.",
        leading.join(", ")
    );

    let plan = unwrap_lines(&read("docs/security-design.md"));
    assert!(
        plan.contains(&expected),
        "docs/security-design.md no longer lists the entry points the registry claims.\n\
         The registry builds: {expected}\n\
         If docs/security-design.md changed deliberately, change `entry::REGISTRY` in the same \
         commit — an entry point named by the gate and absent from the registry \
         is one nothing will ever build."
    );
}

#[test]
fn owed_points_name_a_blocker_and_covered_points_do_not() {
    for record in &REGISTRY {
        match record.status {
            EntryStatus::Covered => assert!(
                record.blocked_on.is_none(),
                "{} is covered but still names a blocker",
                record.name
            ),
            EntryStatus::Owed => {
                let blocker = record.blocked_on.unwrap_or_else(|| {
                    panic!(
                        "{} is owed with no blocker recorded. An owed entry point \
                         with no stated reason reads as forgotten rather than as \
                         waiting on a decision.",
                        record.name
                    )
                });
                assert!(
                    blocker.contains("OD-") || blocker.contains("adr/"),
                    "{}'s blocker must cite the decision that unblocks it, not \
                     just describe the situation: {blocker}",
                    record.name
                );
            }
        }
    }
}

#[test]
fn exactly_one_entry_point_is_covered_today() {
    // Pinned, because `docs/crypto.md` states these counts in prose.
    let covered = REGISTRY
        .iter()
        .filter(|r| r.status == EntryStatus::Covered)
        .count();
    assert_eq!(
        covered, 1,
        "the number of covered entry points changed; update docs/crypto.md's \
         partial-coverage section and this count together"
    );
    assert_eq!(REGISTRY.len(), 6, "the gate names six");
}

#[test]
fn a_covered_point_is_reachable_through_accept() {
    let secret = accept::<PasswordField>(b"a-real-password".to_vec()).expect("covered");
    assert_eq!(secret.expose(), b"a-real-password");
}

#[test]
fn every_covered_point_yields_the_brand_the_registry_records() {
    for record in REGISTRY.iter().filter(|r| r.status == EntryStatus::Covered) {
        let brand = record
            .yields
            .expect("a covered entry point knows what it yields");
        assert_eq!(record.name, PasswordField::NAME);
        let secret = accept::<PasswordField>(b"x".to_vec()).expect("accepted");
        let rendered = format!("{secret:?}");
        assert!(
            rendered.contains(brand),
            "{} yields {rendered}, not the recorded {brand}",
            record.name
        );
    }
}

// Which brands are fingerprinted is tested inside the crate, through `registered_count`.
