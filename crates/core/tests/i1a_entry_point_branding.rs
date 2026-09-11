#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::PathBuf;

use chiavora_core::emergency_kit;
use chiavora_core::entry::{
    accept, CliStdin, ClipboardPaste, EntryError, EntryPoint as _, EntryStatus, PasswordField,
    SecretKeyField, REGISTRY,
};

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
fn every_row_names_either_what_blocks_it_or_what_resolved_it() {
    for record in &REGISTRY {
        match record.status {
            EntryStatus::CoveredInCore | EntryStatus::CarriesNoSecret => {
                assert!(
                    record.blocked_on.is_none(),
                    "{} is no longer owed but still names a blocker",
                    record.name
                );
                let resolved = record.resolved_by.unwrap_or_else(|| {
                    panic!(
                        "{} is no longer owed and does not say what resolved it",
                        record.name
                    )
                });
                assert!(
                    resolved.contains("OD-")
                        || resolved.contains("adr/")
                        || resolved.contains("B-02."),
                    "{}'s resolution must cite a decision or the change that built \
                     it, not describe the situation: {resolved}",
                    record.name
                );
            }
            EntryStatus::Owed => {
                assert!(
                    record.resolved_by.is_none(),
                    "{} is owed and claims to be resolved",
                    record.name
                );
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

/// The call returns the `Debug` of the `Secret` it produced, which names the brand.
type CoveredPoint = (&'static str, fn() -> Result<String, EntryError>);

fn covered_points() -> Vec<CoveredPoint> {
    vec![
        ("password field", || {
            accept::<PasswordField>(b"a-real-password".to_vec()).map(|s| format!("{s:?}"))
        }),
        ("Secret Key field", || {
            accept::<SecretKeyField>(b"CHV1-0000-0000-0000-0000-0000-0000-00XV".to_vec())
                .map(|s| format!("{s:?}"))
        }),
        ("Emergency Kit QR decode path", || {
            // The QR payload is the Kit's compact rendering, so the path is `emergency_kit::parse`.
            let key =
                accept::<SecretKeyField>(b"CHV1-0000-0000-0000-0000-0000-0000-00XV".to_vec())?;
            let kit = emergency_kit::Kit::new([0x11; 16], [0x22; 32], key, None)
                .expect("a well-formed Kit");
            let parsed =
                emergency_kit::parse(kit.render_compact().as_bytes()).expect("its own rendering");
            Ok(format!("{:?}", parsed.secret_key()))
        }),
        ("clipboard paste", || {
            accept::<ClipboardPaste>(b"a-real-password".to_vec()).map(|s| format!("{s:?}"))
        }),
        ("CLI stdin", || {
            accept::<CliStdin>(b"a-real-password\n".to_vec()).map(|s| format!("{s:?}"))
        }),
    ]
}

#[test]
fn the_covered_list_is_exactly_the_registry_s_covered_set() {
    let mut from_registry: Vec<&str> = REGISTRY
        .iter()
        .filter(|r| r.status == EntryStatus::CoveredInCore)
        .map(|r| r.name)
        .collect();
    let mut from_list: Vec<&str> = covered_points().into_iter().map(|(n, _)| n).collect();
    from_registry.sort_unstable();
    from_list.sort_unstable();
    assert_eq!(from_registry, from_list);
}

#[test]
fn the_entry_points_name_themselves_the_way_the_registry_does() {
    let names: Vec<&str> = covered_points().into_iter().map(|(n, _)| n).collect();
    assert!(names.contains(&PasswordField::NAME));
    assert!(names.contains(&SecretKeyField::NAME));
}

#[test]
fn the_two_counts_are_pinned_and_they_are_two_different_numbers() {
    // Pinned, because `docs/crypto.md` states these counts in prose.
    let covered = REGISTRY
        .iter()
        .filter(|r| r.status == EntryStatus::CoveredInCore)
        .count();
    let excluded = REGISTRY
        .iter()
        .filter(|r| r.status == EntryStatus::CarriesNoSecret)
        .count();
    assert_eq!(
        covered, 5,
        "the number of entry points covered in core changed; update \
         docs/crypto.md's partial-coverage section, `covered_points` and this \
         count together"
    );
    assert_eq!(excluded, 1, "inbound native messaging is the only such row");
    assert_eq!(REGISTRY.len(), 6, "the gate names six");
}

#[test]
fn no_entry_point_claims_the_excluded_boundary() {
    let excluded: Vec<&str> = REGISTRY
        .iter()
        .filter(|r| r.status == EntryStatus::CarriesNoSecret)
        .map(|r| r.name)
        .collect();
    let built: Vec<&str> = covered_points().into_iter().map(|(n, _)| n).collect();
    for name in excluded {
        assert!(
            !built.contains(&name),
            "{name} is recorded as carrying no secret and has an entry point \
             behind it. One of the two is wrong, and says which."
        );
    }
}

#[test]
fn every_covered_point_is_reachable_through_accept() {
    for (name, call) in covered_points() {
        call().unwrap_or_else(|e| {
            panic!("{name} is recorded as covered but refused a valid input: {e}")
        });
    }
}

#[test]
fn every_covered_point_yields_the_brand_the_registry_records() {
    let calls = covered_points();
    for record in REGISTRY
        .iter()
        .filter(|r| r.status == EntryStatus::CoveredInCore)
    {
        let brand = record
            .yields
            .expect("a covered entry point knows what it yields");
        let (_, call) = calls
            .iter()
            .find(|(n, _)| *n == record.name)
            .unwrap_or_else(|| {
                panic!(
                    "{} is covered but has no call in `covered_points`",
                    record.name
                )
            });
        let rendered = call().unwrap_or_else(|e| panic!("{}: {e}", record.name));
        assert!(
            rendered.contains(brand),
            "{} yields {rendered}, not the recorded {brand}",
            record.name
        );
    }
}

// Which brands are fingerprinted is tested inside the crate, through `registered_count`.
