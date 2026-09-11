#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::PathBuf;

fn root() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p
}

fn read(rel: &str) -> String {
    let path = root().join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
}

fn test_sources() -> Vec<(String, String)> {
    let mut out = Vec::new();
    for crate_dir in ["core", "protocol"] {
        for sub in ["src", "tests"] {
            let dir = root().join("crates").join(crate_dir).join(sub);
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries {
                let path = entry.expect("a directory entry").path();
                if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                    continue;
                }
                let name = format!(
                    "{crate_dir}/{sub}/{}",
                    path.file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or_default()
                );
                out.push((name, std::fs::read_to_string(&path).expect("a source file")));
            }
        }
    }
    assert!(
        out.len() >= 20,
        "expected the whole suite, found {}",
        out.len()
    );
    out
}

const CORE_INVARIANTS: [(&str, &str); 5] = [
    ("i1a", "The server never receives the account password"),
    ("i2", "every nonce is drawn from the platform"),
    (
        "i3",
        "Integrity-relevant metadata is bound as AEAD associated data",
    ),
    (
        "i4",
        "The client refuses KDF parameters below the hard floor",
    ),
    ("i7", "double-wrap agreement"),
];

#[test]
fn every_core_invariant_has_at_least_one_test_named_for_it() {
    let sources = test_sources();
    let mut missing: Vec<&str> = Vec::new();
    let mut counts: Vec<(&str, usize)> = Vec::new();

    for (invariant, _) in CORE_INVARIANTS {
        let needle = format!("fn {invariant}_");
        let count: usize = sources
            .iter()
            .map(|(_, src)| src.matches(&needle).count())
            .sum();
        counts.push((invariant, count));
        if count == 0 {
            missing.push(invariant);
        }
    }
    assert!(
        missing.is_empty(),
        ": these core invariants have no test named for them, so a failure \
         would name a filename rather than the invariant: {missing:?}\n\
         counts: {counts:?}"
    );
}

#[test]
fn the_invariant_list_matches_the_phrases_the_design_states_them_in() {
    let plan = read("docs/security-design.md");
    let flat = plan.split_whitespace().collect::<Vec<_>>().join(" ");
    for (invariant, phrase) in CORE_INVARIANTS {
        assert!(
            flat.contains(phrase),
            "{invariant}: docs/security-design.md no longer contains {phrase:?}. Either the \
             invariant was restated — in which case update this list — or it \
             was removed, in which case its tests are testing nothing named."
        );
    }
}

#[test]
fn i5_and_i6_are_absent_on_purpose() {
    let names: Vec<&str> = CORE_INVARIANTS.iter().map(|(n, _)| *n).collect();
    for later in ["i5", "i5a", "i5b", "i6"] {
        assert!(
            !names.contains(&later),
            "{later} is not the core's. If its code has landed, add it here \
             *and* give it a named test — a row without a test is worse than \
             no row."
        );
    }
}

const PARSERS: [Parser; 4] = [
    Parser {
        file: "core/src/aad.rs",
        function: "decode",
        target: "aad_decode",
        why: "the inverse of the encoder every record depends on; a disagreement is an I3 failure",
    },
    Parser {
        file: "protocol/src/lib.rs",
        function: "decode",
        target: "wire_record_decode",
        why: "every encrypted record fetched from the server (A1)",
    },
    Parser {
        file: "core/src/secret_key.rs",
        function: "decode",
        target: "secret_key_decode",
        why: "a string typed into a field, or read from a QR code",
    },
    Parser {
        file: "core/src/emergency_kit.rs",
        function: "parse",
        target: "emergency_kit_parse",
        why: "a QR code a camera read",
    },
];

struct Parser {
    file: &'static str,
    function: &'static str,
    target: &'static str,
    why: &'static str,
}

#[test]
fn every_registered_parser_has_a_fuzz_target_with_a_corpus() {
    let targets = root().join("fuzz").join("fuzz_targets");
    let corpus = root().join("fuzz").join("corpus");
    for Parser {
        file,
        function,
        target,
        why,
    } in PARSERS
    {
        assert!(
            !why.is_empty(),
            "{file}::{function} must say why it is attacker-facing"
        );
        let source = targets.join(format!("{target}.rs"));
        assert!(
            source.exists(),
            ": {file}::{function} is registered as an attacker-input parser but \
             `fuzz/fuzz_targets/{target}.rs` does not exist"
        );
        let seeds = corpus
            .join(target)
            .read_dir()
            .map_or(0, |d| d.filter_map(Result::ok).count());
        assert!(
            seeds >= 10,
            " and R7: {target} has {seeds} corpus inputs. An unseeded \
             target for a prefixed format explores the prefix check and \
             nothing else"
        );
    }
}

#[test]
fn every_parser_in_the_source_is_classified() {
    const NOT_SEPARATELY_FUZZED: [(&str, &str, &str); 3] = [
        (
            "core/src/base32.rs",
            "decode_with_checksum",
            "COVERED ELSEWHERE: reached only through secret_key::decode and \
             emergency_kit::parse, both of which are fuzzed; it takes an \
             already-normalised symbol slice rather than raw input",
        ),
        (
            "core/src/nonce.rs",
            "from_stored_bytes",
            "SAFE BY CONSTRUCTION: takes a fixed-size array, so there is no \
             length or structure to get wrong, and a wrong nonce fails the \
             AEAD tag",
        ),
        (
            "core/src/secret_key.rs",
            "looks_like_rendered_key_material",
            "COVERED ELSEWHERE: attacker-facing -- a hostile app can write the \
             clipboard (A8) -- and its whole body is base32::normalise_input \
             plus a length comparison and a prefix match. normalise_input is \
             exercised on arbitrary bytes by the secret_key_decode target, so a \
             fifth target would be fuzzing `>=` and `starts_with`",
        ),
    ];
    let mut unclassified: Vec<String> = Vec::new();
    for (name, source) in test_sources() {
        if !name.contains("/src/") {
            continue;
        }
        let marker = concat!("#[cfg(", "test)]");
        let code = source.split(marker).next().unwrap_or(&source);

        for line in code.lines() {
            let line = line.trim();
            if line.starts_with("//") {
                continue;
            }
            let is_parser = (line.starts_with("pub fn ") || line.starts_with("pub(crate) fn "))
                && ["decode", "parse", "from_stored_bytes", "looks_like"]
                    .iter()
                    .any(|verb| line.contains(&format!("fn {verb}")));
            if !is_parser {
                continue;
            }
            let declared = line
                .split("fn ")
                .nth(1)
                .and_then(|rest| rest.split(['(', '<']).next())
                .unwrap_or_default()
                .trim();
            let known = PARSERS
                .iter()
                .any(|p| p.file == name && p.function == declared)
                || NOT_SEPARATELY_FUZZED
                    .iter()
                    .any(|(file, function, _why)| *file == name && *function == declared);
            if !known {
                unclassified.push(format!("{name}: {line}"));
            }
        }
    }

    assert!(
        unclassified.is_empty(),
        ": these parsers are classified neither as attacker-facing (with \
         a fuzz target) nor as deliberately not. Classify each — a parser \
         nobody decided about is a parser nobody fuzzed:\n  {}",
        unclassified.join("\n  ")
    );
}

#[test]
fn every_fuzz_target_is_registered() {
    let targets = root().join("fuzz").join("fuzz_targets");
    let mut unregistered: Vec<String> = Vec::new();
    for entry in std::fs::read_dir(&targets).expect("fuzz/fuzz_targets is readable") {
        let path = entry.expect("a directory entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or_default()
            .to_owned();
        if !PARSERS.iter().any(|p| p.target == stem) {
            unregistered.push(stem);
        }
    }
    assert!(
        unregistered.is_empty(),
        ": these fuzz targets are in no registry: {unregistered:?}"
    );
}
