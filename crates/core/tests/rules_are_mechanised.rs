//! The rules of `docs/crypto.md` as source scans.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::{Path, PathBuf};

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

fn core_modules() -> Vec<(String, String)> {
    let src = root().join("crates").join("core").join("src");
    let mut out = Vec::new();
    for entry in std::fs::read_dir(&src).expect("crates/core/src is readable") {
        let path = entry.expect("a directory entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_owned();
        out.push((name, std::fs::read_to_string(&path).expect("a module")));
    }
    assert!(
        out.len() >= 10,
        "expected to read every module in crates/core/src, found {}",
        out.len()
    );
    out
}

fn production(source: &str) -> String {
    let marker = concat!("#[cfg(", "test)]");
    let code = source.split(marker).next().unwrap_or(source);
    code.lines()
        .map(|line| {
            line.find("//")
                .map_or(line, |at| line.get(..at).unwrap_or(""))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

const TEST_ONLY_MODULES: [&str; 1] = ["scan.rs"];

#[test]
fn r1_every_absorbing_pattern_carries_a_justification() {
    const PATTERNS: [&str; 5] = [
        ".unwrap_or(",
        ".unwrap_or_else(",
        ".unwrap_or_default()",
        ".ok()",
        "debug_assert",
    ];

    let mut unjustified: Vec<String> = Vec::new();
    for (name, source) in core_modules() {
        if TEST_ONLY_MODULES.contains(&name.as_str()) {
            continue;
        }
        let lines: Vec<&str> = source.lines().collect();
        let marker = concat!("#[cfg(", "test)]");
        let end = lines
            .iter()
            .position(|l| l.contains(marker))
            .unwrap_or(lines.len());

        for (index, line) in lines.iter().enumerate().take(end) {
            let code = line
                .find("//")
                .map_or(*line, |at| line.get(..at).unwrap_or(""));
            if !PATTERNS.iter().any(|p| code.contains(p)) {
                continue;
            }
            let window_start = index.saturating_sub(8);
            let justified = lines
                .get(window_start..=index)
                .unwrap_or_default()
                .iter()
                .any(|l| l.contains("R1:"));
            if !justified {
                unjustified.push(format!("{name}:{}  {}", index + 1, code.trim()));
            }
        }
    }

    assert!(
        unjustified.is_empty(),
        "R1: these absorb a failure with no `R1:` justification within eight \
         lines above. Either propagate the error, or write why the absorbed \
         value cannot be a cryptographic output:\n  {}",
        unjustified.join("\n  ")
    );
}

#[test]
fn r1_the_scan_would_notice_an_unjustified_absorber() {
    let module = "fn f() -> u8 {\n    something.unwrap_or(0)\n}\n";
    let lines: Vec<&str> = module.lines().collect();
    let hit = lines
        .iter()
        .enumerate()
        .find(|(_, l)| l.contains(".unwrap_or("));
    let (index, _) = hit.expect("the pattern must match");
    let justified = lines
        .get(index.saturating_sub(8)..=index)
        .unwrap_or_default()
        .iter()
        .any(|l| l.contains("R1:"));
    assert!(
        !justified,
        "an unannotated absorber must read as unjustified"
    );
}

#[test]
fn r2_the_alphabet_is_defined_once() {
    let literal = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let mut defining: Vec<String> = Vec::new();
    for (name, source) in core_modules() {
        let code = production(&source);
        if code.contains(literal) {
            defining.push(name);
        }
    }
    assert_eq!(
        defining.len(),
        1,
        "R2: the alphabet must be defined once; found it in {defining:?}"
    );
    assert_eq!(
        defining.first().map(String::as_str),
        Some("base32.rs"),
        "R2: the one definition belongs in `base32.rs`"
    );
}

#[test]
fn r2_the_aad_encoder_takes_fields_not_bytes() {
    let aad = read("crates/core/src/aad.rs");
    let code = production(&aad);
    assert!(
        code.contains("pub fn encode(fields: &AadFields"),
        "R2: `aad::encode` must take `&AadFields`, not bytes"
    );
}

#[test]
fn r4_every_dependency_of_core_appears_in_adr_0002() {
    let manifest = read("crates/core/Cargo.toml");
    let adr = read("docs/adr/0002-m1-primitive-and-construction-choices.md");

    let deps = manifest
        .split("[dependencies]")
        .nth(1)
        .expect("crates/core has a [dependencies] section")
        .split("[dev-dependencies]")
        .next()
        .expect("bounded by dev-dependencies");

    let mut missing: Vec<String> = Vec::new();
    for line in deps.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('[') {
            continue;
        }
        let Some(name) = line.split_whitespace().next() else {
            continue;
        };
        let name = name.trim_end_matches('=').trim();
        if name.is_empty() {
            continue;
        }
        if !adr.contains(name) {
            missing.push(name.to_owned());
        }
    }
    assert!(
        missing.is_empty(),
        "R4: these dependencies of `crates/core` are not named in ADR-0002. \
         A construction this crate uses must be recorded before it is used, and \
         the ADR is where: {missing:?}"
    );
}

#[test]
fn r5_every_compile_fail_case_is_in_the_claim_table() {
    let crypto = read("docs/crypto.md");
    let mut missing: Vec<String> = Vec::new();
    for dir in [
        "crates/core/tests/compile-fail",
        "crates/protocol/tests/compile-fail",
    ] {
        let path = root().join(dir);
        for entry in std::fs::read_dir(&path).unwrap_or_else(|e| panic!("{dir}: {e}")) {
            let file = entry.expect("a directory entry").path();
            if file.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let stem = file
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or_default()
                .to_owned();
            if !crypto.contains(&stem) {
                missing.push(format!("{dir}/{stem}"));
            }
        }
    }
    assert!(
        missing.is_empty(),
        "R5: these compile-fail cases are not named anywhere in \
         `docs/crypto.md`. A case nobody can find from the rules document is a \
         case nobody knows establishes anything:\n  {}",
        missing.join("\n  ")
    );
}

#[test]
fn r6_every_text_header_survives_its_own_normalisation() {
    for (what, header) in [
        (
            "secret_key::PREFIX_TAG",
            chiavora_core::secret_key::PREFIX_TAG,
        ),
        (
            "emergency_kit::HEADER",
            chiavora_core::emergency_kit::HEADER,
        ),
    ] {
        for source in ['I', 'L', 'O'] {
            assert!(
                !header.contains(source),
                "R6: {what} = {header:?} contains {source}, a Crockford \
                 normalisation *source*. Input normalisation runs over the whole \
                 buffer before the header is located, so this header is \
                 destroyed by its own normalisation. Choose a different one — \
                 R6 says a header that cannot survive the rule is a format bug, \
                 not a reason to exempt the header."
            );
        }
        // Normalisation uppercases before mapping.
        assert_eq!(
            header.to_uppercase(),
            header,
            "R6: {what} must already be uppercase"
        );
    }

    assert_eq!(
        chiavora_protocol::WIRE_MAGIC,
        b"CHVR",
        "if the wire magic becomes text-normalised, it joins the loop above"
    );
}

#[test]
fn r7_every_fuzz_target_has_a_checked_in_corpus() {
    let targets = root().join("fuzz").join("fuzz_targets");
    let corpus = root().join("fuzz").join("corpus");
    let mut unseeded: Vec<String> = Vec::new();
    let mut count = 0_usize;

    for entry in std::fs::read_dir(&targets).expect("fuzz/fuzz_targets is readable") {
        let path = entry.expect("a directory entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        count += 1;
        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or_default()
            .to_owned();
        let seeds = corpus.join(&name);
        let seeded = seeds
            .read_dir()
            .map_or(0, |d| d.filter_map(Result::ok).count());
        // Ten is arbitrary and low: it asks that somebody seeded the target.
        if seeded < 10 {
            unseeded.push(format!("{name} ({seeded} inputs)"));
        }
    }

    assert!(
        count >= 4,
        "expected at least four fuzz targets, found {count}"
    );
    assert!(
        unseeded.is_empty(),
        "R7: these fuzz targets have no meaningful checked-in corpus. An \
         unseeded target for a format with a magic explores the magic check: \
         `secret_key_decode` reached 15.2 million executions that way and \
         entered its decoder zero times:\n  {}",
        unseeded.join("\n  ")
    );
}

#[test]
fn r7_the_fuzz_workflow_is_not_the_standing_arrangement() {
    let workflow = read(".github/workflows/fuzz.yml");
    assert!(
        !workflow.contains("cron:"),
        ": fuzzing is local and manual. A `cron` here is a change to that \
         decision and belongs in the register first."
    );
}

#[test]
fn every_rule_in_the_index_is_either_mechanised_here_or_says_why_not() {
    let crypto = read("docs/crypto.md");
    let index = crypto
        .split("## Rules for changing `crates/core`")
        .nth(1)
        .expect("the rules index")
        .split("### R1")
        .next()
        .expect("bounded by the first rule");

    let rows: Vec<&str> = index
        .lines()
        .filter(|l| l.starts_with("| **[R") && l.contains("](#r"))
        .collect();
    assert!(
        rows.len() >= 8,
        "the rules index has {} rows; at least R1-R8 exist, so the derivation \
         did not read the table",
        rows.len()
    );
    for row in rows {
        let rule = row
            .split("**[")
            .nth(1)
            .and_then(|rest| rest.split("](").next())
            .unwrap_or_default();
        assert!(
            row.contains('`') || row.to_lowercase().contains("not mechanis"),
            "{rule}'s index row must name its assertion in backticks, or say it \
             is not mechanisable: {row}"
        );
    }

    assert!(
        crypto.contains("rules_are_mechanised"),
        "`docs/crypto.md` must point at `tests/rules_are_mechanised.rs`"
    );
}

/// Keeps `Path` in use on every platform without a `cfg`.
#[allow(dead_code)]
fn _unused(_: &Path) {}
