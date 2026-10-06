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

fn all_sources() -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = core_modules()
        .into_iter()
        .map(|(n, s)| (format!("core/src/{n}"), s))
        .collect();
    let tests = root().join("crates").join("core").join("tests");
    let mut files = Vec::new();
    rs_files_under(&tests, &mut files);
    for path in files {
        let name = path
            .strip_prefix(&tests)
            .expect("under tests")
            .to_string_lossy()
            .replace('\\', "/");
        out.push((
            format!("core/tests/{name}"),
            std::fs::read_to_string(&path).expect("a test"),
        ));
    }
    out
}

fn core_modules() -> Vec<(String, String)> {
    let src = root().join("crates").join("core").join("src");
    let mut files = Vec::new();
    rs_files_under(&src, &mut files);
    let mut out = Vec::new();
    for path in files {
        let name = path
            .strip_prefix(&src)
            .expect("under src")
            .to_string_lossy()
            .replace('\\', "/");
        out.push((name, std::fs::read_to_string(&path).expect("a module")));
    }
    assert!(
        out.iter().any(|(n, _)| n == "lib.rs"),
        "the module walk did not find lib.rs"
    );
    out
}

fn rs_files_under(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut paths: Vec<PathBuf> = entries.filter_map(Result::ok).map(|e| e.path()).collect();
    paths.sort();
    for path in paths {
        if path.is_dir() {
            rs_files_under(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

fn production(source: &str) -> String {
    let lines: Vec<&str> = source.lines().collect();
    let mask = production_mask(&lines);
    lines
        .iter()
        .enumerate()
        .filter(|(i, _)| mask.get(*i).copied().unwrap_or(false))
        .map(|(_, line)| {
            line.find("//")
                .map_or(*line, |at| line.get(..at).unwrap_or(""))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Braces inside string literals are counted too, which can end a mask early;
/// that over-includes, and a scan that sees too much is the safe direction.
fn production_mask(lines: &[&str]) -> Vec<bool> {
    let marker = concat!("#[cfg(", "test)]");
    let mut mask = vec![true; lines.len()];
    let mut i = 0;
    while i < lines.len() {
        let line = lines.get(i).copied().unwrap_or_default();
        if line.trim() != marker {
            i += 1;
            continue;
        }
        if let Some(slot) = mask.get_mut(i) {
            *slot = false;
        }
        i += 1;
        let mut depth = 0_usize;
        let mut started = false;
        while let Some(inner) = lines.get(i) {
            if let Some(slot) = mask.get_mut(i) {
                *slot = false;
            }
            depth += inner.matches('{').count();
            if depth > 0 {
                started = true;
            }
            depth = depth.saturating_sub(inner.matches('}').count());
            i += 1;
            if started && depth == 0 {
                break;
            }
        }
    }
    mask
}

const TEST_ONLY_MODULES: [&str; 1] = ["scan.rs"];

/// R1's absorbing patterns with no `R1:` note in the eight lines above.
fn r1_absorbing_problems(modules: &[(String, String)]) -> Vec<String> {
    const PATTERNS: [&str; 5] = [
        ".unwrap_or(",
        ".unwrap_or_else(",
        ".unwrap_or_default()",
        ".ok()",
        "debug_assert",
    ];

    let mut unjustified: Vec<String> = Vec::new();
    for (name, source) in modules {
        if TEST_ONLY_MODULES.contains(&name.as_str()) {
            continue;
        }
        // The original lines, comments included, so a note can be found.
        let lines: Vec<&str> = source.lines().collect();
        let mask = production_mask(&lines);

        for (index, line) in lines.iter().enumerate() {
            if !mask.get(index).copied().unwrap_or(false) {
                continue;
            }
            let code = line
                .find("//")
                .map_or(*line, |at| line.get(..at).unwrap_or(""));
            if !PATTERNS.iter().any(|p| code.contains(p)) {
                continue;
            }
            let window_start = index.saturating_sub(8);
            let above = lines.get(window_start..=index).unwrap_or_default();
            let justified = above.iter().any(|l| l.contains("R1:"));
            if !justified {
                unjustified.push(format!(
                    "{name}:{}  {}{}",
                    index + 1,
                    code.trim(),
                    near_miss(above, lines.get(index..).unwrap_or_default())
                ));
            }
        }
    }
    unjustified
}

/// Names the near miss: `R1` without its colon above the absorber, or `R1:` below it.
fn near_miss(above: &[&str], from_absorber: &[&str]) -> String {
    if above.iter().any(|l| l.contains("R1") && !l.contains("R1:")) {
        return "\n      ^ found `R1` above WITHOUT THE COLON — the scan matches the literal \
                token `R1:`, which is the one form nobody writes by instinct"
            .to_owned();
    }
    if from_absorber
        .iter()
        .skip(1)
        .take(8)
        .any(|l| l.contains("R1:"))
    {
        return "\n      ^ found `R1:` BELOW this line — the note must be in the eight lines \
                ABOVE, because that is where a reader meets it first"
            .to_owned();
    }
    String::new()
}

#[test]
fn r1_every_absorbing_pattern_carries_a_justification() {
    let unjustified = r1_absorbing_problems(&core_modules());
    assert!(
        unjustified.is_empty(),
        "R1: these absorb a failure with no justification.\n  \
         The note must contain the literal token `R1:` and must be ABOVE the \
         line, within the eight lines preceding it — a note below the line \
         does not count, however close.\n  \
         Either propagate the error, or write why the absorbed value cannot be \
         a cryptographic output:\n  {}",
        unjustified.join("\n  ")
    );
}

#[test]
fn r1_the_failure_names_which_near_miss_it_was() {
    let wrong_token = [
        "    // R1, capacity corollary: the width is a module constant.",
        "    let mut out = Vec::with_capacity(width);",
    ];
    let wrong_position = [
        "    let n = u32::try_from(bytes).unwrap_or(u32::MAX);",
        "    // R1: unreachable, `bytes` is a compile-time constant.",
    ];

    let token = near_miss(&wrong_token, &wrong_token[1..]);
    assert!(
        token.contains("WITHOUT THE COLON"),
        "the wrong-token near miss was not named: {token:?}"
    );

    let position = near_miss(&wrong_position[..1], &wrong_position);
    assert!(
        position.contains("BELOW this line"),
        "the wrong-position near miss was not named: {position:?}"
    );

    let neither = ["    let x = 1;", "    y.unwrap_or(0)"];
    assert_eq!(near_miss(&neither, &neither[1..]), "");

    let correct = ["    // R1: justified.", "    y.unwrap_or(0)"];
    assert_eq!(near_miss(&correct[..1], &correct[1..]), "");
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

/// A `#[cfg(test)]` attribute, split so this file's own scans do not see one.
fn marker() -> String {
    format!("#[cfg({})]", "test")
}

fn fixture(lines: &[&str]) -> String {
    lines
        .iter()
        .map(|l| l.replace("CFG", &marker()))
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

#[test]
fn production_mask_keeps_every_assumption_it_makes() {
    let seen = production(&fixture(&["pub fn only_production() {}"]));
    assert!(seen.contains("only_production"), "{seen}");

    let seen = production(&fixture(&[
        "CFG",
        "mod tests {",
        "    fn inside_leading() {}",
        "}",
        "pub fn after_a_leading_module() {}",
    ]));
    assert!(seen.contains("after_a_leading_module"), "{seen}");
    assert!(!seen.contains("inside_leading"), "{seen}");

    let seen = production(&fixture(&[
        "pub fn above() {}",
        "CFG",
        "mod tests {",
        "    fn inside_trailing() {}",
        "}",
        "pub fn below_a_trailing_module() {}",
    ]));
    assert!(seen.contains("above"), "{seen}");
    assert!(seen.contains("below_a_trailing_module"), "{seen}");
    assert!(!seen.contains("inside_trailing"), "{seen}");

    let seen = production(&fixture(&[
        "pub fn before() {}",
        "CFG",
        "fn only_for_tests() {}",
        "pub fn after_a_mid_file_item() {}",
    ]));
    assert!(
        seen.contains("before") && seen.contains("after_a_mid_file_item"),
        "{seen}"
    );
    assert!(!seen.contains("only_for_tests"), "{seen}");

    let seen = production(&fixture(&[
        "CFG",
        "mod tests {",
        "    fn outer() {",
        "        if true { let _nested = 1; }",
        "        match 1 { _ => {} }",
        "    }",
        "}",
        "pub fn after_nesting() {}",
    ]));
    assert!(
        seen.contains("after_nesting"),
        "nesting ended the mask early or late: {seen}"
    );
    assert!(!seen.contains("_nested"), "{seen}");

    let seen = production(&fixture(&[
        "CFG",
        "fn first_test_item() {}",
        "pub fn between() {}",
        "CFG",
        "fn second_test_item() {}",
        "pub fn last() {}",
    ]));
    assert!(seen.contains("between") && seen.contains("last"), "{seen}");
    assert!(!seen.contains("first_test_item"), "{seen}");
    assert!(!seen.contains("second_test_item"), "{seen}");

    // Line indices are preserved, which the `R1:` lookup depends on.
    let source = fixture(&["pub fn a() {}", "CFG", "fn t() {}", "pub fn b() {}"]);
    let lines: Vec<&str> = source.lines().collect();
    let mask = production_mask(&lines);
    assert_eq!(
        mask.len(),
        lines.len(),
        "the mask must be one flag per line"
    );
    assert!(
        mask.first().copied().unwrap_or(false),
        "line 0 is production"
    );
    assert!(
        mask.last().copied().unwrap_or(false),
        "the last line is production"
    );
}

#[test]
fn production_mask_states_the_limitation_it_has_not_solved() {
    let source = fixture(&[
        "CFG",
        "mod tests {",
        "    fn t() { let _s = \"}\"; }",
        "}",
        "pub fn after_a_brace_in_a_string() {}",
    ]);
    let seen = production(&source);
    assert!(
        seen.contains("after_a_brace_in_a_string"),
        "the production code below the item should still be seen: {seen}"
    );
    assert!(
        !seen.contains("fn t()"),
        "the test function itself must still be masked: {seen}"
    );
    assert!(
        seen.lines().any(|l| l.trim() == "}"),
        "the early end of the mask should leak the item's tail into production -- if this          no longer holds, the mask has been made string-aware and this test and the          limitation it records should go: {seen}"
    );
}

#[test]
fn the_rules_scan_reads_past_a_mid_file_cfg_test() {
    let fixture = concat!(
        "pub fn before_the_marker() {}\n",
        "#[cfg(",
        "test)]\n",
        "fn only_for_tests() {\n",
        "    let _ = None::<u8>.unwrap_or(0);\n",
        "}\n",
        "pub fn after_the_marker() {}\n",
        "#[cfg(",
        "test)]\n",
        "mod tests {\n",
        "    fn inside() { let _ = None::<u8>.unwrap_or(0); }\n",
        "}\n",
    );
    let seen = production(fixture);
    assert!(seen.contains("before_the_marker"));
    assert!(
        seen.contains("after_the_marker"),
        "**the regression this test exists for**: production code after a mid-file \
         #[cfg(test)] item was dropped, so R1's scan was blind to it: {seen}"
    );
    assert!(!seen.contains("only_for_tests"), "{seen}");
    assert!(!seen.contains("inside"), "{seen}");
}

#[test]
fn the_rules_scan_reads_past_the_trailing_test_module() {
    let fixture = concat!(
        "pub fn above_the_module() {}
",
        "#[cfg(",
        "test)]
",
        "mod tests {
",
        "    fn inside() { let _ = None::<u8>.unwrap_or(0); }
",
        "}
",
        "pub fn below_the_module() {}
",
    );
    let seen = production(fixture);
    assert!(seen.contains("above_the_module"), "{seen}");
    assert!(
        seen.contains("below_the_module"),
        "**the regression this test exists for**: production code *after* the trailing          test module was dropped, so every scan using `production` was blind to the bottom          of any file with one: {seen}"
    );
    assert!(
        !seen.contains("inside"),
        "the test module itself must still be masked: {seen}"
    );
}

/// Capacity reservations from an unbounded size with no `R1:` note above them.
fn r1_capacity_problems(modules: &[(String, String)]) -> Vec<String> {
    let mut unjustified: Vec<String> = Vec::new();
    for (name, source) in modules {
        if TEST_ONLY_MODULES.contains(&name.as_str()) {
            continue;
        }
        let lines: Vec<&str> = source.lines().collect();
        let mask = production_mask(&lines);
        for (index, line) in lines.iter().enumerate() {
            if !mask.get(index).copied().unwrap_or(false) {
                continue;
            }
            let code = line
                .find("//")
                .map_or(*line, |at| line.get(..at).unwrap_or(""));
            for size in reservation_sizes(code) {
                if size_is_bounded_by_construction(&size) {
                    continue;
                }
                let window_start = index.saturating_sub(8);
                let justified = lines
                    .get(window_start..=index)
                    .unwrap_or_default()
                    .iter()
                    .any(|l| l.contains("R1:"));
                if !justified {
                    unjustified.push(format!(
                        "{name}:{}  {}  (size: {size})",
                        index + 1,
                        code.trim()
                    ));
                }
            }
        }
    }
    unjustified
}

#[test]
fn r1_no_capacity_is_reserved_from_an_unbounded_claim() {
    let modules: Vec<(String, String)> = core_modules()
        .into_iter()
        .chain(protocol_modules())
        .collect();
    let unjustified = r1_capacity_problems(&modules);
    assert!(
        unjustified.is_empty(),
        "R1 corollary: these reserve capacity from a size that is not a literal, a \
         constant expression or the length of bytes in hand, with no `R1:` note \
         within eight lines above naming the bound. A length read from input is a \
         claim; bound it first, then say so:\n  {}",
        unjustified.join("\n  ")
    );
}

#[test]
fn the_reservation_scan_would_notice_an_unbounded_size() {
    let flagged = reservation_sizes("let v = Vec::with_capacity(declared_len);");
    assert_eq!(flagged, vec!["declared_len".to_owned()]);
    assert!(!size_is_bounded_by_construction("declared_len"));
    assert!(!size_is_bounded_by_construction("to_usize(declared)?"));
    assert!(size_is_bounded_by_construction("32"));
    assert!(size_is_bounded_by_construction("KEY_LEN"));
    assert!(size_is_bounded_by_construction(
        "2 + name.len() + self.value.len()"
    ));
    assert!(size_is_bounded_by_construction("BLOCK as u64"));
    assert_eq!(
        reservation_sizes("let b = Zeroizing::new(vec![0_u8; CHUNK_LEN]);"),
        vec!["CHUNK_LEN".to_owned()]
    );
    assert!(reservation_sizes("let f = vec![Slot::SchemaVersion, Slot::Kind];").is_empty());
}

fn reservation_sizes(code: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut search = 0;
    while let Some(at) = code
        .get(search..)
        .and_then(|rest| rest.find("with_capacity("))
    {
        let open = search + at + "with_capacity(".len();
        if let Some(arg) = balanced(code, open, '(', ')') {
            out.push(arg.trim().to_owned());
        }
        search = open;
    }
    let mut search = 0;
    while let Some(at) = code.get(search..).and_then(|rest| rest.find("vec![")) {
        let open = search + at + "vec![".len();
        if let Some(inner) = balanced(code, open, '[', ']') {
            // `vec![x; n]` reserves n; `vec![a, b]` is a list.
            if let Some(semi) = top_level_semicolon(&inner) {
                out.push(inner.get(semi + 1..).unwrap_or_default().trim().to_owned());
            }
        }
        search = open;
    }
    out
}

fn balanced(code: &str, from: usize, open: char, close: char) -> Option<String> {
    let mut depth = 1_usize;
    let mut end = None;
    for (offset, ch) in code.get(from..)?.char_indices() {
        if ch == open {
            depth += 1;
        } else if ch == close {
            depth -= 1;
            if depth == 0 {
                end = Some(from + offset);
                break;
            }
        }
    }
    code.get(from..end?).map(str::to_owned)
}

fn top_level_semicolon(inner: &str) -> Option<usize> {
    let mut depth = 0_i32;
    for (at, ch) in inner.char_indices() {
        match ch {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth -= 1,
            ';' if depth == 0 => return Some(at),
            _ => {}
        }
    }
    None
}

fn size_is_bounded_by_construction(size: &str) -> bool {
    if size.contains(".len()") {
        return true;
    }
    let mut token = String::new();
    let mut tokens: Vec<String> = Vec::new();
    for ch in size.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            token.push(ch);
        } else if !token.is_empty() {
            tokens.push(std::mem::take(&mut token));
        }
    }
    if !token.is_empty() {
        tokens.push(token);
    }
    !tokens.is_empty()
        && tokens.iter().all(|t| {
            t.chars().all(|c| c.is_ascii_digit() || c == '_')
                || t == "as"
                || t == "usize"
                || t == "u64"
                || (t.chars().next().is_some_and(|c| c.is_ascii_uppercase())
                    && t.chars()
                        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_'))
        })
}

fn protocol_modules() -> Vec<(String, String)> {
    let src = root().join("crates").join("protocol").join("src");
    let mut files = Vec::new();
    rs_files_under(&src, &mut files);
    files
        .into_iter()
        .map(|path| {
            let name = format!(
                "protocol/{}",
                path.strip_prefix(&src)
                    .expect("under src")
                    .to_string_lossy()
                    .replace('\\', "/")
            );
            (name, std::fs::read_to_string(&path).expect("a module"))
        })
        .collect()
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

/// The files that keep the measurement harness out of a release build, named
/// rather than globbed, since a glob over an ignored directory finds nothing.
const RELEASE_ABSENCE_FILES: [&str; 4] = [
    "apps/mobile/modules/chiavora-core/android/src/release/java/ch/chiavora/core/HarnessDefinition.kt",
    "apps/mobile/modules/chiavora-core/android/src/debug/java/ch/chiavora/core/HarnessDefinition.kt",
    "apps/mobile/modules/chiavora-core/android/build.gradle",
    "scripts/mobile-native.ps1",
];

#[test]
fn every_file_the_release_absence_claim_rests_on_is_tracked() {
    for file in RELEASE_ABSENCE_FILES {
        let path = root().join(file);
        assert!(
            path.exists(),
            "{file} is gone; the release-absence claim has lost a piece"
        );

        let output = std::process::Command::new("git")
            .current_dir(root())
            .args(["ls-files", "--error-unmatch", "--", file])
            .output();

        let Ok(output) = output else {
            eprintln!("SKIPPED: git is not on PATH, so tracking cannot be verified");
            return;
        };

        assert!(
            output.status.success(),
            "{file} exists on disk but is NOT TRACKED by git.\n\
             It is one of the files that make the release build's absence of the \
             measurement harness true, so leaving it untracked means the \
             guarantee lives on one machine. Check `.gitignore` — a bare \
             `release/` or `debug/` pattern matches Android build variants.\n\
             git said: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
}

#[test]
fn the_tracking_check_names_the_file_that_was_missing() {
    assert!(
        RELEASE_ABSENCE_FILES
            .iter()
            .any(|f| f.contains("src/release/") && f.ends_with("HarnessDefinition.kt")),
        "the release-side HarnessDefinition.kt is the file R7 case 9 is about; \
         it must stay in this list"
    );
    assert!(
        RELEASE_ABSENCE_FILES
            .iter()
            .any(|f| f.contains("src/debug/") && f.ends_with("HarnessDefinition.kt")),
        "the debug-side registration must be listed too: without it the release \
         file's absence of a registration means nothing"
    );
}

/// Not string-aware, so a `//` inside a string literal is read as a comment.
fn without_comments(source: &str) -> String {
    let chars: Vec<char> = source.chars().collect();
    let mut out = String::with_capacity(source.len());
    let mut i = 0;
    while i < chars.len() {
        let here = chars.get(i).copied().unwrap_or_default();
        let next = chars.get(i + 1).copied().unwrap_or_default();
        if here == '/' && next == '/' {
            while i < chars.len() && chars.get(i).copied().unwrap_or_default() != '\n' {
                i += 1;
            }
        } else if here == '/' && next == '*' {
            i += 2;
            while i < chars.len() {
                if chars.get(i).copied().unwrap_or_default() == '*'
                    && chars.get(i + 1).copied().unwrap_or_default() == '/'
                {
                    i += 2;
                    break;
                }
                i += 1;
            }
        } else {
            out.push(here);
            i += 1;
        }
    }
    out
}

fn bridge_kotlin() -> Vec<(String, String)> {
    let dir = root()
        .join("apps")
        .join("mobile")
        .join("modules")
        .join("chiavora-core")
        .join("android")
        .join("src");
    let mut files = Vec::new();
    files_under(&dir, "kt", &mut files);
    let mut out = Vec::new();
    for path in files {
        // uniffi's generated bindings are not committed.
        let name = path.to_string_lossy().replace('\\', "/");
        if name.contains("/generated/") {
            continue;
        }
        let short = name.rsplit("/src/").next().unwrap_or(&name).to_owned();
        // Unstripped: the `UI-THREAD:` notes live in comments.
        out.push((
            short,
            std::fs::read_to_string(&path).expect("a bridge file"),
        ));
    }
    assert!(
        out.iter()
            .any(|(n, _)| n.ends_with("ChiavoraCoreModule.kt")),
        "the bridge walk did not find ChiavoraCoreModule.kt -- has the module moved?"
    );
    out
}

fn files_under(dir: &Path, extension: &str, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut paths: Vec<PathBuf> = entries.filter_map(Result::ok).map(|e| e.path()).collect();
    paths.sort();
    for path in paths {
        if path.is_dir() {
            files_under(&path, extension, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some(extension) {
            out.push(path);
        }
    }
}

/// Brace-matched, so a brace inside a string literal would confuse it.
fn registration_blocks(source: &str, kind: &str) -> Vec<String> {
    let mut blocks = Vec::new();
    let needle = format!("{kind}(\"");
    let mut rest = source;
    while let Some(at) = rest.find(&needle) {
        // `AsyncFunction(` contains `Function(`.
        let preceded_by_async = rest
            .get(..at)
            .is_some_and(|before| before.ends_with("Async"));
        let after = rest.get(at + needle.len()..).unwrap_or_default();
        if preceded_by_async && kind == "Function" {
            rest = after;
            continue;
        }
        let Some(brace) = after.find('{') else {
            rest = after;
            continue;
        };
        let mut depth = 0_usize;
        let mut end = None;
        for (i, ch) in after.char_indices().skip(brace) {
            if ch == '{' {
                depth += 1;
            } else if ch == '}' {
                depth -= 1;
                if depth == 0 {
                    end = Some(i);
                    break;
                }
            }
        }
        if let Some(end) = end {
            blocks.push(after.get(brace..=end).unwrap_or_default().to_owned());
        }
        rest = after;
    }
    blocks
}

#[test]
fn no_bridge_method_runs_core_on_the_js_thread() {
    let mut problems: Vec<String> = Vec::new();

    for (name, source) in bridge_kotlin() {
        let stripped = without_comments(&source);
        let core_symbols: Vec<String> = stripped
            .lines()
            .filter_map(|l| l.trim().strip_prefix("import uniffi.chiavora_ffi_mobile::"))
            .map(str::to_owned)
            .chain(
                stripped
                    .lines()
                    .filter_map(|l| l.trim().strip_prefix("import uniffi.chiavora_ffi_mobile."))
                    .map(str::to_owned),
            )
            .collect();

        for body in registration_blocks(&stripped, "Function") {
            for symbol in &core_symbols {
                if body.contains(symbol.as_str()) {
                    problems.push(format!(
                        "{name}: a synchronous `Function` calls `{symbol}`, which reaches \
                         `core` on the JS thread. UI-THREAD: use `AsyncFunction`."
                    ));
                }
            }
        }

        // A line is exempt with a `UI-THREAD:` note in the eight lines above.
        let lines: Vec<&str> = source.lines().collect();
        for (index, line) in lines.iter().enumerate() {
            for forbidden in [
                "Handler(",
                "Looper.",
                "postDelayed",
                "runOnUiThread",
                "Dispatchers.Main",
            ] {
                let code = line
                    .find("//")
                    .map_or(*line, |at| line.get(..at).unwrap_or(""));
                if !code.contains(forbidden) {
                    continue;
                }
                let window_start = index.saturating_sub(8);
                let justified = lines
                    .get(window_start..=index)
                    .unwrap_or_default()
                    .iter()
                    .any(|l| l.contains("UI-THREAD:"));
                if !justified {
                    problems.push(format!(
                        "{name}:{}: `{forbidden}` with no `UI-THREAD:` note within eight \
                         lines above. A bridge method dispatches to a native thread and \
                         returns; if this really must touch the UI thread, say why.",
                        index + 1
                    ));
                }
            }
        }
    }

    let wrapper = without_comments(&read("apps/mobile/modules/chiavora-core/index.ts"));
    for forbidden in ["setTimeout", "setInterval", "requestAnimationFrame"] {
        if wrapper.contains(forbidden) {
            problems.push(format!(
                "modules/chiavora-core/index.ts: contains `{forbidden}`. JavaScript is the \
                 caller; it schedules nothing that must complete while the app is not \
                 foregrounded."
            ));
        }
    }

    assert!(
        problems.is_empty(),
        " violations:\n {}",
        problems.join("\n  ")
    );
}

#[test]
fn the_bridge_scan_would_notice_a_synchronous_core_call() {
    let synchronous = r#"
        import uniffi.chiavora_ffi_mobile.ffiSmoke
        class M : Module() {
            override fun definition() = ModuleDefinition {
                Function("ffiSmoke") { ffiSmoke() }
            }
        }
    "#;
    let blocks = registration_blocks(synchronous, "Function");
    assert_eq!(blocks.len(), 1, "the block finder missed a `Function`");
    assert!(
        blocks.first().is_some_and(|b| b.contains("ffiSmoke")),
        "the block finder did not capture the body"
    );

    let asynchronous = r#"
        import uniffi.chiavora_ffi_mobile.ffiSmoke
        AsyncFunction("ffiSmoke") { ffiSmoke() }
    "#;
    assert!(
        registration_blocks(asynchronous, "Function").is_empty(),
        "`AsyncFunction` was counted as a synchronous `Function`"
    );
    assert_eq!(
        registration_blocks(asynchronous, "AsyncFunction").len(),
        1,
        "the block finder missed an `AsyncFunction`"
    );

    let prose = "// a JS setTimeout does not fire when backgrounded
const x = 1;
";
    assert!(
        !without_comments(prose).contains("setTimeout"),
        "comment stripping missed a line comment, so the scan reads prose"
    );
    let block = "/* Handler( and Looper. are named here on purpose */
const y = 2;
";
    assert!(
        !without_comments(block).contains("Handler("),
        "comment stripping missed a block comment"
    );
    assert!(
        without_comments("const z = 3; // tail").contains("const z = 3;"),
        "comment stripping ate the code"
    );

    let total: usize = bridge_kotlin()
        .iter()
        .map(|(_, src)| {
            registration_blocks(src, "AsyncFunction").len()
                + registration_blocks(src, "Function").len()
        })
        .sum();
    assert!(
        total >= 3,
        "the bridge scan found only {total} registrations; it is not reading the module"
    );
}

fn kotlin_fn_body(source: &str, name: &str) -> Option<String> {
    let at = source.find(&format!("fun {name}"))?;
    let after = source.get(at..)?;
    let brace = after.find('{')?;
    let mut depth = 0_usize;
    for (i, ch) in after.char_indices().skip(brace) {
        if ch == '{' {
            depth += 1;
        } else if ch == '}' {
            depth -= 1;
            if depth == 0 {
                return after.get(brace..=i).map(str::to_owned);
            }
        }
    }
    None
}

#[test]
fn i8_the_secret_key_entry_is_not_biometric_bound() {
    let source = without_comments(&read(
        "apps/mobile/modules/chiavora-core/android/src/main/java/ch/chiavora/core/DeviceKeys.kt",
    ));

    let muk = kotlin_fn_body(&source, "createMukWrappingKey")
        .expect("createMukWrappingKey must exist -- I8's paired assertion rests on it");
    let secret = kotlin_fn_body(&source, "createSecretKeyEntry")
        .expect("createSecretKeyEntry must exist -- it is the entry I8 is about");

    // The MUK's key must carry both calls, so the absence check below is not vacuous.
    for required in [
        "setUserAuthenticationRequired(true)",
        "setInvalidatedByBiometricEnrollment(true)",
    ] {
        assert!(
            muk.contains(required),
            "the MUK's wrapping key no longer sets {required}. Either the key is no longer \
             biometric-bound -- which §3.3 requirement 1 forbids -- or this scan has stopped \
             reading the function, in which case I8's half below is passing vacuously."
        );
    }

    for forbidden in [
        "setUserAuthenticationRequired(true)",
        "setInvalidatedByBiometricEnrollment(true)",
    ] {
        assert!(
            !secret.contains(forbidden),
            "I8 VIOLATED: the Secret Key's keystore entry calls {forbidden}.\n\
             This looks like hardening and is a regression: a user enrolling a second \
             fingerprint would lose the Secret Key and need their Emergency Kit for a routine \
             change. docs/security-design.md §2.4 (v0.27) has the reasoning. The Secret Key defends against an \
             attacker holding the encrypted data WITHOUT the device (A3); it is not a defence \
             against the device's owner."
        );
    }

    assert!(
        source.contains("MUK_WRAPPING_KEY_ALIAS") && source.contains("SECRET_KEY_ALIAS"),
        "both aliases must be named constants in this file"
    );
}

#[test]
fn the_i8_scan_would_notice_a_bound_secret_key_and_an_unbound_muk() {
    let good = r"
        fun createMukWrappingKey(): SecretKey {
            return generate { b -> b.setUserAuthenticationRequired(true).setInvalidatedByBiometricEnrollment(true) }
        }
        fun createSecretKeyEntry(): SecretKey {
            return generate { b -> b }
        }
    ";
    let muk = kotlin_fn_body(good, "createMukWrappingKey").expect("finds the MUK body");
    let secret = kotlin_fn_body(good, "createSecretKeyEntry").expect("finds the Secret Key body");
    assert!(muk.contains("setInvalidatedByBiometricEnrollment(true)"));
    assert!(!secret.contains("setInvalidatedByBiometricEnrollment(true)"));

    let hardened = good.replace(
        "fun createSecretKeyEntry(): SecretKey {\n            return generate { b -> b }",
        "fun createSecretKeyEntry(): SecretKey {\n            return generate { b -> b.setInvalidatedByBiometricEnrollment(true) }",
    );
    let secret = kotlin_fn_body(&hardened, "createSecretKeyEntry").expect("finds it");
    assert!(
        secret.contains("setInvalidatedByBiometricEnrollment(true)"),
        "the witness did not actually introduce the regression it is testing for"
    );

    assert!(
        kotlin_fn_body(good, "createSomethingThatDoesNotExist").is_none(),
        "the body finder must return None for a missing function, so the presence \
         half fails loudly rather than the absence half passing quietly"
    );
}

const CRATES_ABOVE_CORE: [&str; 4] = [
    "crates/ffi-mobile/src",
    "crates/ffi-node/src",
    "crates/server/src",
    "apps/cli/src",
];

#[test]
fn the_muk_has_one_door_back_into_core() {
    let mut problems: Vec<String> = Vec::new();

    for dir in CRATES_ABOVE_CORE {
        let mut files = Vec::new();
        rs_files_under(&root().join(dir), &mut files);
        for path in files {
            let source = production(&std::fs::read_to_string(&path).expect("a source file"));
            if source.contains("from_derived_bytes") {
                let name = path.to_string_lossy().replace('\\', "/");
                let short = name.rsplit("chiavora/").next().unwrap_or(&name).to_owned();
                problems.push(format!(
                    "{short} calls `Secret::from_derived_bytes`. The one door for key \
                     material re-entering `core` from a platform keystore is \
                     `device::muk_from_keystore`, which carries the justification and the \
                     length check. See `docs/crypto.md`'s R4 deviation on §3.3 requirement 2."
                ));
            }
        }
    }

    assert!(
        problems.is_empty(),
        "the MUK's door is no longer single:\n  {}",
        problems.join("\n  ")
    );

    let device = production(&read("crates/core/src/device.rs"));
    assert!(
        device.contains("fn muk_from_keystore"),
        "`device::muk_from_keystore` is gone. It is the door the check above assumes exists"
    );
    assert!(
        device.contains("from_derived_bytes"),
        "`muk_from_keystore` no longer calls `from_derived_bytes`, so the scan above is \
         asserting that nobody uses a door that does nothing"
    );

    let manifest = read("Cargo.toml");
    for member in [
        "crates/ffi-mobile",
        "crates/ffi-node",
        "crates/server",
        "apps/cli",
    ] {
        assert!(
            manifest.contains(member),
            "{member} is no longer a workspace member; CRATES_ABOVE_CORE is stale"
        );
    }
    let declared =
        manifest.matches("    \"crates/").count() + manifest.matches("    \"apps/").count();
    assert_eq!(
        declared,
        CRATES_ABOVE_CORE.len() + 2,
        "the workspace has {declared} members and this scan covers {} plus core and protocol. \
         A new crate above `core` must be added to CRATES_ABOVE_CORE, or it is not scanned.",
        CRATES_ABOVE_CORE.len()
    );
}

#[test]
fn the_store_key_is_still_derived_from_the_muk() {
    // A substituted MUK blob is caught only because the Store Key derives from the MUK.
    let derive = production(&read("crates/core/src/derive.rs"));
    let body = derive
        .split("pub fn derive_store_key")
        .nth(1)
        .and_then(|rest| rest.split("\n}").next())
        .expect("derive_store_key must exist");

    assert!(
        body.contains("hkdf_sha256(muk.expose()"),
        "the Store Key is no longer derived with the MUK as its HKDF ikm.\n\
         `docs/crypto.md` declines AAD record type 0x06 for the device-wrapped MUK because a \
         substituted blob is self-detecting: a different MUK derives a different Store Key and \
         the metadata MAC fails on open. That argument rests on this line. If the derivation \
         has genuinely changed, 0x06 has to come back -- and I3's \"five record types\" wording, \
         the injectivity suite and ADR-0002 come with it."
    );
    assert!(
        body.contains("INFO_STORE"),
        "the Store Key's domain separator changed; check the argument above still holds"
    );

    let crypto = read("docs/crypto.md");
    assert!(
        crypto.contains("No sixth AAD record type"),
        "`docs/crypto.md` no longer records why 0x06 was declined, so this test is guarding \
         an argument the document does not make"
    );
}

#[derive(Debug, Clone, Copy)]
enum Placement {
    NearTheTop,
    AboveTheTestCode,
    BelowTheTestModule,
}

/// In memory, so tests running in parallel never see a modified file on disk.
fn with_violation(real_source: &str, violation: &str, at: Placement) -> String {
    let lines: Vec<&str> = real_source.lines().collect();
    let marker = concat!("#[cfg(", "test)]");
    let insert_at = match at {
        // `import` and `internal` cover Kotlin.
        Placement::NearTheTop => lines
            .iter()
            .position(|l| {
                l.starts_with("use ")
                    || l.starts_with("pub ")
                    || l.starts_with("import ")
                    || l.starts_with("internal ")
            })
            .unwrap_or(0),
        Placement::AboveTheTestCode => lines
            .iter()
            .position(|l| l.trim() == marker)
            .unwrap_or(lines.len()),
        Placement::BelowTheTestModule => lines.len(),
    };
    let mut out: Vec<String> = lines.iter().map(|l| (*l).to_owned()).collect();
    out.insert(insert_at.min(out.len()), violation.to_owned());
    out.join("\n") + "\n"
}

const EVERY_PLACEMENT: [Placement; 3] = [
    Placement::NearTheTop,
    Placement::AboveTheTestCode,
    Placement::BelowTheTestModule,
];

#[test]
fn the_r1_absorbing_scan_fires_on_a_violation_planted_in_a_real_module() {
    let modules = core_modules();
    assert!(!modules.is_empty(), "the scan reads no modules at all");

    for at in EVERY_PLACEMENT {
        let poisoned: Vec<(String, String)> = modules
            .iter()
            .map(|(name, source)| {
                if name == "derive.rs" {
                    (
                        name.clone(),
                        with_violation(
                            source,
                            "pub fn planted() { let _ = None::<u8>.unwrap_or(0); }",
                            at,
                        ),
                    )
                } else {
                    (name.clone(), source.clone())
                }
            })
            .collect();

        let problems = r1_absorbing_problems(&poisoned);
        assert!(
            problems.iter().any(|p| p.contains("derive.rs")),
            "R1's absorbing scan did not see an unjustified `unwrap_or` planted in the real \
             `derive.rs` at {at:?}. The scan passes its own suite and is blind to this \
             position -- which is what R7 cases 7 and 10 were. Check `production_mask`."
        );
    }

    assert!(
        r1_absorbing_problems(&modules).is_empty(),
        "the scan reports problems on the real tree, so a planted one proves nothing"
    );
}

#[test]
fn the_muk_door_scan_fires_on_a_violation_planted_in_a_real_crate() {
    let path = root().join("crates/ffi-mobile/src/lib.rs");
    let real = std::fs::read_to_string(&path).expect("ffi-mobile's lib.rs");

    for at in EVERY_PLACEMENT {
        let poisoned = production(&with_violation(
            &real,
            "pub fn planted(b: Vec<u8>) { let _ = Secret::<Muk>::from_derived_bytes(b); }",
            at,
        ));
        assert!(
            poisoned.contains("from_derived_bytes"),
            "the door scan's reading of a real crate file is blind at {at:?}: a planted call \
             to `from_derived_bytes` is not in what it would scan. This is exactly how case 10 \
             was found -- a violation planted below the test module that nothing saw."
        );
    }

    assert!(
        !production(&real).contains("from_derived_bytes"),
        "ffi-mobile already calls `from_derived_bytes`; the witness proves nothing"
    );
}

#[test]
fn the_r1_capacity_scan_fires_on_a_reservation_planted_in_a_real_module() {
    let modules: Vec<(String, String)> = core_modules()
        .into_iter()
        .chain(protocol_modules())
        .collect();
    for at in EVERY_PLACEMENT {
        let poisoned: Vec<(String, String)> = modules
            .iter()
            .map(|(name, source)| {
                if name == "zip.rs" {
                    (
                        name.clone(),
                        with_violation(
                            source,
                            "pub fn planted(declared: usize) { let _v: Vec<u8> = Vec::with_capacity(declared); }",
                            at,
                        ),
                    )
                } else {
                    (name.clone(), source.clone())
                }
            })
            .collect();
        let problems = r1_capacity_problems(&poisoned);
        assert!(
            problems.iter().any(|p| p.contains("zip.rs")),
            "R1's capacity scan did not see an unjustified `Vec::with_capacity(declared)` \
             planted in the real `zip.rs` at {at:?} -- the file the corollary's own incident \
             came from."
        );
    }
    assert!(
        r1_capacity_problems(&modules).is_empty(),
        "the scan reports problems on the real tree, so a planted one proves nothing"
    );
}

#[test]
fn the_bridge_scan_fires_on_a_synchronous_core_call_planted_in_the_real_module() {
    // Kotlin has no `#[cfg(test)]`, so `AboveTheTestCode` lands at the end of the file.
    let path = root()
        .join("apps/mobile/modules/chiavora-core/android/src/main/java/ch/chiavora/core/ChiavoraCoreModule.kt");
    let real = std::fs::read_to_string(&path).expect("the bridge module");

    for at in EVERY_PLACEMENT {
        let poisoned = without_comments(&with_violation(
            &real,
            "        Function(\"planted\") { ffiSmoke() }",
            at,
        ));
        let blocks = registration_blocks(&poisoned, "Function");
        assert!(
            blocks.iter().any(|b| b.contains("ffiSmoke")),
            "the bridge scan did not see a synchronous `Function` calling into `core` planted \
             in the real module at {at:?}. A scan that cannot see a planted violation cannot \
             see a real one."
        );
    }

    let clean = without_comments(&real);
    assert!(
        registration_blocks(&clean, "Function")
            .iter()
            .all(|b| !b.contains("ffiSmoke")),
        "the real bridge module already has a synchronous `core` call; the witness proves nothing"
    );
}

#[test]
fn the_i8_scan_fires_on_a_binding_planted_in_the_real_keystore_code() {
    let path = root().join(
        "apps/mobile/modules/chiavora-core/android/src/main/java/ch/chiavora/core/DeviceKeys.kt",
    );
    let real = std::fs::read_to_string(&path).expect("the keystore code");

    let poisoned = without_comments(&real.replace(
        ") { builder -> builder }",
        ") { builder -> builder.setInvalidatedByBiometricEnrollment(true) }",
    ));
    let secret = kotlin_fn_body(&poisoned, "createSecretKeyEntry")
        .expect("createSecretKeyEntry must still be findable in the poisoned source");
    assert!(
        secret.contains("setInvalidatedByBiometricEnrollment(true)"),
        "I8's scan cannot see the Secret Key's entry being bound to the biometric in the real \
         file. That is the one regression it exists to catch, and it would read as hardening \
         in review."
    );

    let clean = without_comments(&real);
    let muk = kotlin_fn_body(&clean, "createMukWrappingKey").expect("the MUK's builder");
    assert!(
        muk.contains("setInvalidatedByBiometricEnrollment(true)"),
        "the MUK's entry is not biometric-bound in the real file"
    );
}

fn call_sites(source: &str, name: &str) -> Vec<(usize, bool)> {
    let lines: Vec<&str> = source.lines().collect();
    let mask = production_mask(&lines);
    let needle = format!("{name}(");
    lines
        .iter()
        .enumerate()
        .filter(|(index, line)| {
            let code = line
                .find("//")
                .map_or(**line, |at| line.get(..at).unwrap_or(""));
            // The definition is not a call site.
            !code.contains("fn ") && code.contains(&needle) && *index < mask.len()
        })
        .map(|(index, _)| (index + 1, mask.get(index).copied().unwrap_or(false)))
        .collect()
}

#[test]
fn no_hardware_backing_predicate_is_called_only_by_its_own_tests() {
    let device = root()
        .join("crates")
        .join("core")
        .join("src")
        .join("device.rs");
    let source = std::fs::read_to_string(&device).expect("device.rs");

    assert!(
        source.contains("pub const fn is_hardware_backed"),
        "device.rs no longer defines `is_hardware_backed` -- this scan is \
         asserting something about a function that is not there"
    );
    assert!(
        source.contains("pub const fn check_enrolment_backing"),
        "device.rs no longer defines `check_enrolment_backing`, which is the \
         enrolment path's refusal (D2)"
    );

    let sites = call_sites(&source, "is_hardware_backed");
    let production: Vec<usize> = sites
        .iter()
        .filter(|(_, in_production)| *in_production)
        .map(|(line, _)| *line)
        .collect();
    assert!(
        !production.is_empty(),
        "`is_hardware_backed` has {} call site(s) and every one of them is in a \
         test module. A predicate nothing production calls is a check that does \
         not run -- which is exactly what D2 was raised about.",
        sites.len()
    );

    let stripped = without_comments(&source);
    let enrolment = stripped
        .split("pub const fn check_enrolment_backing")
        .nth(1)
        .unwrap_or_default();
    let body = enrolment.split("\n}").next().unwrap_or_default();
    assert!(
        body.contains("is_hardware_backed"),
        "`check_enrolment_backing` no longer consults `is_hardware_backed`, so \
         the enrolment path's refusal is decided by something else"
    );
}

#[test]
fn the_call_site_scan_tells_a_production_caller_from_a_test_one() {
    let only_in_tests = "
pub const fn is_hardware_backed(self) -> bool { true }

#[cfg(test)]
mod tests {
    #[test]
    fn t() {
        assert!(is_hardware_backed(x));
    }
}
";
    let also_in_production = "
pub const fn is_hardware_backed(self) -> bool { true }

pub const fn check_enrolment_backing(b: B) -> Result<(), E> {
    if is_hardware_backed(b) { Ok(()) } else { Err(E) }
}

#[cfg(test)]
mod tests {
    #[test]
    fn t() {
        assert!(is_hardware_backed(x));
    }
}
";

    let tests_only: Vec<usize> = call_sites(only_in_tests, "is_hardware_backed")
        .into_iter()
        .filter(|(_, p)| *p)
        .map(|(line, _)| line)
        .collect();
    let with_caller: Vec<usize> = call_sites(also_in_production, "is_hardware_backed")
        .into_iter()
        .filter(|(_, p)| *p)
        .map(|(line, _)| line)
        .collect();

    assert!(
        tests_only.is_empty(),
        "a predicate called only inside `#[cfg(test)]` reported a production \
         caller at {tests_only:?} -- the mask is not masking"
    );
    assert!(
        !with_caller.is_empty(),
        "a predicate called from a production function reported no production \
         caller -- the detector is not reading its argument"
    );
    assert_ne!(
        tests_only, with_caller,
        "the detector gave the same answer for both inputs"
    );
}

const SCANS_AND_THEIR_WITNESSES: [(&str, bool); 9] = [
    ("r1_every_absorbing_pattern_carries_a_justification", true),
    ("r1_no_capacity_is_reserved_from_an_unbounded_claim", true),
    (
        "r3_getrandom_is_called_in_exactly_one_place_in_the_crate",
        true,
    ),
    ("the_muk_has_one_door_back_into_core", true),
    ("no_bridge_method_runs_core_on_the_js_thread", true),
    ("i8_the_secret_key_entry_is_not_biometric_bound", true),
    ("no_biometric_callback_hands_the_caller_a_flag", true),
    (
        "no_keystore_alias_check_stands_in_for_a_usability_check",
        true,
    ),
    (
        "no_hardware_backing_predicate_is_called_only_by_its_own_tests",
        true,
    ),
];

const SCANS_STILL_IN_THEIR_MODULES: [(&str, &str); 2] = [
    (
        "crates/core/src/nonce.rs",
        "i2_generate_is_the_only_fresh_nonce_source",
    ),
    (
        "crates/core/src/secret.rs",
        "only_the_brand_macro_grants_a_provenance",
    ),
];

#[test]
fn every_scan_without_a_real_file_witness_is_listed_as_such() {
    let suite = read("crates/core/tests/rules_are_mechanised.rs");
    for (scan, _) in SCANS_AND_THEIR_WITNESSES {
        assert!(
            suite.contains(&format!("fn {scan}(")),
            "{scan} is listed here but does not exist in this file"
        );
    }

    for (file, scan) in SCANS_STILL_IN_THEIR_MODULES {
        let source = read(file);
        assert!(
            source.contains(&format!("fn {scan}(")),
            "{scan} is no longer in {file}. A scan outside this registry that has moved is \
             a scan nothing here is tracking"
        );
    }

    let covered = SCANS_AND_THEIR_WITNESSES
        .iter()
        .filter(|(_, has)| *has)
        .count();
    assert_eq!(
        covered,
        SCANS_AND_THEIR_WITNESSES.len(),
        "the count changed without this assertion being updated: real-file witnesses are \
         owed for the rows marked false, and moving a row to `true` should be a deliberate \
         edit here as well as a new test"
    );
}

fn r3_draw_sites(modules: &[(String, String)]) -> Vec<String> {
    modules
        .iter()
        .filter(|(_, source)| {
            let code = production(source);
            code.contains("getrandom::fill") || code.contains("use getrandom")
        })
        .map(|(name, _)| name.clone())
        .collect()
}

#[test]
fn r3_getrandom_is_called_in_exactly_one_place_in_the_crate() {
    let modules = core_modules();
    assert!(
        modules.len() >= 8,
        "expected every module in crates/core/src, found {} — a scan that reads \
         nothing reports success",
        modules.len()
    );
    for required in ["generate.rs", "csprng.rs"] {
        assert!(
            modules.iter().any(|(name, _)| name == required),
            "the module list must include {required}"
        );
    }

    let sites = r3_draw_sites(&modules);
    assert_eq!(
        sites,
        vec!["csprng.rs".to_owned()],
        "R3: randomness must be drawn in exactly one module, and it must be `csprng.rs`"
    );
}

#[test]
fn the_r3_scan_fires_on_a_draw_planted_in_a_real_module() {
    let modules = core_modules();
    for at in EVERY_PLACEMENT {
        let poisoned: Vec<(String, String)> = modules
            .iter()
            .map(|(name, source)| {
                if name == "generate.rs" {
                    (
                        name.clone(),
                        with_violation(
                            source,
                            "pub fn planted() { getrandom::fill(&mut []); }",
                            at,
                        ),
                    )
                } else {
                    (name.clone(), source.clone())
                }
            })
            .collect();
        let sites = r3_draw_sites(&poisoned);
        let clean = r3_draw_sites(&modules);
        assert!(
            !clean.iter().any(|n| n == "generate.rs"),
            "`generate.rs` already draws randomness; the witness proves nothing"
        );
        assert_ne!(
            sites, clean,
            "R3's scan gave the same answer for a poisoned and a clean tree at {at:?} -- it is              not reading the slice it was handed"
        );
        assert!(
            sites.iter().any(|n| n == "generate.rs"),
            "R3's scan did not see a `getrandom::fill` planted in the real `generate.rs` at \
             {at:?}. This is the scan whose second-copy masking helper was blind to 57% of \
             `ffi_guard.rs`."
        );
    }
}

#[test]
fn r3_generate_rs_does_not_draw_directly() {
    let code = production(&read("crates/core/src/generate.rs"));
    assert!(
        !code.contains("getrandom"),
        "R3: `generate.rs` must go through `csprng`, not `getrandom`"
    );
}

#[test]
fn every_detector_taking_a_source_slice_has_a_differential_witness() {
    let suite = read("crates/core/tests/rules_are_mechanised.rs");
    let detectors: Vec<String> = suite
        .lines()
        .filter_map(|line| {
            let rest = line.strip_prefix("fn ")?;
            let name = rest.split('(').next()?;
            rest.contains("&[(String, String)]")
                .then(|| name.to_owned())
        })
        .collect();

    assert!(
        !detectors.is_empty(),
        "no detectors found -- this check is reading nothing and reporting success"
    );

    for detector in &detectors {
        // Its scan, plus a witness calling it on a poisoned and a clean input.
        let calls = suite.matches(&format!("{detector}(&")).count();
        assert!(
            calls >= 3,
            "`{detector}` is called {calls} time(s) -- its scan, and a witness that runs it \
             on both a poisoned and a clean input. Fewer than three means there is no \
             differential witness, and an absolute one passes for a detector that ignores \
             its argument."
        );
    }
}

fn biometric_callback_problems(source: &str) -> Vec<String> {
    let code = without_comments(source);
    if !code.contains("AuthenticationCallback") {
        return Vec::new();
    }
    let mut problems = Vec::new();

    let Some(body) = kotlin_fn_body(&code, "onAuthenticationSucceeded") else {
        problems.push(
            "a file with an `AuthenticationCallback` has no findable \
             `onAuthenticationSucceeded` body -- the scan cannot see what it does"
                .to_owned(),
        );
        return problems;
    };

    if !body.contains("cryptoObject") {
        problems.push(
            "`onAuthenticationSucceeded` never reads `result.cryptoObject`: the flow continues \
             on the fact that authentication succeeded rather than on the key the OS released. \
             That fact is a boolean a patched APK or a hooked callback can forge (§3.3 \
             requirement 1)."
                .to_owned(),
        );
    }

    for forbidden in ["resume(true)", "resume(Unit)", "resume(false)"] {
        if body.contains(forbidden) {
            problems.push(format!(
                "`onAuthenticationSucceeded` calls `{forbidden}`: the caller is being handed a \
                 flag instead of the authenticated `Cipher`, so it can proceed to key material \
                 without the object the OS unlocked. Resume with the cipher."
            ));
        }
    }

    problems
}

#[test]
fn no_biometric_callback_hands_the_caller_a_flag() {
    let mut problems: Vec<String> = Vec::new();
    let mut files_with_callbacks = 0_usize;

    let dir = root()
        .join("apps")
        .join("mobile")
        .join("modules")
        .join("chiavora-core")
        .join("android")
        .join("src");
    let mut files = Vec::new();
    files_under(&dir, "kt", &mut files);

    for path in files {
        let name = path.to_string_lossy().replace('\\', "/");
        if name.contains("/generated/") {
            continue;
        }
        let source = std::fs::read_to_string(&path).expect("a Kotlin file");
        if !without_comments(&source).contains("AuthenticationCallback") {
            continue;
        }
        files_with_callbacks += 1;
        for problem in biometric_callback_problems(&source) {
            let short = name.rsplit("/core/").next().unwrap_or(&name).to_owned();
            problems.push(format!("{short}: {problem}"));
        }
    }

    assert!(
        files_with_callbacks >= 1,
        "no `AuthenticationCallback` found in the bridge module. Either the biometric unlock \
         is gone -- which is the thing §3.3 requirement 1 is about -- or this scan has stopped \
         reading the files it names."
    );
    assert!(
        problems.is_empty(),
        "the biometric no longer binds the key:\n  {}",
        problems.join("\n  ")
    );
}

#[test]
fn the_biometric_scan_would_notice_a_flag_and_a_missing_crypto_object() {
    let good = r"
        object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                val unlocked = result.cryptoObject?.cipher
                continuation.resume(unlocked)
            }
        }
    ";
    assert!(
        biometric_callback_problems(good).is_empty(),
        "the real shape must be accepted: {:?}",
        biometric_callback_problems(good)
    );

    let simplified = r"
        object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                continuation.resume(true)
            }
        }
    ";
    let problems = biometric_callback_problems(simplified);
    assert_ne!(
        problems,
        biometric_callback_problems(good),
        "the detector gave the same answer for a bound and an unbound callback"
    );
    assert!(
        problems.iter().any(|p| p.contains("resume(true)")),
        "the flag was not reported: {problems:?}"
    );
    assert!(
        problems.iter().any(|p| p.contains("cryptoObject")),
        "the missing CryptoObject was not reported: {problems:?}"
    );

    assert!(biometric_callback_problems("class Unrelated { }").is_empty());
}

fn keystore_precondition_problems(source: &str) -> Vec<String> {
    let stripped = without_comments(source);
    if !stripped.contains("KEY_ALIAS") && !stripped.contains("KeyStore") {
        return Vec::new();
    }

    // The original lines, so line numbers match where the note is looked up.
    let lines: Vec<&str> = source.lines().collect();
    let mut problems = Vec::new();

    for (index, line) in lines.iter().enumerate() {
        let code = line
            .find("//")
            .map_or(*line, |at| line.get(..at).unwrap_or(""));
        // `if (!exists(alias)) create()`; `if (exists) delete; create` is fine.
        let negated_existence =
            code.contains('!') && (code.contains("exists(") || code.contains("containsAlias("));
        if !negated_existence {
            continue;
        }
        let creates = lines
            .get(index..=(index + 3).min(lines.len().saturating_sub(1)))
            .unwrap_or_default()
            .iter()
            .any(|l| {
                l.find("//")
                    .map_or(*l, |at| l.get(..at).unwrap_or(""))
                    .contains("create")
            });
        if !creates {
            continue;
        }
        let window_start = index.saturating_sub(8);
        let justified = lines
            .get(window_start..=index)
            .unwrap_or_default()
            .iter()
            .any(|l| l.contains("USABLE-NOT-EXISTS:"));
        if !justified {
            problems.push(format!(
                "{}: `if (!exists(...))` decides whether to create a key. **An                  invalidated key keeps its alias**, so this skips a recreate that                  was needed and the next use throws                  `KeyPermanentlyInvalidatedException`. Delete and recreate                  unconditionally, or write a `USABLE-NOT-EXISTS:` note saying why                  the alias's presence is the right question here.",
                index + 1
            ));
        }
    }
    problems
}

#[test]
fn no_keystore_alias_check_stands_in_for_a_usability_check() {
    let dir = root()
        .join("apps")
        .join("mobile")
        .join("modules")
        .join("chiavora-core")
        .join("android")
        .join("src");
    let mut files = Vec::new();
    files_under(&dir, "kt", &mut files);

    let mut problems: Vec<String> = Vec::new();
    let mut files_touching_the_keystore = 0_usize;
    for path in files {
        let name = path.to_string_lossy().replace('\\', "/");
        if name.contains("/generated/") {
            continue;
        }
        let source = std::fs::read_to_string(&path).expect("a Kotlin file");
        let stripped = without_comments(&source);
        if !stripped.contains("KEY_ALIAS") && !stripped.contains("KeyStore") {
            continue;
        }
        files_touching_the_keystore += 1;
        let short = name.rsplit("/core/").next().unwrap_or(&name).to_owned();
        for problem in keystore_precondition_problems(&source) {
            problems.push(format!("{short}:{problem}"));
        }
    }

    assert!(
        files_touching_the_keystore >= 1,
        "no keystore code found in the bridge module -- this scan is reading nothing"
    );
    assert!(
        problems.is_empty(),
        "an alias check is standing in for a usability check:\n  {}",
        problems.join("\n  ")
    );
}

#[test]
fn the_usability_scan_would_notice_the_incident_it_was_written_for() {
    let guarded = "
        object DeviceKeys { val MUK_KEY_ALIAS = \"a\"
            fun go() {
                if (!DeviceKeys.exists(MUK_KEY_ALIAS)) {
                    DeviceKeys.createMukWrappingKey()
                }
            }
        }
    ";
    let unconditional = "
        object DeviceKeys { val MUK_KEY_ALIAS = \"a\"
            fun go() {
                if (DeviceKeys.exists(MUK_KEY_ALIAS)) {
                    DeviceKeys.delete(MUK_KEY_ALIAS)
                }
                DeviceKeys.createMukWrappingKey()
            }
        }
    ";

    let guarded_problems = keystore_precondition_problems(guarded);
    let fixed_problems = keystore_precondition_problems(unconditional);

    assert!(
        !guarded_problems.is_empty(),
        "the scan did not notice an `exists` guard around a create -- the exact shape of \
          incident"
    );
    assert_ne!(
        guarded_problems, fixed_problems,
        "the detector gave the same answer for the broken shape and the fixed one, so it is \
         not reading its argument"
    );
    assert!(
        fixed_problems.is_empty(),
        "delete-then-create-unconditionally must be accepted: {fixed_problems:?}"
    );

    assert!(keystore_precondition_problems("class Unrelated {}").is_empty());
}

/// The nine domains Android's `data-extraction-rules` defines, listed here
/// independently of the plugin so a domain dropped from it is noticed.
const EXTRACTION_DOMAINS: [&str; 9] = [
    "root",
    "file",
    "database",
    "sharedpref",
    "external",
    "device_root",
    "device_file",
    "device_database",
    "device_sharedpref",
];

fn backup_exclusion_problems(app_json: &str, plugin: &str) -> Vec<String> {
    let mut problems = Vec::new();

    let compact: String = app_json.split_whitespace().collect();

    if !compact.contains("\"allowBackup\":false") {
        problems.push(
            "app.json: expo.android.allowBackup is not false. Cloud backup is governed by \
             this attribute and nothing else; the XML rules cover device-to-device transfer \
             only."
                .to_owned(),
        );
    }
    if compact.contains("\"allowBackup\":true") {
        problems.push("app.json: expo.android.allowBackup is explicitly true".to_owned());
    }
    if !compact.contains("\"./plugins/with-chiavora-backup\"") {
        problems.push(
            "app.json: with-chiavora-backup is not in expo.plugins, so the generated \
             manifest points at no dataExtractionRules and device-to-device transfer is \
             unrestricted — which `allowBackup` does not cover on API 31+."
                .to_owned(),
        );
    }

    // `<device-transfer>` is the one that looks redundant and is not.
    for required in ["<cloud-backup>", "<device-transfer>"] {
        if !plugin.contains(required) {
            problems.push(format!(
                "with-chiavora-backup.js: no `{required}` section. On API 31+ these are \
                 two different transports and excluding one excludes one."
            ));
        }
    }
    for domain in EXTRACTION_DOMAINS {
        if !plugin.contains(&format!("'{domain}'")) {
            problems.push(format!(
                "with-chiavora-backup.js: the domain `{domain}` is not in DOMAINS. An \
                 unexcluded domain is a backed-up domain — the rules file includes \
                 everything it does not name."
            ));
        }
    }
    if !plugin.contains("allowBackup !== false") {
        problems.push(
            "with-chiavora-backup.js: the plugin no longer refuses an app.json whose \
             allowBackup is not false. Half is not a partial mitigation."
                .to_owned(),
        );
    }

    problems
}

#[test]
fn the_vault_database_is_excluded_from_backup_and_device_transfer() {
    let problems = backup_exclusion_problems(
        &read("apps/mobile/app.json"),
        &read("apps/mobile/plugins/with-chiavora-backup.js"),
    );
    assert!(
        problems.is_empty(),
        " violations:\n {}",
        problems.join("\n  ")
    );
}

#[test]
fn the_backup_scan_would_notice_each_half_going_missing() {
    let good_json = read("apps/mobile/app.json");
    let good_plugin = read("apps/mobile/plugins/with-chiavora-backup.js");
    assert!(
        backup_exclusion_problems(&good_json, &good_plugin).is_empty(),
        "the real files must be the passing case, or the mutations below prove nothing"
    );

    let mutations: [(&str, String, String); 5] = [
        (
            "allowBackup flipped to true",
            good_json.replace("\"allowBackup\": false", "\"allowBackup\": true"),
            good_plugin.clone(),
        ),
        (
            "allowBackup removed entirely",
            good_json.replace("\"allowBackup\": false", ""),
            good_plugin.clone(),
        ),
        (
            "the plugin unregistered",
            good_json.replace("\"./plugins/with-chiavora-backup\"", "\"expo-font\""),
            good_plugin.clone(),
        ),
        (
            "<device-transfer> deleted as redundant",
            good_json.clone(),
            good_plugin.replace("<device-transfer>", "<!-- gone -->"),
        ),
        (
            // No `\n` in the needle, so it still matches a CRLF checkout.
            "a domain dropped from DOMAINS",
            good_json.clone(),
            good_plugin.replace("'device_sharedpref',", ""),
        ),
    ];

    for (what, json, plugin) in mutations {
        // Not `assert_ne!`, so a failure names the mutation instead of printing two files.
        assert!(
            json != good_json || plugin != good_plugin,
            "the mutation '{what}' changed nothing, so it tests nothing — the string it \
             replaces is no longer in the file it replaces it in"
        );
        assert!(
            !backup_exclusion_problems(&json, &plugin).is_empty(),
            "the scan accepted '{what}'"
        );
    }
}

/// One row per generator-policy knob: its struct, whether it may move the
/// reported entropy, and the test that asserts so.
const GENERATOR_KNOBS: [(&str, &str, bool, &str); 7] = [
    (
        "Policy",
        "length",
        true,
        "entropy_is_arithmetic_over_the_alphabet",
    ),
    (
        "Policy",
        "classes",
        true,
        "entropy_is_arithmetic_over_the_alphabet",
    ),
    (
        "Policy",
        "exclude_ambiguous",
        true,
        "excluding_ambiguous_characters_lowers_the_reported_entropy",
    ),
    (
        "Policy",
        "require_one_of_each",
        false,
        "requiring_one_of_each_changes_the_output_and_not_the_reported_entropy",
    ),
    (
        "PassphrasePolicy",
        "words",
        true,
        "entropy_is_words_times_log2_of_the_list",
    ),
    (
        "PassphrasePolicy",
        "separator",
        false,
        "the_separator_changes_the_output_and_not_the_entropy",
    ),
    (
        "PassphrasePolicy",
        "capitalise",
        false,
        "capitalising_changes_the_output_and_not_the_entropy",
    ),
];

fn struct_fields(source: &str, name: &str) -> Vec<String> {
    let Some(start) = source.find(&format!("pub struct {name} {{")) else {
        return Vec::new();
    };
    let body = source.get(start..).unwrap_or_default();
    // Ends at a `}` line at any indent, so an indented test struct is read too.
    body.lines()
        .skip(1)
        .take_while(|line| line.trim() != "}")
        .filter_map(|line| {
            let line = line.trim();
            if line.starts_with("//") || line.starts_with('#') {
                return None;
            }
            let (field, _) = line.split_once(':')?;
            let field = field.trim();
            field
                .chars()
                .all(|c| c.is_ascii_lowercase() || c == '_')
                .then(|| field.to_owned())
        })
        .collect()
}

#[test]
fn r1_every_generator_knob_is_registered_with_its_entropy_assertion() {
    let generate = read("crates/core/src/generate.rs");
    let passphrase = read("crates/core/src/passphrase.rs");

    let mut problems = Vec::new();
    for (struct_name, source, label) in [
        ("Policy", &generate, "generate.rs"),
        ("PassphrasePolicy", &passphrase, "passphrase.rs"),
    ] {
        let fields = struct_fields(source, struct_name);
        assert!(
            !fields.is_empty(),
            "no fields found on {struct_name} in {label}; the field reader has stopped reading"
        );
        for field in &fields {
            if !GENERATOR_KNOBS
                .iter()
                .any(|(s, f, _, _)| *s == struct_name && f == field)
            {
                problems.push(format!(
                    "{struct_name}.{field} ({label}) is a generator knob with no row in \
                     GENERATOR_KNOBS. Add one saying whether it moves the reported entropy, \
                     and the test that asserts it --- R1's third corollary."
                ));
            }
        }
        let registered = GENERATOR_KNOBS
            .iter()
            .filter(|(s, _, _, _)| *s == struct_name)
            .count();
        if registered != fields.len() {
            problems.push(format!(
                "{struct_name} has {} fields and {registered} rows; a row names a field that \
                 is gone",
                fields.len()
            ));
        }
    }

    for (struct_name, field, _, test) in GENERATOR_KNOBS {
        let source = if struct_name == "Policy" {
            &generate
        } else {
            &passphrase
        };
        if !source.contains(&format!("fn {test}(")) {
            problems.push(format!(
                "{struct_name}.{field} names the test `{test}`, which is not in that module"
            ));
        }
    }

    assert!(
        problems.is_empty(),
        "R1 third-corollary violations:\n  {}",
        problems.join("\n  ")
    );
}

#[test]
fn the_generator_knob_registry_would_notice_an_unregistered_knob() {
    let synthetic = r"
        pub struct Policy {
            length: usize,
            classes: Vec<CharClass>,
            exclude_ambiguous: bool,
            require_one_of_each: bool,
            leetspeak: bool,
        }
    ";
    let fields = struct_fields(synthetic, "Policy");
    assert_eq!(
        fields.len(),
        5,
        "the field reader missed a field: {fields:?}"
    );
    assert!(
        fields.iter().any(|f| f == "leetspeak"),
        "the new knob was not seen"
    );
    assert!(
        !GENERATOR_KNOBS
            .iter()
            .any(|(s, f, _, _)| *s == "Policy" && *f == "leetspeak"),
        "the synthetic knob must not be registered, or this proves nothing"
    );

    assert!(struct_fields(synthetic, "NoSuchStruct").is_empty());
}

/// Enumerable sets in `core`, as (label, defining file, opener of the member
/// list, the name a consumer must use).
const ENUMERABLE_SETS: [(&str, &str, &str, &str); 4] = [
    (
        "AAD record types",
        "crates/core/src/aad.rs",
        "pub const ALL_RECORD_TYPES",
        "ALL_RECORD_TYPES",
    ),
    (
        "item kinds",
        "crates/core/src/wrap.rs",
        "item_type! {",
        "ItemKind::ALL",
    ),
    (
        "generator character classes",
        "crates/core/src/generate.rs",
        "pub enum CharClass {",
        "CharClass::ALL",
    ),
    (
        "secret brands",
        "crates/core/src/secret.rs",
        "brand! {",
        "assert_every_brand_redacts_debug",
    ),
];

fn set_members(source: &str, opener: &str) -> Vec<String> {
    let Some(start) = source.find(opener) else {
        return Vec::new();
    };
    let body = source.get(start..).unwrap_or_default();
    body.lines()
        .skip(1)
        .take_while(|line| {
            let t = line.trim();
            // `impl ` stops a run past a block whose closer this does not know.
            t != "}" && t != "];" && !t.starts_with("impl ")
        })
        .filter_map(|line| {
            let t = line.trim().trim_end_matches(',');
            if t.is_empty() || t.starts_with("//") || t.starts_with('#') {
                return None;
            }
            let ident = t
                .split(&[' ', '=', '(', '{', ','][..])
                .next()
                .unwrap_or_default()
                .trim_start_matches("Self::");
            (ident.chars().next().is_some_and(char::is_uppercase)
                && ident.chars().all(|c| c.is_alphanumeric() || c == '_'))
            .then(|| ident.to_owned())
        })
        .collect()
}

const ENUMERATION_ALLOWED: [(&str, &str, &str); 3] = [
    (
        "item kinds",
        "core/tests/i7_double_wrap_agreement.rs",
        "TYPE-LEVEL, NOT VALUE-LEVEL: it names the marker types `Login`, `Note` \
         and the rest, not `ItemKind::Login`. `ItemKind::ALL` is a slice of \
         runtime values and types cannot be iterated, so there is nothing to \
         derive from. What forces the decision for a new item type is the \
         `item_type!` macro: `PROVIDER_READABLE` and `Wraps` have no defaults, \
         so a seventh type cannot be declared without stating both. **The \
         assertions could be macro-generated the way `brand!` now generates \
         I1(a)'s** --- recorded here rather than done, because I7 is \
         invariant and `wrap.rs` is not restructured here",
    ),
    (
        "item kinds",
        "core/tests/import_bitwarden_lastpass_chrome.rs",
        "A MAPPING TABLE, NOT A COVERAGE CLAIM: it asserts which foreign type \
         becomes which kind. A seventh item kind with no Bitwarden, LastPass or \
         Chrome equivalent **should not** appear here, so deriving from \
         `ItemKind::ALL` would assert something false",
    ),
    (
        "item kinds",
        "core/tests/import_one_password.rs",
        "A MAPPING TABLE, NOT A COVERAGE CLAIM: as above, for 1PUX and 1PIF. A \
         kind 1Password does not have is correctly absent",
    ),
];

#[test]
fn every_enumerable_set_is_derived_rather_than_listed_by_hand() {
    let mut problems = Vec::new();

    for (label, definition, opener, deriver) in ENUMERABLE_SETS {
        let members = set_members(&read(definition), opener);
        assert!(
            members.len() >= 3,
            "{label}: found {} members in {definition} — the member reader has \
             stopped reading, which would make this test vacuous",
            members.len()
        );
        let threshold = members.len().div_ceil(2);

        // Suites only: production modules naming many members are doing their job.
        for (name, source) in all_sources()
            .into_iter()
            .filter(|(n, _)| n.starts_with("core/tests/"))
        {
            let code = without_comments(&source);
            let named = members.iter().filter(|m| code.contains(*m)).count();
            if named < threshold || code.contains(deriver) {
                continue;
            }
            if ENUMERATION_ALLOWED
                .iter()
                .any(|(l, f, _)| *l == label && *f == name)
            {
                continue;
            }
            problems.push(format!(
                "{name} names {named} of {} {label} without using `{deriver}`",
                members.len()
            ));
        }
    }

    assert!(
        problems.is_empty(),
        "these enumerate a set by hand, so they range over what somebody \
         remembered rather than over what exists:\n  {}",
        problems.join("\n  ")
    );
}

#[test]
fn the_enumerable_set_reader_reads_each_definition() {
    let cases = [
        ("crates/core/src/aad.rs", "pub const ALL_RECORD_TYPES", 8),
        ("crates/core/src/secret.rs", "brand! {", 16),
    ];
    for (file, opener, expected) in cases {
        let members = set_members(&read(file), opener);
        assert_eq!(
            members.len(),
            expected,
            "{file}: read {members:?} from `{opener}`"
        );
    }

    assert!(set_members("fn nothing() {}", "pub enum Absent").is_empty());
}

#[test]
fn plan_mds_record_table_and_the_encoder_define_the_same_set() {
    let plan = read("docs/security-design.md");
    let mut in_plan: Vec<u8> = plan
        .lines()
        .filter_map(|line| line.trim().strip_prefix("recordType 0x"))
        .filter_map(|rest| u8::from_str_radix(rest.get(..2)?, 16).ok())
        .collect();
    in_plan.sort_unstable();
    in_plan.dedup();

    let mut in_code = chiavora_core::aad::ALL_RECORD_TYPES.to_vec();
    in_code.sort_unstable();

    assert!(
        !in_plan.is_empty(),
        "no `recordType 0xNN` lines found in docs/security-design.md -- the §2.2 table moved or \
         changed shape, and this check reads nothing rather than checking \
         nothing"
    );
    assert_eq!(
        in_plan, in_code,
        "docs/security-design.md §2.2 and `aad::ALL_RECORD_TYPES` define different record-type \
         sets. A type in one and not the other is a format that exists in the \
         design and not the encoder, or the reverse"
    );
}

/// Keeps `Path` in use on every platform without a `cfg`.
#[allow(dead_code)]
fn _unused(_: &Path) {}
