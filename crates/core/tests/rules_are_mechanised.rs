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
        return "\n      ^ found `R1` above WITHOUT THE COLON; the scan matches only `R1:`"
            .to_owned();
    }
    if from_absorber
        .iter()
        .skip(1)
        .take(8)
        .any(|l| l.contains("R1:"))
    {
        return "\n      ^ found `R1:` BELOW this line; the note must be in the eight lines above"
            .to_owned();
    }
    String::new()
}

#[test]
fn r1_every_absorbing_pattern_carries_a_justification() {
    let unjustified = r1_absorbing_problems(&core_modules());
    assert!(
        unjustified.is_empty(),
        "R1: these absorb a failure with no `R1:` note in the eight lines above:\n  {}",
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
        "the item's tail no longer leaks, so the mask is string-aware and this test can go: {seen}"
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
        "production code after a mid-file #[cfg(test)] item was dropped: {seen}"
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
        "production code after the trailing test module was dropped: {seen}"
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
        "R1: these reserve capacity from an unbounded size with no `R1:` note:\n  {}",
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
    assert!(
        reservation_sizes("let f = vec![Slot::SchemaVersion, Slot::Kind];").is_empty(),
        "`vec![a, b]` was read as a reservation, but it lists elements and reserves nothing"
    );
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
                "R6: {what} = {header:?} contains {source}, which Crockford normalisation \
                 rewrites, so the header cannot survive its own normalisation."
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
        "R7: these fuzz targets have no meaningful checked-in corpus:\n  {}",
        unseeded.join("\n  ")
    );
}

#[test]
fn r7_the_fuzz_workflow_is_not_the_standing_arrangement() {
    let workflow = read(".github/workflows/fuzz.yml");
    assert!(
        !workflow.contains("cron:"),
        "fuzzing is local and manual; a `cron` here should be a deliberate decision"
    );
}

#[test]
fn the_gate_sets_its_own_exit_code() {
    let gate = read("scripts/gate.ps1");
    let after_verdict = gate
        .split("Write-Verdict 'EXIT 0'")
        .nth(1)
        .expect("gate.ps1 no longer writes `EXIT 0` to the verdict file");
    assert!(
        after_verdict.lines().any(|line| line.trim() == "exit 0"),
        "gate.ps1 writes `EXIT 0` and then exits with whatever the last command left in \
         `$LASTEXITCODE`"
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
            "{file} exists on disk but is not tracked by git; check `.gitignore` for a bare \
             `release/` or `debug/`. git said: {}",
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
        "the release-side HarnessDefinition.kt must stay in this list"
    );
    assert!(
        RELEASE_ABSENCE_FILES
            .iter()
            .any(|f| f.contains("src/debug/") && f.ends_with("HarnessDefinition.kt")),
        "the debug-side HarnessDefinition.kt must stay in this list"
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
                         `core` on the JS thread. Use `AsyncFunction`."
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
                        "{name}:{}: `{forbidden}` with no `UI-THREAD:` note in the eight \
                         lines above.",
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
                "modules/chiavora-core/index.ts: contains `{forbidden}`, and the wrapper \
                 must schedule nothing."
            ));
        }
    }

    assert!(
        problems.is_empty(),
        "bridge threading violations:\n  {}",
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

fn kotlin_registered_functions(source: &str) -> Vec<String> {
    let code = without_comments(source);
    let mut out = Vec::new();
    for marker in ["AsyncFunction(\"", "Function(\""] {
        let mut rest = code.as_str();
        while let Some(at) = rest.find(marker) {
            let after = rest.get(at + marker.len()..).unwrap_or_default();
            if let Some(name) = after.split('"').next() {
                if !name.is_empty() {
                    out.push(name.to_owned());
                }
            }
            rest = after;
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

fn typescript_module_methods(source: &str) -> Vec<(String, bool)> {
    let Some(start) = source.find("interface ChiavoraCoreNativeModule {") else {
        return Vec::new();
    };
    let body = source
        .get(start..)
        .and_then(|r| r.split("\n}").next())
        .unwrap_or_default();
    let mut out = Vec::new();
    for line in body.lines() {
        let trimmed = line.trim_start();
        // Two spaces of indent is a member; more is a parameter continuation.
        if line.starts_with("    ") || trimmed.starts_with("//") || trimmed.starts_with('*') {
            continue;
        }
        let optional = trimmed.contains("?(");
        let Some(name) = trimmed.split(['(', '?']).next() else {
            continue;
        };
        let name = name.trim();
        if name.is_empty()
            || !trimmed.contains('(')
            || !name.chars().all(|c| c.is_alphanumeric() || c == '_')
            || !name.starts_with(|c: char| c.is_ascii_lowercase())
        {
            continue;
        }
        out.push((name.to_owned(), optional));
    }
    out.sort();
    out.dedup();
    out
}

#[test]
fn the_typescript_surface_and_the_kotlin_module_agree() {
    let main_kt = kotlin_registered_functions(&read(
        "apps/mobile/modules/chiavora-core/android/src/main/java/ch/chiavora/core/ChiavoraCoreModule.kt",
    ));
    let debug_kt = kotlin_registered_functions(&read(
        "apps/mobile/modules/chiavora-core/android/src/debug/java/ch/chiavora/core/HarnessDefinition.kt",
    ));
    let ts = typescript_module_methods(&read("apps/mobile/modules/chiavora-core/index.ts"));

    assert!(
        main_kt.len() > 10 && !ts.is_empty(),
        "the reader found {} Kotlin functions and {} TypeScript methods, so it has \
         stopped reading one of the files",
        main_kt.len(),
        ts.len()
    );

    let emits_events = read(
        "apps/mobile/modules/chiavora-core/android/src/main/java/ch/chiavora/core/ChiavoraCoreModule.kt",
    )
    .contains("Events(");
    let framework_provided: &[&str] = if emits_events {
        &["addListener", "removeListeners"]
    } else {
        &[]
    };

    let mut problems = Vec::new();
    for (name, optional) in &ts {
        let registered = main_kt.contains(name)
            || debug_kt.contains(name)
            || framework_provided.contains(&name.as_str());
        if !registered {
            problems.push(format!(
                "TypeScript declares `{name}` and no Kotlin registers it: it \
                 typechecks, passes CI, and throws on the phone"
            ));
        }
        if *optional && main_kt.contains(name) {
            problems.push(format!(
                "`{name}` is optional in TypeScript but registered in the main source set"
            ));
        }
    }
    let ts_names: Vec<&String> = ts.iter().map(|(n, _)| n).collect();
    for name in &main_kt {
        if !ts_names.contains(&name) {
            problems.push(format!(
                "Kotlin registers `{name}` and TypeScript does not declare it: \
                 a caller reaches it untyped, or nothing reaches it at all"
            ));
        }
    }

    assert!(
        problems.is_empty(),
        "the TypeScript and Kotlin halves of the binding disagree:\n  {}",
        problems.join("\n  ")
    );
}

#[test]
fn the_binding_surface_reader_reads_both_halves() {
    let kt = "class M {\n  override fun definition() = ModuleDefinition {\n    AsyncFunction(\"alpha\") { }\n    Function(\"beta\") { }\n  }\n}";
    assert_eq!(
        kotlin_registered_functions(kt),
        vec!["alpha".to_owned(), "beta".to_owned()]
    );

    let commented = "class M {\n  // AsyncFunction(\"ghost\") was removed\n}";
    assert!(
        kotlin_registered_functions(commented).is_empty(),
        "a commented-out registration was read as a live one"
    );

    let ts = "interface ChiavoraCoreNativeModule {\n  alpha(): Promise<void>;\n  beta?(x: number): Promise<void>;\n}";
    assert_eq!(
        typescript_module_methods(ts),
        vec![("alpha".to_owned(), false), ("beta".to_owned(), true)]
    );

    let with_listener = concat!(
        "interface ChiavoraCoreNativeModule {\n",
        "  addListener(e: 'x', l: () => void): { remove: () => void };\n}"
    );
    assert_eq!(
        typescript_module_methods(with_listener),
        vec![("addListener".to_owned(), false)]
    );
}

const TEXT_LEAVING_THE_WINDOW: [(&str, &str); 6] = [
    ("a notification", "NotificationCompat"),
    ("a notification", "Notification.Builder"),
    ("a notification's text", "setContentText"),
    ("the task switcher's label", "setTaskDescription"),
    ("the activity title", "setTitle"),
    // The biometric prompt is drawn over whatever is in front, lock screen included.
    ("a system prompt's subtitle", "setSubtitle"),
];

fn is_comment_line(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with("//") || t.starts_with('*') || t.starts_with("/*")
}

/// Uses of [`TEXT_LEAVING_THE_WINDOW`] with no `LEAVES-WINDOW:` note above them.
/// Comment lines are skipped in place rather than stripped first, so line
/// numbers match the source the note is looked up in.
fn text_leaving_the_window_problems(source: &str) -> Vec<String> {
    let lines: Vec<&str> = source.lines().collect();
    let mut problems = Vec::new();
    for (what, needle) in TEXT_LEAVING_THE_WINDOW {
        for (number, line) in lines.iter().enumerate() {
            if is_comment_line(line) || !line.contains(needle) {
                continue;
            }
            let window_start = number.saturating_sub(8);
            let justified = lines
                .get(window_start..number)
                .unwrap_or_default()
                .iter()
                .any(|above| above.contains("LEAVES-WINDOW:"));
            if !justified {
                problems.push(format!(
                    "line {}: `{needle}` puts text into {what}, with no \
                     `LEAVES-WINDOW:` note within eight lines above",
                    number + 1
                ));
            }
        }
    }
    problems
}

#[test]
fn no_secret_leaves_the_apps_own_window() {
    let mut problems = Vec::new();
    for file in [
        "apps/mobile/modules/chiavora-core/android/src/main/java/ch/chiavora/core/ChiavoraCoreModule.kt",
        "apps/mobile/modules/chiavora-core/android/src/main/java/ch/chiavora/core/SecureWindow.kt",
        "apps/mobile/modules/chiavora-core/android/src/main/java/ch/chiavora/core/SecretClipboard.kt",
        "apps/mobile/modules/chiavora-core/android/src/main/java/ch/chiavora/core/VaultKeys.kt",
        "apps/mobile/modules/chiavora-core/android/src/main/java/ch/chiavora/core/LockController.kt",
    ] {
        for problem in text_leaving_the_window_problems(&read(file)) {
            problems.push(format!("{file}: {problem}"));
        }
    }
    assert!(
        problems.is_empty(),
        "text reaches a surface outside the app's own window, where a locked \
         screen shows it:\n  {}",
        problems.join("\n  ")
    );
}

#[test]
fn the_text_leaving_the_window_scan_fires_on_a_planted_notification() {
    let planted = "class M {\n    fun show() {\n        NotificationCompat.Builder(ctx).setContentText(item.password)\n    }\n}";
    assert_eq!(
        text_leaving_the_window_problems(planted).len(),
        2,
        "the scan missed a notification carrying a password"
    );

    let justified = "class M {\n    fun show() {\n        // LEAVES-WINDOW: the text is a fixed string and names no item.\n        NotificationCompat.Builder(ctx).setContentText(\"Vault locked\")\n    }\n}";
    assert!(
        text_leaving_the_window_problems(justified).is_empty(),
        "a justified use was still reported, so the note cannot be written"
    );

    let after_kdoc = "class M {\n    /**\n     * Something\n     * spread over\n     * several lines.\n     */\n    fun show() {\n        // LEAVES-WINDOW: fixed string.\n        NotificationCompat.Builder(ctx)\n    }\n}";
    assert!(
        text_leaving_the_window_problems(after_kdoc).is_empty(),
        "a note below a KDoc block was not seen, so the scan is reading line \
         numbers from one source and text from another"
    );

    let mentioned = "class M {\n    // We do not call NotificationCompat here.\n}";
    assert!(
        text_leaving_the_window_problems(mentioned).is_empty(),
        "a comment mentioning the symbol was read as a use of it"
    );
}

fn module_session_fields(source: &str) -> Vec<String> {
    let code = without_comments(source);
    let mut out = Vec::new();
    let mut rest = code.as_str();
    while let Some(at) = rest.find("@Volatile") {
        let Some(after) = rest.get(at..) else { break };
        let name = after
            .split("var ")
            .nth(1)
            .and_then(|tail| tail.split([':', ' ', '=']).next())
            .map(str::trim)
            .filter(|n| !n.is_empty());
        if let Some(name) = name {
            out.push(name.to_owned());
        }
        rest = after.get("@Volatile".len()..).unwrap_or_default();
    }
    out
}

#[test]
fn the_lock_clears_every_field_the_module_holds() {
    let source = read(
        "apps/mobile/modules/chiavora-core/android/src/main/java/ch/chiavora/core/ChiavoraCoreModule.kt",
    );
    let fields = module_session_fields(&source);
    assert!(
        fields.len() >= 2,
        "the scan found only {} `@Volatile` fields in ChiavoraCoreModule, so it has \
         stopped reading the class: {fields:?}",
        fields.len()
    );

    let body = kotlin_fn_body(&without_comments(&source), "dropSession")
        .expect("ChiavoraCoreModule has no findable `dropSession` body");

    let missed: Vec<&String> = fields
        .iter()
        .filter(|f| !body.contains(f.as_str()))
        .collect();
    assert!(
        missed.is_empty(),
        "`dropSession` does not clear {missed:?}, so a locked vault still holds it"
    );
}

#[test]
fn the_session_field_reader_reads_the_class() {
    let synthetic = "class M {\n    @Volatile\n    private var a: Foo? = null\n\n    @Volatile\n    private var b: ByteArray? = null\n}";
    assert_eq!(
        module_session_fields(synthetic),
        vec!["a".to_owned(), "b".to_owned()]
    );
    assert!(
        module_session_fields("class M { private var notVolatile: Foo? = null }").is_empty(),
        "a field with no `@Volatile` was read as session state"
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
            "the MUK's wrapping key no longer sets {required}, or this scan has stopped \
             reading the function"
        );
    }

    for forbidden in [
        "setUserAuthenticationRequired(true)",
        "setInvalidatedByBiometricEnrollment(true)",
    ] {
        assert!(
            !secret.contains(forbidden),
            "I8: the Secret Key's keystore entry calls {forbidden}, so a new fingerprint \
             would lose the Secret Key (`docs/security-design.md` §2.4)."
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
        "the body finder must return None for a missing function"
    );
}

const CRATES_ABOVE_CORE: [&str; 4] = [
    "crates/ffi-mobile/src",
    "crates/ffi-node/src",
    "crates/server/src",
    "apps/cli/src",
];

/// Empty: the keystore MUK re-enters through `device::muk_from_keystore`.
const PERMITTED_DERIVED_DOORS: [(&str, &str); 0] = [];

#[test]
fn the_muk_has_one_door_back_into_core() {
    let mut problems: Vec<String> = Vec::new();

    for dir in CRATES_ABOVE_CORE {
        let mut files = Vec::new();
        rs_files_under(&root().join(dir), &mut files);
        for path in files {
            let source = production(&std::fs::read_to_string(&path).expect("a source file"));
            if source.contains("from_derived_bytes") {
                // Repo-relative, so a `PERMITTED_DERIVED_DOORS` row matches in any checkout.
                let short = path
                    .strip_prefix(root())
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .replace('\\', "/");
                problems.push(format!(
                    "{short} calls `Secret::from_derived_bytes`; key material re-enters `core` \
                     only through `device::muk_from_keystore`."
                ));
            }
        }
    }

    let unlisted: Vec<&String> = problems
        .iter()
        .filter(|problem| {
            !PERMITTED_DERIVED_DOORS
                .iter()
                .any(|(path, _)| problem.starts_with(path))
        })
        .collect();
    assert!(
        unlisted.is_empty(),
        "these callers re-enter `core` with key material and are not in \
         PERMITTED_DERIVED_DOORS:\n  {}",
        unlisted
            .iter()
            .map(|problem| problem.as_str())
            .collect::<Vec<_>>()
            .join("\n  ")
    );

    for (path, why) in PERMITTED_DERIVED_DOORS {
        assert!(
            root().join(path).is_file(),
            "PERMITTED_DERIVED_DOORS names {path}, which does not exist"
        );
        assert!(
            why.len() > 40,
            "{path}'s row must say what key material that caller legitimately holds"
        );
    }

    let device = production(&read("crates/core/src/device.rs"));
    assert!(
        device.contains("fn muk_from_keystore"),
        "`device::muk_from_keystore` is gone, and the check above assumes it exists"
    );
    assert!(
        device.contains("from_derived_bytes"),
        "`muk_from_keystore` no longer calls `from_derived_bytes`"
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
        "the workspace has {declared} members and this scan covers {} plus core and protocol; \
         add the new crate to CRATES_ABOVE_CORE.",
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
        "the Store Key is no longer derived from the MUK, so the device-wrapped MUK needs its \
         own AAD record type (see `docs/crypto.md`)."
    );
    assert!(
        body.contains("INFO_STORE"),
        "the Store Key's domain separator changed"
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
            "R1's absorbing scan did not see an `unwrap_or` planted in `derive.rs` at {at:?}; \
             check `production_mask`."
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
            "the door scan did not see a `from_derived_bytes` call planted at {at:?}"
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
            "R1's capacity scan did not see a `Vec::with_capacity(declared)` planted in \
             `zip.rs` at {at:?}"
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
             at {at:?}"
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
         file"
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
        "device.rs no longer defines `is_hardware_backed`"
    );
    assert!(
        source.contains("pub const fn check_enrolment_backing"),
        "device.rs no longer defines `check_enrolment_backing`, which is the \
         enrolment path's refusal"
    );

    let sites = call_sites(&source, "is_hardware_backed");
    let production: Vec<usize> = sites
        .iter()
        .filter(|(_, in_production)| *in_production)
        .map(|(line, _)| *line)
        .collect();
    assert!(
        !production.is_empty(),
        "`is_hardware_backed` has {} call site(s), all of them in test code",
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
        "a predicate called only inside `#[cfg(test)]` reported a production caller at \
         {tests_only:?}"
    );
    assert!(
        !with_caller.is_empty(),
        "a predicate called from a production function reported no production caller"
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
            "{scan} is no longer in {file}"
        );
    }

    let covered = SCANS_AND_THEIR_WITNESSES
        .iter()
        .filter(|(_, has)| *has)
        .count();
    assert_eq!(
        covered,
        SCANS_AND_THEIR_WITNESSES.len(),
        "some scans have no real-file witness; rows marked false still owe one"
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
        "expected every module in crates/core/src, found {}",
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
            "R3's scan gave the same answer for a poisoned and a clean tree at {at:?}"
        );
        assert!(
            sites.iter().any(|n| n == "generate.rs"),
            "R3's scan did not see a `getrandom::fill` planted in `generate.rs` at {at:?}"
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
            "`{detector}` is called {calls} time(s), so it has no differential witness"
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
             `onAuthenticationSucceeded` body"
                .to_owned(),
        );
        return problems;
    };

    if !body.contains("cryptoObject") {
        problems.push(
            "`onAuthenticationSucceeded` never reads `result.cryptoObject`, so it acts on a \
             forgeable success flag rather than the key the OS released (§3.3)."
                .to_owned(),
        );
    }

    for forbidden in ["resume(true)", "resume(Unit)", "resume(false)"] {
        if body.contains(forbidden) {
            problems.push(format!(
                "`onAuthenticationSucceeded` calls `{forbidden}`; resume with the authenticated \
                 `Cipher` instead."
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
        "no `AuthenticationCallback` found in the bridge module, so the biometric unlock is \
         gone or this scan has stopped reading"
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

    assert!(
        biometric_callback_problems("class Unrelated { }").is_empty(),
        "a class with no biometric callbacks was reported as having a problem"
    );
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
                "{}: `if (!exists(...))` decides whether to create a key, but an invalidated key \
                 keeps its alias; delete and recreate, or add a `USABLE-NOT-EXISTS:` note.",
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
        "the scan did not notice an `exists` guard around a create"
    );
    assert_ne!(
        guarded_problems, fixed_problems,
        "the detector gave the same answer for the broken shape and the fixed one"
    );
    assert!(
        fixed_problems.is_empty(),
        "delete-then-create-unconditionally must be accepted: {fixed_problems:?}"
    );

    assert!(
        keystore_precondition_problems("class Unrelated {}").is_empty(),
        "a class that touches no keystore entry was reported"
    );
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
            "app.json: expo.android.allowBackup is not false, and only it governs cloud backup."
                .to_owned(),
        );
    }
    if compact.contains("\"allowBackup\":true") {
        problems.push("app.json: expo.android.allowBackup is explicitly true".to_owned());
    }
    if !compact.contains("\"./plugins/with-chiavora-backup\"") {
        problems.push(
            "app.json: with-chiavora-backup is not in expo.plugins, so device-to-device \
             transfer is unrestricted on API 31+."
                .to_owned(),
        );
    }

    // `<device-transfer>` is the one that looks redundant and is not.
    for required in ["<cloud-backup>", "<device-transfer>"] {
        if !plugin.contains(required) {
            problems.push(format!(
                "with-chiavora-backup.js: no `{required}` section; on API 31+ the two \
                 transports are excluded separately."
            ));
        }
    }
    for domain in EXTRACTION_DOMAINS {
        if !plugin.contains(&format!("'{domain}'")) {
            problems.push(format!(
                "with-chiavora-backup.js: the domain `{domain}` is not in DOMAINS, so it is \
                 backed up."
            ));
        }
    }
    if !plugin.contains("allowBackup !== false") {
        problems.push(
            "with-chiavora-backup.js: the plugin no longer refuses an app.json whose \
             allowBackup is not false."
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
        "backup exclusion violations:\n  {}",
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
            "the mutation '{what}' changed nothing; its needle is no longer in the file"
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
                     GENERATOR_KNOBS."
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

    assert!(
        struct_fields(synthetic, "NoSuchStruct").is_empty(),
        "a struct that is not there returned fields"
    );
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
        "it names the marker types such as `Login`, which cannot be iterated, and \
         `item_type!` makes a new type state both of its properties",
    ),
    (
        "item kinds",
        "core/tests/import_bitwarden_lastpass_chrome.rs",
        "a mapping table, where a kind with no Bitwarden, LastPass or Chrome \
         equivalent is correctly absent",
    ),
    (
        "item kinds",
        "core/tests/import_one_password.rs",
        "a mapping table, where a kind 1Password does not have is correctly absent",
    ),
];

#[test]
fn every_enumerable_set_is_derived_rather_than_listed_by_hand() {
    let mut problems = Vec::new();

    for (label, definition, opener, deriver) in ENUMERABLE_SETS {
        let members = set_members(&read(definition), opener);
        assert!(
            members.len() >= 3,
            "{label}: found only {} members in {definition}, so the member reader has \
             stopped reading",
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
        "these enumerate a set by hand rather than deriving it:\n  {}",
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

    assert!(
        set_members("fn nothing() {}", "pub enum Absent").is_empty(),
        "a shape that is not there returned members"
    );
}

#[test]
fn the_design_record_table_and_the_encoder_define_the_same_set() {
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
        "no `recordType 0xNN` lines found in docs/security-design.md; the §2.2 \
         table moved or changed shape"
    );
    assert_eq!(
        in_plan, in_code,
        "docs/security-design.md §2.2 and `aad::ALL_RECORD_TYPES` define different record-type \
         sets"
    );
}

/// A bare `>` in the salt argument would truncate it, which still fails the check.
fn hkdf_salt_arguments(sources: &[(String, String)]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (name, source) in sources {
        let code = production(source);
        let mut rest = code.as_str();
        while let Some(at) = rest.find("Hkdf::") {
            let after = rest.get(at..).unwrap_or("");
            // `Hkdf::<Sha256>::new(` and `Hkdf::new(` both reach the same call.
            let Some(open) = after.find("new(") else {
                break;
            };
            let args = after.get(open + "new(".len()..).unwrap_or("");
            let mut depth = 0_i32;
            let mut end = args.len();
            for (index, ch) in args.char_indices() {
                match ch {
                    '(' | '[' | '<' => depth += 1,
                    ')' | ']' | '>' if depth > 0 => depth -= 1,
                    ')' | ']' | '>' | ',' if depth == 0 => {
                        end = index;
                        break;
                    }
                    _ => {}
                }
            }
            out.push((
                name.clone(),
                args.get(..end).unwrap_or("").trim().to_owned(),
            ));
            rest = after.get(open + "new(".len()..).unwrap_or("");
        }
    }
    out
}

fn workspace_src() -> Vec<(String, String)> {
    let crates = root().join("crates");
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(&crates) else {
        return out;
    };
    let mut dirs: Vec<PathBuf> = entries.filter_map(Result::ok).map(|e| e.path()).collect();
    dirs.sort();
    for dir in dirs {
        let src = dir.join("src");
        if !src.is_dir() {
            continue;
        }
        let mut files = Vec::new();
        rs_files_under(&src, &mut files);
        for path in files {
            let name = path
                .strip_prefix(&crates)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            out.push((name, std::fs::read_to_string(&path).expect("a module")));
        }
    }
    out
}

#[test]
fn no_hkdf_call_site_passes_a_salt() {
    let sources = workspace_src();
    let sites = hkdf_salt_arguments(&sources);

    assert!(
        !sites.is_empty(),
        "no `Hkdf::new` call site found in any crate's src, so the derivations moved or \
         this walk reads nothing"
    );

    let salted: Vec<String> = sites
        .iter()
        .filter(|(_, salt)| salt != "None")
        .map(|(name, salt)| format!("{name}: Hkdf::new({salt}, ..)"))
        .collect();

    assert!(
        salted.is_empty(),
        "`docs/crypto.md` says no HKDF salt is used, but these call sites pass one:\n  {}",
        salted.join("\n  ")
    );
}

#[test]
fn the_hkdf_salt_scan_would_notice_a_salt() {
    let compliant = [(
        "x/src/a.rs".to_owned(),
        "let hk = Hkdf::<Sha256>::new(None, ikm);".to_owned(),
    )];
    let salted = [(
        "x/src/b.rs".to_owned(),
        "let hk = Hkdf::<Sha256>::new(Some(salt), ikm);".to_owned(),
    )];
    let turbofish_free = [(
        "x/src/c.rs".to_owned(),
        "let hk = Hkdf::new(&self.salt, ikm);".to_owned(),
    )];

    assert_eq!(
        hkdf_salt_arguments(&compliant),
        vec![("x/src/a.rs".to_owned(), "None".to_owned())],
        "a compliant call must be seen and its argument read as `None`"
    );
    assert_eq!(
        hkdf_salt_arguments(&salted),
        vec![("x/src/b.rs".to_owned(), "Some(salt)".to_owned())],
        "a salted call must be caught, with the salt in the message"
    );
    assert_eq!(
        hkdf_salt_arguments(&turbofish_free),
        vec![("x/src/c.rs".to_owned(), "&self.salt".to_owned())],
        "`Hkdf::new` without a turbofish must be caught too"
    );

    let real = hkdf_salt_arguments(&workspace_src());
    assert!(
        real.iter().any(|(name, _)| name.contains("derive.rs")),
        "the walk must reach core/src/derive.rs and its HKDF call site"
    );
}

fn pinned_channel() -> Option<String> {
    let text = read("rust-toolchain.toml");
    let line = text
        .lines()
        .map(|line| line.split('#').next().unwrap_or("").trim())
        .find(|line| line.starts_with("channel"))?;
    let value = line.split('=').nth(1)?.trim().trim_matches('"').to_owned();
    let numeric = value.split('.').count() == 3
        && value
            .split('.')
            .all(|part| part.chars().all(|c| c.is_ascii_digit()));
    numeric.then_some(value)
}

#[test]
fn the_pinned_toolchain_is_the_one_actually_running() {
    let pinned = pinned_channel().unwrap_or_else(|| {
        panic!("rust-toolchain.toml does not pin an exact version, and it must")
    });

    let output = std::process::Command::new("rustc")
        .arg("--version")
        .output()
        .expect("rustc must be invokable from a test");
    let reported = String::from_utf8_lossy(&output.stdout).into_owned();

    assert!(
        reported.contains(&pinned),
        "rust-toolchain.toml pins {pinned} but the compiler running this test \
         reports `{}`; something overrides the toolchain file or the checkout is stale",
        reported.trim()
    );
}

#[test]
fn the_toolchain_pin_parser_distinguishes_a_version_from_a_channel() {
    let parse = |text: &str| -> Option<String> {
        let line = text
            .lines()
            .map(|line| line.split('#').next().unwrap_or("").trim())
            .find(|line| line.starts_with("channel"))?;
        let value = line.split('=').nth(1)?.trim().trim_matches('"').to_owned();
        let numeric = value.split('.').count() == 3
            && value
                .split('.')
                .all(|p| p.chars().all(|c| c.is_ascii_digit()));
        numeric.then_some(value)
    };

    assert_eq!(
        parse("[toolchain]\nchannel = \"1.99.0\"\n"),
        Some("1.99.0".to_owned()),
        "an exact version must be read as pinned"
    );
    assert_eq!(
        parse("[toolchain]\nchannel = \"stable\"\n"),
        None,
        "`stable` is floating and must not read as a pin"
    );
    assert_eq!(
        parse("[toolchain]\nchannel = \"nightly-2026-10-01\"\n"),
        None,
        "a dated nightly is still a channel, not a version"
    );
    assert_eq!(
        parse("# channel = \"1.0.0\"\n[toolchain]\nchannel = \"1.99.0\"\n"),
        Some("1.99.0".to_owned()),
        "a commented-out channel must not be read as the pin; this file's \
         header discusses `channel = \"stable\"` in prose"
    );
    assert_eq!(
        parse("[toolchain]\n"),
        None,
        "no channel line at all must read as unpinned rather than as anything"
    );
}

/// `crates/core`'s dependencies that are cryptographic constructions, which no
/// crate above `core` may depend on (§3.2).
const CRYPTOGRAPHIC_CRATES: [(&str, &str); 10] = [
    ("argon2", "the password KDF (§2.1)"),
    ("hkdf", "every derivation from a high-entropy secret (§2.1)"),
    ("sha2", "HKDF's hash, and SRP's H_x and H_proto"),
    ("hmac", "the store and export MACs, and the request MAC"),
    ("subtle", "constant-time comparison"),
    ("chacha20poly1305", "the AEAD (§2.2)"),
    ("x25519-dalek", "the account key agreement (§2.4)"),
    ("hpke", "the sealed Vault Key (0x06)"),
    ("crypto-bigint", "SRP-6a's modular arithmetic (§2.3)"),
    (
        "getrandom",
        "the CSPRNG. R3: one call site, and it is in `core`",
    ),
];

const NOT_CRYPTOGRAPHIC: [(&str, &str); 9] = [
    (
        "zeroize",
        "hygiene, not a construction. `ffi-mobile` uses it directly and says why",
    ),
    ("region", "mlock. A memory syscall"),
    ("rusqlite", "the local store's file format"),
    (
        "serde",
        "serialisation. What it must never serialise is I1's problem",
    ),
    (
        "serde_json",
        "the vector files and the native export container",
    ),
    ("unicode-normalization", "NFKD for passphrase input (§2.1)"),
    (
        "unicode-general-category",
        "the category lookup NFKD normalisation needs",
    ),
    ("miniz_oxide", "compression"),
    ("chiavora-protocol", "this workspace's wire types"),
];

fn manifest_dependencies(manifest: &str) -> Vec<String> {
    let Some(after) = manifest.split("[dependencies]").nth(1) else {
        return Vec::new();
    };
    let body = after.split("\n[").next().unwrap_or("");
    let mut out = Vec::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some(name) = line.split_whitespace().next() else {
            continue;
        };
        let name = name.trim_end_matches('=').trim();
        if !name.is_empty() {
            out.push(name.to_owned());
        }
    }
    out
}

#[test]
fn every_dependency_of_core_is_classified_as_cryptographic_or_not() {
    let mut actual = manifest_dependencies(&read("crates/core/Cargo.toml"));
    actual.sort_unstable();
    actual.dedup();

    let mut classified: Vec<String> = CRYPTOGRAPHIC_CRATES
        .iter()
        .chain(NOT_CRYPTOGRAPHIC.iter())
        .map(|(name, _)| (*name).to_owned())
        .collect();
    classified.sort_unstable();
    classified.dedup();

    assert_eq!(
        actual, classified,
        "the two classification lists must equal `crates/core`'s dependencies"
    );

    for (name, reason) in CRYPTOGRAPHIC_CRATES.iter().chain(NOT_CRYPTOGRAPHIC.iter()) {
        assert!(
            reason.len() > 10,
            "{name}'s classification must say what it is for"
        );
    }
}

#[test]
fn no_crate_above_core_depends_on_a_cryptographic_crate() {
    let mut problems: Vec<String> = Vec::new();

    for dir in CRATES_ABOVE_CORE {
        let crate_dir = dir.trim_end_matches("/src");
        let manifest_path = root().join(crate_dir).join("Cargo.toml");
        let Ok(manifest) = std::fs::read_to_string(&manifest_path) else {
            continue;
        };
        for dep in manifest_dependencies(&manifest) {
            if let Some((name, purpose)) =
                CRYPTOGRAPHIC_CRATES.iter().find(|(name, _)| *name == dep)
            {
                problems.push(format!(
                    "{crate_dir} depends on `{name}` ({purpose}); route it through \
                     `chiavora-core` instead"
                ));
            }
        }
    }

    assert!(
        problems.is_empty(),
        "a crate above `core` has taken a cryptographic dependency:\n  {}",
        problems.join("\n  ")
    );
}

#[test]
fn the_cryptographic_dependency_scan_would_notice_one() {
    let planted = "[package]\nname = \"x\"\n\n[dependencies]\n\
                   chiavora-core = { workspace = true }\n\
                   hmac = \"0.12\"\n\n[dev-dependencies]\nhex = \"0.4\"\n";
    let deps = manifest_dependencies(planted);
    assert!(
        deps.contains(&"hmac".to_owned()),
        "a cryptographic dependency must be seen"
    );
    assert!(
        deps.contains(&"chiavora-core".to_owned()),
        "and an ordinary one must be too, or the parser is reading one line"
    );
    assert!(
        !deps.contains(&"hex".to_owned()),
        "`[dev-dependencies]` must not be read as `[dependencies]`"
    );
    assert!(
        CRYPTOGRAPHIC_CRATES.iter().any(|(name, _)| *name == "hmac"),
        "`hmac` must be on the list, or the planted case proves nothing"
    );

    let reached = CRATES_ABOVE_CORE
        .iter()
        .filter(|dir| {
            root()
                .join(dir.trim_end_matches("/src"))
                .join("Cargo.toml")
                .is_file()
        })
        .count();
    assert_eq!(
        reached,
        CRATES_ABOVE_CORE.len(),
        "every crate above `core` must have a manifest this scan can read; \
         {reached} of {} were found",
        CRATES_ABOVE_CORE.len()
    );

    let server = read("crates/server/Cargo.toml");
    assert!(
        manifest_dependencies(&server).contains(&"chiavora-core".to_owned()),
        "crates/server must depend on chiavora-core, so there is one SRP implementation"
    );
}

#[test]
fn the_door_list_permits_only_what_it_names() {
    let permits = |listed: &[(&str, &str)], problem: &str| {
        !listed.iter().any(|(path, _)| problem.starts_with(path))
    };

    let problem = "crates/ffi-mobile/src/lib.rs calls `Secret::from_derived_bytes`. ...";

    assert!(
        permits(&[], problem),
        "with nothing listed, every caller must be reported"
    );
    assert!(
        !permits(
            &[("crates/ffi-mobile/src/lib.rs", "the MUK, from the keystore")],
            problem
        ),
        "a listed path must be permitted"
    );
    assert!(
        permits(&[("crates/ffi-node/src/lib.rs", "something else")], problem),
        "a different listed path must not permit this one"
    );

    let sample = root().join("crates").join("server").join("src");
    let mut files = Vec::new();
    rs_files_under(&sample, &mut files);
    let first = files.first().expect("crates/server/src has sources");
    let short = first
        .strip_prefix(root())
        .unwrap_or(first)
        .to_string_lossy()
        .replace('\\', "/");
    assert!(
        short.starts_with("crates/server/src/"),
        "the scan must produce repo-relative paths; got `{short}`"
    );
}

/// Keeps `Path` in use on every platform without a `cfg`.
#[allow(dead_code)]
fn _unused(_: &Path) {}
