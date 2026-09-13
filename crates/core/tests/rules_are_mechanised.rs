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
        let is_test_module = lines
            .get(i..)
            .unwrap_or_default()
            .iter()
            .take(4)
            .any(|l| l.trim_start().starts_with("mod tests"));
        if is_test_module {
            for slot in mask.iter_mut().skip(i) {
                *slot = false;
            }
            break;
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
fn r1_no_capacity_is_reserved_from_an_unbounded_claim() {
    let mut unjustified: Vec<String> = Vec::new();
    for (name, source) in core_modules().into_iter().chain(protocol_modules()) {
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
        let name = path.to_string_lossy().replace('\\', "/");
        if name.contains("/generated/") {
            continue;
        }
        let short = name.rsplit("/src/").next().unwrap_or(&name).to_owned();
        let source = std::fs::read_to_string(&path).expect("a bridge file");
        out.push((short, without_comments(&source)));
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
        let core_symbols: Vec<String> = source
            .lines()
            .filter_map(|l| l.trim().strip_prefix("import uniffi.chiavora_ffi_mobile::"))
            .map(str::to_owned)
            .chain(
                source
                    .lines()
                    .filter_map(|l| l.trim().strip_prefix("import uniffi.chiavora_ffi_mobile."))
                    .map(str::to_owned),
            )
            .collect();

        for body in registration_blocks(&source, "Function") {
            for symbol in &core_symbols {
                if body.contains(symbol.as_str()) {
                    problems.push(format!(
                        "{name}: a synchronous `Function` calls `{symbol}`, which reaches \
                         `core` on the JS thread. UI-THREAD: use `AsyncFunction`."
                    ));
                }
            }
        }

        for forbidden in ["Handler(", "Looper.", "postDelayed", "runOnUiThread"] {
            if source.contains(forbidden) {
                problems.push(format!(
                    "{name}: contains `{forbidden}`. A bridge method dispatches to a native \
                     thread and returns; it does not post to the UI thread."
                ));
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

/// Keeps `Path` in use on every platform without a `cfg`.
#[allow(dead_code)]
fn _unused(_: &Path) {}
