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

const PARSERS: [Parser; 6] = [
    Parser {
        file: "core/src/aad.rs",
        function: "decode",
        target: "aad_decode",
        why: "the inverse of the encoder every record depends on; a disagreement is an I3 failure",
    },
    Parser {
        file: "protocol/src/lib.rs",
        function: "Record::decode",
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
    Parser {
        file: "core/src/stored_record.rs",
        function: "StoredRecord::decode",
        target: "stored_record_decode",
        why: "a record on disk written by *some* build, possibly a newer one, in a file A4 can rewrite",
    },
    Parser {
        file: "core/src/model.rs",
        function: "Item::from_bytes",
        target: "item_body_decode",
        why: "an item body written by a *newer* client, which this build must read and edit; inside the AEAD, but not produced by this build",
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

const NOT_SEPARATELY_FUZZED: [(&str, &str, &str); 31] = [
    (
        "core/src/base32.rs",
        "decode_with_checksum",
        "COVERED ELSEWHERE: reached only through secret_key::decode and \
         emergency_kit::parse, both of which are fuzzed; it takes an \
         already-normalised symbol slice rather than raw input",
    ),
    (
        "core/src/base32.rs",
        "normalise_input",
        "COVERED ELSEWHERE: the first step of all three classified decoders, so \
         every byte a fuzzer feeds any of them passes through here first",
    ),
    (
        "core/src/base32.rs",
        "checksum",
        "COVERED ELSEWHERE: a truncated SHA-256 over a slice, reached from both \
         the encode and the decode direction and fuzzed through the decoders",
    ),
    (
        "core/src/base32.rs",
        "encode_with_checksum",
        "NOT A BOUNDARY: the encode direction. Its input is a key or an \
         accountId this crate generated moments earlier",
    ),
    (
        "core/src/base32.rs",
        "group",
        "NOT A BOUNDARY: presentation over the encoder's own output; the \
         decoder strips separators, so this never sees input",
    ),
    (
        "core/src/nonce.rs",
        "StoredNonce::from_stored_bytes",
        "SAFE BY CONSTRUCTION: takes a fixed-size array, so there is no length \
         or structure to get wrong, and a wrong nonce fails the AEAD tag",
    ),
    (
        "core/src/secret_key.rs",
        "looks_like_rendered_key_material",
        "COVERED ELSEWHERE: attacker-facing -- a hostile app can write the \
         clipboard (A8) -- and its whole body is base32::normalise_input plus a \
         length comparison and a prefix match",
    ),
    (
        "core/src/entry.rs",
        "accept",
        "COVERED ELSEWHERE: the decoding half dispatches to secret_key::decode, \
         which is fuzzed. The validating half is is_empty, a length bound, \
         is_ascii and two whitespace checks -- total functions over a slice, \
         with no parsing and no allocation. A target here would explore \
         is_ascii and report a coverage figure for it, which is R7's own \
         failure wearing a fuzzer",
    ),
    (
        "core/src/ffi_guard.rs",
        "assert_not_key_material",
        "SAFE BY CONSTRUCTION: a 32-byte-window substring search over a slice. \
         A fuzz target here is **impossible** rather than unnecessary -- the \
         failure path is abort, so a fuzzer that found key material would kill \
         itself instead of reporting it. Covered by i1a_ffi_guard_aborts.rs, \
         which re-executes its own binary as a child",
    ),
    (
        "core/src/ffi_guard.rs",
        "register",
        "NOT A BOUNDARY: takes key material this crate produced, from \
         Secret::new, and never anything from outside",
    ),
    (
        "core/src/ffi_guard.rs",
        "deregister",
        "NOT A BOUNDARY: the Drop half of register, over the same bytes",
    ),
    (
        "core/src/item.rs",
        "SealedPayload::from_stored_parts",
        "SAFE BY CONSTRUCTION: reconstitutes a sealed record from SQLite, so \
         the bytes *are* from outside (A4 -- a hostile process on the device \
         can rewrite the file). It parses nothing: a fixed-size nonce array and \
         an opaque ciphertext vector go into a struct, and a tampered \
         ciphertext fails the AEAD tag. The same shape as nonce::from_stored_bytes",
    ),
    (
        "core/src/wrap.rs",
        "WrappedKey::from_stored_parts",
        "SAFE BY CONSTRUCTION: the wrap half of item::from_stored_parts, on the \
         same reasoning",
    ),
    (
        "core/src/item.rs",
        "seal",
        "NOT A BOUNDARY: the plaintext is opaque to the AEAD. It is encrypted, \
         not parsed, so there is no structure here for a hostile value to \
         exploit -- item *decoding* is the schema's work and gets its own \
         targets",
    ),
    (
        "core/src/scan.rs",
        "production",
        "NOT A BOUNDARY: reads this crate's own source text, checked in beside \
         the code it reads",
    ),
    (
        "core/src/secret.rs",
        "Secret::from_derived_bytes",
        "NOT A BOUNDARY: takes KDF output produced moments earlier in the same \
         operation",
    ),
    (
        "core/src/secret.rs",
        "Secret::from_external_bytes",
        "NOT A BOUNDARY: pub(crate), and reached only through entry::accept, \
         which is classified above. The compile-fail case \
         external_secrets_have_no_public_constructor is what makes that true \
         rather than customary",
    ),
    (
        "core/src/wrap.rs",
        "ItemKind::from_tag",
        "SAFE BY CONSTRUCTION: an exact match of a stored tag against six \
         string literals, returning Option. It parses nothing and allocates \
         nothing, and an unrecognised tag is None rather than a guess",
    ),
    (
        "core/src/model.rs",
        "Name::new",
        "SAFE BY CONSTRUCTION: bounded before anything else, then a character \
         check. No parsing, no structure, and the bound comes first so a \
         hostile import cannot make it allocate before refusing",
    ),
    (
        "core/src/model.rs",
        "ItemField::new",
        "SAFE BY CONSTRUCTION: delegates the name to Name::new and treats the \
         value as opaque bytes -- the value is never parsed here, only sealed \
         later",
    ),
    (
        "core/src/model.rs",
        "Item::new",
        "SAFE BY CONSTRUCTION: delegates every name to Name::new and compares \
         names for duplicates. Quadratic in the field count, which is bounded \
         by the caller rather than here -- stated because a hostile import with \
         a million fields is the shape that would matter, and is where \
         that bound belongs",
    ),
    (
        "core/src/model.rs",
        "Item::remove_field",
        "SAFE BY CONSTRUCTION: compares a name against names already validated          by Name::new and retains the rest. No parsing; the slot list is the          representation and retain cannot reorder it",
    ),
    (
        "core/src/model.rs",
        "Item::field",
        "SAFE BY CONSTRUCTION: a linear search comparing a name to names \
         already validated by Name::new",
    ),
    (
        "core/src/store.rs",
        "Store::put_raw",
        "SAFE BY CONSTRUCTION: the opaque-record obligation. The identifiers are \
         opaque keys and the bytes are stored exactly and never read -- a \
         record this build cannot open goes in and comes out identical, so \
         the manifest's ciphertextDigest over it still holds (I6d)",
    ),
    (
        "core/src/store.rs",
        "Store::get_raw",
        "SAFE BY CONSTRUCTION: identifiers used as opaque lookup keys; returns \
         bytes unread",
    ),
    (
        "core/src/store.rs",
        "Store::delete",
        "SAFE BY CONSTRUCTION: identifiers used as opaque keys",
    ),
    (
        "core/src/store.rs",
        "Store::list",
        "SAFE BY CONSTRUCTION: an identifier used as an opaque key",
    ),
    (
        "core/src/store.rs",
        "Store::high_water_mark",
        "SAFE BY CONSTRUCTION: an identifier used as an opaque map key over \
         metadata already authenticated on open",
    ),
    (
        "core/src/store.rs",
        "Store::set_high_water_mark",
        "SAFE BY CONSTRUCTION: an identifier used as an opaque map key; the value \
         is refused if it decreases (I6f), then re-MAC'd",
    ),
    (
        "protocol/src/lib.rs",
        "Field::new",
        "NOT A BOUNDARY: the encode direction -- a field this crate is about to \
         serialise. Record::decode is the inbound half and has a target",
    ),
    (
        "protocol/src/lib.rs",
        "Record::with_field",
        "NOT A BOUNDARY: the encode direction, and the same reasoning as new",
    ),
];

const REASON_KINDS: [&str; 3] = [
    "COVERED ELSEWHERE:",
    "SAFE BY CONSTRUCTION:",
    "NOT A BOUNDARY:",
];

fn production_code(source: &str) -> String {
    let marker = concat!("#[cfg(", "test)]");
    let lines: Vec<&str> = source.lines().collect();
    let mut out = String::with_capacity(source.len());
    let mut i = 0;
    while i < lines.len() {
        let line = lines.get(i).copied().unwrap_or_default();
        let trimmed = line.trim();
        if trimmed.starts_with("//") {
            i += 1;
            continue;
        }
        if trimmed != marker {
            out.push_str(line);
            out.push('\n');
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
            break;
        }
        i += 1;
        let mut depth = 0_usize;
        let mut started = false;
        while let Some(inner) = lines.get(i) {
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
    out
}

fn declared_functions(code: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    // (implementing type, the brace depth the impl block opened at)
    let mut scopes: Vec<(String, usize)> = Vec::new();
    let mut depth = 0_usize;
    let mut offset = 0_usize;

    for line in code.lines() {
        let trimmed = line.trim_start();

        if trimmed.starts_with("impl") && !trimmed.starts_with("impl_") {
            if let Some(ty) = implementing_type(trimmed) {
                scopes.push((ty, depth));
            }
        }

        if let Some(rest) = trimmed.strip_prefix("pub ").or_else(|| {
            trimmed
                .strip_prefix("pub(crate) ")
                .filter(|_| trimmed.starts_with("pub(crate) "))
        }) {
            let rest = rest
                .trim_start_matches("const ")
                .trim_start_matches("unsafe ");
            if let Some(after_fn) = rest.strip_prefix("fn ") {
                let name: String = after_fn
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_')
                    .collect();
                if !name.is_empty() {
                    if let Some(params) = balanced_params(code, offset + (line.len() - rest.len()))
                    {
                        let qualified = scopes
                            .last()
                            .map_or_else(|| name.clone(), |(ty, _)| format!("{ty}::{name}"));
                        out.push((qualified, params));
                    }
                }
            }
        }

        depth += line.matches('{').count();
        depth = depth.saturating_sub(line.matches('}').count());
        while scopes.last().is_some_and(|(_, opened)| depth <= *opened) {
            scopes.pop();
        }
        offset += line.len() + 1;
    }
    out
}

fn implementing_type(line: &str) -> Option<String> {
    let rest = line.strip_prefix("impl")?;
    let rest = if rest.starts_with('<') {
        let mut depth = 0_usize;
        let mut end = None;
        for (at, ch) in rest.char_indices() {
            match ch {
                '<' => depth += 1,
                '>' => {
                    depth -= 1;
                    if depth == 0 {
                        end = Some(at + 1);
                        break;
                    }
                }
                _ => {}
            }
        }
        rest.get(end?..)?
    } else {
        rest
    };
    let rest = rest.split_once(" for ").map_or(rest, |(_, after)| after);
    let ty: String = rest
        .trim()
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect();
    if ty.is_empty() || !ty.starts_with(|c: char| c.is_uppercase()) {
        None
    } else {
        Some(ty)
    }
}

fn balanced_params(code: &str, from: usize) -> Option<String> {
    let rest = code.get(from..)?;
    let open = rest.find('(')?;
    let mut depth = 0_usize;
    for (at, ch) in rest.get(open..)?.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return rest.get(open..=open.saturating_add(at)).map(str::to_owned);
                }
            }
            _ => {}
        }
    }
    None
}

fn takes_bytes_or_text(params: &str) -> bool {
    ["&[u8]", "&str", "Vec<u8>", "&[u8;", "String"]
        .iter()
        .any(|ty| params.contains(ty))
}

fn is_classified(file: &str, function: &str) -> bool {
    PARSERS
        .iter()
        .any(|p| p.file == file && p.function == function)
        || NOT_SEPARATELY_FUZZED
            .iter()
            .any(|(f, fun, _)| *f == file && *fun == function)
}

fn all_declared() -> Vec<(String, String)> {
    let mut found = Vec::new();
    for (name, source) in test_sources() {
        if !name.contains("/src/") {
            continue;
        }
        for (function, _) in declared_functions(&production_code(&source)) {
            found.push((name.clone(), function));
        }
    }
    found
}

const MID_FILE_CFG_TEST_FIXTURE: &str = r"
//! A module.

pub fn before_the_marker(bytes: &[u8]) -> usize {
    bytes.len()
}

/// Test-only, and deliberately in the middle of the file.
#[cfg(test)]
pub(crate) fn only_for_tests(bytes: &[u8]) -> usize {
    if bytes.is_empty() {
        return 0;
    }
    bytes.len()
}

pub fn after_the_marker(outgoing: &[u8]) {
    let _ = outgoing;
}

#[cfg(test)]
mod tests {
    pub fn inside_the_test_module(bytes: &[u8]) -> usize {
        bytes.len()
    }
}
";

#[test]
fn the_stripping_keeps_production_code_after_a_mid_file_cfg_test() {
    let stripped = production_code(MID_FILE_CFG_TEST_FIXTURE);
    let found: Vec<String> = declared_functions(&stripped)
        .into_iter()
        .map(|(name, _)| name)
        .collect();

    assert!(
        found.iter().any(|f| f == "before_the_marker"),
        "the stripping dropped production code *before* the marker: {found:?}"
    );
    assert!(
        found.iter().any(|f| f == "after_the_marker"),
        "**the regression this test exists for.** Production code after a \
         mid-file #[cfg(test)] item was dropped, so every classification check \
         is blind to the rest of the file and cannot notice: {found:?}"
    );
    assert!(
        !found.iter().any(|f| f == "only_for_tests"),
        "the #[cfg(test)] item itself must still be skipped: {found:?}"
    );
    assert!(
        !found.iter().any(|f| f == "inside_the_test_module"),
        "the trailing test module must still be dropped: {found:?}"
    );
}

#[test]
fn the_crate_the_finding_came_from_still_has_the_shape_that_hid_it() {
    let guard = read("crates/core/src/ffi_guard.rs");
    let marker = concat!("#[cfg(", "test)]");
    assert!(
        guard.matches(marker).count() >= 2,
        "ffi_guard.rs no longer has a mid-file {marker}. If that is deliberate \
         the fixture above still guards the stripping, but the real-world case \
         this came from is gone and the comment should say so."
    );
    let visible: Vec<String> = declared_functions(&production_code(&guard))
        .into_iter()
        .map(|(name, _)| name)
        .collect();
    assert!(
        visible.iter().any(|f| f == "assert_not_key_material"),
        "the FFI guard is invisible to the scans again: {visible:?}"
    );
}

#[test]
fn every_parser_in_the_source_is_classified() {
    let mut unclassified: Vec<String> = Vec::new();
    for (name, source) in test_sources() {
        if !name.contains("/src/") {
            continue;
        }
        for (function, params) in declared_functions(&production_code(&source)) {
            let bare = function.rsplit("::").next().unwrap_or(&function);
            let is_parser = ["decode", "parse", "from_stored_bytes", "looks_like"]
                .iter()
                .any(|verb| bare.starts_with(verb));
            if is_parser && !is_classified(&name, &function) {
                unclassified.push(format!("{name}: fn {function}{params}"));
            }
        }
    }

    assert!(
        unclassified.is_empty(),
        ": these parsers have neither a fuzz target of their own nor a \
         recorded reason for not needing one. Classify each — a parser nobody \
         decided about is a parser nobody fuzzed:\n  {}",
        unclassified.join("\n  ")
    );
}

#[test]
fn no_two_boundary_functions_share_a_key() {
    let mut collisions: Vec<String> = Vec::new();
    for (name, source) in test_sources() {
        if !name.contains("/src/") {
            continue;
        }
        let mut seen: Vec<String> = Vec::new();
        for (function, params) in declared_functions(&production_code(&source)) {
            if !takes_bytes_or_text(&params) {
                continue;
            }
            if seen.contains(&function) {
                collisions.push(format!("{name}::{function}"));
            }
            seen.push(function);
        }
    }
    assert!(
        collisions.is_empty(),
        "these boundary functions share a classification key, so one row would \
         cover several: {collisions:?}"
    );
}

#[test]
fn no_free_function_is_attributed_to_an_impl() {
    // `aad.rs` declares the free function `decode` after an `impl Reader` block.
    let aad = read("crates/core/src/aad.rs");
    let names: Vec<String> = declared_functions(&production_code(&aad))
        .into_iter()
        .map(|(name, _)| name)
        .collect();
    assert!(
        names.iter().any(|n| n == "decode"),
        "aad::decode is a free function and must be keyed unqualified: {names:?}"
    );
    assert!(
        !names.iter().any(|n| n.ends_with("::decode")),
        "a free function was attributed to an impl block: {names:?}"
    );
}

#[test]
fn every_function_taking_bytes_or_text_is_classified() {
    let mut unclassified: Vec<String> = Vec::new();
    let mut boundary_count = 0_usize;
    for (name, source) in test_sources() {
        if !name.contains("/src/") {
            continue;
        }
        for (function, params) in declared_functions(&production_code(&source)) {
            if !takes_bytes_or_text(&params) {
                continue;
            }
            boundary_count += 1;
            if !is_classified(&name, &function) {
                unclassified.push(format!("{name}: fn {function}{params}"));
            }
        }
    }

    // Before the count checks, so the failure names the function.
    assert!(
        unclassified.is_empty(),
        ": these functions take bytes or text from a caller and are classified nowhere. Add each to PARSERS with a fuzz target, or to NOT_SEPARATELY_FUZZED with one of the three reason kinds:
  {}",
        unclassified.join("
  ")
    );
    assert!(
        all_declared().len() >= 40,
        "the signature scan found only {} functions in the two crates, which is          too few to have read them",
        all_declared().len()
    );
    assert_eq!(
        boundary_count,
        PARSERS.len() + NOT_SEPARATELY_FUZZED.len() - 1,
        "the classified lists and the signature scan disagree on how many          functions take bytes or text -- so a row is classified that the scan          cannot see, or the reverse. The -1 is nonce::from_stored_bytes, which          takes a fixed-size array by value and is classified because the *name*          scan reaches it: the one row the signature scan does not see, stated          here rather than left as a drifting number"
    );
}

#[test]
fn every_reason_names_one_of_the_three_kinds() {
    for (file, function, why) in NOT_SEPARATELY_FUZZED {
        assert!(
            REASON_KINDS.iter().any(|kind| why.starts_with(kind)),
            "{file}::{function}'s reason begins with none of {REASON_KINDS:?}: {why}"
        );
    }
}

#[test]
fn no_classification_names_a_function_that_is_gone() {
    let found = all_declared();
    let mut stale: Vec<String> = Vec::new();
    for (file, function, _) in NOT_SEPARATELY_FUZZED {
        if !found.iter().any(|(f, fun)| f == file && fun == function) {
            stale.push(format!("{file}::{function}"));
        }
    }
    for Parser { file, function, .. } in PARSERS {
        if !found.iter().any(|(f, fun)| f == file && fun == function) {
            stale.push(format!("{file}::{function}"));
        }
    }
    assert!(
        stale.is_empty(),
        ": these classifications name functions that no longer exist: {stale:?}"
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
