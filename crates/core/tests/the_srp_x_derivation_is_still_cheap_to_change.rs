//! A tripwire: the `x` derivation can change without a migration only until a verifier is stored.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p
}

fn names_the_verifier(code: &str) -> bool {
    if code.contains("srp_verifier") {
        return true;
    }
    let Some(after) = code.split("srp::").nth(1) else {
        return false;
    };
    // Bounded at the statement end, so a later `verifier` on the line cannot match.
    let segment = after.split(';').next().unwrap_or(after);
    segment
        .split(|c: char| !c.is_alphanumeric() && c != '_')
        .any(|token| token == "verifier")
}

fn sources(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            // Tests compute verifiers without registering them, so they are skipped.
            if path.file_name().is_some_and(|n| {
                n == "node_modules" || n == "target" || n == "tests" || n == "benches"
            }) {
                continue;
            }
            out.extend(sources(&path));
        } else if path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| matches!(e, "rs" | "kt" | "ts" | "tsx"))
        {
            out.push(path);
        }
    }
    out
}

#[test]
fn the_tripwire_would_notice_a_caller() {
    let root = repo_root();
    let planted = "let v = chiavora_core::srp::verifier(group, &x)?;";
    let commented = format!("// {planted}");

    // The filter the test above uses, not a copy of it.
    let sees = |line: &str| names_the_verifier(line.split("//").next().unwrap_or(""));

    assert!(sees(planted), "a real call must be seen");
    assert!(
        sees("use chiavora_core::srp::{verifier, Group};"),
        "a braced import must be seen. **This was a hole**: the filter matched the literal `srp::verifier`, and `use chiavora_core::srp::{{verifier, Group}}` puts a `{{` between the two halves, so a production caller who imported the ordinary way was invisible to the tripwire. Found because a legitimate test in `crates/server` used exactly that form -- the shape the instrument could not see turning up in use before it turned up in anger"
    );
    assert!(
        sees("use chiavora_core::srp::{private_exponent, verifier};"),
        "and with another name before it, which is how it actually appeared"
    );
    assert!(
        !sees("use chiavora_core::srp::{private_exponent, Group};"),
        "a braced import that does NOT name the verifier must not fire;          otherwise the widening has turned the tripwire into a check on          whether anyone imports from `srp` at all"
    );
    assert!(
        !sees(&commented),
        "a commented-out call must not fire the tripwire; comments are stripped \
         so that a discussion of the freeze does not read as the freeze"
    );
    assert!(
        !sees("let v = something_else(group, &x)?;"),
        "an unrelated call must not fire it"
    );

    assert!(
        root.join("crates").join("server").is_dir(),
        "crates/server must exist, or this tripwire searches an empty set"
    );
    assert!(
        root.join("crates").join("server").join("src").is_dir(),
        "and crates/server/src specifically, which is the half the walk still reads excluded `tests`"
    );

    let walked = sources(&root.join("crates").join("server"));
    let names: Vec<String> = walked
        .iter()
        .map(|path| path.to_string_lossy().replace('\\', "/"))
        .collect();
    assert!(
        names.iter().any(|name| name.contains("/src/")),
        "the walk must still reach crates/server/src; if it reaches nothing          there, the exclusion has taken the production half with it"
    );
    assert!(
        !names.iter().any(|name| name.contains("/tests/")),
        "and must not reach crates/server/tests, which is what the exclusion is"
    );
}
