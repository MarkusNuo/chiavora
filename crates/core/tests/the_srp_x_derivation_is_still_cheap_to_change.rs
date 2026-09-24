//! A tripwire: the `x` derivation can change without a migration only until a verifier is stored.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p
}

#[test]
fn the_tripwire_would_notice_a_caller() {
    let root = repo_root();
    let planted = "let v = chiavora_core::srp::verifier(group, &x)?;";
    let commented = format!("// {planted}");

    let sees = |line: &str| {
        let code = line.split("//").next().unwrap_or("");
        code.contains("srp::verifier") || code.contains("srp_verifier")
    };

    assert!(sees(planted), "a real call must be seen");
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
}
