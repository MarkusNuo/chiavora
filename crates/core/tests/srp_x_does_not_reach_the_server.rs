//! A real `srpX` is out of the server's reach by type; this scan checks it does not fabricate one.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path
}

fn rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut paths: Vec<PathBuf> = entries.filter_map(Result::ok).map(|e| e.path()).collect();
    paths.sort();
    for path in paths {
        if path.is_dir() {
            rs_files(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

const FORBIDDEN: [(&str, &str); 4] = [
    ("SrpX", "the brand itself. The server holds `v`, never `x`"),
    (
        "srp_x",
        "the snake-case form, including `derive_srp_x` — the function that \
         turns a root key into the thing the server must not have",
    ),
    (
        "from_derived_bytes",
        "the door a fabricated `Secret` would come through",
    ),
    (
        "private_exponent",
        "`srp::private_exponent` computes `x` from `srpSalt` and `srpX`; a \
         server calling it is a server deriving the exponent it stores the \
         verifier of",
    ),
];

fn code_only(source: &str) -> String {
    source
        .lines()
        .map(|line| line.split("//").next().unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n")
}

fn offenders(files: &[(String, String)]) -> Vec<String> {
    let mut out = Vec::new();
    for (name, source) in files {
        let code = code_only(source);
        for (needle, why) in FORBIDDEN {
            if code.contains(needle) {
                out.push(format!("{name}: `{needle}` — {why}"));
            }
        }
    }
    out
}

#[test]
fn nothing_in_crates_server_constructs_or_derives_srp_x() {
    let server = repo_root().join("crates").join("server").join("src");
    let mut paths = Vec::new();
    rs_files(&server, &mut paths);

    assert!(
        !paths.is_empty(),
        "no .rs files found under crates/server/src. A scan over zero files \
         reports success, which is the one result it must never be able to give"
    );

    let files: Vec<(String, String)> = paths
        .iter()
        .map(|path| {
            (
                path.strip_prefix(repo_root())
                    .unwrap_or(path)
                    .to_string_lossy()
                    .replace('\\', "/"),
                std::fs::read_to_string(path).expect("a server source file"),
            )
        })
        .collect();

    let problems = offenders(&files);
    assert!(
        problems.is_empty(),
        "`crates/server` holds the verifier and its salt. These name `x`, or a \
         door to it:\n  {}\n\nIf one of these is genuinely needed, it is a \
         change to what the server is, not a change to this list.",
        problems.join("\n  ")
    );
}

#[test]
fn the_server_scan_would_notice_srp_x() {
    let planted = vec![(
        "crates/server/src/auth.rs".to_owned(),
        "fn bad(rk: &Secret<RootKey>) { let _ = derive_srp_x(rk); }".to_owned(),
    )];
    assert_eq!(
        offenders(&planted).len(),
        1,
        "a real `derive_srp_x` call must be caught exactly once"
    );

    let commented = vec![(
        "crates/server/src/auth.rs".to_owned(),
        "// the server never calls derive_srp_x, and holds no SrpX".to_owned(),
    )];
    assert!(
        offenders(&commented).is_empty(),
        "a comment explaining the rule must not read as breaking it; that is \
         the mistake `nonce.rs` made with `getrandom`"
    );

    let innocent = vec![(
        "crates/server/src/auth.rs".to_owned(),
        "fn fine(v: &BoxedUint) -> usize { v.to_be_bytes().len() }".to_owned(),
    )];
    assert!(
        offenders(&innocent).is_empty(),
        "ordinary verifier handling must not trip it"
    );

    // Every needle must exist in `core`, or forbidding it forbids nothing.
    let core_derive = std::fs::read_to_string(repo_root().join("crates/core/src/derive.rs"))
        .expect("core's derive.rs");
    let core_srp =
        std::fs::read_to_string(repo_root().join("crates/core/src/srp.rs")).expect("core's srp.rs");
    for (needle, _) in FORBIDDEN {
        assert!(
            core_derive.contains(needle)
                || core_srp.contains(needle)
                || std::fs::read_to_string(repo_root().join("crates/core/src/secret.rs"))
                    .expect("core's secret.rs")
                    .contains(needle),
            "`{needle}` appears nowhere in core, so forbidding it above core \
             forbids nothing. A needle that cannot match is a line of this list \
             that reads as protection and is not"
        );
    }
}
