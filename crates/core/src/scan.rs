//! A scan suits "there is exactly one of these" and nothing else.

/// A closing brace in a test string literal ends a mask early; keep it failing
/// toward too much, never too little.
pub(crate) fn production(source: &str) -> String {
    // Built with `concat!` so this file does not contain the marker it searches for.
    let marker = concat!("#[cfg(", "test)]");
    let code = source.split(marker).next().unwrap_or(source);
    strip_comments(code)
}

/// A comment marker inside a string literal cuts that line short too.
fn strip_comments(code: &str) -> String {
    code.lines()
        .map(|line| match line.find("//") {
            Some(at) => line.get(..at).unwrap_or(""),
            None => line,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{production, strip_comments};

    #[test]
    fn comments_are_stripped_including_doc_comments() {
        let input = "//! module doc mentioning getrandom\n\
                     let a = 1; // trailing comment mentioning getrandom\n\
                     /// item doc mentioning getrandom\n\
                     let b = 2;";
        let out = strip_comments(input);
        assert!(
            !out.contains("getrandom"),
            "a comment survived the strip: {out}"
        );
        assert!(out.contains("let a = 1;"));
        assert!(out.contains("let b = 2;"));
    }

    #[test]
    fn the_test_module_is_removed_before_the_comments_are() {
        let input = concat!(
            "let production = 1;\n",
            "#[cfg(",
            "test)]\n",
            "mod tests { let in_a_test = 2; }"
        );
        let out = production(input);
        assert!(out.contains("let production = 1;"));
        assert!(
            !out.contains("in_a_test"),
            "the test module survived: {out}"
        );
    }

    #[test]
    fn this_module_does_not_match_its_own_marker() {
        let out = production(include_str!("scan.rs"));
        assert!(
            out.contains("fn production"),
            "scan.rs cannot scan itself, which is the bug this guards"
        );
    }
}
