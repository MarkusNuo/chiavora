//! A scan suits "there is exactly one of these" and nothing else.

/// A closing brace in a test string literal ends a mask early; keep it failing
/// toward too much, never too little.
pub(crate) fn production(source: &str) -> String {
    let lines: Vec<&str> = source.lines().collect();
    let mask = production_mask(&lines);
    let kept: Vec<&str> = lines
        .iter()
        .enumerate()
        .filter(|(i, _)| mask.get(*i).copied().unwrap_or(false))
        .map(|(_, line)| *line)
        .collect();
    strip_comments(&kept.join("\n"))
}

fn production_mask(lines: &[&str]) -> Vec<bool> {
    // Built with `concat!` so this file does not contain the marker it searches for.
    let marker = concat!("#[cfg(", "test)]");
    let mut mask = vec![true; lines.len()];
    let mut i = 0;
    while i < lines.len() {
        if lines.get(i).copied().unwrap_or_default().trim() != marker {
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
    fn production_reads_past_every_cfg_test_item() {
        let m = concat!("#[cfg(", "test)]");

        let out = production(&format!(
            "pub fn before() {{}}\n{m}\nfn only_test() {{}}\npub fn after_mid() {{}}\n"
        ));
        assert!(out.contains("before") && out.contains("after_mid"), "{out}");
        assert!(!out.contains("only_test"), "{out}");

        let out = production(&format!(
            "pub fn above() {{}}\n{m}\nmod tests {{\n  fn inside() {{}}\n}}\npub fn below() {{}}\n"
        ));
        assert!(out.contains("above") && out.contains("below"), "{out}");
        assert!(!out.contains("inside"), "{out}");

        let out = production(&format!(
            "{m}\nmod tests {{\n  fn first() {{}}\n}}\npub fn after_leading() {{}}\n"
        ));
        assert!(out.contains("after_leading"), "{out}");
        assert!(!out.contains("first"), "{out}");

        let out = production(&format!(
            "{m}\nmod tests {{\n  fn t() {{\n    if true {{ let deeply_nested_only = 1; }}\n  }}\n}}\npub fn after_braces() {{}}\n"
        ));
        assert!(out.contains("after_braces"), "{out}");
        assert!(!out.contains("deeply_nested_only"), "{out}");

        let guard = production(include_str!("ffi_guard.rs"));
        assert!(
            guard.contains("fn assert_not_key_material"),
            "the FFI guard itself is still invisible to every scan built on this helper"
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
