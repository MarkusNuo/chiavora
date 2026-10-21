//! `BoxedMontyForm` has no `pow_vartime` today; this guards a switch to a type that has one.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

const ALLOWED_VARTIME: &[(&str, &str)] = &[(
    "rem_vartime",
    "operates on A and B, which are public protocol values, against the \
     published modulus N — RFC 5054 §2.6's `B % N == 0` abort",
)];

const FORBIDDEN: &[&str] = &["pow_vartime", "pow_bounded_exp_vartime"];

fn srp_source() -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/srp.rs");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
}

fn production(source: &str) -> String {
    let marker = concat!("#[cfg(", "test)]");
    let mut kept: Vec<&str> = Vec::new();
    let mut depth = 0_i32;
    let mut masking = false;
    for line in source.lines() {
        if !masking && line.trim() == marker {
            masking = true;
            depth = 0;
            continue;
        }
        if masking {
            depth += i32::try_from(line.matches('{').count()).unwrap_or(0);
            depth -= i32::try_from(line.matches('}').count()).unwrap_or(0);
            if depth <= 0 && line.contains('}') {
                masking = false;
            }
            continue;
        }
        let code = line.split("//").next().unwrap_or("");
        kept.push(code);
    }
    kept.join("\n")
}

fn vartime_problems(source: &str) -> Vec<String> {
    let code = production(source);
    let mut problems = Vec::new();

    for forbidden in FORBIDDEN {
        if code.contains(forbidden) {
            problems.push(format!(
                "`{forbidden}` appears in srp.rs's production code. The secret \
                 exponent goes through `pow_bounded_exp` and nothing else."
            ));
        }
    }

    for (index, line) in code.lines().enumerate() {
        if !line.contains("_vartime") {
            continue;
        }
        let allowed = ALLOWED_VARTIME.iter().any(|(name, _)| line.contains(name));
        if !allowed {
            problems.push(format!(
                "srp.rs:{} calls a `_vartime` function that is not in \
                 ALLOWED_VARTIME: {}",
                index + 1,
                line.trim()
            ));
        }
    }
    problems
}

#[test]
fn no_variable_time_exponentiation_reaches_a_secret_exponent() {
    let problems = vartime_problems(&srp_source());
    assert!(
        problems.is_empty(),
        "constant-time exponentiation (docs/security-design.md §3.2):\n  {}",
        problems.join("\n  ")
    );
}

#[test]
fn the_vartime_scan_fires_on_each_violation_planted_in_the_real_module() {
    let real = srp_source();
    assert!(
        vartime_problems(&real).is_empty(),
        "precondition: the real module is clean"
    );

    let with_pow_vartime = real.replace(
        ".pow_bounded_exp(&exponent, bound)",
        ".pow_vartime(&exponent)",
    );
    assert_ne!(
        with_pow_vartime, real,
        "the splice must actually change the source, or the case proves nothing"
    );
    assert!(
        !vartime_problems(&with_pow_vartime).is_empty(),
        "a planted `pow_vartime` must be caught"
    );

    let with_unlisted = real.replace(
        "let bytes = value.to_be_bytes();",
        "let bytes = value.to_be_bytes_trimmed_vartime();",
    );
    assert_ne!(with_unlisted, real);
    assert!(
        !vartime_problems(&with_unlisted).is_empty(),
        "a `_vartime` call outside ALLOWED_VARTIME must be caught"
    );

    let after_tests = format!("{real}\nfn appended() {{ let _ = pow_vartime; }}\n");
    assert!(
        !vartime_problems(&after_tests).is_empty(),
        "a violation after the test module must still be seen"
    );
}

#[test]
fn every_permitted_vartime_call_states_what_it_operates_on() {
    assert!(
        !ALLOWED_VARTIME.is_empty(),
        "ALLOWED_VARTIME is empty, so the checks below ran over nothing"
    );
    for (name, reason) in ALLOWED_VARTIME {
        assert!(name.ends_with("_vartime"), "{name} is not a vartime call");
        assert!(
            reason.len() > 40,
            "{name}'s reason must say what value it operates on, not merely that \
             it is allowed"
        );
    }
}
