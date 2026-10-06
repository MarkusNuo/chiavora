//! Here rather than in `core`'s suite, where `chiavora_server` would not resolve.

#[test]
fn the_servers_negative_constraints_do_not_compile() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/compile-fail/*.rs");
}
