#[test]
fn a_version_cannot_be_lowered() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/compile-fail/*.rs");
}
