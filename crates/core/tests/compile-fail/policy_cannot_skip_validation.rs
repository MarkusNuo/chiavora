//! A `Policy` cannot be built from a struct literal, which would skip the checks in `Policy::new`.

use chiavora_core::generate::{CharClass, Policy};

fn main() {
    let policy = Policy {
        length: 0,
        classes: vec![CharClass::Digit],
        exclude_ambiguous: false,
        require_one_of_each: false,
    };
    let _ = policy;
}
