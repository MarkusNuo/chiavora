//! A generator `Policy` has no `Default`; the caller chooses every setting.

use chiavora_core::generate::Policy;

fn main() {
    let policy = Policy::default();
    let _ = policy;
}
