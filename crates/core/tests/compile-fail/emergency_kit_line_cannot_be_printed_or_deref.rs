//! An `EmergencyKitLine` can neither be printed with `{}` nor used as a `&str`.

use chiavora_core::secret_key::{generate, render};

fn takes_a_str(_value: &str) {}

fn main() {
    let key = generate().unwrap();
    let line = render(&key).unwrap();

    // No `Display`.
    println!("{line}");

    // No `Deref` to `str`.
    takes_a_str(&line);
}
