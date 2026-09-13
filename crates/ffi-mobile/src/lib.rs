//! uniffi bindings to Swift and Kotlin: capabilities, never keys (`docs/security-design.md` §3).

// uniffi's scaffolding is `unsafe extern "C"` glue; the allowance is scoped to this crate.
#![allow(unsafe_code)]

uniffi::setup_scaffolding!();
pub mod vault;

#[cfg(feature = "measurement-harness")]
pub mod harness;

#[uniffi::export]
#[must_use]
pub fn ffi_smoke() -> String {
    let value = smoke_value().to_owned();
    chiavora_core::ffi_guard::assert_not_key_material(value.as_bytes());
    value
}

#[must_use]
pub const fn smoke_value() -> &'static str {
    "chiavora-ffi-mobile:ok"
}

#[cfg(test)]
mod tests {
    use super::{ffi_smoke, smoke_value};

    #[test]
    fn smoke_value_is_the_expected_marker() {
        assert_eq!(smoke_value(), "chiavora-ffi-mobile:ok");
    }

    #[test]
    fn ffi_smoke_returns_the_same_value_as_smoke_value() {
        assert_eq!(ffi_smoke(), smoke_value());
    }
}
