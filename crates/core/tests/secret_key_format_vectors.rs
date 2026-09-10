//! The Secret Key format vectors of ADR-0004, produced by an independent Python implementation.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::PathBuf;

use chiavora_core::entry::{accept, SecretKeyField};
use chiavora_core::secret_key::{render, KEY_LEN};

struct Vector {
    name: String,
    key: Vec<u8>,
    rendered: String,
}

fn field(row: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\": \"");
    let start = row.find(&needle)? + needle.len();
    let rest = row.get(start..)?;
    let end = rest.find('"')?;
    Some(rest.get(..end)?.to_owned())
}

fn vectors() -> Vec<Vector> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("vectors")
        .join("secret_key_format.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));

    let mut out = Vec::new();
    for chunk in text.split("\"name\": ").skip(1) {
        let row = format!("\"name\": {chunk}");
        let name = field(&row, "name").expect("name");
        let key_hex = field(&row, "key_hex").expect("key_hex");
        let rendered = field(&row, "rendered").expect("rendered");
        let key = (0..key_hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(key_hex.get(i..i + 2).expect("hex pair"), 16).expect("hex"))
            .collect();
        out.push(Vector {
            name,
            key,
            rendered,
        });
    }
    out
}

#[test]
fn the_vector_file_is_present_and_not_empty() {
    let vectors = vectors();
    assert!(
        vectors.len() >= 4,
        "expected at least four committed vectors, found {}",
        vectors.len()
    );
    for vector in &vectors {
        assert_eq!(vector.key.len(), KEY_LEN, "{}: not 128 bits", vector.name);
        assert_eq!(
            vector.rendered.replace('-', "").len(),
            "CHV1".len() + 28,
            "{}: not 26 key + 2 checksum characters",
            vector.name
        );
    }
}

#[test]
fn the_rust_encoder_agrees_with_the_independent_implementation() {
    for vector in vectors() {
        // `entry::accept` is the only public way from a string to the Secret Key.
        let secret = accept::<SecretKeyField>(vector.rendered.clone().into_bytes())
            .unwrap_or_else(|e| panic!("{}: {} did not decode: {e}", vector.name, vector.rendered));
        assert_eq!(
            secret.expose(),
            vector.key.as_slice(),
            "{}: decoded to the wrong key",
            vector.name
        );

        let line = render(&secret).expect("rendered");
        assert_eq!(
            line.expose_for_printing(),
            vector.rendered,
            "{}: the Rust encoder disagrees with the committed vector",
            vector.name
        );
    }
}

#[test]
fn every_vector_survives_the_forgiving_input_forms() {
    for vector in vectors() {
        let canonical = &vector.rendered;
        let variants = [
            canonical.to_lowercase(),
            canonical.replace('-', ""),
            canonical.replace('-', " "),
            format!("  {canonical}  "),
        ];
        for variant in variants {
            let secret = accept::<SecretKeyField>(variant.clone().into_bytes())
                .unwrap_or_else(|e| panic!("{}: {variant:?} should decode: {e}", vector.name));
            assert_eq!(secret.expose(), vector.key.as_slice(), "{}", vector.name);
        }
    }
}
