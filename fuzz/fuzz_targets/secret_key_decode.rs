//! Through `entry::accept`, the public path that also applies the size bound.
#![no_main]

use libfuzzer_sys::fuzz_target;

use chiavora_core::entry::{accept, SecretKeyField};
use chiavora_core::secret_key::{render, KEY_LEN};

fuzz_target!(|data: &[u8]| {
    let Ok(secret) = accept::<SecretKeyField>(data.to_vec()) else {
        return;
    };

    assert_eq!(
        secret.len(),
        KEY_LEN,
        "accepted input produced a key of the wrong length"
    );

    let line = render(&secret).expect("an accepted key must render");
    let again = accept::<SecretKeyField>(line.expose_for_printing().as_bytes().to_vec())
        .expect("a rendered key must decode");
    assert_eq!(
        again.expose(),
        secret.expose(),
        "render/decode is not the identity on an accepted key"
    );
});
