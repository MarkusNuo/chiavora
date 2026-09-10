//! Fuzzes the Emergency Kit parser, which reads whatever a camera scanned from a QR code.
#![no_main]

use libfuzzer_sys::fuzz_target;

use chiavora_core::emergency_kit::parse;

fuzz_target!(|data: &[u8]| {
    let Ok(kit) = parse(data) else {
        return;
    };

    let rendered = kit.render_compact();
    let again = parse(rendered.as_bytes()).expect("a rendered Kit must parse");

    assert_eq!(again.account_id(), kit.account_id(), "accountId changed");
    assert_eq!(again.account_salt(), kit.account_salt(), "accountSalt changed");
    assert_eq!(
        again.secret_key().expose(),
        kit.secret_key().expose(),
        "the Secret Key changed"
    );
    assert_eq!(
        again.checkpoint(),
        kit.checkpoint(),
        "absent and present must not blur"
    );

    assert_eq!(
        *again.render_compact(),
        *rendered,
        "render is not idempotent on an accepted Kit"
    );
});
