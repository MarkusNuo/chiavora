#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(fields) = chiavora_core::aad::decode(data) {
        let reencoded = chiavora_core::aad::encode(&fields)
            .expect("fields that decoded must re-encode");
        assert_eq!(
            reencoded, data,
            "I3: decode/encode is not the identity on accepted AAD"
        );
    }
});
