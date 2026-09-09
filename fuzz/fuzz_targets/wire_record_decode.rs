//! Fuzzes the wire parser in `crates/protocol`.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(record) = chiavora_protocol::Record::decode(data) {
        let reencoded = record
            .encode()
            .expect("a record that decoded must re-encode");
        assert_eq!(
            reencoded, data,
            "decode/encode is not the identity on accepted input"
        );

        let again = chiavora_protocol::Record::decode(&reencoded)
            .expect("re-encoded bytes must decode again");
        assert_eq!(again, record, "the round trip is not idempotent");
    }
});
