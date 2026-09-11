#![no_main]

use libfuzzer_sys::fuzz_target;

use chiavora_core::stored_record::StoredRecord;

fuzz_target!(|data: &[u8]| {
    let Ok(record) = StoredRecord::decode(data) else {
        return;
    };
    let kind = record.kind().expect("an accepted record has a known kind");
    assert_eq!(
        record.wraps().wrap_count(),
        kind.wrap_count(),
        "the wrap set disagrees with the kind"
    );

    let digest = record.ciphertext_digest().expect("digest");
    let encoded = record.encode().expect("an accepted record re-encodes");
    let again = StoredRecord::decode(&encoded).expect("a re-encoded record decodes");
    assert_eq!(
        again.ciphertext_digest().expect("digest"),
        digest,
        "ciphertextDigest changed across a round trip"
    );
    assert_eq!(again.encode().expect("encodes"), encoded, "encode is not idempotent");
});
