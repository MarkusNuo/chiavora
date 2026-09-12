#![no_main]

use libfuzzer_sys::fuzz_target;

use chiavora_core::aad::RECORD_ATTACHMENT_CHUNK;
use chiavora_core::attachment::StoredChunk;

fuzz_target!(|data: &[u8]| {
    let Ok(chunk) = StoredChunk::decode(data) else {
        return;
    };
    assert_eq!(
        chunk.fields().record_type(),
        RECORD_ATTACHMENT_CHUNK,
        "a non-0x02 record was accepted as a chunk"
    );
    let digest = chunk.digest().expect("digest");
    let encoded = chunk.encode().expect("an accepted chunk re-encodes");
    let again = StoredChunk::decode(&encoded).expect("a re-encoded chunk decodes");
    assert_eq!(again.digest().expect("digest"), digest, "digest changed across a round trip");
    assert_eq!(again.encode().expect("encodes"), encoded, "encode is not idempotent");
});
