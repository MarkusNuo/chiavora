//! Behind an AEAD tag, but a newer client may write bodies this build did not produce.
#![no_main]

use libfuzzer_sys::fuzz_target;

use chiavora_core::model::Item;
use chiavora_protocol::Record;

fuzz_target!(|data: &[u8]| {
    let Ok(item) = Item::from_bytes(data) else {
        return;
    };
    let Ok(original) = Record::decode(data) else {
        panic!("Item::from_bytes accepted bytes Record::decode refuses");
    };

    let encoded = item.to_bytes().expect("an accepted item re-encodes");
    let after = Record::decode(&encoded).expect("a re-encoded body is a record");

    assert_eq!(
        after.fields().len(),
        original.fields().len(),
        "field count changed across a round trip"
    );
    let before_tags: Vec<_> = original.fields().iter().map(|f| f.tag()).collect();
    let after_tags: Vec<_> = after.fields().iter().map(|f| f.tag()).collect();
    assert_eq!(before_tags, after_tags, "field order changed across a round trip");

    assert_eq!(after.version(), original.version(), "wire version changed");
    let again = Item::from_bytes(&encoded).expect("a re-encoded body decodes");
    assert_eq!(again.schema_version(), item.schema_version(), "schema version changed");
    assert_eq!(again.kind(), item.kind(), "kind changed");

    assert_eq!(again.to_bytes().expect("encodes"), encoded, "encode is not idempotent");
});
