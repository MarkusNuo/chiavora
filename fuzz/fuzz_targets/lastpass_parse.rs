#![no_main]

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;

use chiavora_core::lastpass;

fuzz_target!(|data: &[u8]| {
    let Ok(imported) = lastpass::parse(Cursor::new(data)) else {
        return;
    };
    assert_eq!(
        imported.items.len(),
        imported.report.records().len(),
        "an item without a report record, or the reverse"
    );
});
