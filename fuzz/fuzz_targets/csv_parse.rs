#![no_main]

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;

use chiavora_core::csv;
use chiavora_core::import::MAX_FIELDS_PER_RECORD;

fuzz_target!(|data: &[u8]| {
    let mut seen = 0_usize;
    let result = csv::parse(Cursor::new(data), |index, row| {
        assert_eq!(index, seen, "rows must be delivered in order, once each");
        assert!(row.len() <= MAX_FIELDS_PER_RECORD, "a row over the field bound was delivered");
        seen += 1;
        Ok(())
    });
    if let Ok(rows) = result {
        assert_eq!(rows, seen, "the returned count must match the deliveries");
    }
});
