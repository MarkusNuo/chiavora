//! Fuzzes the export file reader, whose framing is parsed before the MAC is checked.
#![no_main]

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;

use chiavora_core::export;
use chiavora_core::secret::{kind::Muk, Secret};
use chiavora_core::store::{Store, Unanchored};

fuzz_target!(|data: &[u8]| {
    let muk = Secret::<Muk>::from_derived_bytes(vec![0x42; 32]);
    let Ok(header) = export::verify(Cursor::new(data), &muk) else {
        return;
    };
    let mut store = Store::open_in_memory(&muk, Box::new(Unanchored)).expect("an in-memory store opens");
    let summary = export::restore(Cursor::new(data), &muk, &mut store).expect("a verified file restores");
    assert_eq!(summary.records, header.records(), "restore and header disagree on records");
    assert_eq!(summary.chunks, header.chunks(), "restore and header disagree on chunks");
});
