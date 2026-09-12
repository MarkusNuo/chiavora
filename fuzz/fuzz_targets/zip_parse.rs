//! Every entry is inflated, so the streaming bounds are exercised.
#![no_main]

use std::io::{Cursor, Write};

use libfuzzer_sys::fuzz_target;

use chiavora_core::zip::{parse, ZipError, ONE_PUX_LIMITS};

struct Count(u64);

impl Write for Count {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0 += buf.len() as u64;
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(mut archive) = parse(Cursor::new(data), &ONE_PUX_LIMITS) else {
        return;
    };
    let count = archive.entries().len();
    for index in 0..count {
        let refused = archive.entries()[index].refusal().is_some();
        let declared = archive.entries()[index].uncompressed_len();
        let mut sink = Count(0);
        match archive.read_entry(index, &mut sink) {
            Ok(n) => {
                assert!(!refused, "entry {index}: a refused entry was read");
                assert_eq!(n, declared, "entry {index}: read a different length than declared");
                assert_eq!(sink.0, n, "entry {index}: sink saw a different length than reported");
                assert!(
                    n <= ONE_PUX_LIMITS.max_entry_bytes,
                    "entry {index}: read past the per-entry bound"
                );
            }
            Err(ZipError::Refused { .. }) => assert!(refused, "entry {index}: Refused without a recorded refusal"),
            Err(_) => {
                assert!(
                    sink.0 <= declared,
                    "entry {index}: wrote past the declaration before refusing"
                );
            }
        }
    }
});
