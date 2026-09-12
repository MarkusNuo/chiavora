#![no_main]

use std::io::{Cursor, Write};

use libfuzzer_sys::fuzz_target;

use chiavora_core::attachment::MAX_ATTACHMENT_BYTES;
use chiavora_core::onepux;

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
    let Ok((mut archive, imported)) = onepux::parse(Cursor::new(data)) else {
        return;
    };
    assert_eq!(
        imported.items.len(),
        imported.report.records().len(),
        "an item without a report record, or the reverse"
    );
    for item in &imported.items {
        for handle in &item.attachments {
            let mut sink = Count(0);
            if let Ok(n) = onepux::read_attachment(&mut archive, handle, &mut sink) {
                assert!(n <= MAX_ATTACHMENT_BYTES, "attachment read past the policy limit");
                assert_eq!(n, handle.declared_len(), "attachment length differs from its declaration");
            }
            assert!(sink.0 <= handle.declared_len(), "sink saw more than the declaration");
        }
    }
});
