//! There is no setter, so a record's version cannot be lowered.
use chiavora_protocol::Record;

fn main() {
    let record = Record::new(Vec::new());
    record.set_version(1);
}
