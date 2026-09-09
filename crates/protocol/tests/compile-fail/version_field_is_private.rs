//! The version is a private field, so it cannot be assigned around the missing setter.
use chiavora_protocol::Record;

fn main() {
    let mut record = Record::new(Vec::new());
    record.version = 1;
}
