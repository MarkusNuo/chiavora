//! `Record::new` takes fields only, so a record cannot be built at a chosen version.
use chiavora_protocol::Record;

fn main() {
    let _record = Record::new(2, Vec::new());
}
