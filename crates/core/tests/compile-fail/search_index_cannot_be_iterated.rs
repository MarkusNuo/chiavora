//! A `SearchIndex` cannot be iterated; `search` is the only way to read it.
use chiavora_core::search::SearchIndex;

fn main() {
    let index = SearchIndex::default();
    for _entry in index {}
}
