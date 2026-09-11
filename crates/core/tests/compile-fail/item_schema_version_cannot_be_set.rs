//! `Item::schema_version` is private, so a client cannot downgrade it.
use chiavora_core::model::{Item, ItemField};
use chiavora_core::wrap::ItemKind;

fn main() {
    let mut item = Item::new(
        ItemKind::Note,
        vec![ItemField::new("body", b"text".to_vec()).unwrap()],
        &[],
    )
    .unwrap();
    item.schema_version = 1;
}
