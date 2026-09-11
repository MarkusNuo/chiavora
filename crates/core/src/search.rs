//! In memory only and never persisted; anything that can query it can still probe it.

use zeroize::Zeroizing;

use crate::model::{Item, FIELD_TITLE, FIELD_URL, FIELD_USERNAME};
use crate::wrap::ItemKind;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchedField {
    Title,
    Username,
    Url,
}

/// Identifier and kind, never text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    pub item_id: Vec<u8>,
    pub kind: ItemKind,
    pub matched: MatchedField,
}

struct Entry {
    item_id: Vec<u8>,
    kind: ItemKind,
    title: Zeroizing<String>,
    username: Zeroizing<String>,
    url: Zeroizing<String>,
}

/// It has no encoding and cannot be iterated.
#[derive(Default)]
pub struct SearchIndex {
    entries: Vec<Entry>,
}

/// Redacted: counts only. The entries are plaintext account names.
impl core::fmt::Debug for SearchIndex {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SearchIndex({} entries, redacted)", self.entries.len())
    }
}

/// The one case fold, applied to both sides of every comparison.
fn fold(text: &str) -> Zeroizing<String> {
    Zeroizing::new(text.to_lowercase())
}

fn folded_field(item: &Item, name: &str) -> Zeroizing<String> {
    item.field(name).map_or_else(
        || Zeroizing::new(String::new()),
        |field| fold(&String::from_utf8_lossy(field.value())),
    )
}

impl SearchIndex {
    #[must_use]
    pub fn build<'a>(items: impl IntoIterator<Item = (&'a [u8], &'a Item)>) -> Self {
        let mut index = Self::default();
        for (item_id, item) in items {
            index.insert(item_id, item);
        }
        index
    }

    pub fn insert(&mut self, item_id: &[u8], item: &Item) {
        let entry = Entry {
            item_id: item_id.to_vec(),
            kind: item.kind(),
            title: folded_field(item, FIELD_TITLE),
            username: folded_field(item, FIELD_USERNAME),
            url: folded_field(item, FIELD_URL),
        };
        match self.entries.iter_mut().find(|e| e.item_id == item_id) {
            Some(existing) => *existing = entry,
            None => self.entries.push(entry),
        }
    }

    pub fn remove(&mut self, item_id: &[u8]) -> bool {
        let before = self.entries.len();
        self.entries.retain(|e| e.item_id != item_id);
        self.entries.len() != before
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// An empty query matches nothing.
    /// Lowercasing is not full case folding: `STRASSE` does not match `Straße`.
    #[must_use]
    pub fn search(&self, query: &str) -> Vec<Hit> {
        if query.is_empty() {
            return Vec::new();
        }
        let needle = fold(query);
        self.entries
            .iter()
            .filter_map(|e| {
                let matched = if e.title.contains(needle.as_str()) {
                    MatchedField::Title
                } else if e.username.contains(needle.as_str()) {
                    MatchedField::Username
                } else if e.url.contains(needle.as_str()) {
                    MatchedField::Url
                } else {
                    return None;
                };
                Some(Hit {
                    item_id: e.item_id.clone(),
                    kind: e.kind,
                    matched,
                })
            })
            .collect()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{fold, SearchIndex};
    use crate::model::{Item, ItemField};
    use crate::wrap::ItemKind;

    #[test]
    fn folding_is_the_same_function_on_both_sides_and_is_lowercasing_not_case_folding() {
        // `to_lowercase` keeps `ß` as `ß`; only full case folding maps it to `ss`.
        let mut index = SearchIndex::default();
        let item = Item::new(
            ItemKind::Login,
            vec![ItemField::new("title", "Straße".as_bytes().to_vec()).unwrap()],
            &[],
        )
        .unwrap();
        index.insert(b"i", &item);
        assert_eq!(index.search("STRAßE").len(), 1, "{:?}", fold("STRAßE"));
        assert_eq!(index.search("straße").len(), 1);
        assert_eq!(
            index.search("STRASSE").len(),
            0,
            "lowercasing is not case folding; if this starts matching, definition changed and the doc comment above is now wrong"
        );
    }

    #[test]
    fn debug_prints_a_count_and_nothing_else() {
        let mut index = SearchIndex::default();
        let item = Item::new(
            ItemKind::Login,
            vec![ItemField::new("title", b"correct-horse-battery-staple".to_vec()).unwrap()],
            &[],
        )
        .unwrap();
        index.insert(b"i", &item);
        let rendered = format!("{index:?}");
        assert!(!rendered.contains("correct-horse"), "{rendered}");
        assert!(rendered.contains("1 entries"), "{rendered}");
    }
}
