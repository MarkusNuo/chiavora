//! Unknown fields are written back unchanged and in place; a newer schema is never lowered.

use zeroize::Zeroizing;

use crate::wrap::ItemKind;

pub const FIELD_TITLE: &str = "title";

pub const FIELD_USERNAME: &str = "username";

pub const FIELD_URL: &str = "url";

pub const SEARCHED_FIELDS: [&str; 3] = [FIELD_TITLE, FIELD_USERNAME, FIELD_URL];

pub const MAX_FIELD_NAME_BYTES: usize = 256;

pub const MAX_TAG_BYTES: usize = 256;

/// No variant carries a field name or value, because errors get logged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ItemError {
    Empty,
    TooLong {
        max: usize,
    },
    NotText,
    DuplicateField {
        at: usize,
    },
    UnknownKind,
}

impl core::fmt::Display for ItemError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::Empty => f.write_str("a field name or tag was empty"),
            Self::TooLong { max } => write!(f, "exceeds the bound of {max} bytes"),
            Self::NotText => f.write_str("a field name or tag is not printable text"),
            Self::DuplicateField { at } => write!(f, "field {at} repeats an earlier name"),
            Self::UnknownKind => f.write_str("no item kind has that tag"),
        }
    }
}

impl core::error::Error for ItemError {}

/// Imports supply names, so they are bounded and refuse control characters.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Name(String);

impl Name {
    pub fn new(name: &str, max: usize) -> Result<Self, ItemError> {
        if name.is_empty() {
            return Err(ItemError::Empty);
        }
        if name.len() > max {
            return Err(ItemError::TooLong { max });
        }
        // Refused, not stripped, so one name cannot have two spellings.
        if name.chars().any(char::is_control) {
            return Err(ItemError::NotText);
        }
        Ok(Self(name.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone)]
pub struct ItemField {
    name: Name,
    value: Zeroizing<Vec<u8>>,
}

impl core::fmt::Debug for ItemField {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "ItemField({:?}, {} bytes, redacted)",
            self.name,
            self.value.len()
        )
    }
}

impl ItemField {
    pub fn new(name: &str, value: Vec<u8>) -> Result<Self, ItemError> {
        Ok(Self {
            name: Name::new(name, MAX_FIELD_NAME_BYTES)?,
            value: Zeroizing::new(value),
        })
    }

    #[must_use]
    pub const fn name(&self) -> &Name {
        &self.name
    }

    #[must_use]
    pub fn value(&self) -> &[u8] {
        &self.value
    }
}

/// No `Display`, and a redacted `Debug`.
#[derive(Clone)]
pub struct Item {
    kind: ItemKind,
    /// No setter, so the version read is the version written back.
    schema_version: u16,
    fields: Vec<ItemField>,
    tags: Vec<Name>,
}

impl core::fmt::Debug for Item {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Item({}, schema v{}, {} fields, {} tags, redacted)",
            self.kind.tag(),
            self.schema_version,
            self.fields.len(),
            self.tags.len()
        )
    }
}

pub const SCHEMA_VERSION: u16 = 1;

impl Item {
    pub fn new(kind: ItemKind, fields: Vec<ItemField>, tags: &[&str]) -> Result<Self, ItemError> {
        for (index, field) in fields.iter().enumerate() {
            if fields
                .iter()
                .take(index)
                .any(|earlier| earlier.name() == field.name())
            {
                return Err(ItemError::DuplicateField { at: index });
            }
        }
        let tags = tags
            .iter()
            .map(|tag| Name::new(tag, MAX_TAG_BYTES))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            kind,
            schema_version: SCHEMA_VERSION,
            fields,
            tags,
        })
    }

    #[must_use]
    pub const fn kind(&self) -> ItemKind {
        self.kind
    }

    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    #[must_use]
    pub fn fields(&self) -> &[ItemField] {
        &self.fields
    }

    #[must_use]
    pub fn tags(&self) -> &[Name] {
        &self.tags
    }

    #[must_use]
    pub fn field(&self, name: &str) -> Option<&ItemField> {
        self.fields.iter().find(|f| f.name().as_str() == name)
    }

    #[must_use]
    pub const fn wrap_count(&self) -> usize {
        self.kind.wrap_count()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::{Item, ItemError, ItemField, Name, MAX_FIELD_NAME_BYTES, SEARCHED_FIELDS};
    use crate::wrap::ItemKind;

    fn login() -> Item {
        Item::new(
            ItemKind::Login,
            vec![
                ItemField::new("title", b"Example".to_vec()).unwrap(),
                ItemField::new("username", b"ada".to_vec()).unwrap(),
                ItemField::new("password", b"correct-horse-battery-staple".to_vec()).unwrap(),
            ],
            &["work"],
        )
        .unwrap()
    }

    #[test]
    fn an_item_reports_the_kind_and_fields_it_was_given() {
        let item = login();
        assert_eq!(item.kind(), ItemKind::Login);
        assert_eq!(item.fields().len(), 3);
        assert_eq!(item.tags().len(), 1);
        assert_eq!(
            item.field("username").map(ItemField::value),
            Some(&b"ada"[..])
        );
        assert!(item.field("no-such-field").is_none());
    }

    #[test]
    fn neither_debug_impl_prints_a_value() {
        let item = login();
        let rendered = format!("{item:?}");
        assert!(
            !rendered.contains("correct-horse-battery-staple"),
            "{rendered}"
        );
        assert!(!rendered.contains("ada"), "{rendered}");
        assert!(rendered.contains("login"), "the kind is legitimate to log");

        let field = ItemField::new("password", b"correct-horse-battery-staple".to_vec()).unwrap();
        let rendered = format!("{field:?}");
        assert!(
            !rendered.contains("correct-horse-battery-staple"),
            "{rendered}"
        );
    }

    #[test]
    fn duplicate_field_names_are_refused_and_the_error_names_a_position() {
        let err = Item::new(
            ItemKind::Note,
            vec![
                ItemField::new("body", b"a".to_vec()).unwrap(),
                ItemField::new("body", b"b".to_vec()).unwrap(),
            ],
            &[],
        )
        .unwrap_err();
        assert_eq!(err, ItemError::DuplicateField { at: 1 });
        assert!(!format!("{err}").contains("body"));
    }

    #[test]
    fn names_are_bounded_and_refuse_control_characters() {
        assert_eq!(Name::new("", 8).unwrap_err(), ItemError::Empty);
        assert_eq!(
            Name::new("aaaaaaaaa", 8).unwrap_err(),
            ItemError::TooLong { max: 8 }
        );
        assert_eq!(Name::new("a\nb", 8).unwrap_err(), ItemError::NotText);
        assert!(Name::new("a-real name", MAX_FIELD_NAME_BYTES).is_ok());
    }

    #[test]
    fn the_searched_fields_are_title_username_and_url() {
        assert_eq!(SEARCHED_FIELDS, ["title", "username", "url"]);
    }
}
