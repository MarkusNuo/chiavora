//! Unknown fields are written back unchanged and in place; a newer schema is never lowered.

use zeroize::Zeroizing;

use chiavora_protocol::{Field, Record, Tag, WireError};

use crate::wrap::ItemKind;

pub const FIELD_TITLE: &str = "title";

pub const FIELD_USERNAME: &str = "username";

pub const FIELD_URL: &str = "url";

pub const SEARCHED_FIELDS: [&str; 3] = [FIELD_TITLE, FIELD_USERNAME, FIELD_URL];

pub const MAX_FIELD_NAME_BYTES: usize = 256;

pub const MAX_TAG_BYTES: usize = 256;

pub const SCHEMA_VERSION: u16 = 1;

// A field name's length is written as `u16` on the wire, so the bound must fit.
const _: () = assert!(MAX_FIELD_NAME_BYTES <= u16::MAX as usize);

// Schema version 0 was never written and is refused on decode.
const _: () = assert!(SCHEMA_VERSION >= 1);

/// A newer schema may add tags but never change these.
pub mod tag {
    use chiavora_protocol::Tag;

    pub const SCHEMA_VERSION: Tag = 1;
    pub const KIND: Tag = 2;
    /// One named field: `u16le(nameLen) ‖ name ‖ value`. Repeated.
    pub const FIELD: Tag = 3;
    pub const TAG: Tag = 4;
}

/// No variant carries a field name or value, because errors get logged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModelError {
    Empty,
    TooLong {
        max: usize,
    },
    NotText,
    DuplicateField {
        at: usize,
    },
    UnknownKind,
    MissingHeader {
        tag: Tag,
    },
    RepeatedHeader {
        at: usize,
    },
    Malformed {
        at: usize,
    },
    UnsupportedSchemaVersion,
    /// Unreachable, as [`Name::new`] bounds names to [`MAX_FIELD_NAME_BYTES`].
    NameTooLongForWire,
    Wire(WireError),
}

impl core::fmt::Display for ModelError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::Empty => f.write_str("a field name or tag was empty"),
            Self::TooLong { max } => write!(f, "exceeds the bound of {max} bytes"),
            Self::NotText => f.write_str("a field name or tag is not printable text"),
            Self::DuplicateField { at } => write!(f, "field {at} repeats an earlier name"),
            Self::UnknownKind => f.write_str(
                "no item kind this build knows has that tag; the record is preserved, not opened",
            ),
            Self::MissingHeader { tag } => write!(f, "the body has no field with tag {tag}"),
            Self::RepeatedHeader { at } => write!(f, "field {at} repeats a header"),
            Self::Malformed { at } => write!(f, "field {at} is not shaped as its tag requires"),
            Self::UnsupportedSchemaVersion => f.write_str("schema version 0 was never written"),
            Self::NameTooLongForWire => {
                f.write_str("a field name exceeds the wire's length prefix")
            }
            Self::Wire(inner) => write!(f, "{inner}"),
        }
    }
}

impl core::error::Error for ModelError {}

impl From<WireError> for ModelError {
    fn from(e: WireError) -> Self {
        Self::Wire(e)
    }
}

/// Imports supply names, so they are bounded and refuse control characters.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Name(String);

impl Name {
    pub fn new(name: &str, max: usize) -> Result<Self, ModelError> {
        if name.is_empty() {
            return Err(ModelError::Empty);
        }
        if name.len() > max {
            return Err(ModelError::TooLong { max });
        }
        // Refused, not stripped, so one name cannot have two spellings.
        if name.chars().any(char::is_control) {
            return Err(ModelError::NotText);
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
    pub fn new(name: &str, value: Vec<u8>) -> Result<Self, ModelError> {
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

    fn encode(&self) -> Result<Vec<u8>, ModelError> {
        let name = self.name.0.as_bytes();
        let len = u16::try_from(name.len()).map_err(|_| ModelError::NameTooLongForWire)?;
        let mut out = Vec::with_capacity(2 + name.len() + self.value.len());
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(name);
        out.extend_from_slice(&self.value);
        Ok(out)
    }

    fn decode(bytes: &[u8], at: usize) -> Result<Self, ModelError> {
        let (len, rest) = bytes
            .split_first_chunk::<2>()
            .ok_or(ModelError::Malformed { at })?;
        let len = usize::from(u16::from_le_bytes(*len));
        // Bound checked before `split_at`, which would panic past the end.
        if len > rest.len() {
            return Err(ModelError::Malformed { at });
        }
        let (name, value) = rest.split_at(len);
        let name = core::str::from_utf8(name).map_err(|_| ModelError::NotText)?;
        Ok(Self {
            name: Name::new(name, MAX_FIELD_NAME_BYTES)?,
            value: Zeroizing::new(value.to_vec()),
        })
    }
}

/// The headers are markers so their positions survive re-encoding too.
#[derive(Clone, Debug)]
enum Slot {
    SchemaVersion,
    Kind,
    Field(ItemField),
    Tag(Name),
    Unknown(Field),
}

/// No `Display`, and a redacted `Debug`.
#[derive(Clone)]
pub struct Item {
    kind: ItemKind,
    /// No setter, so the version read is the version written back.
    schema_version: u16,
    /// The body record, kept for its wire version.
    body: Record,
    slots: Vec<Slot>,
}

impl core::fmt::Debug for Item {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Item({}, schema v{}, wire v{}, {} fields, {} tags, {} unknown, redacted)",
            self.kind.tag(),
            self.schema_version,
            self.body.version(),
            self.fields().count(),
            self.tags().count(),
            self.unknown_fields().count()
        )
    }
}

impl Item {
    pub fn new(kind: ItemKind, fields: Vec<ItemField>, tags: &[&str]) -> Result<Self, ModelError> {
        let mut slots = vec![Slot::SchemaVersion, Slot::Kind];
        for field in fields {
            if slots
                .iter()
                .any(|s| matches!(s, Slot::Field(f) if f.name == field.name))
            {
                return Err(ModelError::DuplicateField { at: slots.len() });
            }
            slots.push(Slot::Field(field));
        }
        for tag in tags {
            slots.push(Slot::Tag(Name::new(tag, MAX_TAG_BYTES)?));
        }
        Ok(Self {
            kind,
            schema_version: SCHEMA_VERSION,
            body: Record::new(Vec::new()),
            slots,
        })
    }

    /// A newer schema version is accepted and preserved; an unknown kind is
    /// refused with [`ModelError::UnknownKind`] so the caller can keep the record opaque.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ModelError> {
        let body = Record::decode(bytes)?;
        let mut schema_version: Option<u16> = None;
        let mut kind: Option<ItemKind> = None;
        let mut slots = Vec::with_capacity(body.fields().len());

        for (at, field) in body.fields().iter().enumerate() {
            let slot = match field.tag() {
                tag::SCHEMA_VERSION => {
                    if schema_version.is_some() {
                        return Err(ModelError::RepeatedHeader { at });
                    }
                    let bytes: [u8; 2] = field
                        .value()
                        .try_into()
                        .map_err(|_| ModelError::Malformed { at })?;
                    let version = u16::from_le_bytes(bytes);
                    if version == 0 {
                        return Err(ModelError::UnsupportedSchemaVersion);
                    }
                    schema_version = Some(version);
                    Slot::SchemaVersion
                }
                tag::KIND => {
                    if kind.is_some() {
                        return Err(ModelError::RepeatedHeader { at });
                    }
                    let text = core::str::from_utf8(field.value())
                        .map_err(|_| ModelError::Malformed { at })?;
                    kind = Some(ItemKind::from_tag(text).ok_or(ModelError::UnknownKind)?);
                    Slot::Kind
                }
                tag::FIELD => {
                    let parsed = ItemField::decode(field.value(), at)?;
                    if slots
                        .iter()
                        .any(|s| matches!(s, Slot::Field(f) if f.name == parsed.name))
                    {
                        return Err(ModelError::DuplicateField { at });
                    }
                    Slot::Field(parsed)
                }
                tag::TAG => {
                    let text = core::str::from_utf8(field.value())
                        .map_err(|_| ModelError::Malformed { at })?;
                    Slot::Tag(Name::new(text, MAX_TAG_BYTES)?)
                }
                _ => Slot::Unknown(field.clone()),
            };
            slots.push(slot);
        }

        Ok(Self {
            kind: kind.ok_or(ModelError::MissingHeader { tag: tag::KIND })?,
            schema_version: schema_version.ok_or(ModelError::MissingHeader {
                tag: tag::SCHEMA_VERSION,
            })?,
            body,
            slots,
        })
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, ModelError> {
        let fields = self
            .slots
            .iter()
            .map(|slot| -> Result<Field, ModelError> {
                match slot {
                    Slot::SchemaVersion => Ok(Field::new(
                        tag::SCHEMA_VERSION,
                        self.schema_version.to_le_bytes().to_vec(),
                    )?),
                    Slot::Kind => Ok(Field::new(tag::KIND, self.kind.tag().as_bytes().to_vec())?),
                    Slot::Field(f) => Ok(Field::new(tag::FIELD, f.encode()?)?),
                    Slot::Tag(t) => Ok(Field::new(tag::TAG, t.0.as_bytes().to_vec())?),
                    Slot::Unknown(f) => Ok(f.clone()),
                }
            })
            .collect::<Result<Vec<_>, ModelError>>()?;
        Ok(self.body.with_fields(fields).encode()?)
    }

    pub fn set_field(&mut self, field: ItemField) {
        match self
            .slots
            .iter_mut()
            .find(|s| matches!(s, Slot::Field(f) if f.name == field.name))
        {
            Some(slot) => *slot = Slot::Field(field),
            None => self.slots.push(Slot::Field(field)),
        }
    }

    pub fn remove_field(&mut self, name: &str) -> bool {
        let before = self.slots.len();
        self.slots
            .retain(|s| !matches!(s, Slot::Field(f) if f.name.0 == name));
        self.slots.len() != before
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
    pub const fn wire_version(&self) -> u16 {
        self.body.version()
    }

    #[must_use]
    pub const fn is_from_a_newer_schema(&self) -> bool {
        self.schema_version > SCHEMA_VERSION
    }

    pub fn fields(&self) -> impl Iterator<Item = &ItemField> {
        self.slots.iter().filter_map(|s| match s {
            Slot::Field(f) => Some(f),
            _ => None,
        })
    }

    pub fn tags(&self) -> impl Iterator<Item = &Name> {
        self.slots.iter().filter_map(|s| match s {
            Slot::Tag(t) => Some(t),
            _ => None,
        })
    }

    pub fn unknown_fields(&self) -> impl Iterator<Item = &Field> {
        self.slots.iter().filter_map(|s| match s {
            Slot::Unknown(f) => Some(f),
            _ => None,
        })
    }

    #[must_use]
    pub fn field(&self, name: &str) -> Option<&ItemField> {
        self.fields().find(|f| f.name.0 == name)
    }

    #[must_use]
    pub const fn wrap_count(&self) -> usize {
        self.kind.wrap_count()
    }
}

/// One arm per version this build has written; a newer version is returned untouched.
pub fn migrate_forward(item: Item) -> Result<Item, ModelError> {
    match item.schema_version {
        1 => Ok(item),
        v if v > SCHEMA_VERSION => Ok(item),
        // Only 0, which decode already refuses.
        _ => Err(ModelError::UnsupportedSchemaVersion),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::{
        migrate_forward, tag, Item, ItemField, ModelError, Name, MAX_FIELD_NAME_BYTES,
        SCHEMA_VERSION, SEARCHED_FIELDS,
    };
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
        assert_eq!(item.fields().count(), 3);
        assert_eq!(item.tags().count(), 1);
        assert_eq!(item.unknown_fields().count(), 0);
        assert_eq!(item.schema_version(), SCHEMA_VERSION);
        assert_eq!(
            item.field("username").map(ItemField::value),
            Some(&b"ada"[..])
        );
        assert!(item.field("no-such-field").is_none());
    }

    #[test]
    fn a_new_item_round_trips_through_its_bytes() {
        let item = login();
        let bytes = item.to_bytes().unwrap();
        let again = Item::from_bytes(&bytes).unwrap();
        assert_eq!(again.kind(), ItemKind::Login);
        assert_eq!(again.schema_version(), SCHEMA_VERSION);
        assert_eq!(
            again.field("password").map(ItemField::value),
            Some(&b"correct-horse-battery-staple"[..])
        );
        assert_eq!(again.tags().map(Name::as_str).collect::<Vec<_>>(), ["work"]);
        assert_eq!(again.to_bytes().unwrap(), bytes);
    }

    #[test]
    fn set_field_replaces_in_place_and_appends_otherwise() {
        let mut item = login();
        item.set_field(ItemField::new("username", b"grace".to_vec()).unwrap());
        let names: Vec<&str> = item.fields().map(|f| f.name().as_str()).collect();
        assert_eq!(names, ["title", "username", "password"]);
        assert_eq!(item.field("username").unwrap().value(), b"grace");

        item.set_field(ItemField::new("url", b"https://example.test".to_vec()).unwrap());
        assert_eq!(item.fields().count(), 4);
        assert!(item.remove_field("url"));
        assert!(!item.remove_field("url"));
        assert_eq!(item.fields().count(), 3);
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
        // Position 3: after the two header slots and the first `body`.
        assert_eq!(err, ModelError::DuplicateField { at: 3 });
        assert!(!format!("{err}").contains("body"));
    }

    #[test]
    fn names_are_bounded_and_refuse_control_characters() {
        assert_eq!(Name::new("", 8).unwrap_err(), ModelError::Empty);
        assert_eq!(
            Name::new("aaaaaaaaa", 8).unwrap_err(),
            ModelError::TooLong { max: 8 }
        );
        assert_eq!(Name::new("a\nb", 8).unwrap_err(), ModelError::NotText);
        assert!(Name::new("a-real name", MAX_FIELD_NAME_BYTES).is_ok());
    }

    #[test]
    fn the_searched_fields_are_title_username_and_url() {
        assert_eq!(SEARCHED_FIELDS, ["title", "username", "url"]);
    }

    #[test]
    fn a_body_missing_a_header_or_repeating_one_is_refused() {
        use chiavora_protocol::{Field, Record};

        let no_kind = Record::new(vec![Field::new(tag::SCHEMA_VERSION, vec![1, 0]).unwrap()]);
        assert_eq!(
            Item::from_bytes(&no_kind.encode().unwrap()).unwrap_err(),
            ModelError::MissingHeader { tag: tag::KIND }
        );

        let twice = Record::new(vec![
            Field::new(tag::SCHEMA_VERSION, vec![1, 0]).unwrap(),
            Field::new(tag::KIND, b"note".to_vec()).unwrap(),
            Field::new(tag::KIND, b"note".to_vec()).unwrap(),
        ]);
        assert_eq!(
            Item::from_bytes(&twice.encode().unwrap()).unwrap_err(),
            ModelError::RepeatedHeader { at: 2 }
        );

        let zero = Record::new(vec![
            Field::new(tag::SCHEMA_VERSION, vec![0, 0]).unwrap(),
            Field::new(tag::KIND, b"note".to_vec()).unwrap(),
        ]);
        assert_eq!(
            Item::from_bytes(&zero.encode().unwrap()).unwrap_err(),
            ModelError::UnsupportedSchemaVersion
        );
    }

    #[test]
    fn migration_is_total_over_every_version_this_build_wrote() {
        for version in 1..=SCHEMA_VERSION {
            let item = login();
            assert_eq!(item.schema_version(), version);
            let migrated = migrate_forward(item).expect("total over written versions");
            assert_eq!(migrated.schema_version(), version);
        }
    }
}
