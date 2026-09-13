//! SQLite as a byte store, with metadata `core` authenticates before it trusts.

use std::collections::BTreeMap;
use std::path::Path;

use hmac::{Hmac, Mac};
use rusqlite::{params, Connection, OptionalExtension};
use sha2::Sha256;

use chiavora_protocol::{Field, Record, WireError};

use crate::derive::{derive_store_key, DeriveError};
use crate::secret::{
    kind::{Muk, StoreKey},
    Secret,
};

pub const STORE_SCHEMA_VERSION: u16 = 1;

/// Tags of the metadata record; additive only.
pub mod meta_tag {
    use chiavora_protocol::Tag;

    pub const SCHEMA_VERSION: Tag = 1;
    pub const GENERATION: Tag = 2;
    pub const HIGH_WATER_MARK: Tag = 3;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RollbackProtection {
    Anchored,
    IntegrityOnly,
}

/// Something outside the database file that remembers the latest generation
/// this device committed, so a file replaced by an older copy of itself is caught.
pub trait RollbackAnchor {
    fn latest(&self) -> Option<u64>;
    /// Records `generation` as committed, durably and outside the file.
    fn advance(&mut self, generation: u64) -> Result<(), StoreError>;
    fn protection(&self) -> RollbackProtection;
}
#[derive(Debug, Clone, Copy, Default)]
pub struct Unanchored;
impl RollbackAnchor for Unanchored {
    fn latest(&self) -> Option<u64> {
        None
    }
    fn advance(&mut self, _generation: u64) -> Result<(), StoreError> {
        Ok(())
    }
    fn protection(&self) -> RollbackProtection {
        RollbackProtection::IntegrityOnly
    }
}

/// No variant carries stored bytes.
#[derive(Debug)]
pub enum StoreError {
    /// Its message names SQL and OS errors, never blob content.
    Database(rusqlite::Error),
    MetadataTampered,
    MetadataRewound {
        stored: u64,
        anchor: u64,
    },
    MetadataMissing,
    MetadataMalformed,
    UnsupportedStoreSchema {
        found: u16,
    },
    HighWaterMarkDecrease {
        current: u64,
        proposed: u64,
    },
    VersionOutOfRange,
    Derive(DeriveError),
    Wire(WireError),
    AnchorFailed,
    MacKeyLength,
}

impl core::fmt::Display for StoreError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Database(e) => write!(f, "database: {e}"),
            Self::MetadataTampered => f.write_str("the store's metadata failed authentication"),
            Self::MetadataRewound { stored, anchor } => write!(
                f,
                "the store's metadata is at generation {stored} but this device last committed {anchor}"
            ),
            Self::MetadataMissing => f.write_str("the store has records but no metadata"),
            Self::MetadataMalformed => f.write_str("the store's metadata verified but is malformed"),
            Self::UnsupportedStoreSchema { found } => {
                write!(f, "store schema version {found} is not one this build understands")
            }
            Self::HighWaterMarkDecrease { current, proposed } => write!(
                f,
                "a high-water mark may only increase: {current} is stored, {proposed} was proposed"
            ),
            Self::VersionOutOfRange => f.write_str("a record version exceeds what the store can hold"),
            Self::Derive(e) => write!(f, "{e}"),
            Self::Wire(e) => write!(f, "{e}"),
            Self::AnchorFailed => f.write_str("the rollback anchor refused to record the generation"),
            Self::MacKeyLength => f.write_str("HMAC refused the Store Key's length"),
        }
    }
}

impl core::error::Error for StoreError {}

impl From<rusqlite::Error> for StoreError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Database(e)
    }
}

impl From<DeriveError> for StoreError {
    fn from(e: DeriveError) -> Self {
        Self::Derive(e)
    }
}

impl From<WireError> for StoreError {
    fn from(e: WireError) -> Self {
        Self::Wire(e)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredRaw {
    pub version: u64,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Metadata {
    schema_version: u16,
    generation: u64,
    /// `BTreeMap`, so the encoding is canonical.
    high_water_marks: BTreeMap<Vec<u8>, u64>,
}

type HmacSha256 = Hmac<Sha256>;

impl Metadata {
    fn fresh() -> Self {
        Self {
            schema_version: STORE_SCHEMA_VERSION,
            generation: 0,
            high_water_marks: BTreeMap::new(),
        }
    }

    fn encode(&self) -> Result<Vec<u8>, StoreError> {
        let mut fields = vec![
            Field::new(
                meta_tag::SCHEMA_VERSION,
                self.schema_version.to_le_bytes().to_vec(),
            )?,
            Field::new(meta_tag::GENERATION, self.generation.to_le_bytes().to_vec())?,
        ];
        for (vault_id, seq) in &self.high_water_marks {
            let len = u16::try_from(vault_id.len()).map_err(|_| StoreError::MetadataMalformed)?;
            let mut value = len.to_le_bytes().to_vec();
            value.extend_from_slice(vault_id);
            value.extend_from_slice(&seq.to_le_bytes());
            fields.push(Field::new(meta_tag::HIGH_WATER_MARK, value)?);
        }
        Ok(Record::new(fields).encode()?)
    }

    fn decode(bytes: &[u8]) -> Result<Self, StoreError> {
        let record = Record::decode(bytes)?;
        let mut schema_version = None;
        let mut generation = None;
        let mut high_water_marks = BTreeMap::new();
        for field in record.fields() {
            match field.tag() {
                meta_tag::SCHEMA_VERSION => {
                    let b: [u8; 2] = field
                        .value()
                        .try_into()
                        .map_err(|_| StoreError::MetadataMalformed)?;
                    if schema_version.replace(u16::from_le_bytes(b)).is_some() {
                        return Err(StoreError::MetadataMalformed);
                    }
                }
                meta_tag::GENERATION => {
                    let b: [u8; 8] = field
                        .value()
                        .try_into()
                        .map_err(|_| StoreError::MetadataMalformed)?;
                    if generation.replace(u64::from_le_bytes(b)).is_some() {
                        return Err(StoreError::MetadataMalformed);
                    }
                }
                meta_tag::HIGH_WATER_MARK => {
                    let value = field.value();
                    let (len, rest) = value
                        .split_first_chunk::<2>()
                        .ok_or(StoreError::MetadataMalformed)?;
                    let len = usize::from(u16::from_le_bytes(*len));
                    if rest.len() != len + 8 {
                        return Err(StoreError::MetadataMalformed);
                    }
                    let (vault_id, seq) = rest.split_at(len);
                    let seq: [u8; 8] = seq.try_into().map_err(|_| StoreError::MetadataMalformed)?;
                    if high_water_marks
                        .insert(vault_id.to_vec(), u64::from_le_bytes(seq))
                        .is_some()
                    {
                        return Err(StoreError::MetadataMalformed);
                    }
                }
                // Metadata is rewritten whole, so an unknown tag is malformed, not preserved.
                _ => return Err(StoreError::MetadataMalformed),
            }
        }
        let schema_version = schema_version.ok_or(StoreError::MetadataMalformed)?;
        if schema_version != STORE_SCHEMA_VERSION {
            return Err(StoreError::UnsupportedStoreSchema {
                found: schema_version,
            });
        }
        Ok(Self {
            schema_version,
            generation: generation.ok_or(StoreError::MetadataMalformed)?,
            high_water_marks,
        })
    }

    fn mac(key: &Secret<StoreKey>, body: &[u8]) -> Result<Vec<u8>, StoreError> {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(key.expose())
            .map_err(|_| StoreError::MacKeyLength)?;
        mac.update(body);
        Ok(mac.finalize().into_bytes().to_vec())
    }
}

pub struct Store {
    conn: Connection,
    key: Secret<StoreKey>,
    meta: Metadata,
    anchor: Box<dyn RollbackAnchor>,
}

impl core::fmt::Debug for Store {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Store(generation {}, {} vaults, {:?})",
            self.meta.generation,
            self.meta.high_water_marks.len(),
            self.anchor.protection()
        )
    }
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS metadata (
    id   INTEGER PRIMARY KEY CHECK (id = 1),
    body BLOB NOT NULL,
    mac  BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS records (
    vault_id BLOB    NOT NULL,
    item_id  BLOB    NOT NULL,
    version  INTEGER NOT NULL,
    bytes    BLOB    NOT NULL,
    PRIMARY KEY (vault_id, item_id)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS chunks (
    vault_id      BLOB    NOT NULL,
    item_id       BLOB    NOT NULL,
    attachment_id BLOB    NOT NULL,
    chunk_index   INTEGER NOT NULL,
    bytes         BLOB    NOT NULL,
    PRIMARY KEY (vault_id, item_id, attachment_id, chunk_index)
) WITHOUT ROWID;
";

impl Store {
    /// A rewind is refused; an anchor that has never seen the store trusts it on first use.
    pub fn open(
        path: &Path,
        muk: &Secret<Muk>,
        anchor: Box<dyn RollbackAnchor>,
    ) -> Result<Self, StoreError> {
        let conn = Connection::open(path)?;
        Self::open_connection(conn, muk, anchor)
    }

    pub fn open_in_memory(
        muk: &Secret<Muk>,
        anchor: Box<dyn RollbackAnchor>,
    ) -> Result<Self, StoreError> {
        Self::open_connection(Connection::open_in_memory()?, muk, anchor)
    }

    fn open_connection(
        conn: Connection,
        muk: &Secret<Muk>,
        mut anchor: Box<dyn RollbackAnchor>,
    ) -> Result<Self, StoreError> {
        conn.execute_batch(SCHEMA)?;
        let key = derive_store_key(muk)?;

        let stored: Option<(Vec<u8>, Vec<u8>)> = conn
            .query_row("SELECT body, mac FROM metadata WHERE id = 1", [], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .optional()?;

        let meta = if let Some((body, mac)) = stored {
            // Verify before decoding, so the parser never sees unvouched bytes.
            let mut verifier = <HmacSha256 as Mac>::new_from_slice(key.expose())
                .map_err(|_| StoreError::MacKeyLength)?;
            verifier.update(&body);
            verifier
                .verify_slice(&mac)
                .map_err(|_| StoreError::MetadataTampered)?;
            Metadata::decode(&body)?
        } else {
            let records: i64 =
                conn.query_row("SELECT COUNT(*) FROM records", [], |row| row.get(0))?;
            if records != 0 {
                return Err(StoreError::MetadataMissing);
            }
            Metadata::fresh()
        };

        match anchor.latest() {
            Some(latest) if meta.generation < latest => {
                return Err(StoreError::MetadataRewound {
                    stored: meta.generation,
                    anchor: latest,
                });
            }
            Some(latest) if meta.generation == latest => {}
            // Ahead of the anchor, or the anchor has never seen this store.
            _ => anchor
                .advance(meta.generation)
                .map_err(|_| StoreError::AnchorFailed)?,
        }

        let mut store = Self {
            conn,
            key,
            meta,
            anchor,
        };
        if stored_is_fresh(&store) {
            store.persist_metadata()?;
        }
        Ok(store)
    }

    #[must_use]
    pub fn rollback_protection(&self) -> RollbackProtection {
        self.anchor.protection()
    }

    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.meta.generation
    }

    /// Stores `bytes` exactly as given, so a record this build cannot open keeps its
    /// `ciphertextDigest` (I6d).
    pub fn put_raw(
        &mut self,
        vault_id: &[u8],
        item_id: &[u8],
        version: u64,
        bytes: &[u8],
    ) -> Result<(), StoreError> {
        let version = i64::try_from(version).map_err(|_| StoreError::VersionOutOfRange)?;
        self.conn.execute(
            "INSERT INTO records (vault_id, item_id, version, bytes) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT (vault_id, item_id) DO UPDATE SET version = excluded.version, bytes = excluded.bytes",
            params![vault_id, item_id, version, bytes],
        )?;
        Ok(())
    }

    pub fn get_raw(
        &self,
        vault_id: &[u8],
        item_id: &[u8],
    ) -> Result<Option<StoredRaw>, StoreError> {
        let row: Option<(i64, Vec<u8>)> = self
            .conn
            .query_row(
                "SELECT version, bytes FROM records WHERE vault_id = ?1 AND item_id = ?2",
                params![vault_id, item_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        Ok(row.map(|(version, bytes)| StoredRaw {
            // Never negative as written; `unsigned_abs` keeps a corrupted value from wrapping.
            version: version.unsigned_abs(),
            bytes,
        }))
    }

    pub fn delete(&mut self, vault_id: &[u8], item_id: &[u8]) -> Result<bool, StoreError> {
        let n = self.conn.execute(
            "DELETE FROM records WHERE vault_id = ?1 AND item_id = ?2",
            params![vault_id, item_id],
        )?;
        Ok(n > 0)
    }

    pub fn list(&self, vault_id: &[u8]) -> Result<Vec<(Vec<u8>, u64)>, StoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT item_id, version FROM records WHERE vault_id = ?1 ORDER BY item_id")?;
        let rows = stmt.query_map(params![vault_id], |row| {
            let item_id: Vec<u8> = row.get(0)?;
            let version: i64 = row.get(1)?;
            Ok((item_id, version.unsigned_abs()))
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }

    #[must_use]
    pub fn high_water_mark(&self, vault_id: &[u8]) -> Option<u64> {
        self.meta.high_water_marks.get(vault_id).copied()
    }

    pub fn set_high_water_mark(&mut self, vault_id: &[u8], seq: u64) -> Result<(), StoreError> {
        if let Some(current) = self.high_water_mark(vault_id) {
            if seq < current {
                return Err(StoreError::HighWaterMarkDecrease {
                    current,
                    proposed: seq,
                });
            }
        }
        self.meta.high_water_marks.insert(vault_id.to_vec(), seq);
        self.persist_metadata()
    }

    /// File first, so a crash leaves the file ahead, which [`Store::open`] treats as catch-up.
    fn persist_metadata(&mut self) -> Result<(), StoreError> {
        self.meta.generation = self.meta.generation.saturating_add(1);
        let body = self.meta.encode()?;
        let mac = Metadata::mac(&self.key, &body)?;
        self.conn.execute(
            "INSERT INTO metadata (id, body, mac) VALUES (1, ?1, ?2)
             ON CONFLICT (id) DO UPDATE SET body = excluded.body, mac = excluded.mac",
            params![body, mac],
        )?;
        self.anchor
            .advance(self.meta.generation)
            .map_err(|_| StoreError::AnchorFailed)
    }

    /// The write lock is taken now, before any sealing work.
    pub fn begin_bulk(&mut self) -> Result<BulkWrite<'_>, StoreError> {
        self.conn.execute_batch("BEGIN IMMEDIATE")?;
        Ok(BulkWrite {
            store: self,
            committed: false,
        })
    }

    pub fn put_chunk_raw(
        &mut self,
        vault_id: &[u8],
        item_id: &[u8],
        attachment_id: &[u8],
        chunk_index: u32,
        bytes: &[u8],
    ) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO chunks (vault_id, item_id, attachment_id, chunk_index, bytes)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT (vault_id, item_id, attachment_id, chunk_index) DO UPDATE SET bytes = excluded.bytes",
            params![vault_id, item_id, attachment_id, i64::from(chunk_index), bytes],
        )?;
        Ok(())
    }

    pub fn get_chunk_raw(
        &self,
        vault_id: &[u8],
        item_id: &[u8],
        attachment_id: &[u8],
        chunk_index: u32,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        self.conn
            .query_row(
                "SELECT bytes FROM chunks
                 WHERE vault_id = ?1 AND item_id = ?2 AND attachment_id = ?3 AND chunk_index = ?4",
                params![vault_id, item_id, attachment_id, i64::from(chunk_index)],
                |row| row.get(0),
            )
            .optional()
            .map_err(StoreError::from)
    }

    pub fn list_chunks(
        &self,
        vault_id: &[u8],
        item_id: &[u8],
        attachment_id: &[u8],
    ) -> Result<Vec<u32>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT chunk_index FROM chunks
             WHERE vault_id = ?1 AND item_id = ?2 AND attachment_id = ?3 ORDER BY chunk_index",
        )?;
        // A row outside `u32` was not written here; rusqlite reports it as a database error.
        let rows = stmt.query_map(params![vault_id, item_id, attachment_id], |row| {
            row.get::<_, u32>(0)
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }

    pub fn list_attachments(
        &self,
        vault_id: &[u8],
        item_id: &[u8],
    ) -> Result<Vec<Vec<u8>>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT DISTINCT attachment_id FROM chunks
             WHERE vault_id = ?1 AND item_id = ?2 ORDER BY attachment_id",
        )?;
        let rows = stmt.query_map(params![vault_id, item_id], |row| row.get::<_, Vec<u8>>(0))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }

    pub fn delete_attachment(
        &mut self,
        vault_id: &[u8],
        item_id: &[u8],
        attachment_id: &[u8],
    ) -> Result<usize, StoreError> {
        self.conn
            .execute(
                "DELETE FROM chunks WHERE vault_id = ?1 AND item_id = ?2 AND attachment_id = ?3",
                params![vault_id, item_id, attachment_id],
            )
            .map_err(StoreError::from)
    }
}

/// A drop without [`BulkWrite::commit`] rolls back. Set the high-water mark only after
/// the commit, because the anchor it advances lives outside SQLite.
pub struct BulkWrite<'a> {
    store: &'a mut Store,
    committed: bool,
}

impl core::fmt::Debug for BulkWrite<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "BulkWrite(committed: {})", self.committed)
    }
}

impl BulkWrite<'_> {
    pub fn store(&mut self) -> &mut Store {
        self.store
    }

    pub fn commit(mut self) -> Result<(), StoreError> {
        self.store.conn.execute_batch("COMMIT")?;
        self.committed = true;
        Ok(())
    }
}

impl Drop for BulkWrite<'_> {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        // R1: `Drop` cannot report a failed rollback, and SQLite rolls back on close anyway.
        let _ = self.store.conn.execute_batch("ROLLBACK");
    }
}

fn stored_is_fresh(store: &Store) -> bool {
    store.meta.generation == 0 && store.meta.high_water_marks.is_empty()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::{Metadata, StoreError, STORE_SCHEMA_VERSION};

    #[test]
    fn metadata_encoding_is_canonical_and_round_trips() {
        let mut a = Metadata::fresh();
        a.high_water_marks.insert(b"vault-b".to_vec(), 7);
        a.high_water_marks.insert(b"vault-a".to_vec(), 3);
        let mut b = Metadata::fresh();
        b.high_water_marks.insert(b"vault-a".to_vec(), 3);
        b.high_water_marks.insert(b"vault-b".to_vec(), 7);
        assert_eq!(a.encode().unwrap(), b.encode().unwrap());
        assert_eq!(Metadata::decode(&a.encode().unwrap()).unwrap(), a);
    }

    #[test]
    fn a_metadata_record_from_an_unknown_store_schema_is_refused() {
        let mut m = Metadata::fresh();
        m.schema_version = STORE_SCHEMA_VERSION + 1;
        let err = Metadata::decode(&m.encode().unwrap()).unwrap_err();
        assert!(matches!(
            err,
            StoreError::UnsupportedStoreSchema { found } if found == STORE_SCHEMA_VERSION + 1
        ));
    }
}
