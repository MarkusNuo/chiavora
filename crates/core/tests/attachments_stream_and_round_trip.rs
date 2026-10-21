#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::io::{Cursor, Read};
use std::path::PathBuf;

use chiavora_core::aad::AadFields;
use chiavora_core::attachment::{
    open_attachment, seal_attachment, AttachmentError, AttachmentRef, StoredChunk, CHUNK_LEN,
    MAX_ATTACHMENT_BYTES,
};
use chiavora_core::item::seal_chunk;
use chiavora_core::nonce::FreshNonce;
use chiavora_core::secret::{
    kind::{ItemKey, Muk},
    Secret,
};
use chiavora_core::store::{Store, Unanchored};
use chiavora_protocol::Record;

fn root() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p
}

struct TempDb(PathBuf);
impl TempDb {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "chiavora-attach-{}-{}-{name}.sqlite",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default()
        ));
        let _ = std::fs::remove_file(&path);
        Self(path)
    }
}
impl Drop for TempDb {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn muk() -> Secret<Muk> {
    Secret::<Muk>::from_derived_bytes(vec![0x4D; 32])
}
fn item_key() -> Secret<ItemKey> {
    Secret::<ItemKey>::from_derived_bytes(vec![0x11; 32])
}
const AT: AttachmentRef<'static> = AttachmentRef {
    vault_id: b"vault-1",
    item_id: b"item-1",
    version: 3,
    attachment_id: b"att-1",
};

/// Non-repeating content, so a reordered or truncated chunk cannot match by accident.
fn content(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| u8::try_from((i.wrapping_mul(31) ^ (i >> 8)) & 0xFF).unwrap())
        .collect()
}

struct Watching<R> {
    inner: R,
    largest_request: usize,
}
impl<R: Read> Read for Watching<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.largest_request = self.largest_request.max(buf.len());
        self.inner.read(buf)
    }
}

#[test]
fn a_three_and_a_half_chunk_attachment_round_trips_across_a_restart() {
    let db = TempDb::new("roundtrip");
    let len = 3 * CHUNK_LEN + CHUNK_LEN / 2;
    let plaintext = content(len);

    {
        let mut store = Store::open(&db.0, &muk(), Box::new(Unanchored)).unwrap();
        let count = seal_attachment(
            &mut store,
            &item_key(),
            AT,
            b"application/pdf",
            len as u64,
            Cursor::new(&plaintext),
        )
        .unwrap();
        assert_eq!(count, 4, "3.5 chunks is four chunks");
        assert_eq!(
            store
                .list_chunks(AT.vault_id, AT.item_id, AT.attachment_id)
                .unwrap(),
            [0, 1, 2, 3]
        );
    }
    let store = Store::open(&db.0, &muk(), Box::new(Unanchored)).unwrap();
    let mut out = Vec::new();
    let total = open_attachment(&store, &item_key(), AT, &mut out).unwrap();
    assert_eq!(total, len as u64);
    assert_eq!(out, plaintext);
}

#[test]
fn the_source_is_read_a_chunk_at_a_time_and_chunks_land_as_they_are_sealed() {
    let mut store = Store::open_in_memory(&muk(), Box::new(Unanchored)).unwrap();
    let len = 2 * CHUNK_LEN + 17;
    let source = Watching {
        inner: Cursor::new(content(len)),
        largest_request: 0,
    };
    let mut watcher = source;
    let count = seal_attachment(
        &mut store,
        &item_key(),
        AT,
        b"text/plain",
        len as u64,
        &mut watcher,
    )
    .unwrap();
    assert_eq!(count, 3);
    assert!(
        watcher.largest_request <= CHUNK_LEN,
        "the source was asked for {} bytes at once",
        watcher.largest_request
    );
    assert_eq!(
        store
            .list_chunks(AT.vault_id, AT.item_id, AT.attachment_id)
            .unwrap()
            .len(),
        3
    );
}

#[test]
fn the_policy_limit_is_refused_before_a_byte_is_read() {
    let mut store = Store::open_in_memory(&muk(), Box::new(Unanchored)).unwrap();
    let mut watcher = Watching {
        inner: Cursor::new(Vec::<u8>::new()),
        largest_request: 0,
    };
    let err = seal_attachment(
        &mut store,
        &item_key(),
        AT,
        b"x",
        MAX_ATTACHMENT_BYTES + 1,
        &mut watcher,
    )
    .unwrap_err();
    assert!(matches!(err, AttachmentError::TooLarge { max } if max == MAX_ATTACHMENT_BYTES));
    assert_eq!(
        watcher.largest_request, 0,
        "the source was read before the limit was applied"
    );
    assert!(
        store
            .list_chunks(AT.vault_id, AT.item_id, AT.attachment_id)
            .unwrap()
            .is_empty(),
        "a refused attachment left chunks behind"
    );

    let err = seal_attachment(
        &mut store,
        &item_key(),
        AT,
        b"x",
        0,
        Cursor::new(Vec::<u8>::new()),
    )
    .unwrap_err();
    assert!(matches!(err, AttachmentError::Empty));
}

#[test]
fn a_length_mismatch_is_refused_and_leaves_no_chunks_behind() {
    let mut store = Store::open_in_memory(&muk(), Box::new(Unanchored)).unwrap();
    // Declares 2.5 chunks, delivers 2.
    let err = seal_attachment(
        &mut store,
        &item_key(),
        AT,
        b"x",
        (2 * CHUNK_LEN + CHUNK_LEN / 2) as u64,
        Cursor::new(content(2 * CHUNK_LEN)),
    )
    .unwrap_err();
    assert!(
        matches!(err, AttachmentError::LengthMismatch { .. }),
        "{err:?}"
    );
    assert!(
        store
            .list_chunks(AT.vault_id, AT.item_id, AT.attachment_id)
            .unwrap()
            .is_empty(),
        "partial chunks were left in the store"
    );
    // Declares 1 chunk, delivers more.
    let err = seal_attachment(
        &mut store,
        &item_key(),
        AT,
        b"x",
        CHUNK_LEN as u64,
        Cursor::new(content(CHUNK_LEN + 1)),
    )
    .unwrap_err();
    assert!(
        matches!(err, AttachmentError::LengthMismatch { .. }),
        "{err:?}"
    );
    assert!(
        store
            .list_chunks(AT.vault_id, AT.item_id, AT.attachment_id)
            .unwrap()
            .is_empty(),
        "a length-mismatched attachment left chunks behind"
    );
}

#[test]
fn a_reordered_chunk_is_refused_by_its_binding() {
    let mut store = Store::open_in_memory(&muk(), Box::new(Unanchored)).unwrap();
    let len = 2 * CHUNK_LEN + 5;
    seal_attachment(
        &mut store,
        &item_key(),
        AT,
        b"x",
        len as u64,
        Cursor::new(content(len)),
    )
    .unwrap();
    // Swap chunks 0 and 1: each is a valid record for the other position.
    let c0 = store
        .get_chunk_raw(AT.vault_id, AT.item_id, AT.attachment_id, 0)
        .unwrap()
        .unwrap();
    let c1 = store
        .get_chunk_raw(AT.vault_id, AT.item_id, AT.attachment_id, 1)
        .unwrap()
        .unwrap();
    store
        .put_chunk_raw(AT.vault_id, AT.item_id, AT.attachment_id, 0, &c1)
        .unwrap();
    store
        .put_chunk_raw(AT.vault_id, AT.item_id, AT.attachment_id, 1, &c0)
        .unwrap();
    let err = open_attachment(&store, &item_key(), AT, Vec::new()).unwrap_err();
    assert!(
        matches!(err, AttachmentError::ChunkBinding { at: 0 }),
        "{err:?}"
    );
}

#[test]
fn a_chunk_from_another_attachment_or_version_is_refused_by_its_binding() {
    let mut store = Store::open_in_memory(&muk(), Box::new(Unanchored)).unwrap();
    let len = CHUNK_LEN + 5;
    seal_attachment(
        &mut store,
        &item_key(),
        AT,
        b"x",
        len as u64,
        Cursor::new(content(len)),
    )
    .unwrap();
    let other = AttachmentRef { version: 4, ..AT };
    seal_attachment(
        &mut store,
        &item_key(),
        other,
        b"x",
        len as u64,
        Cursor::new(content(len)),
    )
    .unwrap();
    let from_v4 = store
        .get_chunk_raw(other.vault_id, other.item_id, other.attachment_id, 1)
        .unwrap()
        .unwrap();
    // Both versions share one store key, so re-seal v3 before planting v4's chunk 1.
    seal_attachment(
        &mut store,
        &item_key(),
        AT,
        b"x",
        len as u64,
        Cursor::new(content(len)),
    )
    .unwrap();
    store
        .put_chunk_raw(AT.vault_id, AT.item_id, AT.attachment_id, 1, &from_v4)
        .unwrap();
    let err = open_attachment(&store, &item_key(), AT, Vec::new()).unwrap_err();
    assert!(
        matches!(err, AttachmentError::ChunkBinding { at: 1 }),
        "{err:?}"
    );
}

#[test]
fn a_short_non_last_chunk_is_refused_after_opening() {
    // Chunk 0 one byte short, under the right key and an AAD claiming two chunks.
    let mut store = Store::open_in_memory(&muk(), Box::new(Unanchored)).unwrap();
    let fields = AadFields::AttachmentChunk {
        vault_id: AT.vault_id.to_vec(),
        item_id: AT.item_id.to_vec(),
        version: AT.version,
        attachment_id: AT.attachment_id.to_vec(),
        chunk_index: 0,
        chunk_count: 2,
        content_type: b"x".to_vec(),
    };
    let short = content(CHUNK_LEN - 1);
    let payload = seal_chunk(
        &item_key(),
        FreshNonce::generate().unwrap(),
        &fields,
        &short,
    )
    .unwrap();
    let encoded = StoredChunk::new(fields, payload).unwrap().encode().unwrap();
    store
        .put_chunk_raw(AT.vault_id, AT.item_id, AT.attachment_id, 0, &encoded)
        .unwrap();
    let err = open_attachment(&store, &item_key(), AT, Vec::new()).unwrap_err();
    assert!(
        matches!(err, AttachmentError::ChunkLength { at: 0 }),
        "{err:?}"
    );
}

#[test]
fn a_missing_chunk_and_an_extra_chunk_are_both_named() {
    let mut store = Store::open_in_memory(&muk(), Box::new(Unanchored)).unwrap();
    let len = 2 * CHUNK_LEN + 5;
    seal_attachment(
        &mut store,
        &item_key(),
        AT,
        b"x",
        len as u64,
        Cursor::new(content(len)),
    )
    .unwrap();
    let saved = store
        .get_chunk_raw(AT.vault_id, AT.item_id, AT.attachment_id, 2)
        .unwrap()
        .unwrap();
    store
        .put_chunk_raw(AT.vault_id, AT.item_id, AT.attachment_id, 7, &saved)
        .unwrap();
    let err = open_attachment(&store, &item_key(), AT, Vec::new()).unwrap_err();
    assert!(matches!(err, AttachmentError::ExtraChunks), "{err:?}");
}

#[test]
fn chunk_bytes_the_build_cannot_decode_round_trip_identically() {
    let garbage: Vec<u8> = (0..=255u8).cycle().take(3_000).collect();
    assert!(Record::decode(&garbage).is_err());
    let mut store = Store::open_in_memory(&muk(), Box::new(Unanchored)).unwrap();
    store.put_chunk_raw(b"v", b"i", b"a", 5, &garbage).unwrap();
    assert_eq!(
        store.get_chunk_raw(b"v", b"i", b"a", 5).unwrap().unwrap(),
        garbage
    );
    assert_eq!(store.list_chunks(b"v", b"i", b"a").unwrap(), [5]);
    assert!(store.delete_attachment(b"v", b"i", b"a").unwrap() > 0);
    assert!(
        store.list_chunks(b"v", b"i", b"a").unwrap().is_empty(),
        "delete_attachment reported a count and left chunks behind"
    );
}

#[test]
fn the_database_file_holds_none_of_the_attachment() {
    let db = TempDb::new("canary");
    // The canary is not a substring of the schema.
    let plaintext: Vec<u8> = b"ATTACHMENT-CANARY-9f8e7d6c5b4a-"
        .iter()
        .copied()
        .cycle()
        .take(CHUNK_LEN + 4096)
        .collect();
    {
        let mut store = Store::open(&db.0, &muk(), Box::new(Unanchored)).unwrap();
        seal_attachment(
            &mut store,
            &item_key(),
            AT,
            b"text/plain",
            plaintext.len() as u64,
            Cursor::new(&plaintext),
        )
        .unwrap();
    }
    let file = std::fs::read(&db.0).unwrap();
    let canary = &b"ATTACHMENT-CANARY-9f8e7d6c5b4a"[..];
    assert!(
        !file.windows(canary.len()).any(|w| w == canary),
        "the database file contains attachment plaintext"
    );
}

#[test]
#[ignore = "writes fuzz/corpus/stored_chunk_decode; run explicitly"]
fn regenerate_stored_chunk_corpus() {
    let dir = root()
        .join("fuzz")
        .join("corpus")
        .join("stored_chunk_decode");
    std::fs::create_dir_all(&dir).unwrap();
    let mut n: u32 = 0;
    for (count, index) in [
        (1, 0),
        (2, 0),
        (2, 1),
        (3, 0),
        (3, 1),
        (3, 2),
        (4, 3),
        (5, 2),
        (7, 6),
        (9, 0),
        (9, 8),
        (12, 5),
    ] {
        let fields = AadFields::AttachmentChunk {
            vault_id: b"vault-1".to_vec(),
            item_id: format!("item-{n}").into_bytes(),
            version: u64::from(n),
            attachment_id: b"att".to_vec(),
            chunk_index: index,
            chunk_count: count,
            content_type: b"application/octet-stream".to_vec(),
        };
        // Small plaintexts: the fuzzer explores structure, not megabytes.
        let body = content(64 + usize::try_from(n).unwrap() * 7);
        let payload =
            seal_chunk(&item_key(), FreshNonce::generate().unwrap(), &fields, &body).unwrap();
        let encoded = StoredChunk::new(fields, payload).unwrap().encode().unwrap();
        std::fs::write(dir.join(format!("seed-{count}-{index}")), encoded).unwrap();
        n += 1;
    }
    assert!(n >= 10);
}
