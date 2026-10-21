#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::PathBuf;

fn root() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p
}

fn read(rel: &str) -> String {
    let path = root().join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
}

fn test_sources() -> Vec<(String, String)> {
    let mut out = Vec::new();
    for crate_dir in ["core", "protocol"] {
        for sub in ["src", "tests"] {
            let dir = root().join("crates").join(crate_dir).join(sub);
            let mut files = Vec::new();
            rs_files_under(&dir, &mut files);
            for path in files {
                let rel = path
                    .strip_prefix(&dir)
                    .expect("under its own directory")
                    .to_string_lossy()
                    .replace('\\', "/");
                out.push((
                    format!("{crate_dir}/{sub}/{rel}"),
                    std::fs::read_to_string(&path).expect("a source file"),
                ));
            }
        }
    }
    assert!(
        out.iter().any(|(n, _)| n == "core/src/lib.rs"),
        "the source walk did not find core/src/lib.rs"
    );
    out
}

fn rs_files_under(dir: &std::path::Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut paths: Vec<PathBuf> = entries.filter_map(Result::ok).map(|e| e.path()).collect();
    paths.sort();
    for path in paths {
        if path.is_dir() {
            rs_files_under(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

#[test]
fn nested_modules_are_walked() {
    // A fixture, because the crate has no nested module yet.
    let dir = std::env::temp_dir().join(format!(
        "chiavora-nested-walk-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    std::fs::create_dir_all(dir.join("sub").join("deeper")).unwrap();
    std::fs::write(dir.join("top.rs"), "pub fn top(a: &[u8]) {}\n").unwrap();
    std::fs::write(dir.join("sub").join("mid.rs"), "pub fn mid(a: &str) {}\n").unwrap();
    std::fs::write(
        dir.join("sub").join("deeper").join("leaf.rs"),
        "pub fn leaf() {}\n",
    )
    .unwrap();
    std::fs::write(dir.join("sub").join("notes.md"), "not source\n").unwrap();

    let mut found = Vec::new();
    rs_files_under(&dir, &mut found);
    let _ = std::fs::remove_dir_all(&dir);

    let names: Vec<String> = found
        .iter()
        .map(|p| {
            p.strip_prefix(&dir)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/")
        })
        .collect();
    assert_eq!(
        names,
        ["sub/deeper/leaf.rs", "sub/mid.rs", "top.rs"],
        "the walk must reach every nesting level, take only .rs files, and be \
         deterministic"
    );
}

/// The invariants the core establishes. Each needs a test whose name starts
/// with it, so a failure names the invariant rather than a file.
const CORE_INVARIANTS: [&str; 5] = ["i1a", "i2", "i3", "i4", "i7"];

const I6_CLAUSES: [&str; 6] = ["i6a", "i6b", "i6c", "i6d", "i6e", "i6f"];

fn tests_named_for(prefix: &str) -> usize {
    let needle = format!("fn {prefix}_");
    test_sources()
        .iter()
        .map(|(_, src)| src.matches(&needle).count())
        .sum()
}

#[test]
fn every_i6_clause_has_a_test_named_for_it() {
    let missing: Vec<&str> = I6_CLAUSES
        .into_iter()
        .filter(|clause| tests_named_for(clause) == 0)
        .collect();
    assert!(missing.is_empty(), "I6 clauses with no test: {missing:?}");
}

#[test]
fn every_core_invariant_has_at_least_one_test_named_for_it() {
    let missing: Vec<&str> = CORE_INVARIANTS
        .into_iter()
        .filter(|invariant| tests_named_for(invariant) == 0)
        .collect();
    assert!(
        missing.is_empty(),
        "core invariants with no test named for them: {missing:?}"
    );
}

#[test]
fn invariants_outside_the_core_are_absent_on_purpose() {
    for later in ["i5", "i5a", "i5b", "i6", "i8"] {
        assert!(
            !CORE_INVARIANTS.contains(&later),
            "{later} is not the core's. If it is now, add it with a test named for it."
        );
    }
}

/// Attacker-supplied means bytes this process did not produce in the same operation.
const PARSERS: [Parser; 18] = [
    Parser {
        file: "core/src/manifest.rs",
        function: "StoredManifest::decode",
        target: "manifest_decode",
        why: "the stored manifest record as the server serves it; the AAD is parsed before the tag is checked",
    },
    Parser {
        file: "core/src/manifest.rs",
        function: "ManifestRoot::decode",
        target: "manifest_decode",
        why: "the manifest root a hostile server serves (A1)",
    },
    Parser {
        file: "core/src/manifest.rs",
        function: "ManifestSegment::decode",
        target: "manifest_decode",
        why: "the segments of the same server-supplied manifest",
    },
    Parser {
        file: "core/src/aad.rs",
        function: "decode",
        target: "aad_decode",
        why: "the inverse of the record AAD encoder; a disagreement is an I3 failure",
    },
    Parser {
        file: "protocol/src/lib.rs",
        function: "Record::decode",
        target: "wire_record_decode",
        why: "every encrypted record fetched from the server (A1)",
    },
    Parser {
        file: "core/src/secret_key.rs",
        function: "decode",
        target: "secret_key_decode",
        why: "a string typed into a field, or read from a QR code",
    },
    Parser {
        file: "core/src/emergency_kit.rs",
        function: "parse",
        target: "emergency_kit_parse",
        why: "a QR code a camera read",
    },
    Parser {
        file: "core/src/zip.rs",
        function: "parse",
        target: "zip_parse",
        why: "a 1PUX export is a zip archive downloaded from elsewhere",
    },
    Parser {
        file: "core/src/onepux.rs",
        function: "parse",
        target: "onepux_parse",
        why: "the JSON inside a 1PUX archive",
    },
    Parser {
        file: "core/src/onepif.rs",
        function: "parse",
        target: "onepif_parse",
        why: "1Password's older line-oriented export",
    },
    Parser {
        file: "core/src/csv.rs",
        function: "parse",
        target: "csv_parse",
        why: "the CSV reader under the LastPass and Chrome exports",
    },
    Parser {
        file: "core/src/bitwarden.rs",
        function: "parse",
        target: "bitwarden_parse",
        why: "a Bitwarden JSON export",
    },
    Parser {
        file: "core/src/lastpass.rs",
        function: "parse",
        target: "lastpass_parse",
        why: "a LastPass CSV export, with a column set that varies by version",
    },
    Parser {
        file: "core/src/chrome.rs",
        function: "parse",
        target: "chrome_parse",
        why: "Chrome's password CSV",
    },
    Parser {
        file: "core/src/export.rs",
        function: "verify",
        target: "export_verify",
        why: "a native export file A4 can rewrite; its framing is parsed before its MAC is checked",
    },
    Parser {
        file: "core/src/attachment.rs",
        function: "StoredChunk::decode",
        target: "stored_chunk_decode",
        why: "a chunk in a file A4 can rewrite, or fetched from the server (A1)",
    },
    Parser {
        file: "core/src/stored_record.rs",
        function: "StoredRecord::decode",
        target: "stored_record_decode",
        why: "a record, possibly from a newer build, in a file A4 can rewrite",
    },
    Parser {
        file: "core/src/model.rs",
        function: "Item::from_bytes",
        target: "item_body_decode",
        why: "an item body from a newer client; inside the AEAD, but not produced by this build",
    },
];

struct Parser {
    file: &'static str,
    function: &'static str,
    target: &'static str,
    why: &'static str,
}

#[test]
fn every_registered_parser_has_a_fuzz_target_with_a_corpus() {
    let targets = root().join("fuzz").join("fuzz_targets");
    let corpus = root().join("fuzz").join("corpus");
    for Parser {
        file,
        function,
        target,
        why,
    } in PARSERS
    {
        assert!(
            !why.is_empty(),
            "{file}::{function} must say why it is attacker-facing"
        );
        let source = targets.join(format!("{target}.rs"));
        assert!(
            source.exists(),
            "{file}::{function} is registered but `fuzz/fuzz_targets/{target}.rs` does not exist"
        );
        let seeds = corpus
            .join(target)
            .read_dir()
            .map_or(0, |d| d.filter_map(Result::ok).count());
        assert!(
            seeds >= 10,
            "{target} has {seeds} corpus inputs; it needs at least 10"
        );
    }
}

/// Each reason starts with one of `REASON_KINDS`: covered elsewhere (reached only through a
/// fuzzed function), safe by construction (nothing to parse or mis-trust), or
/// not a boundary (the bytes come from this crate).
const NOT_SEPARATELY_FUZZED: [(&str, &str, &str); 111] = [
    (
        "core/src/manifest.rs",
        "conflict_item_id",
        "SAFE BY CONSTRUCTION: SHA-256 over a separator, an identifier and a digest from an authenticated manifest; parses nothing",
    ),
    (
        "core/src/manifest.rs",
        "ConflictingVersion::new",
        "NOT A BOUNDARY: built from a decoded itemId and a digest this process computed",
    ),
    (
        "core/src/manifest.rs",
        "hash_item_id",
        "SAFE BY CONSTRUCTION: SHA-256 over a byte string, returning its top eight bytes; parses nothing",
    ),
    (
        "core/src/provision.rs",
        "provision_first_vault",
        "NOT A BOUNDARY: draws sixteen bytes from csprng and calls provision; accountId is an opaque key",
    ),
    (
        "core/src/unlock.rs",
        "UnlockedVault::load_provisioning",
        "COVERED ELSEWHERE: delegates to provision::load with this vault's MUK",
    ),
    (
        "core/src/unlock.rs",
        "UnlockedVault::provision_first_vault",
        "COVERED ELSEWHERE: delegates to provision::provision_first_vault",
    ),
    (
        "core/src/provision.rs",
        "is_provisioned",
        "SAFE BY CONSTRUCTION: an opaque store key and a MAX() over an integer column",
    ),
    (
        "core/src/provision.rs",
        "provision",
        "NOT A BOUNDARY: the write direction; every byte it stores was produced in the same call chain",
    ),
    (
        "core/src/provision.rs",
        "load",
        "COVERED ELSEWHERE: every byte reaches an AEAD before a decision, and the CHVR framing is chiavora-protocol's, which is fuzzed",
    ),
    (
        "core/src/store.rs",
        "Store::account_key_epoch",
        "SAFE BY CONSTRUCTION: an opaque key into metadata the store authenticated; returns a u32 or None",
    ),
    (
        "core/src/store.rs",
        "Store::put_provisioning",
        "SAFE BY CONSTRUCTION: opaque keys, and the payload is stored without being read",
    ),
    (
        "core/src/store.rs",
        "Store::get_provisioning",
        "COVERED ELSEWHERE: returns stored bytes unread, which an AEAD then authenticates under a key the caller holds",
    ),
    (
        "core/src/store.rs",
        "Store::latest_provisioning_epoch",
        "SAFE BY CONSTRUCTION: a MAX() over an integer column, narrowed with try_from; ownerId is an opaque key",
    ),
    (
        "core/src/account_key.rs",
        "WrappedAccountKey::from_stored_parts",
        "COVERED ELSEWHERE: stores a nonce and bytes unread; the AEAD under the MUK authenticates them",
    ),
    (
        "core/src/keywrap.rs",
        "seal",
        "NOT A BOUNDARY: the encrypt direction, over key material and an AAD this crate produced",
    ),
    (
        "core/src/keywrap.rs",
        "open",
        "COVERED ELSEWHERE: one AEAD decrypt and no parse; its callers check the plaintext",
    ),
    (
        "core/src/autofill.rs",
        "WrappedAutofillKey::from_stored_parts",
        "COVERED ELSEWHERE: stores a nonce and bytes unread; the AEAD under the Vault Key authenticates them",
    ),
    (
        "core/src/seal.rs",
        "AccountKeypair::from_private",
        "NOT A BOUNDARY: this account's own private key, just unwrapped and authenticated under the MUK",
    ),
    (
        "core/src/seal.rs",
        "SealedVaultKey::from_stored_parts",
        "COVERED ELSEWHERE: stores two byte strings unread; HPKE's open authenticates them",
    ),
    (
        "core/src/vault.rs",
        "OpenVault::new",
        "COVERED ELSEWHERE: holds its arguments unread; HPKE authenticates the sealed Vault Key when it is opened",
    ),
    (
        "core/src/vault.rs",
        "OpenVault::read",
        "COVERED ELSEWHERE: an opaque key in; what comes back goes through StoredRecord::decode and Item::from_bytes",
    ),
    (
        "core/src/vault.rs",
        "OpenVault::create",
        "SAFE BY CONSTRUCTION: an opaque store key and a typed Item, in the encode direction",
    ),
    (
        "core/src/vault.rs",
        "OpenVault::update",
        "COVERED ELSEWHERE: as create, plus a store read through StoredRecord::decode",
    ),
    (
        "core/src/vault.rs",
        "OpenVault::delete",
        "SAFE BY CONSTRUCTION: one opaque store key and a bool back",
    ),
    (
        "core/src/sync.rs",
        "StagedEdit::new",
        "NOT A BOUNDARY: an edit staged locally, with this installation's own identifier and digest",
    ),
    (
        "core/src/sync.rs",
        "upload",
        "COVERED ELSEWHERE: every server byte reaches it through the three manifest decoders",
    ),
    (
        "core/src/sync.rs",
        "upload_resolving",
        "COVERED ELSEWHERE: as upload; the digest it adds was computed by this device",
    ),
    (
        "core/src/sync.rs",
        "upload_with_retry",
        "COVERED ELSEWHERE: as upload, repeated; it parses nothing",
    ),
    (
        "core/src/rotation.rs",
        "rotate",
        "COVERED ELSEWHERE: as upload; the epoch is chosen by this device and checked by the engine",
    ),
    (
        "core/src/manifest.rs",
        "Entry::accept_attachments",
        "SAFE BY CONSTRUCTION: set comparison over opaque ids, then SHA-256 over fixed-width digests",
    ),
    (
        "core/src/manifest.rs",
        "Entry::accept_item",
        "SAFE BY CONSTRUCTION: two comparisons over a fixed-size digest and a u64",
    ),
    (
        "core/src/manifest.rs",
        "ManifestSegment::entry",
        "SAFE BY CONSTRUCTION: a linear search by opaque itemId over decoded entries",
    ),
    (
        "core/src/manifest.rs",
        "ManifestSegment::reconcile",
        "SAFE BY CONSTRUCTION: set comparison over itemIds used as opaque keys",
    ),
    (
        "core/src/manifest.rs",
        "advance_high_water_mark",
        "SAFE BY CONSTRUCTION: an opaque key and a u64 from an authenticated root",
    ),
    (
        "core/src/item.rs",
        "seal_record",
        "NOT A BOUNDARY: the encrypt direction, over a plaintext this crate just encoded",
    ),
    (
        "core/src/manifest.rs",
        "Entry::new",
        "SAFE BY CONSTRUCTION: assembled from an opaque itemId, two fixed-size digests, a bool and a built list",
    ),
    (
        "core/src/manifest.rs",
        "AttachmentEntry::new",
        "SAFE BY CONSTRUCTION: an opaque attachmentId, a count, a digest root and a size",
    ),
    (
        "core/src/unlock.rs",
        "UnlockedVault::from_stored_muk",
        "COVERED ELSEWHERE: one call to device::muk_from_keystore, which checks the length",
    ),
    (
        "core/src/device.rs",
        "muk_from_keystore",
        "NOT A BOUNDARY: a MUK this installation derived and the keystore holds; a wrong one fails the store's metadata MAC",
    ),
    (
        "core/src/base32.rs",
        "decode_with_checksum",
        "COVERED ELSEWHERE: reached only through secret_key::decode and emergency_kit::parse, both fuzzed",
    ),
    (
        "core/src/base32.rs",
        "normalise_input",
        "COVERED ELSEWHERE: the first step of all three classified decoders",
    ),
    (
        "core/src/base32.rs",
        "checksum",
        "COVERED ELSEWHERE: a truncated SHA-256, fuzzed through the decoders",
    ),
    (
        "core/src/base32.rs",
        "encode_with_checksum",
        "NOT A BOUNDARY: the encode direction, over a key or accountId this crate generated",
    ),
    (
        "core/src/base32.rs",
        "group",
        "NOT A BOUNDARY: presentation over the encoder's own output",
    ),
    (
        "core/src/nonce.rs",
        "StoredNonce::from_stored_bytes",
        "SAFE BY CONSTRUCTION: a fixed-size array; a wrong nonce fails the AEAD tag",
    ),
    (
        "core/src/secret_key.rs",
        "looks_like_rendered_key_material",
        "COVERED ELSEWHERE: clipboard input (A8), checked by base32::normalise_input, a length and a prefix",
    ),
    (
        "core/src/entry.rs",
        "accept",
        "COVERED ELSEWHERE: decodes through secret_key::decode, which is fuzzed; the rest is length and ASCII checks",
    ),
    (
        "core/src/ffi_guard.rs",
        "assert_not_key_material",
        "SAFE BY CONSTRUCTION: a 32-byte-window substring search; its failure path aborts, so it cannot be fuzzed",
    ),
    (
        "core/src/ffi_guard.rs",
        "register",
        "NOT A BOUNDARY: takes key material from Secret::new",
    ),
    (
        "core/src/ffi_guard.rs",
        "deregister",
        "NOT A BOUNDARY: the Drop half of register",
    ),
    (
        "core/src/item.rs",
        "SealedPayload::from_stored_parts",
        "SAFE BY CONSTRUCTION: a fixed-size nonce and an opaque ciphertext from SQLite (A4); tampering fails the AEAD tag",
    ),
    (
        "core/src/wrap.rs",
        "WrappedKey::from_stored_parts",
        "SAFE BY CONSTRUCTION: as SealedPayload::from_stored_parts",
    ),
    (
        "core/src/item.rs",
        "seal",
        "NOT A BOUNDARY: the plaintext is encrypted, not parsed",
    ),
    (
        "core/src/item.rs",
        "seal_chunk",
        "NOT A BOUNDARY: seal with the record type pinned to 0x02",
    ),
    (
        "core/src/scan.rs",
        "production",
        "NOT A BOUNDARY: reads this crate's own source text",
    ),
    (
        "core/src/secret.rs",
        "Secret::from_derived_bytes",
        "NOT A BOUNDARY: KDF output from the same operation",
    ),
    (
        "core/src/secret.rs",
        "Secret::from_external_bytes",
        "NOT A BOUNDARY: pub(crate), reached only through entry::accept",
    ),
    (
        "core/src/wrap.rs",
        "ItemKind::from_tag",
        "SAFE BY CONSTRUCTION: an exact match against six literals, returning Option",
    ),
    (
        "core/src/model.rs",
        "Name::new",
        "SAFE BY CONSTRUCTION: bounded first, then a character check",
    ),
    (
        "core/src/model.rs",
        "ItemField::new",
        "SAFE BY CONSTRUCTION: the name goes through Name::new and the value is opaque",
    ),
    (
        "core/src/model.rs",
        "Item::new",
        "SAFE BY CONSTRUCTION: names go through Name::new and are checked for duplicates; the caller bounds the count",
    ),
    (
        "core/src/model.rs",
        "Item::remove_field",
        "SAFE BY CONSTRUCTION: compares a name against validated names and retains the rest",
    ),
    (
        "core/src/model.rs",
        "Item::field",
        "SAFE BY CONSTRUCTION: a linear search over validated names",
    ),
    (
        "core/src/store.rs",
        "Store::put_raw",
        "SAFE BY CONSTRUCTION: opaque keys, and the bytes are stored exactly and never read",
    ),
    (
        "core/src/store.rs",
        "Store::get_raw",
        "SAFE BY CONSTRUCTION: opaque lookup keys; returns bytes unread",
    ),
    (
        "core/src/store.rs",
        "Store::delete",
        "SAFE BY CONSTRUCTION: identifiers used as opaque keys",
    ),
    (
        "core/src/store.rs",
        "Store::list",
        "SAFE BY CONSTRUCTION: an identifier used as an opaque key",
    ),
    (
        "core/src/store.rs",
        "Store::high_water_mark",
        "SAFE BY CONSTRUCTION: an opaque key over metadata authenticated on open",
    ),
    (
        "core/src/store.rs",
        "Store::set_high_water_mark",
        "SAFE BY CONSTRUCTION: an opaque key; a decreasing value is refused (I6f)",
    ),
    (
        "core/src/search.rs",
        "SearchIndex::insert",
        "SAFE BY CONSTRUCTION: an opaque key; the searched fields are copied, not parsed",
    ),
    (
        "core/src/search.rs",
        "SearchIndex::remove",
        "SAFE BY CONSTRUCTION: an identifier used as an opaque key",
    ),
    (
        "core/src/search.rs",
        "SearchIndex::search",
        "SAFE BY CONSTRUCTION: a lowercased substring match over fields in memory",
    ),
    (
        "core/src/store.rs",
        "Store::put_chunk_raw",
        "SAFE BY CONSTRUCTION: opaque keys, and the chunk bytes are stored exactly and never read",
    ),
    (
        "core/src/store.rs",
        "Store::get_chunk_raw",
        "SAFE BY CONSTRUCTION: opaque keys; returns bytes unread",
    ),
    (
        "core/src/store.rs",
        "Store::list_chunks",
        "SAFE BY CONSTRUCTION: identifiers used as opaque keys",
    ),
    (
        "core/src/store.rs",
        "Store::list_attachments",
        "SAFE BY CONSTRUCTION: identifiers used as opaque keys",
    ),
    (
        "core/src/export.rs",
        "write",
        "SAFE BY CONSTRUCTION: an opaque key; the bytes come from the store and are MACed, never parsed",
    ),
    (
        "core/src/store.rs",
        "Store::delete_attachment",
        "SAFE BY CONSTRUCTION: identifiers used as opaque keys",
    ),
    // `open_attachment` is not listed: its bytes arrive inside `AttachmentRef`,
    // which the signature scan cannot see, and it only compares them to the AAD.
    (
        "core/src/attachment.rs",
        "seal_attachment",
        "SAFE BY CONSTRUCTION: opaque AAD fields, a bounded content type, and bytes sealed chunk by chunk, never parsed",
    ),
    (
        "core/src/zip.rs",
        "Archive::find",
        "SAFE BY CONSTRUCTION: compares a member name against the parsed central directory",
    ),
    (
        "core/src/csv.rs",
        "column",
        "SAFE BY CONSTRUCTION: looks a field up by column name; parses nothing",
    ),
    (
        "core/src/csv.rs",
        "Header::index_of",
        "SAFE BY CONSTRUCTION: compares a column name against the parsed header",
    ),
    (
        "core/src/csv.rs",
        "row_has_columns",
        "SAFE BY CONSTRUCTION: compares column names against a parsed row",
    ),
    (
        "core/src/import.rs",
        "Node::get",
        "SAFE BY CONSTRUCTION: compares a key against parsed object keys",
    ),
    (
        "core/src/import.rs",
        "Node::str_of",
        "SAFE BY CONSTRUCTION: Node::get with a type check",
    ),
    (
        "core/src/import.rs",
        "Node::str_or_empty",
        "SAFE BY CONSTRUCTION: Node::get with a type check and an empty default",
    ),
    (
        "core/src/import.rs",
        "Node::list_of",
        "SAFE BY CONSTRUCTION: Node::get with a type check and an empty default",
    ),
    (
        "core/src/import.rs",
        "parse_json",
        "COVERED ELSEWHERE: reached only through onepux::parse and onepif::parse, both fuzzed",
    ),
    (
        "core/src/import.rs",
        "ItemBuilder::name_of_value",
        "SAFE BY CONSTRUCTION: compares bytes against the values already held",
    ),
    (
        "core/src/import.rs",
        "ItemBuilder::has_field",
        "SAFE BY CONSTRUCTION: compares a name",
    ),
    (
        "core/src/import.rs",
        "ItemBuilder::field",
        "SAFE BY CONSTRUCTION: bounded names are copied; the value is opaque and never parsed",
    ),
    (
        "core/src/import.rs",
        "ItemBuilder::preserved",
        "SAFE BY CONSTRUCTION: ItemBuilder::field with a different move kind",
    ),
    (
        "core/src/import.rs",
        "ItemBuilder::tag",
        "SAFE BY CONSTRUCTION: bounded and copied",
    ),
    (
        "core/src/import.rs",
        "ItemBuilder::attachment",
        "SAFE BY CONSTRUCTION: the source path is copied into the report",
    ),
    (
        "core/src/import.rs",
        "ItemBuilder::attachment_refused",
        "SAFE BY CONSTRUCTION: the source path is copied into the report, with a content-free reason",
    ),
    (
        "core/src/import.rs",
        "ItemBuilder::finish",
        "SAFE BY CONSTRUCTION: the source type name is copied into the report",
    ),
    (
        "core/src/import.rs",
        "AttachmentHandle::new",
        "SAFE BY CONSTRUCTION: the file name is copied, not parsed",
    ),
    (
        "protocol/src/lib.rs",
        "Field::new",
        "NOT A BOUNDARY: the encode direction",
    ),
    (
        "protocol/src/lib.rs",
        "Record::with_field",
        "NOT A BOUNDARY: the encode direction",
    ),
    (
        "core/src/srp.rs",
        "private_exponent",
        "SAFE BY CONSTRUCTION: the server-chosen srpSalt reaches SHA-256 and nothing else",
    ),
    (
        "core/src/srp.rs",
        "client_proof",
        "SAFE BY CONSTRUCTION: both slices reach a hash, and a salt of the wrong length is refused",
    ),
    (
        "core/src/srp.rs",
        "server_proof",
        "SAFE BY CONSTRUCTION: as client_proof; an M1 of the wrong width is refused",
    ),
    (
        "core/src/request_mac.rs",
        "decode",
        "NOT A BOUNDARY: nothing transmits this encoding, so its only input is encode's output; if that changes, it belongs in PARSERS",
    ),
    (
        "core/src/request_mac.rs",
        "tags_match",
        "NOT A BOUNDARY: compares two slices, length first; constant time is subtle's claim",
    ),
    (
        "core/src/request_mac.rs",
        "body_hash",
        "SAFE BY CONSTRUCTION: one Sha256::digest call over any slice",
    ),
    (
        "core/src/srp.rs",
        "fake_credentials",
        "SAFE BY CONSTRUCTION: the seed must be 32 bytes, and the identifier reaches two HMAC updates and nothing else",
    ),
    (
        "core/src/srp.rs",
        "select_credentials",
        "SAFE BY CONSTRUCTION: both slices must have their fixed widths, then a constant-time select",
    ),
    (
        "core/src/srp.rs",
        "check_public_value",
        "SAFE BY CONSTRUCTION: a width check, then a modular reduction",
    ),
    (
        "core/src/srp.rs",
        "server_public_bytes",
        "SAFE BY CONSTRUCTION: the verifier must be the group's width, then fixed-width modular arithmetic",
    ),
    (
        "core/src/srp.rs",
        "server_finish",
        "SAFE BY CONSTRUCTION: fixed-width slices are checked, and the client proof reaches only a constant-time comparison",
    ),
    (
        "core/src/srp.rs",
        "proofs_match",
        "NOT A BOUNDARY: compares two slices, length first; constant time is subtle's claim",
    ),
];

const REASON_KINDS: [&str; 3] = [
    "COVERED ELSEWHERE:",
    "SAFE BY CONSTRUCTION:",
    "NOT A BOUNDARY:",
];

fn production_code(source: &str) -> String {
    let marker = concat!("#[cfg(", "test)]");
    let lines: Vec<&str> = source.lines().collect();
    let mut out = String::with_capacity(source.len());
    let mut i = 0;
    while i < lines.len() {
        let line = lines.get(i).copied().unwrap_or_default();
        let trimmed = line.trim();
        if trimmed.starts_with("//") {
            i += 1;
            continue;
        }
        if trimmed != marker {
            out.push_str(line);
            out.push('\n');
            i += 1;
            continue;
        }
        let is_test_module = lines
            .get(i..)
            .unwrap_or_default()
            .iter()
            .take(4)
            .any(|l| l.trim_start().starts_with("mod tests"));
        if is_test_module {
            break;
        }
        i += 1;
        let mut depth = 0_usize;
        let mut started = false;
        while let Some(inner) = lines.get(i) {
            depth += inner.matches('{').count();
            if depth > 0 {
                started = true;
            }
            depth = depth.saturating_sub(inner.matches('}').count());
            i += 1;
            if started && depth == 0 {
                break;
            }
        }
    }
    out
}

fn declared_functions(code: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    // (implementing type, the brace depth the impl block opened at)
    let mut scopes: Vec<(String, usize)> = Vec::new();
    let mut depth = 0_usize;
    let mut offset = 0_usize;

    for line in code.lines() {
        let trimmed = line.trim_start();

        if trimmed.starts_with("impl") && !trimmed.starts_with("impl_") {
            if let Some(ty) = implementing_type(trimmed) {
                scopes.push((ty, depth));
            }
        }

        if let Some(rest) = trimmed.strip_prefix("pub ").or_else(|| {
            trimmed
                .strip_prefix("pub(crate) ")
                .filter(|_| trimmed.starts_with("pub(crate) "))
        }) {
            let rest = rest
                .trim_start_matches("const ")
                .trim_start_matches("unsafe ");
            if let Some(after_fn) = rest.strip_prefix("fn ") {
                let name: String = after_fn
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_')
                    .collect();
                if !name.is_empty() {
                    if let Some(params) = balanced_params(code, offset + (line.len() - rest.len()))
                    {
                        let qualified = scopes
                            .last()
                            .map_or_else(|| name.clone(), |(ty, _)| format!("{ty}::{name}"));
                        out.push((qualified, params));
                    }
                }
            }
        }

        depth += line.matches('{').count();
        depth = depth.saturating_sub(line.matches('}').count());
        while scopes.last().is_some_and(|(_, opened)| depth <= *opened) {
            scopes.pop();
        }
        offset += line.len() + 1;
    }
    out
}

fn implementing_type(line: &str) -> Option<String> {
    let rest = line.strip_prefix("impl")?;
    let rest = if rest.starts_with('<') {
        let mut depth = 0_usize;
        let mut end = None;
        for (at, ch) in rest.char_indices() {
            match ch {
                '<' => depth += 1,
                '>' => {
                    depth -= 1;
                    if depth == 0 {
                        end = Some(at + 1);
                        break;
                    }
                }
                _ => {}
            }
        }
        rest.get(end?..)?
    } else {
        rest
    };
    let rest = rest.split_once(" for ").map_or(rest, |(_, after)| after);
    let ty: String = rest
        .trim()
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect();
    if ty.is_empty() || !ty.starts_with(|c: char| c.is_uppercase()) {
        None
    } else {
        Some(ty)
    }
}

fn balanced_params(code: &str, from: usize) -> Option<String> {
    let rest = code.get(from..)?;
    let open = rest.find('(')?;
    let mut depth = 0_usize;
    for (at, ch) in rest.get(open..)?.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return rest.get(open..=open.saturating_add(at)).map(str::to_owned);
                }
            }
            _ => {}
        }
    }
    None
}

fn takes_bytes_or_text(params: &str) -> bool {
    ["&[u8]", "&str", "Vec<u8>", "&[u8;", "String"]
        .iter()
        .any(|ty| params.contains(ty))
}

fn is_classified(file: &str, function: &str) -> bool {
    PARSERS
        .iter()
        .any(|p| p.file == file && p.function == function)
        || NOT_SEPARATELY_FUZZED
            .iter()
            .any(|(f, fun, _)| *f == file && *fun == function)
}

fn all_declared() -> Vec<(String, String)> {
    let mut found = Vec::new();
    for (name, source) in test_sources() {
        if !name.contains("/src/") {
            continue;
        }
        for (function, _) in declared_functions(&production_code(&source)) {
            found.push((name.clone(), function));
        }
    }
    found
}

const MID_FILE_CFG_TEST_FIXTURE: &str = r"
//! A module.

pub fn before_the_marker(bytes: &[u8]) -> usize {
    bytes.len()
}

/// Test-only, and deliberately in the middle of the file.
#[cfg(test)]
pub(crate) fn only_for_tests(bytes: &[u8]) -> usize {
    if bytes.is_empty() {
        return 0;
    }
    bytes.len()
}

pub fn after_the_marker(outgoing: &[u8]) {
    let _ = outgoing;
}

#[cfg(test)]
mod tests {
    pub fn inside_the_test_module(bytes: &[u8]) -> usize {
        bytes.len()
    }
}
";

#[test]
fn the_stripping_keeps_production_code_after_a_mid_file_cfg_test() {
    let stripped = production_code(MID_FILE_CFG_TEST_FIXTURE);
    let found: Vec<String> = declared_functions(&stripped)
        .into_iter()
        .map(|(name, _)| name)
        .collect();

    assert!(
        found.iter().any(|f| f == "before_the_marker"),
        "the stripping dropped production code before the marker: {found:?}"
    );
    assert!(
        found.iter().any(|f| f == "after_the_marker"),
        "production code after a mid-file #[cfg(test)] item was dropped: {found:?}"
    );
    assert!(
        !found.iter().any(|f| f == "only_for_tests"),
        "the #[cfg(test)] item itself must still be skipped: {found:?}"
    );
    assert!(
        !found.iter().any(|f| f == "inside_the_test_module"),
        "the trailing test module must still be dropped: {found:?}"
    );
}

#[test]
fn the_crate_the_finding_came_from_still_has_the_shape_that_hid_it() {
    let guard = read("crates/core/src/ffi_guard.rs");
    let marker = concat!("#[cfg(", "test)]");
    assert!(
        guard.matches(marker).count() >= 2,
        "ffi_guard.rs no longer has a mid-file {marker}; the fixture still covers the stripping."
    );
    let visible: Vec<String> = declared_functions(&production_code(&guard))
        .into_iter()
        .map(|(name, _)| name)
        .collect();
    assert!(
        visible.iter().any(|f| f == "assert_not_key_material"),
        "the FFI guard is invisible to the scans again: {visible:?}"
    );
}

#[test]
fn every_parser_in_the_source_is_classified() {
    let mut unclassified: Vec<String> = Vec::new();
    for (name, source) in test_sources() {
        if !name.contains("/src/") {
            continue;
        }
        for (function, params) in declared_functions(&production_code(&source)) {
            let bare = function.rsplit("::").next().unwrap_or(&function);
            let is_parser = ["decode", "parse", "from_stored_bytes", "looks_like"]
                .iter()
                .any(|verb| bare.starts_with(verb));
            if is_parser && !is_classified(&name, &function) {
                unclassified.push(format!("{name}: fn {function}{params}"));
            }
        }
    }

    assert!(
        unclassified.is_empty(),
        "these parsers are classified nowhere. Add each to PARSERS or NOT_SEPARATELY_FUZZED:\n  {}",
        unclassified.join("\n  ")
    );
}

#[test]
fn no_two_boundary_functions_share_a_key() {
    let mut collisions: Vec<String> = Vec::new();
    for (name, source) in test_sources() {
        if !name.contains("/src/") {
            continue;
        }
        let mut seen: Vec<String> = Vec::new();
        for (function, params) in declared_functions(&production_code(&source)) {
            if !takes_bytes_or_text(&params) {
                continue;
            }
            if seen.contains(&function) {
                collisions.push(format!("{name}::{function}"));
            }
            seen.push(function);
        }
    }
    assert!(
        collisions.is_empty(),
        "these boundary functions share a classification key, so one row would \
         cover several: {collisions:?}"
    );
}

#[test]
fn no_free_function_is_attributed_to_an_impl() {
    // `aad.rs` declares the free function `decode` after an `impl Reader` block.
    let aad = read("crates/core/src/aad.rs");
    let names: Vec<String> = declared_functions(&production_code(&aad))
        .into_iter()
        .map(|(name, _)| name)
        .collect();
    assert!(
        names.iter().any(|n| n == "decode"),
        "aad::decode is a free function and must be keyed unqualified: {names:?}"
    );
    assert!(
        !names.iter().any(|n| n.ends_with("::decode")),
        "a free function was attributed to an impl block: {names:?}"
    );
}

#[test]
fn every_function_taking_bytes_or_text_is_classified() {
    let mut unclassified: Vec<String> = Vec::new();
    let mut boundary_count = 0_usize;
    for (name, source) in test_sources() {
        if !name.contains("/src/") {
            continue;
        }
        for (function, params) in declared_functions(&production_code(&source)) {
            if !takes_bytes_or_text(&params) {
                continue;
            }
            boundary_count += 1;
            if !is_classified(&name, &function) {
                unclassified.push(format!("{name}: fn {function}{params}"));
            }
        }
    }

    // Before the count checks, so the failure names the function.
    assert!(
        unclassified.is_empty(),
        "these functions take bytes or text and are classified nowhere. Add each to PARSERS or NOT_SEPARATELY_FUZZED:\n  {}",
        unclassified.join("
  ")
    );
    assert!(
        all_declared().len() >= 40,
        "the signature scan found only {} functions, too few to have read the crates",
        all_declared().len()
    );
    let declared = all_declared_with_params();
    let mut visible = 0_usize;
    let mut invisible: Vec<(String, String)> = Vec::new();
    let classified = PARSERS
        .iter()
        .map(|p| (p.file, p.function))
        .chain(NOT_SEPARATELY_FUZZED.iter().map(|(f, fun, _)| (*f, *fun)));
    for (file, function) in classified {
        let params = declared
            .iter()
            .find(|(f, fun, _)| f == file && fun == function)
            .map(|(_, _, p)| p.as_str());
        match params {
            Some(p) if takes_bytes_or_text(p) => visible += 1,
            Some(_) => invisible.push((file.to_owned(), function.to_owned())),
            None => {
                // Gone from the source; reported as stale by another test.
                invisible.push((file.to_owned(), function.to_owned()));
            }
        }
    }
    for (file, function, _) in INVISIBLE_TO_THE_SIGNATURE_SCAN {
        assert!(
            invisible
                .iter()
                .any(|(f, fun)| f == file && fun == function),
            "{file}::{function} is listed as invisible to the signature scan, but the \
             scan sees it (or it is gone). Remove it from INVISIBLE_TO_THE_SIGNATURE_SCAN"
        );
    }
    for (file, function) in &invisible {
        assert!(
            INVISIBLE_TO_THE_SIGNATURE_SCAN
                .iter()
                .any(|(f, fun, _)| f == file && fun == function),
            "{file}::{function} takes no bare slice, so the signature scan cannot see it. \
             Add it to INVISIBLE_TO_THE_SIGNATURE_SCAN with the reason"
        );
    }
    assert_eq!(
        boundary_count, visible,
        "the signature scan found {boundary_count} functions taking bytes or text but \
         {visible} classified rows it can see"
    );
}

const INVISIBLE_TO_THE_SIGNATURE_SCAN: [(&str, &str, &str); 9] = [
    (
        "core/src/nonce.rs",
        "StoredNonce::from_stored_bytes",
        "a fixed-size array by value; the name scan reaches it",
    ),
    (
        "core/src/zip.rs",
        "parse",
        "a generic `Read + Seek`; in PARSERS",
    ),
    (
        "core/src/onepux.rs",
        "parse",
        "the same generic reader, over the archive; in PARSERS",
    ),
    (
        "core/src/onepif.rs",
        "parse",
        "a generic `BufRead`, line by line; in PARSERS",
    ),
    (
        "core/src/csv.rs",
        "parse",
        "a generic `BufRead` and a row callback; in PARSERS",
    ),
    (
        "core/src/bitwarden.rs",
        "parse",
        "a generic `BufRead`; in PARSERS",
    ),
    (
        "core/src/lastpass.rs",
        "parse",
        "a generic `BufRead`, rows through csv::parse; in PARSERS",
    ),
    (
        "core/src/chrome.rs",
        "parse",
        "a generic `BufRead`, rows through csv::parse; in PARSERS",
    ),
    (
        "core/src/export.rs",
        "verify",
        "a generic `Read + Seek`; in PARSERS",
    ),
];

fn all_declared_with_params() -> Vec<(String, String, String)> {
    let mut found = Vec::new();
    for (name, source) in test_sources() {
        if !name.contains("/src/") {
            continue;
        }
        for (function, params) in declared_functions(&production_code(&source)) {
            found.push((name.clone(), function, params));
        }
    }
    found
}

#[test]
fn every_reason_names_one_of_the_three_kinds() {
    for (file, function, why) in NOT_SEPARATELY_FUZZED {
        assert!(
            REASON_KINDS.iter().any(|kind| why.starts_with(kind)),
            "{file}::{function}'s reason begins with none of {REASON_KINDS:?}: {why}"
        );
    }
}

#[test]
fn no_classification_names_a_function_that_is_gone() {
    let found = all_declared();
    let mut stale: Vec<String> = Vec::new();
    for (file, function, _) in NOT_SEPARATELY_FUZZED {
        if !found.iter().any(|(f, fun)| f == file && fun == function) {
            stale.push(format!("{file}::{function}"));
        }
    }
    for Parser { file, function, .. } in PARSERS {
        if !found.iter().any(|(f, fun)| f == file && fun == function) {
            stale.push(format!("{file}::{function}"));
        }
    }
    assert!(
        stale.is_empty(),
        "these classifications name functions that no longer exist: {stale:?}"
    );
}

#[test]
fn every_fuzz_target_is_registered() {
    let targets = root().join("fuzz").join("fuzz_targets");
    let mut unregistered: Vec<String> = Vec::new();
    for entry in std::fs::read_dir(&targets).expect("fuzz/fuzz_targets is readable") {
        let path = entry.expect("a directory entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or_default()
            .to_owned();
        if !PARSERS.iter().any(|p| p.target == stem) {
            unregistered.push(stem);
        }
    }
    assert!(
        unregistered.is_empty(),
        "these fuzz targets are in no registry: {unregistered:?}"
    );
}

/// Every `[u8; 32]` field on a record type, as `(type::field, computed_by,
/// falsified_by)`: the function that derives it (or `CARRIED`, naming where it
/// is derived) and a test that fails when it is wrong.
const DERIVED_FIELDS: [(&str, &str, &str); 6] = [
    (
        "DeviceMark::root_digest",
        "CARRIED: StoredManifest::digest over the sealed root's own bytes, called by DeviceMark::of",
        "the_same_sequence_with_different_roots_is_a_fork, a_mark_takes_both_halves_from_one_root",
    ),
    (
        "RootEntry::digest",
        "StoredManifest::digest, over the sealed segment's own bytes",
        "i6b_a_segment_the_root_does_not_vouch_for_is_refused",
    ),
    (
        "AttachmentEntry::chunk_digest_root",
        "manifest::chunk_digest_root, SHA-256 over the ordered per-chunk digests",
        "the_order_of_the_chunks_changes_the_root, a_replayed_chunk_is_refused_by_the_root",
    ),
    (
        "Entry::ciphertext_digest",
        "CARRIED: StoredRecord::ciphertext_digest in stored_record.rs, over the sealed item payload",
        "i6d_a_substituted_ciphertext_at_the_same_version_is_refused",
    ),
    (
        "ConflictingVersion::ciphertext_digest",
        "CARRIED: read off an Entry or a StagedEdit; the conflict tiebreak only compares it",
        "the_comparison_is_unsigned_and_most_significant_byte_first",
    ),
    (
        "StagedEdit::ciphertext_digest",
        "CARRIED: computed by this process when it sealed the payload",
        "the_copys_entry_carries_the_resealed_digest_and_not_the_losers",
    ),
];

#[test]
fn every_digest_field_in_a_record_is_registered() {
    let mut unregistered: Vec<String> = Vec::new();
    for (name, source) in test_sources() {
        if !name.contains("/src/") {
            continue;
        }
        let mut current_type: Option<String> = None;
        for line in source.lines() {
            let t = line.trim();
            if let Some(rest) = t.strip_prefix("pub struct ") {
                current_type = Some(
                    rest.split(|c: char| !c.is_alphanumeric() && c != '_')
                        .next()
                        .unwrap_or_default()
                        .to_string(),
                );
                continue;
            }
            // Fields sit at one level of indentation; `new`'s parameters at two.
            if t.ends_with(": [u8; 32],")
                && line.starts_with("    ")
                && !line.starts_with("        ")
            {
                let field = t.trim_end_matches(": [u8; 32],");
                let Some(ty) = current_type.as_deref() else {
                    continue;
                };
                let key = format!("{ty}::{field}");
                if !DERIVED_FIELDS.iter().any(|(k, _, _)| *k == key) {
                    unregistered.push(format!("\n  {name}: {key}"));
                }
            }
        }
    }
    assert!(
        unregistered.is_empty(),
        "these digest fields are registered nowhere. Add each to DERIVED_FIELDS with \
         what computes it and a test that fails when it is wrong:{}",
        unregistered.join("")
    );
}

#[test]
fn a_constructor_parameter_is_not_mistaken_for_a_field() {
    let source = "pub struct Thing {\n    real: [u8; 32],\n}\n\
                  impl Thing {\n    pub const fn new(\n        param: [u8; 32],\n    ) -> Self {}\n}";
    let mut seen = Vec::new();
    for line in source.lines() {
        let t = line.trim();
        if t.ends_with(": [u8; 32],") && line.starts_with("    ") && !line.starts_with("        ") {
            seen.push(t.trim_end_matches(": [u8; 32],").to_string());
        }
    }
    assert_eq!(
        seen,
        vec!["real".to_string()],
        "the scan cannot tell a field from a constructor parameter"
    );
}

#[test]
fn every_registered_field_names_a_test_that_exists() {
    let suite: String = test_sources()
        .into_iter()
        .filter(|(name, _)| name.contains("/tests/"))
        .map(|(_, source)| source)
        .collect();

    let mut missing = Vec::new();
    for (key, _, falsified_by) in DERIVED_FIELDS {
        // A cell may name several tests; at least one must exist.
        let named: Vec<&str> = falsified_by
            .split(|c: char| !c.is_alphanumeric() && c != '_')
            .filter(|w| w.len() > 12 && w.contains('_'))
            .collect();
        assert!(!named.is_empty(), "{key} names no test at all");
        if !named.iter().any(|t| suite.contains(&format!("fn {t}"))) {
            missing.push(format!("\n  {key}: none of {named:?} exists"));
        }
    }
    assert!(
        missing.is_empty(),
        "DERIVED_FIELDS names tests that are not in the suite:{}",
        missing.join("")
    );
}
