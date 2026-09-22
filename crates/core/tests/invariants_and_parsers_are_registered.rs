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

const CORE_INVARIANTS: [(&str, &str); 5] = [
    ("i1a", "The server never receives the account password"),
    ("i2", "every nonce is drawn from the platform"),
    (
        "i3",
        "Integrity-relevant metadata is bound as AEAD associated data",
    ),
    (
        "i4",
        "The client refuses KDF parameters below the hard floor",
    ),
    ("i7", "double-wrap agreement"),
];

const I6_CLAUSES: [(&str, &str); 6] = [
    ("i6a", "No manifest root below the client's persisted"),
    ("i6b", "No segment whose digest the root does not vouch for"),
    ("i6c", "No item below its entry's"),
    (
        "i6d",
        "No item whose ciphertext fails to digest-match its entry",
    ),
    ("i6e", "No silently missing or silently extra item"),
    ("i6f", "is strictly monotonic"),
];

#[test]
fn every_i6_clause_has_a_test_named_for_it_and_a_phrase_in_the_design() {
    let sources = test_sources();
    let plan = read("docs/security-design.md");
    let flat = plan.split_whitespace().collect::<Vec<_>>().join(" ");

    let mut problems: Vec<String> = Vec::new();
    for (clause, phrase) in I6_CLAUSES {
        let needle = format!("fn {clause}_");
        let count: usize = sources
            .iter()
            .map(|(_, src)| src.matches(&needle).count())
            .sum();
        if count == 0 {
            problems.push(format!("{clause}: no test named for it"));
        }
        if !flat.contains(phrase) {
            problems.push(format!(
                "{clause}: docs/security-design.md no longer states {phrase:?} -- either the \
                 clause was reworded, in which case fix this row, or it was \
                 dropped, in which case the test guards nothing"
            ));
        }
    }
    assert!(
        problems.is_empty(),
        "I6 registry:\n  {}",
        problems.join("\n  ")
    );
}

#[test]
fn every_core_invariant_has_at_least_one_test_named_for_it() {
    let sources = test_sources();
    let mut missing: Vec<&str> = Vec::new();
    let mut counts: Vec<(&str, usize)> = Vec::new();

    for (invariant, _) in CORE_INVARIANTS {
        let needle = format!("fn {invariant}_");
        let count: usize = sources
            .iter()
            .map(|(_, src)| src.matches(&needle).count())
            .sum();
        counts.push((invariant, count));
        if count == 0 {
            missing.push(invariant);
        }
    }
    assert!(
        missing.is_empty(),
        ": these core invariants have no test named for them, so a failure \
         would name a filename rather than the invariant: {missing:?}\n\
         counts: {counts:?}"
    );
}

#[test]
fn the_invariant_list_matches_the_phrases_the_design_states_them_in() {
    let plan = read("docs/security-design.md");
    let flat = plan.split_whitespace().collect::<Vec<_>>().join(" ");
    for (invariant, phrase) in CORE_INVARIANTS {
        assert!(
            flat.contains(phrase),
            "{invariant}: docs/security-design.md no longer contains {phrase:?}. Either the \
             invariant was restated — in which case update this list — or it \
             was removed, in which case its tests are testing nothing named."
        );
    }
}

#[test]
fn invariants_outside_the_core_are_absent_on_purpose() {
    let names: Vec<&str> = CORE_INVARIANTS.iter().map(|(n, _)| *n).collect();
    for later in ["i5", "i5a", "i5b", "i6", "i8"] {
        assert!(
            !names.contains(&later),
            "{later} is not the core's. If its code has landed, add \
             it here *and* give it a named test — a row without a test is worse \
             than no row."
        );
    }

    let plan = read("docs/security-design.md");
    let flat = plan.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        flat.contains("the Secret Key's keystore entry is not biometric-bound"),
        "docs/security-design.md no longer states I8. Either it was restated — update this \
         assertion — or it was dropped, in which case is free to bind \
         the Secret Key to the biometric and nothing would object."
    );
}

/// Attacker-supplied means bytes this process did not produce in the same operation.
const PARSERS: [Parser; 18] = [
    Parser {
        file: "core/src/manifest.rs",
        function: "StoredManifest::decode",
        target: "manifest_decode",
        why: "the stored manifest record as the server serves it -- AAD, nonce and ciphertext in the wire framing, every byte the server's choice, and the AAD is parsed before the tag can check it",
    },
    Parser {
        file: "core/src/manifest.rs",
        function: "ManifestRoot::decode",
        target: "manifest_decode",
        why: "the manifest root a hostile server serves (A1): nested, length-prefixed, digest-referenced and entirely server-controlled. it comes ahead of the import formats, and `docs/crypto.md` records it as the first fuzz target sync needs",
    },
    Parser {
        file: "core/src/manifest.rs",
        function: "ManifestSegment::decode",
        target: "manifest_decode",
        why: "the other half of the same server-supplied structure; one target feeds both, dispatching on the record type in the AAD it is given",
    },
    Parser {
        file: "core/src/aad.rs",
        function: "decode",
        target: "aad_decode",
        why: "the inverse of the encoder every record depends on; a disagreement is an I3 failure",
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
        why: "a 1PUX export is a zip archive a person downloaded from somewhere else; the classic bomb and traversal surface, and puts it inside core so it is here",
    },
    Parser {
        file: "core/src/onepux.rs",
        function: "parse",
        target: "onepux_parse",
        why: "the JSON inside a 1PUX archive: attacker-supplied by docs/security-design.md's own classification; every import parser must survive a malformed corpus",
    },
    Parser {
        file: "core/src/onepif.rs",
        function: "parse",
        target: "onepif_parse",
        why: "1Password's older line-oriented export (names both)",
    },
    Parser {
        file: "core/src/csv.rs",
        function: "parse",
        target: "csv_parse",
        why: "the CSV reader under LastPass and Chrome exports: quoting, embedded newlines, ragged rows, a BOM -- all from a file a person downloaded",
    },
    Parser {
        file: "core/src/bitwarden.rs",
        function: "parse",
        target: "bitwarden_parse",
        why: "a Bitwarden JSON export, attacker-supplied by docs/security-design.md's classification; it must survive a malformed corpus",
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
        why: "a native export file is read back from wherever the user kept it -- a file A4 can rewrite -- and its framing is parsed before its MAC is checked, so the framing is a parser of attacker-supplied bytes",
    },
    Parser {
        file: "core/src/attachment.rs",
        function: "StoredChunk::decode",
        target: "stored_chunk_decode",
        why: "a chunk on disk written by *some* build in a file A4 can rewrite, and later one fetched from the server (A1)",
    },
    Parser {
        file: "core/src/stored_record.rs",
        function: "StoredRecord::decode",
        target: "stored_record_decode",
        why: "a record on disk written by *some* build, possibly a newer one, in a file A4 can rewrite",
    },
    Parser {
        file: "core/src/model.rs",
        function: "Item::from_bytes",
        target: "item_body_decode",
        why: "an item body written by a *newer* client, which this build must read and edit; inside the AEAD, but not produced by this build",
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
            ": {file}::{function} is registered as an attacker-input parser but \
             `fuzz/fuzz_targets/{target}.rs` does not exist"
        );
        let seeds = corpus
            .join(target)
            .read_dir()
            .map_or(0, |d| d.filter_map(Result::ok).count());
        assert!(
            seeds >= 10,
            " and R7: {target} has {seeds} corpus inputs. An unseeded \
             target for a prefixed format explores the prefix check and \
             nothing else"
        );
    }
}

const NOT_SEPARATELY_FUZZED: [(&str, &str, &str); 75] = [
    (
        "core/src/manifest.rs",
        "hash_item_id",
        "SAFE BY CONSTRUCTION: SHA-256 over a byte string, returning its top          eight bytes. It parses nothing, and there is no length, content or          encoding it can be wrong about -- a hash is total over bytes. A          hostile itemId lands in the segment its hash selects, which is where          it belongs; what must not be wrong is the ORIENTATION of those eight          bytes, and that is vectored and property-tested in          segment_split_is_one_cas_write.rs rather than left to this row",
    ),
    (
        "core/src/seal.rs",
        "AccountKeypair::from_private",
        "NOT A BOUNDARY: the bytes are this account's own X25519 private key,          just unwrapped from under this device's MUK. They crossed no boundary          -- §2.2 wraps the private key locally and the unwrap authenticates          them, so a caller reaching here with attacker-chosen bytes has          already broken the MUK wrap. The length is checked and          x25519-dalek clamps the scalar; there is no parse to fuzz",
    ),
    (
        "core/src/seal.rs",
        "SealedVaultKey::from_stored_parts",
        "COVERED ELSEWHERE: it stores two byte strings without reading them.          Every byte reaches HPKE's own open, which authenticates the          ciphertext under a key derived from the 0x06 info -- so hostile          bytes here fail at single_shot_open rather than at a parse this          module wrote. The framing they came out of is chiavora-protocol's          CHVR record, which is in PARSERS and fuzzed",
    ),
    (
        "core/src/sync.rs",
        "StagedEdit::new",
        "NOT A BOUNDARY: an edit this client staged locally. The itemId is          this installation's own identifier and the digest was computed here          from bytes this process just sealed. Nothing crosses a boundary until          upload sends it, and what comes back is parsed by StoredManifest and          ManifestRoot, both in PARSERS",
    ),
    (
        "core/src/sync.rs",
        "upload",
        "COVERED ELSEWHERE: the vaultId is an opaque key, and every byte the          server returns reaches it through StoredManifest::decode,          ManifestRoot::decode and ManifestSegment::decode -- all three in          PARSERS and all three fed by manifest_decode. What upload itself does          with those bytes is apply the read path, which is I6a-I6f and has          eighteen named tests",
    ),
    (
        "core/src/manifest.rs",
        "Entry::accept_item",
        "SAFE BY CONSTRUCTION: two comparisons and no parsing. The digest is a          fixed-size array the caller computed with          StoredRecord::ciphertext_digest, and the version is a u64. This is          I6c and I6d themselves -- the thing that refuses attacker input, not          a thing that reads it",
    ),
    (
        "core/src/manifest.rs",
        "ManifestSegment::entry",
        "SAFE BY CONSTRUCTION: an itemId used as an opaque key in a linear          search over entries this build decoded. Returns a borrow or None, and          the None is I6e's ItemDeliveredNotListed at every call site",
    ),
    (
        "core/src/manifest.rs",
        "ManifestSegment::reconcile",
        "SAFE BY CONSTRUCTION: set comparison over itemIds used as opaque          keys. It parses nothing; it is I6e, the rule that decides whether an          absence is a tombstoned delete or an attack",
    ),
    (
        "core/src/manifest.rs",
        "advance_high_water_mark",
        "SAFE BY CONSTRUCTION: the vaultId is an opaque key into the store's          metadata map, never parsed, and the only other input is a u64 read          from a root this build has already authenticated. What the function          decides is which of two errors a refused write is -- I6f's rewind or          an ordinary store fault -- and it parses nothing to do it",
    ),
    (
        "core/src/item.rs",
        "seal_record",
        "NOT A BOUNDARY: the encrypt direction, over a plaintext this crate just          encoded. Its callers are manifest::seal_root and seal_segment, each          with the record type pinned; the decrypt direction is open_record,          reached from open_root and open_segment, and the bytes it returns are          parsed by ManifestRoot::decode and ManifestSegment::decode, which are          both in PARSERS",
    ),
    (
        "core/src/manifest.rs",
        "Entry::new",
        "SAFE BY CONSTRUCTION: an item entry is assembled from an itemId used          as an opaque key, two fixed-size digests, a bool and an already-built          attachment list. It parses nothing. On the server path its bytes come          from ManifestSegment::decode, which is in PARSERS and fuzzed; on the          local path they are this build's own identifiers",
    ),
    (
        "core/src/manifest.rs",
        "AttachmentEntry::new",
        "SAFE BY CONSTRUCTION: the same shape one layer in -- an attachmentId          used as an opaque key, a count, a fixed-size digest root and a size.          No parsing, and the counts are compared rather than used to size          anything (R1's corollary)",
    ),
    (
        "core/src/unlock.rs",
        "UnlockedVault::from_stored_muk",
        "COVERED ELSEWHERE: it is one call to `device::muk_from_keystore`, which          carries the length check and its own classification. Its input is a MUK          this installation derived earlier and the device's keystore has been          holding since -- not attacker-chosen input -- and a wrong one is          self-detecting when the store's metadata MAC fails on the next open",
    ),
    (
        "core/src/device.rs",
        "muk_from_keystore",
        "NOT A BOUNDARY: its input is a MUK this installation derived earlier and \n         the device's own keystore has been holding since -- not attacker-chosen \n         input. An attacker who can choose these bytes has already replaced the \n         keystore entry, and a wrong MUK is self-detecting one layer down: the \n         Store Key is HKDF(ikm = MUK) and the metadata MAC fails on the next \n         Store::open. The one length check it does have is asserted by \n         a_keystore_buffer_of_the_wrong_length_is_refused_by_name",
    ),
    (
        "core/src/base32.rs",
        "decode_with_checksum",
        "COVERED ELSEWHERE: reached only through secret_key::decode and \
         emergency_kit::parse, both of which are fuzzed; it takes an \
         already-normalised symbol slice rather than raw input",
    ),
    (
        "core/src/base32.rs",
        "normalise_input",
        "COVERED ELSEWHERE: the first step of all three classified decoders, so \
         every byte a fuzzer feeds any of them passes through here first",
    ),
    (
        "core/src/base32.rs",
        "checksum",
        "COVERED ELSEWHERE: a truncated SHA-256 over a slice, reached from both \
         the encode and the decode direction and fuzzed through the decoders",
    ),
    (
        "core/src/base32.rs",
        "encode_with_checksum",
        "NOT A BOUNDARY: the encode direction. Its input is a key or an \
         accountId this crate generated moments earlier",
    ),
    (
        "core/src/base32.rs",
        "group",
        "NOT A BOUNDARY: presentation over the encoder's own output; the \
         decoder strips separators, so this never sees input",
    ),
    (
        "core/src/nonce.rs",
        "StoredNonce::from_stored_bytes",
        "SAFE BY CONSTRUCTION: takes a fixed-size array, so there is no length \
         or structure to get wrong, and a wrong nonce fails the AEAD tag",
    ),
    (
        "core/src/secret_key.rs",
        "looks_like_rendered_key_material",
        "COVERED ELSEWHERE: attacker-facing -- a hostile app can write the \
         clipboard (A8) -- and its whole body is base32::normalise_input plus a \
         length comparison and a prefix match",
    ),
    (
        "core/src/entry.rs",
        "accept",
        "COVERED ELSEWHERE: the decoding half dispatches to secret_key::decode, \
         which is fuzzed. The validating half is is_empty, a length bound, \
         is_ascii and two whitespace checks -- total functions over a slice, \
         with no parsing and no allocation. A target here would explore \
         is_ascii and report a coverage figure for it, which is R7's own \
         failure wearing a fuzzer",
    ),
    (
        "core/src/ffi_guard.rs",
        "assert_not_key_material",
        "SAFE BY CONSTRUCTION: a 32-byte-window substring search over a slice. \
         A fuzz target here is **impossible** rather than unnecessary -- the \
         failure path is abort, so a fuzzer that found key material would kill \
         itself instead of reporting it. Covered by i1a_ffi_guard_aborts.rs, \
         which re-executes its own binary as a child",
    ),
    (
        "core/src/ffi_guard.rs",
        "register",
        "NOT A BOUNDARY: takes key material this crate produced, from \
         Secret::new, and never anything from outside",
    ),
    (
        "core/src/ffi_guard.rs",
        "deregister",
        "NOT A BOUNDARY: the Drop half of register, over the same bytes",
    ),
    (
        "core/src/item.rs",
        "SealedPayload::from_stored_parts",
        "SAFE BY CONSTRUCTION: reconstitutes a sealed record from SQLite, so \
         the bytes *are* from outside (A4 -- a hostile process on the device \
         can rewrite the file). It parses nothing: a fixed-size nonce array and \
         an opaque ciphertext vector go into a struct, and a tampered \
         ciphertext fails the AEAD tag. The same shape as nonce::from_stored_bytes",
    ),
    (
        "core/src/wrap.rs",
        "WrappedKey::from_stored_parts",
        "SAFE BY CONSTRUCTION: the wrap half of item::from_stored_parts, on the \
         same reasoning",
    ),
    (
        "core/src/item.rs",
        "seal",
        "NOT A BOUNDARY: the plaintext is opaque to the AEAD. It is encrypted, \
         not parsed, so there is no structure here for a hostile value to \
         exploit -- item *decoding* is the schema's work and gets its own \
         targets",
    ),
    (
        "core/src/item.rs",
        "seal_chunk",
        "NOT A BOUNDARY: seal with the record type pinned to 0x02; the chunk's \
         plaintext is opaque to the AEAD exactly as an item payload's is",
    ),
    (
        "core/src/scan.rs",
        "production",
        "NOT A BOUNDARY: reads this crate's own source text, checked in beside \
         the code it reads",
    ),
    (
        "core/src/secret.rs",
        "Secret::from_derived_bytes",
        "NOT A BOUNDARY: takes KDF output produced moments earlier in the same \
         operation",
    ),
    (
        "core/src/secret.rs",
        "Secret::from_external_bytes",
        "NOT A BOUNDARY: pub(crate), and reached only through entry::accept, \
         which is classified above. The compile-fail case \
         external_secrets_have_no_public_constructor is what makes that true \
         rather than customary",
    ),
    (
        "core/src/wrap.rs",
        "ItemKind::from_tag",
        "SAFE BY CONSTRUCTION: an exact match of a stored tag against six \
         string literals, returning Option. It parses nothing and allocates \
         nothing, and an unrecognised tag is None rather than a guess",
    ),
    (
        "core/src/model.rs",
        "Name::new",
        "SAFE BY CONSTRUCTION: bounded before anything else, then a character \
         check. No parsing, no structure, and the bound comes first so a \
         hostile import cannot make it allocate before refusing",
    ),
    (
        "core/src/model.rs",
        "ItemField::new",
        "SAFE BY CONSTRUCTION: delegates the name to Name::new and treats the \
         value as opaque bytes -- the value is never parsed here, only sealed \
         later",
    ),
    (
        "core/src/model.rs",
        "Item::new",
        "SAFE BY CONSTRUCTION: delegates every name to Name::new and compares \
         names for duplicates. Quadratic in the field count, which is bounded \
         by the caller rather than here -- stated because a hostile import with \
         a million fields is the shape that would matter, and is where \
         that bound belongs",
    ),
    (
        "core/src/model.rs",
        "Item::remove_field",
        "SAFE BY CONSTRUCTION: compares a name against names already validated          by Name::new and retains the rest. No parsing; the slot list is the          representation and retain cannot reorder it",
    ),
    (
        "core/src/model.rs",
        "Item::field",
        "SAFE BY CONSTRUCTION: a linear search comparing a name to names \
         already validated by Name::new",
    ),
    (
        "core/src/store.rs",
        "Store::put_raw",
        "SAFE BY CONSTRUCTION: the opaque-record obligation. The identifiers are \
         opaque keys and the bytes are stored exactly and never read -- a \
         record this build cannot open goes in and comes out identical, so \
         the manifest's ciphertextDigest over it still holds (I6d)",
    ),
    (
        "core/src/store.rs",
        "Store::get_raw",
        "SAFE BY CONSTRUCTION: identifiers used as opaque lookup keys; returns \
         bytes unread",
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
        "SAFE BY CONSTRUCTION: an identifier used as an opaque map key over \
         metadata already authenticated on open",
    ),
    (
        "core/src/store.rs",
        "Store::set_high_water_mark",
        "SAFE BY CONSTRUCTION: an identifier used as an opaque map key; the value \
         is refused if it decreases (I6f), then re-MAC'd",
    ),
    (
        "core/src/search.rs",
        "SearchIndex::insert",
        "SAFE BY CONSTRUCTION: the identifier is an opaque key; the item's three \
         searched fields are lowercased into Zeroizing buffers -- copied, not parsed",
    ),
    (
        "core/src/search.rs",
        "SearchIndex::remove",
        "SAFE BY CONSTRUCTION: an identifier used as an opaque key",
    ),
    (
        "core/src/search.rs",
        "SearchIndex::search",
        "SAFE BY CONSTRUCTION: the query is lowercased and compared by substring \
         against fields already in memory. No parsing, no allocation per entry, \
         and the result carries identifiers rather than text",
    ),
    (
        "core/src/store.rs",
        "Store::put_chunk_raw",
        "SAFE BY CONSTRUCTION: the opaque-record obligation for chunks -- \
         identifiers are opaque keys and the bytes are stored exactly, never read",
    ),
    (
        "core/src/store.rs",
        "Store::get_chunk_raw",
        "SAFE BY CONSTRUCTION: identifiers used as opaque keys; returns bytes \
         unread",
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
        "SAFE BY CONSTRUCTION: the vault id is an opaque key into the store; the \
         bytes it writes are read from the store and MACed, never parsed",
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
        "SAFE BY CONSTRUCTION: the identifiers are opaque AAD fields, the content \
         type is bounded and copied into the AAD, and the attachment bytes are \
         read one chunk at a time and sealed -- never parsed. The policy limit is \
         applied before the first read",
    ),
    (
        "core/src/zip.rs",
        "Archive::find",
        "SAFE BY CONSTRUCTION: compares a caller's member name against the parsed \
         central directory; parses nothing",
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
        "SAFE BY CONSTRUCTION: compares the required column names against a parsed \
         row; parses nothing",
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
        "COVERED ELSEWHERE: every byte it parses arrives through onepux::parse or \
         onepif::parse, both fuzzed; the JSON grammar underneath is serde_json's",
    ),
    (
        "core/src/import.rs",
        "ItemBuilder::name_of_value",
        "SAFE BY CONSTRUCTION: compares bytes against the values already held; \
         parses nothing",
    ),
    (
        "core/src/import.rs",
        "ItemBuilder::has_field",
        "SAFE BY CONSTRUCTION: compares a name",
    ),
    (
        "core/src/import.rs",
        "ItemBuilder::field",
        "SAFE BY CONSTRUCTION: the names are bounded and copied into the item and \
         the report; the value is opaque bytes, sealed later and never parsed",
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
        "SAFE BY CONSTRUCTION: the source path is copied into the report; the \
         reason is rendered from an error that carries no content",
    ),
    (
        "core/src/import.rs",
        "ItemBuilder::finish",
        "SAFE BY CONSTRUCTION: the source type name is copied into the report",
    ),
    (
        "core/src/import.rs",
        "AttachmentHandle::new",
        "SAFE BY CONSTRUCTION: the file name is copied; it is content for the \
         report and the caller, not parsed",
    ),
    (
        "protocol/src/lib.rs",
        "Field::new",
        "NOT A BOUNDARY: the encode direction -- a field this crate is about to \
         serialise. Record::decode is the inbound half and has a target",
    ),
    (
        "protocol/src/lib.rs",
        "Record::with_field",
        "NOT A BOUNDARY: the encode direction, and the same reasoning as new",
    ),
    (
        "core/src/srp.rs",
        "private_exponent",
        "SAFE BY CONSTRUCTION: `srpSalt` genuinely is attacker-facing -- the          server hands it to the client in the login exchange, so a hostile          server chooses it. But it reaches SHA-256 and nothing else. There          is no length to trust, no structure to parse, and no branch taken          on its contents; any 32 bytes are as valid as any other. A chosen          salt produces a different `x`, which produces a verifier that does          not match the stored one, and the exchange fails to authenticate --          §2.1's self-detecting downgrade wearing different clothes. The one          thing a fuzzer could look for here, a panic on an odd length, cannot          happen: `update` takes any slice",
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
        "the stripping dropped production code *before* the marker: {found:?}"
    );
    assert!(
        found.iter().any(|f| f == "after_the_marker"),
        "**the regression this test exists for.** Production code after a \
         mid-file #[cfg(test)] item was dropped, so every classification check \
         is blind to the rest of the file and cannot notice: {found:?}"
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
        "ffi_guard.rs no longer has a mid-file {marker}. If that is deliberate \
         the fixture above still guards the stripping, but the real-world case \
         this came from is gone and the comment should say so."
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
        ": these parsers have neither a fuzz target of their own nor a \
         recorded reason for not needing one. Classify each — a parser nobody \
         decided about is a parser nobody fuzzed:\n  {}",
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
        ": these functions take bytes or text from a caller and are classified nowhere. Add each to PARSERS with a fuzz target, or to NOT_SEPARATELY_FUZZED with one of the three reason kinds:
  {}",
        unclassified.join("
  ")
    );
    assert!(
        all_declared().len() >= 40,
        "the signature scan found only {} functions in the two crates, which is          too few to have read them",
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
            "{file}::{function} is classified but takes no bare slice, so the signature \
             scan cannot see it (R7 case 8). Either the signature should carry the \
             bytes -- or this is a known blind spot: add it to \
             INVISIBLE_TO_THE_SIGNATURE_SCAN with the reason"
        );
    }
    assert_eq!(
        boundary_count, visible,
        "the signature scan found {boundary_count} functions taking bytes or text; the \
         classified rows it can see number {visible}. A row is classified twice, or \
         the scan sees a function the lists do not name"
    );
}

const INVISIBLE_TO_THE_SIGNATURE_SCAN: [(&str, &str, &str); 9] = [
    (
        "core/src/nonce.rs",
        "StoredNonce::from_stored_bytes",
        "takes a fixed-size array by value, not a slice; the name scan reaches it",
    ),
    (
        "core/src/zip.rs",
        "parse",
        "takes a generic `Read + Seek`: the bytes arrive through a reader, not a slice. \
         Registered in PARSERS by name, with its own target",
    ),
    (
        "core/src/onepux.rs",
        "parse",
        "the same generic reader, over the archive. Registered in PARSERS by name",
    ),
    (
        "core/src/onepif.rs",
        "parse",
        "takes a generic `BufRead`, line by line. Registered in PARSERS by name",
    ),
    (
        "core/src/csv.rs",
        "parse",
        "takes a generic `BufRead` and a row callback. Registered in PARSERS by name",
    ),
    (
        "core/src/bitwarden.rs",
        "parse",
        "takes a generic `BufRead`. Registered in PARSERS by name",
    ),
    (
        "core/src/lastpass.rs",
        "parse",
        "takes a generic `BufRead`, rows through csv::parse. Registered in PARSERS by name",
    ),
    (
        "core/src/chrome.rs",
        "parse",
        "takes a generic `BufRead`, rows through csv::parse. Registered in PARSERS by name",
    ),
    (
        "core/src/export.rs",
        "verify",
        "takes a generic `Read + Seek`. Registered in PARSERS by name",
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
        ": these classifications name functions that no longer exist: {stale:?}"
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
        ": these fuzz targets are in no registry: {unregistered:?}"
    );
}
