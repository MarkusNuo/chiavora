# Chiavora cryptography

The cryptographic detail behind [`docs/security-design.md`](security-design.md):
primitives, formats, parameters, vectors, known limitations, and the rules for
changing `crates/core`. Decisions and alternatives are in [`docs/adr/`](adr/README.md).
Every hex string here is re-derived from the encoders and compared against this
file by `crates/core/tests/documented_vectors_match_the_code.rs`.

## Primitive choices

| Primitive | Crate | Used for |
|---|---|---|
| Argon2id | `argon2` | `passKey` from the account password |
| HKDF-SHA256 | `hkdf` | every key derived from a high-entropy secret |
| XChaCha20-Poly1305 | `chacha20poly1305` | every AEAD seal; 192-bit random nonces, no counter |
| X25519 | `x25519-dalek` | the account keypair |
| HPKE, RFC 9180 Base mode | `hpke` | sealing a Vault Key to an account public key: `DHKEM(X25519, HKDF-SHA256)`, `HKDF-SHA256`, `ChaCha20Poly1305` |
| HMAC-SHA256 | `hmac` | local store metadata, the `CHVX` container, the request MAC, fabricated SRP records |
| SHA-256 | `sha2` | SRP's `H`, record and chunk digests, manifest prefixes, the FFI guard's fingerprints, the `CHV1-` checksum |
| SRP-6a | `crypto-bigint` | authentication, over constant-time big integers |
| Constant-time comparison | `subtle` | `M1` and `M2`, I7's double-wrap agreement, the unknown-account selection |
| Randomness | `getrandom` | one call site, `crates/core/src/csprng.rs` (R3) |
| Memory hygiene | `zeroize`, `region` | wipe-on-drop key buffers and a best-effort `mlock` (N1) |

The rationale is `docs/adr/0002`, SRP over OPAQUE is `docs/adr/0007`, and the
SRP construction is `docs/adr/0008`. SHA-1 is a dev-dependency only, for RFC
5054's Appendix B.

`crates/core/tests/published_primitive_vectors.rs` checks the crates against
`tests/vectors/published_primitives.json`: HKDF, ChaCha20-Poly1305 and HChaCha20
independently reproduced, XChaCha20-Poly1305 composed from them, X25519 and
Argon2id checked against one implementation each.

## Key derivation

§2.1, as `crates/core/src/derive.rs` implements it:

```text
salt        = HKDF-SHA256(ikm = accountSalt, info = "chiavora-salt|" ‖ accountId, len = 16)
secretKeyKD = HKDF-SHA256(ikm = secretKey,   info = "chiavora-skk|"  ‖ accountId, len = 32)
passKey     = Argon2id(password, salt, m, t, p = 4)                                 len = 32
rootKey     = passKey XOR secretKeyKD                                               len = 32
MUK         = HKDF-SHA256(ikm = rootKey, info = "chiavora-muk",    len = 32)
srpX        = HKDF-SHA256(ikm = rootKey, info = "chiavora-srp",    len = 32)
StoreKey    = HKDF-SHA256(ikm = MUK,     info = "chiavora-store",  len = 32)
ExportKey   = HKDF-SHA256(ikm = MUK,     info = "chiavora-export", len = 32)   // StoreKey's sibling
```

- Argon2id runs at `m = 256 MiB, t = 4, p = 4`, as measured (*Benchmark
  results*). Parameters are per-account. The client refuses anything below I4's
  floor, `m = 64 MiB, t = 3` (`I4_FLOOR_MEMORY_KIB`, `I4_FLOOR_ITERATIONS`).
- No HKDF salt is used; separation is carried entirely by `info`.
  `no_hkdf_call_site_passes_a_salt` checks every call site under `crates/*/src`.
- `srpX` is a sibling of the MUK, not a child (`srp_x_cannot_be_derived_from_the_muk`).
  The XOR is why both factors are required
  (`a3_the_password_alone_does_not_determine_the_root_key`).
- The account password is normalised to NFC and nothing else
  (`entry::PasswordField`); control characters, unassigned code points and
  non-UTF-8 input are refused. The rule is frozen once an account exists.
- The Secret Key is `CHV1-` and 26 Crockford base32 characters (128 bits, two
  zero padding bits) plus a 10-bit checksum (`docs/adr/0004`,
  `tests/vectors/secret_key_format.json`).

## The versioned wire format

`crates/protocol` frames every stored and transmitted record, little-endian and
length-prefixed rather than delimited:

```text
magic      4 bytes   "CHVR"
version    u16 LE    currently 1
fieldCount u32 LE
  per field:
    tag    u16 LE
    len    u32 LE
    value  len bytes
```

A record with two fields, `tag 1 = "ab"` and `tag 2 = "c"`:

```text
43485652 0100 02000000 0100 02000000 6162 0200 01000000 63
^CHVR    ^v1  ^2 flds  ^t1  ^len 2   ^ab  ^t2  ^len 1   ^c
```

`43485652010002000000010002000000616202000100000063`

- Decoding reserves nothing from `fieldCount` or `len` until the claim is
  bounded against the bytes present (R1). Editing a field whose tag appears
  twice is refused (`WireError::AmbiguousTag`).
- A higher `version` is accepted on decode and kept; `Record::new` writes this
  build's `WIRE_VERSION`, and nothing can set a version.
- An item body is a `CHVR` record with its own `model::tag::SCHEMA_VERSION`.
  Schema changes are additive: unknown fields are written back in position, an
  unknown item kind is refused (`UnknownKind`) and kept opaque.
- `ciphertextDigest = SHA-256(AAD ‖ nonce ‖ ciphertext ‖ tag)` over the payload
  record only, so a Vault Key rotation changes no digest.
- Attachments are 1 MiB chunks (`attachment::CHUNK_LEN`, a format constant)
  sealed under the item's Item Key, at most 100 MiB (`MAX_ATTACHMENT_BYTES`, a
  policy). Each chunk's digest, computed as above, feeds `chunkDigestRoot`.
- The local store's metadata is one `CHVR` record HMAC-SHA256'd under the Store
  Key and verified on every `Store::open`: authenticated, not encrypted.
- The device-wrapped MUK has no AAD record type: a substituted blob yields a
  different MUK, whose Store Key fails that MAC.

## The AAD encoding

Invariant I3 (§2.2): integrity-relevant metadata is bound as associated data,
and no two distinct field tuples produce the same AAD. One encoder,
`aad::encode` (R2). Every string starts `"CHV1" ‖ recordType`; variable-length
fields carry a `u32` LE length prefix; integers are fixed-width LE.

| Type | Record | Fields after the prefix |
|---|---|---|
| `0x01` | item payload | `vaultId`, `itemId`, `version` (u64), `contentType` |
| `0x02` | attachment chunk | `vaultId`, `itemId`, `version` (u64), `attachmentId`, `chunkIndex` (u32), `chunkCount` (u32), `contentType` |
| `0x03` | manifest root | `vaultId`, `manifestSeq` (u64), `vaultKeyEpoch` (u32), `segmentCount` (u32) |
| `0x04` | manifest segment | `vaultId`, `segmentSeq` (u64), `vaultKeyEpoch` (u32), `prefixLen` (u8), `prefixBits` (u64) |
| `0x05` | wrapped Item Key | `vaultId`, `itemId`, `wrapPurpose` (u8) |
| `0x06` | sealed Vault Key, as HPKE `info` | `vaultId`, `vaultKeyEpoch` (u32), `recipientPk` |
| `0x07` | Autofill Key wrapped under the Vault Key | `vaultId`, `vaultKeyEpoch` (u32) |
| `0x08` | account private key wrapped under the MUK | `accountId`, `accountKeyEpoch` (u32) |

Refused on encode and decode, never masked: `prefixLen` above 64
(`AadError::PrefixLenTooLarge`); a `prefixBits` bit set below the top
`prefixLen` bits (`AadError::PrefixBitsNotCanonical`); a `wrapPurpose` other
than `0x01` (Vault Key) or `0x02` (Autofill Key) (`AadError::UnknownWrapPurpose`);
bytes after a complete record (`AadError::TrailingBytes`). `aad::decode` is the
inverse, and `i3_aad_injectivity.rs` proves the round trip for every type in
`aad::ALL_RECORD_TYPES`.

A `login` or `TOTP` item's two `0x05` wraps differ only in `wrapPurpose`
(`docs/adr/0006`). `0x06` is HPKE's `info`, so a transplanted seal never derives
the right key (`docs/adr/0009`). `0x08` has no manifest above it, so the store
keeps `ACCOUNT_KEY_HIGH_WATER_MARK` and refuses a rewind
(`StoreError::AccountKeyRewound`).

### Vectors

`vaultId = "ab"`, `itemId = "c"`, `version = 1` throughout: the pair that
collides with `vaultId = "a", itemId = "bc"` without length prefixes.

`0x01` item payload, `contentType = "login"`:

```text
434856310102000000616201000000630100000000000000050000006c6f67696e

43485631 01 02000000 6162 01000000 63 0100000000000000 05000000 6c6f67696e
^CHV1    ^  ^len 2   ^ab  ^len 1   ^c ^version 1       ^len 5   ^login
```

`0x02` attachment chunk, `attachmentId = "at"`, chunk 0 of 2,
`contentType = "application/pdf"`:

```text
43485631020200000061620100000063010000000000000002000000617400000000020000000f0000006170706c69636174696f6e2f706466
```

`0x03` manifest root, `manifestSeq = 7`, `vaultKeyEpoch = 1`, `segmentCount = 4`:

```text
434856310302000000616207000000000000000100000004000000
```

`0x04` manifest segment, `segmentSeq = 7`, `vaultKeyEpoch = 1`, `prefixLen = 2`,
`prefixBits = 0xC000000000000000`:

```text
43485631040200000061620700000000000000010000000200000000000000c0
```

`0x05` wrapped Item Key, `wrapPurpose = 0x01` (Vault Key) and `0x02` (Autofill Key):

```text
4348563105020000006162010000006301
4348563105020000006162010000006302
```

## The manifest structure

One root (`0x03`) and one or more segments (`0x04`), all under the Vault Key.
The root carries `manifestSeq`, `vaultKeyEpoch`, `segmentCount` and, per
segment, its prefix, the digest of the sealed segment and the sequence it was
last written at. A segment carries the entries whose `H(itemId)` falls under its
prefix: `itemId`, `currentVersion`, `ciphertextDigest`, a tombstone flag and the
attachment set with each attachment's `chunkDigestRoot`. `H` is SHA-256, the
prefix is its top 64 bits big-endian, and `itemId` is 128 bits. A segment splits
at `prefixLen + 1` when it crosses 512 entries, targeting 256; segments never
merge, and tombstones are permanent.

| | Read-path refusal | Error |
|---|---|---|
| I6a | a root below this device's high-water mark | `RootBelowHighWaterMark` |
| I6b | prefixes that do not tile exactly; a segment the root does not vouch for | `PrefixSetHasGap`, `PrefixSetOverlaps`, `SegmentDigestMismatch` |
| I6c | an item below its entry's version | `ItemVersionRollback` |
| I6d | different bytes at the same version | `CiphertextDigestMismatch` |
| I6e | listed and not delivered, or delivered and not listed | `ItemListedNotDelivered`, `ItemDeliveredNotListed`, `SegmentListedNotDelivered`, `AttachmentListedNotDelivered`, `AttachmentDeliveredNotListed` |
| I6f | `manifestSeq` going backwards, including across a rotation | `HighWaterMarkRewound` |
| | wrong chunk count; a replayed, stale or reordered chunk | `AttachmentChunkCountDisagrees`, `ChunkDigestRootMismatch` |

I6a is checked before I6b, I6c before I6d, and a chunk count before its digest
root. Canonicality is checked before tiling, never normalised first.

A write verifies the current root and the segments it touches, merges taking
the higher version, and writes at the fetched root's `manifestSeq + 1` in one
compare-and-swap. A conflict keeps both versions: the smaller `ciphertextDigest`
stays primary and the loser is re-sealed (`sync::ConflictCopySealer`) as
`SHA-256("chiavora-conflict|" ‖ losingItemId ‖ losingDigest)[..16]`. Rotation
re-wraps first and flips the root last. The compare-and-swap contract
(`crates/core/tests/write_path_and_cas_contract.rs`):

| | |
|---|---|
| C1 | A root write is accepted iff `manifestSeq == current + 1`. Not `>`, not `>=` |
| C2 | The root and the segments it names land as one transaction; a write replaces the segments it carries and keeps the rest |
| C3 | A refused write returns the current `manifestSeq` |
| C4 | The server never reads, re-encodes or re-orders a record |
| C5 | Chunks are content-addressed; unreferenced blobs are collected only after the grace period (default 30 days, floor 7) |
| C6 | The server enumerates exactly the metadata it sees |
| C7 | The previous epoch's sealed Vault Key is retained until a client explicitly releases it, never by timeout or inference |
| C8 | The release is an authenticated request any enrolled device may send, after a manifest-checked read shows nothing left at the old epoch |

Every clause is a liveness obligation: a hostile server can refuse writes but
cannot make a client accept a bad state. The server sees `vaultId`,
`manifestSeq`, `vaultKeyEpoch`, `segmentCount`, every `segmentPrefix`, record
sizes, write times and frequency, and the number and sizes of chunks.

## Authentication (SRP-6a)

RFC 5054's exchange over its 4096-bit group, `g = 5`, `H = SHA-256`; only `x`'s
provenance changes (`docs/adr/0008`).

```text
x       = SHA-256(srpSalt ‖ srpX)
v       = g^x mod N
k       = H(N ‖ PAD(g))
u       = H(PAD(A) ‖ PAD(B))
K       = HKDF-SHA256(S, "chiavora-srp-k",   32)
macC2S  = HKDF-SHA256(S, "chiavora-mac-c2s", 32)
macS2C  = HKDF-SHA256(S, "chiavora-mac-s2c", 32)
M1      = H( H(N) XOR H(g) ‖ H(I) ‖ srpSalt ‖ PAD(A) ‖ PAD(B) ‖ K )
M2      = H( PAD(A) ‖ M1 ‖ K )
```

- `srpSalt` is 32 random bytes, independent of `accountSalt`. `I` is
  `accountId`, never the email. `S` is never a key.
- Every transcript field is fixed-width; a wrong-width `srpSalt` or `M1` is
  `SrpError::TranscriptFieldLength`. `proofs_match` compares in constant time.
- The group and hash are compile-time (`srp_group_cannot_come_from_the_wire`).
- A public value `≡ 0 mod N` is refused, `A` before any exponentiation
  (`check_public_value`) and again in `server_premaster`.
- `b` is per attempt (`srp::generate_ephemeral`) and consumed by
  `PendingExchange` (`a_pending_exchange_cannot_be_finished_twice`). Secret
  exponents cannot leave `core::srp` (`srp_secret_exponents_do_not_leave_the_module`).
- The server stores `AuthRecord = accountId (16) ‖ srpSalt (32) ‖ v (512)`.
  No crate above `core` depends on a cryptographic crate
  (`no_crate_above_core_depends_on_a_cryptographic_crate`).
- The request MAC (`core::request_mac`) is HMAC-SHA256 under `macC2S` or
  `macS2C` over the label `chiavora-request-mac`, method, path, `SHA-256(body)`,
  a timestamp (±300 s) and a 16-byte nonce, each behind a big-endian `u32` length.

An unknown identifier gets a fabricated record (RFC 5054 §2.5.1.3):

```text
e          = normalise(email)                                    // adr/0008 §5.3
srpSalt'   = HMAC-SHA256(seedKey, "chiavora-srp-fake-salt"    ‖ e)
x'         = HMAC-SHA256(seedKey, "chiavora-srp-fake-x"       ‖ e)
accountId' = HMAC-SHA256(seedKey, "chiavora-srp-fake-account" ‖ e)[0..16]
v'         = g^x' mod N
```

It fails at `M1` with the wrong-password error. The fabrication is
unconditional and selected byte-wise with `subtle`
(`the_known_and_unknown_paths_produce_an_identical_operation_trace`). The seed
key is 32 bytes (`SRP_SEED_KEY_LEN`), refused at any other width.

The vectors are in `crates/core/tests/vectors/`, written by
`tools/srp_reference.py`, which shares no code with `crates/core`:

| File | Holds | Test |
|---|---|---|
| `srp_groups.json` | `N`, `g` for the 4096-bit and 1024-bit groups, with safe-prime and generator checks | `the_group_table_matches_the_rfc` |
| `rfc5054_appendix_b.json` | Appendix B, 1024-bit/SHA-1: the algebra, not what ships | `rfc5054_appendix_b_vectors_pass_for_the_exchange_algebra_at_1024_sha1` |
| `srp_derivation.json` | `x` and `v` at 4096-bit/SHA-256, one `x` with a leading zero byte | `project_vectors_cover_the_x_derivation_and_verifier_at_4096_sha256` |
| `srp_proofs.json` | `M1`, `M2`, `K` and both MAC keys at 4096-bit/SHA-256 | `project_vectors_cover_m1_m2_and_the_key_schedule_at_4096_sha256` |

## The native export container (CHVX)

```text
"CHVX" ‖ u16le(version = 1)
‖ u32le(len) ‖ header record         VAULT_ID, GENERATION, [HIGH_WATER_MARK], RECORDS, CHUNKS
‖ ( 0x01 ‖ u32le(len) ‖ item record   ITEM_ID, VERSION, BYTES )*
‖ ( 0x02 ‖ u32le(len) ‖ chunk record  ITEM_ID, ATTACHMENT_ID, CHUNK_INDEX, BYTES )*
‖ 0x00 ‖ HMAC-SHA256(Export Key, everything before it)
```

Records are `CHVR` wire records, and items and chunks are the exact bytes the
store holds, so the export is lossless. Every `len` is bounded against
`export::MAX_ENTRY_BYTES` (16 MiB) before anything is reserved. Restore verifies
the MAC in a first pass and writes in a second. The content is ciphertext under
keys descending from the MUK; the metadata is authenticated and visible.

## Benchmark results

Argon2id through `derive_root_key`, `p = 4`, on a 2024 flagship Android phone
(12 GB, Android 16), well above the 6 GB entry-tier reference class §2.1 names.

| Run | `m` | `t` | Time |
|---|---|---|---|
| shell, median of five | 64 / 128 / 256 / 512 / 1024 MiB | 3 | 88.47 / 189.68 / 394.48 / 819.91 ms / 1.733 s |
| shell, median | 256 MiB | 3 / 4 | 396.96 / 508.90 ms |
| app, foreground, Kotlin / Expo | 256 MiB | 4 | 544 / 566 ms |
| app, backgrounded (`oom_score_adj` 700), Kotlin / Expo | 256 MiB | 4 | 1844 / 970 ms |
| app, backgrounded under memory pressure, Kotlin / Expo | 256 MiB | 4 | 2428 / 2773 ms; repeat 1716 / 1741 ms |
| laptop | 256 MiB | 3 | 545.51 ms |

256 MiB is §2.1's target against a 6 GB floor; `t = 4` is the first to clear
500 ms. Every in-app run allocated and completed; the backgrounded rows are
scheduler variance, not a comparison. The SRP client side costs about 9.7 ms.
The harness is `crates/core/tests/on_device_cost_reports.rs` (`report_kdf_cost_on_this_machine`).

## Known limitations

- N1: key material is wiped in `core` (best-effort `mlock`); decrypted UI content is not.
- On Android the plaintext MUK crosses a Java `byte[]` in the Keystore `Cipher`.
- Argon2id is unmeasured on iOS and on an entry-tier Android device.
- The measured Argon2id default is not a constant in `crates/core`; only I4's floor is.
- The low-memory killer can end a derivation, which is not a refusal.
- A whole-file rewind of the local store is detectable only through a `RollbackAnchor`.
- The Keystore's TEE fallback has never run on hardware.
- The FFI guard catches key material crossing by accident, and never sees the password.
- Five of I1(a)'s six entry points have a core-side path; none has a host yet.
- Auto-lock is the only defence that survives an accessibility service.
- The password gets NFC only, so a width difference reads as a wrong password.
- A photograph of the Emergency Kit plus the password is a complete break.
- The `CHV1-` checksum is 10 unkeyed bits: a typo aid, not integrity.
- The search index holds plaintext titles, usernames and URLs in memory.
- `serde_json`'s scratch buffer for escaped strings in an import is not zeroized.
- `segmentPrefix` tells the server which subset of items an edit concerns.
- A frozen server looks the same as a device that has not synced (`Behind`).
- Manifest size grows with every deletion ever made.
- Nothing published covers SRP as it ships; its vectors have one independent check.
- Constant-time SRP exponentiation rests on a type and a scan, not a measurement.
- There is no transport yet, so its own oracle surfaces are unexamined.
- `0x06`, `0x07` and `0x08` have no documented vectors.

## Rules for changing `crates/core`

- R1 — No cryptographic operation absorbs a failure into a valid-looking output.
- R2 — Nothing constructs AAD by hand.
- R3 — One CSPRNG call site.
- R4 — Deviations are written down before they are coded.
- R5 — A claim that code cannot be written is only established by a compile-fail test.
- R6 — A header is not exempt: whatever the rule is, it applies to the whole input.
- R7 — A fuzzing result is not evidence without a coverage figure and a seeded corpus.
- R8 — A heuristic that can misattribute silently is worse than one that fails loudly.
- R9 — A mechanism that only runs in a situation which has not yet arisen has not run.
- R10 — A value an adversary chooses, whose wrongness raises no error, has no defence until somebody writes one.

Every rule that can be mechanised is checked by
`crates/core/tests/rules_are_mechanised.rs`.
