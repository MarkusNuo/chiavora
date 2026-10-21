# Chiavora — security design

The threat model, cryptographic design and architecture of Chiavora, a
mobile-first, end-to-end-encrypted password manager. `docs/crypto.md` holds the
detail; `docs/adr/` records the individual decisions.

## Ground rules

1. **No novel cryptography.** Every primitive comes from the RustCrypto crates
   (`argon2`, `chacha20poly1305`, `x25519-dalek`, `hkdf`, `sha2`, `subtle`),
   composed only in constructions with public specs (Argon2id, HKDF,
   XChaCha20-Poly1305, SRP-6a, X25519). Any deviation is justified in
   `docs/crypto.md` before it is coded. SRP-6a is the known exception: no
   widely audited implementation exists, so ours is verified against published
   test vectors.
2. **Own code only.** No code, assets or UI copied from other products.

## 1. Threat model

| ID | Adversary | Defence |
|---|---|---|
| A1 | Server operator or breach, with read-write access to database and blobs | Learns nothing beyond metadata: item counts, sizes, timestamps, IP addresses |
| A2 | Network attacker, including one with a mis-issued TLS certificate | Application-layer E2EE plus SRP; TLS is not load-bearing for secrecy |
| A3 | Offline brute force on an encrypted copy held without the device | The 128-bit Secret Key. With a dumped device keystore as well, the attacker is A4/A8 (§2.4) |
| A4 | Another local process reading our files, clipboard or IPC socket | OS keychain, clipboard TTL, authenticated IPC; N1 is the limit |
| A5 | A malicious website seeking a fill for another origin | Exact-origin matching, no cross-origin iframe fill without confirmation, no autosubmit |
| A6 | Shoulder surfing, an unattended device | Auto-lock, concealed fields, no secrets in window titles or notifications |
| A7 | A malicious co-member of a shared vault | The server refuses the write; against a colluding server, nothing until manifests carry per-writer signatures |
| A8 | A hostile app on the same phone | `FLAG_SECURE`, iOS snapshot suppression, sensitive clipboard entries with a TTL, `FLAG_WINDOW_IS_OBSCURED` checked before fill confirmation |

An accessibility service the user has granted defeats every A8 defence except
auto-lock, which is why the idle timeout has a ceiling. That case is accepted.

Out of scope, besides a compromised OS, a malicious build-time dependency
(mitigated, not solved) and legal compulsion:

- **N1** Memory disclosure of decrypted content. Key material (root key, MUK,
  vault keys, item keys, the SRP exponent) never leaves the Rust core, but item
  content shown in a garbage-collected UI cannot be zeroed. A dump of a locked
  client yields nothing; one of an unlocked client may yield what is on screen.
- **N2** A device compromised while unlocked. Revocation protects later writes
  and recalls nothing; recovery ends with a credential-rotation checklist.
- **N3** Freeze and fork: a stale but genuine view, which only a second device's
  high-water mark exposes. A new device confirms a checkpoint fingerprint
  against an enrolled one, or is trust-on-first-use.
- **N4** Read-only sharing is server policy, not cryptography (A7); the sharing
  UI says so.

Invariants, each with an automated test named after it:

- **I1** The server never receives the account password, the Secret Key, the
  root key, the MUK or any vault key, in any form, including logs and crash
  reports. Branding starts at the input boundary, which has these entry points:
  the password field, the Secret Key field, the Emergency Kit QR decode path,
  clipboard paste, CLI stdin, and inbound native messaging.
- **I2** Every ciphertext is AEAD; every nonce comes from the platform CSPRNG
  through one audited helper.
- **I3** Integrity-relevant metadata is bound as AAD in one canonical encoding
  (§2.2), so no ciphertext can move between items, attachment chunks,
  wrapped-key slots, vaults, epochs or members.
- **I4** The client refuses KDF parameters below the §2.1 floor.
- **I5a** Browser autofill fills only an exact scheme + host match, unless the
  user has broadened that item (§3.1).
- **I5b** Mobile fills an app only through a platform-verified association, or
  after an explicit confirmation naming its package or team identifier.
- **I6** Freshness (§2.5), one test per clause:
  - **I6a** No manifest root below the persisted `manifestSeq` high-water mark.
  - **I6b** No segment the root does not vouch for, and no root whose segment
    prefixes fail to tile the keyspace. A non-canonical prefix fails outright.
  - **I6c** No item below its entry's `currentVersion`.
  - **I6d** No item whose ciphertext fails to digest-match its entry.
  - **I6e** No silently missing or extra item or chunk; deletes are tombstones.
  - **I6f** `manifestSeq` is strictly monotonic, across Vault Key rotations
    too, and its high-water mark lives in the authenticated local store.
- **I7** A `login` or `TOTP` item's Item Key unwraps byte-for-byte identically
  under the Vault Key and the Autofill Key; other items have one copy (§2.2).
- **I8** The Secret Key's keystore entry is protected by device credential and
  never biometric-bound; the MUK's wrapping key is biometric-bound (§2.4).

## 2. Cryptographic design

### 2.1 Two-secret key derivation (2SKD)

At signup the client generates a 128-bit Secret Key and shows it once, on the
Emergency Kit, as `CHV1-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXCC` in Crockford Base32;
`CC` is a checksum for transcription, not integrity (`docs/adr/0004`).
Re-exporting the Kit needs a fresh password or biometric check. The password
never leaves the device and is normalised to NFC, nothing else.

```text
salt        = HKDF-SHA256(ikm = accountSalt, info = "chiavora-salt|" || accountId, len = 16)
passKey     = Argon2id(password, salt, m, t, p = 4, len = 32)
secretKeyKD = HKDF-SHA256(ikm = secretKey, info = "chiavora-skk|" || accountId, len = 32)
rootKey     = passKey XOR secretKeyKD          // never stored, never sent
MUK         = HKDF-SHA256(ikm = rootKey, info = "chiavora-muk", len = 32)
srpX        = HKDF-SHA256(ikm = rootKey, info = "chiavora-srp", len = 32)
```

`accountId` (128 bits) and `accountSalt` (256 bits) are independent random
values generated on the device at signup and never changed (`docs/adr/0005`);
no mutable identifier, such as an email address, feeds key derivation.
Breaking the password still leaves all 128 bits of the Secret Key.

Argon2id parameters are per account, so the weakest device that will unlock the
account sets them: the largest `m` that allocates reliably in a backgrounded app
under memory pressure, then `t` raised to at least 500 ms (`docs/crypto.md`).
The device floor is 6 GB of RAM (Android 13 or 14; iPhone 14 or newer, 12 Pro
and 13 Pro), enforced by Play on Android and checked before derivation on iOS.
The hard floor (I4) is `m = 64 MiB, t = 3`. Changing parameters rotates the
private-key wrap and the SRP verifier on every device; a failed allocation is
an error, never a retry at weaker settings.

### 2.2 Key hierarchy and record format

```text
rootKey (derived, never stored)
 ├─ MUK
 │   └─ wraps  Account Private Key      (X25519, one per account)
 │                └─ unwraps  Vault Key  (symmetric, one per vault)
 │                                └─ unwraps  Item Key (one per item)
 │                                                └─ encrypts the item payload
 └─ srpX  ──────────────────────────────────────►  SRP-6a verifier (§2.3)

Autofill Key (provisioned to the autofill provider only — §3.3)
 └─ unwraps  Item Key  ── for items of type login and TOTP only
```

The account keypair is not derived from the MUK, so a password change only
re-wraps the private key. The Vault Key is sealed to each member's public key
with HPKE (RFC 9180, Base mode; `docs/adr/0009`) and rotates when a member is
removed. The Autofill Key is a random 256-bit key per vault, wrapped under the
Vault Key (`docs/adr/0003`); `note`, `card`, `identity` and `SSH key` items
have no Autofill Key copy.

Records use XChaCha20-Poly1305 with a 192-bit random nonce — collision risk is
negligible, so there is no nonce counter state to get wrong. One encoder in
`core` builds the length-prefixed, versioned AAD (I3):

```text
common = "CHV1" || u8(recordType) || u32le(len(vaultId)) || vaultId
           || u32le(len(itemId)) || itemId || u64le(version)

recordType 0x01 — item payload
  AAD = common || u32le(len(contentType)) || contentType
recordType 0x02 — attachment chunk
  AAD = common || u32le(len(attachmentId)) || attachmentId || u32le(chunkIndex)
               || u32le(chunkCount) || u32le(len(contentType)) || contentType
recordType 0x03 — manifest root (§2.5)
  AAD = "CHV1" || u8(0x03) || u32le(len(vaultId)) || vaultId
               || u64le(manifestSeq) || u32le(vaultKeyEpoch) || u32le(segmentCount)
recordType 0x04 — manifest segment (§2.5)
  AAD = "CHV1" || u8(0x04) || u32le(len(vaultId)) || vaultId || u64le(segmentSeq)
               || u32le(vaultKeyEpoch) || u8(prefixLen) || u64le(prefixBits)
recordType 0x05 — wrapped Item Key
  AAD = "CHV1" || u8(0x05) || u32le(len(vaultId)) || vaultId
               || u32le(len(itemId)) || itemId || u8(wrapPurpose)
recordType 0x06 — sealed Vault Key, HPKE `info`
  AAD = "CHV1" || u8(0x06) || u32le(len(vaultId)) || vaultId
               || u32le(vaultKeyEpoch) || u32le(len(recipientPk)) || recipientPk
recordType 0x07 — wrapped Autofill Key
  AAD = "CHV1" || u8(0x07) || u32le(len(vaultId)) || vaultId || u32le(vaultKeyEpoch)
recordType 0x08 — wrapped account private key
  AAD = "CHV1" || u8(0x08) || u32le(len(accountId)) || accountId || u32le(accountKeyEpoch)
```

`wrapPurpose` is `0x01` for the Vault Key and `0x02` for the Autofill Key. In
`0x04`, `prefixLen` must be `0..=64` and `prefixBits` zero below the prefix.

### 2.3 Authentication (SRP-6a)

Login uses SRP-6a over a 4096-bit group with `x = SHA-256(srpSalt || srpX)`,
computed outside the SRP code as a recorded deviation (`docs/adr/0008`;
`docs/adr/0007` covers OPAQUE). The server stores only the verifier and its
salt, and answers the pre-login parameter fetch for unknown accounts with
plausible deterministic values, so it reveals no account's existence. The
session key MACs each request: HMAC over method, path, body hash, timestamp and
nonce.

### 2.4 Secondary unlock

The MUK is stored wrapped by a biometric-gated key in Secure Enclave, StrongBox
or the platform keychain, wiped on lock timeout or after N failed attempts, and
invalidated when biometrics are re-enrolled. The Secret Key stays in the
keystore under device credential (I8), so a biometric change costs only the
password; the Emergency Kit is for new or wiped devices. Without the Secret Key
or a device holding it, there is no recovery.

### 2.5 Freshness: rollback, suppression and deletion (I6)

Per-item AAD stops forgery, not replay, withholding or deletion. A per-vault
manifest, encrypted under the Vault Key, does:

```text
root (0x03)     manifestSeq u64, vaultKeyEpoch u32,
                segments[] { prefixLen, prefixBits, digest, segmentSeq }
segment (0x04)  segmentSeq u64, prefixLen u8, prefixBits u64,
                entries[] itemId → { currentVersion, ciphertextDigest, tombstone,
                  attachments[] { attachmentId, chunkCount, chunkDigestRoot, totalSize } }
```

An edit rewrites one segment and the root. Clients write at `manifestSeq + 1`
after rebasing on the newest root they can authenticate, and the server rejects
any other value. A real conflict keeps both versions. Tombstones are permanent
in v1. The high-water mark is MAC'd under a key derived from the MUK.

### 2.6 What gets written down

`docs/crypto.md` has the primitives, wire format, AAD vectors and benchmarks.

## 3. Architecture and stack

A polyglot monorepo: one Rust core, three thin platform shells above it.

### 3.1 Origin and app matching (I5a, I5b)

In the browser an item saved for `https://login.example.com` fills there and
nowhere else; eTLD+1 only ranks suggestions. Broadening an item to its
registrable domain is opt-in, visible and timestamped. On mobile only Android
Digital Asset Links or iOS Associated Domains link an app to a site.

### 3.2 Stack decisions, and the reasoning

| Part | Choice |
|---|---|
| Core and CLI | Rust, bound through `uniffi` and `napi-rs` (`docs/adr/0001`) |
| Mobile | React Native (Expo); native Swift and Kotlin autofill providers |
| Desktop | Electron, sandboxed and context-isolated |
| Browser extension | MV3, TypeScript, no keys, native messaging to the desktop app |
| Server | Rust, `axum`, `sqlx`, PostgreSQL |
| Storage | SQLite with records encrypted by `core`; keys in the platform keystore |

The core is Rust because SRP needs constant-time modular exponentiation, which
JavaScript's `BigInt` cannot guarantee.

The server sees item ids, versions, sizes, timestamps, `manifestSeq`,
`vaultKeyEpoch`, `segmentPrefix` and `accountKeyEpoch`.

### 3.3 The trust boundary

| Component | Holds key material? | Trust boundary |
|---|---|---|
| `core` (Rust) | Yes — all of it | Inside |
| Mobile app, desktop app, CLI | Via `core` | Inside |
| iOS AutoFill provider / Android AutofillService | Yes — the Autofill Key; the MUK never leaves the main app | Inside |
| Browser extension (MV3) | No | Outside |
| Sync server | No | Outside (and hostile, per A1) |

The autofill provider holds every fillable item's key. Requirements:

1. The Autofill Key is stored only wrapped by a biometric-gated hardware key.
2. Key material goes storage → `core`, never through Swift or Kotlin. The
   provider links `core` and hands it an opaque handle.
3. The key is obtained per fill request and released straight after.
4. Association verification (I5b) runs before any vault access.
5. Before filling, the provider checks the item's digest and version against an
   authenticated manifest snapshot from the host app.
