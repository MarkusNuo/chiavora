# ADR-0009 — Sealing the Vault Key to an account public key

Status: Accepted · 2026-09-21

## Context

The key hierarchy is MUK → Account Private Key (X25519) → Vault Key → Item Key,
and it runs in full offline: signup generates the account keypair, wraps the
private key under the MUK and seals a random Vault Key to the account's own
public key. ADR-0002 names X25519 for sealing but no construction, and X25519 is
key agreement, not public-key encryption.

## Decision

The seal is HPKE (RFC 9180), Base mode: `DHKEM(X25519, HKDF-SHA256)` (`0x0020`),
`HKDF-SHA256` (`0x0001`) and `ChaCha20Poly1305` (`0x0003`), through the `hpke`
crate pinned to 0.12 with `default-features = false`.

HPKE's `info` binds `vaultId`, `vaultKeyEpoch` and the recipient public key,
encoded by the canonical AAD encoder as record type `0x06`:

```text
recordType 0x06 — sealed Vault Key (HPKE info)
  AAD = "CHV1" || u8(0x06)
                || u32le(len(vaultId))    || vaultId
                || u32le(vaultKeyEpoch)
                || u32le(len(recipientPk)) || recipientPk
```

HPKE's own `enc ‖ ct` is not re-framed. The stored blob is a `CHVR` record with
two fields, the encapsulated key and the ciphertext.

## Consequences

- A wrong `info` never derives the right key, so a seal moved between vaults,
  across a rotation or to another member fails at the key schedule.
- I3's bijection proof extends to `0x06`; the injectivity test ranges over
  `aad::ALL_RECORD_TYPES`.
- `seal.rs` holds seal and open; the Vault Key comes from `csprng` and stays a
  `Secret<VaultKey>`. `manifest.rs` only receives the opened key.
- `hpke` 0.12 compiles in an unused `aes-gcm` and is two majors behind; ADR-0002
  carries the review date.
- Not decided here: publishing the public key, re-sealing on member removal,
  how long a server keeps a sealed Vault Key, and whether the keypair rotates.

## Alternatives considered

- Hand-composing ephemeral X25519 → HKDF-SHA256 → XChaCha20-Poly1305: what the
  first ground rule exists to prevent, even when the primitives are right.
- Auth or PSK mode: authenticating the sender answers a question sharing has
  not asked yet.
- HPKE's `aad` instead of `info`: a transplant then fails at the tag, which is
  ambiguous with damaged bytes.
- `hpke` 0.14: conflicts with `sha2`, `hkdf`, `chacha20poly1305` and
  `x25519-dalek`.
