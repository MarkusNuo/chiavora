# ADR-0002 — Primitive and construction choices

Status: Accepted · 2026-09-07

## Context

The first ground rule: no novel cryptography. Every primitive comes from the
RustCrypto crates, composed only in constructions that have public specs, and
any deviation is written down before it is coded. This ADR is the one record of
what `crates/core` may use and of every crate it links.

## Decision

| Crate | Use |
|---|---|
| `argon2` | Argon2id: password hashing and KDF |
| `hkdf` | HKDF: key derivation from a high-entropy secret |
| `chacha20poly1305` | XChaCha20-Poly1305: the AEAD |
| `x25519-dalek` | X25519: the account key pair, key agreement and sealing to a public key |
| `sha2` | SHA-256: HKDF, the FFI guard's fingerprints, the `CHV1-` checksum |
| `subtle` | Constant-time comparison, for I7's double-wrap agreement check |
| `crypto-bigint` 0.7.5 | Constant-time modular exponentiation for SRP-6a over the 4096-bit group; sets the MSRV at 1.85 |
| `hpke` 0.12 | HPKE Base mode, sealing the Vault Key (ADR-0009); `default-features = false`, so X25519 is the only KEM |
| `hmac` | HMAC-SHA256 over the local store's metadata and over a native export's container |
| `zeroize` | Wipes key material on drop |
| `region` | `mlock`/`VirtualLock`, best-effort by design; `LockState` reports the outcome |
| `getrandom` | The only randomness source, reached only through `csprng::fill_bytes` |
| `rusqlite` (`bundled`) | The local store: a byte store outside the trust boundary, payloads encrypted by `core` |
| `chiavora-protocol` | Our own `CHVR` wire codec; the item body is one of its records |
| `miniz_oxide` | DEFLATE for 1PUX members, a written exception; the zip container is our own `zip.rs` |
| `serde`, `serde_json` | The JSON in 1PUX and 1PIF exports, deserialised by hand into `Zeroizing` strings |
| `unicode-normalization` | NFC on the account password at the entry point |
| `unicode-general-category` | Refuses unassigned code points in the account password |
| `aes-gcm` | Transitive through `hpke` 0.12; nothing calls it |

Permitted constructions: 2SKD, with the MUK and `srpX` as domain-separated
siblings of `rootKey`; MUK → Vault Key → Item Key by wrap and unwrap, the
Account Private Key never stored unwrapped; one canonical AAD encoder; every
nonce from the platform CSPRNG through one helper, never a counter; KDF
parameters refused below the I4 floor and never retried weaker. The one accepted
deviation is SRP-6a, adapted because no widely audited implementation exists to
drop in (ADR-0007, ADR-0008).

### The JavaScript dependency layout

`.npmrc` sets `node-linker=hoisted`. React Native compiles C++ inside
`node_modules`, and pnpm's store paths exceed the Windows 260-character limit.

## Consequences

- Anything not listed here is a deviation and needs its own ADR before it is
  coded. R4's check fails on a `crates/core` dependency not named here.
- Argon2id's `m` and `t` are set by measurement on hardware and recorded in
  `docs/crypto.md`.
- `bundled` statically links SQLite's C; `crypto-bigint` 0.7 adds `asm!` beneath
  `core` through `cmov`; `serde_json`'s scratch buffer is cleared, not zeroized.
- The `hpke` pin is reviewed by 2027-03-21 or once SRP authentication is
  complete, whichever is first, and on any `cargo deny` advisory naming it.
- Hoisting can resolve two majors to one and makes undeclared dependencies
  resolvable; `pnpm -r typecheck` catches the second. Neither reaches `core`.

## Alternatives considered

- A zip crate for 1PUX: none can refuse a compression ratio above a bound.
- `crypto-bigint` 0.5.5 at MSRV 1.77: adequate, but two majors behind and
  unmaintained.
- `hpke` 0.14: needs major bumps of `sha2`, `hkdf`, `chacha20poly1305` and
  `x25519-dalek`. Hand-composing the suite is what the first ground rule
  prevents.
- The Windows long-paths setting instead of hoisting: a machine-wide change for
  one project's build.
