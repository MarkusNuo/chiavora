# Chiavora

Chiavora is an end-to-end-encrypted password manager, mobile first. It is
built on well-studied designs: two-secret key derivation, SRP authentication,
per-vault and per-item keys, and a sync server that only ever sees
ciphertext. Android comes first; desktop, a browser extension, a CLI, a
self-hostable server and iOS follow.

> **Status: pre-alpha.** The core is largely built and tested, the Android app
> is in progress, sync and autofill are not there yet. Nothing has been
> audited. Do not store real passwords in it.

## Features

- Two-secret key derivation: your password plus a 128-bit Secret Key, through
  Argon2id and HKDF.
- Per-vault keys sealed to an account key pair, per-item keys, and a separate
  autofill key.
- Every record is AEAD-encrypted (XChaCha20-Poly1305) with a canonical AAD
  encoding, so records cannot be swapped.
- An authenticated manifest per vault, so a server cannot roll back, drop or
  reorder items unnoticed.
- SRP-6a (RFC 5054, 4096-bit, SHA-256) on client and server.
- Secret Key format and a printable Emergency Kit.
- Password and passphrase generator.
- Import from 1Password, Bitwarden, LastPass and Chrome; an encrypted export.
- Android app: vault list, item editor, biometric unlock, auto-lock,
  screenshot protection, self-clearing clipboard.

## Tech stack

| Area | Technology |
|---|---|
| Core | Rust, RustCrypto, `hpke`, `crypto-bigint`, SQLite (`rusqlite`) |
| Bindings | `uniffi` (Kotlin, Swift), `napi-rs` (Node) |
| Mobile | React Native (Expo) and a native Kotlin module |
| Desktop, extension, CLI | scaffolds |
| Server | Rust; the SRP library is done, the HTTP server is not |

## Getting started

You need Rust (the version is pinned in `rust-toolchain.toml`), Node.js 20 and
pnpm 9. For the Android app also the Android SDK and NDK and
`cargo install cargo-ndk`; on Windows the Visual Studio C++ build tools.

```bash
git clone https://github.com/MarkusNuo/chiavora.git
cd chiavora
cargo test --workspace
pnpm install && pnpm test
```

On Windows, run `pwsh -File scripts/gate.ps1` instead of a bare `cargo test`.
It picks an MSVC toolchain that can link the tests and runs fmt, clippy, the
tests, `cargo deny` and the Android compile.

To run the Android app:

```powershell
pwsh -File scripts/mobile-native.ps1
cd apps/mobile
pnpm android
```

Fuzzing needs nightly and `cargo-fuzz`: `pwsh -File scripts/fuzz.ps1 -Seconds 45`.

## Project structure

| Folder | Contents |
|---|---|
| `crates/core/` | Cryptography, key hierarchy, items, store, manifest, sync, importers |
| `crates/protocol/` | Wire types shared by client and server |
| `crates/ffi-mobile/`, `crates/ffi-node/` | Bindings for Kotlin/Swift and Node |
| `crates/server/` | The sync server |
| `apps/mobile/` | The React Native app and its Android module |
| `apps/desktop/`, `apps/extension/`, `apps/cli/` | Scaffolds |
| `fuzz/` | Fuzz targets |
| `scripts/`, `tools/` | Build and test scripts, vector generators |
| `docs/` | Security design, cryptography, decision records |

## Security

The design is in [docs/security-design.md](docs/security-design.md) and
[docs/crypto.md](docs/crypto.md). Please report vulnerabilities privately; see
[SECURITY.md](SECURITY.md).

The products named in the import list are trademarks of their owners;
Chiavora is not affiliated with them.

## License

Copyright (C) 2026 MarkusNuo

- **Code:** [GNU Affero General Public License v3.0 only](LICENSE)
  (`AGPL-3.0-only`). You may use, change and host it, also commercially, as
  long as you publish the complete source of your version under the same
  license, including versions offered only over a network.
- **Name and logo** are not covered by the license; your own version needs its
  own name.
- **Other terms**, e.g. a commercial license, are available from the author
  (GitHub: @MarkusNuo).
- **Third-party parts** keep their own licenses: the EFF Long Wordlist
  (CC BY 3.0 US, see [NOTICE](NOTICE)) and the dependencies in the `Cargo.toml`
  and `package.json` files.
