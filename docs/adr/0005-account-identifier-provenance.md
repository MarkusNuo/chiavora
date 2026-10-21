# ADR-0005 — Account-identifier provenance for offline-first signup

Status: Accepted · 2026-09-09

## Context

The security design said `accountId` is server-assigned at signup. The Android
app is a fully offline client: signup happens on the phone, and there is no
server to assign anything. What key derivation needs is immutability, not
provenance: a changing identifier would rotate the salt, the root key and every
wrapped key on the account.

## Decision

- `accountId` is 128 bits, generated on the device at signup from the platform
  CSPRNG through the single helper (I2), and immutable thereafter.
- `accountSalt` is 256 bits, generated the same way and immutable. It is HKDF
  input keying material, not an identifier, and is not derived from `accountId`.
- Both are sent to the server at enrollment and stored as-is. The server never
  assigns or reassigns either; a server that returns a different `accountId` is
  hostile and the client refuses it.
- They enter the salt derivation as two independent values:

```text
salt = HKDF-SHA256(ikm = accountSalt, info = "chiavora-salt|" || accountId, len = 16)
```

`srpSalt` is a third independent value (ADR-0008) and must not reuse `accountSalt`.

## Consequences

- Offline signup needs no placeholder and no re-derivation on first sync.
- "No mutable identifier is ever an input to key derivation" still holds.
- Uniqueness rests on 128 bits of entropy, not on the server. A duplicate
  `accountId` at enrollment should be rejected, never adopted or merged; that
  server behaviour is not specified here.
- Neither value is secret: `accountId` is server-visible metadata, and
  `accountSalt` is served unauthenticated before login with the Argon2 parameters.
- Only entropy and immutability are fixed here; the wire and store encodings
  are a format question.

## Alternatives considered

- A local placeholder, rotated at first registration: a mandatory rotation that
  re-derives every key of every account created offline.
- Gating signup on the sync server: contradicts the offline Android client.
