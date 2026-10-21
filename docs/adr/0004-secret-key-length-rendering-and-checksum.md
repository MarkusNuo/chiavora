# ADR-0004 — Secret Key length, rendering and checksum

Status: Accepted · 2026-09-10

## Context

The security design states a 128-bit Secret Key, but its illustration,
`CHV1-XXXXXX-XXXXXX-XXXXX-XXXXX-XXXXX-XXXXX`, held 32 base32 characters, which
carry 160 bits. Typing the key in also needs a checksum. The bit length is the
security parameter, so the rendering gives.

## Decision

- Key: 128 bits, 16 bytes from the platform CSPRNG.
- Alphabet: Crockford base32, `0123456789ABCDEFGHJKMNPQRSTVWXYZ`, no padding,
  uppercase on output. `I`, `L`, `O` and `U` are excluded.
- 26 key characters. The 26th carries 3 key bits and 2 padding bits, which must
  be zero; a non-canonical last character is refused on decode.
- Checksum: 2 characters, the low 10 bits of SHA-256 over the 16 key bytes,
  big-endian, `((d[30] & 0x03) << 8) | d[31]`, rendered high five bits first.
- Format: `CHV1-` + 28 characters, displayed as 7 hyphen-separated groups of 4.
- Decoding accepts lowercase, ignores hyphens and whitespace, and maps `O`→`0`,
  `I`→`1` and `L`→`1` before the prefix is matched, so `CHVI` reads as `CHV1`.
  `U` maps to nothing and is refused.

The key `000102…0f` renders as `CHV1-000G-40R4-0M30-E209-185G-R38E-1WCH`. The
vectors in `crates/core/tests/vectors/secret_key_format.json` come from an
independent Python implementation.

## Consequences

- The grouping is display-only and can change without breaking printed Kits.
  The alphabet and the checksum cannot.
- The checksum is a typo aid, not integrity: it has no key and catches about
  1023 in 1024 errors. It is the only defence against `S`/`5`, `Z`/`2`, `B`/`8`.
- A wrong Secret Key is caught by the derivation: a failed SRP authentication
  with sync, an AEAD failure on the first unwrap offline, shown as "wrong
  password or Secret Key".
- The Kit leaves the process only through `secret_key::render`, which returns
  `EmergencyKitLine`, with no `Deref` and one accessor, `expose_for_printing`.
- The generator, the manual-entry validator (`entry::SecretKeyField`) and the
  Kit's QR path share one format, one implementation and the vectors.

## Alternatives considered

- A 32-bit checksum in 32 characters: fits the illustration, not the requirement.
- A 160-bit key: contradicts the stated 128 bits and leaves no room for a checksum.
- RFC 4648 base32: `O`, `I` and `L` are valid there, so the normalisation
  contradicts it.
