# ADR-0006 — The wrapped-Item-Key record format

Status: Accepted · 2026-09-09

## Context

The security design defined four AAD record types (`0x01` item payload, `0x02`
attachment chunk, `0x03` manifest root, `0x04` manifest segment). It placed the
wrapped Item Key outside the AAD-bound payload, as a sibling field excluded from
`ciphertextDigest`, and gave the wrap no format of its own. ADR-0003's double
wrap needs one.

## Decision

A wrapped Item Key is AAD record type `0x05`, produced by the one canonical
encoder in `crates/core/src/aad.rs`:

```text
recordType 0x05 — wrapped Item Key
  AAD = "CHV1" || u8(0x05)
                || u32le(len(vaultId)) || vaultId
                || u32le(len(itemId))  || itemId
                || u8(wrapPurpose)

wrapPurpose = 0x01  wrapped under the Vault Key
              0x02  wrapped under the Autofill Key (login and TOTP only)
```

An undefined `wrapPurpose` is refused on encode and on decode.

## Consequences

- I3's bijection proof and the collision hunt cover `0x05` with the other
  record types. There is no second encoding to prove.
- This is defence in depth, not a closed gap. A transplanted wrap already fails
  at the payload AAD, a swapped slot at the AEAD; `0x05` makes both fail at the
  wrap with an error that names it, which the hostile-server suite relies on.
- Downstream checks stay; the wrap binding does not replace them.
- `docs/crypto.md` carries `0x05` vectors, the encoder's fuzz target covers it,
  and `wrap.rs` holds no encoding of its own.

## Alternatives considered

- A separate format: a second canonical encoding with its own injectivity
  proof, vectors and canonicalisation rules, and the likely home of the next
  canonicalisation bug.
