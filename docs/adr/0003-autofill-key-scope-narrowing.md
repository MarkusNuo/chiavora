# ADR-0003 — Autofill Key scope narrowing

Status: Accepted · 2026-09-07, revised 2026-09-09

## Context

The autofill providers sit inside the trust boundary: they hold the MUK behind a
biometric prompt, so iOS's extension memory cap never has to fit Argon2. A
provider holding the MUK can unwrap every Item Key in the vault while it parses
hostile input. Narrowing that changes the record format, so it is decided with
the core, before the vault holds real passwords.

## Decision

Item Keys of `login` and `TOTP` items are double-wrapped: once under the Vault
Key, the path the app, the desktop client and the CLI use, and once under a
dedicated Autofill Key, the only path the provider has. The provider is
provisioned with the Autofill Key alone. `note`, `card`, `identity` and
`SSH key` items have no Autofill-Key copy and are unreachable from the provider.
A TOTP secret stored as a field on a login is covered already, because the whole
payload sits under one Item Key.

## Consequences

- A compromised provider reaches credentials and their second factors, not the
  whole vault.
- For the accounts it can fill it holds both the password and the TOTP secret,
  so 2FA is no longer an independent factor against provider compromise.
- Per-request acquisition limits that to a fill behind a live biometric prompt.
  It bounds the window, not the reach: a live compromise still gets both.
- I7 (both wraps yield the same Item Key) is checked only by clients holding
  both keys; the provider's `unwrap_for_provider` cannot check it.
- Item type is security-relevant: promoting a note to a login makes it
  provider-readable.
- Decided since: the Autofill Key is a random key per vault, wrapped under the
  Vault Key (`docs/security-design.md` §2.2); ADR-0006 fixes the second wrap's
  encoding. Its rotation is not decided here.

## Alternatives considered

- Login only: keeps 2FA independent, but breaks autofill for standalone TOTP items.
- Fold TOTP into the login type: removes one of six item types and forces a
  remapping in all four importers.
- Per-type keys for all six types: nothing calls for it, and it multiplies
  rotation by six.
- A third key for TOTP alone: the provider holds both keys at fill time anyway.
