# ADR-0007 — OPAQUE versus SRP-6a

Status: Accepted · 2026-09-14

## Context

The security design required OPAQUE (RFC 9807) to be evaluated against SRP-6a
(RFC 5054) before a protocol was chosen. On specification quality OPAQUE is
ahead: a current RFC, a security proof, vectors for its shipping configuration,
and normative fake records for unknown users. SRP-6a's only published vectors
are one set, 1024-bit with SHA-1.

## Decision

SRP-6a over RFC 5054's 4096-bit group, with the externally derived `x` recorded
in ADR-0008. Chiavora unlocks with no server: `rootKey` is a local computation,
and the Android app works fully offline. OPAQUE's key material comes out of an
OPRF whose key the server holds, so it could only sit beside 2SKD. Feeding it a
derived value instead of the password puts the system outside the proof that is
the reason to choose OPAQUE; against SRP the same deviation is bounded.

## 3. What OPAQUE would have bought

Three costs: pre-computation resistance, a normative answer to enumeration, and
cheap exponentiation. SRP-6a over the 4096-bit group does full-width
constant-time exponentiation on the phone, so that cost is measured and
recorded in `docs/crypto.md`.

### 3.1 Pre-computation resistance

SRP hands its salt to anyone who asks, so an attacker can precompute `x` and
`v = g^x` over a dictionary before any breach. Against Chiavora that does not
start: `x` descends from `rootKey`, which needs the 128-bit Secret Key. A dumped
device keystore holds the Secret Key, but that attacker is inside the device
(A4/A8); against a remote copy of the server's data (A3) it is intact.

### 3.2 A normative, vectorised answer to account enumeration

RFC 9807 §6.3.2.2 requires fake records and ships fake vectors. RFC 5054
§2.5.1.3 describes the technique as a `MAY`, in prose, with no vectors. ADR-0008
§6 takes its fake-verifier option, and that path needs vectors of our own.

## Consequences

- The ground rules and the security design already name SRP-6a; they need no
  change.
- ADR-0008 records the deviation, the SRP salt, the login identifier and the
  unknown-identifier path.
- Reopen this on an offline-capable OPAQUE composition, on vault keys becoming
  sync-only, on a published SRP-6a break, or on an audited SRP-6a in Rust.

## Alternatives considered

- OPAQUE beside 2SKD with its own password path: the password is stretched
  twice, and login pays Argon2id again on the slowest devices.
- OPAQUE fed a derived value: buys the deviation and none of the protocol.
