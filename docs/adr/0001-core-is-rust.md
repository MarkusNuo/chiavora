# ADR-0001 — Core is Rust

Status: Accepted · 2026-09-07

## Context

The security design fixes the architecture as a polyglot monorepo: one Rust
core, three thin platform shells above it. N1 requires that key material never
leaves the core. I1(a) requires key material to be a distinct type that cannot
cross the FFI boundary, the serializer, the logger or the crash reporter.

## Decision

`crates/core` is Rust. Every platform shell reaches it through a binding,
`uniffi` for Swift and Kotlin and `napi-rs` for Node, and holds capabilities,
never keys.

## Consequences

- The type system can express I1(a) as a compile-time guarantee.
- Key material lives in `Zeroizing`, mlocked buffers.
- There are two binding toolchains. Both are proven to build before any
  cryptography depends on them.

## Alternatives considered

- A TypeScript core. The security design gives three reasons against it: one
  implementation on every platform, constant-time modular exponentiation for
  SRP, and structured fuzzing.
