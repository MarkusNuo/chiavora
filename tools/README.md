# `tools/`

Generators whose output is committed and which are run by hand, rarely.
Operational scripts (the gate, fuzzing, device and FFI checks) live in `scripts/`.

- [`srp_reference.py`](srp_reference.py) writes the SRP test vectors in
  `crates/core/tests/vectors/` (`srp_groups.json`, `rfc5054_appendix_b.json`
  and the `x`-derivation vectors). It is independent of `crates/core`, and it
  checks the values it extracts from RFC 5054 against the RFC's published ones.

Every file a tool writes names its source in the file itself.
