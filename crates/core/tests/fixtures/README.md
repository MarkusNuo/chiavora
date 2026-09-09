# Hostile fixtures

Each file under `hostile/` is an input the core must refuse. Its `attacks` field names the
invariant it attacks, `why` says what the attack achieves if that invariant fails, `expect` is
the expected outcome, and `kind` tells the loader how to build it (`item-payload`,
`wrapped-key`, `aad-bytes`, `kdf-params`, `manifest-read`).

`hostile_fixture_corpus.rs` loads every file in the directory, so a new fixture needs no index
entry.
