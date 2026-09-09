#!/usr/bin/env bash
set -euo pipefail

EXPECTED="chiavora-ffi-mobile:ok"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

if [ "$(uname -s)" != "Darwin" ]; then
  echo "ffi-smoke-swift.sh requires macOS (swiftc); got $(uname -s)" >&2
  exit 1
fi

cache="target/ffi-smoke-swift"
rm -rf "$cache"
mkdir -p "$cache"

echo "==> building the cdylib"
cargo build -p chiavora-ffi-mobile

echo "==> generating Swift bindings"
cargo run -q -p chiavora-ffi-mobile --bin uniffi-bindgen -- \
  generate --library target/debug/libchiavora_ffi_mobile.dylib \
  --language swift --out-dir "$cache/gen"

# swiftc expects the module map at a fixed name inside the include path.
mv "$cache/gen/chiavora_ffi_mobileFFI.modulemap" "$cache/gen/module.modulemap"

# swiftc permits top-level statements only in a file named main.swift.
cat > "$cache/main.swift" <<'SW'
import Foundation

let expected = "chiavora-ffi-mobile:ok"
let actual = ffiSmoke()
if actual != expected {
    FileHandle.standardError.write(
        "FFI smoke test FAILED: expected '\(expected)', got '\(actual)'\n".data(using: .utf8)!)
    exit(1)
}
print("Swift -> Rust FFI smoke test ok: \(actual)")
SW

echo "==> compiling Swift"
swiftc \
  -I "$cache/gen" \
  -L target/debug \
  -lchiavora_ffi_mobile \
  -Xcc -fmodule-map-file="$cache/gen/module.modulemap" \
  "$cache/gen/chiavora_ffi_mobile.swift" \
  "$cache/main.swift" \
  -o "$cache/smoke"

echo "==> running Swift"
DYLD_LIBRARY_PATH="target/debug:${DYLD_LIBRARY_PATH:-}" "$cache/smoke"
