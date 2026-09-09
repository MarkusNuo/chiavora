#!/usr/bin/env bash
set -euo pipefail

KOTLIN_VERSION="2.0.21"
JNA_VERSION="5.14.0"
COROUTINES_VERSION="1.8.1"
EXPECTED="chiavora-ffi-mobile:ok"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
cache="target/ffi-smoke"
mkdir -p "$cache"

case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) libname="chiavora_ffi_mobile.dll"; sep=";" ;;
  Darwin)               libname="libchiavora_ffi_mobile.dylib"; sep=":" ;;
  *)                    libname="libchiavora_ffi_mobile.so"; sep=":" ;;
esac

echo "==> building the cdylib"
cargo build -p chiavora-ffi-mobile

echo "==> generating Kotlin bindings"
rm -rf "$cache/kotlin"
cargo run -q -p chiavora-ffi-mobile --bin uniffi-bindgen -- \
  generate --library "target/debug/$libname" --language kotlin --out-dir "$cache/kotlin"

fetch() {
  [ -f "$2" ] || curl -fsSL --retry 3 -o "$2" "$1"
}

echo "==> fetching the Kotlin compiler and runtime jars"
if [ ! -x "$cache/kotlinc/bin/kotlinc" ]; then
  fetch "https://github.com/JetBrains/kotlin/releases/download/v${KOTLIN_VERSION}/kotlin-compiler-${KOTLIN_VERSION}.zip" "$cache/kotlinc.zip"
  ( cd "$cache" && rm -rf kotlinc && unzip -q kotlinc.zip && mv kotlinc kotlinc.tmp && mv kotlinc.tmp kotlinc )
fi
fetch "https://repo1.maven.org/maven2/net/java/dev/jna/jna/${JNA_VERSION}/jna-${JNA_VERSION}.jar" "$cache/jna.jar"
fetch "https://repo1.maven.org/maven2/org/jetbrains/kotlinx/kotlinx-coroutines-core-jvm/${COROUTINES_VERSION}/kotlinx-coroutines-core-jvm-${COROUTINES_VERSION}.jar" "$cache/coroutines.jar"

cat > "$cache/Smoke.kt" <<'KT'
import uniffi.chiavora_ffi_mobile.ffiSmoke

fun main() {
    val expected = "chiavora-ffi-mobile:ok"
    val actual = ffiSmoke()
    if (actual != expected) {
        System.err.println("FFI smoke test FAILED: expected '$expected', got '$actual'")
        kotlin.system.exitProcess(1)
    }
    println("Kotlin -> Rust FFI smoke test ok: $actual")
}
KT

echo "==> compiling Kotlin"
cp "target/debug/$libname" "$cache/"
classpath="$cache/jna.jar${sep}$cache/coroutines.jar"
"$cache/kotlinc/bin/kotlinc" \
  "$cache/kotlin/uniffi/chiavora_ffi_mobile/chiavora_ffi_mobile.kt" \
  "$cache/Smoke.kt" \
  -classpath "$classpath" \
  -include-runtime -d "$cache/smoke.jar" 2>&1 | grep -v '^warning:' || true

echo "==> running Kotlin"
java -cp "$cache/smoke.jar${sep}${classpath}" -Djna.library.path="$cache" SmokeKt
