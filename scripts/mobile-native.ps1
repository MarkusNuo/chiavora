<#
.SYNOPSIS
    Builds the Rust core into `apps/mobile`'s local Expo module. Only the debug
    build has `measurement-harness`, so a release library has no harness at all.
#>
[CmdletBinding()]
param(
    [ValidateSet('debug', 'release')]
    [string] $Variant = 'debug',
    [switch] $SkipPrebuild
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

# Build scripts are compiled for the host, which needs a linkable MSVC toolchain.
. "$PSScriptRoot/msvc-env.ps1"
Import-LinkableVcEnvironment

$abi = 'arm64-v8a'
$target = 'aarch64-linux-android'
$lib = 'libchiavora_ffi_mobile.so'
$module = 'apps/mobile/modules/chiavora-core/android'

if (-not $env:ANDROID_HOME) { $env:ANDROID_HOME = "$env:LOCALAPPDATA\Android\Sdk" }
if (-not $env:ANDROID_NDK_HOME) { $env:ANDROID_NDK_HOME = "$env:ANDROID_HOME\ndk\27.3.13750724" }

$features = if ($Variant -eq 'debug') { @('--features', 'measurement-harness') } else { @() }

# A pinned toolchain does not inherit `stable`'s targets, so add Android here.
$toolchain = (rustup show active-toolchain) -split ' ' | Select-Object -First 1
if ((rustup target list --installed --toolchain $toolchain) -notcontains $target) {
    Write-Host "==> 0/3  adding $target to $toolchain" -ForegroundColor Cyan
    rustup target add $target --toolchain $toolchain
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

Write-Host "==> 1/3  cross-compiling the cdylib for $abi ($Variant)" -ForegroundColor Cyan
# `-P 26` is the module's minSdk. `--release` in both variants: the variant only
# selects features, and a debug-optimised Argon2id would measure the wrong thing.
cargo ndk -t $abi -P 26 build --release --package chiavora-ffi-mobile @features
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$jniLibs = "$module/src/$Variant/jniLibs/$abi"
New-Item -ItemType Directory -Force -Path $jniLibs | Out-Null
Copy-Item "target/$target/release/$lib" "$jniLibs/$lib" -Force

Write-Host '==> 2/3  generating Kotlin bindings' -ForegroundColor Cyan
# From the library just built, so release bindings have no harness function.
$generated = "$module/src/$Variant/generated"
if (Test-Path $generated) { Remove-Item -Recurse -Force $generated }
cargo run -q --package chiavora-ffi-mobile --bin uniffi-bindgen -- `
    generate --library "target/$target/release/$lib" --language kotlin --out-dir $generated
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

if ($SkipPrebuild) {
    Write-Host '==> 3/3  skipped (--SkipPrebuild)' -ForegroundColor DarkGray
} else {
    Write-Host '==> 3/3  expo prebuild' -ForegroundColor Cyan
    # Gradle fails with "Unable to establish loopback connection" under a long Windows temp path.
    $gradleTmp = 'C:/Temp/chiavora-gradle'
    New-Item -ItemType Directory -Force -Path $gradleTmp | Out-Null
    $env:GRADLE_OPTS = "-Djava.io.tmpdir=$gradleTmp"
    $env:TMP = $gradleTmp
    $env:TEMP = $gradleTmp

    Push-Location 'apps/mobile'
    try {
        pnpm exec expo prebuild --platform android --clean
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    } finally {
        Pop-Location
    }

    # The generated project ignores `ANDROID_HOME` and `--clean` deletes this file.
    # Forward slashes, because a backslash is an escape in a properties file.
    "sdk.dir=$($env:ANDROID_HOME -replace '\\', '/')" |
        Set-Content -Path 'apps/mobile/android/local.properties' -Encoding utf8
}

Write-Host ''
Write-Host "native module ready ($Variant): $jniLibs/$lib" -ForegroundColor Green
