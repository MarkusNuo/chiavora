<#
    Needs NDK r27d, `cargo-ndk`, Android SDK 36, a JDK 17+ and Gradle.
#>
[CmdletBinding()]
param(
    [switch]$Install
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

. "$PSScriptRoot/msvc-env.ps1"
Import-LinkableVcEnvironment

$app = 'apps/android-harness'
$abi = 'arm64-v8a'
$target = 'aarch64-linux-android'
$lib = 'libchiavora_ffi_mobile.so'

if (-not $env:ANDROID_HOME) { $env:ANDROID_HOME = "$env:LOCALAPPDATA\Android\Sdk" }
if (-not $env:ANDROID_NDK_HOME) { $env:ANDROID_NDK_HOME = "$env:ANDROID_HOME\ndk\27.3.13750724" }
$gradle = if ($env:GRADLE_BIN) { $env:GRADLE_BIN } else { "$env:LOCALAPPDATA\Gradle\gradle-9.7.1\bin\gradle.bat" }

foreach ($needed in @($env:ANDROID_HOME, $env:ANDROID_NDK_HOME, $gradle)) {
    if (-not (Test-Path $needed)) {
        Write-Host "MISSING: $needed" -ForegroundColor Red
        exit 1
    }
}

Write-Host '==> 1/3  cross-compiling the cdylib' -ForegroundColor Cyan
# `-P 26` is the app's minSdk, so the library cannot link anything newer.
cargo ndk -t $abi -P 26 build --release --package chiavora-ffi-mobile --features measurement-harness
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host '==> 2/3  generating Kotlin bindings from the built library' -ForegroundColor Cyan
$generated = "$app/app/src/main/generated"
if (Test-Path $generated) { Remove-Item -Recurse -Force $generated }
cargo run -q --package chiavora-ffi-mobile --bin uniffi-bindgen -- `
    generate --library "target/$target/release/$lib" --language kotlin --out-dir $generated
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host '==> 3/3  assembling the APK' -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path "$app/app/src/main/jniLibs/$abi" | Out-Null
Copy-Item "target/$target/release/$lib" "$app/app/src/main/jniLibs/$abi/$lib" -Force

# Written explicitly: a missing SDK path fails deep inside AGP with an unrelated error.
"sdk.dir=$($env:ANDROID_HOME -replace '\\', '\\')" | Set-Content -Path "$app/local.properties" -Encoding utf8

# Gradle fails with "Unable to establish loopback connection" under a long Windows temp path.
$gradleTmp = 'C:/Temp/chiavora-gradle'
New-Item -ItemType Directory -Force -Path $gradleTmp | Out-Null
$env:GRADLE_OPTS = "-Djava.io.tmpdir=$gradleTmp"
$env:TMP = $gradleTmp
$env:TEMP = $gradleTmp

Push-Location $app
try {
    & $gradle --no-daemon assembleRelease
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
} finally {
    Pop-Location
}

$apk = "$app/app/build/outputs/apk/release/app-release.apk"
Write-Host ''
Write-Host "APK: $apk  ($([math]::Round((Get-Item $apk).Length / 1MB, 1)) MB)" -ForegroundColor Green

if ($Install) {
    Write-Host '==> installing' -ForegroundColor Cyan
    adb install -r $apk
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
