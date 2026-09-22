<#
.SYNOPSIS
    Compiles the Android module's Kotlin, which no `cargo` step of the gate does.
    Only the debug variant is compiled; `src/release` is not.
#>
[CmdletBinding()]
param(
    [switch] $Full
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot

if (-not $env:ANDROID_HOME) { $env:ANDROID_HOME = "$env:LOCALAPPDATA\Android\Sdk" }

$generated = Join-Path $repo 'apps/mobile/android/gradlew.bat'
$reasons = @()
if (-not (Test-Path $env:ANDROID_HOME)) {
    $reasons += "no Android SDK at $env:ANDROID_HOME"
}
if (-not (Test-Path $generated)) {
    $reasons += 'apps/mobile/android is not generated (run scripts/mobile-native.ps1)'
}

if ($reasons.Count -gt 0) {
    Write-Host 'MOBILE_COMPILE SKIPPED' -ForegroundColor Yellow
    foreach ($reason in $reasons) {
        Write-Host "  $reason" -ForegroundColor Yellow
    }
    Write-Host '  The app was NOT compiled. This is the check that catches a' -ForegroundColor Yellow
    Write-Host '  ChiavoraCoreModule.kt that does not build -- see the header.' -ForegroundColor Yellow
    # 2, not 1: a skip is not a failure, but `gate.ps1` must not record a pass.
    exit 2
}

# Gradle fails with "Unable to establish loopback connection" under a long Windows temp path.
$gradleTmp = 'C:/Temp/chiavora-gradle'
New-Item -ItemType Directory -Force -Path $gradleTmp | Out-Null
$env:GRADLE_OPTS = "-Djava.io.tmpdir=$gradleTmp"
$env:TMP = $gradleTmp
$env:TEMP = $gradleTmp

$task = if ($Full) { ':app:assembleDebug' } else { ':chiavora-core:compileDebugKotlin' }

Push-Location (Join-Path $repo 'apps/mobile/android')
try {
    & ./gradlew $task --console=plain
    if ($LASTEXITCODE -ne 0) {
        Write-Host 'MOBILE_COMPILE FAILED' -ForegroundColor Red
        exit 1
    }
}
finally {
    Pop-Location
}

Write-Host 'MOBILE_COMPILE_OK' -ForegroundColor Green
