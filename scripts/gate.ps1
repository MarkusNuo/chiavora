<#
.SYNOPSIS
    Runs the local gate, the checks that must pass before merging. The verdict
    goes to `target/gate-verdict.txt`; read it with `scripts/gate-verdict.ps1`.
#>
[CmdletBinding()]
param(
    [string] $Cargo,
    [switch] $SkipFuzz
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot

. (Join-Path $PSScriptRoot 'msvc-env.ps1')
Import-LinkableVcEnvironment

Push-Location $repo
try {
    if ($Cargo) {
        $passthrough = $Cargo -split '\s+'
        & cargo @passthrough
        exit $LASTEXITCODE
    }

    cargo fmt --all -- --check
    if ($LASTEXITCODE -ne 0) { Write-Host 'FMT FAILED' -ForegroundColor Red; exit 1 }
    Write-Host 'FMT_OK' -ForegroundColor Green

    cargo clippy --workspace --all-targets -- -D warnings
    if ($LASTEXITCODE -ne 0) { Write-Host 'CLIPPY FAILED' -ForegroundColor Red; exit 1 }
    Write-Host 'CLIPPY_OK' -ForegroundColor Green

    cargo test --workspace
    if ($LASTEXITCODE -ne 0) { Write-Host 'TEST FAILED' -ForegroundColor Red; exit 1 }
    Write-Host 'TEST_OK' -ForegroundColor Green

    # The harness feature is off by default, so nothing above compiles it.
    cargo clippy -p chiavora-ffi-mobile --all-targets --features measurement-harness -- -D warnings
    if ($LASTEXITCODE -ne 0) { Write-Host 'HARNESS CLIPPY FAILED' -ForegroundColor Red; exit 1 }
    cargo test -p chiavora-ffi-mobile --features measurement-harness
    if ($LASTEXITCODE -ne 0) { Write-Host 'HARNESS TEST FAILED' -ForegroundColor Red; exit 1 }
    Write-Host 'HARNESS_OK' -ForegroundColor Green

    cargo deny check
    if ($LASTEXITCODE -ne 0) { Write-Host 'DENY FAILED' -ForegroundColor Red; exit 1 }
    Write-Host 'DENY_OK' -ForegroundColor Green

    if (-not $SkipFuzz) {
        Write-Host ''
        Write-Host 'R7: a change that touched a parser also needs a local fuzz run, reported' -ForegroundColor Yellow
        Write-Host 'with its coverage figure and corpus size. See scripts/fuzz.ps1.' -ForegroundColor Yellow
    }
}
finally {
    Pop-Location
}
