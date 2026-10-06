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

# Deleted first, so a run cut short by whatever reads its output can never leave a pass behind.
$verdictPath = Join-Path $repo 'target/gate-verdict.txt'
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $verdictPath) | Out-Null
Remove-Item -Force -ErrorAction SilentlyContinue $verdictPath

$script:verdictLines = @()
function Write-Verdict([string] $line) {
    $script:verdictLines += $line
    Set-Content -Path $verdictPath -Value $script:verdictLines -Encoding utf8
}

function Complete-Step([string] $marker, [int] $code) {
    if ($code -ne 0) {
        $failed = $marker -replace '_OK$', ' FAILED'
        Write-Host $failed -ForegroundColor Red
        Write-Verdict $failed
        Write-Verdict 'EXIT 1'
        Pop-Location
        exit 1
    }
    Write-Host $marker -ForegroundColor Green
    Write-Verdict $marker
}

Push-Location $repo
try {
    if ($Cargo) {
        $passthrough = $Cargo -split '\s+'
        & cargo @passthrough
        exit $LASTEXITCODE
    }

    $sha = (& git -C $repo rev-parse HEAD 2>$null)
    $dirty = [bool] (& git -C $repo status --porcelain 2>$null)
    Write-Verdict "commit  $sha"
    Write-Verdict "dirty   $dirty"
    Write-Verdict "started $([DateTimeOffset]::UtcNow.ToString('o'))"

    cargo fmt --all -- --check
    Complete-Step 'FMT_OK' $LASTEXITCODE

    cargo clippy --workspace --all-targets -- -D warnings
    Complete-Step 'CLIPPY_OK' $LASTEXITCODE

    cargo test --workspace
    Complete-Step 'TEST_OK' $LASTEXITCODE

    # Without test targets: the tests turn on core's `harness` feature for every
    # crate, so only this step catches `store::Unanchored` in production code.
    cargo check --workspace
    Complete-Step 'RELEASE_SHAPE_OK' $LASTEXITCODE

    # The harness feature is off by default, so nothing above compiles it.
    cargo clippy -p chiavora-ffi-mobile --all-targets --features measurement-harness -- -D warnings
    Complete-Step 'HARNESS_CLIPPY_OK' $LASTEXITCODE
    cargo test -p chiavora-ffi-mobile --features measurement-harness
    Complete-Step 'HARNESS_OK' $LASTEXITCODE

    cargo deny check
    Complete-Step 'DENY_OK' $LASTEXITCODE

    & (Join-Path $PSScriptRoot 'mobile-compile.ps1')
    # Exit 2 means no Android SDK: recorded as skipped, not as a pass.
    if ($LASTEXITCODE -eq 2) {
        Write-Host 'MOBILE_COMPILE_SKIPPED' -ForegroundColor Yellow
        Write-Verdict 'MOBILE_COMPILE_SKIPPED'
    }
    else {
        Complete-Step 'MOBILE_COMPILE_OK' $LASTEXITCODE
    }

    Write-Verdict 'EXIT 0'
    Write-Host ''
    Write-Host "verdict written to $verdictPath" -ForegroundColor Green

    # Set explicitly: the skip path leaves 2 in `$LASTEXITCODE`. `finally` still runs.
    exit 0

    if (-not $SkipFuzz) {
        Write-Host ''
        Write-Host 'R7: a change that touched a parser also needs a local fuzz run, reported' -ForegroundColor Yellow
        Write-Host 'with its coverage figure and corpus size. See scripts/fuzz.ps1.' -ForegroundColor Yellow
    }
}
finally {
    Pop-Location
}
