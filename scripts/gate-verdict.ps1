<#
.SYNOPSIS
    Reads the gate's verdict file and prints PASS or FAIL; exits 0 only on PASS.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$verdictPath = Join-Path $repo 'target/gate-verdict.txt'

# Listed here as well as in `gate.ps1`, so a step dropped from the gate fails here.
$required = @(
    'FMT_OK', 'CLIPPY_OK', 'TEST_OK', 'RELEASE_SHAPE_OK',
    'HARNESS_CLIPPY_OK', 'HARNESS_OK', 'DENY_OK', 'MOBILE_COMPILE_OK'
)

function Fail([string] $why) {
    Write-Host 'GATE VERDICT: FAIL' -ForegroundColor Red
    Write-Host "  $why" -ForegroundColor Red
    exit 1
}

if (-not (Test-Path $verdictPath)) {
    Fail "no verdict file at $verdictPath — the gate has not run on this tree"
}

$lines = @(Get-Content -Path $verdictPath)
$head = (& git -C $repo rev-parse HEAD 2>$null)

$commitLine = $lines | Where-Object { $_ -like 'commit *' } | Select-Object -First 1
$verdictSha = if ($commitLine) { ($commitLine -split '\s+', 2)[1].Trim() } else { '' }
if ($verdictSha -ne $head) {
    Fail "verdict is for commit $verdictSha but HEAD is $head — re-run the gate"
}

if ($lines | Where-Object { $_ -eq 'dirty   True' }) {
    Fail 'the gate ran against a dirty tree; commit first, then re-run'
}

foreach ($marker in $required) {
    if (-not ($lines -contains $marker)) {
        Fail "the verdict has no $marker — the run did not finish"
    }
}

if (-not ($lines -contains 'EXIT 0')) {
    Fail 'the verdict does not end EXIT 0'
}

Write-Host 'GATE VERDICT: PASS' -ForegroundColor Green
Write-Host "  commit $head, all $($required.Count) markers, EXIT 0"
exit 0
