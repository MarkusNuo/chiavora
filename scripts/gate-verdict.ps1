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
    'HARNESS_CLIPPY_OK', 'HARNESS_OK', 'DENY_OK'
)

$mobileMarkers = @('MOBILE_COMPILE_OK', 'MOBILE_COMPILE_SKIPPED')

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

# Only as fresh as the last fetch: this script does no network I/O.
$originMain = (& git rev-parse --verify --quiet 'refs/remotes/origin/main')
if ($LASTEXITCODE -eq 0 -and $originMain) {
    & git merge-base --is-ancestor 'refs/remotes/origin/main' HEAD
    if ($LASTEXITCODE -ne 0) {
        $behind = (& git rev-list --count 'HEAD..refs/remotes/origin/main').Trim()
        Fail ("HEAD is behind origin/main by $behind commit(s) as of the last " +
            'fetch, so this verdict is for a tree that is not what would merge. ' +
            'git fetch, rebase, re-run the gate')
    }
}
else {
    # Not a failure: a clone that never fetched has nothing to be behind.
    Write-Host '  (no origin/main known locally — behind not checked)' -ForegroundColor DarkGray
}

foreach ($marker in $required) {
    if (-not ($lines -contains $marker)) {
        Fail "the verdict has no $marker — the run did not finish"
    }
}

$mobileSeen = @($mobileMarkers | Where-Object { $lines -contains $_ })
if ($mobileSeen.Count -ne 1) {
    Fail ("the verdict has neither MOBILE_COMPILE_OK nor MOBILE_COMPILE_SKIPPED " +
        "($($mobileSeen.Count) found) — the run did not finish")
}

if (-not ($lines -contains 'EXIT 0')) {
    Fail 'the verdict does not end EXIT 0'
}

Write-Host 'GATE VERDICT: PASS' -ForegroundColor Green
Write-Host "  commit $head, all $($required.Count + 1) markers, EXIT 0"
if ($mobileSeen[0] -eq 'MOBILE_COMPILE_SKIPPED') {
    Write-Host '  NOTE: the Android app was NOT compiled (no SDK on this machine).' -ForegroundColor Yellow
}
exit 0
