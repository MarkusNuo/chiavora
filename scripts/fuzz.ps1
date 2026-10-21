<#
.SYNOPSIS
    Runs the fuzz targets locally and reports executions, coverage and corpus
    size, since an execution count alone says little (`docs/crypto.md` R7).
#>
[CmdletBinding()]
param(
    [int] $Seconds = 45,
    [string] $Target
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot

. (Join-Path $PSScriptRoot 'msvc-env.ps1')
Import-LinkableVcEnvironment

Push-Location $repo
try {
    $targets = if ($Target) { @($Target) } else {
        Get-ChildItem (Join-Path $repo 'fuzz\fuzz_targets') -Filter *.rs |
            ForEach-Object { $_.BaseName }
    }

    $report = @()
    foreach ($t in $targets) {
        Write-Host "fuzzing $t for ${Seconds}s..." -ForegroundColor DarkGray
        $out = cargo +nightly fuzz run $t -- "-max_total_time=$Seconds" 2>&1
        $done = $out | Select-String 'DONE\s+cov:' | Select-Object -Last 1
        if (-not $done) {
            Write-Host "$t : NO DONE LINE — the run did not finish cleanly" -ForegroundColor Red
            $out | Select-Object -Last 20
            exit 1
        }
        # "#5595141  DONE   cov: 458 ft: 1035 corp: 164/22Kb ..."
        $line = $done.ToString()
        $cov = [regex]::Match($line, 'cov:\s*(\d+)').Groups[1].Value
        $corp = [regex]::Match($line, 'corp:\s*(\d+)').Groups[1].Value
        $runs = [regex]::Match($line, '^#?(\d+)').Groups[1].Value
        $report += "{0}: {1} executions, cov {2}, corpus {3}" -f $t, $runs, $cov, $corp
    }

    Write-Host ''
    Write-Host 'Fuzz report (keep all three numbers together):' -ForegroundColor Green
    $report | ForEach-Object { Write-Host "  $_" }
}
finally {
    Pop-Location
}
