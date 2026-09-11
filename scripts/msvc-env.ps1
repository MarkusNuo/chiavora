<#
    `rustc` picks the newest Visual Studio, which may lack the desktop libraries, so
    the first installation with `lib\x64\msvcrt.lib` and `vcvarsall.bat` wins.
#>

function Find-LinkableToolchain {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path $vswhere)) { return $null }

    foreach ($install in & $vswhere -products * -format value -property installationPath) {
        $vcvars = Join-Path $install 'VC\Auxiliary\Build\vcvars64.bat'
        $vcvarsall = Join-Path $install 'VC\Auxiliary\Build\vcvarsall.bat'
        if (-not (Test-Path $vcvars) -or -not (Test-Path $vcvarsall)) { continue }

        $toolsets = Join-Path $install 'VC\Tools\MSVC'
        if (-not (Test-Path $toolsets)) { continue }
        $desktopLibs = Get-ChildItem $toolsets -Directory -ErrorAction SilentlyContinue |
            ForEach-Object { Join-Path $_.FullName 'lib\x64\msvcrt.lib' } |
            Where-Object { Test-Path $_ }
        if ($desktopLibs) { return $vcvars }
    }
    return $null
}

function Import-LinkableVcEnvironment {
    $vcvars = Find-LinkableToolchain
    if (-not $vcvars) {
        Write-Host 'GATE PRECONDITION FAILED' -ForegroundColor Red
        Write-Host @'
No Visual Studio installation on this machine can link a desktop x64 binary:
none carries VC\Tools\MSVC\<version>\lib\x64\msvcrt.lib together with a usable
vcvarsall.bat.

`cargo build` on a library will still appear to work. `cargo test` fails at link
time with LNK1181 or LNK1104 — so the gate cannot run, and the gate is
the merge condition, so nothing can be merged.

Fix: install or repair the "Desktop development with C++" workload:

  & "C:\Program Files (x86)\Microsoft Visual Studio\Installer\setup.exe" modify `
      --installPath "<your VS install>" `
      --add Microsoft.VisualStudio.Workload.NativeDesktop
'@
        exit 1
    }

    # A batch file cannot export into this process, so read back what it set.
    $before = @{}
    Get-ChildItem Env: | ForEach-Object { $before[$_.Name] = $_.Value }
    $lines = cmd /c "`"$vcvars`" >nul 2>&1 && set"
    if ($LASTEXITCODE -ne 0) { Write-Host "vcvars64 failed: $vcvars" -ForegroundColor Red; exit 1 }
    foreach ($line in $lines) {
        $name, $value = $line -split '=', 2
        if ($name -and $null -ne $value -and $before[$name] -ne $value) {
            Set-Item -Path "Env:$name" -Value $value
        }
    }
    Write-Host "MSVC: $vcvars" -ForegroundColor DarkGray
}
