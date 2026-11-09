<#
.SYNOPSIS
    Offline installer safety regression. Uses temporary fixtures only; never starts CPA.
#>
param(
    [string]$BashPath = "",
    [string]$PowerShellPath = ""
)
$ErrorActionPreference = "Stop"
$RepositoryRoot = Split-Path $PSScriptRoot -Parent
$ShellInstaller = Join-Path $RepositoryRoot "install.sh"
$PowerShellInstaller = Join-Path $RepositoryRoot "install.ps1"
if (-not $PowerShellPath) { $PowerShellPath = (Get-Process -Id $PID).Path }
if (-not $BashPath) {
    $command = Get-Command bash.exe -ErrorAction SilentlyContinue
    if ($command) { $BashPath = $command.Source }
    if (-not $BashPath) {
        $git = Get-Command git.exe -ErrorAction SilentlyContinue
        if ($git) {
            $candidate = Join-Path (Split-Path (Split-Path $git.Source -Parent) -Parent) "bin/bash.exe"
            if (Test-Path -LiteralPath $candidate) { $BashPath = $candidate }
        }
    }
}
if (-not $BashPath -or -not (Test-Path -LiteralPath $BashPath)) { throw "Git Bash is required for offline shell installer safety tests." }

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}
function Get-Snapshot([string]$Root) {
    if (-not (Test-Path -LiteralPath $Root)) { return "MISSING" }
    $entries = @(Get-ChildItem -LiteralPath $Root -Recurse -Force | Sort-Object FullName | ForEach-Object {
        $relative = $_.FullName.Substring($Root.Length)
        if ($_.PSIsContainer) { "D:$relative" }
        else { "F:$($relative):$((Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash)" }
    })
    return [string]::Join([Environment]::NewLine, $entries)
}
function Get-DatabaseSnapshot([string]$Root) {
    return [string]::Join(";", @(Get-ChildItem -LiteralPath $Root -Recurse -File | Where-Object { $_.Name -match '\.db(?:-wal|-shm|[.]lock)?$' } | Sort-Object FullName | ForEach-Object { $_.FullName + ":" + (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash }))
}
function New-Fixture([string]$Root) {
    New-Item -ItemType Directory -Path (Join-Path $Root "data"),(Join-Path $Root "custom"),(Join-Path $Root "plugins") -Force | Out-Null
    foreach ($folder in @("data", "custom")) {
        foreach ($name in @("key_usage.db", "key_usage.db-wal", "key_usage.db-shm", "key_usage.db.lock")) {
            [System.IO.File]::WriteAllText((Join-Path (Join-Path $Root $folder) $name), "$folder/$name/DO-NOT-MOVE")
        }
    }
    [System.IO.File]::WriteAllText((Join-Path $Root "config.yaml"), "plugins:`n  enabled: true`n  configs:`n    cpa-plugin-key-manager:`n      enabled: true`n      storage:`n        usage_db_file: ./custom/key_usage.db`n")
    [System.IO.File]::WriteAllText((Join-Path $Root "data/models_dev.json"), '{"pricing":"sentinel"}')
    [System.IO.File]::WriteAllText((Join-Path $Root "plugins/cpa-plugin-key-manager.dll"), "INSTALLED-BINARY-SENTINEL")
    [System.IO.File]::WriteAllText((Join-Path $Root "other-sentinel.txt"), "UNRELATED-DATA")
}
function Invoke-CheckedChild([string]$Executable, [string[]]$Arguments) {
    $old = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try { $output = @(& $Executable @Arguments 2>&1); $code = $LASTEXITCODE }
    finally { $ErrorActionPreference = $old }
    return @{ Code = $code; Output = ($output | Out-String) }
}
function Quote-Single([string]$Value) { return "'" + $Value.Replace("'", "''") + "'" }

$TestRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("km-install-reset-safety-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $TestRoot | Out-Null
$PriorPath = $env:PATH
$PriorDB = $env:CPA_KEY_MANAGER_USAGE_DB
$PriorCurl = $env:KM_INSTALL_DOWNLOAD_SENTINEL
try {
    $bin = Join-Path $TestRoot "bin"
    New-Item -ItemType Directory -Path $bin | Out-Null
    $DownloadSentinel = Join-Path $TestRoot "download-was-attempted"
    $env:KM_INSTALL_DOWNLOAD_SENTINEL = $DownloadSentinel
    $env:PATH = $bin + [System.IO.Path]::PathSeparator + $env:PATH
    # Literal shell dollar is required; no network operation is ever allowed.
    $fakeCurl = '#!/bin/sh' + "`n" + 'printf attempted > "$KM_INSTALL_DOWNLOAD_SENTINEL"' + "`nexit 91`n"
    [System.IO.File]::WriteAllText((Join-Path $bin "curl"), $fakeCurl, (New-Object System.Text.UTF8Encoding($false)))

    $tokens = $null; $errors = $null
    [System.Management.Automation.Language.Parser]::ParseFile($PowerShellInstaller, [ref]$tokens, [ref]$errors) | Out-Null
    Assert-True ($errors.Count -eq 0) "PowerShell installer syntax is invalid."
    $parse = Invoke-CheckedChild $BashPath @("-n", $ShellInstaller)
    Assert-True ($parse.Code -eq 0) ("Shell installer syntax is invalid: " + $parse.Output)

    $powershellCases = @(
        @{ Name = "reset-existing"; Existing = $true; Flags = "-ResetData" },
        @{ Name = "reset-init-existing"; Existing = $true; Flags = "-InitOnly -ResetData" },
        @{ Name = "reset-local-existing"; Existing = $true; Flags = "-Local 'missing.dll' -ResetData" },
        @{ Name = "reset-missing"; Existing = $false; Flags = "-ResetData" }
    )
    foreach ($case in $powershellCases) {
        $target = Join-Path $TestRoot ("ps-" + $case.Name)
        if ($case.Existing) { New-Fixture $target }
        $env:CPA_KEY_MANAGER_USAGE_DB = Join-Path $target "custom/key_usage.db"
        $before = Get-Snapshot $target
        $runner = Join-Path $TestRoot ($case.Name + ".ps1")
        $wrapper = '$ErrorActionPreference="Stop"' + "`n" + 'function global:Invoke-RestMethod { [System.IO.File]::WriteAllText($env:KM_INSTALL_DOWNLOAD_SENTINEL,"network"); throw "Network disabled by test" }' + "`n" + 'function global:Invoke-WebRequest { [System.IO.File]::WriteAllText($env:KM_INSTALL_DOWNLOAD_SENTINEL,"network"); throw "Network disabled by test" }' + "`n" + "try { & " + (Quote-Single $PowerShellInstaller) + " -Dir " + (Quote-Single $target) + " " + $case.Flags + "; exit 0 } catch { Write-Output `$_.Exception.Message; exit 73 }"
        [System.IO.File]::WriteAllText($runner, $wrapper, (New-Object System.Text.UTF8Encoding($false)))
        $result = Invoke-CheckedChild $PowerShellPath @("-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", $runner)
        Assert-True ($result.Code -ne 0) ("PowerShell reset unexpectedly succeeded: " + $case.Name)
        Assert-True ($result.Output -match "ResetData is disabled") ("PowerShell reset did not fail at its safety gate: " + $result.Output)
        Assert-True ((Get-Snapshot $target) -ceq $before) ("PowerShell reset changed files/directories: " + $case.Name)
        Assert-True (-not (Test-Path -LiteralPath $DownloadSentinel)) "PowerShell reset attempted a download."
        Write-Output ("PASS PowerShell " + $case.Name)
    }

    $shellCases = @(
        @{ Name = "reset-existing"; Existing = $true; Flags = @("--reset-data") },
        @{ Name = "reset-init-existing"; Existing = $true; Flags = @("--init-only", "--reset-data") },
        @{ Name = "reset-local-existing"; Existing = $true; Flags = @("--local", "missing.so", "--reset-data") },
        @{ Name = "reset-help-existing"; Existing = $true; Flags = @("--help", "--reset-data") },
        @{ Name = "reset-missing"; Existing = $false; Flags = @("--reset-data") }
    )
    foreach ($case in $shellCases) {
        $target = Join-Path $TestRoot ("sh-" + $case.Name)
        if ($case.Existing) { New-Fixture $target }
        $env:CPA_KEY_MANAGER_USAGE_DB = Join-Path $target "custom/key_usage.db"
        $before = Get-Snapshot $target
        $arguments = @($ShellInstaller, "--dir", $target.Replace("\", "/")) + $case.Flags
        $result = Invoke-CheckedChild $BashPath $arguments
        Assert-True ($result.Code -ne 0) ("Shell reset unexpectedly succeeded: " + $case.Name)
        Assert-True ($result.Output -match "reset-data is disabled") ("Shell reset did not fail at its safety gate: " + $result.Output)
        Assert-True ((Get-Snapshot $target) -ceq $before) ("Shell reset changed files/directories: " + $case.Name)
        Assert-True (-not (Test-Path -LiteralPath $DownloadSentinel)) "Shell reset attempted a download."
        Write-Output ("PASS Shell " + $case.Name)
    }

    foreach ($kind in @("ps", "sh")) {
        $target = Join-Path $TestRoot ($kind + "-normal")
        New-Fixture $target
        $env:CPA_KEY_MANAGER_USAGE_DB = Join-Path $target "custom/key_usage.db"
        $before = Get-DatabaseSnapshot $target
        if ($kind -eq "ps") {
            $result = Invoke-CheckedChild $PowerShellPath @("-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", $PowerShellInstaller, "-Dir", $target, "-InitOnly", "-SkipModelsSync")
        } else {
            $result = Invoke-CheckedChild $BashPath @($ShellInstaller, "--dir", $target.Replace("\", "/"), "--init-only", "--skip-models-sync")
        }
        Assert-True ($result.Code -eq 0) ("Normal InitOnly failed: " + $result.Output)
        Assert-True ((Get-DatabaseSnapshot $target) -ceq $before) ("Normal InitOnly changed SQLite/WAL/SHM/lock files: " + $kind)
        Assert-True (-not (Test-Path -LiteralPath $DownloadSentinel)) "Offline InitOnly attempted a download."
        Write-Output ("PASS " + $kind + " InitOnly preserves SQLite files")
    }
    # Offline local upgrade may replace the fixture plugin, but never its live DB.
    $LocalBinary = Join-Path $TestRoot "new-plugin.dll"
    [System.IO.File]::WriteAllText($LocalBinary, "NEW-OFFLINE-BINARY")
    foreach ($kind in @("ps", "sh")) {
        $target = Join-Path $TestRoot ($kind + "-local-upgrade")
        New-Fixture $target
        $env:CPA_KEY_MANAGER_USAGE_DB = Join-Path $target "custom/key_usage.db"
        $before = Get-DatabaseSnapshot $target
        if ($kind -eq "ps") {
            $result = Invoke-CheckedChild $PowerShellPath @("-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", $PowerShellInstaller, "-Dir", $target, "-Local", $LocalBinary, "-SkipModelsSync")
        } else {
            $result = Invoke-CheckedChild $BashPath @($ShellInstaller, "--dir", $target.Replace("\", "/"), "--local", $LocalBinary.Replace("\", "/"), "--skip-models-sync")
        }
        Assert-True ($result.Code -eq 0) ("Offline local upgrade failed: " + $result.Output)
        Assert-True ((Get-DatabaseSnapshot $target) -ceq $before) ("Local upgrade changed SQLite/WAL/SHM/lock files: " + $kind)
        $installed = Join-Path $target "plugins/cpa-plugin-key-manager.dll"
        Assert-True ((Get-FileHash -LiteralPath $installed -Algorithm SHA256).Hash -ceq (Get-FileHash -LiteralPath $LocalBinary -Algorithm SHA256).Hash) ("Offline local upgrade did not install fixture binary: " + $kind)
        Assert-True (-not (Test-Path -LiteralPath $DownloadSentinel)) "Offline local upgrade attempted a download."
        Write-Output ("PASS " + $kind + " local upgrade preserves SQLite files")
    }
    Write-Output "INSTALLER_RESET_SAFETY_TESTS_PASSED"
} finally {
    $env:PATH = $PriorPath
    $env:CPA_KEY_MANAGER_USAGE_DB = $PriorDB
    $env:KM_INSTALL_DOWNLOAD_SENTINEL = $PriorCurl
    # TestRoot is a generated, verified temporary fixture only.
    if ($TestRoot -and (Split-Path $TestRoot -Leaf) -like "km-install-reset-safety-*") {
        Remove-Item -LiteralPath $TestRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}
