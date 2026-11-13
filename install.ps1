<#
.SYNOPSIS
    cpa-plugin-key-manager — Windows One-Click & Manual Installer + Data Initializer
.DESCRIPTION
    Downloads the latest (or specified) cpa-plugin-key-manager Windows DLL from GitHub Releases,
    verifies its SHA256 checksum, installs it into .\plugins\cpa-plugin-key-manager.dll,
    and initializes the SQLite data directory, .\data\models_dev.json pricing cache,
    and config.yaml.
.EXAMPLE
    irm https://raw.githubusercontent.com/YzMzx/cpa-plugin-key-manager/main/install.ps1 | iex
.EXAMPLE
    .\install.ps1 -Dir "D:\CLIProxyAPI" -Version "v0.5.0"
#>
param(
    [string]$Dir = (Get-Location).Path,
    [string]$Version = "",
    [string]$Local = "",
    [switch]$InitOnly,
    [switch]$ResetData,
    [switch]$SkipModelsSync
)

$ErrorActionPreference = "Stop"

# Reject before directory creation, downloads, binary replacement or database access.
if ($ResetData) {
    throw "-ResetData is disabled: the installer never resets databases automatically. Stop CPA, fully back up the actual storage.usage_db_file (or CPA_KEY_MANAGER_USAGE_DB) and its WAL/SHM files, then reset manually."
}
$Repo = if ($env:CPA_PLUGIN_REPO) { $env:CPA_PLUGIN_REPO } else { "YzMzx/cpa-plugin-key-manager" }
$PluginName = "cpa-plugin-key-manager"
$PluginFile = "$PluginName.dll"
$PluginDir = Join-Path $Dir "plugins"
$DataDir = Join-Path $Dir "data"
$ConfigFile = Join-Path $Dir "config.yaml"

function Write-Info([string]$Message) {
    Write-Host "[$PluginName] $Message" -ForegroundColor Cyan
}

function Write-Warn([string]$Message) {
    Write-Host "[$PluginName] WARN: $Message" -ForegroundColor Yellow
}

if (-not $InitOnly) {
    New-Item -ItemType Directory -Force -Path $PluginDir | Out-Null
    $TargetPath = Join-Path $PluginDir $PluginFile
    $StagedPath = Join-Path $PluginDir ".$PluginFile.tmp.$PID"

    if ($Local -ne "") {
        if (-not (Test-Path $Local)) {
            throw "Local file not found: $Local"
        }
        Write-Info "Installing from local file: $Local"
        Copy-Item -Path $Local -Destination $StagedPath -Force
        Move-Item -Path $StagedPath -Destination $TargetPath -Force
    } else {
        if ($Version -eq "") {
            Write-Info "Resolving latest release from github.com/$Repo..."
            $RelResp = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" -Method Get
            $Version = $RelResp.tag_name
        }
        if ($Version -notmatch '^v') {
            $Version = "v$Version"
        }

        $Asset = "$PluginName-windows-amd64.dll"
        $DownloadUrl = "https://github.com/$Repo/releases/download/$Version/$Asset"
        $ChecksumsUrl = "https://github.com/$Repo/releases/download/$Version/SHA256SUMS.txt"

        $TmpDir = Join-Path ([System.IO.Path]::GetTempPath()) "$PluginName-$PID"
        New-Item -ItemType Directory -Force -Path $TmpDir | Out-Null
        try {
            $TmpDll = Join-Path $TmpDir $Asset
            $TmpSums = Join-Path $TmpDir "SHA256SUMS.txt"

            Write-Info "Downloading $Asset ($Version)..."
            Invoke-WebRequest -Uri $DownloadUrl -OutFile $TmpDll -UseBasicParsing

            Write-Info "Verifying SHA256 checksum..."
            Invoke-WebRequest -Uri $ChecksumsUrl -OutFile $TmpSums -UseBasicParsing

            $Expected = ""
            $EntryCount = 0
            $InvalidEntry = $false
            foreach ($line in (Get-Content -LiteralPath $TmpSums)) {
                $Fields = @($line.Trim() -split '\s+')
                if ($Fields.Count -ge 2 -and ($Fields[1] -ceq $Asset -or $Fields[1] -ceq "*$Asset")) {
                    $EntryCount++
                    if ($Fields.Count -ne 2 -or $Fields[0] -notmatch '^[0-9a-fA-F]{64}$') {
                        $InvalidEntry = $true
                    } else {
                        $Expected = $Fields[0].ToLowerInvariant()
                    }
                }
            }
            if ($EntryCount -ne 1 -or $InvalidEntry) {
                throw "SHA256SUMS.txt must contain exactly one valid 64-hex entry for $Asset"
            }
            # Do not compare arrays: duplicate hash results must fail, even if all match.
            $HashResults = @(Get-FileHash -LiteralPath $TmpDll -Algorithm SHA256 -ErrorAction Stop)
            if ($HashResults.Count -ne 1 -or $HashResults[0].Hash -notmatch '^[0-9a-fA-F]{64}$') {
                throw "Hash tool must return exactly one valid SHA256 digest"
            }
            $Actual = $HashResults[0].Hash.ToLowerInvariant()
            if ($Actual -ne $Expected) {
                throw "SHA256 checksum mismatch for $Asset (expected $Expected, got $Actual)"
            }

            Copy-Item -Path $TmpDll -Destination $StagedPath -Force
            Move-Item -Path $StagedPath -Destination $TargetPath -Force
            Write-Info "Installed plugin binary: $TargetPath"
        } finally {
            if (Test-Path $TmpDir) {
                Remove-Item -Path $TmpDir -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

New-Item -ItemType Directory -Force -Path $DataDir | Out-Null

# Runtime records live only in SQLite; the plugin creates its database on first start.
$PluginYamlBlock = @"

# Suggested cpa-plugin-key-manager configuration; merge into existing mappings.
# NOTE: all data lives in <CLIProxyAPI>/data/key_usage.db (SQLite).
# For Docker deployments mount that directory, e.g.
#   volumes:
#     - ./data:/CLIProxyAPI/data
plugins:
  enabled: true
  dir: ./plugins
  configs:
    cpa-plugin-key-manager:
      enabled: true
      storage:
        # 留空则使用 <CLIProxyAPI 根目录>/data/key_usage.db
        usage_db_file: ""
"@

# Never parse or rewrite existing YAML, regardless of quoting, encoding or contents.
if (-not (Test-Path -LiteralPath $ConfigFile)) {
    # CreateNew also refuses a configuration created after the existence check.
    $ConfigStream = [System.IO.File]::Open($ConfigFile, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write)
    try {
        $ConfigBytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes($PluginYamlBlock.TrimStart())
        $ConfigStream.Write($ConfigBytes, 0, $ConfigBytes.Length)
    } finally {
        $ConfigStream.Dispose()
    }
    Write-Info "Created initial config.yaml with cpa-plugin-key-manager enabled: $ConfigFile"
} else {
    Write-Warn "Existing configuration left unchanged: $ConfigFile. Configuration was NOT completed automatically."
    Write-Warn "Manually merge the following fragment into the existing YAML mappings; do not append a duplicate plugins key."
    Write-Warn "Preserve existing settings and storage paths. If already configured correctly, no changes are needed. Verify before restarting CPA."
    Write-Host $PluginYamlBlock.TrimStart()
}

Write-Host ""
Write-Host "==============================================================================" -ForegroundColor Green
Write-Host "  cpa-plugin-key-manager installer finished; review configuration instructions above." -ForegroundColor Green
Write-Host "  - Plugin directory : $PluginDir"
Write-Host "  - Data directory   : $DataDir"
Write-Host "  - Admin Web UI     : http://127.0.0.1:8317/v0/resource/plugins/cpa-plugin-key-manager/ui"
Write-Host "  Verify/merge configuration before restarting CLIProxyAPI to load the plugin."
Write-Host "==============================================================================" -ForegroundColor Green
