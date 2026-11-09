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
            foreach ($line in (Get-Content $TmpSums)) {
                if ($line -match "^([0-9a-fA-F]{64})\s+\*?$([regex]::Escape($Asset))$") {
                    $Expected = $Matches[1].ToLower()
                    break
                }
            }
            if ($Expected -eq "") {
                throw "SHA256SUMS.txt does not contain an entry for $Asset"
            }
            $Actual = (Get-FileHash -Path $TmpDll -Algorithm SHA256).Hash.ToLower()
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

# --- Added by cpa-plugin-key-manager installer ---
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

if (-not (Test-Path $ConfigFile)) {
    [System.IO.File]::WriteAllText($ConfigFile, $PluginYamlBlock.TrimStart(), (New-Object System.Text.UTF8Encoding($false)))
    Write-Info "Created initial config.yaml with cpa-plugin-key-manager enabled: $ConfigFile"
} else {
    $RawCfg = Get-Content -Path $ConfigFile -Raw
    if ($RawCfg -match "cpa-plugin-key-manager") {
        Write-Info "Detected existing cpa-plugin-key-manager configuration in $ConfigFile"
    } elseif ($RawCfg -notmatch "(?m)^plugins:") {
        Copy-Item -Path $ConfigFile -Destination "$ConfigFile.bak" -Force
        Add-Content -Path $ConfigFile -Value $PluginYamlBlock -Encoding UTF8
        Write-Info "Appended plugins.configs.cpa-plugin-key-manager to $ConfigFile (backup saved to $ConfigFile.bak)"
    } else {
        Write-Warn "$ConfigFile already contains a 'plugins:' section. Please ensure 'cpa-plugin-key-manager' is configured under plugins.configs."
    }
}

Write-Host ""
Write-Host "==============================================================================" -ForegroundColor Green
Write-Host "  cpa-plugin-key-manager installation & data initialization completed!" -ForegroundColor Green
Write-Host "  - Plugin directory : $PluginDir"
Write-Host "  - Data directory   : $DataDir"
Write-Host "  - Admin Web UI     : http://127.0.0.1:8317/v0/resource/plugins/cpa-plugin-key-manager/ui"
Write-Host "  Restart CLIProxyAPI to load the plugin."
Write-Host "==============================================================================" -ForegroundColor Green
