<#
.SYNOPSIS
    cpa-plugin-key-manager — Windows One-Click & Manual Installer + Data Initializer
.DESCRIPTION
    Downloads the latest (or specified) cpa-plugin-key-manager Windows DLL from GitHub Releases,
    verifies its SHA256 checksum, installs it into .\plugins\cpa-plugin-key-manager.dll,
    and initializes .\data\key_guard_rules.json, .\data\key_usage_stats.json,
    .\data\models_dev.json, and config.yaml.
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
$NowUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

$RulesFile = Join-Path $DataDir "key_guard_rules.json"
if ((-not (Test-Path $RulesFile)) -or $ResetData) {
    $RulesJson = @"
{
  "version": 1,
  "updated_at": "$NowUtc",
  "default_policy": {
    "allow_unlisted_keys": true,
    "max_concurrency": 0,
    "allowed_models": [
      "*"
    ],
    "upstream_binding": {
      "strategy": "round-robin"
    }
  },
  "keys": []
}
"@
    [System.IO.File]::WriteAllText($RulesFile, $RulesJson, (New-Object System.Text.UTF8Encoding($false)))
    Write-Info "Initialized dynamic rules store: $RulesFile"
} else {
    Write-Info "Preserved existing dynamic rules store: $RulesFile"
}

$UsageFile = Join-Path $DataDir "key_usage_stats.json"
if ((-not (Test-Path $UsageFile)) -or $ResetData) {
    $UsageJson = @"
{
  "version": 1,
  "updated_at": "$NowUtc",
  "keys": {}
}
"@
    [System.IO.File]::WriteAllText($UsageFile, $UsageJson, (New-Object System.Text.UTF8Encoding($false)))
    Write-Info "Initialized token usage store: $UsageFile"
} else {
    Write-Info "Preserved existing token usage store: $UsageFile"
}

$PluginYamlBlock = @"

# --- Added by cpa-plugin-key-manager installer ---
plugins:
  enabled: true
  dir: ./plugins
  configs:
    cpa-plugin-key-manager:
      enabled: true
      priority: 100
      storage:
        usage_file: "./data/key_usage_stats.json"
        rules_file: "./data/key_guard_rules.json"
        flush_interval_seconds: 10
      default_policy:
        allow_unlisted_keys: true
        max_concurrency: 0
        allowed_models:
          - "*"
"@

if (-not (Test-Path $ConfigFile)) {
    [System.IO.File]::WriteAllText($ConfigFile, $PluginYamlBlock.TrimStart(), (New-Object System.Text.UTF8Encoding($false)))
    Write-Info "Created initial config.yaml with cpa-plugin-key-manager enabled: $ConfigFile"
} else {
    $RawCfg = Get-Content -Path $ConfigFile -Raw
    if ($RawCfg -match "cpa-plugin-key-manager") {
        Write-Info "Detected existing cpa-plugin-key-manager configuration in $ConfigFile"
    } elseif ($RawCfg -match "cpa-plugin-key:") {
        Write-Info "Migrating legacy cpa-plugin-key configuration to cpa-plugin-key-manager in $ConfigFile"
        Copy-Item -Path $ConfigFile -Destination "$ConfigFile.bak" -Force
        $MigratedCfg = $RawCfg -replace "cpa-plugin-key:", "cpa-plugin-key-manager:"
        [System.IO.File]::WriteAllText($ConfigFile, $MigratedCfg, (New-Object System.Text.UTF8Encoding($false)))
        Write-Info "Updated config.yaml to cpa-plugin-key-manager (backup saved to $ConfigFile.bak)"
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
