<#
.SYNOPSIS
    Offline installer regressions for byte-preserving config handling and fail-closed SHA256.
    Also runs the existing 13 reset/local-install safety cases. All inputs are temporary fixtures.
#>
param([string]$BashPath = "", [string]$PowerShellPath = "")
$ErrorActionPreference = "Stop"
# Do not inherit real installation paths, local binaries or release overrides.
$EnvironmentNames = @("CPA_DIR", "CPA_CONFIG_FILE", "CPA_PLUGIN_LOCAL", "CPA_PLUGIN_VERSION", "CPA_PLUGIN_REPO", "CPA_KEY_MANAGER_USAGE_DB")
$SavedEnvironment = @{}
foreach ($name in $EnvironmentNames) {
    $SavedEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, "Process")
    [Environment]::SetEnvironmentVariable($name, $null, "Process")
}
$Root = $null
try {
. (Join-Path $PSScriptRoot "install_reset_test.ps1") -BashPath $BashPath -PowerShellPath $PowerShellPath

$Root = Join-Path ([System.IO.Path]::GetTempPath()) ("km-install-config-sha-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $Root | Out-Null
$Failures = @()
$Passed = 0
$Utf8 = New-Object System.Text.UTF8Encoding($false)
function Write-FixtureText([string]$Path, [string]$Text) {
    [System.IO.File]::WriteAllText($Path, $Text.Replace("`r`n", "`n"), $Utf8)
}
function Check-Case([string]$Name, [scriptblock]$Body) {
    try { & $Body; $script:Passed++; Write-Output "PASS $Name" }
    catch { $script:Failures += "$Name : $($_.Exception.Message)"; Write-Output "FAIL $Name : $($_.Exception.Message)" }
}
function Invoke-InitFixture([string]$Kind, [string]$Target) {
    if ($Kind -eq "ps") {
        return Invoke-CheckedChild $PowerShellPath @("-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", $PowerShellInstaller, "-Dir", $Target, "-InitOnly", "-SkipModelsSync")
    }
    return Invoke-CheckedChild $BashPath @($ShellInstaller, "--dir", $Target.Replace("\", "/"), "--init-only", "--skip-models-sync")
}
    $configs = @(
        @{ Name = "quoted-double"; Text = '"plugins": {enabled: false}'; Encoding = $Utf8 },
        @{ Name = "quoted-single"; Text = "'plugins': {enabled: false}"; Encoding = $Utf8 },
        @{ Name = "utf8-bom"; Text = "plugins: {enabled: false}"; Encoding = (New-Object System.Text.UTF8Encoding($true)) },
        @{ Name = "utf16-le"; Text = "'plugins': {enabled: false}"; Encoding = [System.Text.Encoding]::Unicode },
        @{ Name = "utf16-be"; Text = '"plugins": {enabled: false}'; Encoding = [System.Text.Encoding]::BigEndianUnicode },
        @{ Name = "no-plugins"; Text = "port: 8317"; Encoding = $Utf8 },
        @{ Name = "empty"; Text = ""; Encoding = $Utf8 },
        @{ Name = "comment-only"; Text = "# cpa-plugin-key-manager is not configured"; Encoding = $Utf8 },
        @{ Name = "already-configured"; Text = "plugins:
  enabled: true
  configs:
    cpa-plugin-key-manager:
      enabled: true
"; Encoding = $Utf8 }
    )
    foreach ($kind in @("ps", "sh")) {
        foreach ($case in $configs) {
            Check-Case "$kind config $($case.Name)" {
                $target = Join-Path $Root ("$kind-config-" + $case.Name)
                New-Item -ItemType Directory -Path $target | Out-Null
                $config = Join-Path $target "config.yaml"
                [System.IO.File]::WriteAllText($config, $case.Text, $case.Encoding)
                $before = (Get-FileHash -LiteralPath $config -Algorithm SHA256).Hash
                $result = Invoke-InitFixture $kind $target
                Assert-True ($result.Code -eq 0) ("Init failed: " + $result.Output)
                Assert-True ((Get-FileHash -LiteralPath $config -Algorithm SHA256).Hash -ceq $before) "Existing config bytes changed"
                Assert-True (-not (Test-Path -LiteralPath "$config.bak")) "Created an unnecessary config backup"
                Assert-True ($result.Output -match "(?i)manual.*merge|merge.*manually") "Missing explicit manual merge action"
                Assert-True ($result.Output -match "(?m)^plugins:" -and $result.Output -match "usage_db_file") "Missing complete suggested YAML fragment"
                Assert-True ($result.Output -notmatch "installation & data initialization completed") "Misleading automatic completion claim"
            }
        }
        Check-Case "$kind config absent" {
            $target = Join-Path $Root "$kind-config-absent"
            $result = Invoke-InitFixture $kind $target
            Assert-True ($result.Code -eq 0) ("Initial config creation failed: " + $result.Output)
            $config = [System.IO.File]::ReadAllText((Join-Path $target "config.yaml"))
            Assert-True ($config -match "(?m)^plugins:" -and $config -match "cpa-plugin-key-manager:") "Initial config is missing plugin section"
        }
    }

    $binary = Join-Path $Root "download.dll"
    Write-FixtureText $binary "OFFLINE-DOWNLOAD-BINARY"
    $hash = (Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash.ToLowerInvariant()
    $asset = "cpa-plugin-key-manager-windows-amd64.dll"
    $shaCases = @(
        @{ Name = "valid"; Manifest = "$hash  $asset
"; Accept = $true; Mode = "valid" },
        @{ Name = "uppercase-star"; Manifest = "$($hash.ToUpperInvariant()) *$asset
"; Accept = $true; Mode = "valid" },
        @{ Name = "duplicate-same"; Manifest = "$hash  $asset
$hash  $asset
"; Accept = $false; Mode = "valid" },
        @{ Name = "duplicate-conflicting"; Manifest = "$hash  $asset
$('0' * 64)  $asset
"; Accept = $false; Mode = "valid" },
        @{ Name = "duplicate-malformed"; Manifest = "$hash  $asset
bad  $asset
"; Accept = $false; Mode = "valid" },
        @{ Name = "short-hash"; Manifest = "bad  $asset
"; Accept = $false; Mode = "valid" },
        @{ Name = "nonhex-hash"; Manifest = "$('z' * 64)  $asset
"; Accept = $false; Mode = "valid" },
        @{ Name = "extra-fields"; Manifest = "$hash  $asset  unexpected
"; Accept = $false; Mode = "valid" },
        @{ Name = "missing-entry"; Manifest = "$hash  other.dll
"; Accept = $false; Mode = "valid" },
        @{ Name = "mismatch"; Manifest = "$('0' * 64)  $asset
"; Accept = $false; Mode = "valid" },
        @{ Name = "tool-error-with-hash"; Manifest = "$hash  $asset
"; Accept = $false; Mode = "error" },
        @{ Name = "tool-multiple-hashes"; Manifest = "$hash  $asset
"; Accept = $false; Mode = "multiple" }
    )
    foreach ($kind in @("ps", "sha256sum", "shasum", "openssl")) {
        foreach ($case in $shaCases) {
            Check-Case "$kind checksum $($case.Name)" {
                $target = Join-Path $Root ("$kind-sha-" + $case.Name)
                New-Fixture $target
                $before = Get-Snapshot $target
                $manifest = Join-Path $Root "$kind-$($case.Name).txt"
                Write-FixtureText $manifest $case.Manifest
                if ($kind -eq "ps") {
                    $runner = Join-Path $Root "$kind-$($case.Name).ps1"
                    $mockHash = ""
                    if ($case.Mode -eq "error") {
                        $mockHash = 'function global:Get-FileHash { [pscustomobject]@{ Hash = "' + $hash + '" }; Write-Error "Hash tool failed" }' + "`n"
                    } elseif ($case.Mode -eq "multiple") {
                        $mockHash = 'function global:Get-FileHash { [pscustomobject]@{ Hash = "' + $hash + '" }; [pscustomobject]@{ Hash = "' + $hash + '" } }' + "`n"
                    }
                    $wrapper = '$ErrorActionPreference="Stop"; Import-Module Microsoft.PowerShell.Utility' + "`n" +
                        'function global:Invoke-RestMethod { throw "Unexpected network request" }' + "`n" +
                        'function global:Invoke-WebRequest { param($Uri,$OutFile,[switch]$UseBasicParsing); if ($Uri -like "*/SHA256SUMS.txt") { Copy-Item -LiteralPath ' + (Quote-Single $manifest) + ' -Destination $OutFile } elseif ($Uri -like "*/' + $asset + '") { Copy-Item -LiteralPath ' + (Quote-Single $binary) + ' -Destination $OutFile } else { throw "Unexpected network request" } }' + "`n" + $mockHash +
                        'try { & ' + (Quote-Single $PowerShellInstaller) + ' -Dir ' + (Quote-Single $target) + ' -Version v0.0.0 -SkipModelsSync; exit 0 } catch { Write-Output $_.Exception.Message; exit 73 }'
                    Write-FixtureText $runner $wrapper
                    $result = Invoke-CheckedChild $PowerShellPath @("-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", $runner)
                } else {
                    $runner = Join-Path $Root "$kind-$($case.Name).sh"
                    # Functions replace every network/hash/platform operation; no external download runs.
                    $wrapper = @'
#!/bin/bash
set -eu
command() {
  if [ "$1" = "-v" ]; then
    case "$2" in
      sha256sum|shasum|openssl) [ "$2" = "__TOOL__" ]; return ;;
    esac
  fi
  builtin command "$@"
}
uname() { if [ "$1" = "-s" ]; then printf 'MINGW64_NT\n'; else printf 'x86_64\n'; fi; }
curl() {
  out=""; url=""
  while [ "$#" -gt 0 ]; do
    case "$1" in -o) out="$2"; shift 2 ;; *) url="$1"; shift ;; esac
  done
  case "$url" in
    */SHA256SUMS.txt) cp '__MANIFEST__' "$out" ;;
    */cpa-plugin-key-manager-windows-amd64.dll) cp '__BINARY__' "$out" ;;
    *) return 92 ;;
  esac
}
fixture_hash() {
  if [ '__TOOL__' = 'openssl' ]; then printf 'SHA2-256(file)= __HASH__\n'; else printf '__HASH__  file\n'; fi
  if [ '__MODE__' = 'multiple' ]; then printf '__HASH__\n'; fi
  if [ '__MODE__' = 'error' ]; then return 91; fi
}
sha256sum() { fixture_hash; }
shasum() { fixture_hash; }
openssl() { fixture_hash; }
. '__INSTALLER__' --dir '__TARGET__' --version v0.0.0 --skip-models-sync
'@
                    $wrapper = $wrapper.Replace('__TOOL__', $kind).Replace('__MANIFEST__', $manifest.Replace("\", "/")).Replace('__BINARY__', $binary.Replace("\", "/")).Replace('__HASH__', $hash).Replace('__MODE__', $case.Mode).Replace('__INSTALLER__', $ShellInstaller.Replace("\", "/")).Replace('__TARGET__', $target.Replace("\", "/"))
                    Write-FixtureText $runner $wrapper
                    $result = Invoke-CheckedChild $BashPath @($runner)
                }
                if ($case.Accept) {
                    Assert-True ($result.Code -eq 0) ("Valid fixture download rejected: " + $result.Output)
                    $installed = Join-Path $target "plugins/cpa-plugin-key-manager.dll"
                    Assert-True ((Get-FileHash -LiteralPath $installed -Algorithm SHA256).Hash.ToLowerInvariant() -ceq $hash) "Fixture binary not installed"
                } else {
                    Assert-True ($result.Code -ne 0) "Unsafe checksum accepted"
                    Assert-True ($result.Output -match "(?i)SHA256|hash tool") ("Rejected for an unrelated reason: " + $result.Output)
                    Assert-True ((Get-Snapshot $target) -ceq $before) "Rejected checksum changed existing target files"
                }
            }
        }
    }
    if ($Failures.Count) { throw ("$($Failures.Count) installer regressions failed:`n" + ($Failures -join "`n")) }
    Write-Output "INSTALLER_CONFIG_CHECKSUM_TESTS_PASSED ($Passed cases plus 13 existing safety cases)"
} finally {
    foreach ($name in $EnvironmentNames) {
        [Environment]::SetEnvironmentVariable($name, $SavedEnvironment[$name], "Process")
    }
    # Root is generated above, outside the repository, with this exact dedicated prefix.
    if ($Root -and (Split-Path $Root -Leaf) -like "km-install-config-sha-*") {
        Remove-Item -LiteralPath $Root -Recurse -Force -ErrorAction SilentlyContinue
    }
}
