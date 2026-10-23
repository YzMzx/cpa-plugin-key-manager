#!/bin/sh
# ==============================================================================
# cpa-plugin-key-manager — One-Click & Manual Installer + Data Initializer
# Repository: https://github.com/YzMzx/cpa-plugin-key-manager
#
# Quick Install (Online):
#   curl -LsSf https://raw.githubusercontent.com/YzMzx/cpa-plugin-key-manager/main/install.sh | sh
#
# Manual / Custom Options:
#   sh install.sh [--dir /path/to/cpa] [--version v0.5.0] [--local ./cpa-plugin-key-manager.so]
#                 [--init-only] [--reset-data] [--skip-models-sync]
# ==============================================================================

set -eu

repository="${CPA_PLUGIN_REPO:-YzMzx/cpa-plugin-key-manager}"
plugin_name="cpa-plugin-key-manager"
cpa_dir="${CPA_DIR:-$(pwd)}"
release_tag="${CPA_PLUGIN_VERSION:-}"
local_source="${CPA_PLUGIN_LOCAL:-}"
init_only=0
reset_data=0
skip_models_sync=0

tmp_dir=""
staged_file=""

info() {
  printf '[%s] %s\n' "$plugin_name" "$*"
}

warn() {
  printf '[%s] WARN: %s\n' "$plugin_name" "$*" >&2
}

fail() {
  printf '[%s] ERROR: %s\n' "$plugin_name" "$*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
Usage: install.sh [options]

Options:
  --dir <path>         CLIProxyAPI root directory (default: current working directory)
  --version <tag>      Install a specific release tag (e.g. v0.2.0; default: latest)
  --local <file>       Install from a local archive (.tar.gz) or compiled library (.so/.dylib/.dll)
  --init-only          Only initialize plugin data files and config.yaml (skip binary download)
  --reset-data         Overwrite existing key_guard_rules.json and key_usage_stats.json with clean defaults
  --skip-models-sync   Skip initial models.dev reference pricing download
  -h, --help           Show this help message
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --dir)
      [ $# -ge 2 ] || fail "--dir requires a path argument"
      cpa_dir="$2"
      shift 2
      ;;
    --version)
      [ $# -ge 2 ] || fail "--version requires a tag argument (e.g. v0.2.0)"
      release_tag="$2"
      shift 2
      ;;
    --local)
      [ $# -ge 2 ] || fail "--local requires a file path"
      local_source="$2"
      shift 2
      ;;
    --init-only)
      init_only=1
      shift
      ;;
    --reset-data)
      reset_data=1
      shift
      ;;
    --skip-models-sync)
      skip_models_sync=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail "unknown option: $1 (run with --help for usage)"
      ;;
  esac
done

checksum_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  elif command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 "$1" | awk '{print $NF}'
  else
    fail "sha256sum, shasum, or openssl is required to verify the download"
  fi
}

cleanup() {
  if [ -n "$staged_file" ] && [ -e "$staged_file" ]; then
    rm -f "$staged_file"
  fi
  if [ -n "$tmp_dir" ] && [ -d "$tmp_dir" ]; then
    rm -rf "$tmp_dir"
  fi
}

trap cleanup EXIT
trap 'exit 1' HUP INT TERM

plugin_dir="${cpa_dir}/plugins"
data_dir="${cpa_dir}/data"
config_file="${cpa_dir}/config.yaml"

detect_platform() {
  os_name="$(uname -s 2>/dev/null || echo unknown)"
  arch_name="$(uname -m 2>/dev/null || echo unknown)"

  case "$os_name" in
    Darwin)
      target_os="darwin"
      extension="dylib"
      ;;
    Linux)
      target_os="linux"
      extension="so"
      ;;
    MINGW*|MSYS*|CYGWIN*)
      target_os="windows"
      extension="dll"
      ;;
    *)
      fail "unsupported operating system: ${os_name}"
      ;;
  esac

  case "$arch_name" in
    x86_64|amd64)
      target_arch="amd64"
      ;;
    arm64|aarch64)
      target_arch="arm64"
      ;;
    *)
      fail "unsupported architecture: ${arch_name}"
      ;;
  esac

  target="${target_os}-${target_arch}"
  plugin_file="${plugin_name}.${extension}"
}

install_binary() {
  detect_platform
  mkdir -p "$plugin_dir" || fail "failed to create plugin directory: ${plugin_dir}"

  tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/${plugin_name}.XXXXXX")" || fail "failed to create temporary directory"

  if [ -n "$local_source" ]; then
    [ -f "$local_source" ] || fail "local file not found: ${local_source}"
    info "Installing from local file: ${local_source}"
    case "$local_source" in
      *.tar.gz|*.tgz)
        command -v tar >/dev/null 2>&1 || fail "tar is required to extract ${local_source}"
        tar -xzf "$local_source" -C "$tmp_dir" || fail "failed to extract ${local_source}"
        if [ -f "${tmp_dir}/config.example.yaml" ]; then
          cp "${tmp_dir}/config.example.yaml" "${plugin_dir}/${plugin_name}.example.yaml" 2>/dev/null || true
        fi
        ;;
      *.so|*.dylib|*.dll)
        cp "$local_source" "${tmp_dir}/${plugin_file}" || fail "failed to copy ${local_source}"
        ;;
      *)
        fail "unsupported local file format: ${local_source}"
        ;;
    esac
  else
    command -v curl >/dev/null 2>&1 || fail "curl is required to download the plugin"

    if [ -z "$release_tag" ]; then
      info "Resolving latest release from github.com/${repository}..."
      latest_release_url="$(
        curl -fsSL --retry 3 --connect-timeout 15 -o /dev/null -w '%{url_effective}' \
          "https://github.com/${repository}/releases/latest"
      )" || fail "failed to resolve the latest release from GitHub"
      release_tag="${latest_release_url##*/}"
    fi

    case "$release_tag" in
      v[0-9]*.[0-9]*.[0-9]*) ;;
      [0-9]*.[0-9]*.[0-9]*) release_tag="v${release_tag}" ;;
      *) fail "invalid release tag: ${release_tag}" ;;
    esac

    checksums_url="https://github.com/${repository}/releases/download/${release_tag}/SHA256SUMS.txt"
    checksums="${tmp_dir}/SHA256SUMS.txt"

    if [ "$target_os" = "windows" ]; then
      asset="${plugin_name}-${target}.dll"
    else
      asset="${plugin_name}-${target}.tar.gz"
    fi
    download_url="https://github.com/${repository}/releases/download/${release_tag}/${asset}"
    archive="${tmp_dir}/${asset}"

    info "Downloading ${asset} (${release_tag})..."
    curl -fsSL --retry 3 --connect-timeout 15 -o "$archive" "$download_url" \
      || fail "failed to download: ${download_url}"

    info "Verifying SHA256 checksum..."
    curl -fsSL --retry 3 --connect-timeout 15 -o "$checksums" "$checksums_url" \
      || fail "failed to download checksums: ${checksums_url}"

    expected_checksum="$(awk -v name="$asset" '$2 == name || $2 == "*" name {print $1; exit}' "$checksums")"
    [ -n "$expected_checksum" ] || fail "SHA256SUMS.txt does not contain an entry for ${asset}"
    actual_checksum="$(checksum_file "$archive")"
    [ "$actual_checksum" = "$expected_checksum" ] \
      || fail "SHA256 checksum mismatch for ${asset} (expected ${expected_checksum}, got ${actual_checksum})"

    if [ "$target_os" = "windows" ]; then
      cp "$archive" "${tmp_dir}/${plugin_file}"
    else
      command -v tar >/dev/null 2>&1 || fail "tar is required to extract ${asset}"
      tar -xzf "$archive" -C "$tmp_dir" \
        || fail "failed to extract ${asset}"
      if [ -f "${tmp_dir}/config.example.yaml" ]; then
        cp "${tmp_dir}/config.example.yaml" "${plugin_dir}/${plugin_name}.example.yaml" 2>/dev/null || true
      fi
    fi
  fi

  [ -s "${tmp_dir}/${plugin_file}" ] || fail "extracted plugin binary ${plugin_file} is missing or empty"

  staged_file="${plugin_dir}/.${plugin_file}.tmp.$$"
  cp "${tmp_dir}/${plugin_file}" "$staged_file" || fail "failed to stage plugin binary in ${plugin_dir}"
  chmod 0755 "$staged_file"
  mv -f "$staged_file" "${plugin_dir}/${plugin_file}" || fail "failed to move plugin binary into place"
  staged_file=""

  info "Installed plugin binary: ${plugin_dir}/${plugin_file}"
}

init_plugin_data() {
  mkdir -p "$data_dir" || fail "failed to create data directory: ${data_dir}"
  now_utc="$(date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || echo "2026-01-01T00:00:00Z")"

  rules_file="${data_dir}/key_guard_rules.json"
  if [ ! -f "$rules_file" ] || [ "$reset_data" -eq 1 ]; then
    cat > "${rules_file}.tmp.$$" <<EOF
{
  "version": 1,
  "updated_at": "${now_utc}",
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
EOF
    mv -f "${rules_file}.tmp.$$" "$rules_file"
    info "Initialized dynamic rules store: ${rules_file}"
  else
    info "Preserved existing dynamic rules store: ${rules_file}"
  fi

  usage_file="${data_dir}/key_usage_stats.json"
  if [ ! -f "$usage_file" ] || [ "$reset_data" -eq 1 ]; then
    cat > "${usage_file}.tmp.$$" <<EOF
{
  "version": 1,
  "updated_at": "${now_utc}",
  "keys": {}
}
EOF
    mv -f "${usage_file}.tmp.$$" "$usage_file"
    info "Initialized token usage store: ${usage_file}"
  else
    info "Preserved existing token usage store: ${usage_file}"
  fi
}

init_plugin_config() {
  if [ ! -f "$config_file" ]; then
    cat > "$config_file" <<'EOF'
# Generated by cpa-plugin-key-manager installer
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
EOF
    info "Created initial config.yaml with cpa-plugin-key-manager enabled: ${config_file}"
    return
  fi

  if grep -q "cpa-plugin-key-manager" "$config_file" 2>/dev/null; then
    info "Detected existing cpa-plugin-key-manager configuration in ${config_file}"
    return
  fi

  if grep -q "cpa-plugin-key:" "$config_file" 2>/dev/null; then
    info "Migrating legacy cpa-plugin-key configuration to cpa-plugin-key-manager in ${config_file}"
    cp "$config_file" "${config_file}.bak" 2>/dev/null || true
    sed -i.bak 's/cpa-plugin-key:/cpa-plugin-key-manager:/g' "$config_file" 2>/dev/null || sed -i '' 's/cpa-plugin-key:/cpa-plugin-key-manager:/g' "$config_file" 2>/dev/null || true
    info "Updated config.yaml to cpa-plugin-key-manager (backup saved to ${config_file}.bak)"
    return
  fi

  if ! grep -q "^plugins:" "$config_file" 2>/dev/null; then
    cp "$config_file" "${config_file}.bak" 2>/dev/null || true
    cat >> "$config_file" <<'EOF'

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
EOF
    info "Appended plugins.configs.cpa-plugin-key-manager to ${config_file} (backup saved to ${config_file}.bak)"
  else
    warn "${config_file} already contains a 'plugins:' section. Please ensure 'cpa-plugin-key-manager' is enabled under plugins.configs:"
    cat <<'EOF'
    cpa-plugin-key-manager:
      enabled: true
      priority: 100
      storage:
        usage_file: "./data/key_usage_stats.json"
        rules_file: "./data/key_guard_rules.json"
        flush_interval_seconds: 10
EOF
  fi
}

if [ "$init_only" -eq 0 ]; then
  install_binary
else
  info "Skipping binary download (--init-only specified)"
fi

init_plugin_data
init_plugin_config

printf '\n==============================================================================\n'
printf '  cpa-plugin-key-manager installation & data initialization completed!\n'
printf '  - Plugin directory : %s\n' "$plugin_dir"
printf '  - Data directory   : %s\n' "$data_dir"
printf '  - Admin Web UI     : http://127.0.0.1:8317/v0/resource/plugins/cpa-plugin-key-manager/ui\n'
printf '  Restart CLIProxyAPI to load the plugin.\n'
printf '==============================================================================\n'
