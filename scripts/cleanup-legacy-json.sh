#!/usr/bin/env bash
# cleanup-legacy-json.sh - remove the JSON stores left by v0.8.* and the early
# SQLite builds (v0.9.0-sqlite.1 .. .3).
#
# After the move to SQLite everything lives in key_usage.db:
#   rules_state / key_usage / key_model_usage / account_usage / account_model_usage / usage_ledger
#
# This script only touches the retired JSON stores:
#   key_guard_rules.json  key_guard_rules.state
#   key_usage_stats.json  key_usage_stats.state
#   leftovers: <name>.tmp.<digits>
# It never touches models_dev.json (still the price cache), *.db / -wal / -shm,
# *.lock or config.yaml.
#
# Examples:
#   ./cleanup-legacy-json.sh                    # dry-run, only prints
#   ./cleanup-legacy-json.sh --apply            # move into a timestamped backup dir
#   ./cleanup-legacy-json.sh --apply --delete   # delete permanently
#   ./cleanup-legacy-json.sh --root /srv/cpa --apply
#
# Safety: refuses to act while no key_usage.db exists, because then the JSON files
# may still be the only copy of the rules and the usage history. Use --force to
# override.
#
# Exit codes: 0 ok, 1 usage error, 2 refused (no database), 3 failure.

set -uo pipefail

APPLY="no"
DELETE="no"
FORCE="no"
ROOT=""
BACKUP_DIR=""

usage() {
  sed -n '3,23p' "$0" | sed 's/^# \{0,1\}//'
  exit "${1:-0}"
}

while [ $# -gt 0 ]; do
  case "$1" in
    --apply)   APPLY="yes"; shift ;;
    --delete)  DELETE="yes"; shift ;;
    --force)   FORCE="yes"; shift ;;
    --root)    ROOT="${2:-}"; shift 2 ;;
    --backup)  BACKUP_DIR="${2:-}"; shift 2 ;;
    -h|--help) usage 0 ;;
    *) echo "unknown argument: $1" >&2; usage 1 ;;
  esac
done

if [ -n "$ROOT" ]; then
  ROOT="${ROOT%/}"
elif [ -d /CLIProxyAPI ]; then
  ROOT="/CLIProxyAPI"
else
  ROOT="$(pwd)"
fi

CANDIDATE_DIRS=()
add_dir() {
  if [ -n "${1:-}" ] && [ -d "$1" ]; then
    CANDIDATE_DIRS+=("${1%/}")
  fi
}

add_dir "$ROOT/data"
add_dir "$ROOT"
add_dir "$ROOT/plugins/data"
# compose deployments usually bind the auth directory next to the compose file
for local_auth in "$ROOT/auths" "$ROOT/auth" "$ROOT/data/auths"; do
  add_dir "$local_auth"
  add_dir "$local_auth/key-manager"
done
for auth in "${CPA_AUTH_DIR:-}" "${HOME:-}/.cli-proxy-api" "/root/.cli-proxy-api"; do
  if [ -z "$auth" ]; then
    continue
  fi
  add_dir "$auth"
  add_dir "$auth/key-manager"
  add_dir "$auth/data"
done
add_dir "$(pwd)"
add_dir "$(pwd)/data"

DIRS=()
if [ ${#CANDIDATE_DIRS[@]} -gt 0 ]; then
  for d in "${CANDIDATE_DIRS[@]}"; do
    dup="no"
    if [ ${#DIRS[@]} -gt 0 ]; then
      for seen in "${DIRS[@]}"; do
        if [ "$seen" = "$d" ]; then dup="yes"; break; fi
      done
    fi
    if [ "$dup" = "no" ]; then DIRS+=("$d"); fi
  done
fi

if [ ${#DIRS[@]} -eq 0 ]; then
  echo "no candidate directories found" >&2
  exit 1
fi

# Refuse to destroy the only copy while SQLite has not produced a database yet.
DB_FOUND=""
for d in "${DIRS[@]}"; do
  if [ -f "$d/key_usage.db" ]; then DB_FOUND="$d/key_usage.db"; break; fi
done
if [ -z "$DB_FOUND" ] && [ "$FORCE" != "yes" ]; then
  {
    echo "[refused] no key_usage.db found under:"
    for d in "${DIRS[@]}"; do echo "  - $d"; done
    echo "The JSON files may still be the only copy of your rules and usage history."
    echo "Start the plugin once so SQLite is populated, verify the dashboard looks right,"
    echo "then re-run this script. Use --force only if you are certain."
  } >&2
  exit 2
fi
if [ -n "$DB_FOUND" ]; then
  echo "[info] database: $DB_FOUND"
else
  echo "[warning] --force given: proceeding without a key_usage.db"
fi

matches() {
  case "$(basename "$1")" in
    key_guard_rules.json|key_usage_stats.json) return 0 ;;
    key_guard_rules.state|key_usage_stats.state) return 0 ;;
    key_guard_rules.json.tmp.*|key_usage_stats.json.tmp.*) return 0 ;;
    key_guard_rules.state.tmp.*|key_usage_stats.state.tmp.*) return 0 ;;
  esac
  return 1
}

TARGETS=()
LIST_FILE="$(mktemp)"
for d in "${DIRS[@]}"; do
  find "$d" -maxdepth 1 -type f 2>/dev/null
done | sort >"$LIST_FILE"
while IFS= read -r f; do
  if [ -n "$f" ] && matches "$f"; then
    TARGETS+=("$f")
  fi
done <"$LIST_FILE"
rm -f -- "$LIST_FILE"

if [ ${#TARGETS[@]} -eq 0 ]; then
  echo "[done] nothing to clean up: no legacy JSON store found"
  exit 0
fi

echo "[info] found ${#TARGETS[@]} legacy file(s):"
TOTAL=0
for f in "${TARGETS[@]}"; do
  size=$(wc -c <"$f" 2>/dev/null | tr -d ' ')
  TOTAL=$((TOTAL + ${size:-0}))
  printf '  %10s B  %s\n' "${size:-0}" "$f"
done
printf '[info] total size: %s bytes\n' "$TOTAL"

if [ "$APPLY" != "yes" ]; then
  echo
  echo "[dry-run] nothing was changed. Re-run with --apply to move the files into a backup"
  echo "          folder, or with '--apply --delete' to remove them permanently."
  exit 0
fi

if [ "$DELETE" = "yes" ]; then
  for f in "${TARGETS[@]}"; do
    if rm -f -- "$f"; then
      echo "[deleted] $f"
    else
      echo "[error] failed to delete $f" >&2
      exit 3
    fi
  done
  echo "[done] removed ${#TARGETS[@]} legacy file(s)"
  exit 0
fi

# Default: move into a timestamped backup folder so the data stays recoverable.
if [ -z "$BACKUP_DIR" ]; then
  base="$ROOT/data"
  if [ ! -d "$base" ]; then base="$ROOT"; fi
  BACKUP_DIR="$base/legacy-json-backup-$(date +%Y%m%d-%H%M%S)"
fi
mkdir -p "$BACKUP_DIR" || { echo "[error] cannot create $BACKUP_DIR" >&2; exit 3; }

MOVED=0
for f in "${TARGETS[@]}"; do
  safe=$(printf '%s' "$f" | sed 's#^/##; s#^[A-Za-z]:##; s#[/\\\\:]#__#g')
  if mv -- "$f" "$BACKUP_DIR/$safe"; then
    MOVED=$((MOVED + 1))
    echo "[moved] $f -> $BACKUP_DIR/$safe"
  else
    echo "[error] failed to move $f" >&2
    exit 3
  fi
done

echo "[done] moved $MOVED legacy file(s) into $BACKUP_DIR"
echo "[hint] the plugin now reads and writes only the SQLite database;"
echo "       delete the backup folder once you are satisfied."
