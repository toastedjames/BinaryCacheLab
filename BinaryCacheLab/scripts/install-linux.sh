#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
if [ "$#" -ne 2 ]; then
  printf 'Usage: sh scripts/install-linux.sh NEW_ABSOLUTE_DIRECTORY EXISTING_CONFIG\n' >&2
  exit 2
fi
TARGET=$1
CONFIG=$2
case "$TARGET" in /*) ;; *) printf 'Use an absolute installation directory.\n' >&2; exit 2;; esac
if [ -e "$TARGET" ] || [ -L "$TARGET" ]; then
  printf 'Installation directory already exists: %s\n' "$TARGET" >&2
  exit 2
fi
if [ ! -f "$CONFIG" ]; then printf 'Configuration file missing.\n' >&2; exit 2; fi
RESOLVED=$(realpath -m -- "$TARGET")
case "$RESOLVED/" in "$ROOT/"*) printf 'Install outside the source package directory.\n' >&2; exit 2;; esac
command -v java >/dev/null
(cd "$ROOT" && sha256sum --check --status binarycachelab.jar.sha256)
mkdir -- "$TARGET"
cp -R -- "$ROOT/." "$TARGET/"
cp -- "$CONFIG" "$TARGET/bcl.toml"
chmod +x -- "$TARGET/bcl"
printf 'Installed: %s\nLaunch: cd "%s" && ./bcl tui\nNo native experiments were run.\n' "$TARGET" "$TARGET"
