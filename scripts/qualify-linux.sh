#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
case "${1-}" in
  --list)
    java -jar "$ROOT/binarycachelab.jar" suite "$ROOT/examples/layout-suite.json" --list
    java -jar "$ROOT/binarycachelab.jar" suite "$ROOT/examples/qualification-suite.json" --list
    ;;
  '')
    java -jar "$ROOT/binarycachelab.jar" suite "$ROOT/examples/layout-suite.json"
    java -jar "$ROOT/binarycachelab.jar" suite "$ROOT/examples/qualification-suite.json"
    ;;
  *) printf 'Usage: sh scripts/qualify-linux.sh [--list]\n' >&2; exit 2;;
esac
