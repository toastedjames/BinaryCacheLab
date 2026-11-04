#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
mkdir -p "$ROOT/build"
STAGE=$(mktemp -d "$ROOT/build/linux-demo-XXXXXXXX")
mkdir "$STAGE/classes"
find "$ROOT/src/main/java" -name '*.java' -print0 |
  xargs -0 javac --release 17 -encoding UTF-8 -d "$STAGE/classes"
jar --create --file "$STAGE/binarycachelab.jar" \
  --main-class org.binarycachelab.BinaryCacheLabCli -C "$STAGE/classes" .
printf 'Built %s\n' "$STAGE/binarycachelab.jar"
# Source builds remain separate; use java -jar on the printed artifact.
