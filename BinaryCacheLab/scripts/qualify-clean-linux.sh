#!/bin/bash
set -euo pipefail
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
if [ "$#" -ne 1 ]; then printf 'Usage: bash scripts/qualify-clean-linux.sh NEW_OUTPUT_DIRECTORY\n' >&2; exit 2; fi
command -v docker >/dev/null || { printf 'Docker is required for clean OS qualification; no result was certified.\n' >&2; exit 7; }
[ ! -e "$1" ] || { printf 'Use a new output directory.\n' >&2; exit 2; }
mkdir -p -- "$1"
OUT=$(CDPATH= cd -- "$1" && pwd)
IMAGE="binarycachelab-qualification:$(date +%s)-$$"
docker build --no-cache --file "$ROOT/qualification/Dockerfile" --tag "$IMAGE" "$ROOT" 2>&1 | tee "$OUT/build.log"
docker image inspect "$IMAGE" > "$OUT/image-inspect.json"
docker run --rm --network none --mount "type=bind,source=$OUT,target=/evidence" "$IMAGE" 2>&1 | tee "$OUT/run.log"
[ -f "$OUT/CLEAN-INSTALL-PASSED.json" ] || { printf 'Clean installation did not qualify.\n' >&2; exit 7; }
printf 'Clean installation qualified. Evidence: %s\n' "$OUT"
