#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
if [ "$#" -lt 1 ]; then
  printf 'Usage: sh scripts/configure-wsl.sh /absolute/path/to/pin [/absolute/path/to/tracer.so] [--lift] [--sudo-docker]\n' >&2
  exit 2
fi
PIN=$1
shift
case "$PIN" in /*) ;; *) printf 'PIN path must be absolute.\n' >&2; exit 2;; esac
if [ ! -x "$PIN" ]; then printf 'PIN executable not found: %s\n' "$PIN" >&2; exit 2; fi
TRACER="$ROOT/fixtures/pin/WholeProgramMemoryTracer.so"
LIFT=false
SUDO=false
for ARG in "$@"; do
  case "$ARG" in
    --lift) LIFT=true ;;
    --sudo-docker) SUDO=true ;;
    /*) TRACER=$ARG ;;
    *) printf 'Unknown argument: %s\n' "$ARG" >&2; exit 2 ;;
  esac
done
if [ ! -f "$TRACER" ]; then printf 'Tracer not found: %s\n' "$TRACER" >&2; exit 2; fi
if ! command -v python3 >/dev/null 2>&1; then printf 'python3 is required.\n' >&2; exit 2; fi
python3 - "$ROOT/bcl.toml" "$PIN" "$TRACER" "$LIFT" "$SUDO" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
text = path.read_text()
updates = {
    'pin': json.dumps(str(pathlib.Path(sys.argv[2]).resolve())),
    'tracer': json.dumps(str(pathlib.Path(sys.argv[3]).resolve())),
    'enabled': sys.argv[4],
    'docker_sudo': sys.argv[5],
}
section = ''
found = set()
lines = []
for line in text.splitlines():
    stripped = line.strip()
    if stripped.startswith('[') and stripped.endswith(']'):
        section = stripped[1:-1]
    key = stripped.split('=', 1)[0].strip() if '=' in stripped else ''
    target = (section, key)
    if target == ('tools', 'pin'):
        line = 'pin = ' + updates['pin']; found.add(target)
    elif target == ('tools', 'tracer'):
        line = 'tracer = ' + updates['tracer']; found.add(target)
    elif target == ('tools', 'docker_sudo'):
        line = 'docker_sudo = ' + updates['docker_sudo']; found.add(target)
    elif target == ('lift', 'enabled'):
        line = 'enabled = ' + updates['enabled']; found.add(target)
    lines.append(line)
required = {('tools', 'pin'), ('tools', 'tracer'), ('tools', 'docker_sudo'), ('lift', 'enabled')}
if found != required:
    raise SystemExit('Config is missing keys: ' + repr(sorted(required - found)))
backup = path.with_name(path.name + '.before-wsl-setup')
if not backup.exists():
    backup.write_text(text)
path.write_text('\n'.join(lines) + '\n')
print('Configured:', path)
print('PIN:', sys.argv[2])
print('Tracer:', sys.argv[3])
print('Fresh FoxDec lift:', sys.argv[4])
print('Docker through sudo:', sys.argv[5])
PY
