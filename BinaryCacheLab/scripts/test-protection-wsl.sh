#!/bin/bash
set -euo pipefail
if [[ $# != 0 && ( $# != 2 || ( "$1" != "--interfaces-from" && "$1" != "--constructs-from" ) ) ]]; then
    printf 'Usage: bash test-protection-wsl.sh [--interfaces-from ACCEPTED_EXPERIMENT | --constructs-from ACCEPTED_INTERFACE_EXPERIMENT]\n' >&2
    exit 2
fi
SOURCE=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
DEST=$(mktemp -d "$HOME/BinaryCacheLab-protection-XXXXXXXX")
export SOURCE DEST
python3 -B - <<'PY'
from pathlib import Path
import hashlib,json,os,shutil
source,dest=(Path(os.environ[k]) for k in ('SOURCE','DEST'))
manifest={}
for folder in ('src','scripts','backend','fixtures','examples','qualification'):
    for path in (source/folder).rglob('*'):
        relative=path.relative_to(source)
        if not path.is_file() or any(part in ('__pycache__','runs','build','experiments') for part in relative.parts) or path.suffix in ('.pyc','.pyo') or '.backup-' in path.name:continue
        target=dest/relative;target.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(path,target);manifest[relative.as_posix()]=hashlib.sha256(target.read_bytes()).hexdigest()
for name in ('bcl','bcl.toml','binarycachelab.jar','binarycachelab.jar.sha256'):
    shutil.copyfile(source/name,dest/name);manifest[name]=hashlib.sha256((dest/name).read_bytes()).hexdigest()
(dest/'experiments').mkdir()
(dest/'test-inputs.json').write_text(json.dumps(manifest,indent=2))
print('Protection test installation:',dest,flush=True)
PY
cd "$DEST"
chmod +x bcl fixtures/group_lookup/original
exec > >(tee -a "$DEST/native-protection.log") 2>&1
export PYTHONDONTWRITEBYTECODE=1
sha256sum -c binarycachelab.jar.sha256
PIN=${BCL_PIN:-}
if [[ -z "$PIN" ]]; then
    PIN=$(find "$HOME" -maxdepth 9 -type f -path '*/pin-4.4/*/pin' -executable -print -quit 2>/dev/null || true)
fi
if [[ -z "$PIN" || ! -x "$PIN" ]]; then
    printf 'Set BCL_PIN to the installed Intel PIN 4.4 executable; no download will be attempted.\n' >&2
    exit 2
fi
if [[ ! -f fixtures/pin/WholeProgramMemoryTracer.so ]]; then
    printf 'Missing built PIN tracer in source installation; run the existing dependency setup first.\n' >&2
    exit 2
fi
sudo -v
export JAVA=$(command -v java)
export BCL_NATIVE_EXPORT="$SOURCE/../../stage3-completion"
python3 -B -m unittest discover -s scripts -p 'test_*.py' >python-tests.log 2>&1 || { tail -n 80 python-tests.log; exit 1; }
tail -n 5 python-tests.log
if [[ ${1:-} == --constructs-from ]]; then
    python3 -B scripts/test_protection_constructs.py --existing "$2" --pin "$PIN"
elif [[ $# == 2 ]]; then
    python3 -B scripts/test_protection_interfaces.py --existing "$2" --pin "$PIN"
else
    python3 -B scripts/test_protection_native.py --pin "$PIN"
fi
python3 -B - <<'PY'
from pathlib import Path
import hashlib,json
root=Path.cwd()
for name,digest in json.loads((root/'test-inputs.json').read_text()).items():
    if hashlib.sha256((root/name).read_bytes()).hexdigest()!=digest:raise SystemExit('Test input changed: '+name)
print('PROTECTED_BUILD_FINAL_INPUT_HASHES_VERIFIED')
PY
