#!/bin/bash
set -euo pipefail
if [[ $# -gt 1 || ( $# -eq 1 && "$1" != "--prime-only" ) ]]; then
    printf 'Usage: bash test-programs-wsl.sh [--prime-only]\n' >&2
    exit 2
fi
PRIME_ONLY=false
if [[ ${1:-} == --prime-only ]]; then PRIME_ONLY=true; fi
export PRIME_ONLY
SOURCE=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
DEST=$(mktemp -d "$HOME/BinaryCacheLab-programs-XXXXXXXX")
export SOURCE DEST
python3 -B - <<'PY'
from pathlib import Path
import os,shutil,hashlib,json
source,dest=(Path(os.environ[k]) for k in ('SOURCE','DEST'))
manifest={}
for folder in ('src','scripts','backend','fixtures','examples','qualification'):
    for path in (source/folder).rglob('*'):
        relative=path.relative_to(source)
        if not path.is_file() or any(part in ('__pycache__','runs','build','experiments') for part in relative.parts) or path.suffix in ('.pyc','.pyo') or '.backup-' in path.name:continue
        target=dest/relative;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(path,target)
        manifest[relative.as_posix()]=hashlib.sha256(target.read_bytes()).hexdigest()
for name in ('bcl','bcl.toml','binarycachelab.jar','binarycachelab.jar.sha256','start.sh'):
    shutil.copyfile(source/name,dest/name);manifest[name]=hashlib.sha256((dest/name).read_bytes()).hexdigest()
(dest/'test-inputs.json').write_text(json.dumps(manifest,indent=2))
print('Program/TUI test installation:',dest,flush=True)
PY
cd "$DEST"
chmod +x bcl fixtures/group_lookup/original
exec > >(tee -a "$DEST/native-programs.log") 2>&1
export PYTHONDONTWRITEBYTECODE=1
export JAVA=$(command -v java)
sha256sum -c binarycachelab.jar.sha256
sudo -v
printf 'Running Python regression (full output: %s/python-tests.log)\n' "$DEST"
if python3 -B -m unittest discover -s scripts -p 'test_*.py' > "$DEST/python-tests.log" 2>&1; then
    tail -n 5 "$DEST/python-tests.log"
else
    cat "$DEST/python-tests.log"
    exit 1
fi
if [[ $PRIME_ONLY == true ]]; then
    python3 -B scripts/test_programs_native.py --prime-only
else
    python3 -B scripts/test_programs_native.py
    python3 -B scripts/test_assessments_native.py
    python3 -B scripts/test_dashboard_native.py --saved --expect COMPROMISED
fi
python3 -B - <<'PY'
from pathlib import Path
import hashlib,json,os
root=Path.cwd();manifest=json.loads((root/'test-inputs.json').read_text())
for name,digest in manifest.items():
    if hashlib.sha256((root/name).read_bytes()).hexdigest()!=digest:raise SystemExit('Test input changed: '+name)
result={'status':'PRIME_PROGRAM_EXPECTATIONS_MET' if os.environ.get('PRIME_ONLY')=='true' else 'PROGRAM_AND_GROUPED_FINDINGS_EXPECTATIONS_MET','installation':str(root),'files_unchanged':len(manifest),'general_programs':'PASS','lookup_and_leakage_control':'NOT_RUN' if os.environ.get('PRIME_ONLY')=='true' else 'PASS','grouped_TUI_findings':'NOT_RUN' if os.environ.get('PRIME_ONLY')=='true' else 'PASS'}
(root/'native-programs-result.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2))
PY
