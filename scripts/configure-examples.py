"""Copy locally installed tool settings into the bundled workflow examples."""
from pathlib import Path
import json,re,tomllib
root=Path(__file__).resolve().parent.parent
settings=tomllib.loads((root/'bcl.toml').read_text())
for folder in ('workflow','programs','protection'):
    path=root/'examples'/folder/'bcl.toml'
    text=path.read_text(); section=''; lines=[]
    for line in text.splitlines():
        stripped=line.strip()
        if stripped.startswith('['):section=stripped.strip('[]')
        key=stripped.split('=',1)[0].strip() if '=' in stripped else ''
        value=None
        if section=='tools' and key in ('pin','tracer','tracer_source','docker','docker_sudo'):
            value=settings['tools'].get(key)
        elif section=='lift' and key=='image':value=settings['lift'].get('image')
        if value is not None:line=key+' = '+json.dumps(value)
        lines.append(line)
    path.write_text('\n'.join(lines)+'\n')
    print('Configured:',path)
