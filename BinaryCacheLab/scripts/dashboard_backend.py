"""Small TUI adapter to existing schema-2 configuration and execution; no verdict logic."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import signal
import tempfile
import tomllib

import workflow


def describe(path,input_path=None):
    path = Path(path).resolve()
    doc = workflow.config(path)
    if input_path and Path(input_path).is_file():
        from program_workflow import workflow_for,ProgramWorkflow,asm_description,program_config
        selected=workflow_for(input_path,path)
        if isinstance(selected,ProgramWorkflow) and Path(input_path).suffix.lower()=='.asm':doc=program_config(doc,asm_description(input_path),selected.automatic)
    base = path.parent
    def resolve(value):
        return str((base / str(value).replace('{home}', str(Path.home())).replace('{toolkit}', str(workflow.ROOT))).resolve())
    inputs = sorted(base.glob('*.asm'))
    return {'schema': 'dashboard-config-1', 'input': str(inputs[0]) if len(inputs) == 1 else '',
            'output': resolve(doc.get('output', 'runs')), 'observer': doc['comparison']['line_identity'] + ' / ' + doc['comparison']['scope'],
            'line_bytes': doc['comparison']['line_bytes'], 'coverage': 'UNVERIFIED',
            'stages': workflow.STAGES, 'configuration': doc,
            'paths': {key: resolve(value) for key, value in doc['tools'].items() if key in ('pin', 'tracer', 'tracer_source')}}


def edit(path, assignment):
    """Edit one existing scalar; validate the entire candidate before backup/replace."""
    path = Path(path).resolve()
    key, separator, literal = assignment.partition('=')
    key, literal = key.strip(), literal.strip()
    if not separator or not re.fullmatch(r'[a-z_]+(?:\.[a-z_]+)*', key):
        raise ValueError('Use E section.key=literal')
    old = path.read_text()
    current = tomllib.loads(old)
    parts = key.split('.')
    target = current
    for part in parts[:-1]:
        if not isinstance(target, dict) or part not in target:
            raise ValueError('Unknown setting: ' + key)
        target = target[part]
    if not isinstance(target, dict) or parts[-1] not in target:
        raise ValueError('Unknown setting: ' + key)
    value = tomllib.loads('value = ' + literal)['value']
    if type(value) not in (str, int, bool) or type(value) is not type(target[parts[-1]]):
        raise ValueError('This editor supports existing scalar settings of the same type')
    section = ''; changed = 0; lines = []
    for line in old.splitlines(keepends=True):
        match = re.match(r'^\s*\[([^\]]+)\]\s*(?:#.*)?$', line.strip())
        if match: section = match.group(1)
        if line.lstrip().startswith('[['): section = '<array>'
        match = re.match(r'^(\s*)([a-z_]+)\s*=', line)
        if match and '.'.join(filter(None, (section, match.group(2)))) == key:
            line = match.group(1) + match.group(2) + ' = ' + literal + '\n'; changed += 1
        lines.append(line)
    if changed != 1: raise ValueError('Setting is not an editable single-line scalar')
    candidate = ''.join(lines)
    handle, name = tempfile.mkstemp(prefix='.bcl-config-', suffix='.toml', dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(handle, 'w') as stream: stream.write(candidate)
        workflow.config(temporary)
        if path.read_text() != old: raise ValueError('Configuration changed concurrently; reload before editing')
        backup = path.with_name(path.name + '.backup-' + temporary.stem)
        shutil.copy2(path, backup)
        shutil.copymode(path, temporary)
        os.replace(temporary, path)
        return {'status': 'PASS', 'detail': 'Configuration validated and saved', 'backup': str(backup)}
    finally:
        temporary.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('describe', 'edit', 'run', 'open-report'))
    parser.add_argument('config', type=Path)
    parser.add_argument('value', nargs='?')
    args = parser.parse_args()
    if args.action == 'open-report':
        from open_report import open_report
        result=open_report(args.value)
    elif args.action == 'describe': result = describe(args.config,args.value)
    elif args.action == 'edit': result = edit(args.config, args.value or '')
    else:
        if not args.value: raise ValueError('Select an input file first')
        # Process.destroy sends SIGTERM on Linux. Let the existing Runner kill its
        # process groups and Workflow finalize its partial evidence on cancellation.
        def cancel(signum, frame): raise KeyboardInterrupt()
        signal.signal(signal.SIGTERM, cancel)
        return workflow.main([args.value, '--config', str(args.config)])
    print(json.dumps(result))
    return 0


if __name__ == '__main__':
    try: raise SystemExit(main())
    except (ValueError, OSError, RuntimeError) as error:
        print(json.dumps({'status': 'UNAVAILABLE', 'detail': str(error)})); raise SystemExit(2)
