#!/usr/bin/env python3
"""Readable CLI adapter; Java APIs and --report JSON stay unchanged."""
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
sys.dont_write_bytecode = True
from readable import render


def tui_call(command,environment,args,action=None):
    """Authenticate before Java's input reader starts; never prompt in the worker."""
    admin=False
    try:
        import tomllib
        config=tomllib.loads(Path(args[args.index('--config')+1]).read_text())
        lift=config.get('lift',{})
        tools=config.get('tools',{})
        if not isinstance(lift,dict) or not isinstance(tools,dict):raise ValueError('Invalid tool configuration')
        admin=sys.platform.startswith('linux') and tools.get('docker_sudo') is True and (lift.get('adapter')=='foxdec' or lift.get('enabled') is True)
    except (ImportError,ValueError,KeyError,IndexError,OSError):pass
    stop=threading.Event();keeper=None
    def renew():
        while not stop.wait(45):
            try:subprocess.run(['sudo','-n','-v'],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10)
            except (OSError,subprocess.TimeoutExpired):return
    if admin:
        try:ready=subprocess.run(['sudo','-n','-v'],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10).returncode==0
        except (OSError,subprocess.TimeoutExpired):ready=False
        if not ready and sys.stdin.isatty():
            print('Docker needs administrator access; sudo may ask for your password.',flush=True)
            try:ready=subprocess.run(['sudo','-v']).returncode==0
            except OSError:ready=False
        if ready:
            keeper=threading.Thread(target=renew,daemon=True);keeper.start()
        else:print('Docker authentication unavailable; analysis preflight will report it without prompting in the background.',file=sys.stderr)
    try:return action() if action is not None else subprocess.call(command,env=environment)
    finally:
        stop.set()
        if keeper:keeper.join(timeout=2)

def main():
    root = Path(__file__).resolve().parent.parent
    args = sys.argv[1:]
    raw = '--json' in args
    args = [arg for arg in args if arg != '--json']
    if args and (args[0].lower().endswith('.asm') or Path(args[0]).is_file()):
        from workflow import main as workflow_main,select_config
        explicit=Path(args[args.index('--config')+1]) if '--config' in args else None
        configured=args if explicit is not None else [*args,'--config',str(select_config(Path(args[0])))]
        return tui_call([],dict(os.environ),configured,action=lambda:workflow_main(configured))
    if args and args[0] == 'qualify-broad':
        from qualify_broad import main as broad_main
        return broad_main(args[1:], raw=raw)
    if args and args[0] == 'rewrite':
        from automatic import main as automatic_main
        return automatic_main(args[1:], raw=raw)
    if args and args[0] == 'protect':
        from protection import main as protection_main
        return tui_call([],dict(os.environ),args,action=lambda:protection_main(args[1:]))
    if args and args[0] == 'project':
        from project import main as project_main
        return project_main(args[1:], raw=raw)
    if args and args[0] == 'report':
        if len(args) != 2:
            raise ValueError('Usage: ./bcl report FILE.json')
        data = json.loads(Path(args[1]).read_text())
        print(json.dumps(data, indent=2) if raw else render(data))
        return 0
    if not args:
        args = ['--help']
    if args[0]=='tui' and '--config' not in args:
        sample=root/'examples/workflow'
        if (sample/'bcl.toml').is_file():
            args += ['--config',str(sample/'bcl.toml')]
            if '--input' not in args:args += ['--input',str(sample/'sample1.asm')]
    if args[0] in {'tui','run','rebuild','demo-fixture','plan','assess','--doctor','--init','--last','history'} or args[0].endswith('.asm'):
        if '--config' not in args:
            args += ['--config', str(root / 'bcl.toml')]
    command = [os.environ.get('JAVA', 'java'), '-jar', str(root / 'binarycachelab.jar'), *args]
    environment = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', BCL_PYTHON=sys.executable, BCL_ROOT=str(root))
    if args[0] == 'tui':
        return tui_call(command,environment,args)
    if raw:
        return subprocess.call(command, env=environment)
    with subprocess.Popen(command, stdout=subprocess.PIPE, text=True, errors='replace', env=environment) as child:
        try:
            for line in child.stdout:
                try:
                    data = json.loads(line)
                except ValueError:
                    print(line, end='', flush=True)
                else:
                    print(render(data), flush=True)
            return child.wait()
        except KeyboardInterrupt:
            child.terminate()
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                child.kill(); child.wait()
            return 130

def entrypoint():
    try:
        return main()
    except KeyboardInterrupt:
        print('Cancelled; partial evidence is retained.', file=sys.stderr)
        return 130
    except (OSError, ValueError, RuntimeError) as error:
        print('ERROR: ' + str(error), file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(entrypoint())
