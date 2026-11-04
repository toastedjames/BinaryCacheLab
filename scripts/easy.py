#!/usr/bin/env python3
"""One-command setup and demo for the bundled fixture on Ubuntu/Debian WSL."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
import urllib.error
import zipfile
import runpy
sys.dont_write_bytecode = True
from readable import render, label

ROOT = Path(__file__).resolve().parent.parent
STATE = ROOT / '.bcl'
ENV = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
FOX_URL = 'https://raw.githubusercontent.com/ssrg-vt/FoxDec/0abd8c85cda0ccf3da9ef6683acb77a99c04b8b6/foxdec/release/FoxDec.zip'
FOX_SHA = '783ab34ac419fb00646994db520ab1c943382773002f0797bdbf80592b7ed262'
PIN_URL = 'https://software.intel.com/sites/landingpage/pintool/downloads/pin-external-4.4-99977-g54fbb8814-gcc-linux.tar.gz'


def say(text):
    print(text, flush=True)


def read(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def save(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + '.tmp')
    temporary.write_text(json.dumps(data, indent=2) + '\n', encoding='utf-8')
    temporary.replace(path)


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def config_values():
    values, section = {}, ''
    for line in (ROOT / 'bcl.toml').read_text().splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if line.startswith('[') and line.endswith(']'):
            section = line[1:-1]
        elif '=' in line:
            key, raw = map(str.strip, line.split('=', 1))
            try:
                values[section + '.' + key] = json.loads(raw)
            except ValueError:
                try:
                    values[section + '.' + key] = int(raw, 0)
                except ValueError:
                    pass
    return values


def resolve(value):
    path = Path(str(value)).expanduser()
    return path if path.is_absolute() else ROOT / path


def configure(changes):
    path = ROOT / 'bcl.toml'
    text = path.read_text()
    lines, seen, section = [], set(), ''
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith('[') and stripped.endswith(']'):
            section = stripped[1:-1]
        elif '=' in stripped and not stripped.startswith('#'):
            key = stripped.split('=', 1)[0].strip()
            full = section + '.' + key
            if full in changes:
                line = key + ' = ' + json.dumps(changes[full])
                seen.add(full)
        lines.append(line)
    if set(changes) != seen:
        raise ValueError('Configuration is missing required fields: ' + ', '.join(set(changes) - seen))
    updated = '\n'.join(lines) + '\n'
    if updated != text:
        backups = STATE / 'config-backups'
        backups.mkdir(parents=True, exist_ok=True)
        descriptor, filename = tempfile.mkstemp(prefix='bcl-', suffix='.toml', dir=backups)
        os.close(descriptor)
        backup = Path(filename)
        backup.write_text(text)
        temporary = path.with_name('bcl.toml.new')
        temporary.write_text(updated)
        temporary.replace(path)


def command_process_options():
    # Keep the controlling terminal so sudo's per-terminal credentials remain
    # available. A separate process group still lets cancellation stop children.
    if not sys.platform.startswith('linux'):
        return {}
    if sys.version_info >= (3, 11):
        return {'process_group': 0}
    # The launcher is single threaded; support Ubuntu's Python 3.10 as well.
    return {'preexec_fn': os.setpgrp}


def kill_group(process):
    if process.poll() is None:
        if sys.platform.startswith('linux'):
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        else:
            process.terminate()
        try:
            process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            if sys.platform.startswith('linux'):
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            else:
                process.kill()
            process.wait()


class Runner:
    def __init__(self):
        (STATE / 'logs').mkdir(parents=True, exist_ok=True)
        self.logs = Path(tempfile.mkdtemp(prefix='session-', dir=STATE / 'logs'))
        self.number = 0
        self.priv = []
        self.docker = []

    def command(self, name, argv, allowed=(0,), seconds=600, cwd=None):
        self.number += 1
        log = self.logs / f'{self.number:02d}-{name}.log'
        save(log.with_suffix('.command.json'), {'argv': list(map(str, argv)), 'cwd': str(cwd or ROOT)})
        say(f'  Working: {name.replace("-", " ")}')
        with log.open('w', encoding='utf-8') as output:
            process = subprocess.Popen(list(map(str, argv)), cwd=cwd or ROOT,
                stdout=output, stderr=subprocess.STDOUT, env=ENV,
                **command_process_options())
            start = time.monotonic()
            heartbeat = start
            try:
                while process.poll() is None:
                    if time.monotonic() - start > seconds:
                        raise TimeoutError(f'{name} exceeded {seconds} seconds. Log: {log}')
                    if time.monotonic() - heartbeat >= 20:
                        say(f'    Still working ({int(time.monotonic()-start)}s). Log: {log}')
                        heartbeat = time.monotonic()
                    time.sleep(0.2)
            except BaseException:
                kill_group(process)
                raise
        text = log.read_text(errors='replace')
        save(log.with_suffix('.exit.json'), {'exit': process.returncode})
        if process.returncode not in allowed:
            # Keep JSON out of the terminal even when a command fails.
            tail = [line for line in text.splitlines() if line and not line.startswith('{')][-6:]
            raise RuntimeError(f'{name} failed (exit {process.returncode}).\n' + '\n'.join(tail) + f'\nFull log: {log}')
        say(f'  Done:    {name.replace("-", " ")}')
        return text, process.returncode

    def capture(self, argv, seconds=20):
        try:
            result = subprocess.run(list(map(str, argv)), stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, text=True, errors='replace', timeout=seconds, env=ENV)
            return result.returncode, result.stdout
        except (OSError, subprocess.TimeoutExpired) as error:
            return 2, str(error)

    def privilege(self):
        if hasattr(os, 'geteuid') and os.geteuid() == 0:
            return []
        if not shutil.which('sudo'):
            raise RuntimeError('Administrator access is needed to install missing packages; sudo is unavailable.')
        say('  Administrator access is needed for Docker or system packages (sudo may ask for your password).')
        if subprocess.call(['sudo', '-v']) != 0:
            raise RuntimeError('Could not obtain administrator access.')
        self.priv = ['sudo', '-n', '--']
        return self.priv

    def packages(self):
        required = {'gcc': 'build-essential', 'g++': 'build-essential', 'make': 'build-essential',
            'nasm': 'nasm', 'objdump': 'binutils', 'nm': 'binutils', 'setarch': 'util-linux',
            'timeout': 'coreutils', 'unzip': 'unzip', 'curl': 'curl'}
        missing = {package for tool, package in required.items() if not shutil.which(tool)}
        java = os.environ.get('JAVA', 'java')
        code, version = self.capture([java, '-version'])
        match = re.search(r'version "(\d+)', version)
        if code or not match or int(match.group(1)) < 17:
            missing.add('openjdk-17-jre-headless')
        if not shutil.which('docker'):
            missing.add('docker.io')
        if missing:
            if not shutil.which('apt-get'):
                raise RuntimeError('Automatic package installation supports Ubuntu/Debian. Missing: ' + ', '.join(sorted(missing)))
            priv = self.privilege()
            self.command('package-index', [*priv, 'apt-get', 'update'], seconds=900)
            self.command('install-packages', [*priv, 'apt-get', 'install', '-y', *sorted(missing), 'ca-certificates'], seconds=1800)
        code, version = self.capture([java, '-version'])
        match = re.search(r'version "(\d+)', version)
        if code or not match or int(match.group(1)) < 17:
            raise RuntimeError('Java 17+ is required; an older JAVA override may still be selected.')
        say('  Ready: Java, Python, GCC, NASM, binutils, and execution controls')

    def docker_access(self):
        code, _ = self.capture(['docker', 'info'])
        if code == 0:
            self.docker = ['docker']
            return
        priv = self.privilege()
        code, _ = self.capture([*priv, 'docker', 'info'])
        if code:
            for argv in ([*priv, 'systemctl', 'start', 'docker'], [*priv, 'service', 'docker', 'start']):
                self.capture(argv, seconds=40)
                code, _ = self.capture([*priv, 'docker', 'info'])
                if code == 0:
                    break
        if code:
            raise RuntimeError('Docker is installed but its engine is unreachable. Start Docker Desktop with WSL integration, or enable the Linux Docker service, then rerun bash start.sh.')
        self.docker = [*priv, 'docker']

    def find_pin(self, values):
        candidates = []
        if os.environ.get('PIN_ROOT'):
            candidates.append(Path(os.environ['PIN_ROOT']) / 'pin')
        if values.get('tools.pin'):
            candidates.append(resolve(values['tools.pin']))
        if shutil.which('pin'):
            candidates.append(Path(shutil.which('pin')))
        bases = [ROOT / 'tools', ROOT / '.bcl/tools', Path.home() / 'BinaryCacheLab/tools',
                 Path.home() / 'tools', Path.home() / 'Downloads', Path('/opt')]
        for base in bases:
            for pattern in ('pin-*/pin', 'pin-*/kit/pin', 'pin/pin'):
                candidates.extend(sorted(base.glob(pattern)))
        for path in candidates:
            if path.is_file() and os.access(path, os.X_OK):
                code, text = self.capture([path, '-version'])
                if code == 0 and re.search(r'\b4\.4\b', text):
                    return path.resolve()
        return None

    def pin_and_tracer(self, values):
        pin = self.find_pin(values)
        if pin is None:
            say('  Installing PIN 4.4 from Intel. License: https://www.intel.com/content/www/us/en/developer/articles/tool/pin-a-dynamic-binary-instrumentation-tool.html')
            archive = STATE / 'downloads/pin-4.4.tar.gz'
            local = list((Path.home() / 'Downloads').glob('pin*4.4*linux.tar.gz'))
            if local:
                archive = sorted(local)[0]
                say('  Using downloaded PIN archive: ' + str(archive))
            else:
                try:
                    download(PIN_URL, archive)
                except urllib.error.HTTPError as error:
                    raise RuntimeError('Intel refused the PIN download (HTTP ' + str(error.code) + '). '
                        'Download the Linux PIN 4.4 kit from Intel into ~/Downloads, then rerun this script; '
                        'it will find and extract that archive automatically. Existing working PIN kits are always reused.') from error
            target = STATE / 'tools'
            target.mkdir(parents=True, exist_ok=True)
            with tarfile.open(archive) as kit:
                safe_tar(kit, target)
            pin = self.find_pin(values)
            if pin is None:
                raise RuntimeError('Downloaded PIN kit did not provide a working PIN 4.4 executable.')
        say(f'  Ready: PIN at {pin}')
        tracer = resolve(values.get('tools.tracer', 'fixtures/pin/WholeProgramMemoryTracer.so'))
        source = resolve(values.get('tools.tracer_source', 'fixtures/pin/WholeProgramMemoryTracer.cpp'))
        if not tracer.is_file():
            tracer = ROOT / 'fixtures/pin/WholeProgramMemoryTracer.so'
            source = ROOT / 'fixtures/pin/WholeProgramMemoryTracer.cpp'
        smoke = Path(tempfile.mkdtemp(prefix='pin-smoke-', dir=self.logs))
        def probe(path):
            argv = [pin, '-t', path, '-o', smoke / 'trace.csv', '-images', smoke / 'images.csv',
                    '-meta', smoke / 'trace.properties', '-maps', smoke / 'maps.log', '--', '/bin/true']
            code, _ = self.capture(argv, seconds=45)
            metadata = smoke / 'trace.properties'
            return code == 0 and metadata.is_file() and 'status=complete' in metadata.read_text()
        if not source.is_file() or not probe(tracer):
            build = STATE / 'native'
            build.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / 'fixtures/pin/WholeProgramMemoryTracer.cpp', build / 'WholeProgramMemoryTracer.cpp')
            source = build / 'WholeProgramMemoryTracer.cpp'
            (build / 'Makefile').write_text('PIN_ROOT ?= /missing\nCONFIG_ROOT := $(PIN_ROOT)/source/tools/Config\ninclude $(CONFIG_ROOT)/makefile.config\nTOOL_ROOTS := WholeProgramMemoryTracer\ninclude $(TOOLS_ROOT)/Config/makefile.default.rules\n')
            self.command('build-tracer', ['make', '-C', build, 'PIN_ROOT=' + str(pin.parent), 'obj-intel64/WholeProgramMemoryTracer.so'])
            tracer = build / 'obj-intel64/WholeProgramMemoryTracer.so'
            if not probe(tracer):
                raise RuntimeError('The tracer failed its PIN smoke check. Inspect ' + str(smoke))
        say('  Ready: PIN loaded the tracer and recorded a complete smoke trace')
        return pin, tracer, source

    def image_works(self, image):
        code, _ = self.capture([*self.docker, 'image', 'inspect', image])
        if code:
            return False
        name = 'bcl-setup-' + os.urandom(6).hex()
        try:
            code, text = self.capture([*self.docker, 'run', '--rm', '--name', name, '--entrypoint', '/bin/bash', image,
                '-c', 'set -eu; command -v ghc; cd /FoxDec/foxdec_v0.7; test -f config/config.dhall; p=$(cabal list-bin foxdec-exe); test -x "$p"'], seconds=120)
            return code == 0
        finally:
            self.capture([*self.docker, 'rm', '-f', name])

    def foxdec(self, values):
        images = [str(values.get('lift.image', 'foxdec')), 'foxdec', 'bcl-foxdec:v0.7']
        code, text = self.capture([*self.docker, 'image', 'ls', '--format', '{{.Repository}}:{{.Tag}}'])
        if not code:
            images += [line for line in text.splitlines() if 'foxdec' in line.lower()]
        for image in dict.fromkeys(images):
            if self.image_works(image):
                say(f'  Ready: compatible FoxDec image {image}')
                return image
        say('  Building FoxDec from its official pinned Docker release. First installation can take a while.')
        archive = STATE / 'downloads/FoxDec.zip'
        download(FOX_URL, archive, FOX_SHA)
        source = STATE / 'foxdec-source'
        with zipfile.ZipFile(archive) as release:
            safe_zip(release, source)
        context = source / 'FoxDec'
        original = (context / 'Dockerfile').read_text()
        if not original.startswith('FROM haskell:9\n'):
            raise RuntimeError('Official FoxDec Dockerfile layout changed; refusing an unreviewed installer recipe.')
        # Same official v0.7 release, with GHC pinned to the compiler used in the recorded installation.
        (context / 'Dockerfile.bcl').write_text(original.replace('FROM haskell:9\n', 'FROM haskell:9.6.7\n', 1))
        image = 'bcl-foxdec:v0.7'
        self.command('install-foxdec', [*self.docker, 'build', '-f', context / 'Dockerfile.bcl', '-t', image, context], seconds=10800)
        if self.docker[0] == 'sudo' and subprocess.call(['sudo', '-v']) != 0:
            raise RuntimeError('FoxDec built, but sudo access expired. Rerun setup to finish detection.')
        if not self.image_works(image):
            raise RuntimeError('FoxDec image built but failed the compatibility check. Logs: ' + str(self.logs))
        return image

    def setup(self):
        if platform.system() != 'Linux' or platform.machine() not in ('x86_64', 'amd64'):
            raise RuntimeError('Automatic setup requires x86-64 Linux/WSL. Use report or check to inspect files elsewhere.')
        say('\nBinaryCacheLab setup\n====================')
        self.packages()
        expected = (ROOT / 'binarycachelab.jar.sha256').read_text().split()[0]
        if sha(ROOT / 'binarycachelab.jar') != expected:
            raise RuntimeError('Application checksum mismatch; extract a fresh package.')
        (ROOT / 'bcl').chmod((ROOT / 'bcl').stat().st_mode | 0o111)
        original = resolve(config_values()['input.original'])
        original.chmod(original.stat().st_mode | 0o111)
        code, _ = self.capture(['setarch', 'x86_64', '-R', '/bin/true'])
        if code:
            raise RuntimeError('This environment blocks setarch -R, which the raw-address repeat controls require. Run in WSL directly with that permission; do not disable the checker to obtain a verdict.')
        values = config_values()
        pin, tracer, source = self.pin_and_tracer(values)
        self.docker_access()
        image = self.foxdec(values)
        configure({'tools.pin': str(pin), 'tools.tracer': str(tracer),
            'tools.tracer_source': str(source),
            'tools.python': sys.executable, 'tools.backend': str(ROOT / 'backend'),
            'lift.enabled': True, 'lift.image': image, 'tools.docker_sudo': 'sudo' in self.docker})
        save(STATE / 'setup.json', {'schema': 'bcl-easy-setup-1', 'pin': str(pin),
            'tracer': str(tracer), 'image': image, 'log_directory': str(self.logs)})
        say('\nSetup complete. Paths and Docker access were configured automatically.')

    def demo(self):
        state = {'schema': 'bcl-easy-demo-1', 'status': 'RUNNING', 'log_directory': str(self.logs)}
        save(STATE / 'latest-demo.json', state)
        try:
            self.setup()
            java = os.environ.get('JAVA', 'java')
            for suite in ('layout-suite', 'qualification-suite'):
                self.command(suite, [java, '-jar', ROOT / 'binarycachelab.jar', 'suite', ROOT / f'examples/{suite}.json'], seconds=1800)
            text, _ = self.command('fresh-three-layout-experiment', [java, '-jar', ROOT / 'binarycachelab.jar', 'demo-fixture', '--config', ROOT / 'bcl.toml'], seconds=10800)
            match = re.search(r'^Experiment: (.+)$', text, re.M)
            if not match:
                raise RuntimeError('Build completed without an experiment location. Inspect the build log.')
            build = Path(match.group(1).strip())
            state['build'] = str(build)
            save(STATE / 'latest-demo.json', state)
            summary = read(build / 'summary.json')
            if summary.get('status') != 'DEMO_EXPECTATIONS_MET' or summary.get('workflow_mode') != 'CONTROLLED_FIXTURE_EXPERIMENT':
                raise RuntimeError('Fresh layout experiment did not meet its recorded controls.')
            verification = self.logs / 'verification.json'
            self.command('verify-fresh-evidence', [java, '-jar', ROOT / 'binarycachelab.jar', 'verify', build, '--report', verification], seconds=900)
            checked = read(verification)
            if checked.get('status') != 'RECORDED_EXPECTATIONS_CONFIRMED' or checked.get('callback_entry_mapping_replayed') is not True:
                raise RuntimeError('Fresh evidence verification did not confirm linked callback mappings.')
            state['evidence_verified'] = True
            assessment_path = self.logs / 'assessment.json'
            self.command('assess-fresh-references', [java, '-jar', ROOT / 'binarycachelab.jar', 'assess-references', build, '--report', assessment_path], allowed=(6, 7), seconds=600)
            assessment = read(assessment_path)
            state['assessment'] = str(assessment_path)
            state['safety_decision'] = assessment['decision']
            state['variants'] = {name: {'verdict': summary['variants'][name]['verdict'],
                'report': str(build / name / 'comparison.json')} for name in ('baseline', 'shifted', 'protected')}
            state['verdict'] = state['variants']['baseline']['verdict']
            save(STATE / 'latest-demo.json', state)
            state['detector_control'] = self.detector_control(java, build)
            state['status'] = 'COMPLETED'
            save(STATE / 'latest-demo.json', state)
            show_latest(detailed=False)
            return 0
        except BaseException as error:
            state.update(status='INTERRUPTED' if isinstance(error, KeyboardInterrupt) else 'FAILED', error=str(error))
            save(STATE / 'latest-demo.json', state)
            raise

    def detector_control(self, java, build):
        """Fresh leaky-original detection control; both sides deliberately use the same ELF."""
        control = self.logs / 'secret-dependent-control'
        control.mkdir()
        for name in ('secret_line.c', 'fixture.h'):
            shutil.copy2(ROOT / 'examples/benchmarks' / name, control / name)
        binary = control / 'program'
        self.command('build-secret-dependent-control', ['gcc', '-std=c11', '-O1', '-g', '-fPIE', '-pie', control / 'secret_line.c', '-o', binary])
        values = config_values()
        repetitions, timeout = int(values['experiment.repetitions']), int(values['experiment.timeout'])
        backend = build / 'inputs/backend'
        collect = [sys.executable, backend / 'collect_whole.py', '--original', binary, '--rebuilt', binary,
            '--pin', resolve(values['tools.pin']), '--tool', build / 'inputs/tracer.so',
            '--tool-source', build / 'inputs/tracer.cpp', '--secret-0', '0', '--secret-1', '1',
            '--repetitions', str(repetitions), '--timeout', str(timeout), '--output-parent', control]
        if values.get('experiment.eager_binding'):
            collect.append('--eager-binding')
        self.command('collect-secret-dependent-control', collect, seconds=timeout*repetitions*8+180)
        batches = list(control.glob('whole-collection-*'))
        if len(batches) != 1:
            raise RuntimeError('Expected one collection for the secret-dependent control.')
        python_report, java_report = control / 'python-comparison.json', control / 'java-comparison.json'
        _, python_exit = self.command('check-secret-dependent-python', [sys.executable, backend / 'whole_trace_check.py', batches[0],
            '--repetitions', str(repetitions), '--line-size', '64', '--report', python_report], allowed=(0, 2, 3, 4, 5))
        _, java_exit = self.command('check-secret-dependent-java', [java, '-jar', ROOT / 'binarycachelab.jar', 'pin-check-java', batches[0],
            '--repetitions', str(repetitions), '--report', java_report], allowed=(0, 2, 3, 4, 5))
        agreement = runpy.run_path(str(ROOT / 'scripts/validate-baseline.py'))['agree']
        verdict = agreement(read(python_report), read(java_report), python_exit, java_exit)
        if verdict != 'ORIGINAL_OBSERVATIONS_DIFFER' or java_exit != 5:
            raise RuntimeError('The deliberate secret-dependent control did not reveal the expected original distinction.')
        record = {'schema': 'bcl-detector-control-1', 'verdict': verdict, 'report': str(python_report),
            'binary_sha256': sha(binary), 'source_sha256': sha(control / 'secret_line.c'),
            'header_sha256': sha(control / 'fixture.h'), 'python_java_agreement': True,
            'scope': 'Detector control: same freshly compiled C binary on both sides; this is not a FoxDec rebuild comparison.'}
        save(control / 'control.json', record)
        return record


def download(url, target, expected=None):
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.is_file() and expected and sha(target) == expected:
        return
    partial = target.with_suffix(target.suffix + '.partial')
    say('  Download: ' + url)
    request = urllib.request.Request(url, headers={'User-Agent': 'BinaryCacheLab/1.0'})
    with urllib.request.urlopen(request, timeout=90) as source, partial.open('wb') as output:
        shutil.copyfileobj(source, output)
    if expected and sha(partial) != expected:
        raise RuntimeError('Download checksum mismatch: ' + str(partial))
    partial.replace(target)
    save(target.with_suffix(target.suffix + '.download.json'), {'url': url, 'sha256': sha(target)})


def within(path, directory):
    return path == directory or directory in path.parents


def safe_zip(archive, target):
    target = target.resolve()
    for member in archive.infolist():
        if not within((target / member.filename).resolve(), target) or (member.external_attr >> 16) & 0o170000 == 0o120000:
            raise ValueError('Unsafe path in ZIP')
    target.mkdir(parents=True, exist_ok=True)
    archive.extractall(target)


def safe_tar(archive, target):
    target = target.resolve()
    for member in archive.getmembers():
        destination = (target / member.name).resolve()
        if not within(destination, target) or member.isdev() or member.isfifo():
            raise ValueError('Unsafe path in PIN archive')
        if member.issym() or member.islnk():
            base = destination.parent if member.issym() else target
            if not within((base / member.linkname).resolve(), target):
                raise ValueError('Unsafe link in PIN archive')
    archive.extractall(target)


def show_latest(detailed=True):
    path = STATE / 'latest-demo.json'
    if not path.is_file():
        # Adopt an already completed manual validation without rerunning it.
        output = resolve(config_values().get('project.output', 'experiments'))
        candidates = sorted(output.glob('baseline-validation-*/summary.json'), key=lambda item: item.stat().st_mtime, reverse=True)
        for candidate in candidates:
            previous = read(candidate)
            if previous.get('status') == 'COMPARISON_COMPLETE':
                assessment = candidate.parent / 'assessment.json'
                record = {'schema': 'bcl-easy-demo-1', 'status': 'COMPLETED', 'discovered': True,
                    'build': previous.get('build_evidence'), 'validation': str(candidate.parent),
                    'verdict': previous.get('observation_verdict'), 'log_directory': str(candidate.parent)}
                if assessment.is_file():
                    record['safety_decision'] = read(assessment).get('decision')
                save(path, record)
                break
        else:
            say('No completed baseline validation was found. Start one with: bash start.sh')
            return
    record = read(path)
    parts = [render(record)]
    for name, variant in record.get('variants', {}).items():
        report = Path(variant['report'])
        if report.is_file():
            parts.append('\nFresh ' + name + ' variant')
            parts.append(render(read(report)))
    if record.get('assessment') and Path(record['assessment']).is_file():
        parts.append(render(read(record['assessment'])))
    if record.get('detector_control'):
        parts.append('\nFresh detector control (same C binary on both sides)')
        parts.append(render(read(record['detector_control']['report'])))
    validation = Path(record['validation']) if record.get('validation') else None
    if validation:
        for name in ('python-comparison.json', 'assessment.json'):
            if (validation / name).is_file():
                parts.append(render(read(validation / name)))
    if record.get('historical_verified'):
        parts.append('\nHistorical controls (earlier linked binaries; callback caveat applies)\n===================================================================')
        for name in ('shifted', 'protected'):
            report = ROOT / f'historical-evidence/stage3-864527925292488627/{name}/comparison.json'
            parts.append(f'  {name:12} {label(read(report)["verdict"])}')
    text = '\n'.join(parts)
    (STATE / 'latest-report.txt').write_text(text + '\n')
    say(text if detailed else render(record))
    say('\nReadable report saved: ' + str(STATE / 'latest-report.txt'))


def main():
    parser = argparse.ArgumentParser(description='BinaryCacheLab: automatic setup, fresh demo, and readable results.')
    parser.add_argument('command', nargs='?', choices=['demo', 'setup', 'check', 'report'], default='demo')
    parser.add_argument('path', nargs='?', help='Optional saved JSON report for the report command')
    args = parser.parse_args()
    if args.command == 'report':
        if args.path:
            say(render(read(args.path)))
        else:
            show_latest()
        return 0
    if args.command == 'check':
        say('\nDependency discovery (no installs or experiments)\n================================================')
        for name in ('java', 'python3', 'gcc', 'nasm', 'objdump', 'docker'):
            say(f'  {name:12} {shutil.which(name) or "missing"}')
        runner = Runner()
        pin = runner.find_pin(config_values())
        say('  PIN 4.4     ' + (str(pin) if pin else 'not found in the standard locations'))
        return 0
    runner = Runner()
    if args.command == 'setup':
        runner.setup()
        return 0
    return runner.demo()


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        say('\nCancelled. Partial logs and evidence were kept.')
        sys.exit(130)
    except Exception as error:
        say('\nCould not complete this step\n============================')
        say(str(error))
        say('Fix the reported dependency and rerun bash start.sh. Previous evidence is retained.')
        sys.exit(2)
