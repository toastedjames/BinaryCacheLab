"""Interactive Linux installation. No dependency is installed without consent."""
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
DEPS = ROOT / '.deps'
MANIFEST = json.loads((ROOT / 'scripts/dependencies.json').read_text())


def ask(message):
    while True:
        answer = input(message + ' [Y/N] ').strip().lower()
        if answer == 'y':
            return
        if answer == 'n':
            raise RuntimeError('Setup cancelled; no successful installation has been declared.')
        print('Enter Y or N.')


def run(args, **kwargs):
    print('  ' + shlex.join(list(map(str, args))), flush=True)
    return subprocess.run(list(map(str, args)), check=True, **kwargs)


def capture(args):
    try:
        result = subprocess.run(list(map(str, args)), capture_output=True, text=True, timeout=30)
        return result.returncode, result.stdout + result.stderr
    except (OSError, subprocess.TimeoutExpired):
        return 127, ''


def package(label, package_name, probes):
    if all(shutil.which(x) for x in probes):
        for probe in probes:
            code, _ = capture([probe, '-v' if probe == 'unzip' else '--version'])
            if code:
                break
        else:
            print(label + ': FOUND (system version)')
            return
    print(label + ': MISSING or unusable')
    print('This native toolchain component uses distribution libraries/package integration; installing isolated binaries is not offered.')
    if not shutil.which('apt-get'):
        raise RuntimeError('Install ' + package_name + ' using your supported system package manager, then rerun.')
    ask('Install ' + label + ' through apt system packages (' + package_name + ')?')
    priv = [] if os.geteuid() == 0 else ['sudo']
    run([*priv, 'apt-get', 'update'])
    run([*priv, 'apt-get', 'install', '-y', package_name])
    if not all(shutil.which(x) for x in probes):
        raise RuntimeError(label + ' is still unavailable')
    for probe in probes:
        if capture([probe, '-v' if probe == 'unzip' else '--version'])[0]:
            raise RuntimeError(label + ' failed its version check')


def official(url):
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != 'https' or parsed.hostname not in {
        'api.github.com', 'github.com', 'release-assets.githubusercontent.com',
        'objects.githubusercontent.com', 'raw.githubusercontent.com'}:
        raise RuntimeError('Unapproved download location: ' + url)


def fetch(url, target):
    official(url)
    request = urllib.request.Request(url, headers={'User-Agent': 'BinaryCacheLab-Setup'})
    with urllib.request.urlopen(request, timeout=120) as response:
        official(response.url)
        with target.open('wb') as stream:
            shutil.copyfileobj(response, stream)


def unpack_tar(archive, destination):
    with tarfile.open(archive) as tar:
        for member in tar.getmembers():
            path = Path(member.name)
            if path.is_absolute() or '..' in path.parts or not (member.isfile() or member.isdir() or member.issym() or member.islnk()):
                raise RuntimeError('Unsafe archive member: ' + member.name)
            if member.issym() or member.islnk():
                link = Path(member.linkname)
                if link.is_absolute() or '..' in link.parts:
                    raise RuntimeError('Unsafe archive link')
        # Python 3.11 maintenance releases differ in extraction-filter support.
        # The explicit member/link checks above apply on both paths.
        if hasattr(tarfile, 'data_filter'):
            tar.extractall(destination, filter='data')
        else:
            tar.extractall(destination)


def java():
    candidates = [DEPS / 'java/bin/java', os.environ.get('JAVA', 'java')]
    for candidate in candidates:
        code, version = capture([candidate, '-version'])
        match = re.search(r'version "(\d+)', version)
        path = shutil.which(str(candidate))
        if code == 0 and match and int(match[1]) >= 17 and path and (Path(path).resolve().parent / 'javac').is_file():
            print('Java JDK: FOUND (' + match[1] + ')')
            return Path(path).resolve().parent
    print('Java: missing/incompatible JDK; version 17+ with javac/jar required for a source clone.')
    ask('Download the pinned official Temurin JDK into .deps/java?')
    with tempfile.TemporaryDirectory(dir=DEPS, prefix='java-') as temporary:
        temp = Path(temporary)
        metadata = temp / 'release.json'
        tag = urllib.parse.quote(MANIFEST['java_release'], safe='')
        fetch('https://api.github.com/repos/' + MANIFEST['java_repository'] + '/releases/tags/' + tag, metadata)
        assets = {a['name']: a['browser_download_url'] for a in json.loads(metadata.read_text())['assets']}
        name = MANIFEST['java_archive']
        fetch(assets[name + '.sha256.txt'], temp / 'checksum')
        expected = (temp / 'checksum').read_text().split()[0]
        if not re.fullmatch('[0-9a-fA-F]{64}', expected):
            raise RuntimeError('Official checksum is malformed')
        fetch(assets[name], temp / 'jdk.tar.gz')
        if hashlib.file_digest((temp / 'jdk.tar.gz').open('rb'), 'sha256').hexdigest() != expected.lower():
            raise RuntimeError('JDK checksum mismatch; archive will not be executed')
        unpack_tar(temp / 'jdk.tar.gz', temp / 'unpacked')
        homes = list((temp / 'unpacked').glob('*/bin/javac'))
        if len(homes) != 1:
            raise RuntimeError('Unexpected JDK archive layout')
        target = DEPS / 'java'
        if target.exists():
            raise RuntimeError('Existing .deps/java is incompatible; move it aside manually before retrying')
        shutil.move(homes[0].parent.parent, target)
    return java()


def pin():
    candidates = [DEPS / 'pin/pin']
    if os.environ.get('PIN_ROOT'):
        candidates.append(Path(os.environ['PIN_ROOT']) / 'pin')
    if shutil.which('pin'):
        candidates.append(Path(shutil.which('pin')))
    for candidate in candidates:
        code, text = capture([candidate, '-version'])
        if code == 0 and re.search(r'\b4\.4\b', text):
            print('Intel PIN 4.4: FOUND')
            return candidate.resolve()
    print('Intel PIN 4.4 Linux x86-64 requires a separate Intel download and license acceptance.')
    print('Obtain it from https://www.intel.com/content/www/us/en/developer/articles/tool/pin-a-dynamic-binary-instrumentation-tool.html')
    ask('Continue by supplying your trusted PIN 4.4 kit or archive?')
    source = Path(input('Path to extracted kit directory or downloaded archive: ').strip()).expanduser().resolve(strict=True)
    if source.is_dir():
        code, text = capture([source / 'pin', '-version'])
        if code or not re.search(r'\b4\.4\b', text):
            raise RuntimeError('Supplied kit is not compatible PIN 4.4')
        return source / 'pin'
    expected = input('Trusted SHA-256 from your approved download source (required): ').strip().lower()
    if not re.fullmatch('[0-9a-f]{64}', expected) or hashlib.file_digest(source.open('rb'), 'sha256').hexdigest() != expected:
        raise RuntimeError('PIN archive checksum not supplied or mismatched; not extracting/executing')
    with tempfile.TemporaryDirectory(dir=DEPS, prefix='pin-') as temporary:
        temp = Path(temporary)
        unpack_tar(source, temp)
        matches = list(temp.glob('*/pin'))
        if len(matches) != 1 or (DEPS / 'pin').exists():
            raise RuntimeError('Unexpected PIN archive layout or existing incompatible .deps/pin')
        shutil.move(matches[0].parent, DEPS / 'pin')
    return pin()


def write_configuration(pin_path, tracer, image, sudo_docker):
    paths = [ROOT / 'bcl.toml'] + [ROOT / 'examples' / x / 'bcl.toml' for x in ('workflow', 'programs', 'protection')]
    replacements = {'tools.pin': str(pin_path), 'tools.tracer': str(tracer),
                    'tools.tracer_source': str(ROOT / 'fixtures/pin/WholeProgramMemoryTracer.cpp'),
                    'tools.docker_sudo': sudo_docker, 'lift.image': image}
    updates = []
    for path in paths:
        original = path.read_text(); section = ''; lines = []
        for line in original.splitlines():
            stripped = line.strip()
            if stripped.startswith('['):
                section = stripped.strip('[]')
            key = stripped.split('=', 1)[0].strip() if '=' in stripped and not stripped.startswith('#') else ''
            full = section + '.' + key
            if full in replacements:
                line = key + ' = ' + json.dumps(replacements[full])
            lines.append(line)
        updated = '\n'.join(lines) + '\n'
        if updated != original:
            updates.append((path, original, updated))
    if updates:
        print('Configuration files to update:\n' + '\n'.join(str(x[0].relative_to(ROOT)) for x in updates))
        ask('Update these configurations, keeping backups under .deps/config-backups?')
        backups = DEPS / 'config-backups'; backups.mkdir(exist_ok=True)
        for path, original, updated in updates:
            with tempfile.NamedTemporaryFile(mode='w', dir=backups, prefix=path.parent.name + '-', suffix='.toml', delete=False) as stream:
                stream.write(original)
            temporary = path.with_name(path.name + '.setup-tmp')
            with temporary.open('x') as stream:
                stream.write(updated)
            temporary.replace(path)


def main():
    if platform.system() != 'Linux' or platform.machine() != 'x86_64':
        raise RuntimeError('Only Linux x86-64 / WSL2 x86-64 is supported')
    release = platform.release().lower()
    if 'microsoft' in release and 'wsl2' not in release and 'microsoft-standard' not in release:
        raise RuntimeError('This appears to be WSL1. Convert the distribution to WSL2 before installation.')
    print('========================================\n       BinaryCacheLab Setup\n========================================')
    print('Environment: ' + ('WSL (WSL2 required)' if 'microsoft' in platform.release().lower() else 'native Linux'))
    DEPS.mkdir(exist_ok=True)
    lock = DEPS / 'setup.lock'
    try:
        fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        raise RuntimeError('Another setup may be running. If an interrupted setup left .deps/setup.lock, remove it after confirming no setup is active.')
    os.close(fd)
    try:
        java_bin = java()
        os.environ['PATH'] = str(java_bin) + os.pathsep + os.environ['PATH']
        for label, pkg, probes in [
            ('NASM', 'nasm', ['nasm']), ('C/C++ compiler and make', 'build-essential', ['gcc', 'g++', 'make']),
            ('GNU binary tools', 'binutils', ['ld', 'nm', 'readelf', 'objdump']),
            ('Linux utilities', 'util-linux', ['setarch']), ('Core utilities', 'coreutils', ['timeout', 'sha256sum']),
            ('Archive extraction', 'unzip', ['unzip']), ('HTTPS utility', 'curl', ['curl'])]:
            package(label, pkg, probes)
        package('Docker CLI/daemon', 'docker.io', ['docker'])
        docker = ['docker']
        if capture([*docker, 'info'])[0]:
            ask('Docker is inaccessible. Try authenticated sudo Docker? This does not configure/start the daemon.')
            run(['sudo', '-v'])
            docker = ['sudo', '-n', 'docker']
            run([*docker, 'info'], stdout=subprocess.DEVNULL)
        pin_path = pin()
        # The existing pinned FoxDec builder has no package installation side effects.
        import easy
        if easy.FOX_SHA != MANIFEST['foxdec_sha256'] or easy.FOX_URL != MANIFEST['foxdec_url']:
            raise RuntimeError('FoxDec dependency manifest differs from the reviewed integration')
        easy.STATE = DEPS / 'foxdec'
        easy.ENV = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
        runner = easy.Runner(); runner.docker = docker
        image = next((x for x in ('foxdec', 'bcl-foxdec:v0.7') if runner.image_works(x)), None)
        if image is None:
            print('FoxDec source is stored in .deps/foxdec; Docker layers are managed by Docker, outside .deps.')
            ask('Download the checksum-pinned official FoxDec release and build its Docker image (including GHC/Cabal downloads)?')
            image = runner.foxdec({})
        build = DEPS / 'tracer'; build.mkdir(exist_ok=True)
        tracer = build / 'obj-intel64/WholeProgramMemoryTracer.so'
        source = ROOT / 'fixtures/pin/WholeProgramMemoryTracer.cpp'
        source_hash = hashlib.sha256(source.read_bytes() + pin_path.read_bytes()).hexdigest()
        stamp = build / 'source.sha256'
        if not tracer.is_file() or not stamp.exists() or stamp.read_text() != source_hash:
            ask('Compile the BCL tracer locally against your licensed PIN kit?')
            shutil.copyfile(source, build / source.name)
            (build / 'Makefile').write_text('PIN_ROOT ?= /missing\nCONFIG_ROOT := $(PIN_ROOT)/source/tools/Config\ninclude $(CONFIG_ROOT)/makefile.config\nTOOL_ROOTS := WholeProgramMemoryTracer\ninclude $(TOOLS_ROOT)/Config/makefile.default.rules\n')
            run(['make', '-C', build, 'PIN_ROOT=' + str(pin_path.parent), 'obj-intel64/WholeProgramMemoryTracer.so'])
            stamp.write_text(source_hash)
        jar = ROOT / 'binarycachelab.jar'
        if not jar.exists():
            ask('Build the BCL Java application from this source clone?')
            classes = DEPS / 'classes'; classes.mkdir(exist_ok=True)
            sources = sorted((ROOT / 'src/main/java').rglob('*.java'))
            run([java_bin / 'javac', '--release', '17', '-encoding', 'UTF-8', '-d', classes, *sources])
            temporary = DEPS / 'application.jar'
            run([java_bin / 'jar', '--create', '--file', temporary, '--main-class', 'org.binarycachelab.BinaryCacheLabCli', '-C', classes, '.'])
            shutil.copyfile(temporary, jar)
            (ROOT / 'binarycachelab.jar.sha256').write_text(hashlib.sha256(jar.read_bytes()).hexdigest() + '  binarycachelab.jar\n')
        else:
            checksum = ROOT / 'binarycachelab.jar.sha256'
            if not checksum.exists() or checksum.read_text().split()[0] != hashlib.sha256(jar.read_bytes()).hexdigest():
                raise RuntimeError('Existing JAR has no matching checksum; restore a trusted JAR or move it aside and rerun setup')
        write_configuration(pin_path, tracer, image, len(docker) > 1)
        env = ROOT / '.deps/environment.sh'
        text = '# Generated by BCL setup; do not commit.\n'
        # Local JDK paths resolve against the launcher-defined BCL_ROOT after relocation.
        if java_bin.is_relative_to(ROOT):
            relative = java_bin.relative_to(ROOT).as_posix()
            text += 'export PATH="$BCL_ROOT/' + relative + ':$PATH"\n'
            text += 'export JAVA="$BCL_ROOT/' + relative + '/java"\n'
        else:
            text += 'export JAVA=' + shlex.quote(str(java_bin / 'java')) + '\n'
        text += 'export BCL_PYTHON=' + shlex.quote(sys.executable) + '\n'
        if env.exists() and env.read_text() != text:
            ask('Replace the existing generated .deps/environment.sh?')
        env.write_text(text)
        (ROOT / 'bcl').chmod((ROOT / 'bcl').stat().st_mode | 0o111)
        (ROOT / 'fixtures/group_lookup/original').chmod((ROOT / 'fixtures/group_lookup/original').stat().st_mode | 0o111)
        print('Setup complete. Launch: ./bcl tui\nProtected example: ./bcl protect examples/protection/tables.asm --config examples/protection/bcl.toml')
        print('Dependency checks completed; setup does not certify Stage 3 experiments. Run the documented tests separately.')
    finally:
        lock.unlink(missing_ok=True)


if __name__ == '__main__':
    try:
        main()
    except (Exception, KeyboardInterrupt) as error:
        print('Setup incomplete: ' + str(error), file=sys.stderr)
        sys.exit(2)
