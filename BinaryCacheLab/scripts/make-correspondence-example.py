#!/usr/bin/env python3
"""Reproduce an equivalent bounded ELF pair with code padding and relocated data."""
import json
from pathlib import Path
import runpy
import struct


def make(destination):
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    builder = runpy.run_path(str(Path(__file__).with_name('make-bounded-example.py')))['make']
    builder(destination / 'original')
    rebuilt = builder(destination / 'rebuilt')
    binary = destination / 'rebuilt/lookup.elf'
    raw = bytearray(binary.read_bytes())
    code = b'\x90' + bytes(raw[0x200:0x214])
    raw[0x200:0x200 + len(code)] = code
    struct.pack_into('<Q', raw, 0x209, 0x401040)
    raw[0x1040:0x1048] = raw[0x1000:0x1008]
    struct.pack_into('<Q', raw, 0xca0, len(code))
    struct.pack_into('<Q', raw, 0xcd0, 0x401040)
    struct.pack_into('<Q', raw, 0xcd8, 0x1040)
    binary.write_bytes(raw)
    rebuilt['regions'][0]['address'] = 0x401040
    (destination / 'rebuilt/lookup.json').write_text(json.dumps(rebuilt, indent=2) + '\n')
    pair = {
        'schema': 'bcl-bounded-correspondence-1', 'abi': 'sysv-amd64-integer',
        'original': 'original/lookup.json', 'rebuilt': 'rebuilt/lookup.json',
        'entries': [{'original': 0x400200, 'rebuilt': 0x400200}],
        'control_map': [{'original': 0x400213, 'rebuilt': 0x400214}],
        'memory_maps': [{'name': 'table', 'original': 0x401000, 'rebuilt': 0x401040, 'size': 8}],
        'input_map': [{'original': 0, 'rebuilt': 0, 'encoding': 'scalar'}],
        'register_outputs': [{'register': 'rax', 'encoding': 'scalar'}],
    }
    (destination / 'correspondence.json').write_text(json.dumps(pair, indent=2) + '\n')
    project = {'schema': 'bcl-project-1', 'original': 'original/lookup.elf',
               'rebuilt': 'rebuilt/lookup.elf', 'output': 'experiments',
               'correspondence': 'correspondence.json'}
    (destination / 'project.json').write_text(json.dumps(project, indent=2) + '\n')
    return pair


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('new_directory', type=Path)
    args = parser.parse_args()
    if args.new_directory.exists():
        parser.error('Use a new directory; existing files are never overwritten by this command')
    make(args.new_directory)
