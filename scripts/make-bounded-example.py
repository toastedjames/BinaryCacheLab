#!/usr/bin/env python3
"""Reproduce the closed-model example ELF. This is a callable analysis fixture, not a Linux process."""
from pathlib import Path
import json
import struct


def make(destination):
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    raw = bytearray(8192)
    raw[:7] = b'\x7fELF\x02\x01\x01'
    struct.pack_into('<HHIQQQ', raw, 16, 2, 62, 1, 0x400200, 64, 0xc00)
    struct.pack_into('<HHHHHH', raw, 52, 64, 56, 2, 64, 4, 1)
    struct.pack_into('<IIQQQQQQ', raw, 64, 1, 5, 0, 0x400000, 0, 0x1000, 0x1000, 0x1000)
    struct.pack_into('<IIQQQQQQ', raw, 120, 1, 6, 0x1000, 0x401000, 0, 0x1000, 0x1000, 0x1000)
    # mov eax,edi; shl rax,2; movabs rcx,0x401000; mov eax,[rcx+rax]; ret
    code = bytes.fromhex('89f8 48c1e002 48b90010400000000000 8b0401 c3')
    raw[0x200:0x200 + len(code)] = code
    struct.pack_into('<II', raw, 0x1000, 7, 7)
    names = b'\0.shstrtab\0.text\0.data\0'
    raw[0xb00:0xb00 + len(names)] = names
    struct.pack_into('<IIQQQQIIQQ', raw, 0xc40, 1, 3, 0, 0, 0xb00, len(names), 0, 0, 1, 0)
    struct.pack_into('<IIQQQQIIQQ', raw, 0xc80, 11, 1, 6, 0x400200, 0x200, len(code), 0, 0, 1, 0)
    struct.pack_into('<IIQQQQIIQQ', raw, 0xcc0, 17, 1, 3, 0x401000, 0x1000, 8, 0, 0, 4, 0)
    (destination / 'lookup.elf').write_bytes(raw)
    profile = {
        'schema': 'bcl-bounded-references-1', 'binary': 'lookup.elf', 'entries': [0x400200],
        'regions': [{'name': 'table', 'address': 0x401000, 'size': 8}],
        'machine': {'runtime': 'closed-static-x86-64', 'instruction_set': 'bcl-x86-64-integer-1', 'register_defaults': 'zero',
                    'initial_registers': {}, 'flags': 'zero',
                    'memory_initialization': 'elf-file-bss-zero-stack-zero',
                    'stack': {'address': 0x700000, 'size': 4096}},
        'inputs': [{'register': 'rdi', 'values': [0, 1]}],
        'bounds': {'max_steps_per_execution': 100, 'max_total_steps': 1000, 'max_executions': 2,
                   'max_memory_bytes': 12288, 'max_reference_events': 100},
    }
    (destination / 'lookup.json').write_text(json.dumps(profile, indent=2) + '\n')
    return profile


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('new_directory', type=Path)
    args = parser.parse_args()
    if args.new_directory.exists():
        parser.error('Use a new directory; existing files are never overwritten by this command')
    make(args.new_directory)
