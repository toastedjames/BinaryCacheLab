"""Generate a complete automatic literal-region rewrite example."""
from pathlib import Path
import json
import runpy

def make(destination):
    runpy.run_path(str(Path(__file__).with_name('make-bounded-example.py')))['make'](destination / 'original')
    policy = {'schema': 'bcl-automatic-rewrite-1', 'original': 'original/lookup.json',
              'regions': [{'name': 'table', 'address': 0x401000, 'size': 8, 'alignment': 4}],
              'destinations': [0x401004, 0x401040], 'secret_inputs': [0],
              'register_outputs': [{'register': 'rax', 'encoding': 'scalar'}]}
    (destination / 'rewrite.json').write_text(json.dumps(policy, indent=2) + '\n')
    return policy

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('new_directory', type=Path)
    args = parser.parse_args()
    if args.new_directory.exists(): parser.error('Use a new directory')
    make(args.new_directory)
