"""Generate a complete bounded transformation approval example."""
from pathlib import Path
import json
import runpy

def make(destination):
    runpy.run_path(str(Path(__file__).with_name('make-correspondence-example.py')))['make'](destination)
    policy = {'schema': 'bcl-bounded-transformation-1', 'correspondence': 'correspondence.json',
              'observer': {'policy': 'ordered-raw-virtual-lines', 'line_bytes': 64},
              'secret_inputs': [0], 'require_nonvacuous': True,
              'layout': {'policy': 'preserve-byte-line-partition', 'regions': [{'name': 'table', 'alignment': 4}]}}
    (destination / 'approval.json').write_text(json.dumps(policy, indent=2) + '\n')
    project = json.loads((destination / 'project.json').read_text())
    project['approval'] = 'approval.json'
    (destination / 'project.json').write_text(json.dumps(project, indent=2) + '\n')
    return policy

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('new_directory', type=Path)
    args = parser.parse_args()
    if args.new_directory.exists():
        parser.error('Use a new directory')
    make(args.new_directory)
