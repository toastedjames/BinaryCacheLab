"""Export a sealed run's comparisons without rerunning targets or modifying evidence."""
import argparse
import json
from pathlib import Path
import project
from workflow_text import render_report


def export(run,output=None):
    run=Path(run).resolve(strict=True)
    project.verify_manifest(run)
    output=Path(output).resolve() if output else run.parent/(run.name+'-trace-diff.txt')
    if output.is_relative_to(run):raise ValueError('Export outside the sealed evidence directory')
    report=project.read(run/'report.json')
    render_report(run,report,output)
    return output


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('run',type=Path);parser.add_argument('--output',type=Path)
    args=parser.parse_args();print(export(args.run,args.output))
