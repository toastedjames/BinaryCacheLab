"""Read-only integrity and cross-format consistency check; not execution attestation."""
import argparse
from collections import Counter
import csv
from itertools import zip_longest
import json
from pathlib import Path
import project
import workflow_events


def verify(root):
    root=Path(root).resolve(strict=True)
    files=project.verify_manifest(root)
    report=project.read(root/'report.json');manifest=project.read(root/'manifest.json')
    def require(condition,detail):
        if not condition:raise ValueError(detail)
    for name,digest in manifest['files'].items():
        path=root/name
        require(path.resolve().is_relative_to(root) and path.is_file(),'Invalid manifest path')
        require(workflow_events.sha(path)==digest,'Manifest hash differs: '+name)
    summary=(root/'summary.txt').read_text()
    require('OVERALL VERDICT: '+report['overall_verdict'] in summary,'Summary verdict differs')
    counts={}
    for variant,stats in report['event_statistics'].items():
        path=root/'traces'/(variant+'.jsonl');count=0
        if path.exists():
            with path.open() as stream:
                for line in stream:
                    row=json.loads(line);count+=1
                    require(row['schema_version']=='bcl-memory-event-1' and row['variant']==variant,'Invalid event schema/variant')
                    require(row['trace_completeness']=='complete','Incomplete event exported as complete')
                    require(row['virtual_cache_lines']==workflow_events.lines(row['effective_address'],row['width'],row['cache_line_size']),'Wrong touched cache lines')
                    require(row['trace_ref']['line']==count,'Incorrect event reference line')
        require(count==stats['events'],'Report/event count differs: '+variant)
        complete=[r for r in manifest['trace_completeness'] if r['variant']==variant]
        require(sum(r['events'] for r in complete)==count,'Manifest/event count differs')
        counts[variant]=count
    comparison=report['comparison'];csvpath=root/'comparisons/trace_diff.csv';jsonpath=root/'comparisons/trace_diff.jsonl'
    classes=Counter();violations=0;rows=0
    if csvpath.exists() or jsonpath.exists():
        require(csvpath.exists() and jsonpath.exists(),'Missing comparison format')
        with csvpath.open(newline='') as c,jsonpath.open() as j:
            for left,right in zip_longest(csv.DictReader(c),j):
                require(left is not None and right is not None,'CSV/JSONL row count differs')
                row=json.loads(right);rows+=1;classes[row['classification']]+=1
                violations+=bool(row['rule_violated'])
                for field in ('pair','input_case','classification','rule_id'):
                    require(left[field]==str(row[field]),'CSV/JSONL field differs: '+field)
                require(int(left['repetition'])==row['repetition'],'Repetition differs')
        require(dict(classes)==comparison['classification_counts'],'Classification totals differ')
        require(violations==comparison['policy_violations'],'Violation total differs')
        textpath=root/'comparisons/trace_diff.txt'
        if textpath.exists():
            with textpath.open('rb') as textfile:
                textfile.seek(max(0,textpath.stat().st_size-8192));tail=textfile.read().decode('utf-8').replace('\r\n','\n')
            if report.get('presentation',{}).get('schema')=='bcl-readable-decisions-2':
                require('Unique access comparisons: ' in tail,'TXT grouped summary is missing')
                require('Run verdict: '+report['overall_verdict']+'\n' in tail,'TXT verdict differs')
            else:require('Comparison rows: '+str(rows)+'\n' in tail,'TXT comparison total differs')
            require('Policy violations: '+str(violations)+'\n' in tail,'TXT violation total differs')
        pairs=comparison['pairs']
        require(sum(p['violations'] for p in pairs)==violations,'Pair violation totals differ')
        require(sum(p['preserved_observations'] for p in pairs)==comparison['preserved_observations'],'Pair preservation totals differ')
        require(sum(p['unmatched_or_ambiguous'] for p in pairs)==comparison['unmatched_events'],'Pair unmatched totals differ')
    protection=report.get('protection')
    if protection:
        output=root/'protected/program'
        if protection.get('published'):
            require(report['overall_verdict']=='PASS' and report['checks'].get('protection',{}).get('status')=='PASS','Protected output has failed or incomplete checks')
            require(protection.get('executable')=='protected/program' and output.is_file() and not output.is_symlink(),'Invalid protected executable path')
            require(workflow_events.sha(output)==protection['sha256']==report['artifacts']['transformed']['sha256'],'Protected executable hash differs')
            for name in ('approval-report.json','final-approval-report.json'):
                approval=project.read(root/'validation/protection'/name)
                require(approval.get('bounded_transformation_approved') is True,'Missing exhaustive protection approval')
                require(approval['original_sha256']==report['artifacts']['original']['sha256'] and approval['candidate_sha256']==protection['sha256'],'Protection approval binds different binaries')
            decision=project.read(root/'validation/protection-decision.json')
            require(decision==protection,'Protected publication decision differs between reports')
        else:require(not output.exists(),'Rejected build retained a protected executable')
    return {'status':'REPORT_CONSISTENCY_VERIFIED','files_checked':files,'trace_events':counts,'comparison_rows':rows,'policy_violations':violations,'scope':'Integrity and cross-format consistency; not execution attestation or a security proof'}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('run',type=Path)
    print(json.dumps(verify(parser.parse_args().run),indent=2))
