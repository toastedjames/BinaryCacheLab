"""Decision-first, deduplicated human reports; full evidence stays in JSONL/CSV."""
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile


def hexadecimal(value):return '-' if value is None else hex(value)
def encoded(value):return json.dumps(value,sort_keys=True,separators=(',',':'))
def digest(value):return hashlib.sha256(encoded(value).encode()).hexdigest()
def lines_text(value):return ', '.join(hexadecimal(v) for v in value or []) or '-'
def label(value):return str(value).replace('_',' ').title()


class DifferenceTextWriter:
    def __init__(self,path,policy,overwrite=False):
        self.path=Path(path);self.policy=policy;self.overwrite=overwrite;self.closed=False;self.rows=0;self.violations=0
        if self.path.exists() and not overwrite:raise FileExistsError(self.path)
        self.path.parent.mkdir(parents=True,exist_ok=True)
        fd,name=tempfile.mkstemp(prefix='.readable-',suffix='.sqlite',dir=self.path.parent);os.close(fd)
        self.cache=Path(name);self.db=sqlite3.connect(name)
        self.db.execute('CREATE TABLE changes (seq INTEGER PRIMARY KEY, k TEXT UNIQUE, payload TEXT)')
        self.db.execute('CREATE TABLE findings (k TEXT, finding TEXT, violated INTEGER, PRIMARY KEY(k,finding))')
        self.db.execute('CREATE TABLE accesses (seq INTEGER PRIMARY KEY, k TEXT UNIQUE, variant TEXT, input_case TEXT, payload TEXT)')
        self.db.execute('CREATE TABLE placements (seq INTEGER PRIMARY KEY, k TEXT UNIQUE, variant TEXT, payload TEXT)')
    def placement(self,variant,image):
        row={'executable':image['name'],'image_start':image['low'],'load_bias':image['bias']}
        self.db.execute('INSERT OR IGNORE INTO placements(k,variant,payload) VALUES(?,?,?)',(digest([variant,row]),variant,encoded(row)))
    def event(self,event):
        row={key:event.get(key) for key in ('variant','input_case','instruction_address','effective_address','virtual_cache_lines','operation','width')}
        row['region']=None if event.get('region') is None else {key:event['region'][key] for key in ('name','offset')}
        self.db.execute('INSERT OR IGNORE INTO accesses(k,variant,input_case,payload) VALUES(?,?,?,?)',(digest(row),row['variant'],row['input_case'],encoded(row)))
    def emit(self,row):
        self.rows+=1;self.violations+=bool(row['rule_violated'])
        data={k:v for k,v in row.items() if k not in ('classification','rule_violated','explanation','repetition','baseline_trace_ref','transformed_trace_ref','baseline_module','transformed_module')}
        key=digest(data)
        self.db.execute('INSERT OR IGNORE INTO changes(k,payload) VALUES(?,?)',(key,encoded(data)))
        self.db.execute('INSERT OR IGNORE INTO findings VALUES(?,?,?)',(key,row['classification'],None if row['rule_violated'] is None else int(row['rule_violated'])))
    def close(self,verdict=None,preserved=None,report=None):
        if self.closed:return
        self.closed=True
        try:
            with self.path.open('w' if self.overwrite else 'x',encoding='utf-8') as out:
                self.render(out,verdict,report or {})
        finally:
            self.db.close();self.cache.unlink(missing_ok=True)
    def render(self,out,verdict,report):
        out.write('BinaryCacheLab - Results\n'+'='*78+'\nResult: '+str(verdict or 'See report.json')+'\nPolicy: '+self.policy+'\n\n')
        if report and 'protection' in report:
            protected=report['protection']
            out.write('Protected build: '+protected['status']+'\n')
            if protected.get('published'):out.write('Executable: '+str(self.run_root/protected['executable'])+'\n')
            else:out.write('No protected executable published. '+protected.get('reason','')+'\n')
            out.write('Approval scope: declared finite entries/inputs and 64-byte virtual data lines.\n\n')
        observer=report.get('configuration',{}).get('comparison',{})
        if observer:out.write('Observer: '+str(observer.get('line_identity'))+' / '+str(observer.get('line_bytes'))+'-byte lines / '+str(observer.get('scope'))+'\n')
        for name,row in report.get('checks',{}).items():
            if row.get('required') and row.get('status')!='PASS':out.write(name+': '+str(row.get('status'))+' - '+str(row.get('detail'))+'\n')
        out.write('\n')
        cases={c['id']:c for c in report.get('configuration',{}).get('execution',{}).get('cases',[])}
        security=report.get('security_assessment',{});settings=report.get('configuration',{}).get('security',{})
        pairs=security.get('secret_pairs',[])
        if not pairs and len(security.get('cases',[]))==2:pairs=[{'cases':security['cases'],'by_variant':security.get('by_variant',{})}]
        out.write('SECRET INPUT DECISIONS\n'+'-'*78+'\n')
        if not pairs:
            out.write('No configured secret-input decision is available.\nSecurity: '+str(security.get('status','NOT_CONFIGURED'))+'\n')
        for number,pair in enumerate(pairs,1):
            ids=pair['cases'];secret=settings.get('secret_argv_index')
            def input_label(case):
                argv=cases.get(case,{}).get('argv',[])
                return case+(' [key='+repr(argv[secret])+']' if isinstance(secret,int) and 0<=secret<len(argv) else '')
            out.write('G'+str(number)+': '+input_label(ids[0])+' versus '+input_label(ids[1])+'\n')
            observations=pair.get('by_variant',{})
            for variant,decision in observations.items():
                equality=decision.get('equal_across_secrets')
                trusted=decision.get('assessed',decision.get('stable',False))
                result='SAME observed line sequence' if equality else 'DIFFERENT observed line sequences'
                if not trusted:result='INCONCLUSIVE - '+result
                out.write('  '+label(variant)+': '+result+'\n')
            original=observations.get('original',{});target=observations.get(settings.get('variant','transformed'),{})
            original_ok=original.get('assessed',original.get('stable',False));target_ok=target.get('assessed',target.get('stable',False))
            if not original_ok or not target_ok:decision='INCONCLUSIVE: complete evidence for this decision is missing.'
            elif report.get('checks',{}).get('functional',{}).get('status') not in (None,'PASS'):decision='INCONCLUSIVE PRESERVATION: functional checks did not pass.'
            elif original.get('equal_across_secrets') and not target.get('equal_across_secrets'):decision='NEW SECRET DISTINCTION: original secrets look equal; rebuilt secrets look different.'
            elif not original.get('equal_across_secrets'):decision='SECRET DISTINCTION ALREADY PRESENT IN ORIGINAL.'
            else:decision='NO SECRET DISTINCTION OBSERVED; observation equality preserved for these inputs.'
            out.write('  Decision: '+decision+'\n\n')
        out.write('OBSERVED ACCESSES - secret inputs together within each build\n'+'-'*78+'\n')
        count=0
        variants=list(dict.fromkeys([row[0] for row in self.db.execute('SELECT variant FROM placements GROUP BY variant ORDER BY MIN(seq)')]+[row[0] for row in self.db.execute('SELECT variant FROM accesses GROUP BY variant ORDER BY MIN(seq)')]))
        for variant in variants:
            out.write(label(variant)+'\n')
            for payload, in self.db.execute('SELECT payload FROM placements WHERE variant=? ORDER BY seq',(variant,)):
                placement=json.loads(payload)
                out.write('  Executable: '+placement['executable']+'\n')
                out.write('  Recorded image start: '+hexadecimal(placement['image_start'])+' | Load bias: '+hexadecimal(placement['load_bias'])+'\n')
            for payload, in self.db.execute('SELECT payload FROM accesses WHERE variant=? ORDER BY input_case,seq',(variant,)):
                row=json.loads(payload);count+=1
                out.write('  '+str(row['input_case'])+' | IP '+hexadecimal(row['instruction_address'])+' | Memory '+hexadecimal(row['effective_address'])+' | Cache '+lines_text(row['virtual_cache_lines'])+'\n')
                out.write('    '+str(row['operation'])+' '+str(row['width'])+' bytes'+(' | '+row['region']['name']+' +'+hex(row['region']['offset']) if row['region'] else '')+'\n')
            out.write('\n')
        if not count:out.write('No user-space data accesses in the selected scope. Kernel accesses and instruction fetches are excluded.\n\n')
        if report.get('configuration',{}).get('mode')=='program' and hasattr(self,'run_root'):
            for variant in report.get('artifacts',{}):
                for case in cases:
                    path=(self.run_root/'raw'/variant/case/'0/native.stdout').resolve()
                    if path.is_relative_to(self.run_root.resolve()) and path.is_file():
                        with path.open('rb') as stream:value=stream.read(4096).decode(errors='replace')
                        out.write(label(variant)+' / '+case+' stdout: '+repr(value)+'\n')
            out.write('\n')
        out.write('BUILD CHANGES - all findings for one access together\n'+'-'*78+'\n')
        groups=0
        order={'ADDRESS_CHANGED':0,'CACHE_LINE_CHANGED':1}
        for key,payload in self.db.execute('SELECT k,payload FROM changes ORDER BY seq'):
            row=json.loads(payload);groups+=1
            values=list(self.db.execute('SELECT finding,violated FROM findings WHERE k=?',(key,)))
            findings=[v[0] for v in sorted(values,key=lambda x:(order.get(x[0],2),x[0]))]
            status='VIOLATION' if any(v[1]==1 for v in values) else 'INCONCLUSIVE' if any(v[1] is None for v in values) else 'PERMITTED'
            out.write('C'+str(groups)+' | '+str(row['input_case'])+' | '+label(row['baseline_variant'])+' -> '+label(row['transformed_variant'])+'\n')
            out.write('  FINDINGS: '+'; '.join(v.replace('_',' ') for v in findings)+'\n')
            out.write('  IP:     '+hexadecimal(row.get('baseline_ip'))+' -> '+hexadecimal(row.get('transformed_ip'))+'\n')
            out.write('  Memory: '+hexadecimal(row.get('baseline_address'))+' -> '+hexadecimal(row.get('transformed_address'))+'\n')
            out.write('  Cache:  '+lines_text(row.get('baseline_lines'))+' -> '+lines_text(row.get('transformed_lines'))+'\n')
            out.write('  Policy: '+status+'\n\n')
        if not groups:out.write('No cross-build event correspondence was established or requested.\n\n')
        out.write('SUMMARY\nUnique access comparisons: '+str(groups)+'\nPolicy violations: '+str(self.violations)+'\n')
        out.write('Run verdict: '+str(verdict or 'see report.json')+'\n')


def render_report(root,report,output=None):
    root=Path(root);path=Path(output) if output else root/'comparisons/trace_diff.txt'
    writer=DifferenceTextWriter(path,report.get('configuration',{}).get('policy','unknown'),overwrite=output is None)
    writer.run_root=root
    try:
        source=root/'comparisons/trace_diff.jsonl'
        if source.exists():
            with source.open(encoding='utf-8') as stream:
                for line in stream:writer.emit(json.loads(line))
        scope=report.get('configuration',{}).get('comparison',{}).get('scope','all')
        for variant in report.get('artifacts',{}):
            from workflow_events import image_updates
            for imagefile in sorted((root/'raw'/variant).glob('*/*/images.csv')):
                images=[image for image in image_updates(imagefile) if image['main'] and image['action']=='LOAD']
                if len(images)!=1:raise ValueError('Missing/ambiguous recorded program image: '+str(imagefile))
                writer.placement(variant,images[0])
            trace=root/'traces'/(variant+'.jsonl')
            if trace.exists():
                with trace.open(encoding='utf-8') as stream:
                    for line in stream:
                        event=json.loads(line)
                        if scope=='all' or event.get('region') is not None:writer.event(event)
    finally:writer.close(report.get('overall_verdict'),report=report)
    return path
