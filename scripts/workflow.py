"""One-command native three-variant workflow. Target traces always come from executed PIN processes."""
import argparse
import copy
import csv
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import shlex
import struct
import subprocess
import sys
import tempfile
import time
try:import tomllib
except ImportError:tomllib=None
import easy
import project
import workflow_events as trace
import workflow_compare as compare

ROOT=Path(__file__).resolve().parent.parent
VARIANTS=('original','baseline','transformed')
STAGES=['Inspect input','Build original','Trace original','Lift and rebuild baseline','Trace baseline','Transform and validate','Trace transformed','Compare observations']
class Stop(RuntimeError):
    def __init__(self,status,detail):super().__init__(detail);self.status=status

def require(value,detail,status='INCONCLUSIVE'):
    if not value:raise Stop(status,detail)

def write(path,value):project.save(path,value)
def check(status,detail,required=True,evidence=None):return {'status':status,'detail':detail,'required':required,'evidence':evidence or []}
def verdict(checks,security):
    # A distinction cannot override failed functional/capture/protection
    # prerequisites. Retain the security evidence as a separate assessment.
    prerequisites=[v['status'] for key,v in checks.items()
                   if v.get('required') and key not in ('security','stage_8')]
    if 'FAIL' in prerequisites:return 'FAIL'
    if any(s!='PASS' for s in prerequisites):return 'INCONCLUSIVE'
    if security.get('compromise_demonstrated'):return 'COMPROMISED'
    required=[v['status'] for v in checks.values() if v.get('required')]
    if 'FAIL' in required:return 'FAIL'
    if any(s!='PASS' for s in required):return 'INCONCLUSIVE'
    return 'PASS'

def config(path):
    require(tomllib is not None,'Python 3.11+ is required for workflow TOML','UNSUPPORTED')
    doc=tomllib.loads(Path(path).read_text())
    require(doc.get('schema_version')=='2.0','Use a schema_version="2.0" workflow configuration; legacy research configuration remains supported by explicit legacy commands','UNSUPPORTED')
    allowed={'schema_version','policy','output','build','lift','transform','tools','execution','comparison','checks','regions','layout_constraints','security','reference_profiles','reference_analysis','formats','mode','protection'}
    require(not set(doc)-allowed,'Unknown configuration fields: '+str(set(doc)-allowed),'UNSUPPORTED')
    require(doc.get('policy') in compare.POLICIES,'Select an explicit named policy','UNSUPPORTED')
    for section in ('execution','comparison','checks','lift','transform','tools'):require(isinstance(doc.get(section),dict),'Missing configuration section: '+section,'UNSUPPORTED')
    allowed_sections={
        'build':{'original','baseline','transformed','adapter'},'lift':{'adapter','image','timeout','extra_link_args','commands'},
        'transform':{'adapter','profile','region_names','end_symbols','alignments','commands'},'tools':{'pin','tracer','tracer_source','docker','docker_sudo'},
        'execution':{'backend','operations','instruction_fetch','repetitions','timeout','max_events','max_snapshots','disable_aslr','cases','stdin_file','eager_binding'},
        'comparison':{'scope','line_identity','line_bytes','lookahead','context','report_sample_limit'},'security':{'enabled','criterion','variant','cases','secret_argv_index'}}
    for name,keys in allowed_sections.items():
        section=doc.get(name,{})
        require(isinstance(section,dict) and not set(section)-keys,'Unknown or invalid '+name+' configuration fields','UNSUPPORTED')
    require(all(isinstance(doc['tools'].get(key),str) and doc['tools'][key] for key in ('pin','tracer','tracer_source')),'Configure PIN, tracer and tracer_source','UNSUPPORTED')
    try:json.dumps(doc)
    except TypeError:raise Stop('UNSUPPORTED','Workflow configuration accepts JSON-compatible TOML values; date/time values are unsupported')
    execution=doc['execution'];comparison=doc['comparison'];checks=doc['checks']
    require(execution.get('backend')=='pin','Only actual whole-2 PIN instrumentation is supported','UNSUPPORTED')
    require(not execution.get('instruction_fetch',False),'Instruction-fetch collection is unsupported by whole-2','UNSUPPORTED')
    for key,lo,hi in [('repetitions',1,20),('timeout',1,86400),('max_events',1,100000000),('max_snapshots',1,100000)]:
        require(type(execution.get(key)) is int and lo<=execution[key]<=hi,'Invalid execution '+key,'UNSUPPORTED')
    require(execution.get('disable_aslr') is True,'Reliable raw-virtual comparisons require explicit disable_aslr=true','UNSUPPORTED')
    cases=execution.get('cases')
    require(isinstance(cases,list) and 1<=len(cases)<=32,'Require 1..32 input cases','UNSUPPORTED')
    ids=set()
    for case in cases:
        require(isinstance(case,dict) and set(case)<={'id','argv','public_id'},'Invalid input case','UNSUPPORTED')
        require(isinstance(case.get('id'),str) and re.fullmatch('[A-Za-z0-9_-]{1,64}',case['id']) and case['id'] not in ids,'Input IDs must be unique safe names','UNSUPPORTED');ids.add(case['id'])
        require(isinstance(case.get('argv'),list) and all(isinstance(s,str) and '\0' not in s for s in case['argv']),'Case argv must contain literal strings','UNSUPPORTED')
    require(comparison.get('scope') in ('all','declared_regions'),'Select comparison scope','UNSUPPORTED')
    require(comparison.get('line_identity') in ('raw_virtual','region_relative'),'Select raw_virtual or region_relative line identity','UNSUPPORTED')
    require(comparison['line_identity']!='region_relative' or comparison['scope']=='declared_regions','Region-relative line identity requires declared_regions scope','UNSUPPORTED')
    line=comparison.get('line_bytes');trace.lines(0,1,line)
    for key,lo,hi in [('lookahead',2,256),('context',0,32),('report_sample_limit',1,10000)]:require(type(comparison.get(key)) is int and lo<=comparison[key]<=hi,'Invalid comparison '+key,'UNSUPPORTED')
    require(execution.get('operations') and set(execution['operations'])<={'READ','WRITE'},'Select READ and/or WRITE; RMW is reported as its separate operations','UNSUPPORTED')
    require(set(checks)=={'functional','references','layout','event_correspondence'} and all(type(v) is bool for v in checks.values()),'Declare required checks explicitly','UNSUPPORTED')
    require(doc['lift'].get('adapter') in ('foxdec','commands'),'Unsupported lift adapter','UNSUPPORTED')
    require(doc.get('mode','experiment') in ('experiment','program'),'Unsupported workflow mode','UNSUPPORTED')
    require(doc['transform'].get('adapter') in ('regions','commands') or doc.get('mode')=='program' and doc['transform'].get('adapter')=='none','Unsupported transform adapter','UNSUPPORTED')
    regions=doc.get('regions',[])
    require(isinstance(regions,list) and len(regions)<=128,'Invalid region declarations','UNSUPPORTED')
    require(comparison['scope']!='declared_regions' or regions,'Declared-region scope needs region mappings','UNSUPPORTED')
    names=set()
    for r in regions:
        require(set(r)=={'name','size','original','baseline','transformed'} and isinstance(r['name'],str) and r['name'] not in names and type(r['size']) is int and 0<r['size']<=4*1024*1024,'Invalid region declaration','UNSUPPORTED');names.add(r['name'])
        for v in VARIANTS:
            require(isinstance(r[v],dict) and set(r[v]) in ({'address'},{'symbol'}),'Each variant region needs one link address or symbol','UNSUPPORTED')
    require(sum(r['size'] for r in regions)<=4*1024*1024,'Logical regions exceed 4 MiB','UNSUPPORTED')
    formats=doc.get('formats',['txt','json','jsonl','csv'])
    require(set(formats)=={'txt','json','jsonl','csv'},'Initial workflow writes all required TXT/JSON/JSONL/CSV formats','UNSUPPORTED')
    local=doc.get('reference_analysis')
    if local is not None:
        require(isinstance(local,dict) and set(local)=={'adapter','region','entry_symbols','immutable_region','entry_stack','execution'},'Invalid reference_analysis contract','UNSUPPORTED')
        require(local['adapter']=='declared_lookup_kernel' and local['region'] in names,'Unsupported declared reference adapter/region','UNSUPPORTED')
        require(local['immutable_region'] is True and local['entry_stack']=='fixed-valid-return' and local['execution']=='ordinary-x86-64','Declare the supported local entry contract','UNSUPPORTED')
        require(isinstance(local['entry_symbols'],dict) and set(local['entry_symbols'])==set(VARIANTS) and all(isinstance(v,str) and re.fullmatch('[A-Za-z_][A-Za-z0-9_]*',v) for v in local['entry_symbols'].values()),'Declare each variant kernel entry symbol','UNSUPPORTED')
        require(not doc.get('reference_profiles'),'Choose local kernel or bounded correspondence profiles','UNSUPPORTED')
    if 'protection' in doc:
        import protection
        protection.validate_config(doc)
    return doc

class Runner(easy.Runner):
    def __init__(self,root,doc):
        self.root=root;self.logs=root/'logs';self.logs.mkdir(exist_ok=True);self.number=0;self.priv=[];self.docker=[];self.commands=[];self.doc=doc
    def command(self,name,argv,allowed=(0,),seconds=600,cwd=None,env=None,output=None,error=None,stdin=None):
        self.number+=1;argv=list(map(str,argv));cwd=Path(cwd or self.root)
        stem=self.logs/f'{self.number:03d}-{name}'
        write(stem.with_suffix('.command.json'),{'argv':argv,'cwd':str(cwd),'timeout_seconds':seconds})
        outpath=Path(output or stem.with_suffix('.log'));errpath=Path(error) if error else None
        started=time.monotonic();exit_code=None
        environment=dict(os.environ,PYTHONDONTWRITEBYTECODE='1',LC_ALL='C',TZ='UTC') if env is None else env
        with outpath.open('wb') as out, (errpath.open('wb') if errpath else open(os.devnull,'wb')) as err, open(stdin or os.devnull,'rb') as inp:
            process=subprocess.Popen(argv,cwd=cwd,env=environment,stdin=inp,stdout=out,stderr=err if errpath else subprocess.STDOUT,**easy.command_process_options())
            try:exit_code=process.wait(timeout=seconds)
            except BaseException:
                easy.kill_group(process);raise
            finally:
                row={'name':name,'argv':argv,'cwd':str(cwd),'exit_code':process.returncode,'seconds':time.monotonic()-started,'stdout':str(outpath.relative_to(self.root))}
                self.commands.append(row);write(stem.with_suffix('.exit.json'),row)
                group='instrumentation' if name.endswith(('-native','-pin')) or name=='aslr-control-probe' else 'transformation' if any(part in name for part in ('transform','apply-regions','audit-region')) else 'build'
                with (self.logs/(group+'.log')).open('a') as aggregate:
                    aggregate.write(name+'\n  argv: '+shlex.join(argv)+'\n  exit: '+str(process.returncode)+'\n  output: '+row['stdout']+'\n')
        if exit_code not in allowed:raise Stop('INCONCLUSIVE',name+' exited '+str(exit_code)+'; see '+str(outpath))
        # Tool adapters consume small diagnostics; large runtime output stays on disk.
        with outpath.open('rb') as stream:text=stream.read(1024*1024).decode(errors='replace')
        return text,exit_code
    def docker_access(self):
        tool=self.doc['tools'].get('docker','docker');self.docker=['sudo','-n','--',tool] if self.doc['tools'].get('docker_sudo',False) else [tool]
        self.command('docker-access',[*self.docker,'info'],seconds=60)
    def foxdec(self,values):
        image=self.doc['lift'].get('image','foxdec')
        require(self.image_works(image),'Configured FoxDec image is unavailable/incompatible; run the existing setup first','UNSUPPORTED')
        return image

class Workflow:
    def __init__(self,input_path,config_path):
        self.input=Path(input_path).resolve();self.config_path=Path(config_path).resolve();self.base=self.config_path.parent
        self.root=None;self.doc=None;self.runner=None;self.runs={};self.regions={};self.inventories={};self.resolved_symbols={};self.instruction_maps={};self.native_outputs={};self.next_lines={v:1 for v in VARIANTS}
        self.report={'schema_version':'1.0','run_id':None,'input':{'path':str(self.input)},'environment':{'platform':platform.platform(),'python':sys.version},'configuration':{},'artifacts':{},'overall_verdict':'INCONCLUSIVE','checks':{},'event_statistics':{},'comparison':{},'violations':[],
                     'security_assessment':{'status':'NOT_ASSESSED','compromise_demonstrated':False},'limitations':['PIN user-space virtual data references; no physical-cache, timing, kernel or speculative-execution measurement','Finite configured runs; PASS is not universal rewriting authorization'],'reproducibility':{}}
    def path(self,value):
        result=str(value).replace('{home}',str(Path.home())).replace('{toolkit}',str(ROOT));return (self.base/result).resolve()
    def load_config(self):return config(self.config_path)
    def preflight(self):pass
    def expand(self,value):
        context={'input':self.root/'inputs'/self.input.name,'work':self.root/'build','original':self.root/'build/original','baseline':self.root/'build/baseline','transformed':self.root/'build/transformed','lifted':self.root/'build/lifted.asm','transformed_asm':self.root/'build/transformed.asm','toolkit':ROOT,'home':Path.home()}
        result=str(value)
        for key,path in context.items():result=result.replace('{'+key+'}',str(path))
        require(not re.search(r'\{[^}]+\}',result),'Unknown command placeholder: '+result,'UNSUPPORTED');return result
    def commands(self,name,commands):
        require(isinstance(commands,list) and commands and len(commands)<=32,'Missing command recipe: '+name,'UNSUPPORTED')
        for index,argv in enumerate(commands):
            require(isinstance(argv,list) and argv and all(isinstance(v,str) and '\0' not in v for v in argv),'Commands must be argument arrays','UNSUPPORTED')
            self.runner.command(name+'-'+str(index),[self.expand(v) for v in argv],seconds=self.doc['execution']['timeout'],cwd=self.root/'build')
    def java(self,*args,allowed=(0,)):
        if self.doc.get('protection'):
            require(trace.sha(self.root/'toolkit.jar')==self.report['reproducibility'].get('toolkit_jar_sha256'),
                    'Protection checker JAR changed after input inspection','UNSUPPORTED')
        name=str(args[0]);return self.runner.command(name,[os.environ.get('JAVA','java'),'-jar',self.root/'toolkit.jar',*args],allowed=allowed,seconds=self.doc['execution']['timeout'])
    def elf(self,path):
        require(path.is_file() and path.stat().st_size>=64,'Build did not produce an ELF executable: '+str(path))
        with path.open('rb') as stream:raw=stream.read(64)
        require(raw[:6]==b'\x7fELF\x02\x01' and struct.unpack_from('<H',raw,18)[0]==62 and struct.unpack_from('<H',raw,16)[0] in (2,3),'Unsupported executable format','UNSUPPORTED')
        path.chmod(0o755)
        return {'path':str(path.relative_to(self.root)),'sha256':trace.sha(path),'bytes':path.stat().st_size}
    def label(self,text,name):
        if '{original_' not in text:return text
        original=next(r for r in self.regions.get('original',[]) if r['name']==name)
        for field,value in [('original_address',original['address']),('original_end',original['address']+original['size'])]:
            text=text.replace('{'+field+':x}',format(value,'x')).replace('{'+field+'}',str(value))
        require('{' not in text,'Unsupported symbol template','UNSUPPORTED');return text
    def resolve_regions(self,variant):
        binary=self.root/'build'/variant
        if any('symbol' in r[variant] for r in self.doc.get('regions',[])):
            text,_=self.runner.command('symbols-'+variant,['nm','-an','--defined-only',binary]);symbols={}
            for line in text.splitlines():
                fields=line.split()
                if len(fields)>=3:
                    try:address=int(fields[0],16)
                    except ValueError:continue
                    symbols.setdefault(fields[-1],set()).add(address)
        else:symbols={}
        result=[]
        for region in self.doc.get('regions',[]):
            descriptor=region[variant]
            if 'symbol' in descriptor:
                symbol=self.label(descriptor['symbol'],region['name'])
                matches=symbols.get(symbol,set());require(len(matches)==1,'Missing/ambiguous symbol '+symbol,'UNSUPPORTED');address=next(iter(matches))
                self.resolved_symbols[variant,region['name']]=symbol
            else:address=descriptor['address']
            require(type(address) is int and address>=0,'Invalid region address','UNSUPPORTED')
            result.append({'name':region['name'],'address':address,'size':region['size']})
        ordered=sorted(result,key=lambda r:r['address'])
        if not all(a['address']+a['size']<=b['address'] for a,b in zip(ordered,ordered[1:])):
            self.report['checks']['region_mapping']=check('FAIL','Overlapping logical regions are ambiguous',True)
        self.regions[variant]=result
    def native(self,variant):
        execution=self.doc['execution'];binary=self.root/'build'/variant
        pin=self.path(self.doc['tools']['pin']);tracer=self.root/'tools/tracer.so'
        require(pin.is_file() and tracer.is_file(),'PIN or tracer missing','UNSUPPORTED')
        env={'PATH':'/usr/bin:/bin','LC_ALL':'C','TZ':'UTC','HOME':str(self.root/'home')}
        if execution.get('eager_binding',False):env['LD_BIND_NOW']='1'
        stdin=self.root/'inputs/public-stdin.bin' if execution.get('stdin_file') else None
        self.pending_trace=None
        self.resolve_regions(variant)
        runs=[]
        for case in execution['cases']:
            for repeat in range(execution['repetitions']):
                raw=self.root/'raw'/variant/case['id']/str(repeat);raw.mkdir(parents=True)
                expected_hash=self.report['artifacts'][variant]['sha256']
                require(trace.sha(binary)==expected_hash,'Executable changed before target collection')
                control=['setarch','x86_64','-R']
                self.pending_trace=variant
                for mode in ('native','pin'):
                    argv=[str(binary),*case['argv']]
                    if mode=='pin':argv=[str(pin),'-t',str(tracer),'-o',str(raw/'trace.csv'),'-images',str(raw/'images.csv'),'-maps',str(raw/'maps.log'),'-meta',str(raw/'trace.properties'),'-max_events',str(execution['max_events']),'-max_snapshots',str(execution['max_snapshots']),*(['-allow_empty','1'] if self.doc.get('mode')=='program' else []),'--',*argv]
                    _,code=self.runner.command(variant+'-'+case['id']+'-'+str(repeat)+'-'+mode,control+argv,allowed=tuple(range(-128,256)),seconds=execution['timeout'],cwd=self.root,env=env,output=raw/(mode+'.stdout'),error=raw/(mode+'.stderr'),stdin=stdin)
                    write(raw/(mode+'.execution.json'),{'exit_code':code,'argv':argv,'environment':env,'instrumented_target':str(binary) if mode=='pin' else None})
                outputs=[]
                for mode in ('native','pin'):outputs.append({'stdout_sha256':trace.sha(raw/(mode+'.stdout')),'stderr_sha256':trace.sha(raw/(mode+'.stderr')),'exit_code':project.read(raw/(mode+'.execution.json'))['exit_code']})
                key=(variant,case['id'],repeat);self.native_outputs[key]=outputs
                converted=trace.convert(raw,self.root/'traces'/(variant+'.jsonl'),variant,case['id'],repeat,self.doc['comparison']['line_bytes'],self.regions[variant],execution['operations'],self.next_lines[variant],expected_binary=binary,allow_empty=self.doc.get('mode')=='program')
                if outputs[0]!=outputs[1] or outputs[0]['exit_code']!=0:self.report['checks']['functional']=check('FAIL','Native/PIN output or exit mismatch',self.doc['checks']['functional'],[str(raw.relative_to(self.root))])
                require(trace.sha(binary)==expected_hash,'Executable changed during collection')
                self.pending_trace=None
                converted['executable_sha256']=expected_hash
                self.next_lines[variant]=converted['next_line'];self.runs[key]=converted;runs.append(converted)
                converted['observed_events']=sum(1 for _ in trace.events(converted,self.doc['comparison']['scope']))
                if not converted['observed_events']:
                    if self.doc.get('mode')=='program' and not self.doc.get('security',{}).get('enabled'):
                        self.report['checks']['observation_population']=check('NOT_APPLICABLE','Complete capture contains no selected user-space data accesses; no security claim',False)
                    else:self.report['checks']['observation_population']=check('INCONCLUSIVE','No events in the configured comparison scope for '+variant+'/'+case['id'],self.doc['policy']!='layout_only' or self.doc.get('security',{}).get('enabled',False))
                self.report['event_statistics'][variant]={'events':sum(r['events'] for r in runs),'raw_events':sum(r['raw_events'] for r in runs),'observed_events':sum(r['observed_events'] for r in runs),'runs':len(runs),'incomplete_traces':0}
        self.report['artifacts'][variant]=self.elf(binary)
        self.report['event_statistics'][variant]={'events':sum(r['events'] for r in runs),'raw_events':sum(r['raw_events'] for r in runs),'observed_events':sum(r['observed_events'] for r in runs),'runs':len(runs),'incomplete_traces':0}
        if variant=='original' and 'protection' in self.doc:
            import protection
            protection.inspect_original(self)
    def lift(self):
        build=self.root/'build';adapter=self.doc['lift']['adapter']
        if 'protection' in self.doc:
            from program_workflow import ProgramWorkflow
            import automatic
            try:automatic.load_elf((build/'original').read_bytes());static=True
            except ValueError:static=False
            if static:
                # Reuse the checked syscall/entry/callback route; keep static
                # output static rather than introducing a dynamic loader.
                self.description={'entry':'_start','static_start':True,'labels':[]}
                self.link=['ld','-m','elf_x86_64','-e','_start','{object}','-o','{output}']
                ProgramWorkflow.lift(self)
                return
        if adapter=='foxdec':
            assembly,link=project.lift_original(build,{k:v for k,v in self.doc['lift'].items() if k in ('image','timeout','extra_link_args')},self.runner,[os.environ.get('JAVA','java'),'-jar',self.root/'toolkit.jar'],self.base,configuration_values={'lift.image':self.doc['lift'].get('image','foxdec')})
            shutil.copy2(assembly,build/'lifted.asm');self.link=link
            if 'protection' in self.doc:
                import protection_regions
                protection_regions.materialize(self,build/'lifted.asm')
            self.runner.command('baseline-assemble',['nasm','-f','elf64',build/'lifted.asm','-o',build/'baseline.o'])
            self.runner.command('baseline-link',[str(v).replace('{object}',str(build/'baseline.o')).replace('{output}',str(build/'baseline')) for v in link])
        else:
            self.commands('lift',self.doc['lift'].get('commands'))
            require((build/'lifted.asm').is_file() and (build/'lifted.asm').stat().st_size>0,'Lifter produced no nonempty assembly')
            self.commands('baseline-build',self.doc.get('build',{}).get('baseline'))
        self.report['artifacts']['baseline']=self.elf(build/'baseline')
        self.check_main_definition('baseline')
    def check_main_definition(self,variant):
        definitions={}
        for name in ('original',variant):
            text,_=self.runner.command('symbols-entry-'+name,['nm','-an','--defined-only',self.root/'build'/name])
            definitions[name]={line.split()[-1] for line in text.splitlines() if len(line.split())>=3}
        require('main' not in definitions['original'] or 'main' in definitions[variant],
                'Rebuilt executable omits original main definition; unsupported lift/startup discovery','UNSUPPORTED')

    def transform(self):
        build=self.root/'build';options=self.doc['transform']
        if options['adapter']=='regions':
            if 'profile' in options:source=project.read(self.path(options['profile']))
            else:
                names=options.get('region_names',[]);ends=options.get('end_symbols',[]);alignments=options.get('alignments',[])
                require(names and len(names)==len(ends)==len(alignments),'Region transformation needs parallel region_names, end_symbols, alignments arrays','UNSUPPORTED')
                original={r['name']:r for r in self.regions['original']}
                source={'schema':'bcl-regions-1','line_bytes':self.doc['comparison']['line_bytes'],'placement_base':0,'regions':[]}
                for name,end,alignment in zip(names,ends,alignments):
                    require(name in original and ('baseline',name) in self.resolved_symbols,'Region transform needs resolved original and baseline symbols','UNSUPPORTED')
                    source['regions'].append({'name':self.resolved_symbols['baseline',name],'end_label':self.label(end,name),'address':original[name]['address'],'size':original[name]['size'],'alignment':alignment})
            source['assembly']=str(build/'lifted.asm')
            if 'protection' in self.doc:
                import protection
                source=protection.planner_input(source,build)
            self.transform_profile=source
            write(build/'regions.json',source)
            self.java('apply-regions',build/'regions.json','--output',build/'transformed.asm','--report',build/'transformation.json')
            self.runner.command('transformed-assemble',['nasm','-f','elf64',build/'transformed.asm','-o',build/'transformed.o'])
            if self.doc['lift']['adapter']=='foxdec':self.runner.command('transformed-link',[str(v).replace('{object}',str(build/'transformed.o')).replace('{output}',str(build/'transformed')) for v in self.link])
            else:self.commands('transformed-build',self.doc.get('build',{}).get('transformed'))
        else:
            self.commands('transform',options.get('commands'))
            require((build/'transformed.asm').is_file() and (build/'transformed.asm').stat().st_size>0,'Transformation produced no assembly')
            self.commands('transformed-build',self.doc.get('build',{}).get('transformed'))
        self.report['artifacts']['transformed']=self.elf(build/'transformed')
        self.check_main_definition('transformed')
        self.resolve_regions('transformed')
        self.validate()
    def validate(self):
        audits={};checks=[]
        for variant in VARIANTS:
            rows=[]
            for region in self.regions[variant]:
                target=self.root/'validation'/(variant+'-'+region['name']+'-region.json')
                require(re.fullmatch('[A-Za-z0-9_.-]{1,64}',region['name']),'Unsafe logical region name','UNSUPPORTED')
                self.java('audit-region',self.root/'build'/variant,hex(region['address']),str(region['size']),'--report',target)
                audit=project.read(target);require(audit['binary_sha256']==self.report['artifacts'][variant]['sha256'],'Audit did not bind actual executable')
                rows.append({**region,'audit':str(target.relative_to(self.root)),'contents_sha256':audit['region_sha256'],'relocation_write_hazards':[r for r in audit['relocations'] if r['write_overlaps_region'] or r['write_width'] is None],'reference_coverage':audit['reference_coverage']})
            audits[variant]={r['name']:r for r in rows}
        write(self.root/'validation/final_binary_checks.json',{'scope':'ELF header and declared-region byte/relocation inventory; not general reference closure','artifacts':self.report['artifacts'],'regions':audits})
        constraints=self.doc.get('layout_constraints',[])
        require(isinstance(constraints,list) and len(constraints)<=256,'Invalid layout constraint list','UNSUPPORTED')
        for constraint in constraints:
            kind=constraint.get('kind');ident=constraint.get('id');require(isinstance(ident,str) and ident,'Layout rule needs an ID','UNSUPPORTED')
            variants=constraint.get('variants',['baseline','transformed']);require(set(variants)<=set(VARIANTS) and variants,'Invalid layout variants','UNSUPPORTED')
            status='PASS';actual=[]
            try:
                if kind in ('alignment','placement'):
                    for variant in variants:
                        address=audits[variant][constraint['region']]['address'];expected=constraint['bytes' if kind=='alignment' else 'address']
                        require(type(expected) is int and expected>0,'Invalid layout expected value','UNSUPPORTED')
                        okay=address%expected==0 if kind=='alignment' else address==expected
                        actual.append({'variant':variant,'address':address,'satisfied':okay})
                elif kind=='spacing':
                    for variant in variants:
                        spacing=audits[variant][constraint['right']]['address']-audits[variant][constraint['left']]['address']
                        actual.append({'variant':variant,'spacing':spacing,'satisfied':spacing==constraint['bytes']})
                elif kind=='non_overlap':
                    for variant in variants:
                        require(audits[variant],'Non-overlap needs declared region evidence','UNSUPPORTED')
                        rows=sorted(audits[variant].values(),key=lambda r:r['address'])
                        okay=all(a['address']+a['size']<=b['address'] for a,b in zip(rows,rows[1:]))
                        actual.append({'variant':variant,'satisfied':okay})
                elif kind in ('contents','line_partition'):
                    source=constraint.get('source','baseline');target=constraint.get('target','transformed')
                    require(audits.get(source) and audits.get(target),'A layout relationship needs actual declared region evidence','UNSUPPORTED')
                    require(source in VARIANTS and target in VARIANTS,'Invalid layout comparison variants','UNSUPPORTED')
                    if kind=='contents':okay=all(audits[source][name]['contents_sha256']==audits[target][name]['contents_sha256'] and not audits[target][name]['relocation_write_hazards'] for name in audits[source])
                    else:
                        forward={};reverse={};okay=True;size=self.doc['comparison']['line_bytes']
                        for name,old in audits[source].items():
                            new=audits[target][name];offset=0
                            while offset<old['size']:
                                a=(old['address']+offset)//size;b=(new['address']+offset)//size
                                if a in forward and forward[a]!=b or b in reverse and reverse[b]!=a:okay=False;break
                                forward[a]=b;reverse[b]=a
                                require(len(forward)<=200000,'Line-partition inventory exceeds supported bound','UNSUPPORTED')
                                offset+=min(old['size']-offset,size-(old['address']+offset)%size,size-(new['address']+offset)%size)
                        actual=[{'source':source,'target':target,'satisfied':okay,'line_classes':len(forward)}]
                    if kind=='contents':actual=[{'source':source,'target':target,'satisfied':okay}]
                else:raise Stop('UNSUPPORTED','Unknown layout constraint: '+str(kind))
                if not all(r['satisfied'] for r in actual):status='FAIL'
            except (KeyError,Stop) as error:status='UNSUPPORTED';actual=[{'reason':str(error)}]
            checks.append({'rule_id':ident,'kind':kind,'expected':constraint,'observed':actual,'status':status,'evidence':['validation/final_binary_checks.json']})
        write(self.root/'validation/layout_checks.json',checks)
        status='NOT_ASSESSED' if not checks else 'FAIL' if any(c['status']=='FAIL' for c in checks) else 'UNSUPPORTED' if any(c['status']!='PASS' for c in checks) else 'PASS'
        self.report['checks']['layout']=check(status,'Configured final linked layout constraints',self.doc['checks']['layout'],['validation/layout_checks.json'])
        if 'protection' in self.doc:
            import protection
            protection.prepare(self)
            return
        if self.doc.get('reference_analysis'):
            self.local_references(self.doc['reference_analysis']);return
        refs=[];covered=set()
        for index,profile in enumerate(self.doc.get('reference_profiles',[])):
            require(set(profile)=={'left','right','profile'},'Reference profiles need left/right/profile','UNSUPPORTED')
            left,right=profile['left'],profile['right'];require(left in VARIANTS and right in VARIANTS and left!=right,'Invalid reference pair','UNSUPPORTED')
            source=self.path(profile['profile']);pair=project.read(source);directory=self.root/'validation'/('references-'+str(index));directory.mkdir()
            for field,variant in [('original',left),('rebuilt',right)]:
                bounded=project.read(project.resolve(source.parent,pair[field]));bounded['binary']=str(self.root/'build'/variant);write(directory/(field+'.json'),bounded);pair[field]=field+'.json'
            write(directory/'profile.json',pair)
            self.java('correspondence',directory/'profile.json','--report',directory/'report.json',allowed=(0,3,7))
            result=project.read(directory/'report.json');status='PASS' if result['correspondence_established'] else 'FAIL' if result['status']=='CORRESPONDENCE_COUNTEREXAMPLE' else 'UNSUPPORTED'
            if status=='PASS':
                require(result['original_analysis']['binary_sha256']==self.report['artifacts'][left]['sha256'] and result['rebuilt_analysis']['binary_sha256']==self.report['artifacts'][right]['sha256'],'Reference report binary binding mismatch')
                old={r['ip'] for r in result['original_analysis']['instruction_coverage']};new={r['ip'] for r in result['rebuilt_analysis']['instruction_coverage']}
                anchors=[r for r in pair['control_map']+pair['entries'] if r['original'] in old and r['rebuilt'] in new]
                self.instruction_maps[left,right]={left:{r['original']:r['original'] for r in anchors},right:{r['rebuilt']:r['original'] for r in anchors}}
            refs.append({'left':left,'right':right,'status':status,'evidence':str((directory/'report.json').relative_to(self.root))});covered.add((left,right))
        required_pairs={('original','baseline'),('baseline','transformed')}
        status='NOT_ASSESSED' if not required_pairs<=covered else 'FAIL' if any(r['status']=='FAIL' for r in refs) else 'UNSUPPORTED' if any(r['status']!='PASS' for r in refs) else 'PASS'
        self.report['checks']['references']=check(status,'Bounded correspondence only for explicitly supplied contracts; no inferred whole-program proof',self.doc['checks']['references'],[r['evidence'] for r in refs])
        if refs:write(self.root/'validation/reference_checks.json',refs)
    def local_references(self,settings):
        directory=self.root/'validation/kernel-references';directory.mkdir()
        profile={'schema':'bcl-workflow-kernel-references-1','contract':{key:settings[key] for key in ('immutable_region','entry_stack','execution')},'variants':{}}
        for variant in VARIANTS:
            binary=self.root/'build'/variant;assembly=directory/(variant+'.disassembly.txt')
            self.runner.command('kernel-disassembly-'+variant,['objdump','-d','-w','-Mintel',binary],output=assembly)
            text,_=self.runner.command('kernel-symbol-'+variant,['nm','-an','--defined-only',binary])
            symbol=settings['entry_symbols'][variant];addresses=set()
            for line in text.splitlines():
                fields=line.split()
                if len(fields)>=3 and fields[-1]==symbol:addresses.add(int(fields[0],16))
            require(len(addresses)==1,'Missing/ambiguous declared kernel entry: '+symbol,'UNSUPPORTED')
            region=next(r for r in self.regions[variant] if r['name']==settings['region'])
            profile['variants'][variant]={'binary':str(binary),'disassembly':str(assembly),'address':region['address'],'size':region['size'],'entry':next(iter(addresses))}
        write(directory/'profile.json',profile)
        target=self.root/'validation/reference_checks.json'
        self.java('workflow-references',directory/'profile.json','--report',target,allowed=(0,7))
        result=project.read(target);status='PASS' if result.get('verified') is True else 'UNSUPPORTED'
        if status=='PASS':
            for variant,row in result['variants'].items():require(row['binary_sha256']==self.report['artifacts'][variant]['sha256'],'Declared-reference binary hash mismatch')
            for pair in result['pairs']:
                left,right=pair['left'],pair['right'];a={};b={}
                for site in pair['access_correspondence']['sites']:
                    old,new=site['original_ips'][0],site['rebuilt_ips'][0];a[old]=old;b[new]=old
                self.instruction_maps[left,right]={left:a,right:b}
        self.report['reference_coverage']='INCOMPLETE'
        self.report['checks']['references']=check(status,'Declared lookup-kernel references and local ABI verified' if status=='PASS' else result.get('reason','Unsupported declared kernel'),self.doc['checks']['references'],['validation/reference_checks.json'])

    def compare(self):
        execution=self.doc['execution'];configuration=self.doc['comparison'];results=[];functional=[];stable=True
        writer=compare.Writer(self.root/'comparisons',self.doc['policy'],configuration['context'],configuration['report_sample_limit'])
        try:
            for case in execution['cases']:
                for repeat in range(execution['repetitions']):
                    outputs=[self.native_outputs[v,case['id'],repeat] for v in VARIANTS]
                    okay=all(pair[0]==pair[1] and pair[0]['exit_code']==0 for pair in outputs) and all(pair[0]==outputs[0][0] for pair in outputs)
                    functional.append({'case':case['id'],'repetition':repeat,'status':'PASS' if okay else 'FAIL','outputs':dict(zip(VARIANTS,outputs))})
                    for left,right in [('original','baseline'),('baseline','transformed'),('original','transformed')]:
                        pair={'name':left+'__'+right,'case':case['id'],'repeat':repeat,'left':left,'right':right}
                        hashes={v:self.report['artifacts'][v]['sha256'] for v in (left,right)}
                        hashes['_verified_maps']=self.instruction_maps.get((left,right),{})
                        certified=getattr(self,'certified_reference_sequences',None)
                        if certified is not None:
                            hashes['_certified_sequence']={'left':certified[left][case['id']],'right':certified[right][case['id']]}
                        results.append(writer.compare(pair,self.runs[left,case['id'],repeat],self.runs[right,case['id'],repeat],configuration,hashes))
                for variant in VARIANTS:
                    for repeat in range(1,execution['repetitions']):
                        same=compare.same_signature(self.runs[variant,case['id'],0],self.runs[variant,case['id'],repeat],self.doc['policy'],configuration)
                        stable &= same and self.native_outputs[variant,case['id'],0]==self.native_outputs[variant,case['id'],repeat]
        finally:writer.close()
        write(self.root/'validation/functional_tests.json',functional)
        self.report['checks']['functional']=check('PASS' if all(r['status']=='PASS' for r in functional) else 'FAIL','Native vs PIN and original/baseline/transformed stdout, stderr and exit checks',self.doc['checks']['functional'],['validation/functional_tests.json'])
        self.report['checks']['repeat_stability']=(check('NOT_REQUESTED','One run per input; repeat stability was not tested',False) if execution['repetitions']==1 else check('PASS' if stable else 'INCONCLUSIVE','Policy-relevant observations and outputs repeat for each fixed case',self.doc['policy']!='layout_only' or self.doc['checks']['functional']))
        required_results=results if self.doc['policy']!='layout_only' else []
        status='FAIL' if any(r['status']=='FAIL' for r in required_results) else 'INCONCLUSIVE' if any(r['status']=='INCONCLUSIVE' for r in required_results) else 'PASS'
        self.report['checks']['observations']=check(status,'Three-way comparisons under '+self.doc['policy'],True,['comparisons/trace_diff.csv','comparisons/trace_diff.jsonl'])
        unknown=sum(r['unmatched_or_ambiguous'] for r in results)
        self.report['checks']['event_correspondence']=check('INCONCLUSIVE' if unknown else 'PASS','Ambiguous/unmapped event identities are not guessed',self.doc['checks']['event_correspondence'])
        self.report['comparison']={'policy':self.doc['policy'],'scope':configuration['scope'],'line_identity':configuration['line_identity'],'pairs':results,'classification_counts':dict(writer.counts),'preserved_observations':sum(r['preserved_observations'] for r in results),'policy_violations':writer.violations_count,'unmatched_events':unknown,'first_difference':writer.first,
                'attribution':'Original-to-baseline changes are associated with the configured lift/rebuild. Baseline-to-transformed changes are associated with the configured transformation/rebuild; exact causal instruction/dataflow attribution is not established beyond matched region evidence.'}
        self.report['violations']=writer.samples;self.report['comparison']['violation_samples_truncated']=writer.violations_count>len(writer.samples)
        self.security(stable)
        if 'protection' in self.doc:
            import protection
            protection.enforce(self)
    def security(self,stable):
        settings=self.doc.get('security',{})
        enabled=settings.get('enabled',False)
        if not enabled:
            require(self.doc['policy']!='security_evaluation','security_evaluation requires explicit security test settings','UNSUPPORTED');return
        criterion=settings.get('criterion')
        require(criterion in ('stable_disjoint_virtual_line_sequences','configured_virtual_line_sequences'),'Unsupported compromise criterion','UNSUPPORTED')
        variant=settings.get('variant');require(variant in VARIANTS,'Invalid security variant','UNSUPPORTED')
        case_ids=settings.get('cases');require(isinstance(case_ids,list) and 2<=len(case_ids)<=32 and len(set(case_ids))==len(case_ids),'Security criterion needs 2..32 distinct declared cases','UNSUPPORTED')
        cases={c['id']:c for c in self.doc['execution']['cases']};require(set(case_ids)<=set(cases),'Unknown security case','UNSUPPORTED')
        secret=settings.get('secret_argv_index');first=cases[case_ids[0]]
        require(type(secret) is int and 0<=secret<len(first['argv']),'Declare the secret argv position','UNSUPPORTED')
        for name in case_ids[1:]:
            other=cases[name]
            require(len(first['argv'])==len(other['argv']) and all(x==y for index,(x,y) in enumerate(zip(first['argv'],other['argv'])) if index!=secret),'Security cases must differ only at the declared secret argument','UNSUPPORTED')
        require(len({cases[name]['argv'][secret] for name in case_ids})==len(case_ids),'Secret argument values must be distinct','UNSUPPORTED')
        configuration=self.doc['comparison'];repetitions=self.doc['execution']['repetitions'];variants=getattr(self,'active_variants',VARIANTS)
        repeat_ok={}
        for name in variants:
            require(all((name,case,repeat) in self.runs for case in case_ids for repeat in range(repetitions)),'Missing security runs for '+name,'INCONCLUSIVE')
            repeat_ok[name]=bool(stable and all(compare.token_compare(self.runs[name,case,0],self.runs[name,case,repeat],configuration['line_identity'],configuration['scope'])['equal'] for case in case_ids for repeat in range(1,repetitions)))
        from itertools import combinations
        pairs=[]
        for left,right in combinations(case_ids,2):
            by_variant={}
            for name in variants:
                evidence=[compare.token_compare(self.runs[name,left,repeat],self.runs[name,right,repeat],configuration['line_identity'],configuration['scope']) for repeat in range(repetitions)]
                assessed=repeat_ok[name] and (repetitions>=2 or criterion=='configured_virtual_line_sequences')
                by_variant[name]={'stable':repeat_ok[name] if repetitions>=2 else None,'assessed':assessed,'equal_across_secrets':all(row['equal'] for row in evidence),'evidence':evidence}
            preservation={}
            for name in variants:
                if name=='original':continue
                original=by_variant['original'];candidate=by_variant[name]
                preservation[name]=('INCONCLUSIVE' if not original['assessed'] or not candidate['assessed'] else
                    'PREMISE_FALSE_BASELINE_ALREADY_DISTINGUISHES' if not original['equal_across_secrets'] else
                    'SATISFIED_FOR_TESTED_PAIR' if candidate['equal_across_secrets'] else 'CANDIDATE_PRESERVATION_VIOLATION')
            pairs.append({'cases':[left,right],'by_variant':by_variant,'preservation':preservation})
        established=all(p['by_variant'][variant]['assessed'] for p in pairs)
        differing=[p for p in pairs if p['by_variant'][variant]['assessed'] and not p['by_variant'][variant]['equal_across_secrets']]
        demonstrated=bool(differing)
        introduced=any(p['by_variant']['original']['assessed'] and p['by_variant']['original']['equal_across_secrets'] for p in differing)
        present=any(p['by_variant']['original']['assessed'] and not p['by_variant']['original']['equal_across_secrets'] for p in differing)
        origin='INTRODUCED_FOR_TESTED_PAIR' if introduced else 'PRESENT_IN_ORIGINAL' if present else 'NOT_ESTABLISHED'
        selected=pairs[0]['by_variant'][variant]
        self.report['security_assessment']={'status':'COMPROMISED' if demonstrated else 'NOT_ESTABLISHED' if established else 'INCONCLUSIVE','criterion':criterion,'variant':variant,'cases':case_ids,'compromise_demonstrated':demonstrated,'evidence':selected['evidence'],'by_variant':pairs[0]['by_variant'],'secret_pairs':pairs,'difference_origin':origin,
                'repeat_stability_tested':repetitions>=2,'scope':'Observed secret-input distinguishability for configured inputs with identical public arguments and runtime controls; complete configured virtual-line sequences compared within each build. One-run mode does not establish repeat stability or physical-cache security.'}
        self.report['checks']['security']=check('FAIL' if demonstrated else 'PASS' if established else 'INCONCLUSIVE','Configured secret-input pairs compared within each build; repeat stability tested only when multiple runs are requested',True)
    def stage(self,index,action):
        ident='stage_'+str(index);print(f'[{index}/8] {STAGES[index-1]} ...',flush=True)
        try:
            action()
            related=['layout','references'] if index==6 else ['functional','observations','event_correspondence','repeat_stability','security','protection'] if index==8 else []
            required=[self.report['checks'][key]['status'] for key in related if key in self.report['checks'] and self.report['checks'][key]['required']]
            state='FAIL' if 'FAIL' in required else 'INCONCLUSIVE' if any(s!='PASS' for s in required) else 'PASS'
            if index==6 and state!='PASS':raise Stop(state,'Required layout/reference validation did not pass; transformed execution was not authorized')
            self.report['checks'][ident]=check(state,'Stage outputs and required related checks evaluated',True);print('       '+state,flush=True)
        except (Stop,ValueError,RuntimeError,OSError,TypeError,IndexError,OverflowError,subprocess.TimeoutExpired) as error:
            status=error.status if isinstance(error,Stop) else 'INCONCLUSIVE'
            if index in (3,5,7) and getattr(self,'pending_trace',None) is not None:
                variant={3:'original',5:'baseline',7:'transformed'}[index]
                self.report['event_statistics'].setdefault(variant,{'events':0,'raw_events':0,'runs':0,'incomplete_traces':0})['incomplete_traces']+=1
            self.report['checks'][ident]=check(status,str(error),True);print('       '+status+': '+str(error),flush=True);raise
    def run(self):
        try:self.doc=self.load_config()
        except (Stop,ValueError,OSError) as error:
            self.doc=None;config_error=error
        else:config_error=None
        output=self.path(self.doc.get('output','runs')) if self.doc else Path.cwd()/'runs'
        output.mkdir(parents=True,exist_ok=True);self.root=Path(tempfile.mkdtemp(prefix=time.strftime('%Y%m%d-%H%M%S-'),dir=output))
        self.report['run_id']=self.root.name
        print('Run directory: '+str(self.root),flush=True)
        for name in ('inputs','build','logs','traces','validation','home'):(self.root/name).mkdir()
        for index in range(1,9):self.report['checks']['stage_'+str(index)]=check('NOT_RUN',STAGES[index-1],True)
        if self.doc and self.doc.get('mode')=='program':
            for index in (6,7):self.report['checks']['stage_'+str(index)]=check('NOT_REQUESTED','No layout transformation requested for this program',False)
        if self.config_path.is_file():shutil.copy2(self.config_path,self.root/'configuration.toml')
        if config_error:
            self.report['checks']['configuration']=check('UNSUPPORTED',str(config_error),True);self.finalize();return self.report
        self.report['configuration']=self.doc;self.report['checks']['configuration']=check('PASS','Versioned configuration validated',True)
        self.report['checks']['references']=check('NOT_ASSESSED','No reference checks have run',self.doc['checks']['references'])
        self.report['checks']['layout']=check('NOT_ASSESSED','No linked layout checks have run',self.doc['checks']['layout'])
        self.report['checks']['functional']=check('NOT_RUN','No runtime outputs collected',self.doc['checks']['functional'])
        if 'protection' in self.doc:
            self.report['checks']['protection']=check('NOT_RUN','Protected publication requires completed native checks and exhaustive approval',True)
            self.report['protection']={'schema':'bcl-protected-build-1','status':'INCONCLUSIVE','published':False,'reason':'Required pipeline stages have not completed'}
        self.runner=Runner(self.root,self.doc)
        try:
            def inspect():
                require(platform.system()=='Linux' and platform.machine() in ('x86_64','amd64'),'Native target instrumentation requires Linux x86-64','UNSUPPORTED')
                require(self.input.is_file(),'Input file does not exist');shutil.copy2(self.input,self.root/'inputs'/self.input.name)
                self.report['input'].update(sha256=trace.sha(self.root/'inputs'/self.input.name),kind='assembly' if self.input.suffix.lower()=='.asm' else 'executable')
                if self.input.suffix.lower()!='.asm':self.elf(self.root/'inputs'/self.input.name)
                require((ROOT/'binarycachelab.jar').is_file(),'Missing toolkit JAR','UNSUPPORTED');shutil.copy2(ROOT/'binarycachelab.jar',self.root/'toolkit.jar')
                self.report['reproducibility']['toolkit_jar_sha256']=trace.sha(self.root/'toolkit.jar')
                (self.root/'tools').mkdir()
                for key,dest in [('tracer','tracer.so'),('tracer_source','tracer.cpp')]:shutil.copy2(self.path(self.doc['tools'][key]),self.root/'tools'/dest)
                if self.doc['execution'].get('stdin_file'):shutil.copy2(self.path(self.doc['execution']['stdin_file']),self.root/'inputs/public-stdin.bin')
                versions={}
                for name,command in [('java',[os.environ.get('JAVA','java'),'-version']),('pin',[self.path(self.doc['tools']['pin']),'-version']),('nasm',['nasm','-v']),('gcc',['gcc','--version']),('nm',['nm','--version'])]:
                    text,_=self.runner.command('version-'+name,command,seconds=30);versions[name]=text[:4096]
                self.report['reproducibility']['controller_sources']={name:trace.sha(ROOT/'scripts'/name) for name in ('workflow.py','workflow_events.py','workflow_compare.py','project.py','easy.py','console.py')}
                if self.doc.get('protection'):
                    self.report['reproducibility']['controller_sources'].update({name:trace.sha(ROOT/'scripts'/name) for name in
                        ('protection.py','protection_regions.py','protection_correspondence.py','program_workflow.py','callback_rebind.py','syscall_lift.py','syscall_cfg.py')})
                self.report['environment']['tool_versions']=versions
                self.report['environment']['pin']={'path':str(self.path(self.doc['tools']['pin'])),'sha256':trace.sha(self.path(self.doc['tools']['pin']))}
                self.runner.command('aslr-control-probe',['setarch','x86_64','-R','/bin/true'],seconds=30)
                if self.doc['lift']['adapter']=='foxdec':self.runner.docker_access()
                self.preflight()
            self.stage(1,inspect)
            def original():
                if self.input.suffix.lower()=='.asm':self.commands('original-build',self.doc.get('build',{}).get('original'))
                else:shutil.copy2(self.root/'inputs'/self.input.name,self.root/'build/original')
                self.report['artifacts']['original']=self.elf(self.root/'build/original')
            self.stage(2,original);self.stage(3,lambda:self.native('original'));self.stage(4,self.lift);self.stage(5,lambda:self.native('baseline'))
            if self.doc.get('mode')=='program':
                for index in (6,7):self.report['checks']['stage_'+str(index)]=check('NOT_REQUESTED','No layout transformation requested for this program',False)
            else:self.stage(6,self.transform);self.stage(7,lambda:self.native('transformed'))
            self.stage(8,self.compare)
        except KeyboardInterrupt:self.report['checks']['cancelled']=check('INCONCLUSIVE','User cancelled; partial evidence retained',True)
        except (Stop,ValueError,RuntimeError,OSError,KeyError,TypeError,IndexError,OverflowError,subprocess.TimeoutExpired) as error:
            self.report['limitations'].append(str(error))
            if 'protection' in self.report:
                self.report['protection'].update(status='FAIL' if getattr(error,'status',None)=='FAIL' else 'INCONCLUSIVE',reason=str(error))
        finally:
            try:self.finalize()
            except BaseException:
                if self.report.get('protection',{}).get('published'):
                    import protection
                    protection.revoke(self,'Evidence finalization did not complete')
                raise
        return self.report
    def finalize(self):
        if self.report.get('protection',{}).get('published') and verdict(self.report['checks'],self.report['security_assessment'])!='PASS':
            import protection
            protection.revoke(self,'A required check did not pass at finalization')
        self.report=json.loads(json.dumps(self.report))
        self.report['overall_verdict']=verdict(self.report['checks'],self.report['security_assessment'])
        if self.runner:self.report['reproducibility']['commands']=self.runner.commands
        self.report['reproducibility'].update(controls='setarch x86_64 -R; fixed public stdin, case argv, common cwd, LC_ALL=C, TZ=UTC and HOME',configuration_snapshot='configuration.toml',scope='Recorded commands and hashes support auditing; no independent execution attestation')
        text_report=self.root/'comparisons/trace_diff.txt'
        if not text_report.exists():
            text_report.parent.mkdir(exist_ok=True)
            text_report.write_text('BinaryCacheLab - Analysis result\nNo trace comparison was completed.\n'+''.join(name+': '+row['status']+' - '+row['detail']+'\n' for name,row in self.report['checks'].items()),encoding='utf-8')
        if (self.root/'comparisons/trace_diff.jsonl').exists() or self.report.get('event_statistics'):
            from workflow_text import render_report
            self.report['presentation']={'schema':'bcl-readable-decisions-2','duplicate_findings':'combined','repeated_display_rows':'collapsed','secret_inputs':'grouped_within_build'}
            render_report(self.root,self.report)
        else:
            with text_report.open('a',encoding='utf-8') as stream:stream.write('\nRun verdict: '+self.report['overall_verdict']+'\n')
        write(self.root/'report.json',self.report)
        manifest={'schema_version':'bcl-run-manifest-1','run_id':self.root.name,'configuration':self.report['configuration'],'input':self.report['input'],'artifacts':self.report['artifacts'],'environment':self.report['environment'],'execution_inputs':self.doc['execution'] if self.doc else {},'trace_completeness':[{k:r[k] for k in ('variant','input_case','repetition','raw_events','events','trace_complete','raw_csv_sha256')} for r in self.runs.values()],'commands':self.runner.commands if self.runner else [],'files':{}}
        for path in self.root.rglob('*'):
            if path.is_file() and path.name not in ('manifest.json','summary.txt','SHA256SUMS'):manifest['files'][path.relative_to(self.root).as_posix()]=trace.sha(path)
        # Every configured layout constraint and every check, including missing/unsupported evidence.
        comparison=self.root/'comparisons';comparison.mkdir(exist_ok=True)
        with (comparison/'preserved_constraints.csv').open('w',newline='') as stream:
            writer=csv.DictWriter(stream,fieldnames=['rule_id','expected','observed','status','evidence']);writer.writeheader()
            for ident,row in self.report['checks'].items():writer.writerow({'rule_id':ident,'expected':'PASS' if row['required'] else 'optional','observed':row['detail'],'status':row['status'],'evidence':json.dumps(row['evidence'])})
            layout=self.root/'validation/layout_checks.json'
            if layout.exists():
                for row in project.read(layout):writer.writerow({'rule_id':row['rule_id'],'expected':json.dumps(row['expected']),'observed':json.dumps(row['observed']),'status':row['status'],'evidence':json.dumps(row['evidence'])})
            for row in self.report['comparison'].get('pairs',[]):
                writer.writerow({'rule_id':'TRACE/'+row['pair']['name']+'/'+row['pair']['case']+'/'+str(row['pair']['repeat']),
                                 'expected':self.doc['policy'],'observed':json.dumps({'preserved':row['preserved_observations'],'violations':row['violations'],'unknown':row['unmatched_or_ambiguous']}),'status':row['status'],'evidence':'comparisons/trace_diff.csv'})
        summary=self.summary();(self.root/'summary.txt').write_text(summary+'\n')
        manifest['files']={path.relative_to(self.root).as_posix():trace.sha(path) for path in self.root.rglob('*') if path.is_file() and path.name not in ('manifest.json','SHA256SUMS')}
        write(self.root/'manifest.json',manifest);project.seal(self.root);print('\n'+summary,flush=True)
    def summary(self):
        r=self.report;lines=['BinaryCacheLab','Policy: '+str(r['configuration'].get('policy','UNCONFIGURED')),'OVERALL VERDICT: '+r['overall_verdict'],'']
        for variant in getattr(self,'active_variants',VARIANTS):lines.append(variant.title()+' trace events: '+str(r['event_statistics'].get(variant,{}).get('events','NOT_RUN')))
        comparison=r['comparison'];lines+=['Preserved observations (pairwise): '+str(comparison.get('preserved_observations',0)),'Policy violations: '+str(comparison.get('policy_violations',0)),'Unmatched/ambiguous events: '+str(comparison.get('unmatched_events',0)),
                'Incomplete traces: '+str(sum(v.get('incomplete_traces',0) for v in r['event_statistics'].values())),'Uncollected required runs: '+str((len(self.doc['execution']['cases'])*self.doc['execution']['repetitions']*len(getattr(self,'active_variants',VARIANTS))-len(self.runs)) if self.doc else 'NOT_ASSESSED'),'Security assessment: '+r['security_assessment']['status'],'Security compromise: '+('DEMONSTRATED FOR CONFIGURED CRITERION' if r['security_assessment'].get('compromise_demonstrated') else 'NOT ESTABLISHED')]
        if 'protection' in r:
            lines.append('Protected build: '+r['protection']['status'])
            if r['protection'].get('published'):lines.append('Protected executable: '+str(self.root/r['protection']['executable']))
        first=r['violations'][0] if r['violations'] else None
        if first:
            lines+=['','First violation: '+first['rule_id']+' / '+first['classification'],'  IP: '+str(first['baseline_ip'])+' -> '+str(first['transformed_ip']),'  Address: '+str(first['baseline_address'])+' -> '+str(first['transformed_address']),'  Virtual lines: '+str(first['baseline_lines'])+' -> '+str(first['transformed_lines']),'  '+first['explanation']]
        for name,c in r['checks'].items():
            if c['status']!='PASS':lines.append(name+': '+c['status']+'; '+c['detail'])
        lines+=['','Reports: '+str(self.root/'summary.txt'),str(self.root/'report.json'),str(self.root/'manifest.json'),str(self.root/'comparisons'),str(self.root/'traces'),'Scope: finite configured user-space virtual data observations; no physical-cache or general safety proof.']
        return '\n'.join(lines)

def select_config(input_path,explicit=None):
    path=Path(explicit) if explicit is not None else (Path(input_path).resolve().parent/'bcl.toml')
    if not path.is_file() and explicit is None:path=Path.cwd()/'bcl.toml'
    if explicit is None and (not path.is_file() or 'schema_version' not in path.read_text()):path=ROOT/'examples/workflow/bcl.toml'
    return path


def main(args=None):
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('input',type=Path);parser.add_argument('--config',type=Path)
    opts=parser.parse_args(args)
    path=select_config(opts.input,opts.config)
    from program_workflow import workflow_for
    report=workflow_for(opts.input,path).run()
    return {'PASS':0,'FAIL':3,'COMPROMISED':5,'INCONCLUSIVE':7}[report['overall_verdict']]
