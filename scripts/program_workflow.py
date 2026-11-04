"""Automatic entry/build selection for general programs; no inferred leakage contract."""
import copy
import hashlib
import json
from pathlib import Path
import re
import shutil
import struct
import workflow as w
import workflow_events as trace
import workflow_compare as compare
import project


def asm_description(path):
    text=Path(path).read_text(encoding='utf-8')
    # NASM comments inside quoted data must not create fake entry definitions.
    code='\n'.join(line.split(';',1)[0] for line in text.splitlines())
    labels=re.findall(r'^\s*([A-Za-z_][\w.$]*):',code,re.M)
    entries=[name for name in ('main','_start') if name in labels]
    w.require(len(entries)==1,'Automatic ASM build requires exactly one main or _start definition; use an explicit build recipe for macros/includes or multiple entries','UNSUPPORTED')
    entry=entries[0]
    w.require(labels.count(entry)==1,'Duplicate entry definition','UNSUPPORTED')
    externs=re.findall(r'^\s*extern\s+([^\n]+)',code,re.M|re.I)
    return {'entry':entry,'static_start':entry=='_start' and not externs,'labels':labels}


def rebind_main_startup(assembly,symbols):
    """Rebind only the ABI-defined main argument in the lifted CRT startup."""
    matches={int(parts[0],16) for line in symbols.splitlines() if len(parts:=line.split())==3 and parts[2]=='main' and parts[1] in ('T','t')}
    w.require(len(matches)==1,'Original main has no unique executable symbol','UNSUPPORTED')
    text=Path(assembly).read_text();start=re.search(r'^_start:\s*$',text,re.M)
    w.require(start is not None,'Lifted program has no _start definition','UNSUPPORTED')
    end=re.search(r'^\s*HLT\s*(?:;[^\n]*)?$',text[start.end():],re.M|re.I)
    w.require(end is not None,'Unsupported lifted libc startup termination','UNSUPPORTED')
    finish=start.end()+end.end();body=text[start.end():finish]
    w.require(re.search(r'CALL\s+__libc_start_main\b',body,re.I),'Unsupported main startup ABI','UNSUPPORTED')
    address=matches.pop()
    literal=re.compile(r'^(\s*)MOV\s+RDI,\s*0x'+format(address,'x')+r'\s*(?:;[^\n]*)?$',re.M|re.I)
    if literal.search(body):
        w.require(len(literal.findall(body))==1,'Ambiguous original main pointer in startup','UNSUPPORTED')
        body=literal.sub(lambda m:m.group(1)+'LEA RDI, [rel main] ; original ELF main pointer rebound',body)
        Path(assembly).write_text(text[:start.end()]+body+text[finish:],encoding='utf-8')
        return True
    w.require(re.search(r'(?:LEA\s+RDI,\s*\[.*\bmain\b.*\]|MOV\s+RDI,\s*main\b)',body,re.I),'No supported main argument binding in lifted startup','UNSUPPORTED')
    return False


def program_config(doc,description,automatic):
    doc=copy.deepcopy(doc)
    if not automatic:w.require(doc.get('policy')=='layout_only','General program capture uses layout_only; secret distinguishability is an explicitly configured separate test','UNSUPPORTED')
    w.require(doc.get('build',{}).get('adapter','auto') in ('auto','commands'),'Unsupported program build adapter','UNSUPPORTED')
    if automatic:
        # The bundled lookup configuration is a fixture, not a contract on
        # arbitrary inputs. Make the switch explicit in the saved report.
        doc.pop('reference_analysis',None);doc.pop('reference_profiles',None)
        doc['regions']=[];doc['layout_constraints']=[]
        doc['checks']={'functional':True,'references':False,'layout':False,'event_correspondence':False}
        doc['security']={'enabled':False}
        doc['execution']['cases']=[{'id':'default','argv':[],'public_id':'default'}]
        doc['execution'].pop('stdin_file',None)
        doc['comparison'].update(scope='all',line_identity='raw_virtual')
    w.require(not doc.get('reference_analysis') and not doc.get('reference_profiles') and not doc['checks']['references'],
              'General program mode does not infer a reference contract; use the explicit bounded/lookup experiment for reference approval','UNSUPPORTED')
    w.require(not doc.get('layout_constraints') and not doc['checks']['layout'],'Program capture mode does not apply layout transformations','UNSUPPORTED')
    w.require(not doc['checks']['event_correspondence'],'General capture mode does not claim instruction correspondence','UNSUPPORTED')
    doc['mode']='program';doc['policy']='layout_only';doc['transform']={'adapter':'none'}
    if doc.get('build',{}).get('adapter','auto')=='auto':
        entry=description['entry'];assemble=['nasm','-f','elf64','{input}','-o','{work}/original.o']
        if entry=='main':link=['gcc','-no-pie','{work}/original.o','-o','{original}']
        elif description['static_start']:link=['ld','-m','elf_x86_64','-e','_start','{work}/original.o','-o','{original}']
        else:link=['gcc','-no-pie','-nostartfiles','-Wl,-e,_start','{work}/original.o','-o','{original}']
        doc['build']={'adapter':'auto','original':[assemble,link]}
    security=doc.get('security',{})
    if security.get('enabled'):
        w.require(security.get('variant') in ('original','baseline'),'Program security target must be original or baseline','UNSUPPORTED')
        w.require(doc['comparison']['scope'] in ('all','declared_regions'),'Explicit observation scope required','UNSUPPORTED')
    return doc


def workflow_for(input_path,config_path):
    try:doc=w.config(config_path)
    except (w.Stop,ValueError,OSError):return w.Workflow(input_path,config_path)
    path=Path(input_path)
    if not path.is_file():return w.Workflow(input_path,config_path)
    # A missing entry/region must not silently turn protection into capture.
    if 'protection' in doc:return w.Workflow(input_path,config_path)
    explicit=doc.get('mode')=='program'
    if path.suffix.lower()=='.asm':
        raw=path.read_text(encoding='utf-8')
        labels=set(re.findall(r'^\s*([A-Za-z_][\w.$]*):',raw,re.M))
        fixture=doc.get('reference_analysis',{}).get('adapter')=='declared_lookup_kernel'
        required=set(doc.get('reference_analysis',{}).get('entry_symbols',{}).values())
        expected={r['original']['symbol'] for r in doc.get('regions',[]) if 'symbol' in r['original']}
        automatic=fixture and Path(config_path).resolve()==(w.ROOT/'examples/workflow/bcl.toml').resolve() and not required.union(expected)<=labels
        if explicit or automatic:
            return ProgramWorkflow(input_path,config_path,doc,automatic)
    elif explicit:return ProgramWorkflow(input_path,config_path,doc,False)
    return w.Workflow(input_path,config_path)


class ProgramWorkflow(w.Workflow):
    active_variants=('original','baseline')
    def __init__(self,input_path,config_path,doc,automatic=False):
        super().__init__(input_path,config_path);self.supplied=doc;self.automatic=automatic;self.description=None
    def load_config(self):
        if self.input.suffix.lower()=='.asm':self.description=asm_description(self.input)
        else:
            # Existing ELF images need an explicit program profile; entry roots
            # come from the ELF header, not guessed source labels.
            self.description={'entry':'_start','static_start':False,'labels':[]}
        doc=program_config(self.supplied,self.description,self.automatic)
        self.report['input']['profile_selection']='automatic general program' if self.automatic else 'explicit general program'
        self.report['input']['build_selection']=self.description
        self.report['security_assessment']={'status':'NOT_CONFIGURED','compromise_demonstrated':False,'detail':'No secret-input test was declared; build/trace success is not a security verdict'}
        self.report['limitations'].append('General program capture: no transformation, inferred aliases, instruction correspondence or universal security claim')
        print('General program mode: '+self.description['entry']+'; no layout transformation; leakage testing requires explicit secrets and observation scope.',flush=True)
        return doc
    def preflight(self):
        w.require(self.doc['lift']['adapter']=='foxdec','General program capture currently requires the real FoxDec adapter','UNSUPPORTED')
        w.write(self.root/'validation/automatic-profile.json',{'selection':self.report['input']['profile_selection'],'entry':self.description,'security_inputs_inferred':False,'layout_transformation_requested':False,'source_configuration_sha256':trace.sha(self.config_path)})
        w.write(self.root/'effective-configuration.json',self.doc)
        source=self.root/'tools/tracer.cpp';pin=self.path(self.doc['tools']['pin'])
        w.require((pin.parent/'source/tools/Config/makefile.config').is_file(),'PIN kit build files are required to build the general-program tracer','UNSUPPORTED')
        key=hashlib.sha256(source.read_bytes()+trace.sha(pin).encode()).hexdigest()[:24]
        cache=w.ROOT/'.bcl/program-tracer'/key;cache.mkdir(parents=True,exist_ok=True)
        binary=cache/'obj-intel64/WholeProgramMemoryTracer.so';stamp=cache/'build.json'
        valid=binary.is_file() and stamp.is_file() and project.read(stamp).get('sha256')==trace.sha(binary)
        if not valid:
            shutil.copyfile(source,cache/'WholeProgramMemoryTracer.cpp')
            (cache/'Makefile').write_text('PIN_ROOT ?= /missing\nCONFIG_ROOT := $(PIN_ROOT)/source/tools/Config\ninclude $(CONFIG_ROOT)/makefile.config\nTOOL_ROOTS := WholeProgramMemoryTracer\ninclude $(TOOLS_ROOT)/Config/makefile.default.rules\n')
            self.runner.command('build-program-tracer',['make','-C',cache,'PIN_ROOT='+str(pin.parent),'obj-intel64/WholeProgramMemoryTracer.so'])
            w.require(binary.is_file(),'Tracer build produced no shared library','UNSUPPORTED')
            w.write(stamp,{'sha256':trace.sha(binary),'source_sha256':trace.sha(source),'pin_sha256':trace.sha(pin)})
        shutil.copyfile(binary,self.root/'tools/tracer.so')
        w.write(self.root/'validation/tracer-build.json',project.read(stamp))
        self.report['checks']['references']=w.check('NOT_CONFIGURED','No general reference-approval contract supplied',False)
        self.report['checks']['layout']=w.check('NOT_REQUESTED','No layout transformation requested',False)
    def lift(self):
        build=self.root/'build';options={k:v for k,v in self.doc['lift'].items() if k in ('image','timeout','extra_link_args')}
        options['entry_symbols']=[self.description['entry']]
        assembly,link=project.lift_original(build,options,self.runner,[__import__('os').environ.get('JAVA','java'),'-jar',self.root/'toolkit.jar'],self.base,configuration_values={'lift.image':self.doc['lift'].get('image','foxdec')},static_syscalls=self.description['static_start'])
        shutil.copyfile(assembly,build/'lifted.asm')
        import callback_rebind
        callback_changes=callback_rebind.restore(build/'lifted.asm',build/'original',project.read(build/'callback-plan.json'))
        w.write(self.root/'validation/callback-array-bindings.json',{'rebound_slots':callback_changes,'final_link_validation_required':True})
        if self.description['entry']=='main':
            symbols,_=self.runner.command('original-main-startup-symbol',['nm','-an','--defined-only',build/'original'])
            repaired=rebind_main_startup(build/'lifted.asm',symbols)
            w.write(self.root/'validation/main-startup-binding.json',{'original_main_pointer_rebound':repaired,'scope':'ABI main argument in lifted CRT _start only; no general pointer proof'})
        if 'protection' in self.doc:
            import protection_regions
            protection_regions.materialize(self,build/'lifted.asm')
        self.runner.command('baseline-assemble',['nasm','-f','elf64',build/'lifted.asm','-o',build/'baseline.o'])
        raw=(build/'original').read_bytes();static=not project.elf_inventory(build/'original')['external_libraries']
        if self.description['entry']=='_start' and static:
            argv=['ld','-m','elf_x86_64','-e','_start',build/'baseline.o','-o',build/'baseline']
        else:
            # Preserve original ET_EXEC/ET_DYN linking class; no implicit CRT main.
            mode='-no-pie' if struct.unpack_from('<H',raw,16)[0]==2 else '-pie'
            argv=[str(v).replace('{object}',str(build/'baseline.o')).replace('{output}',str(build/'baseline')) for v in link]
            argv.insert(1,mode)
        self.runner.command('baseline-link',argv)
        if self.description['static_start']:
            import syscall_lift
            original_contract=project.read(build/'syscall-extension/contract.json')
            if original_contract['schema']=='bcl-static-syscalls-2':
                from syscall_cfg import contract as cfg_contract,disassemble
                decoded=disassemble(build/'baseline',self.runner,'baseline-syscall-inventory')
                rebuilt_contract=cfg_contract(build/'baseline',decoded)
            else:rebuilt_contract=syscall_lift.contract(build/'baseline')
            # Validate live buffer bindings before executing the lifted program.
            def effects(contract):
                if contract['schema']=='bcl-static-syscalls-2':return sorted({(site['kind'],site['number']) for site in contract['sites']})
                return [{k:v for k,v in site.items() if k not in ('ip','address')} for site in contract['sites']]
            w.require(effects(original_contract)==effects(rebuilt_contract),'Rebuilt syscall inventory or verified constant buffer bytes differ','UNSUPPORTED')
            w.write(self.root/'validation/syscall-bindings.json',{'status':'PASS','original':original_contract,'baseline':rebuilt_contract})
        self.report['artifacts']['baseline']=self.elf(build/'baseline')
        self.check_main_definition('baseline')
        self.runner.command('baseline-entry-header',['readelf','-h',build/'baseline'])
        self.java('callback-check',build/'original','--rebuilt',build/'baseline','--report',self.root/'validation/callbacks.json')
    def compare(self):
        execution=self.doc['execution'];functional=[];stable=True
        for case in execution['cases']:
            for repeat in range(execution['repetitions']):
                outputs=[self.native_outputs[v,case['id'],repeat] for v in self.active_variants]
                okay=all(pair[0]==pair[1] and pair[0]['exit_code']==0 for pair in outputs) and outputs[0][0]==outputs[1][0]
                functional.append({'case':case['id'],'repetition':repeat,'status':'PASS' if okay else 'FAIL','outputs':dict(zip(self.active_variants,outputs))})
            for variant in self.active_variants:
                for repeat in range(1,execution['repetitions']):
                    stable &= compare.token_compare(self.runs[variant,case['id'],0],self.runs[variant,case['id'],repeat],self.doc['comparison']['line_identity'],self.doc['comparison']['scope'])['equal'] and self.native_outputs[variant,case['id'],0]==self.native_outputs[variant,case['id'],repeat]
        w.write(self.root/'validation/functional_tests.json',functional)
        self.report['checks']['functional']=w.check('PASS' if all(r['status']=='PASS' for r in functional) else 'FAIL','Original/baseline and native/PIN outputs and zero exits compared',True,['validation/functional_tests.json'])
        self.report['checks']['repeat_stability']=(w.check('NOT_REQUESTED','One run per input; repeat stability was not tested',False) if execution['repetitions']==1 else w.check('PASS' if stable else 'INCONCLUSIVE','Recorded line sequences and outputs checked across repeated fixed inputs',False))
        self.report['checks']['observations']=w.check('PASS','PIN traces captured; no cross-build observation-equality claim requested',True)
        self.report['checks']['event_correspondence']=w.check('NOT_CONFIGURED','No inferred cross-build instruction correspondence',False)
        self.report['comparison']={'policy':'capture_only','scope':self.doc['comparison']['scope'],'line_identity':self.doc['comparison']['line_identity'],'pairs':[],'classification_counts':{},'preserved_observations':0,'policy_violations':0,'unmatched_events':0,'attribution':'Trace capture only; no inferred transformation or security proof'}
        if self.doc.get('security',{}).get('enabled'):
            w.require(all(run['observed_events']>0 for run in self.runs.values()),'No observed accesses for the requested secret-input security test','INCONCLUSIVE')
            self.security(stable)

