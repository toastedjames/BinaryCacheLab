"""Broader reference/transformation qualification with explicitly separated environment gates."""
from pathlib import Path
import argparse
import copy
import hashlib
import json
import os
import shutil
import subprocess
import struct
import sys
import tempfile
import automatic
import broad_fixtures
import easy
import project


def portable(root):
    rows=[]
    for kind in ('linear','loop','multi'):
        for sectioned in (True,False):
            name=kind+('-sections' if sectioned else '-sectionless')
            source=root/name/'source'
            dimensions=broad_fixtures.make(source,kind,sectioned)
            evidence=root/name/'evidence'
            before=(source/'original.elf').read_bytes()
            result=automatic.run(source/'rewrite.json',evidence)
            project.require(result.get('bounded_transformation_approved'),name+': '+str(result))
            project.require(automatic.verify(evidence)==result,'Broader reconstruction replay differs')
            original=project.read(evidence/'original-analysis.json')
            manifest=project.read(evidence/('attempt-%02d'%result['selected_attempt'])/'transformation.json')
            project.require(manifest.get('executed_reference_rebinding_verified'),'Missing reference-rebinding proof')
            project.require(original['evaluated_executions']==dimensions['inputs'],'Input enumeration omitted cases')
            project.require((source/'original.elf').read_bytes()==before,'Original changed')
            project.require(original['reference_events']>0,'Reference analysis was not exercised')
            rows.append({'case':name,**dimensions,'status':result['status'],'executions':original['evaluated_executions'],
                         'instructions_covered':len(original['instruction_coverage']),'reference_events':original['reference_events'],
                         'rebinding_verified':True,'replay_verified':True,'metadata_variant':'sectioned' if sectioned else 'sectionless; not a tool-stripped artifact'})
    # Larger unsupported-reference and incomplete-exploration controls must not publish.
    for name in ('missing-address-encoding','insufficient-bound'):
        source=root/name/'source'
        broad_fixtures.make(source,'linear')
        if name=='missing-address-encoding':
            binary=source/'original.elf';raw=bytearray(binary.read_bytes())
            # RIP-relative LEA is interpreted but is outside automatic immediate rebinding.
            start=0x209;raw[start:start+10]=bytes.fromhex('488d0d')+struct.pack('<i',broad_fixtures.DATA-(broad_fixtures.CODE+9+7))+b'\x90'*3
            binary.write_bytes(raw)
        else:
            profile=project.read(source/'original.json');profile['bounds']['max_steps_per_execution']=3;project.save(source/'original.json',profile)
        evidence=root/name/'evidence';result=automatic.run(source/'rewrite.json',evidence)
        project.require(not result['bounded_transformation_approved'] and not (evidence/'protected.elf').exists(),'Larger unsupported case was published')
        project.require(automatic.verify(evidence)==result,'Larger rejection replay differs')
        rows.append({'case':name,'status':result['status'],'expected_rejection':True,'replay_verified':True})
    return {'status':'PORTABLE_TRANSFORMATION_REFERENCE_EXPECTATIONS_MET','cases':rows}


def isolated_install(root):
    install=root/'isolated-installation'
    (install/'scripts').mkdir(parents=True)
    shutil.copy2(project.ROOT/'binarycachelab.jar',install/'binarycachelab.jar')
    for file in (project.ROOT/'scripts').glob('*.py'):
        shutil.copy2(file,install/'scripts'/file.name)
    # Only installed runtime/scripts, fresh configuration/home, separate current directory; no previous evidence.
    source=root/'isolated-input'
    broad_fixtures.make(source,'multi')
    env=dict(os.environ,HOME=str(root/'fresh-home'),USERPROFILE=str(root/'fresh-home'),PYTHONDONTWRITEBYTECODE='1')
    Path(env['HOME']).mkdir()
    runner=easy.Runner();runner.logs=root/'isolated-logs';runner.logs.mkdir()
    for args in ([str(source/'rewrite.json'),'--output',str(root/'isolated-evidence')],['verify',str(root/'isolated-evidence')]):
        command=[sys.executable,'-B',install/'scripts/console.py','rewrite',*args]
        # Runner uses inherited environment, so explicitly invoke the child here with its clean home.
        result=subprocess.run(list(map(str,command)),env=env,cwd=root,capture_output=True,text=True,timeout=300)
        (runner.logs/('run.log' if args[0]!='verify' else 'verify.log')).write_text(result.stdout+'\n'+result.stderr)
        project.require(result.returncode==0,'Isolated installation failed: '+result.stderr+result.stdout[-1000:])
    return {'status':'ISOLATED_COPY_EXPECTATIONS_MET','fresh_home':True,'new_working_directory':True,
            'scope':'Fresh toolkit copy and configuration using preinstalled host Java/Python; not a clean OS dependency installation'}


def native(root):
    compilers={name:shutil.which(name) for name in ('gcc','clang')}
    tools={name:shutil.which(name) for name in ('strip','nm')}
    missing=[name for name,path in {**compilers,**tools}.items() if path is None]
    if not sys.platform.startswith('linux') or missing:
        return {'status':'BLOCKED_NATIVE_ENVIRONMENT','missing_tools':missing,'reason':'Requires Linux with GCC, Clang, strip and nm; no compiler matrix was claimed'}
    runner=easy.Runner();runner.logs=root/'logs';runner.logs.mkdir(parents=True)
    rows=[]
    for compiler,path in compilers.items():
        runner.command(compiler+'-version',[path,'--version'])
        for optimization in ('-O0','-O1','-O2','-O3','-Os'):
            try:
                case=root/(compiler+optimization[1:]);case.mkdir()
                source=case/'kernel.c'
                statements='\n'.join('v = v + %du;'%((i%13)+1) for i in range(512))
                source.write_text('typedef unsigned U;\n__attribute__((section(".table"),aligned(64))) volatile U table[16] = {'+','.join(['7']*16)+'};\n__attribute__((section(".spare"),aligned(64))) volatile unsigned char spare[32768] = {1};\nU kernel(U s) { volatile U v = table[s & 15u];\n'+statements+'\nreturn v; }\n')
                binary=case/'unstripped.elf'
                argv=[path,optimization,'-fno-pie','-no-pie','-mcmodel=large','-nostdlib','-static','-fno-stack-protector','-fno-asynchronous-unwind-tables','-fno-unwind-tables','-fcf-protection=none','-fno-ident','-Wl,--build-id=none,-e,kernel,-Ttext=0x400000,-Tdata=0x500000',source,'-o',binary]
                runner.command(case.name+'-compile',argv)
                symbols,_=runner.command(case.name+'-symbols',[tools['nm'],'-S','--defined-only',binary])
                selected={}
                for line in symbols.splitlines():
                    fields=line.split()
                    if len(fields)>=4 and fields[-1] in ('kernel','table','spare'):selected[fields[-1]]=(int(fields[0],16),int(fields[1],16))
                project.require(set(selected)=={'kernel','table','spare'},'Missing compiled symbols')
                stripped=case/'stripped.elf';shutil.copy2(binary,stripped)
                runner.command(case.name+'-strip',[tools['strip'],'--strip-all',stripped])
                profile={'schema':'bcl-bounded-references-1','binary':'stripped.elf','entries':[selected['kernel'][0]],
                         'regions':[{'name':'table','address':selected['table'][0],'size':64}],
                         'machine':{'runtime':'closed-static-x86-64','instruction_set':'bcl-x86-64-integer-1','register_defaults':'zero','initial_registers':{},'flags':'zero','memory_initialization':'elf-file-bss-zero-stack-zero','stack':{'address':0x70000000,'size':65536}},
                         'inputs':[{'register':'rdi','values':list(range(16))}],
                         'bounds':{'max_steps_per_execution':10000,'max_total_steps':500000,'max_executions':16,'max_memory_bytes':1048576,'max_reference_events':100000}}
                project.save(case/'original.json',profile)
                policy={'schema':'bcl-automatic-rewrite-1','original':'original.json','regions':[{'name':'table','address':selected['table'][0],'size':64,'alignment':64}],
                        'destinations':[selected['spare'][0]+64],'secret_inputs':[0],'register_outputs':[{'register':'rax','encoding':'scalar'}]}
                project.save(case/'rewrite.json',policy)
                result=automatic.run(case/'rewrite.json',case/'evidence')
                project.require(result['bounded_transformation_approved'],'Compiler transformation did not qualify: '+case.name+'; inspect '+str(case/'evidence/summary.json'))
                automatic.verify(case/'evidence')
                # Unstripped symbol tables are a deliberate supported-boundary rejection, not a successful transform.
                profile['binary']='unstripped.elf';project.save(case/'original.json',profile)
                rejected=automatic.run(case/'rewrite.json',case/'unstripped-rejection')
                project.require(not rejected['bounded_transformation_approved'] and not (case/'unstripped-rejection/protected.elf').exists(),'Unsupported symbol-table transform was published')
                rows.append({'compiler':compiler,'optimization':optimization,'stripped_transformation':'APPROVED_WITHIN_BOUNDS','reference_replay':True,'unstripped_symbol_table_rejection':True,
                             'original_sha256':hashlib.sha256(stripped.read_bytes()).hexdigest(),'binary_bytes':stripped.stat().st_size})
            except (ValueError,RuntimeError,OSError,subprocess.TimeoutExpired) as error:
                rows.append({'compiler':compiler,'optimization':optimization,'status':'FAILED','failure':str(error)})
    return {'status':'NATIVE_COMPILER_EXPECTATIONS_MET' if all(r.get('status')!='FAILED' for r in rows) else 'NATIVE_COMPILER_EXPECTATIONS_FAILED','cases':rows}


def qualify(output,run_native=False):
    root=Path(output).absolute();project.require(not root.exists(),'Use a new broader qualification directory');root.mkdir(parents=True)
    summary={'schema':'bcl-broader-qualification-1','status':'RUNNING','native_requested':run_native,'automatic_rewrite_allowed':False,
             'clean_installation':{'status':'NOT_RUN_REQUIRES_DOCKER','command':'bash scripts/qualify-clean-linux.sh NEW_OUTPUT_DIRECTORY'}}
    project.save(root/'environment.json',{'platform':sys.platform,'python':sys.version,'java':os.environ.get('JAVA','java'),
                 'tools':{k:shutil.which(k) for k in ('gcc','clang','strip','nm','docker','wsl')}})
    try:
        summary['portable']=portable(root/'portable')
        summary['isolated_installation']=isolated_install(root)
        summary['native']=native(root/'native') if run_native else {'status':'NOT_RUN_NATIVE_MATRIX'}
        summary['status']='BROADER_QUALIFICATION_EXPECTATIONS_MET' if summary['native']['status']=='NATIVE_COMPILER_EXPECTATIONS_MET' else 'BROADER_QUALIFICATION_FAILED' if summary['native']['status']=='NATIVE_COMPILER_EXPECTATIONS_FAILED' else 'PORTABLE_QUALIFIED_NATIVE_UNVERIFIED'
    except (ValueError,RuntimeError,OSError,subprocess.TimeoutExpired) as error:
        summary['status']='BROADER_QUALIFICATION_FAILED';summary['failure']=str(error)
    project.save(root/'summary.json',summary);project.seal(root)
    return summary


def main(args=None,raw=False):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',required=True,type=Path)
    parser.add_argument('--native',action='store_true',help='Require GCC/Clang optimization and real strip matrices on Linux')
    opts=parser.parse_args(args)
    result=qualify(opts.output,opts.native)
    if raw:print(json.dumps(result,indent=2))
    else:
        print('Broader qualification\n=====================\nStatus: '+result['status'])
        for key in ('portable','isolated_installation','native'):print(key.replace('_',' ').title()+': '+result.get(key,{}).get('status','not completed'))
        if result.get('failure'):print('Failure: '+result['failure'])
        print('Evidence: '+str(opts.output.absolute()))
        print('Clean OS dependency installation is a separate Docker qualification; an isolated copy does not establish it.')
    return 0 if result['status']=='BROADER_QUALIFICATION_EXPECTATIONS_MET' or result['status']=='PORTABLE_QUALIFIED_NATIVE_UNVERIFIED' and not opts.native else 7
