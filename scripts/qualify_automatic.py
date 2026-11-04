"""Real end-to-end automatic-decision qualification, with finite encoded ELF programs."""
from pathlib import Path
import runpy
import shutil
import struct
import automatic
import project


def qualify(output):
    root=Path(output).absolute()
    project.require(not root.exists(),'Qualification output already exists')
    root.mkdir(parents=True)
    generator=runpy.run_path(str(Path(__file__).with_name('make-automatic-example.py')))['make']
    rows=[]
    for name in ('supported','bad-placement','occupied','bound-exhaustion','unsupported-opcode','already-distinguishing','compiler-reg-inc','compiler-stack-inc','compiler-imm32'):
        source=root/name/'source'
        generator(source)
        policy=project.read(source/'rewrite.json')
        original=project.read(source/'original/lookup.json')
        binary=source/'original/lookup.elf'
        raw=bytearray(binary.read_bytes())
        if name=='bad-placement':policy['destinations']=[0x401004]
        if name=='occupied':raw[0x1040]=1;policy['destinations']=[0x401040]
        if name=='bound-exhaustion':original['bounds']['max_steps_per_execution']=1
        if name=='unsupported-opcode':raw[0x200:0x202]=b'\x0f\x05'
        if name=='already-distinguishing':
            raw[0x205]=6
            struct.pack_into('<II',raw,0x1040,7,7)
            struct.pack_into('<Q',raw,0xce0,68)
            policy['regions'][0]['size']=68
            policy['destinations']=[0x401100]
            original['regions'][0]['size']=68
        if name.startswith('compiler-'):
            base=(0x401000).to_bytes(8,'little')
            lookup=bytes.fromhex('89f848c1e00248b9')+base+bytes.fromhex('8b0401')
            if name=='compiler-reg-inc':code=lookup+bytes.fromhex('ffc0c3')
            elif name=='compiler-stack-inc':code=lookup+bytes.fromhex('894424fcff4424fc8b4424fcc3')
            else:code=bytes.fromhex('554889e5897dfc8b45fc83e00189c1b8')+(0x401000).to_bytes(4,'little')+bytes.fromhex('488d04888b008945f8ff45f88b45f85dc3')
            raw[0x200:0x200+len(code)]=code
            struct.pack_into('<Q',raw,0xca0,len(code))
        binary.write_bytes(raw)
        project.save(source/'rewrite.json',policy)
        project.save(source/'original/lookup.json',original)
        before=binary.read_bytes()
        evidence=root/name/'evidence'
        result=automatic.run(source/'rewrite.json',evidence)
        expected=name=='supported' or name.startswith('compiler-')
        project.require(result['bounded_transformation_approved']==expected,'Unexpected automatic decision: '+name+': '+str(result))
        project.require(binary.read_bytes()==before,'Original binary changed')
        project.require((evidence/'protected.elf').exists()==expected,'Rejected candidate was published')
        replay=automatic.verify(evidence)
        project.require(result==replay,'Qualification replay disagreement')
        rows.append({'case':name,'status':result['status'],'expected_approval':expected,'replayed':True,'original_unchanged':True})
    moved=root/'relocated-evidence'
    shutil.copytree(root/'supported/evidence',moved)
    project.require(automatic.verify(moved)['bounded_transformation_approved'],'Relocated evidence cannot replay')
    # A modified artifact must fail integrity before another decision or publication.
    target=moved/'protected.elf'
    target.write_bytes(target.read_bytes()+b'!')
    try:
        automatic.verify(moved)
    except ValueError:
        pass
    else:
        raise AssertionError('Tampered automatic evidence accepted')
    result={'schema':'bcl-automatic-qualification-1','status':'AUTOMATIC_QUALIFICATION_EXPECTATIONS_MET',
            'cases':rows,'checks':len(rows)*5+2,'scope':'Real exhaustive interpreter, rewrite, approval, publication and replay; no native ELF process execution'}
    project.save(root/'summary.json',result)
    project.seal(root)
    return result
