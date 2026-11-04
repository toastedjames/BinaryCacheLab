"""Larger encoded ELF programs for qualification of the declared machine, not native Linux processes."""
from pathlib import Path
import struct
import project

CODE=0x400200
DATA=0x410000

def make(destination, kind, sectioned=True):
    destination=Path(destination)
    destination.mkdir(parents=True)
    regions=[]
    if kind=='linear':
        code=bytes.fromhex('89f883e00f48c1e00248b9')+struct.pack('<Q',DATA)+bytes.fromhex('8b0401')
        code+=bytes.fromhex('83c001')*1024+b'\xc3'
        regions=[{'name':'table','address':DATA,'size':64,'alignment':64}]
        inputs=[{'register':'rdi','values':list(range(16))},{'register':'rsi','values':[0,1]}]
    elif kind=='loop':
        code=bytes.fromhex('48b9')+struct.pack('<Q',DATA)+bytes.fromhex('31c0ba8000000003014883c10483ea0175f5c3')
        regions=[{'name':'table','address':DATA,'size':512,'alignment':64}]
        inputs=[{'register':'rdi','values':[0,1,2,3]},{'register':'rsi','values':[0,1]}]
    elif kind=='multi':
        code=bytes.fromhex('89fa83e20f48c1e20231c0')
        for i in range(8):
            address=DATA+i*128
            code+=bytes.fromhex('48b9')+struct.pack('<Q',address)+bytes.fromhex('030411')
            regions.append({'name':'table'+str(i),'address':address,'size':64,'alignment':64})
        code+=b'\xc3'
        inputs=[{'register':'rdi','values':list(range(16))},{'register':'rsi','values':[0,1]}]
    else:raise ValueError('Unknown larger fixture')
    raw=bytearray(0x20000)
    raw[:7]=b'\x7fELF\x02\x01\x01'
    struct.pack_into('<HHIQQQ',raw,16,2,62,1,CODE,64,0xc000 if sectioned else 0)
    struct.pack_into('<HHHHHH',raw,52,64,56,2,64 if sectioned else 0,3+len(regions) if sectioned else 0,1 if sectioned else 0)
    struct.pack_into('<IIQQQQQQ',raw,64,1,5,0,0x400000,0,0x10000,0x10000,0x1000)
    struct.pack_into('<IIQQQQQQ',raw,120,1,6,0x10000,DATA,0,0x10000,0x10000,0x1000)
    raw[0x200:0x200+len(code)]=code
    for region in regions:
        offset=region['address']-DATA+0x10000
        raw[offset:offset+region['size']]=struct.pack('<I',7)*(region['size']//4)
    if sectioned:
        names=b'\0.shstrtab\0.text\0'
        name_offsets=[]
        for region in regions:
            name_offsets.append(len(names));names+=('.'+region['name']).encode()+b'\0'
        raw[0xb000:0xb000+len(names)]=names
        struct.pack_into('<IIQQQQIIQQ',raw,0xc040,1,3,0,0,0xb000,len(names),0,0,1,0)
        struct.pack_into('<IIQQQQIIQQ',raw,0xc080,11,1,6,CODE,0x200,len(code),0,0,1,0)
        for i,region in enumerate(regions):
            struct.pack_into('<IIQQQQIIQQ',raw,0xc0c0+64*i,name_offsets[i],1,3,region['address'],0x10000+region['address']-DATA,region['size'],0,0,region['alignment'],0)
    (destination/'original.elf').write_bytes(raw)
    profile={'schema':'bcl-bounded-references-1','binary':'original.elf','entries':[CODE],
             'regions':[{k:r[k] for k in ('name','address','size')} for r in regions],
             'machine':{'runtime':'closed-static-x86-64','instruction_set':'bcl-x86-64-integer-1','register_defaults':'zero','initial_registers':{},'flags':'zero','memory_initialization':'elf-file-bss-zero-stack-zero','stack':{'address':0x700000,'size':4096}},
             'inputs':inputs,'bounds':{'max_steps_per_execution':10000,'max_total_steps':500000,'max_executions':256,'max_memory_bytes':135168,'max_reference_events':20000}}
    policy={'schema':'bcl-automatic-rewrite-1','original':'original.json','regions':regions,'destinations':[DATA+4,DATA+0x2000],
            'secret_inputs':[0],'register_outputs':[{'register':'rax','encoding':'scalar'}]}
    project.save(destination/'original.json',profile)
    project.save(destination/'rewrite.json',policy)
    return {'code_bytes':len(code),'binary_bytes':len(raw),'region_count':len(regions),'inputs':len(inputs[0]['values'])*len(inputs[1]['values'])}
