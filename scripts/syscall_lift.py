"""Byte-checked Linux syscall extension for the pinned FoxDec source.

A strict constant-buffer fast path is retained. Other programs use a bounded
interprocedural CFG inventory with runtime write arguments. Syscall numbers must
resolve to write, exit or exit_group; unmodeled kernel effects are rejected.
"""
import hashlib
import json
from pathlib import Path
import struct
import zipfile


def require(ok, detail):
    if not ok:
        raise RuntimeError('Unsupported static syscall program: '+detail)


def contract(path):
    blob=Path(path).read_bytes()
    require(len(blob)>=64 and blob[:7]==b'\x7fELF\x02\x01\x01','require ELF64 little endian')
    kind,machine=struct.unpack_from('<HH',blob,16)
    entry,phoff=struct.unpack_from('<QQ',blob,24)
    width,count=struct.unpack_from('<HH',blob,54)
    require(kind==2 and machine==62 and width==56 and 0<count<=128 and phoff+width*count<=len(blob),'require fixed x86-64 ET_EXEC with valid program headers')
    headers=[struct.unpack_from('<IIQQQQQQ',blob,phoff+n*width) for n in range(count)]
    require(not any(h[0] in (2,3) for h in headers),'dynamic loading is outside this contract')
    loads=[h for h in headers if h[0]==1]
    require(all(h[2]+h[5]<=len(blob) and h[5]<=h[6] for h in loads),'invalid load segment')
    def mapped(address,size,permission):
        owners=[h for h in loads if h[1]&permission and h[3]<=address and address+size<=h[3]+h[5]]
        require(size>0 and len(owners)==1,'address is not uniquely file backed with required permissions')
        h=owners[0];offset=h[2]+address-h[3]
        return blob[offset:offset+size]
    regs={};ip=entry;sites=[];instructions=[]
    for _ in range(256):
        start=ip;first=mapped(ip,1,1)[0];rex=0
        if 0x40<=first<=0x4f:
            rex=first;ip+=1;first=mapped(ip,1,1)[0]
        if 0xb8<=first<=0xbf:
            reg=first-0xb8+(8 if rex&1 else 0);size=8 if rex&8 else 4
            data=mapped(ip+1,size,1);regs[reg]=int.from_bytes(data,'little');ip+=1+size
        elif first==0xc7:
            modrm=mapped(ip+1,1,1)[0]
            require(modrm&0xf8==0xc0,'only register immediate MOV is supported')
            value=int.from_bytes(mapped(ip+2,4,1),'little',signed=bool(rex&8))
            regs[(modrm&7)+(8 if rex&1 else 0)]=value&((1<<64)-1);ip+=6
        elif first in (0x31,0x33):
            modrm=mapped(ip+1,1,1)[0];a=(modrm&7)+(8 if rex&1 else 0);b=((modrm>>3)&7)+(8 if rex&4 else 0)
            require(modrm>>6==3 and a==b,'only register-self XOR is supported')
            regs[a]=0;ip+=2
        elif first==0x90 and not rex:
            ip+=1
        elif first==0x0f and not rex and mapped(ip,2,1)==b'\x0f\x05':
            number=regs.get(0);ip+=2
            require(number in (1,60),'only constant write and exit syscall numbers are supported')
            if number==1:
                fd,address,size=regs.get(7),regs.get(6),regs.get(2)
                require(fd in (1,2) and isinstance(address,int) and isinstance(size,int) and 0<size<=1048576,'write requires constant stdout/stderr, buffer and bounded length')
                data=mapped(address,size,4)
                sites.append({'ip':start,'kind':'write','fd':fd,'address':address,'length':size,'buffer_sha256':hashlib.sha256(data).hexdigest()})
                for reg in (0,1,11):regs.pop(reg,None)
            else:
                require(regs.get(7)==0,'only exit(0) is supported')
                sites.append({'ip':start,'kind':'exit','status':0})
                instructions.append({'ip':start,'bytes':mapped(start,ip-start,1).hex()})
                return {'schema':'bcl-static-syscalls-1','binary_sha256':hashlib.sha256(blob).hexdigest(),'entry':entry,'sites':sites,'instructions':instructions,
                        'scope':'Straight-line constant write/exit; syscall return and RCX/R11 clobbered; kernel reads excluded from data observer'}
        else:
            raise RuntimeError('Unsupported static syscall program: opcode at '+hex(start)+' is outside the straight-line write/exit contract')
        instructions.append({'ip':start,'bytes':mapped(start,ip-start,1).hex()})
    raise RuntimeError('Unsupported static syscall program: instruction bound exceeded or no exit')


def writable_regions(path):
    blob=Path(path).read_bytes()
    require(len(blob)>=64 and blob[:6]==b'\x7fELF\x02\x01','invalid ELF for writable region inventory')
    phoff,=struct.unpack_from('<Q',blob,32);phwidth,phcount=struct.unpack_from('<HH',blob,54)
    require(phwidth==56 and phoff+phcount*phwidth<=len(blob),'invalid program header inventory')
    loads=[struct.unpack_from('<IIQQQQQQ',blob,phoff+n*phwidth) for n in range(phcount)]
    shoff,=struct.unpack_from('<Q',blob,40);width,count,strings=struct.unpack_from('<HHH',blob,58)
    if not shoff and not count:return []
    require(width==64 and 0<count<=8192 and strings<count and shoff+width*count<=len(blob),'invalid section inventory')
    sections=[struct.unpack_from('<IIQQQQIIQQ',blob,shoff+n*width) for n in range(count)]
    names_section=sections[strings]
    require(names_section[4]+names_section[5]<=len(blob),'invalid section names')
    names=blob[names_section[4]:names_section[4]+names_section[5]];result=[]
    for section in sections:
        name_offset,kind,flags,address,offset,size,*_=section
        if flags&3!=3 or flags&4 or not size:continue
        require(kind in (1,8) and size<=134217728 and address+size<1<<63,'unsupported writable section extent')
        require(kind==8 or offset+size<=len(blob),'writable section bytes exceed ELF')
        owners=[h for h in loads if h[0]==1 and h[1]&2 and h[3]<=address and address+size<=h[3]+h[6]]
        require(len(owners)==1,'writable section not uniquely contained in writable load mapping')
        require(name_offset<len(names) and b'\0' in names[name_offset:],'invalid section name')
        result.append({'name':names[name_offset:].split(b'\0',1)[0].decode('ascii'),'address':address,'size':size,'zero_initialized':kind==8})
    return result


def prepare(original, destination, disassembly=None):
    try:doc=contract(original)
    except RuntimeError:
        if disassembly is None:raise
        from syscall_cfg import contract as cfg_contract
        doc=cfg_contract(original,disassembly)
    destination=Path(destination);destination.mkdir()
    writes=[s['ip'] for s in doc['sites'] if s['kind']=='write'];exits=[s['ip'] for s in doc['sites'] if s['kind']=='exit']
    sites=writes+exits
    sources={
        'src/Disassembler/Disassembler.hs':('baseOpcode = choice [','baseOpcode = choice [\n                opcode 0x0f >> opcode 0x05 >> instr "syscall" [] ,'),
        'src/Data/X86/Instruction.hs':('do_not_modify mnemonic = isCall mnemonic','do_not_modify mnemonic = mnemonic == SYSCALL || isCall mnemonic'),
        'src/WithAbstractPredicates/ControlFlow.hs':('    | isHalt op = Terminal',
            '    | op == SYSCALL && inAddress i `elem` '+str(exits)+' = Terminal\n'
            '    | op == SYSCALL && inAddress i `elem` '+str(writes)+' = JustRips [inAddress i + fromIntegral (inSize i)]\n'
            '    | op == SYSCALL = error "Undeclared syscall site"\n'
            '    | isHalt op = Terminal'),
        'src/WithAbstractSymbolicValues/SymbolicExecution.hs':('  | isRet mnemonic        = sreturn ctxt i',
            '  | mnemonic == SYSCALL && label `elem` '+str(sites)+' = mapM_ (\\reg -> swrite_reg ctxt "Linux syscall clobber" (Reg64 reg) (top ctxt "syscall")) [RAX,RCX,R11]\n'
            '  | mnemonic == SYSCALL = error "Undeclared syscall site"\n'
            '  | isRet mnemonic        = sreturn ctxt i')}
    regions=writable_regions(original)
    doc['global_memory_regions']=regions
    if regions:
        boundaries=sorted({value for region in regions for value in (region['address'],region['address']+region['size'])})
        structure='IM.fromList ['+','.join('('+str(value)+',False)' for value in boundaries)+']'
        sources['src/WithAbstractPredicates/ContextSensitiveAnalysis.hs']=(
            '  let empty_L0 = L0 IM.empty IM.empty IM.empty ""',
            '  let empty_L0 = L0 IM.empty IM.empty ('+structure+') ""')
    manifest=[];checks=[]
    with zipfile.ZipFile(Path(__file__).with_name('foxdec-syscall-base.zip')) as archive:
        for name,(old,new) in sources.items():
            data=archive.read(name);text=data.decode('utf-8')
            require(text.count(old)==1,'pinned source patch anchor mismatch: '+name)
            patched=text.replace(old,new).encode('utf-8');target=destination/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(patched)
            before=hashlib.sha256(data).hexdigest();after=hashlib.sha256(patched).hexdigest()
            checks.append(before+'  '+name+'\n');manifest.append({'path':name,'base_sha256':before,'patched_sha256':after})
        (destination/'LICENSE').write_bytes(archive.read('LICENSE'))
    (destination/'base.sha256').write_bytes(''.join(checks).encode('ascii'))
    doc['source_files']=manifest
    (destination/'contract.json').write_text(json.dumps(doc,indent=2)+'\n',encoding='utf-8')
    return doc


def container_setup():
    # Refuse any source revision other than the exact reviewed official files.
    return ('sha256sum -c /bcl-syscall/base.sha256; '
            'while read -r hash file; do cp "/bcl-syscall/$file" "$file"; done < /bcl-syscall/base.sha256; ')
