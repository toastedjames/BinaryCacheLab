"""Conservative interprocedural syscall inventory for static ELF64 programs.

Instruction decoding comes from objdump; every instruction's bytes are checked
against the executable. Register value sets and function return summaries reach a fixed point.
Unknown instruction effects erase constants instead of guessing syscall numbers.
This is a lifting adapter inventory, not whole-program equivalence verification.
"""
from collections import deque
import hashlib
from pathlib import Path
import re
import struct


def require(ok, detail):
    if not ok:raise RuntimeError('Unsupported syscall control flow: '+detail)


def register(text):
    text=text.strip().lower()
    names=['rax','rcx','rdx','rbx','rsp','rbp','rsi','rdi']
    for index,name in enumerate(names):
        aliases={name:(64,0),'e'+name[1:]:(32,0),name[1:]:(16,0)}
        if index<4:aliases[name[1]+'l']=(8,0);aliases[name[1]+'h']=(8,8)
        else:aliases[{'rsp':'spl','rbp':'bpl','rsi':'sil','rdi':'dil'}[name]]=(8,0)
        if text in aliases:return index,*aliases[text]
    match=re.fullmatch(r'r(8|9|1[0-5])([dwb]?)',text)
    if match:return int(match[1]),{'':64,'d':32,'w':16,'b':8}[match[2]],0
    return None


MAX_VALUES=64


def finite(values):
    values=frozenset(values)
    return values if 0<len(values)<=MAX_VALUES else None


def merge(left,right):
    result={}
    for index in left.keys()&right.keys():
        joined=finite(left[index]|right[index])
        if joined is not None:result[index]=joined
    return result


def address(text,state,next_ip):
    text=text.strip().lower()
    if any(segment+':' in text for segment in ('fs','gs')):return None
    text=re.sub(r'^(?:(?:byte|word|dword|qword)\s+ptr\s+)?(?:ds:|cs:|es:|ss:)?','',text)
    if text.startswith('[') and text.endswith(']'):text=text[1:-1]
    terms=re.findall(r'[+-]?[^+-]+',text.replace(' ',''))
    if not terms or ''.join(terms)!=text.replace(' ',''):return None
    totals=frozenset([0]);bits=64
    for term in terms:
        sign=-1 if term.startswith('-') else 1;term=term.lstrip('+-');parts=term.split('*')
        if len(parts)>2:return None
        atom=parts[0]
        if atom in ('rip','eip'):
            values=frozenset([next_ip]);bits=32 if atom=='eip' else bits
        else:
            reg=register(atom)
            if reg:
                index,width,shift=reg
                if width not in (32,64):return None
                values=state.get(index)
                if values is not None:values=finite((v>>shift)&((1<<width)-1) for v in values)
                if width==32:bits=32
            else:
                try:values=frozenset([int(atom,0)])
                except ValueError:return None
        if values is None:return None
        try:scale=int(parts[1],0) if len(parts)==2 else 1
        except ValueError:return None
        if len(parts)==2 and scale not in (1,2,4,8):return None
        totals=finite(a+sign*b*scale for a in totals for b in values)
        if totals is None:return None
    return finite(v&((1<<bits)-1) for v in totals)


def value(text,state,next_ip=0,read=None):
    reg=register(text)
    if reg:
        index,width,shift=reg;values=state.get(index)
        return None if values is None else finite((v>>shift)&((1<<width)-1) for v in values)
    if '[' in text or re.match(r'(?:byte|word|dword|qword)\s+ptr\b',text):
        match=re.match(r'(byte|word|dword|qword)\s+ptr\b',text)
        if read is None or match is None:return None
        addresses=address(text,state,next_ip)
        if addresses is None:return None
        width={'byte':1,'word':2,'dword':4,'qword':8}[match[1]];result=[]
        for at in addresses:
            number=read(at,width)
            if number is None:return None
            result.append(number)
        return finite(result)
    try:return frozenset([int(text.strip(),0)])
    except ValueError:return None


def assign(state,target,numbers):
    reg=register(target)
    if not reg:return
    index,width,shift=reg
    if numbers is None:state.pop(index,None);return
    numbers=finite(v&((1<<width)-1) for v in numbers)
    if width in (32,64):result=numbers
    elif index in state:
        mask=((1<<width)-1)<<shift
        result=finite((old&~mask)|(v<<shift) for old in state[index] for v in numbers)
    else:result=None
    if result is None:state.pop(index,None)
    else:state[index]=result


def transfer(mnemonic,args,incoming,next_ip=0,read=None):
    state=dict(incoming);operands=[v.strip().lower() for v in args.split(',')]
    if mnemonic in ('cmp','test','nop','endbr64') or mnemonic.startswith('j'):return state
    if mnemonic in ('mov','movabs') and len(operands)==2:
        assign(state,operands[0],value(operands[1],state,next_ip,read));return state
    if mnemonic=='lea' and len(operands)==2:
        assign(state,operands[0],address(operands[1],state,next_ip));return state
    if mnemonic in ('movsx','movsxd','movzx') and len(operands)==2:
        numbers=value(operands[1],state,next_ip,read);source=register(operands[1])
        match=re.match(r'(byte|word|dword|qword)\s+ptr\b',operands[1])
        width=source[1] if source else {'byte':8,'word':16,'dword':32,'qword':64}.get(match[1]) if match else None
        if numbers is not None and width is not None and mnemonic!='movzx':numbers=finite(v-(1<<width) if v&(1<<(width-1)) else v for v in numbers)
        assign(state,operands[0],numbers if width is not None else None);return state
    if mnemonic.startswith('cmov') and len(operands)==2:
        a=value(operands[0],state,next_ip,read);b=value(operands[1],state,next_ip,read)
        assign(state,operands[0],None if a is None or b is None else finite(a|b));return state
    if mnemonic.startswith('set') and len(operands)==1:
        assign(state,operands[0],frozenset([0,1]));return state
    if mnemonic=='xchg' and len(operands)==2:
        a=value(operands[0],state,next_ip,read);b=value(operands[1],state,next_ip,read)
        assign(state,operands[0],b);assign(state,operands[1],a);return state
    if mnemonic in ('xor','and','or','add','sub') and len(operands)==2:
        a,b=(value(v,state,next_ip,read) for v in operands)
        if mnemonic=='xor' and operands[0]==operands[1]:result=frozenset([0])
        elif mnemonic=='and' and a is None and b is not None and len(b)==1 and 0<=next(iter(b))<MAX_VALUES:
            mask=next(iter(b));result=finite(v for v in range(mask+1) if v&~mask==0)
        elif a is None or b is None:result=None
        else:
            operation={'xor':lambda x,y:x^y,'and':lambda x,y:x&y,'or':lambda x,y:x|y,'add':lambda x,y:x+y,'sub':lambda x,y:x-y}[mnemonic]
            result=finite(operation(x,y) for x in a for y in b)
        assign(state,operands[0],result);return state
    if mnemonic in ('inc','dec') and len(operands)==1:
        old=value(operands[0],state);assign(state,operands[0],None if old is None else finite(v+(1 if mnemonic=='inc' else -1) for v in old));return state
    if mnemonic in ('div','idiv','mul') or mnemonic=='imul' and len(operands)==1:
        state.pop(0,None);state.pop(2,None);return state
    if mnemonic=='imul' and len(operands) in (2,3):
        a=value(operands[-2],state,next_ip,read);b=value(operands[-1],state,next_ip,read)
        assign(state,operands[0],None if a is None or b is None else finite(x*y for x in a for y in b));return state
    if mnemonic=='push':state.pop(4,None);return state
    if mnemonic=='pop':state.pop(4,None);assign(state,operands[0],None);return state
    if mnemonic in ('leave','leaveq'):state.pop(4,None);state.pop(5,None);return state
    if mnemonic=='syscall':
        for index in (0,1,11):state.pop(index,None)
        return state
    # Unmodeled implicit effects erase facts rather than assuming preservation.
    return {}


def disassemble(path,runner,name):
    text,_=runner.command(name,['objdump','-d','-Mintel','--insn-width=16',path])
    logs=getattr(runner,'logs',None)
    files=[] if logs is None else list(Path(logs).glob('*-'+name+'.log'))
    if files:
        require(len(files)==1,'ambiguous disassembly log')
        require(files[0].stat().st_size<=64*1024*1024,'disassembly exceeds 64 MiB inventory bound')
        text=files[0].read_text(encoding='utf-8',errors='replace')
    return text


def contract(path,disassembly):
    blob=Path(path).read_bytes()
    require(len(blob)>=64 and blob[:7]==b'\x7fELF\x02\x01\x01','require ELF64 little endian')
    kind,machine=struct.unpack_from('<HH',blob,16);entry,phoff=struct.unpack_from('<QQ',blob,24)
    width,count=struct.unpack_from('<HH',blob,54)
    require(kind==2 and machine==62 and width==56 and 0<count<=128 and phoff+width*count<=len(blob),'require fixed x86-64 ET_EXEC')
    headers=[struct.unpack_from('<IIQQQQQQ',blob,phoff+n*width) for n in range(count)]
    require(not any(h[0] in (2,3) for h in headers),'dynamic loading requires a different adapter')
    loads=[h for h in headers if h[0]==1]
    require(all(h[2]+h[5]<=len(blob) and h[5]<=h[6] for h in loads),'invalid load segment')
    require(not any(h[1]&3==3 for h in loads),'writable executable code is outside the immutable-code inventory')
    require(not any(max(a[3],b[3])<min(a[3]+a[6],b[3]+b[6]) for i,a in enumerate(loads) for b in loads[i+1:]),'overlapping load mappings')
    instructions={}
    for line in disassembly.splitlines():
        match=re.match(r'^\s*([0-9a-fA-F]+):\s*((?:[0-9a-fA-F]{2}\s+)+)\s*(\S.*)$',line)
        if not match:continue
        ip=int(match[1],16);raw=bytes.fromhex(match[2]);text=match[3].split('#',1)[0].strip().lower()
        words=text.split(None,1)
        while len(words)==2 and (words[0] in ('lock','rep','repe','repz','repne','repnz','bnd','notrack','data16','addr32','cs','ds','es','fs','gs','ss') or words[0].startswith('rex')):words=words[1].split(None,1)
        mnemonic=words[0];args=words[1] if len(words)>1 else ''
        require(0<len(raw)<=15 and ip not in instructions,'invalid or duplicate instruction at '+hex(ip))
        owners=[h for h in loads if h[1]&1 and h[3]<=ip and ip+len(raw)<=h[3]+h[5]]
        require(len(owners)==1,'instruction not uniquely mapped at '+hex(ip))
        owner=owners[0];offset=owner[2]+ip-owner[3]
        require(blob[offset:offset+len(raw)]==raw,'disassembly bytes differ from ELF at '+hex(ip))
        instructions[ip]={'ip':ip,'bytes':raw.hex(),'mnemonic':mnemonic,'args':args,'next':ip+len(raw)}
        require(len(instructions)<=200000,'instruction inventory bound exceeded')
    require(entry in instructions,'entry is not a decoded instruction boundary')
    def read_constant(at,width):
        owners=[h for h in loads if h[1]&4 and not h[1]&2 and h[3]<=at and at+width<=h[3]+h[5]]
        if len(owners)!=1:return None
        h=owners[0];offset=h[2]+at-h[3]
        return int.from_bytes(blob[offset:offset+width],'little')
    states={};work=deque();returns={};callers={};steps=0;resolved={}
    def enqueue(ip,context,state):
        require(ip in instructions,'unresolved instruction boundary at '+hex(ip))
        key=(ip,context)
        if key not in states:
            require(len(states)<200000,'context inventory bound exceeded')
            states[key]=dict(state);work.append(key);return
        joined=merge(states[key],state)
        if joined!=states[key]:states[key]=joined;work.append(key)
    def targets(ins,state):
        match=re.fullmatch(r'(?:0x)?([0-9a-f]+)(?:\s+<[^>]+>)?',ins['args'])
        found=frozenset([int(match[1],16)]) if match else value(ins['args'],state,ins['next'],read_constant)
        require(found is not None,'unresolved indirect/far control-flow target at '+hex(ins['ip']))
        require(all(at in instructions for at in found),'unresolved instruction boundary at '+hex(ins['ip']))
        resolved.setdefault(ins['ip'],set()).update(found)
        return found
    enqueue(entry,entry,{})
    while work:
        ip,context=work.popleft();ins=instructions[ip];mnemonic=ins['mnemonic'];state=states[ip,context];steps+=1
        require(steps<=4000000,'register dataflow bound exceeded')
        if mnemonic in ('ret','retq'):
            output=dict(state);output.pop(4,None)
            joined=output if context not in returns else merge(returns[context],output)
            if context not in returns or joined!=returns[context]:
                returns[context]=joined
                for continuation,owner in callers.get(context,set()):enqueue(continuation,owner,joined)
            continue
        require(mnemonic not in ('iret','iretq','iretd','retf','lcall','ljmp','sysenter','sysret','sysretq','xbegin','xabort','xend') and not mnemonic.startswith('int'),'unmodeled control transfer at '+hex(ip))
        require(mnemonic not in ('(bad)','.byte'),'undecodable reachable bytes at '+hex(ip))
        if mnemonic in ('call','callq'):
            for at in targets(ins,state):
                callers.setdefault(at,set()).add((ins['next'],context))
                callee=dict(state);callee.pop(4,None);enqueue(at,at,callee)
                if at in returns:enqueue(ins['next'],context,returns[at])
            continue
        if mnemonic in ('jmp','jmpq'):
            for at in targets(ins,state):enqueue(at,context,state)
            continue
        if mnemonic.startswith('j') or mnemonic in ('loop','loope','loopne','loopnz','loopz'):
            output=transfer(mnemonic,ins['args'],state,ins['next'],read_constant)
            if mnemonic.startswith('loop'):output.pop(1,None)
            for at in targets(ins,state):enqueue(at,context,output)
            enqueue(ins['next'],context,output);continue
        if mnemonic=='syscall':
            require(ins['bytes']=='0f05','prefixed syscall encoding is unsupported')
            numbers=state.get(0)
            if numbers is not None and numbers<=frozenset([60,231]):continue
            if ins['next'] not in instructions:continue
        enqueue(ins['next'],context,transfer(mnemonic,ins['args'],state,ins['next'],read_constant))
    joined_states={}
    for (ip,context),state in states.items():joined_states[ip]=state if ip not in joined_states else merge(joined_states[ip],state)
    sites=[]
    for ip,state in sorted(joined_states.items()):
        ins=instructions[ip]
        if ins['mnemonic']!='syscall':continue
        numbers=state.get(0)
        require(numbers is not None and len(numbers)==1,'unknown or ambiguous syscall number at '+hex(ip))
        number=next(iter(numbers))
        require(number in (1,60,231),'unmodeled syscall number at '+hex(ip)+': '+str(number))
        kind='write' if number==1 else 'exit'
        if kind=='write':require(ins['next'] in instructions,'write has no decoded continuation')
        sites.append({'ip':ip,'kind':kind,'number':number,'arguments':'runtime register values','effects':'no user-memory writes; RAX/RCX/R11 unknown' if kind=='write' else 'terminates process'})
    require(any(s['kind']=='exit' for s in sites),'no classified process-exit syscall')
    return {'schema':'bcl-static-syscalls-2','binary_sha256':hashlib.sha256(blob).hexdigest(),'entry':entry,'sites':sites,
        'instructions':[instructions[ip] for ip in sorted(joined_states)],'dataflow_steps':steps,
        'resolved_control_flow':[{'ip':ip,'targets':sorted(found)} for ip,found in sorted(resolved.items())],
        'function_entries':sorted({context for ip,context in states}),
        'analysis_bounds':{'register_value_set':MAX_VALUES,'contexts':200000,'steps':4000000},
        'scope':'Interprocedural CFG with standard CALL/RET structure; bounded finite register sets and read-only pointer loads; recursion shares fixed-point summaries. Dynamic write arguments supported. Not whole-program equivalence or complete runtime proof.'}
