"""Rebind byte-verified ET_EXEC callback arrays to explicit lifted code symbols."""
import hashlib
from pathlib import Path
import re
import struct


def require(ok, detail):
    if not ok:
        raise RuntimeError('Cannot rebind callback array: '+detail)


def operands(text):
    """FoxDec byte literals: numbers and unescaped printable NASM strings only."""
    token=re.compile(r"\s*(`[^`\\]*`|'[^'\\]*'|\"[^\"\\]*\"|[A-Za-z_.$][\w.$]*|0[xX][0-9a-fA-F]+|[0-9][0-9a-fA-F]*[hH]|[0-9]+)\s*(,|$)")
    result=[]
    while text:
        match=token.match(text)
        require(match is not None,'unsupported data literal')
        result.append(match.group(1));text=text[match.end():]
        require(match.group(2)!=',' or text.strip(),'trailing operand comma')
    require(result,'empty data directive')
    return result


def literal(value, width, roots):
    if value[0] in "`'\"":
        require(width==1 and all(32<=ord(c)<=126 for c in value[1:-1]),'unsupported string literal')
        return value[1:-1].encode('ascii')
    if value in roots:
        require(width==8,'callback symbol requires a qword')
        number=roots[value]
    elif re.fullmatch(r'0[xX][0-9a-fA-F]+',value):number=int(value,16)
    elif re.fullmatch(r'[0-9][0-9a-fA-F]*[hH]',value):number=int(value[:-1],16)
    else:
        require(value.isdecimal(),'unknown symbol in callback array')
        number=int(value)
    require(0<=number<1<<(8*width),'data literal exceeds directive width')
    return number.to_bytes(width,'little')


def restore(assembly, original, plan):
    blob=Path(original).read_bytes()
    require(len(blob)>=64 and blob[:6]==b'\x7fELF\x02\x01','invalid ELF64 source')
    # ET_DYN array relocations are already emitted symbolically by FoxDec.
    if struct.unpack_from('<H',blob,16)[0]!=2:return []
    slots=plan.get('array_slots',[])
    if not slots:return []
    require(plan.get('original_binary_sha256')==hashlib.sha256(blob).hexdigest(),'source hash differs from callback plan')
    roots={row['symbol']:row['original_entry'] for row in plan['required_roots']}
    require(all(re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.$]*',name) for name in roots),'invalid callback symbol')
    off,=struct.unpack_from('<Q',blob,40);width,count,strings=struct.unpack_from('<HHH',blob,58)
    require(width==64 and 0<strings<count and off+width*count<=len(blob),'invalid section table')
    sections=[struct.unpack_from('<IIQQQQIIQQ',blob,off+n*width) for n in range(count)]
    names_section=sections[strings]
    require(names_section[4]+names_section[5]<=len(blob),'invalid section names')
    names=blob[names_section[4]:names_section[4]+names_section[5]]
    text=Path(assembly).read_text(encoding='utf-8');lines=text.splitlines(keepends=True)
    changes=[];edits=[];consumed=set()
    kinds={'.init_array':(14,'DT_INIT_ARRAY'),'.fini_array':(15,'DT_FINI_ARRAY'),'.preinit_array':(16,'DT_PREINIT_ARRAY')}
    for start,line in enumerate(lines):
        header=re.fullmatch(r'\s*section\s+(\.init_array|\.fini_array|\.preinit_array)\s+align=\d+\s*;\s*@([0-9a-fA-F]+)\s*',line,re.I)
        if not header:continue
        name=header.group(1).lower();base=int(header.group(2),16)
        owners=[s for s in sections if s[0]<len(names) and names[s[0]:].split(b'\0',1)[0].decode('ascii')==name and s[3]==base and s[1]==kinds[name][0] and s[2]&2]
        require(len(owners)==1,'missing/ambiguous original '+name+' section')
        owner=owners[0];size=owner[5]
        require(size>0 and size<=1048576 and size%8==0 and owner[4]+size<=len(blob),'unsupported callback section size')
        selected=sorted([row for row in slots if row['source']==kinds[name][1]],key=lambda r:r['index'])
        require(len(selected)==size//8 and [r['index'] for r in selected]==list(range(size//8)),'callback inventory does not cover section exactly')
        for i,row in enumerate(selected):
            require(row['slot']==base+8*i and roots.get(row['symbol'])==row['original_target'],'slot/symbol mapping disagrees with original')
            require(struct.unpack_from('<Q',blob,owner[4]+8*i)[0]==row['original_target'],'original slot bytes differ from mapped target')
            require(row['slot'] not in consumed,'duplicate callback section')
            consumed.add(row['slot'])
            require(len(re.findall(r'^\s*'+re.escape(row['symbol'])+r':\s*(?:;[^\r\n]*)?$',text,re.M))==1,'missing/duplicate lifted callback definition')
        data=bytearray();labels={};end=start+1
        while end<len(lines) and not re.match(r'\s*section\b',lines[end],re.I):
            body=lines[end].split(';',1)[0].strip()
            if body:
                label=re.fullmatch(r'([A-Za-z_.$][\w.$]*):',body)
                if label:
                    require(len(data)%8==0,'label inside callback pointer')
                    labels.setdefault(len(data),[]).append(label.group(1))
                else:
                    directive=re.fullmatch(r'(db|dw|dd|dq)\s+(.+)',body,re.I)
                    require(directive is not None,'unsupported callback section directive')
                    for value in operands(directive.group(2)):
                        data.extend(literal(value,{'db':1,'dw':2,'dd':4,'dq':8}[directive.group(1).lower()],roots))
                        require(len(data)<=size,'emitted callback bytes exceed original section')
            end+=1
        require(data==blob[owner[4]:owner[4]+size],'emitted callback bytes do not match original ELF')
        body=[]
        for i,row in enumerate(selected):
            body.extend(label+':\n' for label in labels.get(8*i,[]))
            body.append('dq '+row['symbol']+' ; rebound original callback slot '+hex(row['slot'])+'\n')
            changes.append({'source':row['source'],'index':i,'original_slot':row['slot'],'original_target':row['original_target'],'symbol':row['symbol']})
        body.extend(label+':\n' for label in labels.get(size,[]));body.append('\n')
        edits.append((start+1,end,body))
    require(consumed=={r['slot'] for r in slots},'missing emitted callback section')
    for start,end,body in reversed(edits):lines[start:end]=body
    Path(assembly).write_text(''.join(lines),encoding='utf-8')
    return changes
