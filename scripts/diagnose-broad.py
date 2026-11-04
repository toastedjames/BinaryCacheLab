"""Read retained broader-qualification failures; never rebuild or execute target binaries."""
from pathlib import Path
import json
import struct
import sys

root=Path(sys.argv[1]).expanduser()
for label,base in [('WSL',root/'native-evidence'),('Clean container',root/'clean-evidence/run')]:
    report=base/'summary.json'
    print('\n'+label+'\n'+'='*len(label))
    if not report.is_file():
        print('Missing report:',report);continue
    summary=json.loads(report.read_text())
    print('Overall:',summary['status'])
    native=summary.get('native',{})
    for case in native.get('cases',[]):
        if case.get('status')!='FAILED':continue
        name=case['compiler']+case['optimization'][1:]
        print('\nCASE',name)
        print('Reason:',case.get('failure','unknown'))
        evidence=base/'native'/name/'evidence'
        detail=evidence/'summary.json'
        if detail.is_file():
            data=json.loads(detail.read_text())
            print('Rewrite decision:',json.dumps(data,ensure_ascii=False))
        analysis=evidence/'original-analysis.json'
        if analysis.is_file():
            data=json.loads(analysis.read_text())
            print('Reference status:',data.get('status'),'rejection:',data.get('rejection'))
            seen=set()
            for execution in data.get('executions',[]):
                fail=execution.get('failure')
                if fail is None:continue
                key=json.dumps(fail,sort_keys=True)
                if key in seen:continue
                seen.add(key)
                print('Execution failure:',key)
                ip=fail.get('ip');binary=evidence/'original.elf'
                if isinstance(ip,int) and binary.is_file():
                    raw=binary.read_bytes()
                    ph=struct.unpack_from('<Q',raw,32)[0]
                    count=struct.unpack_from('<H',raw,56)[0]
                    for index in range(count):
                        at=ph+56*index
                        if struct.unpack_from('<I',raw,at)[0]!=1:continue
                        offset,address=struct.unpack_from('<QQ',raw,at+8)
                        size=struct.unpack_from('<Q',raw,at+32)[0]
                        if address<=ip<address+size:
                            pos=offset+ip-address
                            print('Bytes at failing IP',hex(ip)+':',raw[pos:min(pos+32,offset+size)].hex())
                if len(seen)>=3:break
