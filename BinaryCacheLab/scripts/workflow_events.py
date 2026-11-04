"""Versioned, streaming conversion of actual whole-2 PIN output to workflow JSONL."""
from pathlib import Path
import csv
import json
import hashlib

HEADER=['sequence','thread_id','instruction_address','memory_address','access_size_bytes','access_type','source_backend']
REQUIRED={'status':'complete','reason':'normal-exit','tracer_version':'whole-2','backend':'PIN','application_threads':'1','main_images':'1','application_exit':'0','address_space':'raw-virtual','observation_filter':'none','normalization':'none','scope':'pin-instrumented-user-space','event_semantics':'before-instruction-pin-predication','read_modify_write':'separate-read-then-write','kernel_memory_accesses':'excluded','instruction_fetches':'excluded'}

def require(value,detail):
    if not value:raise ValueError(detail)

def sha(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda:stream.read(1048576),b''):h.update(block)
    return h.hexdigest()

def lines(address,width,size):
    require(type(address) is int and type(width) is int and 0<=address<2**64 and 0<width<=65536 and address+width<=2**64,'Invalid memory access extent')
    require(type(size) is int and 1<=size<=4096 and size&(size-1)==0,'Line size must be a power of two <=4096')
    return list(range(address//size*size,(address+width-1)//size*size+1,size))

def properties(path):
    result={}
    for line in Path(path).read_text().splitlines():
        key,value=line.split('=',1)
        require(key not in result,'Duplicate tracer property: '+key);result[key]=value
    for key,value in REQUIRED.items():require(result.get(key)==value,'Unsupported/incomplete PIN trace: '+key+'='+str(result.get(key)))
    require(int(result.get('mapping_snapshots','0'))>0,'No mapping snapshots')
    return result

def csv_events(path):
    with Path(path).open(newline='') as stream:
        reader=csv.reader(stream);require(next(reader,None)==HEADER,'Invalid PIN CSV header')
        for index,row in enumerate(reader):
            require(len(row)==7,'Invalid PIN CSV row width')
            seq,thread,ip,address,width,operation,backend=row
            seq,thread,ip,address,width=int(seq),int(thread),int(ip,16),int(address,16),int(width)
            require(seq==index and thread>=0 and 0<=ip<2**64 and operation in ('READ','WRITE') and backend=='PIN','Invalid PIN event')
            lines(address,width,64)
            yield {'sequence':seq,'thread':thread,'instruction_address':ip,'effective_address':address,'width':width,'operation':operation}

def image_updates(path):
    with Path(path).open(newline='') as stream:
        reader=csv.DictReader(stream)
        required={'image_sequence','action','next_memory_sequence','image_id','is_main','low','high_inclusive','load_offset','name_hex'}
        require(set(reader.fieldnames or [])==required,'Invalid PIN images header')
        previous=-1
        for index,row in enumerate(reader):
            require(index<8192,'Image inventory exceeds supported bound')
            require(int(row['image_sequence'])==index,'Image sequence mismatch')
            seq=int(row['next_memory_sequence']);require(seq>=previous,'Image callbacks out of order');previous=seq
            require(row['is_main'] in ('0','1'),'Invalid main-image flag')
            require(row['action'] in ('LOAD','UNLOAD'),'Unknown image action')
            yield {'next':seq,'action':row['action'],'id':int(row['image_id']),'main':row['is_main']=='1','low':int(row['low'],16),'high':int(row['high_inclusive'],16),'bias':int(row['load_offset'],16),'name':bytes.fromhex(row['name_hex']).decode(errors='replace')}

def convert(directory,destination,variant,case,repeat,line_size,regions,operations,first_line=1,expected_binary=None,allow_empty=False):
    directory=Path(directory);destination=Path(destination)
    meta=properties(directory/'trace.properties')
    digest=sha(directory/'trace.csv');count=0;threads=set()
    # First pass validates the entire trace before calling its events complete.
    for event in csv_events(directory/'trace.csv'):count+=1;threads.add(event['thread'])
    require(count==int(meta['events']) and (len(threads)==1 if count else allow_empty and meta.get('empty_trace_allowed')=='true'),'Empty trace without explicit support, event-count mismatch or multiple threads')
    images=list(image_updates(directory/'images.csv'))
    require(len(images)==int(meta['image_events']) and sum(m['action']=='LOAD' and m['main'] for m in images)==1,'Image count/main-image mismatch')
    if expected_binary is not None:
        main_image=next(m for m in images if m['main'] and m['action']=='LOAD')
        require(Path(main_image['name']).resolve()==Path(expected_binary).resolve(),'PIN main image does not match the target executable')
    updates=iter(images);pending=next(updates,None)
    active={};main=None;line_number=first_line;written=0
    destination.parent.mkdir(parents=True,exist_ok=True)
    with destination.open('ab') as out:
        start=out.tell()
        for event in csv_events(directory/'trace.csv'):
            while pending is not None and pending['next']<=event['sequence']:
                if pending['action']=='LOAD':
                    active[pending['id']]=pending
                    if pending['main']:
                        require(main is None or main['id']==pending['id'],'Multiple main images');main=pending
                else:active.pop(pending['id'],None)
                pending=next(updates,None)
            require(main is not None,'No main image/load bias at event')
            if event['operation'] not in operations:continue
            touched=lines(event['effective_address'],event['width'],line_size)
            modules=[m for m in active.values() if m['low']<=event['instruction_address']<=m['high']]
            module=None
            if len(modules)==1:
                m=modules[0];module={'name':m['name'],'is_main':m['main'],'load_bias':m['bias'],'module_offset':event['instruction_address']-m['low'],'link_address':event['instruction_address']-m['bias'],'identity_basis':'unique-image-envelope; not a complete executable mapping proof'}
            matches=[]
            for region in regions:
                address=region['address']+main['bias']
                if address<=event['effective_address'] and event['effective_address']+event['width']<=address+region['size']:
                    matches.append({'name':region['name'],'offset':event['effective_address']-address,'runtime_start':address,'size':region['size']})
            logical=matches[0] if len(matches)==1 else None
            record={'schema_version':'bcl-memory-event-1','variant':variant,'event_id':f'{variant}/{case}/{repeat}/{event["sequence"]}',**event,
                    'instruction_module':module,'cache_line_size':line_size,'virtual_cache_lines':touched,'cross_line':len(touched)>1,'region':logical,
                    'input_case':case,'repetition':repeat,'trace_completeness':'complete','backend':'PIN','event_semantics':'before-instruction; RMW is separate READ then WRITE',
                    'trace_ref':{'path':'traces/'+destination.name,'line':line_number,'csv_path':str(directory.relative_to(destination.parent.parent)).replace('\\','/')+'/trace.csv','csv_row':event['sequence']+2}}
            out.write((json.dumps(record,separators=(',',':'))+'\n').encode());line_number+=1;written+=1
        end=out.tell()
    require(sha(directory/'trace.csv')==digest,'Raw trace changed during conversion')
    require(written>0 or allow_empty,'Configured operation filter selected no events')
    return {'variant':variant,'input_case':case,'repetition':repeat,'raw_events':count,'events':written,'start':start,'end':end,'first_line':first_line,'next_line':line_number,'trace_complete':True,'raw_csv_sha256':digest,'metadata':meta,'path':str(destination)}

def events(run,scope='all'):
    with Path(run['path']).open('rb') as stream:
        stream.seek(run['start'])
        while stream.tell()<run['end']:
            raw=stream.readline();require(raw and stream.tell()<=run['end'],'Truncated JSONL segment')
            event=json.loads(raw)
            require(event['schema_version']=='bcl-memory-event-1','Unknown event schema')
            if scope=='all' or event['region'] is not None:yield event

def line_tokens(run,identity,scope):
    for event in events(run,scope):
        for base in event['virtual_cache_lines']:
            if identity=='raw_virtual':key=base
            else:
                require(event['region'] is not None,'Region-relative line identity requires mapped events')
                region=event['region'];key=(region['name'],(base-region['runtime_start']//event['cache_line_size']*event['cache_line_size'])//event['cache_line_size'])
            yield key,event
