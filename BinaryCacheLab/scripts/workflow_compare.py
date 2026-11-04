"""Bounded-memory, policy-driven comparisons; ambiguous correspondence is never guessed."""
from collections import Counter,deque
import csv
import json
from itertools import zip_longest
from pathlib import Path
from workflow_events import events,line_tokens
from workflow_text import DifferenceTextWriter

POLICIES={'strict_address','region_relative','cache_line_sequence','layout_only','security_evaluation'}
CLASSIFICATIONS={'PRESERVED','ADDRESS_CHANGED','CACHE_LINE_CHANGED','NEW_ACCESS','MISSING_ACCESS','ACCESS_TYPE_CHANGED','ACCESS_WIDTH_CHANGED','CROSS_LINE_CHANGE','ORDER_CHANGED','REGION_MAPPING_CHANGED','UNMATCHED','INCONCLUSIVE'}
FIELDS=['pair','input_case','repetition','classification','rule_id','rule_violated','correspondence','baseline_variant','transformed_variant','baseline_ip','transformed_ip','baseline_module','transformed_module','baseline_address','transformed_address','baseline_lines','transformed_lines','baseline_width','transformed_width','baseline_operation','transformed_operation','baseline_region','transformed_region','baseline_trace_ref','transformed_trace_ref','explanation']

def region_key(event):
    r=event.get('region')
    return None if r is None else (r['name'],r['offset'])

def anchor(event,hashes):
    module=event.get('instruction_module')
    verified=hashes.get('_verified_maps',{}).get(event.get('variant'),{})
    if module and module.get('is_main') and module['link_address'] in verified:return ('verified-code-anchor',verified[module['link_address']])
    key=region_key(event)
    if key is not None:return ('region',*key)
    module=event.get('instruction_module')
    if module and module['is_main'] and len(set(value for key,value in hashes.items() if not key.startswith('_')))==1:
        return ('same-binary-site',module['link_address'],event['effective_address'])
    return None

def matched_events(left,right,lookahead,hashes):
    if '_certified_sequence' in hashes:
        from protection_correspondence import match
        yield from match(left,right,hashes['_certified_sequence'])
        return
    a,b=deque(),deque();ae=be=False
    def fill(queue,source):
        end=False
        while len(queue)<lookahead:
            event=next(source,None)
            if event is None:end=True;break
            queue.append(event)
        return end
    while True:
        ae=fill(a,left) or ae;be=fill(b,right) or be
        if not a and not b:return
        if not a:yield None,b.popleft(),'NEW_ACCESS','end-of-left-stream';continue
        if not b:yield a.popleft(),None,'MISSING_ACCESS','end-of-right-stream';continue
        ka=[anchor(e,hashes) for e in a];kb=[anchor(e,hashes) for e in b]
        ca,cb=Counter(ka),Counter(kb)
        if ka[0] is not None and ka[0]==kb[0] and ca[ka[0]]==cb[kb[0]]==1:
            yield a.popleft(),b.popleft(),None,'unique-logical-region-or-identical-binary-site';continue
        # A unique local swap is an observed ordering change, not a sequence-number match.
        if ka[0] is not None and kb[0] is not None and ka[0]!=kb[0] and ca[ka[0]]==cb[ka[0]]==1 and ca[kb[0]]==cb[kb[0]]==1:
            index=kb.index(ka[0]);right_event=b[index];del b[index]
            yield a.popleft(),right_event,'ORDER_CHANGED','unique-context-reordering';continue
        anchors=[(i+j,i,j) for i,k in enumerate(ka) if k is not None and ca[k]==cb[k]==1 for j,q in enumerate(kb) if q==k]
        if anchors:
            best=min(v[0] for v in anchors);choices=[v for v in anchors if v[0]==best]
            if len(choices)==1:
                _,i,j=choices[0]
                if i:
                    yield a.popleft(),None,'MISSING_ACCESS' if be and ka[0] not in kb else 'UNMATCHED','bounded-context-resynchronization';continue
                if j:
                    yield None,b.popleft(),'NEW_ACCESS' if ae and kb[0] not in ka else 'UNMATCHED','bounded-context-resynchronization';continue
        yield a.popleft(),b.popleft(),'INCONCLUSIVE','ambiguous-or-unmapped-correspondence'

def classify(a,b,forced):
    if forced:return [forced]
    differences=[]
    if a['effective_address']!=b['effective_address']:differences.append('ADDRESS_CHANGED')
    if a['virtual_cache_lines']!=b['virtual_cache_lines']:differences.append('CACHE_LINE_CHANGED')
    if a['operation']!=b['operation']:differences.append('ACCESS_TYPE_CHANGED')
    if a['width']!=b['width']:differences.append('ACCESS_WIDTH_CHANGED')
    if a['cross_line']!=b['cross_line']:differences.append('CROSS_LINE_CHANGE')
    if region_key(a)!=region_key(b):differences.append('REGION_MAPPING_CHANGED')
    return differences or ['PRESERVED']

def violation(policy,classification):
    if classification in ('UNMATCHED','INCONCLUSIVE'):return None
    if policy in ('layout_only','cache_line_sequence','security_evaluation'):return False
    if classification=='PRESERVED':return False
    if policy=='region_relative' and classification in ('ADDRESS_CHANGED','CACHE_LINE_CHANGED','CROSS_LINE_CHANGE'):return False
    return True

def token_compare(left,right,identity,scope):
    count=0
    for index,(a,b) in enumerate(zip_longest(line_tokens(left,identity,scope),line_tokens(right,identity,scope))):
        if a is None or b is None or a[0]!=b[0]:
            return {'equal':False,'first_token':index,'left':None if a is None else a[1],'right':None if b is None else b[1],'left_line':None if a is None else a[0],'right_line':None if b is None else b[0],'equal_prefix_tokens':count}
        count+=1
    return {'equal':True,'tokens':count}

def signature(run,policy,configuration):
    if policy in ('cache_line_sequence','security_evaluation'):
        for key,_ in line_tokens(run,configuration['line_identity'],configuration['scope']):yield key
    elif policy!='layout_only':
        for event in events(run,configuration['scope']):
            yield (event['effective_address'] if policy=='strict_address' else region_key(event),event['width'],event['operation'])

def same_signature(left,right,policy,configuration):
    missing=object()
    return all(a==b for a,b in zip_longest(signature(left,policy,configuration),signature(right,policy,configuration),fillvalue=missing))

class Writer:
    def __init__(self,root,policy,context=2,sample_limit=100):
        self.root=Path(root);self.root.mkdir(parents=True,exist_ok=True);self.policy=policy;self.context=context;self.limit=sample_limit
        self.csvfile=(self.root/'trace_diff.csv').open('w',newline='');self.csv=csv.DictWriter(self.csvfile,fieldnames=FIELDS);self.csv.writeheader()
        self.jsonl=(self.root/'trace_diff.jsonl').open('w');self.violations=(self.root/'violations.json').open('w');self.violations.write('[')
        self.text=DifferenceTextWriter(self.root/'trace_diff.txt',policy)
        self.counts=Counter();self.violations_count=0;self.samples=[];self.first=None;self.preserved=0
    def emit(self,pair,a,b,classification,violated,reason,correspondence,rule='TRACE-001'):
        self.counts[classification]+=1
        if a is not None and b is not None and a.get('region') and b.get('region'):
            reason+=' Region evidence: '+str(region_key(a))+' -> '+str(region_key(b))+'. Transformation causality beyond this correspondence is not proved.'
        row={'pair':pair['name'],'input_case':pair['case'],'repetition':pair['repeat'],'classification':classification,'rule_id':rule,'rule_violated':violated,'correspondence':correspondence,'explanation':reason}
        for side,event in [('baseline',a),('transformed',b)]:
            row[side+'_variant']=pair['left'] if side=='baseline' else pair['right']
            for suffix,key in [('ip','instruction_address'),('module','instruction_module'),('address','effective_address'),('lines','virtual_cache_lines'),('width','width'),('operation','operation'),('region','region'),('trace_ref','trace_ref')]:row[side+'_'+suffix]=None if event is None else event.get(key)
        encoded=json.dumps(row,separators=(',',':'))
        self.text.emit(row)
        self.jsonl.write(encoded+'\n');self.csv.writerow({k:json.dumps(v) if isinstance(v,(dict,list)) or v is None else v for k,v in row.items()})
        if classification=='PRESERVED':self.preserved+=1
        if violated:
            if self.violations_count:self.violations.write(',\n')
            self.violations.write(encoded);self.violations_count+=1
            if len(self.samples)<self.limit:self.samples.append(row)
        if self.first is None and classification!='PRESERVED':self.first={'finding':row,'context_before':[],'context_after':[]}
        return row
    def compare(self,pair,left,right,config,hashes):
        before=deque(maxlen=self.context);first_here=None;after_needed=0;unknown=0;violations_before=self.violations_count;preserved_before=self.preserved;preserved_events=0
        for a,b,forced,confidence in matched_events(iter(events(left,config['scope'])),iter(events(right,config['scope'])),config['lookahead'],hashes):
            classes=classify(a,b,forced)
            if a is not None and b is not None and all(violation(self.policy,c) is False for c in classes):preserved_events+=1
            for classification in classes:
                v=violation(self.policy,classification)
                if v is None:unknown+=1
                reason=('No unique correspondence is established; sequence numbers alone do not identify accesses.' if v is None else
                        'Changed observation violates the selected rule.' if v else 'Reported observation is permitted by the selected policy.' if classification!='PRESERVED' else 'Configured access properties are preserved.')
                row=self.emit(pair,a,b,classification,v,reason,confidence)
                if first_here is None and classification!='PRESERVED':
                    first_here={'finding':row,'context_before':list(before),'context_after':[]};after_needed=self.context
                    if self.first and self.first['finding']==row:self.first=first_here
                elif after_needed:
                    first_here['context_after'].append(row);after_needed-=1
                before.append(row)
        token_result=None
        if self.policy in ('cache_line_sequence','security_evaluation'):
            token_result={'equal':True,'equal_tokens':0,'different_tokens':0}
            history=deque(maxlen=self.context);tail=0
            for index,(a,b) in enumerate(zip_longest(line_tokens(left,config['line_identity'],config['scope']),line_tokens(right,config['line_identity'],config['scope']))):
                position={'token':index,'left_line':None if a is None else a[0],'right_line':None if b is None else b[0],
                          'left_ref':None if a is None else a[1]['trace_ref'],'right_ref':None if b is None else b[1]['trace_ref']}
                if a is None or b is None or a[0]!=b[0]:
                    if token_result['equal']:
                        token_result.update(equal=False,first_token=index,left=None if a is None else a[1],right=None if b is None else b[1],context_before=list(history),context_after=[])
                        tail=self.context
                    token_result['different_tokens']+=1
                    self.emit(pair,None if a is None else a[1],None if b is None else b[1],'CACHE_LINE_CHANGED',True,
                              'Ordered '+config['line_identity']+' line observations differ at token '+str(index)+'. This is observation-position evidence, not verified event identity.','observation-position-only','TRACE-LINE-001')
                else:token_result['equal_tokens']+=1
                if not token_result['equal'] and index>token_result['first_token'] and tail:
                    token_result['context_after'].append(position);tail-=1
                history.append(position)
            preserved_events=token_result['equal_tokens']
        status='FAIL' if self.violations_count>violations_before else 'INCONCLUSIVE' if unknown and self.policy in ('strict_address','region_relative') else 'PASS'
        return {'pair':pair,'status':status,'unmatched_or_ambiguous':unknown,'violations':self.violations_count-violations_before,'preserved_observations':preserved_events,'line_comparison':token_result,'first_difference':first_here}
    def close(self):
        self.violations.write(']\n');self.violations.close();self.csvfile.close();self.jsonl.close();self.text.close()
