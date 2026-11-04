"""Certify repeated dynamic occurrences using exhaustive reference executions."""
import project

def require(value,message):
    if not value:raise ValueError(message)

def selected(execution,regions):
    result=[]
    for access in execution['references']:
        hits=[r for r in regions if access['address']<r['address']+r['size'] and r['address']<access['address']+access['width']]
        if not hits:continue
        require(len(hits)==1,'Certified native mapping rejects cross-region references')
        region=hits[0]
        require(region['address']<=access['address'] and access['address']+access['width']<=region['address']+region['size'],
                'Certified reference crosses a declared region boundary')
        result.append({'ip':access['ip'],'region':region['name'],'offset':access['address']-region['address'],
                       'width':access['width'],'operation':'WRITE' if access['write'] else 'READ'})
    return result

def bind(workflow,settings,protected,baseline):
    require(workflow.doc['comparison']['scope']=='declared_regions','Certified occurrence matching requires declared-region scope')
    require(workflow.doc['execution']['operations']==['READ','WRITE'],'Certified occurrence matching requires both reads and writes')
    bindings=settings['native_cases']
    require(isinstance(bindings,list) and len(bindings)==len(workflow.doc['execution']['cases']),'Bind every native case exactly once')
    cases={row['id'] for row in workflow.doc['execution']['cases']}
    require(all(isinstance(row,dict) and set(row)=={'id','entry','values'} for row in bindings),'Invalid native-to-model case binding')
    require({row['id'] for row in bindings}==cases and len({row['id'] for row in bindings})==len(bindings),'Missing or duplicate native case binding')
    analyses={'original':protected['original_analysis'],'transformed':protected['rebuilt_analysis'],'baseline':baseline['rebuilt_analysis']}
    for variant,analysis in analyses.items():
        require(analysis.get('exhaustive') is True and analysis['binary_sha256']==workflow.report['artifacts'][variant]['sha256'],
                'Certified occurrence mapping must bind exhaustive actual-binary analysis')
    sequences={variant:{} for variant in analyses}
    for binding in bindings:
        entry=binding['entry'];values=binding['values']
        require(type(entry) is int and 0<=entry<len(settings['entries']),'Native binding entry index outside contract')
        require(isinstance(values,list) and len(values)==len(settings['inputs']) and all(type(value) is int for value in values),'Native bindings require scalar integer assignments')
        for variant,analysis in analyses.items():
            root=analysis['contract']['entries'][entry]
            matches=[execution for execution in analysis['executions'] if execution['entry']==root and
                     [value['value'] for value in execution['inputs']]==values]
            require(len(matches)==1,'Native case assignment does not identify one exhaustive model execution')
            sequences[variant][binding['id']]=selected(matches[0],workflow.regions[variant])
    for case in cases:
        logical=lambda sequence:[{key:value for key,value in row.items() if key!='ip'} for row in sequence]
        require(logical(sequences['original'][case]) and
                all(logical(sequences[variant][case])==logical(sequences['original'][case]) for variant in ('baseline','transformed')),
                'Selected reference sequence changed; certified one-to-one occurrence correspondence unavailable')
    workflow.certified_reference_sequences=sequences
    project.save(workflow.root/'validation/protection/certified-occurrences.json',
        {'schema':'bcl-exhaustive-native-occurrences-1','status':'EXHAUSTIVE_REFERENCE_SEQUENCES_BOUND',
         'native_bindings':bindings,'binary_sha256':{v:a['binary_sha256'] for v,a in analyses.items()},'sequences':sequences,
         'scope':'Every actual selected event must match its exhaustive model occurrence in every native repetition'})

def event_signature(event):
    if event is None or not event.get('region') or not event.get('instruction_module',{}).get('is_main'):return None
    return {'ip':event['instruction_module']['link_address'],'region':event['region']['name'],
            'offset':event['region']['offset'],'width':event['width'],'operation':event['operation']}

def match(left,right,certificate):
    from itertools import zip_longest
    expected_left,expected_right=certificate['left'],certificate['right']
    require(len(expected_left)==len(expected_right),'Invalid certified occurrence count')
    for a,b,x,y in zip_longest(left,right,expected_left,expected_right):
        if x is None or y is None or event_signature(a)!=x or event_signature(b)!=y:
            yield a,b,'INCONCLUSIVE','native-events-do-not-match-exhaustive-reference-certificate'
        else:yield a,b,None,'exhaustive-contract-certified-dynamic-occurrence'
