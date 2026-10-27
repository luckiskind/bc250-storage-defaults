"""Strict diagnostic graph; object lineage is not a completed wait attribution."""
def union_ns(intervals):
    result=0;end=0
    for start,finish in sorted(intervals):
        result+=max(0,finish-max(start,end));end=max(end,finish)
    return result


def validate(raw):
    header={'schema_version','kind','libbpf','start_ns','finish_ns','detached_ns','events','malformed','discarded','interrupted',
        'limit_reached','counters','pending_contexts','records','links_detached','maps_pinned','critical_path_attribution_qualified','overhead_qualified'}
    if set(raw)!=header:raise ValueError('Private/unknown header field')
    for name in ('start_ns','finish_ns','detached_ns','events','malformed','discarded'):
        if type(raw[name]) is not int or not 0<=raw[name]<2**64:raise ValueError('Rounded/out-of-range header integer')
    for name in ('interrupted','limit_reached','links_detached','maps_pinned','critical_path_attribution_qualified','overhead_qualified'):
        if type(raw[name]) is not bool:raise ValueError('Invalid boolean flag')
    if raw['critical_path_attribution_qualified'] or raw['overhead_qualified']:raise ValueError('Unsupported qualification claim')
    fields={'id','parent','time_ns','value','aux','result','stage','flags'}
    if raw['kind']!='bc250-read-lineage-diagnostic' or raw['schema_version']!=1:raise ValueError('Wrong diagnostic schema')
    counters=raw['counters'];pending=raw['pending_contexts'];records=raw['records']
    if len(counters)!=16 or len(pending)!=5 or any(type(n) is not int or n<0 for n in counters+pending):raise ValueError('Invalid counters')
    if raw['events']!=len(records) or counters[0]!=len(records)+counters[1]+raw['discarded']+raw['malformed']:raise ValueError('Delivery accounting differs')
    if not 0<raw['start_ns']<=raw['finish_ns']<=raw['detached_ns']:raise ValueError('Capture clocks differ')
    groups={}
    for row in records:
        if set(row)!=fields or any(type(v) is not int for v in row.values()):raise ValueError('Private/unknown field or rounded integer')
        if any(not 0<=v<2**64 for k,v in row.items() if k!='result') or not -2**63<=row['result']<2**63:raise ValueError('Out-of-range wire integer')
        if row['id']<=0 or row['parent']<0 or row['stage'] not in range(1,13) or row['flags']<0:raise ValueError('Bad identity/stage')
        if not raw['start_ns']<=row['time_ns']<=raw['detached_ns']:raise ValueError('Event outside attachment bounds')
        groups.setdefault(row['id'],[]).append(row)
    complete=bool(not raw['interrupted'] and not raw['limit_reached'] and not raw['malformed'] and not raw['discarded'] and not counters[1] and not any(pending)
                  and raw['links_detached'] and not raw['maps_pinned'])
    kinds={};demands=[];sleeps=[];bio_ids=[];decomp=[];unparented=0;errors=0;partial=0;unlocks=0;unknown_unlocks=0
    for identity,group in groups.items():
        group.sort(key=lambda r:r['time_ns']);first=group[0];stages=[r['stage'] for r in group]
        if any(r['parent']!=first['parent'] or r['value']!=first['value'] or r['aux']!=first['aux'] for r in group):raise ValueError('Object identity changed')
        if stages==[1,2]:
            if first['parent'] or first['result'] not in (1,2,3) or group[-1]['flags']!=first['result']:raise ValueError('Demand kind differs')
            kinds[identity]='demand';demands.append((first['time_ns'],group[-1]['time_ns']));errors+=int(group[-1]['result']<0)
        elif stages in ([3,8,9],[3,4,5,8,9]):
            if first['value']<=0:raise ValueError('Empty submitted data bio')
            kinds[identity]='bio';bio_ids.append(identity);unparented+=int(not first['parent']);errors+=sum(r['result']!=0 for r in group)
        elif stages==[6,7]:
            kinds[identity]='decomp';decomp.append((first['time_ns'],group[-1]['time_ns']));errors+=int(group[-1]['result']!=0)
        elif stages==[10,11]:
            kinds[identity]='sleep';sleeps.append((first['time_ns'],group[-1]['time_ns']))
        elif stages==[12]:kinds[identity]='unlock';unlocks+=1;unknown_unlocks+=int(not first['parent'])
        elif complete:raise ValueError('Unsupported/duplicated/reused lifecycle')
        else:partial+=1;kinds[identity]='partial'
    for identity,group in groups.items():
        first=group[0];parent=first['parent'];kind=kinds[identity]
        required='demand' if kind in ('bio','sleep') else 'bio' if kind in ('decomp','unlock') else None
        if kind in ('sleep','decomp') and not parent:
            if complete:raise ValueError('Missing required parent')
            partial+=1
        if parent and required and kinds.get(parent)!=required:
            if complete:raise ValueError('Missing/wrong parent object')
            partial+=1
        if kind=='sleep' and parent and kinds.get(parent)=='demand':
            pg=groups[parent]
            if not pg[0]['time_ns']<=first['time_ns']<=group[-1]['time_ns']<=pg[-1]['time_ns']:raise ValueError('Sleep outside its selected demand')
        if kind=='decomp' and parent and kinds.get(parent)=='bio':
            pg=groups[parent];by={r['stage']:r for r in pg}
            if 5 not in by or 8 not in by:
                if complete:raise ValueError('Decompression parent lacks compressed completion')
                partial+=1
            elif not by[5]['time_ns']<=first['time_ns']<=group[-1]['time_ns']<=by[8]['time_ns']:raise ValueError('Decompression outside compressed completion path')
        if kind=='unlock' and parent and kinds.get(parent)=='bio':
            by={r['stage']:r for r in groups[parent]}
            if 8 in by and 9 in by and not by[8]['time_ns']<=first['time_ns']<=by[9]['time_ns']:raise ValueError('Unlock outside data-end callback')
    bad=sum(counters[2:7])+sum(counters[8:])
    return dict(stream_quality_passed=bool(complete and not bad and not errors and not partial and not unparented),transport_complete=complete,
        demand_attempts=sum(k=='demand' for k in kinds.values()),buffered_read_returned_bytes=sum(g[-1]['result'] for g in groups.values() if [r['stage'] for r in g]==[1,2] and g[0]['result']==1),
        buffered_read_attempts=sum(g[0]['stage']==1 and g[0]['result']==1 for g in groups.values()),
        filemap_fault_attempts=sum(g[0]['stage']==1 and g[0]['result']==2 for g in groups.values()),
        fault_around_attempts=sum(g[0]['stage']==1 and g[0]['result']==3 for g in groups.values()),
        original_data_bios=len(bio_ids),compressed_original_bios=sum(any(r['stage']==4 for r in groups[i]) for i in bio_ids),
        decompression_spans=len(decomp),io_schedule_spans=len(sleeps),folio_unlock_calls=unlocks,unparented_unlock_calls=unknown_unlocks,
        unparented_bios=unparented,partial_objects=partial,error_records=errors,identity_rejections=counters[7],
        selected_demand_interval_union_ns=union_ns(demands),io_schedule_interval_union_ns=union_ns(sleeps),
        decompression_wall_interval_union_ns=union_ns(decomp),remaining_contexts=sum(pending),
        bio_to_request_mapping_qualified=False,exact_folio_wait_dependency_qualified=False,
        io_schedule_wall_time_is_storage_critical_path=False,decompression_cpu_time_qualified=False,overhead_qualified=False)
