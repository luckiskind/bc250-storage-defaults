"""Task-local capability/lifecycle evidence, separate from I/O causality."""


def validate(raw):
    allowed={'schema_version','kind','start_ns','finish_ns','detached_ns','events','discarded','malformed','interrupted','limit_reached','creation_enabled','controlled_markers','pending_expected','threads_seen','task_storage_iteration_result','task_storage_iteration_errno','counters','records','links_detached','maps_pinned','causal_attribution_qualified','observer_cost_qualified'}
    if set(raw)!=allowed:raise ValueError('Unknown/private feature metadata')
    if raw.get('kind')!='bc250-task-context-feature' or type(raw.get('schema_version')) is not int or raw['schema_version']!=1:raise ValueError('Wrong task-context feature schema')
    for key in ('interrupted','limit_reached','creation_enabled','controlled_markers','links_detached','maps_pinned','causal_attribution_qualified','observer_cost_qualified'):
        if type(raw[key]) is not bool:raise ValueError('Rounded feature flag')
    if raw['maps_pinned'] or raw['causal_attribution_qualified'] or raw['observer_cost_qualified']:raise ValueError('Unqualified feature claim')
    if any(type(raw[k]) is not int or not 0<=raw[k]<2**64 for k in ('start_ns','finish_ns','detached_ns','events','discarded','malformed','pending_expected','threads_seen')):raise ValueError('Bad feature metadata')
    if not raw['start_ns']<=raw['finish_ns']<=raw['detached_ns']:raise ValueError('Feature capture clocks differ')
    if type(raw['task_storage_iteration_result']) is not int or not -4095<=raw['task_storage_iteration_result']<=0 or type(raw['task_storage_iteration_errno']) is not int or not 0<=raw['task_storage_iteration_errno']<=4095:raise ValueError('Invalid map iteration status')
    counters=raw['counters'];rows=raw['records']
    if len(counters)!=16 or any(type(n) is not int or not 0<=n<2**64 for n in counters):raise ValueError('Bad feature counters')
    if len(rows)!=raw['events'] or counters[0]!=len(rows)+raw['discarded']+raw['malformed']+counters[1]:raise ValueError('Feature delivery accounting differs')
    transport=bool(raw['links_detached'] and not(raw['interrupted'] or raw['limit_reached'] or raw['discarded'] or raw['malformed'] or counters[1]))
    fields={'id','token','time_ns','observed_ns','value','aux','result','stage','flags'};groups={}
    for e in rows:
        if set(e)!=fields or any(type(n) is not int for n in e.values()):raise ValueError('Private/rounded task-context record')
        if any(not 0<=n<2**64 for k,n in e.items() if k!='result') or not -2**63<=e['result']<2**63:raise ValueError('Feature wire range')
        if not e['id'] or not e['token'] or e['stage'] not in range(1,7) or e['flags'] not in (0,1):raise ValueError('Feature identity/stage/flag differs')
        if not raw['start_ns']<=e['time_ns']<=e['observed_ns']<=raw['detached_ns']:raise ValueError('Feature event outside capture')
        if e['stage']!=2 and e['result']:raise ValueError('Unknown feature return')
        if e['stage']!=3 and (e['value'] or e['aux']):raise ValueError('Unknown feature payload')
        if e['stage']==3 and (e['aux'] not in (0,1) or e['value']>=2**32):raise ValueError('Unsupported switch encoding')
        groups.setdefault(e['id'],[]).append(e)
    opens=closes=partial=0;tokens=set();observations=0
    for g in groups.values():
        g.sort(key=lambda e:(e['time_ns'],e['stage']));tokens.add(g[0]['token'])
        if any(e['token']!=g[0]['token'] for e in g):raise ValueError('Task token changed inside context')
        begin=[e for e in g if e['stage']==1];end=[e for e in g if e['stage']==2]
        if len(begin)>1 or len(end)>1:raise ValueError('Duplicated feature lifecycle')
        opens+=len(begin);closes+=len(end)
        if not begin or not end:partial+=1
        if begin and any(e['observed_ns']<begin[0]['time_ns'] for e in g):raise ValueError('Observation before context entry')
        if end and any(e['time_ns']>end[0]['observed_ns'] for e in g):raise ValueError('Observation after context exit')
        observations+=sum(e['stage']>=3 for e in g)
    match=bool(counters[2]==opens and counters[3]==closes and counters[4]==sum(e['stage']==1 and e['flags']==1 for e in rows)
        and counters[5]==sum(e['stage']==2 and e['result']==0 for e in rows) and counters[9]==raw['threads_seen']==len(tokens))
    contexts=bool(not partial and not raw['pending_expected'] and not counters[11] and opens==closes)
    errors=sum(counters[k] for k in (6,7,8,12,13,14,15))
    quality=bool(transport and contexts and raw['creation_enabled'] and match and not errors and all(e['flags']==1 for e in rows))
    return dict(transport_complete=transport,contexts_complete=contexts,stream_quality_passed=quality,
        context_entries=opens,context_returns=closes,partial_contexts=partial,threads_observed=len(tokens),
        scheduler_observations=observations,blocked_switch_outs=sum(e['stage']==3 and not e['aux'] and e['value']!=0 for e in rows),
        task_storage_creations=counters[4],task_storage_deletions=counters[5],max_simultaneous_contexts=counters[10],
        active_ledger=counters[11],pending_expected=raw['pending_expected'],counter_graph_counts_match=match,
        storage_oracle_mismatches=counters[6],feature_errors=errors,
        controlled_markers=raw['controlled_markers'],task_storage_iteration_supported=True if raw['task_storage_iteration_result']==0 or raw['task_storage_iteration_errno']==2 else False if raw['task_storage_iteration_errno'] in (95,524) else None,
        task_storage_iteration_errno=raw['task_storage_iteration_errno'],kernel_task_storage_lookup_capability_qualified=quality and observations>0,
        io_causality_qualified=False,observer_cost_qualified=False,whole_application_critical_path_qualified=False)
