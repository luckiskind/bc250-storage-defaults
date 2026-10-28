"""Independent wake-function evidence; no inferred hardware wait duration."""
import copy
from handoff_wait import validate as handoff_validate


def validate(raw):
    if raw.get('kind')!='bc250-wake-witness-diagnostic' or type(raw.get('witness_enabled')) is not bool:raise ValueError('Wrong wake witness protocol')
    stats=raw['witness_counters'];pending=raw['pending_contexts'];rows=raw['records']
    if len(stats)!=16 or len(pending)!=14 or any(type(n) is not int or not 0<=n<2**64 for n in stats+pending):raise ValueError('Bad witness counters')
    if raw['events']!=len(rows):raise ValueError('Witness delivery count differs')
    extra=[r for r in rows if r['stage']>30];base_rows=[r for r in rows if r['stage']<=30]
    p=copy.deepcopy(raw);p.pop('witness_counters');p.pop('witness_enabled')
    p.update(kind='bc250-handoff-wait-diagnostic',records=base_rows,events=len(base_rows),pending_contexts=pending[:13])
    p['counters'][0]-=len(extra)
    base=handoff_validate(p);complete=bool(base['transport_complete'] and not pending[13])
    fields={'id','parent','time_ns','value','aux','result','stage','flags'}
    base_ids={r['id'] for r in base_rows};groups={};callbacks={r['id']:r for r in base_rows if r['stage']==24}
    returns={r['id']:r for r in base_rows if r['stage']==25}
    for e in extra:
        if set(e)!=fields or any(type(v) is not int for v in e.values()):raise ValueError('Private/rounded witness field')
        if any(not 0<=v<2**64 for k,v in e.items() if k!='result') or not -2**63<=e['result']<2**63:raise ValueError('Witness wire range differs')
        if not e['id'] or e['id'] in base_ids or e['stage'] not in (31,32,33):raise ValueError('Witness identity/stage differs')
        if not raw['start_ns']<=e['time_ns']<=raw['detached_ns']:raise ValueError('Witness outside capture')
        groups.setdefault(e['id'],[]).append(e)
    attempts=[];partial=0
    for group in groups.values():
        g=sorted(group,key=lambda e:(e['time_ns'],e['stage']));stages=[e['stage'] for e in g]
        if stages not in ([31,32],[31,33,32]):
            if complete:raise ValueError('Duplicated/incomplete wake-function lifecycle')
            partial+=1;continue
        a,b=g[0],g[-1];snapshot=g[1] if len(g)==3 else None
        if any(e[k]!=a[k] for e in g for k in ('parent','value')):raise ValueError('Witness owner/callback changed')
        callback=callbacks.get(a['value']);ret=returns.get(a['value'])
        if not callback or not ret:
            if complete:raise ValueError('Witness has no complete actual folio callback')
            partial+=1;continue
        if callback['parent']!=a['parent'] or not callback['time_ns']<=a['time_ns']<=b['time_ns']<=ret['time_ns']:raise ValueError('Wake function outside claimed callback')
        if not 0<a['result']<2**32 or b['result'] not in (0,1) or a['flags']>=2**32 or b['flags']!=a['flags'] or b['aux']!=a['aux']:raise ValueError('Wake function arguments/return differ')
        for e in (a,snapshot):
            if e is not None and (e['aux']&~0xffff or e['aux']&255>1 or (e['aux']>>8)&255>2):raise ValueError('Unknown task state encoding')
        if snapshot and (snapshot['flags'] or not snapshot['time_ns']<=snapshot['result']<=b['time_ns']):raise ValueError('Unbounded waking snapshot')
        attempts.append(dict(entry=a,returned=b,snapshot=snapshot))
    waking=[e for e in base_rows if e['stage']==28];backed={};missing=0
    for event in waking:
        candidates=[a for a in attempts if a['entry']['value']==event['value'] and a['entry']['parent']==event['parent']
            and a['entry']['time_ns']<=event['time_ns']<=a['returned']['time_ns'] and a['returned']['result']==1 and a['snapshot'] is not None]
        if len(candidates)!=1:missing+=1
        else:backed[event['id']]=candidates[0]
    if len({a['entry']['id'] for a in backed.values()})!=len(backed):raise ValueError('Wake function reused across waking records')
    early_seen=0;early_verified=0
    for parent in {r['parent'] for r in base_rows if r['stage']==26}:
        timeline=sorted([r for r in base_rows if r['parent']==parent and 26<=r['stage']<=29],key=lambda e:(e['time_ns'],e['id']))
        out=None;boundary=raw['start_ns']
        for e in timeline:
            if e['stage']==26:out=e
            elif e['stage']==27:
                if out and not out['aux'] and out['value']:
                    candidates=[w for w in timeline if w['stage']==28 and boundary<=w['time_ns']<out['time_ns']]
                    if len(candidates)==1:
                        early_seen+=1;attempt=backed.get(candidates[0]['id'])
                        if attempt:
                            snapshot=attempt['snapshot']
                            if snapshot['aux']&255==1 and snapshot['result']<out['time_ns']:early_verified+=1
                out=None;boundary=e['time_ns']
    counter_match=all(stats[i]==sum(r['stage']==stage for r in extra) for i,stage in enumerate((31,32,33)))
    early_missing=max(0,base['early_wake_handoff_segments']-early_verified)
    quality=bool(base['stream_quality_passed'] and complete and raw['witness_enabled'] and counter_match
        and not any(stats[3:]) and not partial and not missing and not early_missing and early_seen==base['early_wake_handoff_segments'])
    result=dict(base)
    result.update(stream_quality_passed=quality,transport_complete=complete,remaining_contexts=sum(pending),
        wake_function_attempts=len(attempts),successful_wake_function_returns=sum(a['returned']['result']==1 for a in attempts),
        waking_task_state_snapshots=sum(a['snapshot'] is not None for a in attempts),
        waking_snapshots_on_cpu=sum(a['snapshot'] is not None and a['snapshot']['aux']&255==1 for a in attempts),
        waking_records_with_function_witness=len(backed),missing_wake_function_witnesses=missing,
        early_wake_overlap_witness_segments=early_verified,early_wake_overlap_witness_missing=early_missing,
        early_wake_overlap_independently_witnessed=bool(quality and early_verified>0),
        witness_counter_graph_counts_match=counter_match,partial_wake_function_objects=partial,witness_counters=stats,
        selected_worker_request_folio_wait_edges_qualified=quality and base['blocked_switch_segments']>0,
        resolved_request_folio_blocked_segments=base['resolved_request_folio_blocked_segments'] if quality else 0,
        storage_blocked_interval_accounting_complete=bool(quality and not base['early_wake_handoff_segments']),
        hardware_wait_duration_qualified=False,witness_observer_cost_qualified=False)
    return result
