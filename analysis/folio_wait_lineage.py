"""Selected-worker folio wake/scheduler proof, distinct from device wait time."""
import copy
from read_lineage import validate as base_validate,union_ns


def validate(raw):
    if raw.get('kind')!='bc250-folio-wait-diagnostic' or type(raw.get('schema_version')) is not int or raw['schema_version']!=1:
        raise ValueError('Wrong folio-wait schema')
    if type(raw.get('folio_proof_enabled')) is not bool:raise ValueError('Missing proof configuration')
    wc=raw['wait_counters'];pending=raw['pending_contexts']
    if len(wc)!=16 or len(pending)!=7 or any(type(n) is not int or n<0 for n in wc+pending):raise ValueError('Invalid wait counters')
    records=raw['records'];counters=raw['counters']
    if raw['events']!=len(records) or counters[0]!=len(records)+counters[1]+raw['discarded']+raw['malformed']:raise ValueError('Combined delivery accounting differs')
    base_records=[r for r in records if r['stage']<=12];extra=[r for r in records if r['stage']>12]
    projected=copy.deepcopy(raw)
    for name in ('wait_counters','folio_proof_enabled'):projected.pop(name)
    projected.update(kind='bc250-read-lineage-diagnostic',records=base_records,events=len(base_records),pending_contexts=pending[:5])
    projected['counters'][0]=len(base_records)+counters[1]+raw['discarded']+raw['malformed']
    result=base_validate(projected)
    complete=bool(result['transport_complete'] and not any(pending[5:]))
    bg={};groups={}
    for r in base_records:bg.setdefault(r['id'],[]).append(r)
    for g in bg.values():g.sort(key=lambda r:r['time_ns'])
    fields={'id','parent','time_ns','value','aux','result','stage','flags'}
    for row in extra:
        if set(row)!=fields or any(type(v) is not int for v in row.values()):raise ValueError('Private/rounded wait field')
        if any(not 0<=v<2**64 for k,v in row.items() if k!='result') or not -2**63<=row['result']<2**63:raise ValueError('Wait wire range differs')
        if not row['id'] or row['id'] in bg or row['stage'] not in range(13,19):raise ValueError('Wait identity/stage differs')
        if not raw['start_ns']<=row['time_ns']<=raw['detached_ns']:raise ValueError('Wait event outside capture')
        groups.setdefault(row['id'],[]).append(row)
    sleeps={i:g for i,g in bg.items() if [r['stage'] for r in g]==[10,11]}
    wakes={};sched={};unresolved=0;unsupported=0;partial=0;failed_wakes=0;late_returns=0
    for identity,g in groups.items():
        g.sort(key=lambda r:r['time_ns']);first=g[0];stages=[r['stage'] for r in g]
        if any(r['parent']!=first['parent'] for r in g):raise ValueError('Wait parent changed')
        parent=first['parent']
        if parent not in sleeps:
            if complete:raise ValueError('Wait event has no complete io_schedule parent')
            partial+=1;continue
        sleep=sleeps[parent]
        if not sleep[0]['time_ns']<=first['time_ns']<=sleep[-1]['time_ns']:raise ValueError('Wait event outside active slot')
        if stages==[13,14]:
            if any(r[k]!=first[k] for r in g for k in ('value','aux','flags')):raise ValueError('Wake identity/proof changed')
            if first['result']!=0:raise ValueError('Unsupported folio bit')
            mask=first['flags']>>16;flags=first['flags']&65535
            if mask&~15 or mask&7!=7:raise ValueError('Missing queued-folio/inode/task proof')
            if flags not in (0,1):unsupported+=1
            success=flags in (0,1) and g[-1]['result']==flags
            failed_wakes+=int(not success)
            bio=bg.get(first['value'],[]);by={r['stage']:r for r in bio}
            linked=bool(mask==15 and first['value'] and 3 in by and 8 in by and 9 in by)
            if linked:
                offset=first['aux']*4096;submit=by[3]
                if not submit['aux']<=offset<submit['aux']+submit['value']:raise ValueError('Folio outside claimed original-bio range')
                if not by[8]['time_ns']<=first['time_ns']<=g[-1]['time_ns']<=by[9]['time_ns']:raise ValueError('Wake outside claimed data-end callback')
            elif complete:unresolved+=1
            wakes[identity]=dict(rows=g,success=success,linked=linked)
            late_returns+=int(g[-1]['time_ns']>sleep[-1]['time_ns'])
        elif len(g)==1 and first['stage'] in (15,16,17,18):
            if first['flags'] or first['result']:raise ValueError('Unknown scheduler flags')
            if first['stage']==15 and (first['value']>=2**32 or first['aux'] not in (0,1)):raise ValueError('Unsupported switch state')
            if first['stage'] in (16,17,18) and first['aux']:raise ValueError('Unknown scheduler payload')
            if first['stage']==16 and first['value']:raise ValueError('Unknown switch-in payload')
            sched.setdefault(parent,[]).append(first)
        elif complete:raise ValueError('Duplicated/incomplete wake lifecycle')
        else:partial+=1
    blocked=[];runnable=[];delivery=[];off_cpu=[];runnable_switch=[];segments=0;resolved=0
    for identity,sleep in sleeps.items():
        timeline=sorted(sched.get(identity,[]),key=lambda r:r['time_ns']);out=None
        for event in timeline:
            if event['stage']==15:
                if out is not None:unresolved+=1
                out=event
            elif event['stage']==16:
                if out is None:unresolved+=1;continue
                start,finish=out['time_ns'],event['time_ns'];off_cpu.append((start,finish))
                if not out['aux'] and out['value']:
                    segments+=1
                    waking=[r for r in timeline if r['stage']==17 and start<=r['time_ns']<=finish]
                    woken=[r for r in timeline if r['stage']==18 and start<=r['time_ns']<=finish]
                    proof=wakes.get(waking[0]['value']) if len(waking)==1 else None
                    good=bool(proof and proof['success'] and proof['linked'] and len(woken)==1)
                    if good:
                        a,b=proof['rows'];w=waking[0];u=woken[0]
                        good=bool(a['parent']==identity and a['time_ns']<=w['time_ns']<=b['time_ns']
                            and start<=a['time_ns']<=w['time_ns']<=u['time_ns']<=finish and u['value'] in (0,a['id']))
                    if good:
                        resolved+=1;blocked.append((start,w['time_ns']));delivery.append((w['time_ns'],u['time_ns']));runnable.append((u['time_ns'],finish))
                    else:unresolved+=1
                else:runnable_switch.append((start,finish))
                out=None
        if out is not None:unresolved+=1
    transport=complete
    quality=bool(result['stream_quality_passed'] and transport and raw['folio_proof_enabled'] and not unresolved and not unsupported and not partial
                 and not any(wc[:5]+wc[7:]))
    result.update(stream_quality_passed=quality,transport_complete=transport,matched_folio_callbacks=len(wakes),
        successful_matched_callbacks=sum(w['success'] for w in wakes.values()),failed_matched_callbacks=failed_wakes,
        blocked_switch_segments=segments,resolved_folio_blocked_segments=resolved,unresolved_wait_edges=unresolved,
        unsupported_wait_flag_contexts=unsupported,partial_wait_objects=partial,wait_return_after_caller_resumed=late_returns,
        off_cpu_interval_union_ns=union_ns(off_cpu),proven_blocked_until_waking_union_ns=union_ns(blocked),
        wake_delivery_union_ns=union_ns(delivery),runnable_after_wakeup_union_ns=union_ns(runnable),
        other_runnable_switch_union_ns=union_ns(runnable_switch),wait_counters=wc,
        selected_worker_folio_wake_edges_qualified=quality and segments==resolved,
        device_request_edges_qualified=False,whole_application_critical_path_qualified=False,
        diagnostic_overhead_qualified=False)
    return result
