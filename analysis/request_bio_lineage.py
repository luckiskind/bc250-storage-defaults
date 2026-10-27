"""Issue-time bio membership and generation-safe request completion graph."""
import copy
from physical_bio_lineage import validate as physical_validate


def validate(raw):
    if raw.get('kind')!='bc250-request-bio-diagnostic' or type(raw.get('schema_version')) is not int or raw['schema_version']!=1:raise ValueError('Wrong request-bio protocol')
    if type(raw.get('issue_proof_enabled')) is not bool:raise ValueError('Missing issue proof configuration')
    pc=raw['request_counters'];pending=raw['pending_contexts'];records=raw['records'];counters=raw['counters']
    if len(pc)!=24 or len(pending)!=9 or any(type(v) is not int or not 0<=v<2**64 for v in pc+pending):raise ValueError('Invalid request-bio counters')
    if raw['events']!=len(records) or counters[0]!=len(records)+counters[1]+raw['discarded']+raw['malformed']:raise ValueError('Combined request delivery differs')
    physical=[r for r in records if r['stage']<=16];extra=[r for r in records if r['stage']>16]
    projected=copy.deepcopy(raw)
    for name in ('request_counters','issue_proof_enabled'):projected.pop(name)
    projected.update(kind='bc250-physical-bio-diagnostic',records=physical,events=len(physical),pending_contexts=pending[:7])
    projected['counters'][0]=len(physical)+counters[1]+raw['discarded']+raw['malformed'];result=physical_validate(projected)
    complete=result['transport_complete'] and not any(pending[7:]);physical_ids={r['id'] for r in physical}
    pg={}
    for r in physical:
        if r['stage'] in (13,14,15,16):pg.setdefault(r['id'],[]).append(r)
    fields={'id','parent','time_ns','value','aux','result','stage','flags'}
    for r in extra:
        if set(r)!=fields or any(type(v) is not int for v in r.values()):raise ValueError('Private/rounded request field')
        if any(not 0<=v<2**64 for k,v in r.items() if k!='result') or not -2**63<=r['result']<2**63:raise ValueError('Request wire range differs')
        if not r['id'] or r['id'] in physical_ids or r['stage'] not in range(17,24) or r['flags'] not in (0,1):raise ValueError('Request identity/stage differs')
        if not raw['start_ns']<=r['time_ns']<=raw['detached_ns']:raise ValueError('Request record outside attachment')
    requests={};members={};bound=set();partial=0;errors=0;requeues=0;reissues=0;chunks=0;partial_chunks=0;completed=0;reuses=0
    for row in sorted(extra,key=lambda x:x['time_ns']):
        identity=row['id'];stage=row['stage'];parent=row['parent'];value=row['value'];aux=row['aux'];time=row['time_ns']
        if stage==17:
            if identity in requests or identity in members or parent or row['flags'] or not value or not 1<=row['result']<=aux<=64:raise ValueError('Invalid/reused selected request')
            if not raw['issue_proof_enabled']:raise ValueError('Request without enabled issue proof')
            requests[identity]=dict(total=value,remaining=value,expected=aux,selected=row['result'],members=[],next=0,issues=1,issued=True,done=False,start=time,end=None,reuse=None)
            continue
        if stage==23:
            r=requests.get(identity);previous=requests.get(parent)
            if not r or not previous:
                if complete:raise ValueError('Recycled request lacks both generations')
                partial+=1;continue
            if r is previous or r['reuse'] is not None or r['members'] or not previous['done'] or previous['end']>time or value or aux or row['result'] or row['flags']:
                raise ValueError('Recycled request does not follow a closed prior generation')
            r['reuse']=parent;reuses+=1;continue
        if stage==18:
            r=requests.get(parent)
            if not r:
                if complete:raise ValueError('Member lacks request origin')
                partial+=1;continue
            if identity in requests or identity in members or r['done'] or r['next'] or len(r['members'])>=r['expected'] or not aux or row['result'] or row['flags']!=int(bool(value)):
                raise ValueError('Invalid/reused request member snapshot')
            if value and (value not in pg or value in bound):raise ValueError('Missing/reused physical bio membership')
            if value:
                bound.add(value);terminal=[e for e in pg[value] if e['stage']==16]
                origin=next(e for e in pg[value] if e['stage'] in (13,14))
                device=bool(origin['flags']&256) or any(e['stage']==15 and e['time_ns']<=time for e in pg[value])
                if origin['time_ns']>time or not device or any(e['stage']==14 and e['parent']==value and e['time_ns']>time for e in physical):raise ValueError('Issue precedes physical device proof or final partition')
                if terminal and (len(terminal)!=1 or terminal[0]['value']!=aux or terminal[0]['time_ns']<time):raise ValueError('Physical issue size/lifetime differs')
                if not terminal and complete:raise ValueError('Selected member lacks full physical report')
            members[identity]=dict(request=parent,physical=value,initial=aux,remaining=aux,start=time,last=None,errors=0)
            r['members'].append(identity);continue
        if stage==21:
            m=members.get(identity);r=requests.get(parent)
            if not m or not r:
                if complete:raise ValueError('Completion chunk lacks membership')
                partial+=1;continue
            if m['request']!=parent or r['done'] or not r['issued'] or len(r['members'])!=r['expected'] or r['next']>=len(r['members']) or r['members'][r['next']]!=identity:
                raise ValueError('Completion is not the live issued prefix')
            if row['flags']!=int(bool(m['physical'])) or aux!=m['remaining'] or not 0<value<=aux or value>r['remaining']:raise ValueError('Completion byte prefix differs')
            partial_chunks+=int(value<aux);chunks+=1;errors+=int(row['result']!=0);m['errors']+=int(row['result']!=0)
            m['remaining']-=value;r['remaining']-=value;m['last']=time
            if not m['remaining']:r['next']+=1
            continue
        r=requests.get(identity)
        if not r:
            if complete:raise ValueError('Request lifecycle lacks origin')
            partial+=1;continue
        if parent or row['flags'] or r['done']:raise ValueError('Request lifecycle identity differs')
        if stage in (19,20):
            if value!=r['remaining'] or value<=0 or row['result']:raise ValueError('Requeue/reissue range differs')
            if stage==19:
                if not r['issued'] or aux!=r['issues']:raise ValueError('Repeated/nonissued requeue')
                r['issued']=False;requeues+=1
            else:
                if r['issued'] or aux!=r['issues']+1:raise ValueError('Unproven/duplicated reissue')
                r['issued']=True;r['issues']+=1;reissues+=1
        elif stage==22:
            if not r['issued'] or r['remaining'] or value!=r['total'] or aux!=r['issues'] or r['next']!=r['expected']:raise ValueError('Request final byte/lifecycle accounting differs')
            r['done']=True;r['end']=time;completed+=1;errors+=int(row['result']!=0)
    for r in requests.values():
        snapshots=[members[i] for i in r['members']]
        if len(snapshots)!=r['expected'] or sum(m['initial'] for m in snapshots)!=r['total'] or sum(bool(m['physical']) for m in snapshots)!=r['selected']:
            if complete:raise ValueError('Request snapshot does not match issued bytes/members')
            partial+=1
    for m in members.values():
        if m['physical']:
            terminal=[e for e in pg[m['physical']] if e['stage']==16]
            if terminal and (m['remaining'] or m['last'] is None or terminal[0]['time_ns']<m['last']):raise ValueError('Physical final report lacks preceding full member bytes')
    unfinished=sum(not r['done'] for r in requests.values())+sum(m['remaining']>0 for m in members.values());uncovered=len(set(pg)-bound)
    selected=sum(bool(m['physical']) for m in members.values())
    expected_counts=[len(requests),len(requests)+reissues,completed,selected,len(members),requeues,partial_chunks]
    matched=pc[:7]==expected_counts and pc[16]==reuses
    quality=bool(result['stream_quality_passed'] and complete and matched and not any(pc[7:16]+pc[17:]) and not (unfinished or uncovered or partial or errors))
    result.update(stream_quality_passed=quality,transport_complete=bool(complete),request_generations=len(requests),
        issued_request_members=len(members),selected_request_members=selected,unselected_request_members=len(members)-selected,
        multi_bio_requests=sum(r['expected']>1 for r in requests.values()),mixed_selected_unselected_requests=sum(r['selected']<r['expected'] for r in requests.values()),
        request_requeue_events=requeues,request_reissue_events=reissues,request_completion_chunks=chunks,request_partial_member_chunks=partial_chunks,
        request_address_reuses_with_changed_generation=reuses,
        completed_request_generations=completed,request_reported_total_bytes=sum(r['total'] for r in requests.values()),
        selected_request_member_bytes=sum(m['initial'] for m in members.values() if m['physical']),
        request_counter_graph_counts_match=matched,request_unfinished_objects=unfinished,request_uncovered_physical_bios=uncovered,
        request_partial_objects=partial,request_error_records=errors,remaining_contexts=sum(pending),
        selected_physical_bio_request_generations_qualified=quality and bool(requests),
        request_queue_wait_qualified=False,merge_history_qualified=False,broader_native_requeue_partial_reuse_qualified=False,
        whole_application_critical_path_qualified=False,overhead_qualified=False)
    return result
