"""Physical bio object proof and byte partitions; never request attribution."""
import copy
from read_lineage import validate as base_validate


def validate(raw):
    if raw.get('kind')!='bc250-physical-bio-diagnostic' or type(raw.get('schema_version')) is not int or raw['schema_version']!=1:
        raise ValueError('Wrong physical-bio protocol')
    for name in ('callback_proof_enabled','callback_identity_witnessed'):
        if type(raw.get(name)) is not bool:raise ValueError('Missing callback proof flag')
    pc=raw['physical_counters'];pending=raw['pending_contexts'];records=raw['records'];counters=raw['counters']
    if len(pc)!=16 or len(pending)!=7 or any(type(v) is not int or not 0<=v<2**64 for v in pc+pending):raise ValueError('Invalid physical counters')
    if raw['events']!=len(records) or counters[0]!=len(records)+counters[1]+raw['discarded']+raw['malformed']:raise ValueError('Physical delivery accounting differs')
    logical=[r for r in records if r['stage']<=12];extra=[r for r in records if r['stage']>12]
    projected=copy.deepcopy(raw)
    for name in ('physical_counters','callback_proof_enabled','callback_identity_witnessed'):projected.pop(name)
    projected.update(kind='bc250-read-lineage-diagnostic',records=logical,events=len(logical),pending_contexts=pending[:5])
    projected['counters'][0]=len(logical)+counters[1]+raw['discarded']+raw['malformed'];result=base_validate(projected)
    complete=result['transport_complete'] and not any(pending[5:])
    logical_groups={}
    for r in logical:logical_groups.setdefault(r['id'],[]).append(r)
    original={i:{r['stage']:r for r in g} for i,g in logical_groups.items() if any(r['stage']==3 for r in g)}
    fields={'id','parent','time_ns','value','aux','result','stage','flags'}
    for r in extra:
        if set(r)!=fields or any(type(v) is not int for v in r.values()):raise ValueError('Private/rounded physical field')
        if any(not 0<=v<2**64 for k,v in r.items() if k!='result') or not -2**63<=r['result']<2**63:raise ValueError('Physical wire range differs')
        if not r['id'] or r['id'] in logical_groups or r['stage'] not in (13,14,15,16) or r['flags'] not in (0,1,256,257):raise ValueError('Physical identity/stage/flags differ')
        if not raw['start_ns']<=r['time_ns']<=raw['detached_ns']:raise ValueError('Physical event outside capture')
    states={};roots={};covered=set();partial=0;splits=0;visits=0;completions=0;errors=0;unknown=0
    for r in sorted(extra,key=lambda r:r['time_ns']):
        identity=r['id'];stage=r['stage'];kind=r['flags']&1;device=bool(r['flags']&256)
        if stage in (13,14):
            if identity in states or r['value']<=0:raise ValueError('Empty/reused physical object')
            if stage==13:
                if device or r['aux'] or r['result']:raise ValueError('Invalid physical root')
                parent=original.get(r['parent'])
                if not parent:
                    if complete:raise ValueError('Unknown original bio')
                    partial+=1;continue
                if bool(4 in parent)!=bool(kind):raise ValueError('Compressed type differs')
                if kind and not raw['callback_proof_enabled']:raise ValueError('Compressed cast lacks enabled callback proof')
                if r['parent'] in covered:raise ValueError('Duplicate physical root for original')
                if 3 in parent and r['time_ns']<parent[3]['time_ns']:raise ValueError('Physical root before original')
                if kind and r['time_ns']<parent[4]['time_ns']:raise ValueError('Physical root before compressed dispatch')
                if not kind and r['value']!=parent[3]['value']:raise ValueError('Plain physical bytes differ')
                covered.add(r['parent']);root=identity;roots[root]=dict(bytes=r['value'],original=r['parent'],leaves=[])
            else:
                parent=states.get(r['parent'])
                if not parent:
                    if complete:raise ValueError('Split has no live parent')
                    partial+=1;continue
                if parent['done'] or parent['kind']!=kind or device!=parent['device'] or r['aux']!=parent['offset'] or r['result']!=parent['remaining'] or r['value']>=parent['remaining']:
                    raise ValueError('Split does not partition its live parent')
                root=parent['root'];parent['remaining']-=r['value'];parent['offset']+=r['value'];splits+=1
            states[identity]=dict(parent=r['parent'],root=root,remaining=r['value'],offset=r['aux'],kind=kind,device=device,done=False,boundary=None,start=r['time_ns'])
        else:
            s=states.get(identity)
            if not s:
                if complete:raise ValueError('Physical event lacks live origin')
                partial+=1;continue
            if s['done'] or r['parent']!=s['parent'] or kind!=s['kind'] or r['value']!=s['remaining'] or r['aux']!=s['offset']:
                raise ValueError('Physical slice identity/range changed')
            if stage==15:
                if not device or r['result'] or s['boundary']==(r['value'],r['aux']):raise ValueError('Invalid/repeated submission boundary')
                s['device']=True;s['boundary']=(r['value'],r['aux']);visits+=1
            else:
                unknown+=int(not device or not s['device']);errors+=int(r['result']!=0);s['done']=True;completions+=1
                roots[s['root']]['leaves'].append((s['offset'],s['offset']+s['remaining']))
                parent=original[roots[s['root']]['original']];end=parent.get(5 if kind else 8)
                if end and r['time_ns']>end['time_ns']:raise ValueError('Physical completion after logical callback')
    for root in roots.values():
        end=0
        for start,finish in sorted(root['leaves']):
            if start!=end or finish<=start:
                if complete:raise ValueError('Physical completion byte partition overlaps or has a gap')
                partial+=1
            end=finish
        if end!=root['bytes']:partial+=1
    unfinished=sum(not s['done'] for s in states.values());uncovered=len(set(original)-covered)
    quality=bool(result['stream_quality_passed'] and complete and raw['callback_identity_witnessed'] and pc[0]>0 and not any(pc[1:12]+pc[14:]) and not (partial or unfinished or uncovered or unknown or errors))
    result.update(stream_quality_passed=quality,transport_complete=bool(complete),physical_root_bios=len(roots),
        compressed_physical_roots=sum(s['kind'] for i,s in states.items() if i in roots),split_child_bios=splits,
        physical_submission_boundary_visits=visits,physical_bio_completions=completions,
        physical_completed_bytes=sum(b-a for root in roots.values() for a,b in root['leaves']),
        physical_root_input_bytes=sum(root['bytes'] for root in roots.values()),
        uncovered_original_bios=uncovered,unfinished_physical_objects=unfinished,physical_partial_objects=partial,
        physical_unknown_device_edges=unknown,physical_error_records=errors,remaining_contexts=sum(pending),
        selected_original_to_physical_bio_edges_qualified=quality and bool(roots),
        physical_bio_request_edges_qualified=False,split_and_merge_native_coverage_qualified=False,
        whole_application_critical_path_qualified=False,overhead_qualified=False)
    return result
