"""Join independently validated request and folio graphs through actual vectors.

Early wake handoffs have unknown storage-blocked duration. This is not a
whole-application critical path. Frozen reference readers remain unchanged.
"""
import copy
from request_bio_accounting import validate as request_validate
from handoff_folio import validate as folio_validate


def validate(raw):
    if raw.get('kind')!='bc250-handoff-wait-diagnostic' or type(raw.get('schema_version')) is not int or raw['schema_version']!=2:raise ValueError('Wrong combined protocol')
    for name in ('vector_proof_enabled','folio_proof_enabled'):
        if type(raw.get(name)) is not bool:raise ValueError('Missing combined proof flag')
    if raw.get('scheduler_timestamp_basis')!='hook-entry-v1' or raw.get('unlock_hook_loaded') is not False:raise ValueError('Wrong handoff timing/omission')
    if any(r['stage']==12 for r in raw['records']):raise ValueError('Omitted unlock record present')
    pending=raw['pending_contexts'];vc=raw['vector_counters'];wc=raw['wait_counters'];records=raw['records'];counters=raw['counters']
    if len(pending)!=13 or len(vc)!=16 or len(wc)!=16 or any(type(n) is not int or not 0<=n<2**64 for n in pending+vc+wc):raise ValueError('Invalid combined counters')
    fields={'id','parent','time_ns','value','aux','result','stage','flags'}
    for r in records:
        if set(r)!=fields or any(type(v) is not int for v in r.values()):raise ValueError('Private/rounded combined field')
        if any(not 0<=v<2**64 for k,v in r.items() if k!='result') or not -2**63<=r['result']<2**63:raise ValueError('Combined wire range differs')
        if not r['id'] or not 1<=r['stage']<=30 or not raw['start_ns']<=r['time_ns']<=raw['detached_ns']:raise ValueError('Combined identity/stage/time differs')
    if raw['events']!=len(records) or counters[0]!=len(records)+counters[1]+raw['discarded']+raw['malformed']:raise ValueError('Combined delivery differs')
    def project(kind,rows,contexts,remove):
        p=copy.deepcopy(raw)
        for n in remove:p.pop(n)
        p.update(schema_version=1,kind=kind,records=copy.deepcopy(rows),events=len(rows),pending_contexts=contexts)
        p.pop('scheduler_timestamp_basis');p.pop('unlock_hook_loaded')
        p['counters'][0]=len(rows)+counters[1]+raw['discarded']+raw['malformed'];return p
    request_rows=[r for r in records if r['stage']<=23]
    request=request_validate(project('bc250-request-bio-diagnostic',request_rows,pending[:9],('vector_counters','wait_counters','vector_proof_enabled','folio_proof_enabled')))
    folio_rows=[r for r in records if r['stage']<=12 or 24<=r['stage']<=29]
    fp=project('bc250-folio-wait-diagnostic',folio_rows,pending[:5]+pending[9:11],('vector_counters','vector_proof_enabled','physical_counters','callback_proof_enabled','callback_identity_witnessed','request_counters','issue_proof_enabled'))
    fp.update(kind='bc250-handoff-folio-diagnostic',schema_version=2,scheduler_timestamp_basis='hook-entry-v1')
    for r in fp['records']:
        if r['stage']>=24:r['stage']-=11
    folio=folio_validate(fp)
    complete=bool(request['transport_complete'] and folio['transport_complete'] and not any(pending[11:]))
    request_ids={r['id'] for r in request_rows};wake_ids={r['id'] for r in records if 24<=r['stage']<=29}
    if request_ids & wake_ids:raise ValueError('Combined anonymous identity reused')
    originals={r['id']:r for r in records if r['stage']==3};ends={r['id']:r for r in records if r['stage']==8}
    wakes={r['id']:r for r in records if r['stage']==24};wake_returns={r['id']:r for r in records if r['stage']==25}
    origins={r['id']:r for r in records if r['stage'] in (13,14)};terminals={r['id']:r for r in records if r['stage']==16}
    members={r['value']:r for r in records if r['stage']==18 and r['value']};chunks={}
    for r in records:
        if r['stage']==21:chunks.setdefault(r['id'],[]).append(r)
    dependencies={};unbacked=0
    for identity,origin in origins.items():
        seen=set();node=origin
        while node['stage']==14:
            if node['id'] in seen:raise ValueError('Cyclic physical ancestry')
            seen.add(node['id']);node=origins.get(node['parent'])
            if node is None:break
        original=node['parent'] if node else None;member=members.get(identity);terminal=terminals.get(identity)
        if original not in originals or not member or not terminal:
            unbacked+=1;continue
        reports=chunks.get(member['id'],[]);end=ends.get(original)
        if not end or not reports or sum(r['value'] for r in reports)!=member['aux'] or max(r['time_ns'] for r in reports)>terminal['time_ns'] or terminal['time_ns']>end['time_ns']:
            if complete:raise ValueError('Original callback lacks preceding actual member reports')
            unbacked+=1;continue
        dependencies.setdefault(original,set()).add(member['parent'])
    edges={};partial=0
    for r in records:
        if r['stage']!=30:continue
        if not raw['vector_proof_enabled'] or r['id'] in edges:raise ValueError('Disabled/duplicated vector edge')
        wake=wakes.get(r['id']);ret=wake_returns.get(r['id']);original=originals.get(r['parent']);end=ends.get(r['parent'])
        if not wake or not ret or not original or not end:
            if complete:raise ValueError('Vector edge lacks actual wake/original')
            partial+=1;continue
        if wake['value']!=r['parent'] or not end['time_ns']<=r['time_ns']<=wake['time_ns']:raise ValueError('Vector edge outside claimed callback/wake')
        pages=r['result']>>32;folio_byte=r['result']&0xffffffff
        if not 0<pages<=1<<20 or pages&(pages-1) or not r['aux'] or r['flags']&~7:raise ValueError('Invalid vector geometry')
        if folio_byte+r['aux']>pages*4096 or r['value']+r['aux']>original['value']:raise ValueError('Vector outside submitted/folio bytes')
        if original['aux']+r['value']!=wake['aux']*4096+folio_byte:raise ValueError('Vector file coordinate differs')
        if bool(r['flags']&2)!=(pages>1) or bool(r['flags']&4)!=bool(folio_byte or r['aux']<pages*4096):raise ValueError('Vector shape flags differ')
        edges[r['id']]=r
    missing=len(set(wakes)-set(edges));backed={i for i,e in edges.items() if e['parent'] in dependencies}
    counter_match=vc[0]==len(wakes) and vc[1]==len(edges) and vc[9]==sum(bool(r['flags']&2) for r in edges.values()) and vc[10]==sum(bool(r['flags']&1) for r in edges.values()) and vc[11]==sum(bool(r['flags']&4) for r in edges.values())
    # Slot errors are independently retained by the frozen folio reader. Here
    # missing vector evidence can never be supplied by its older range proof.
    quality=bool(request['stream_quality_passed'] and folio['stream_quality_passed'] and complete and raw['vector_proof_enabled'] and counter_match
        and not any(vc[2:8]+vc[13:]) and not (missing or partial or unbacked) and len(backed)==len(edges))
    result=dict(request)
    result.update({k:v for k,v in folio.items() if k not in request or k.startswith(('matched_','successful_','failed_','blocked_','resolved_','unresolved_','unsupported_','partial_wait','wait_','off_cpu','proven_blocked','wake_delivery','runnable_','other_runnable'))})
    result.update({k:folio[k] for k in ('normal_post_switch_wake_segments','early_wake_handoff_segments','early_wake_off_cpu_union_ns','early_wake_delivery_overlap_union_ns','unused_scheduler_wake_records','ambiguous_scheduler_orders','scheduler_timestamp_basis','storage_blocked_interval_accounting_complete','early_wake_storage_blocked_ns')})
    result.update(folio_unlock_calls=None,unparented_unlock_calls=None,folio_unlock_hook_loaded=False,folio_unlock_count_available=False)
    result.update(stream_quality_passed=quality,transport_complete=complete,remaining_contexts=sum(pending),vector_counters=vc,
        actual_vector_edges=len(edges),missing_vector_edges=missing,partial_vector_objects=partial,request_backed_matched_wakes=len(backed),
        original_bios_with_reported_request_dependencies=len(dependencies),unbacked_physical_request_objects=unbacked,
        vector_counter_graph_counts_match=counter_match,large_folio_vector_edges=sum(bool(r['flags']&2) for r in edges.values()),
        multi_page_vector_edges=sum(bool(r['flags']&1) for r in edges.values()),partial_folio_vector_edges=sum(bool(r['flags']&4) for r in edges.values()),
        resolved_request_folio_blocked_segments=folio['resolved_folio_blocked_segments'] if quality else 0,
        selected_worker_request_folio_wait_edges_qualified=quality and folio['blocked_switch_segments']>0,
        full_folio_bio_request_wait_chain_qualified=False,whole_application_critical_path_qualified=False,
        minimal_hardware_service_time_qualified=False,diagnostic_overhead_qualified=False,overhead_qualified=False)
    result['storage_blocked_interval_accounting_complete']=bool(quality and not folio['early_wake_handoff_segments'])
    return result
