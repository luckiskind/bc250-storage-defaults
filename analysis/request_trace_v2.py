"""Separate v2 wire/provenance checks; old v1 results are never reinterpreted."""
COUNTERS=('insert','issue','final','orphan_complete','zero_generation','map_update_fail','repeat_insert','duplicate_issue',
    'requeue','partial','overshoot','ring_lost','delete_race','no_issue','bad_time','orphan_requeue',
    'software_entry','software_return_true','software_return_false','software_complete','software_final','internal_final','software_anomaly','context_fail')
FIELDS={'id','insert_ns','issue_ns','complete_ns','enter_ns','return_ns','bytes','completed_bytes','operation','flags','event_class','evidence','entry_cmd_flags','status'}
TOP={'schema_version','kind','libbpf','software_tracking_enabled','internal_tracking_enabled','preflush_mask','start_ns','finish_ns','detached_ns','events','malformed','discarded','interrupted','limit_reached','right_censored_requests','return_contexts','counters','records','links_detached','maps_pinned','foreground_attribution_qualified','performance_result'}


def require(value,message):
    if not value:raise ValueError(message)


def uint(value,bits=64):return type(value) is int and 0<=value<2**bits


def validate(report):
    require(isinstance(report,dict) and set(report)==TOP,'Unexpected v2 fields')
    require(report['schema_version']==2 and report['kind']=='bc250-request-trace-v2','Wrong v2 schema')
    require(isinstance(report['libbpf'],str) and len(report['libbpf'])<=64,'Invalid library version')
    for name in ('software_tracking_enabled','internal_tracking_enabled','interrupted','limit_reached','links_detached','maps_pinned','foreground_attribution_qualified','performance_result'):
        require(type(report[name]) is bool,'Invalid Boolean field')
    require(report['links_detached'] and not any(report[k] for k in ('maps_pinned','foreground_attribution_qualified','performance_result')),'Unexpected persistent/attributed/performance report')
    require(all(uint(report[n]) for n in ('start_ns','finish_ns','detached_ns','events','malformed','discarded','right_censored_requests','return_contexts')),'Invalid clocks/counters')
    require(report['start_ns']<report['finish_ns']<=report['detached_ns'] and report['preflush_mask']==262144,'Capture lifetime/ABI differs')
    rows=report['records'];values=report['counters']
    require(isinstance(rows,list) and len(rows)==report['events']<=200000,'Record count mismatch/bound')
    require(isinstance(values,list) and len(values)==24 and all(uint(v) for v in values),'Counter schema differs')
    stats=dict(zip(COUNTERS,values));lost=stats['ring_lost']+report['discarded']
    require(stats['final']==len(rows)+lost,'Final delivery accounting mismatch')
    require(report['right_censored_requests']<=8192 and report['return_contexts']<=8192,'Private map bounds exceeded')
    seen=set();classes=[0]*4;ordinary=internal=software=unresolved=raw_flags=read=written=0;service_sum=queue_sum=0
    for row in rows:
        require(isinstance(row,dict) and set(row)==FIELDS,'Unexpected v2 event fields')
        require(all(uint(row[n],64 if n in ('id','insert_ns','issue_ns','complete_ns','enter_ns','return_ns') else 32) for n in FIELDS),'Invalid v2 event integer')
        require(row['id']>0 and row['id'] not in seen,'Repeated/zero request identity');seen.add(row['id'])
        require(row['event_class']<4 and row['operation']<256 and row['flags']&~1023==0,'Unknown class/operation/flags')
        require(report['start_ns']<=row['complete_ns']<=report['detached_ns'],'Completion outside capture')
        require(bool(row['status'])==bool(row['flags']&4),'Error status/flag mismatch')
        cls=row['event_class'];classes[cls]+=1;raw_flags+=bool(row['flags'])
        if row['operation']==0:read+=row['completed_bytes']
        if row['operation']==1:written+=row['completed_bytes']
        if cls in (0,1):
            require(report['start_ns']<=row['issue_ns']<=row['complete_ns'],'Issue outside request lifetime')
            require(not any(row[k] for k in ('enter_ns','return_ns','entry_cmd_flags')),'Device request contains software markers')
            if cls==0:
                require(row['evidence']==0,'Ordinary request has auxiliary proof')
                good=not row['flags'] and not row['status'] and row['bytes']==row['completed_bytes']>0 and report['start_ns']<=row['insert_ns']<=row['issue_ns']
                if good:ordinary+=1;service_sum+=row['complete_ns']-row['issue_ns'];queue_sum+=row['issue_ns']-row['insert_ns']
                else:unresolved+=1
            else:
                require(report['internal_tracking_enabled'] and row['evidence']==9 and row['operation']==2 and row['bytes']==row['completed_bytes']==0,'Device flush lacks positive identity/completion proof')
                expected=128|(16 if not row['insert_ns'] else 0)
                good=row['flags']==expected and not row['status'] and (not row['insert_ns'] or report['start_ns']<=row['insert_ns']<=row['issue_ns'])
                if good:internal+=1
                else:unresolved+=1
        else:
            require(report['software_tracking_enabled'] and row['operation']==1 and row['bytes']==row['completed_bytes']==0 and not row['insert_ns'] and not row['issue_ns'],'Software request has ordinary device I/O')
            require(report['start_ns']<=row['enter_ns']<=row['return_ns']<=report['detached_ns'] and row['enter_ns']<=row['complete_ns'],'Software entry/return/completion ordering invalid')
            require(row['entry_cmd_flags']&255==1 and row['entry_cmd_flags']&report['preflush_mask'],'Software entry lacks original preflush')
            require(row['evidence']==(14 if cls==2 else 26),'Software sequence lacks entry/return/completion proof')
            if cls==2 and row['flags']==144 and not row['status']:software+=1
            else:unresolved+=1
    require(classes[1]<=stats['internal_final'] and classes[2]+classes[3]<=stats['software_final'],'Class counters undercount records')
    if not lost:require(classes[1]==stats['internal_final'] and classes[2]+classes[3]==stats['software_final'],'Class counter mismatch')
    require(stats['software_return_true']+stats['software_return_false']<=stats['software_entry'] and stats['software_complete']<=stats['software_entry'],'Software lifecycle counters exceed entries')
    require(classes[2]<=stats['software_return_true'] and classes[3]<=stats['software_return_false'],'Software class lacks return accounting')
    transport=not lost and not any(report[k] for k in ('malformed','interrupted','limit_reached')) and not any(stats[k] for k in ('map_update_fail','zero_generation','context_fail'))
    closed=not report['right_censored_requests'] and not report['return_contexts'] and stats['software_entry']==stats['software_return_true']+stats['software_return_false']==stats['software_complete']==stats['software_final']
    bad=('orphan_complete','repeat_insert','duplicate_issue','requeue','partial','overshoot','delete_race','no_issue','bad_time','orphan_requeue','software_return_false','software_anomaly')
    quality=transport and closed and not unresolved and not any(stats[k] for k in bad)
    return dict(wire_consistent=True,transport_complete=transport,stream_quality_passed=quality,ordinary_full_requests=ordinary,
        proven_internal_flushes=internal,proven_software_sequences=software,unresolved_records=unresolved,raw_flagged_records=raw_flags,
        read_completed_bytes=read,write_completed_bytes=written,ordinary_service_sum_ns=service_sum,ordinary_queue_sum_ns=queue_sum,
        kernel_counters=stats,software_contexts_closed=closed,foreground_attribution_qualified=False,overhead_qualified=False)
