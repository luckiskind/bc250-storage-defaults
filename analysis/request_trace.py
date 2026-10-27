"""Independent trace-wire consistency check; not foreground attribution."""
COUNTERS=('insert','issue','final','orphan_complete','zero_generation','map_update_fail',
    'repeat_insert','duplicate_issue','requeue','partial','overshoot','ring_lost',
    'delete_race','no_issue','bad_time','orphan_requeue')


def require(value,message):
    if not value:raise ValueError(message)


def validate(report):
    require(report['schema_version']==1 and report['kind']=='bc250-request-trace','Unsupported trace schema')
    records=report['records'];require(len(records)==report['events'],'Missing saved records')
    require(len(report['kernel_counters'])==len(COUNTERS),'Counter schema changed')
    stats=dict(zip(COUNTERS,report['kernel_counters']))
    require(all(type(n) is int and n>=0 for n in stats.values()),'Invalid counter')
    require(stats['final']==len(records)+report['limit_discarded_records']+stats['ring_lost'],
        'Final-completion transport accounting mismatch')
    seen=set();service=[0]*64;queue=[0]*64;qualified=flagged=read=written=service_sum=queue_sum=0
    end=report['detached_monotonic_ns'];start=report['start_monotonic_ns']
    for row in records:
        require(row['id']>0 and row['id'] not in seen,'Repeated or missing request identity');seen.add(row['id'])
        require(row['flags']&~511==0,'Unknown flags')
        require(start<=row['issue_ns']<=row['complete_ns']<=end,'Event outside capture lifetime')
        if row['operation']==0:read+=row['completed_bytes']
        if row['operation']==1:written+=row['completed_bytes']
        if row['flags'] or not row['insert_ns'] or row['bytes']!=row['completed_bytes'] or row['issue_ns']<row['insert_ns']:
            flagged+=1;continue
        qualified+=1;s=row['complete_ns']-row['issue_ns'];q=row['issue_ns']-row['insert_ns']
        service[max(0,s.bit_length()-1)]+=1;queue[max(0,q.bit_length()-1)]+=1
        service_sum+=s;queue_sum+=q
    require((read,written)==(report['read_completed_bytes'],report['write_completed_bytes']),'Byte accounting mismatch')
    require((qualified,flagged)==(report['qualified_full_requests'],report['flagged_events']),'Quality accounting mismatch')
    require(service==report['service_log2_ns'] and queue==report['queue_log2_ns'],'Timing histogram mismatch')
    require(service_sum==report['service_sum_ns'] and queue_sum==report['queue_sum_ns'],'Timing sum mismatch')
    require(report['links_detached'] and not report['maps_pinned'],'Persistent observer resources')
    usable=(not report['event_limit_reached'] and not report['interrupted'] and not report['malformed_events']
        and not stats['ring_lost'] and not stats['map_update_fail'] and not stats['zero_generation'])
    return dict(wire_consistent=True,transport_complete=usable,unique_request_ids=len(seen),
        kernel_counters=stats,qualified_full_requests=qualified,flagged_requests=flagged,
        foreground_attribution_qualified=False,device_only_latency_qualified=False,
        partial_requeue_error_paths_qualified=False)
