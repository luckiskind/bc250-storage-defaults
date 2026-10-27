"""Validate callback transport and describe only observed lifecycle patterns.

Distinct from timing validation. Never reclassifies the original observer or
attributes callbacks to a foreground task from timing/count coincidences.
"""
import argparse
import collections
import json
from pathlib import Path

FIELDS={'id','ordinal','time_ns','stage','operation','data_bytes','completed_bytes','status',
    'rq_flags','cmd_flags','internal_flush','flush_seq','bio_present'}
TOP={'schema_version','kind','start_ns','finish_ns','detached_ns','events','malformed','discarded',
    'interrupted','limit_reached','counters','records','links_detached','maps_pinned','performance_result'}


def require(value,message):
    if not value:raise ValueError(message)


def number(value,maximum=2**64-1):
    return type(value) is int and 0<=value<=maximum


def summarize(report):
    require(isinstance(report,dict) and set(report)==TOP,'Unexpected lifecycle schema/fields')
    require(report['schema_version']==1 and report['kind']=='bc250-request-lifecycle-diagnostic','Wrong lifecycle format')
    require(all(number(report[name]) for name in ('start_ns','finish_ns','detached_ns','events','malformed','discarded')),'Invalid counters/clocks')
    require(report['start_ns']<report['finish_ns']<=report['detached_ns'],'Invalid capture lifetime')
    require(all(type(report[name]) is bool for name in ('interrupted','limit_reached','links_detached','maps_pinned','performance_result')),'Invalid state flags')
    records=report['records'];stats=report['counters']
    require(isinstance(records,list) and len(records)==report['events']<=50000,'Record count bound/mismatch')
    require(isinstance(stats,list) and len(stats)==4 and all(number(v) for v in stats),'Invalid transport counters')
    require(stats[0]==len(records)+stats[1]+stats[2]+stats[3]+report['discarded'],'Callback transport accounting differs')
    require(not report['malformed'] and report['links_detached'] and not report['maps_pinned'] and not report['performance_result'],'Malformed or persistent/performance diagnostic')
    complete=not any(stats[1:]) and not report['discarded'] and not report['interrupted'] and not report['limit_reached']
    groups=collections.defaultdict(list)
    for row in records:
        require(isinstance(row,dict) and set(row)==FIELDS,'Unexpected callback fields')
        require(all(number(row[name],2**64-1 if name in ('id','ordinal','time_ns') else 2**32-1) for name in FIELDS),'Invalid callback integer')
        require(row['id']>0 and row['ordinal']>0 and 1<=row['stage']<=6 and row['operation']<=255,'Invalid callback identity/stage')
        require(row['internal_flush'] in (0,1) and row['bio_present'] in (0,1),'Invalid pointer-presence relation')
        require(report['start_ns']<=row['time_ns']<=report['detached_ns'],'Callback outside attached lifetime')
        require(row['stage']!=6 or row['status'] in (0,1),'Flush return is not Boolean')
        require(row['stage']==4 or row['completed_bytes']==0,'Completion bytes on a noncompletion callback')
        groups[row['id']].append(row)
    require(len(groups)<=8192,'Identity map bound')
    classes=collections.Counter();internal=consumed=unissued=unexplained=read_groups=read_bytes=errors=0
    for rows in groups.values():
        rows.sort(key=lambda r:r['ordinal']);ordinals=[r['ordinal'] for r in rows]
        require(len(set(ordinals))==len(ordinals),'Duplicate per-request callback ordinal')
        if complete:require(ordinals==list(range(1,len(rows)+1)),'Missing per-request callback ordinal')
        require(all(rows[i]['time_ns']<=rows[i+1]['time_ns'] for i in range(len(rows)-1)),'Per-request callback clock order differs')
        stages=tuple(r['stage'] for r in rows);ops=tuple(sorted(set(r['operation'] for r in rows)))
        zero=all(not r['data_bytes'] and not r['completed_bytes'] for r in rows)
        relation=tuple(sorted(set(r['internal_flush'] for r in rows)))
        classes[(ops,stages,zero,relation)]+=1
        finishes=[r for r in rows if r['stage']==4];errors+=sum(r['status']!=0 for r in finishes)
        no_issue=bool(finishes) and 2 not in stages;unissued+=no_issue
        known_internal=(complete and stages==(2,4) and ops==(2,) and zero and relation==(1,)
            and all(not r['status'] and not r['bio_present'] for r in rows))
        known_consumed=(complete and stages==(5,6,4) and ops==(1,) and zero and relation==(0,)
            and [r['status'] for r in rows]==[0,1,0] and all(r['bio_present'] for r in rows))
        ordinary=(stages==(1,2,4) or (stages==(5,6,1,2,4) and rows[1]['status']==0))
        ordinary=ordinary and len(ops)==1 and ops[0] in (0,1) and relation==(0,)
        ordinary=ordinary and not any(r['status'] for r in rows) and rows[-1]['completed_bytes']==rows[-2]['data_bytes']>0
        internal+=known_internal;consumed+=known_consumed
        if finishes and not (known_internal or known_consumed or ordinary):unexplained+=1
        if ordinary and ops==(0,):read_groups+=1;read_bytes+=rows[-1]['completed_bytes']
    return dict(schema_version=1,transport_complete=complete,callbacks=len(records),request_identity_groups=len(groups),
        ordinary_read_groups=read_groups,ordinary_read_completed_bytes=read_bytes,completion_error_callbacks=errors,
        internal_zero_payload_device_flush_groups=internal,zero_payload_consumed_sequence_groups=consumed,
        unissued_completion_groups=unissued,unexplained_completion_groups=unexplained,
        classes=[dict(operations=list(ops),stages=list(stages),zero_data=zero,internal_flush_relations=list(relation),groups=count)
            for (ops,stages,zero,relation),count in sorted(classes.items())],
        historical_orphan_causes_proven=False,old_verdicts_changed=False,full_flush_error_partial_requeue_paths_qualified=False,
        foreground_request_attribution_qualified=False,performance_result=False)


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('capture',type=Path);args=parser.parse_args()
    require(args.capture.stat().st_size<=32*2**20,'Diagnostic input bound')
    print(json.dumps(summarize(json.loads(args.capture.read_text())),indent=2))


if __name__=='__main__':main()
