#!/usr/bin/env python3
"""Replay frozen native traces and one explicitly synthetic censored prefix."""
import argparse
import copy
import json
import os
from pathlib import Path
import re
import sys
import qualify_request_trace as q
from request_bio_accounting import validate
from request_bio_lineage import validate as reference_validate

ROOT=Path(__file__).resolve().parents[1]


def censored_prefix(raw):
    order=sorted(raw['records'],key=lambda x:x['time_ns']);cut=next(i for i,r in enumerate(order) if r['stage']==21)
    result=copy.deepcopy(raw);rows=copy.deepcopy(order[:cut+1]);result.update(records=rows,events=len(rows),interrupted=True,pending_contexts=[1]*9)
    # These counters/open markers are reconstructed for a synthetic censor,
    # never presented as an actual kernel snapshot from the original run.
    result['counters']=[len(rows)]+[0]*15;pc=[0]*24
    for r in rows:
        s=r['stage']
        if s==17:pc[0]+=1;pc[1]+=1
        if s==18:pc[3]+=int(bool(r['value']));pc[4]+=1
        if s==19:pc[5]+=1
        if s==20:pc[1]+=1
        if s==21:pc[6]+=int(r['value']<r['aux'])
        if s==22:pc[2]+=1
        if s==23:pc[16]+=1
    result['request_counters']=pc;return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('reference','reviewed','output'):parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--reviewed-sha256',required=True);args=parser.parse_args()
    q.require(sys.platform=='linux' and os.geteuid()==0,'Root reads protected native evidence; no kernel tracing or workload is started')
    ref=args.reference.absolute();out=args.output.absolute();q.native.private_area(ref);q.native.private_area(out,creating=True)
    source=json.loads((ref/'result.json').read_text());q.require(source['passed'] and source['case_count']==14,'Frozen native qualification missing')
    q.require(re.fullmatch('[0-9a-f]{64}',args.reviewed_sha256) and q.digest(args.reviewed)==args.reviewed_sha256,'Reviewed evidence hash differs')
    reviewed=json.loads(args.reviewed.read_text());q.require(reviewed['passed'] and reviewed['case_count']==14 and reviewed['raw_reviews_recomputed'],'Reviewed native evidence missing')
    q.require(reviewed['private_result_sha256']==q.digest(ref/'result.json'),'Reviewed parent result differs')
    reviewed_cases={row['case']:row for row in reviewed['cases']}
    for name,sha in source['contract']['source_sha256'].items():q.require(q.digest(ROOT/name)==sha,'Frozen native source differs: '+name)
    for name,sha in source['extension']['compiled_sha256'].items():q.require(q.digest(ref/name)==sha,'Frozen native binary differs')
    names=['analysis/request_bio_accounting.py','bench/replay_request_accounting.py'];own={name:q.digest(ROOT/name) for name in names}
    out.mkdir(mode=0o700);rows=[]
    for case in source['cases']:
        if case.get('forced_exit'):continue
        path=ref/(case['case']+'-raw-private.json');raw=json.loads(path.read_text());before=copy.deepcopy(raw)
        q.require(q.digest(path)==reviewed_cases[case['case']]['raw_capture_sha256'],'Frozen reviewed raw hash differs')
        old=reference_validate(raw);q.require(old==case['validation'],'Frozen native interpretation differs');new=validate(raw);q.require(raw==before,'Replay mutated source input')
        q.require(new['stream_quality_passed']==old['stream_quality_passed'],'Reader changed quality verdict')
        if old['stream_quality_passed']:q.require(new['request_reported_total_bytes']==old['request_reported_total_bytes'],'Complete totals changed')
        rows.append(dict(case=case['case'],source='frozen native raw replay',raw_sha256=q.digest(path),validation=new))
    target=ref/'compressed-read-cold-raw-private.json';raw=censored_prefix(json.loads(target.read_text()));old=reference_validate(raw);new=validate(raw)
    q.require(not new['stream_quality_passed'] and new['request_issued_total_bytes']>new['request_reported_total_bytes']>0,'Synthetic censor did not expose issued/reported difference')
    q.require(old['request_reported_total_bytes']==new['request_issued_total_bytes'],'Legacy label no longer reproduces')
    (out/'synthetic-prefix-private.json').write_text(json.dumps(raw,indent=2)+'\n')
    rows.append(dict(case='synthetic-censor-after-first-completion-chunk',source='synthetic prefix; reconstructed counters and conservative open-context markers, not a native stop',
        original_raw_sha256=q.digest(target),legacy_reported_label_bytes=old['request_reported_total_bytes'],validation=new))
    for name,sha in own.items():q.require(q.digest(ROOT/name)==sha,'Accounting source changed during replay')
    result=dict(schema_version=1,kind='bc250-request-accounting-replay',passed=True,case_count=len(rows),native_raw_replays=len(rows)-1,
        synthetic_prefix_cases=1,cases=rows,source_sha256=own,frozen_native_result_sha256=q.digest(ref/'result.json'),reviewed_native_evidence_sha256=args.reviewed_sha256,
        frozen_native_sources_and_binaries_verified=True,new_kernel_collection=False,new_workload_execution=False,
        native_partial_or_error_paths_qualified=False,performance_result=False,stage1_gate_passed=False)
    (out/'result.json').write_text(json.dumps(result,indent=2)+'\n');aggregate=out.parent/'request-accounting-reviewed.json';aggregate.write_text(json.dumps(result,indent=2)+'\n');aggregate.chmod(0o644)
    print(json.dumps(dict(passed=True,native_raw_replays=len(rows)-1,synthetic_prefix_cases=1,issued_bytes=new['request_issued_total_bytes'],reported_bytes=new['request_reported_total_bytes'])))


if __name__=='__main__':main()
