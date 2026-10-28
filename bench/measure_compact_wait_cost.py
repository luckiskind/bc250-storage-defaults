#!/usr/bin/env python3
"""Fixed contemporaneous off/full/compact comparison on private cold data."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import time
import uuid
from types import SimpleNamespace
from unittest.mock import patch
import measure_combined_wait_cost as frozen
import qualify_compact_wait as compact
from compact_wait_cost import CONTRACT,planned_order,summarize

q=frozen.q;ROOT=frozen.ROOT;pilot=frozen.pilot
COMPACT_OBSERVER=SimpleNamespace(base=frozen.observer.base,start=compact.start,validate=compact.validate)


def prepare(area,full_reference,compact_reference):
    full,fixtures,expected,binaries=frozen.prepare(area,full_reference)
    q.native.private_area(compact_reference);candidate=json.loads((compact_reference/'result.json').read_text())
    q.require(candidate['kind']=='bc250-compact-wait-qualification' and candidate['passed'] and candidate['case_count']==16 and candidate['compact_wait_controls_passed'],'Compact native qualification required')
    q.require(candidate['contract']['kernel']==full['contract']['kernel']==os.uname().release and candidate['extension']['active_program_count']==28,'Compact kernel/program contract changed')
    q.require(candidate['full_combined_reference_sha256']==q.digest(full_reference/'result.json'),'Compact full reference differs')
    for n,h in candidate['contract']['source_sha256'].items():q.require(q.digest(ROOT/n)==h,'Compact qualified source changed: '+n)
    for n,h in {**candidate['compiled_sha256'],**candidate['extension']['compiled_sha256']}.items():q.require(q.digest(compact_reference/n)==h,'Compact qualified binary changed')
    q.require(candidate['compiled_sha256']['read-lineage-probe']==binaries['read-lineage-probe'] and candidate['shared_worker_binary_unchanged'],'Exact common worker required')
    q.require(candidate['extension']['btf_header_sha256']==full['extension']['btf_header_sha256'],'Qualified BTF differs')
    for n in ('compact-wait','compact_wait.bpf.o'):
        shutil.copyfile(compact_reference/n,area/n);(area/n).chmod(0o600 if n.endswith('.o') else 0o700);binaries[n]=q.digest(area/n)
        q.require(binaries[n]==candidate['extension']['compiled_sha256'][n],'Copied compact binary differs')
    return full,candidate,fixtures,expected,binaries


def trial(area,device,expected,inventory,item):
    transformed=dict(item,condition='off' if item['condition']=='off' else 'combined')
    observer=COMPACT_OBSERVER if item['condition']=='compact' else frozen.observer
    try:
        with patch.object(frozen,'observer',observer):row,raw,log=frozen.trial(area,device,expected,inventory,transformed)
    except BaseException as exc:
        pilot.save(area/'failed-native-arm-private.json',dict(item,error=str(exc)));raise
    row.update(item);row['observer_variant']=item['condition'];return row,raw,log


def host(args):
    area=args.output.absolute();full_reference=args.full_reference.absolute();compact_reference=args.compact_reference.absolute()
    device=q.block_device(area.parent);q.require(device==q.block_device(Path('/')),'Physical namespace differs')
    qos=Path('/sys/class/nvme/nvme0/power/pm_qos_latency_tolerance_us');q.require(qos.read_text().strip()=='5000','Power policy changed')
    state,inventory=q.trace_state(),q.programs();full,candidate,fixtures,expected,binaries=prepare(area,full_reference,compact_reference)
    # The inherited trial body reads these fields. Keep the cache, endpoint,
    # environmental and capture rules exactly equal in all three arms.
    used=('post_setup_idle_seconds','background_cpu_fraction_max','minimum_available_bytes','pre_workload_device_bytes_max',
        'timed_write_bytes_max','timed_read_bytes_max','capture_seconds','max_saved_records','logical_bytes')
    q.require(all(CONTRACT[n]==frozen.CONTRACT[n] for n in used),'Frozen per-trial rules changed')
    paths=set(full['contract']['source_sha256'])|set(candidate['contract']['source_sha256'])|{
        'bench/measure_compact_wait_cost.py','analysis/compact_wait_cost.py','bench/measure_combined_wait_cost.py','analysis/combined_wait_cost.py',
        'bench/measure_trace_overhead.py','analysis/trace_overhead.py','tools/native_volume_lab.py','tools/native_trial_lab.py'}
    sources={n:q.digest(ROOT/n) for n in sorted(paths)};order=planned_order()
    contract=dict(CONTRACT,order=order,source_sha256=sources,full_reference_sha256=q.digest(full_reference/'result.json'),
        compact_reference_sha256=q.digest(compact_reference/'result.json'),copied_compiled_sha256=binaries,fixture_records=fixtures,
        worker_fnv64=expected,kernel=os.uname().release,btf_header_sha256=full['extension']['btf_header_sha256'],
        frozen_before_collection=True,contract_fsynced=True,unchanged_shared_trial_body=True,exact_shared_worker=True,
        observer_binaries_not_recompiled=True,whole_block_exclusions=True,raw_output_deferred=True,progress_only_in_tmpfs=True,
        production_defaults_changed=False,global_cache_reset=False,historical_results_pooled=False,
        frozen_monotonic_ns=time.monotonic_ns(),frozen_unix_ns=time.time_ns())
    pilot.save(area/'contract.json',contract)
    with (area/'contract.json').open('rb') as stream:os.fsync(stream.fileno())
    dfd=os.open(area,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(dfd)
    finally:os.close(dfd)
    q.require(args.progress.parent==Path('/run') and re.fullmatch(r'bc250-compact-cost-[0-9a-f]{12}\.json',args.progress.name),'Invalid owned progress target')
    pfd=os.open(args.progress,os.O_RDWR|os.O_NOFOLLOW);info=os.fstat(pfd);q.require(stat.S_ISREG(info.st_mode) and info.st_uid==0 and info.st_nlink==1,'Unowned progress file')
    rows=[];captures=[];retained=0
    try:
        with os.fdopen(pfd,'w') as progress:
            for item in order:
                row,raw,log=trial(area,device,expected,inventory,item);rows.append(row);captures.append((raw,log));retained+=len(raw)+len(log)
                q.require(retained<=CONTRACT['maximum_retained_raw_bytes'],'Aggregate retained raw bound')
                progress.seek(0);json.dump(dict(completed_trials=len(rows),total_trials=len(order),collection_live=True),progress);progress.truncate();progress.flush()
        for scenario in CONTRACT['scenarios']:
            for pair in range(CONTRACT['pairs_per_scenario']):
                group=[r for r in rows if r['scenario']==scenario and r['pair']==pair and not r['warmup']]
                policies={json.dumps(pilot.policy(r[phase]),sort_keys=True) for r in group for phase in ('before','after')}
                if len(policies)!=1:
                    for row in group:row['environment_exclusions'].append('cpu-policy-changed-within-block')
    finally:
        pilot.save(area/'trials-private.json',rows)
        for i,(raw,log) in enumerate(captures):
            if raw:(area/('trace-%d-private.json'%i)).write_bytes(raw)
            (area/('trace-%d-loader-private.log'%i)).write_bytes(log)
        q.require(q.trace_state()==state and q.programs()==inventory and qos.read_text().strip()=='5000','Global tracing/program/power state changed')
    for n,h in sources.items():q.require(q.digest(ROOT/n)==h,'Comparison source changed')
    for n,h in binaries.items():q.require(q.digest(area/n)==h,'Comparison binary changed')
    for n,record in fixtures.items():q.require(q.digest(area/n)==record['sha256']==q.digest(full_reference/n),'Fixture/reference content changed')
    q.require(q.digest(full_reference/'result.json')==contract['full_reference_sha256'] and q.digest(compact_reference/'result.json')==contract['compact_reference_sha256'],'Native reference result changed')
    result=dict(schema_version=1,kind='bc250-compact-wait-cost',collection_complete=True,contract=contract,summary=summarize(rows,contract),
        all_owned_programs_gone=True,global_trace_state_unchanged=True,unrelated_program_inventory_unchanged=True,
        qualified_binaries_unchanged=True,private_and_reference_contents_unchanged=True,retained_raw_bytes=retained,
        production_defaults_changed=False,production_observer_installed=False,global_cache_reset=False,historical_results_pooled=False,
        accelerator_gain_comparison=False,stage1_gate_passed=False)
    pilot.save(area/'result.json',result);print(json.dumps(result['summary']),flush=True)


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('step',choices=('run','_host'))
    for name in ('full-reference','compact-reference','output'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--progress',type=Path);args=p.parse_args();q.require(sys.platform=='linux' and os.geteuid()==0,'Linux root required')
    if args.step=='_host':q.require(args.progress is not None,'Owned progress required');host(args);return
    q.require(args.progress is None,'Progress target is created by launcher')
    unit='bc250-compact-cost-'+uuid.uuid4().hex[:12];progress=Path('/run')/(unit+'.json');fd=os.open(progress,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o644)
    with os.fdopen(fd,'w') as out:json.dump(dict(completed_trials=0,total_trials=len(planned_order()),collection_live=True),out)
    print(json.dumps(dict(unit=unit,progress=str(progress),total_trials=len(planned_order()))),flush=True)
    try:
        subprocess.run(['systemd-run','--quiet','--wait','--pipe','--collect','--unit='+unit,'--property=MemoryMax=2G','--property=MemorySwapMax=0',
            '--property=CPUQuota=200%','--property=TasksMax=128','--property=RuntimeMaxSec='+str(CONTRACT['parent_runtime_seconds']),'--property=KillMode=control-group',
            '/usr/bin/unshare','--mount','--propagation','private','/usr/bin/python3','-B',str(Path(__file__).resolve()),'_host',
            '--full-reference',str(args.full_reference),'--compact-reference',str(args.compact_reference),'--output',str(args.output),'--progress',str(progress)],
            check=True,timeout=CONTRACT['parent_runtime_seconds']+30)
    finally:progress.unlink(missing_ok=True)


if __name__=='__main__':main()
