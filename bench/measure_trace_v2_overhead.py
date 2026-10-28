#!/usr/bin/env python3
"""Freeze 24 off/v2 pairs in each original serial/concurrent read scenario."""
import argparse
import copy
import fcntl
import json
import os
from pathlib import Path
import random
import shutil
import stat
import struct
import subprocess
import sys
import time
import uuid
import measure_trace_overhead as pilot
import qualify_trace_v2 as observer
from trace_v2_overhead import summarize

q=pilot.q
ROOT=Path(__file__).resolve().parents[1]
CONTRACT=copy.deepcopy(pilot.CONTRACT)
CONTRACT.update(version=5,seed=253,pairs_per_scenario=24,minimum_valid_pairs=20,
    conditions=['off','v2'],ordering='Twelve off-first and twelve v2-first pairs per scenario, shuffled before collection',
    exclusion_scope='Whole pair; every failed measured/warmup capture prevents a pass',
    capture_quality='v2 native-qualified positive provenance; unknown/lost/unclosed contexts remain disqualifying',
    progress_output_deferred_until_after_collection=True,scope='Two synthetic controls, one physical fixture; not application overhead or accelerator gain')


def prepare(area,qualified,original):
    q.native.confined();q.native.private_area(area,creating=True);q.native.private_area(qualified);q.native.private_area(original);q.native.host_space(area.parent)
    reference=pilot.ownership.safe_json(qualified/'result.json');base=pilot.ownership.safe_json(original/'result.json')
    q.require(reference['passed'] and reference['case_count']==10 and reference['all_owned_programs_gone'],'Ten-case v2 qualification required')
    q.require(base['passed'] and base['case_count']==5 and reference['kernel']==base['kernel']==os.uname().release,'Qualified kernel/baseline changed')
    for report in (reference,base):
        for name,sha in report['source_sha256'].items():q.require(q.digest(ROOT/name)==sha,'Qualified source changed: '+name)
    area.mkdir(mode=0o700);target=area/'observer';target.mkdir(mode=0o700)
    for name in ('request_trace_v2.bpf.o','request-trace-v2'):
        q.require(q.digest(qualified/name)==reference['compiled_sha256'][name],'V2 binary changed');shutil.copyfile(qualified/name,target/name)
        (target/name).chmod(0o700 if name=='request-trace-v2' else 0o600)
    q.require(q.digest(original/'direct-probe')==base['compiled_sha256']['direct-probe'],'Original worker changed')
    shutil.copyfile(original/'direct-probe',area/'direct-probe');(area/'direct-probe').chmod(0o700)
    source=original/'fixture.bin';info=source.lstat()
    q.require(stat.S_ISREG(info.st_mode) and info.st_uid==0 and info.st_nlink==1 and info.st_size==64*2**20,'Unsafe original fixture')
    fixture=area/'fixture.bin';fd=os.open(fixture,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        before=os.fstat(fd);flags=bytearray(8);fcntl.ioctl(fd,0x80086601,flags,True)
        fcntl.ioctl(fd,0x40086602,struct.pack('=Q',struct.unpack('=Q',flags)[0]|0x800000));fcntl.ioctl(fd,0x80086601,flags,True)
        q.require(struct.unpack('=Q',flags)[0]&0x800000,'NOCOW not established')
    finally:os.close(fd)
    q.command('cp','--reflink=never','--sparse=never',source,fixture);now=fixture.lstat()
    q.require((now.st_dev,now.st_ino)==(before.st_dev,before.st_ino),'New fixture replaced')
    fd=os.open(fixture,os.O_RDONLY|os.O_NOFOLLOW)
    try:q.require(not any(flags&(8|0x2000) for _,_,flags in q.native.repack.extents(fd,now.st_size)),'Fixture shared/encoded')
    finally:os.close(fd)
    sha=q.digest(source);q.require(q.digest(fixture)==sha,'Fixture copy differs');q.command('sync','-f',fixture)
    return reference,base,sha


def trial(area,device,scenario,pair,condition,warmup):
    q.require(q.residency(area/'fixture.bin',evict=True)==0,'New private fixture not data-cold')
    parameters=CONTRACT['scenarios'][scenario];proc=None;ids=[];log=b'';raw=None;checked=None;stdout=b'';worker=None
    slot_start=time.monotonic_ns();startup=None
    qos=Path('/sys/class/nvme/nvme0/power/pm_qos_latency_tolerance_us')
    try:
        if condition=='v2':
            started=time.monotonic_ns();proc,ids,log=observer.start(area/'observer',device,duration=2);startup=time.monotonic_ns()-started
        else:q.programs()
        quiet0=pilot.environment(device);time.sleep(CONTRACT['post_setup_idle_seconds']);before=pilot.environment(device)
        q.require(qos.read_text().strip()=='5000','Drive policy changed before worker')
        delta=[b-a for a,b in zip(quiet0['cpu'],before['cpu'])];total=sum(delta[:8]);idle=delta[3]+delta[4]
        cpu_fraction=(total-idle)/total if total else 0
        child=pilot.cpu_seconds()
        worker=json.loads(q.command(area/'direct-probe',area/'fixture.bin',parameters['threads'],parameters['operations'],parameters['pattern'],timeout=15))
        worker_cpu=pilot.cpu_seconds()-child;after=pilot.environment(device)
        q.require(qos.read_text().strip()=='5000','Drive policy changed after worker')
        q.require(worker['passed'] and worker['operations']==parameters['threads']*parameters['operations'],'Dedicated read worker failed')
        resident=q.residency(area/'fixture.bin');q.require(resident==0,'Direct worker populated fixture cache')
        integrity=True;observer_cpu=None;window_reads=None;window_bytes=None
        if proc:
            child=pilot.cpu_seconds();stdout,stderr=proc.communicate(timeout=10);observer_cpu=pilot.cpu_seconds()-child;log+=stderr
            q.require(proc.returncode==0 and q.absent(ids),'V2 observer failed/left programs');raw=json.loads(stdout);checked=observer.validate(raw)
            window=[r for r in raw['records'] if r['event_class']==0 and worker['start_monotonic_ns']<=r['issue_ns']<=r['complete_ns']<=worker['finish_monotonic_ns'] and r['operation']==0]
            window_reads=len(window);window_bytes=sum(r['completed_bytes'] for r in window)
            integrity=bool(checked['stream_quality_passed'] and window_reads==worker['operations'] and window_bytes==worker['read_bytes']
                and raw['start_ns']<=worker['start_monotonic_ns']<worker['finish_monotonic_ns']<=raw['finish_ns'])
        else:
            remaining=2-(time.monotonic_ns()-slot_start)/1e9
            if remaining>0:time.sleep(remaining)
        read=(after['disk'][2]-before['disk'][2])*512;written=(after['disk'][6]-before['disk'][6])*512;extra=max(0,read-worker['read_bytes'])+written
        pre_io=((before['disk'][2]-quiet0['disk'][2])+(before['disk'][6]-quiet0['disk'][6]))*512;reasons=[]
        if cpu_fraction>CONTRACT['background_cpu_fraction_max']:reasons.append('pre-workload-cpu-busy')
        if pre_io>CONTRACT['pre_workload_device_bytes_max']:reasons.append('pre-workload-device-busy')
        if min(before['memory']['MemAvailable'],after['memory']['MemAvailable'])<CONTRACT['minimum_available_bytes']:reasons.append('low-available-memory')
        if extra>CONTRACT['additional_io_bytes_max']:reasons.append('additional-device-io')
        if pilot.policy(before)!=pilot.policy(after):reasons.append('cpu-policy-changed')
        def throttle(snapshot):return int(dict(line.split() for line in snapshot['cgroup_cpu_stat'].splitlines()).get('nr_throttled',0))
        throttled=throttle(after)-throttle(before)
        if throttled:reasons.append('cgroup-cpu-throttled')
        if read<worker['read_bytes']:integrity=False
        return dict(scenario=scenario,pair=pair,condition=condition,warmup=warmup,workload=worker,environment_exclusions=reasons,
            capture_integrity=integrity,observed_read_bytes=read,observed_write_bytes=written,additional_io_bytes=extra,
            pre_workload_cpu_fraction=cpu_fraction,pre_workload_device_bytes=pre_io,fixture_resident_before_bytes=0,fixture_resident_after_bytes=resident,
            worker_process_cpu_seconds=worker_cpu,observer_process_cpu_seconds=observer_cpu,observer_startup_ns=startup,
            observer_cpu_excludes_kernel_callback_cost=True,before=before,after=after,validation=checked,
            timed_window_read_records=window_reads,timed_window_read_bytes=window_bytes,cgroup_throttled_periods_delta=throttled),raw,log
    except BaseException as exc:
        if proc:q.finish(proc)
        prefix=area/('failed-'+scenario+'-'+str(pair)+'-'+condition+'-'+str(int(warmup)))
        pilot.save(prefix.with_suffix('.json'),dict(error=str(exc),worker=worker,trace=raw));prefix.with_suffix('.stdout').write_bytes(stdout);prefix.with_suffix('.log').write_bytes(log)
        raise
    finally:
        if proc:q.finish(proc)


def host(args):
    area=args.output.absolute();qualified=args.qualified.absolute();original=args.original.absolute()
    device=q.block_device(area.parent);q.require(device==q.block_device(Path('/')),'Different observed physical namespace')
    qos=Path('/sys/class/nvme/nvme0/power/pm_qos_latency_tolerance_us');q.require(qos.read_text().strip()=='5000','Drive policy changed')
    before_trace=q.trace_state();inventory=q.programs();reference,baseline,sha=prepare(area,qualified,original)
    rng=random.Random(CONTRACT['seed']);order=[]
    for scenario in CONTRACT['scenarios']:
        order += [dict(scenario=scenario,pair=-1,condition=c,warmup=True) for c in CONTRACT['conditions']]
        orientations=['off','v2']*12;rng.shuffle(orientations)
        for pair,first in enumerate(orientations):
            order += [dict(scenario=scenario,pair=pair,condition=c,warmup=False) for c in (first,'off' if first=='v2' else 'v2')]
    sources={name:q.digest(ROOT/name) for name in ('bench/measure_trace_v2_overhead.py','analysis/trace_v2_overhead.py','bench/measure_trace_overhead.py','analysis/trace_overhead.py','bench/qualify_trace_v2.py','analysis/request_trace_v2.py')}
    contract=dict(CONTRACT,order=order,fixture_sha256=sha,qualification_sha256=q.digest(qualified/'result.json'),original_qualification_sha256=q.digest(original/'result.json'),
        source_sha256=sources,v2_compiled_sha256=reference['compiled_sha256'],worker_compiled_sha256=baseline['compiled_sha256']['direct-probe'],
        one_physical_fixture_for_all_conditions=True,contract_file_fsynced_before_collection=True,warmup_capture_failure_is_disqualifying=True,
        cgroup_throttling_is_environment_exclusion=True,exact_known_read_window_required=True,frozen_unix=time.time())
    pilot.save(area/'contract.json',contract)
    with (area/'contract.json').open('rb') as stream:os.fsync(stream.fileno())
    rows=[];captures=[]
    try:
        for item in order:
            row,raw,log=trial(area,device,**item);rows.append(row);captures.append((raw,log))
        for scenario in CONTRACT['scenarios']:
            for pair in range(CONTRACT['pairs_per_scenario']):
                group=[r for r in rows if r['scenario']==scenario and not r['warmup'] and r['pair']==pair]
                policies={json.dumps(pilot.policy(r[name]),sort_keys=True) for r in group for name in ('before','after')}
                if len(policies)!=1:
                    for row in group:row['environment_exclusions'].append('cpu-policy-changed-within-pair')
    finally:
        pilot.save(area/'trials-private.json',rows)
        for index,(raw,log) in enumerate(captures):
            if raw is not None:pilot.save(area/f'trace-{index}-private.json',raw)
            (area/f'trace-{index}.loader.log').write_bytes(log)
        q.require(q.trace_state()==before_trace and qos.read_text().strip()=='5000','Trace/power state changed')
    q.require(q.digest(area/'fixture.bin')==sha==q.digest(original/'fixture.bin'),'Read fixture contents changed')
    q.require(q.programs()==inventory,'Unrelated programs changed')
    q.require(all(q.digest(ROOT/n)==v for n,v in sources.items()),'Calibration source changed')
    result=dict(schema_version=1,collection_complete=True,contract=contract,summary=summarize(rows,CONTRACT),
        fixture_unchanged=True,one_physical_fixture_for_all_conditions=True,original_worker_binary_unchanged=True,
        all_owned_programs_gone=True,unrelated_program_inventory_unchanged=True,global_trace_state_unchanged=True,nvme_qos_us=5000,
        global_page_cache_reset_performed=False,private_fixture_eviction_only=True,production_observer_enabled=False,
        historical_results_pooled=False,new_accelerator_throughput_comparison_performed=False,completed_unix=time.time())
    pilot.save(area/'result.json',result);print(json.dumps(result['summary']),flush=True)


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('step',choices=('run','_host'))
    for name in ('qualified','original','output'):parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args();q.require(sys.platform=='linux' and os.geteuid()==0,'Linux root required')
    if args.step=='_host':host(args);return
    unit='bc250-trace2-overhead-'+uuid.uuid4().hex[:12]
    subprocess.run(['systemd-run','--quiet','--wait','--pipe','--collect','--unit='+unit,'--property=MemoryMax=2G','--property=MemoryHigh=1536M',
        '--property=MemorySwapMax=0','--property=CPUQuota=200%','--property=TasksMax=128','--property=RuntimeMaxSec=300','--property=KillMode=control-group',
        '/usr/bin/unshare','--mount','--propagation','private','/usr/bin/python3','-B',str(Path(__file__).resolve()),'_host',
        '--qualified',str(args.qualified),'--original',str(args.original),'--output',str(args.output)],check=True,timeout=330)


if __name__=='__main__':main()
