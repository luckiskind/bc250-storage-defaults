#!/usr/bin/env python3
"""Bounded off/combined cost experiment on new independent private fixtures."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import subprocess
import sys
import time
import uuid
import measure_trace_overhead as pilot
import qualify_combined_wait as observer
from combined_wait_cost import CONTRACT,planned_order,summarize

q=observer.q;ROOT=observer.ROOT


def prepare(area,qualified):
    q.native.confined();q.native.private_area(area,creating=True);q.native.private_area(qualified);q.native.host_space(area.parent)
    report=json.loads((qualified/'result.json').read_text());q.require(report['passed'] and report['case_count']==16 and report['selected_worker_request_folio_wait_controls_passed'],'Combined reference unqualified')
    q.require(report['contract']['kernel']==os.uname().release and report['extension']['active_program_count']==29,'Qualified kernel/program scope changed')
    for name,sha in report['contract']['source_sha256'].items():q.require(q.digest(ROOT/name)==sha,'Frozen combined source differs: '+name)
    hashes={**report['compiled_sha256'],**report['extension']['compiled_sha256']}
    for name,sha in hashes.items():q.require(q.digest(qualified/name)==sha,'Frozen combined binary differs')
    actual_btf=subprocess.check_output(['bpftool','btf','dump','file','/sys/kernel/btf/vmlinux','format','c'],timeout=30)
    q.require(hashlib.sha256(actual_btf).hexdigest()==report['extension']['btf_header_sha256'],'Actual kernel BTF changed')
    area.mkdir(mode=0o700)
    for name in ('combined-wait','combined_wait.bpf.o','read-lineage-probe'):
        shutil.copyfile(qualified/name,area/name);(area/name).chmod(0o600 if name.endswith('.o') else 0o700)
        q.require(q.digest(area/name)==hashes[name],'Copied executable differs')
    fixtures={};content=None
    for name,nocow in [('plain.bin',True),('compressed.bin',False)]:
        old=qualified/name;info=old.lstat();record=report['contract']['fixtures'][name]
        q.require(stat.S_ISREG(info.st_mode) and info.st_uid==0 and info.st_nlink==1 and info.st_size==CONTRACT['fixture_bytes'] and q.digest(old)==record['sha256'],'Unsafe/changed qualified fixture')
        data=old.read_bytes()
        if content is None:content=data
        else:q.require(data==content,'Plain/encoded reference contents differ')
        path=area/name;fd=os.open(path,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        try:
            if nocow:
                flags=bytearray(8);fcntl.ioctl(fd,0x80086601,flags,True);fcntl.ioctl(fd,0x40086602,struct.pack('=Q',struct.unpack('=Q',flags)[0]|0x800000))
            with os.fdopen(os.dup(fd),'wb') as out:out.write(data);out.flush();os.fsync(out.fileno())
            spans=q.native.repack.extents(fd,len(data));q.require(bool(any(flags&8 for _,_,flags in spans))==bool(not nocow) and not any(flags&0x2000 for _,_,flags in spans),'Private fixture encoding/sharing differs')
            q.require(q.digest(path)==record['sha256'],'New independent fixture content differs')
            fixtures[name]=dict(bytes=len(data),sha256=record['sha256'],encoded_extents=sum(bool(flags&8) for _,_,flags in spans),shared_extents=0)
        finally:os.close(fd)
    fnv=14695981039346656037
    for byte in content[:CONTRACT['logical_bytes']]:fnv=((fnv^byte)*1099511628211)&((1<<64)-1)
    return report,fixtures,f'{fnv:016x}',{n:hashes[n] for n in ('combined-wait','combined_wait.bpf.o','read-lineage-probe')}


def exclusions(quiet,before,after):
    delta=[b-a for a,b in zip(quiet['cpu'],before['cpu'])];total=sum(delta[:8]);idle=delta[3]+delta[4];busy=(total-idle)/total if total else 0
    pre=((before['disk'][2]-quiet['disk'][2])+(before['disk'][6]-quiet['disk'][6]))*512
    read=(after['disk'][2]-before['disk'][2])*512;written=(after['disk'][6]-before['disk'][6])*512;reasons=[]
    if min(pre,read,written)<0:raise ValueError('Device counters moved backwards')
    if busy>CONTRACT['background_cpu_fraction_max']:reasons.append('pre-workload-cpu-busy')
    if pre>CONTRACT['pre_workload_device_bytes_max']:reasons.append('pre-workload-device-busy')
    if min(before['memory']['MemAvailable'],after['memory']['MemAvailable'])<CONTRACT['minimum_available_bytes']:reasons.append('low-available-memory')
    if read>CONTRACT['timed_read_bytes_max']:reasons.append('timed-global-read-bound')
    if written>CONTRACT['timed_write_bytes_max']:reasons.append('timed-global-write-bound')
    if pilot.policy(before)!=pilot.policy(after):reasons.append('cpu-policy-changed')
    def throttle(s):return int(dict(line.split() for line in s['cgroup_cpu_stat'].splitlines()).get('nr_throttled',0))
    throttled=throttle(after)-throttle(before)
    if throttled:reasons.append('parent-cgroup-cpu-throttled')
    return reasons,dict(pre_workload_cpu_fraction=busy,pre_workload_device_bytes=pre,observed_read_bytes=read,observed_write_bytes=written,parent_cgroup_throttled_periods_delta=throttled)


def trial(area,device,expected_hash,inventory,item):
    filename='compressed.bin' if item['scenario'].startswith('encoded-') else 'plain.bin';mode=item['scenario'].split('-')[1];path=area/filename
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW);trace=None;worker=None;ids=[];log=b'';raw=None;stdout=b'';checked=None;errors=[];work=None
    qos=Path('/sys/class/nvme/nvme0/power/pm_qos_latency_tolerance_us')
    try:
        worker=subprocess.Popen([str(area/'read-lineage-probe'),str(fd),mode],pass_fds=(fd,),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        q.require(observer.base.line(worker)==b'BC250_READ_WORKER_READY\n','Pinned worker not ready')
        setup=time.monotonic_ns()
        if item['condition']=='combined':trace,ids,log=observer.start(area,worker.pid,fd,CONTRACT['max_saved_records'],True,True,True,True)
        else:
            q.require(q.programs()==inventory,'Unexpected observer in off arm')
            q.require(q.residency(area/'compressed.bin',evict=True)==0,'Off-arm calibration not cold');q.digest(area/'compressed.bin')
        startup=time.monotonic_ns()-setup;slot=time.monotonic_ns()
        resident=q.residency(path,evict=True);q.require(resident==0,'Selected private data not cold after calibration')
        quiet=pilot.environment(device);time.sleep(CONTRACT['post_setup_idle_seconds']);before=pilot.environment(device)
        q.require(qos.read_text().strip()=='5000','Drive policy changed before worker')
        worker.stdin.write(b'G');worker.stdin.flush();work=json.loads(observer.base.line(worker));after=pilot.environment(device)
        q.require(work['passed'] and work['logical_bytes']==CONTRACT['logical_bytes'] and work['fnv64']==expected_hash and work['start_ns']<work['finish_ns'],'Worker content/endpoint failed')
        q.require(qos.read_text().strip()=='5000','Drive policy changed after worker')
        if trace:
            stdout,err=trace.communicate(timeout=10);log+=err;q.require(trace.returncode==0 and q.absent(ids),'Observer exited abnormally or left hooks')
            raw=json.loads(stdout)
            try:
                checked=observer.validate(raw)
                if not checked['stream_quality_passed']:errors.append('combined-stream-quality-failed')
                if not raw['start_ns']<=work['start_ns']<work['finish_ns']<=raw['finish_ns']:errors.append('worker-outside-capture')
                if checked['demand_attempts']==0 or checked['original_data_bios']==0 or checked['request_generations']==0:errors.append('cold-demand-request-coverage-absent')
                if checked['blocked_switch_segments']==0 or checked['resolved_request_folio_blocked_segments']!=checked['blocked_switch_segments']:errors.append('cold-causal-blocked-coverage-absent')
                if mode=='read' and checked['buffered_read_returned_bytes']!=work['logical_bytes']:errors.append('buffered-byte-accounting-differs')
            except ValueError as exc:errors.append('combined-reader-rejected: '+str(exc))
        else:
            remaining=CONTRACT['capture_seconds']-(time.monotonic_ns()-slot)/1e9
            if remaining>0:time.sleep(remaining)
        resident_after=q.residency(path);reasons,environment=exclusions(quiet,before,after)
        worker.stdin.write(b'D');worker.stdin.flush();worker.communicate(timeout=5);q.require(worker.returncode==0,'Pinned worker did not close normally')
        return dict(item,workload=dict(work,elapsed_ns=work['finish_ns']-work['start_ns']),capture_integrity=not errors,capture_errors=errors,
            environment_exclusions=reasons,**environment,selected_resident_before_bytes=resident,selected_resident_after_bytes=resident_after,
            observer_and_calibration_setup_ns=startup,setup_excluded_from_endpoint=True,pinned_descriptor_lifetime_verified=True,
            content_checked=True,owned_programs_gone=True,validation=checked,before=before,after=after),stdout,log
    except BaseException as exc:
        # Collection stops on lifecycle/setup/content failures. Preserve the
        # partial schedule instead of retrying or treating it as exclusion.
        prefix=area/('failed-'+item['scenario']+'-'+str(item['pair'])+'-'+item['condition'])
        pilot.save(prefix.with_suffix('.json'),dict(item,error=str(exc),worker=work,validation=checked))
        prefix.with_suffix('.stdout').write_bytes(stdout);prefix.with_suffix('.log').write_bytes(log);raise
    finally:
        if trace:q.finish(trace);q.require(q.absent(ids),'Owned observer remains')
        if worker and worker.poll() is None:worker.kill();worker.communicate(timeout=5)
        os.close(fd)


def host(args):
    area=args.output.absolute();qualified=args.qualified.absolute();device=q.block_device(area.parent)
    q.require(device==q.block_device(Path('/')),'Different physical NVMe namespace')
    qos=Path('/sys/class/nvme/nvme0/power/pm_qos_latency_tolerance_us');q.require(qos.read_text().strip()=='5000','Drive policy differs')
    state,inventory=q.trace_state(),q.programs();reference,fixtures,expected,binaries=prepare(area,qualified)
    paths=set(reference['contract']['source_sha256'])|{'bench/measure_combined_wait_cost.py','analysis/combined_wait_cost.py','bench/measure_trace_overhead.py',
        'analysis/trace_overhead.py','tools/native_volume_lab.py','tools/native_trial_lab.py'}
    sources={n:q.digest(ROOT/n) for n in sorted(paths)};order=planned_order()
    contract=dict(CONTRACT,order=order,source_sha256=sources,qualified_reference_sha256=q.digest(qualified/'result.json'),
        copied_compiled_sha256=binaries,fixture_records=fixtures,worker_fnv64=expected,kernel=os.uname().release,
        btf_header_sha256=reference['extension']['btf_header_sha256'],frozen_before_collection=True,contract_fsynced=True,
        common_private_calibration_in_both_arms=True,private_target_evicted_after_calibration=True,observer_not_recompiled=True,
        off_arm_program_inventory_matches_original=True,progress_only_in_tmpfs=True,raw_output_deferred=True,
        capture_failures_not_environment_exclusions=True,global_cache_reset=False,production_defaults_changed=False)
    pilot.save(area/'contract.json',contract)
    with (area/'contract.json').open('rb') as stream:os.fsync(stream.fileno())
    dfd=os.open(area,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(dfd)
    finally:os.close(dfd)
    q.require(args.progress.parent==Path('/run') and re.fullmatch(r'bc250-combined-cost-[0-9a-f]{12}\.json',args.progress.name),'Invalid temporary progress target')
    pfd=os.open(args.progress,os.O_RDWR|os.O_NOFOLLOW);info=os.fstat(pfd)
    q.require(stat.S_ISREG(info.st_mode) and info.st_uid==0 and info.st_nlink==1,'Unowned progress file')
    rows=[];captures=[];retained=0
    try:
        with os.fdopen(pfd,'w') as progress:
            for index,item in enumerate(order):
                row,raw,log=trial(area,device,expected,inventory,item);rows.append(row);captures.append((raw,log));retained+=len(raw)+len(log)
                q.require(retained<=CONTRACT['maximum_retained_raw_bytes'],'Aggregate retained raw-byte bound')
                progress.seek(0);json.dump(dict(completed_trials=len(rows),total_trials=len(order),collection_live=True),progress);progress.truncate();progress.flush()
        for scenario in CONTRACT['scenarios']:
            for pair in range(CONTRACT['pairs_per_scenario']):
                group=[r for r in rows if r['scenario']==scenario and r['pair']==pair and not r['warmup']]
                policies={json.dumps(pilot.policy(r[phase]),sort_keys=True) for r in group for phase in ('before','after')}
                if len(policies)!=1:
                    for row in group:row['environment_exclusions'].append('cpu-policy-changed-within-pair')
    finally:
        pilot.save(area/'trials-private.json',rows)
        for index,(raw,log) in enumerate(captures):
            if raw:(area/('trace-%d-private.json'%index)).write_bytes(raw)
            (area/('trace-%d-loader-private.log'%index)).write_bytes(log)
        q.require(q.trace_state()==state and q.programs()==inventory and qos.read_text().strip()=='5000','Tracing/program/power state changed')
    for name,sha in sources.items():q.require(q.digest(ROOT/name)==sha,'Cost source changed')
    for name,sha in binaries.items():q.require(q.digest(area/name)==sha,'Copied binary changed')
    for name,record in fixtures.items():q.require(q.digest(area/name)==record['sha256']==q.digest(qualified/name),'Private/reference content changed')
    q.require(q.digest(qualified/'result.json')==contract['qualified_reference_sha256'],'Qualified result changed')
    result=dict(schema_version=1,kind='bc250-combined-wait-cost',collection_complete=True,contract=contract,summary=summarize(rows,contract),
        all_owned_programs_gone=True,global_trace_state_unchanged=True,unrelated_program_inventory_unchanged=True,
        private_and_reference_contents_unchanged=True,qualified_observer_binary_unchanged=True,retained_raw_bytes=retained,
        production_observer_installed=False,production_defaults_changed=False,global_cache_reset=False,
        historical_results_pooled=False,accelerator_gain_comparison=False,stage1_gate_passed=False)
    pilot.save(area/'result.json',result);print(json.dumps(result['summary']),flush=True)


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('step',choices=('run','_host'))
    for name in ('qualified','output'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--progress',type=Path);args=p.parse_args();q.require(sys.platform=='linux' and os.geteuid()==0,'Linux root required')
    if args.step=='_host':q.require(args.progress is not None,'Owned temporary progress required');host(args);return
    q.require(args.progress is None,'Progress target is created by the bounded launcher')
    unit='bc250-combined-cost-'+uuid.uuid4().hex[:12];progress=Path('/run')/(unit+'.json')
    fd=os.open(progress,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o644)
    with os.fdopen(fd,'w') as out:json.dump(dict(completed_trials=0,total_trials=len(planned_order()),collection_live=True),out)
    print(json.dumps(dict(unit=unit,progress=str(progress),total_trials=len(planned_order()))),flush=True)
    try:
        subprocess.run(['systemd-run','--quiet','--wait','--pipe','--collect','--unit='+unit,'--property=MemoryMax=2G','--property=MemorySwapMax=0',
            '--property=CPUQuota=200%','--property=TasksMax=128','--property=RuntimeMaxSec='+str(CONTRACT['parent_runtime_seconds']),'--property=KillMode=control-group',
            '/usr/bin/unshare','--mount','--propagation','private','/usr/bin/python3','-B',str(Path(__file__).resolve()),'_host',
            '--qualified',str(args.qualified),'--output',str(args.output),'--progress',str(progress)],check=True,timeout=CONTRACT['parent_runtime_seconds']+30)
    finally:progress.unlink(missing_ok=True)


if __name__=='__main__':main()
