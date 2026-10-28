#!/usr/bin/env python3
"""Randomized paired observer calibration using a frozen private read fixture.

Only the new fixture is copied/evicted. Drive/CPU policy, global tracing and
working data remain unchanged. The contract is saved before collecting timings.
"""
import argparse
import fcntl
import json
import os
from pathlib import Path
import random
import resource
import shutil
import stat
import struct
import subprocess
import sys
import time
import uuid

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'));sys.path.insert(0,str(ROOT/'analysis'))
import native_trial_lab as ownership
import native_volume_lab as native
import qualify_request_trace as q
from request_trace import validate
from trace_overhead import summarize

CONTRACT=dict(version=1,seed=250,pairs_per_scenario=8,minimum_valid_pairs=6,
    scenarios={'serial-strided':dict(threads=1,operations=8192,pattern='stride'),
               'concurrent-same-location':dict(threads=4,operations=2048,pattern='same')},
    warmup_pairs_per_scenario=1,point_limit=.03,upper_interval_limit=.05,
    background_cpu_fraction_max=.10,minimum_available_bytes=2*2**30,
    additional_io_bytes_max=128*1024,pre_workload_device_bytes_max=128*1024,post_setup_idle_seconds=.25,
    scope='Exploratory control screen, not an application-overhead or Stage 1 gate verdict')


def require(value,message):
    if not value:raise RuntimeError(message)


def save(path,value):
    with path.open('x') as stream:json.dump(value,stream,indent=2);stream.write('\n')


def pressure(name):
    return {line.split()[0]:int(next(token.split('=')[1] for token in line.split() if token.startswith('total=')))
        for line in Path('/proc/pressure',name).read_text().splitlines()}


def environment(device):
    memory={line.split(':')[0]:int(line.split()[1])*1024 for line in Path('/proc/meminfo').read_text().splitlines()
        if line.startswith(('MemAvailable:','Dirty:','Writeback:'))}
    policies={}
    for p in sorted(Path('/sys/devices/system/cpu/cpufreq').glob('policy*')):
        policies[p.name]={name:(p/name).read_text().strip() for name in
            ('scaling_governor','scaling_min_freq','scaling_max_freq','scaling_cur_freq') if (p/name).exists()}
    temperatures={}
    for p in Path('/sys/class/hwmon').glob('hwmon*'):
        if (p/'name').exists():
            temperatures[p.name+':'+(p/'name').read_text().strip()]={t.name:int(t.read_text()) for t in p.glob('temp*_input')}
    group=next(row.split('::')[1] for row in Path('/proc/self/cgroup').read_text().splitlines() if row.startswith('0::'))
    return dict(monotonic_ns=time.monotonic_ns(),cpu=list(map(int,Path('/proc/stat').read_text().splitlines()[0].split()[1:])),
        disk=list(map(int,(Path('/sys/class/block')/device.name/'stat').read_text().split())),memory=memory,
        pressure={name:pressure(name) for name in ('cpu','io','memory')},cpu_policies=policies,temperatures_millicelsius=temperatures,
        cgroup_cpu_stat=(Path('/sys/fs/cgroup')/group.lstrip('/')/'cpu.stat').read_text())


def policy(snapshot):
    return {name:{key:value for key,value in row.items() if key!='scaling_cur_freq'}
        for name,row in snapshot['cpu_policies'].items()}


def cpu_seconds():
    value=resource.getrusage(resource.RUSAGE_CHILDREN);return value.ru_utime+value.ru_stime


def trial(area,device,scenario,pair,condition,warmup):
    require(q.residency(area/'fixture.bin',evict=True)==0,'Private fixture not cache-cold')
    parameters=CONTRACT['scenarios'][scenario];proc=None;ids=[];startup=None;log=b'';trace=None
    condition_start=time.monotonic_ns();work=None;stdout=b''
    try:
        if condition=='on':
            started=time.monotonic_ns();proc,ids,log=q.start(area,device,2,200000)
            startup=time.monotonic_ns()-started
        else:q.programs()  # Same inventory helper before the common idle interval.
        quiet0=environment(device);time.sleep(CONTRACT['post_setup_idle_seconds']);before=environment(device)
        delta=[b-a for a,b in zip(quiet0['cpu'],before['cpu'])]
        total=sum(delta[:8]);idle=delta[3]+delta[4]
        cpu_fraction=(total-idle)/total if total else 0
        before_child=cpu_seconds()
        work=json.loads(q.command(area/'direct-probe',area/'fixture.bin',parameters['threads'],parameters['operations'],parameters['pattern'],timeout=15))
        worker_cpu=cpu_seconds()-before_child;after=environment(device)
        require(work['passed'] and work['operations']==parameters['threads']*parameters['operations'],'Read workload failed')
        resident=q.residency(area/'fixture.bin');require(resident==0,'Read control populated private page cache')
        integrity=True;validation=None;observer_cpu=None
        if proc:
            before_reap=cpu_seconds();stdout,stderr=proc.communicate(timeout=10);observer_cpu=cpu_seconds()-before_reap;log+=stderr
            require(proc.returncode==0,'Observer failed during calibration')
            trace=json.loads(stdout);validation=validate(trace)
            integrity=bool(validation['transport_complete'] and not trace['flagged_events'] and not trace['right_censored_requests']
                and all(v==0 for k,v in validation['kernel_counters'].items() if k not in ('insert','issue','final'))
                and trace['read_completed_bytes']>=work['read_bytes']
                and trace['start_monotonic_ns']<=work['start_monotonic_ns']<work['finish_monotonic_ns']
                <=trace['start_monotonic_ns']+trace['elapsed_ns'])
            require(q.absent(ids),'Owned observer programs remain after exit')
        else:
            # Balance each condition's overall slot; workload elapsed time is
            # always the worker's own barrier-to-join interval, not this delay.
            remaining=2-(time.monotonic_ns()-condition_start)/1e9
            if remaining>0:time.sleep(remaining)
        read=(after['disk'][2]-before['disk'][2])*512;written=(after['disk'][6]-before['disk'][6])*512
        extra=max(0,read-work['read_bytes'])+written;reasons=[]
        pre_io=((before['disk'][2]-quiet0['disk'][2])+(before['disk'][6]-quiet0['disk'][6]))*512
        if cpu_fraction>CONTRACT['background_cpu_fraction_max']:reasons.append('pre-workload-cpu-busy')
        if pre_io>CONTRACT['pre_workload_device_bytes_max']:reasons.append('pre-workload-device-busy')
        if min(before['memory']['MemAvailable'],after['memory']['MemAvailable'])<CONTRACT['minimum_available_bytes']:reasons.append('low-available-memory')
        if extra>CONTRACT['additional_io_bytes_max']:reasons.append('additional-device-io')
        if read<work['read_bytes']:integrity=False
        if policy(before)!=policy(after):reasons.append('cpu-policy-changed')
        record=dict(scenario=scenario,pair=pair,condition=condition,warmup=warmup,workload=work,
            environment_exclusions=reasons,capture_integrity=integrity,
            observed_read_bytes=read,observed_write_bytes=written,additional_io_bytes=extra,
            pre_workload_cpu_fraction=cpu_fraction,pre_workload_device_bytes=pre_io,fixture_resident_before_bytes=0,fixture_resident_after_bytes=resident,
            worker_process_cpu_seconds=worker_cpu,observer_process_cpu_seconds=observer_cpu,
            observer_startup_ns=startup,observer_cpu_excludes_kernel_callback_cost=True,
            before=before,after=after,validation=validation)
        return record,trace,log
    except BaseException as exc:
        if proc:q.finish(proc)
        prefix=area/('failed-'+scenario+'-'+str(pair)+'-'+condition+'-'+str(int(warmup)))
        save(prefix.with_suffix('.json'),dict(error=str(exc),workload=work,trace=trace,observer_log=log.decode(errors='replace')))
        prefix.with_suffix('.stdout').write_bytes(stdout)
        raise
    finally:
        if proc:q.finish(proc)


def host(args):
    native.confined();area=args.output.absolute();source=args.qualified.absolute()
    native.private_area(source);native.private_area(area,creating=True);native.host_space(area.parent)
    reference=ownership.safe_json(source/'result.json')
    require(reference['passed'] and reference['case_count']==5 and reference['all_owned_programs_gone'],'Use a passing qualification')
    require(os.uname().release==reference['kernel'],'Kernel changed')
    for name,sha in reference['source_sha256'].items():require(q.digest(ROOT/name)==sha,'Qualified source changed: '+name)
    device=q.block_device(area.parent);require(device==q.block_device(Path('/')),'Fixture uses a different physical namespace')
    ns=(Path('/sys/class/block')/device.name).resolve(strict=True);linked=(ns/'device').resolve(strict=True)
    controllers=[p for p in Path('/sys/class/nvme').iterdir() if p.resolve() in ns.parents or p.resolve()==linked]
    require(len(controllers)==1,'Ambiguous controller relationship');qos=controllers[0]/'power/pm_qos_latency_tolerance_us'
    require(qos.read_text().strip()=='5000','Actual drive policy changed')
    before_trace=q.trace_state();before_programs=q.programs();area.mkdir(mode=0o700)
    for name,sha in reference['compiled_sha256'].items():
        require(q.digest(source/name)==sha,'Qualified binary changed');shutil.copyfile(source/name,area/name)
        (area/name).chmod(0o700 if name!='request_trace.bpf.o' else 0o600)
    original=source/'fixture.bin';info=original.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid==0 and info.st_nlink==1 and info.st_size==64*2**20,'Unsafe source fixture')
    source_sha=q.digest(original);fixture=area/'fixture.bin'
    fd=os.open(fixture,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        before_inode=os.fstat(fd);flags=bytearray(8);fcntl.ioctl(fd,0x80086601,flags,True)
        fcntl.ioctl(fd,0x40086602,struct.pack('=Q',struct.unpack('=Q',flags)[0]|0x800000))
        fcntl.ioctl(fd,0x80086601,flags,True);require(struct.unpack('=Q',flags)[0]&0x800000,'Fixture NOCOW not established')
    finally:os.close(fd)
    q.command('cp','--reflink=never','--sparse=never',original,fixture)
    current=fixture.lstat();require((current.st_dev,current.st_ino)==(before_inode.st_dev,before_inode.st_ino),'Fixture inode replaced')
    fd=os.open(fixture,os.O_RDONLY|os.O_NOFOLLOW)
    try:require(not any(flags&(8|0x2000) for _,_,flags in native.repack.extents(fd,current.st_size)),'Shared/encoded fixture extents')
    finally:os.close(fd)
    require(q.digest(fixture)==source_sha,'Copied fixture content differs')
    q.command('sync','-f',fixture)
    rng=random.Random(CONTRACT['seed']);order=[]
    for scenario in CONTRACT['scenarios']:
        order += [dict(scenario=scenario,pair=-1,condition=c,warmup=True) for c in ('off','on')]
        orientations=['on','off']*(CONTRACT['pairs_per_scenario']//2);rng.shuffle(orientations)
        for pair,first in enumerate(orientations):
            order += [dict(scenario=scenario,pair=pair,condition=c,warmup=False) for c in (first,'off' if first=='on' else 'on')]
    save(area/'contract.json',dict(CONTRACT,order=order,fixture_sha256=source_sha,qualified_report_sha256=q.digest(source/'result.json'),
        frozen_unix=time.time(),source_sha256={'bench/measure_trace_overhead.py':q.digest(Path(__file__)),
            'analysis/trace_overhead.py':q.digest(ROOT/'analysis/trace_overhead.py')}))
    rows=[];raw=[]
    try:
        for item in order:
            row,trace,log=trial(area,device,**item);rows.append(row);raw.append((trace,log))
            print(json.dumps(dict(scenario=row['scenario'],pair=row['pair'],condition=row['condition'],warmup=row['warmup'],
                elapsed_ms=row['workload']['elapsed_ns']/1e6,exclusions=row['environment_exclusions'],capture_integrity=row['capture_integrity'])),flush=True)
    finally:
        # Flush evidence only after collection, avoiding earlier trace-file
        # writeback contaminating a later pair's measured device traffic.
        save(area/'trials-private.json',rows)
        for i,(trace,log) in enumerate(raw):
            if trace is not None:save(area/('trace-'+str(i)+'-private.json'),trace)
            (area/('trace-'+str(i)+'.loader.log')).write_bytes(log)
        require(q.trace_state()==before_trace and qos.read_text().strip()=='5000','Working trace/power state changed')
    summary=summarize(rows,CONTRACT)
    require(q.digest(fixture)==source_sha==q.digest(original),'Fixture changed')
    result=dict(schema_version=1,collection_complete=True,contract=CONTRACT,summary=summary,
        source_sha256={'bench/measure_trace_overhead.py':q.digest(Path(__file__)),
            'analysis/trace_overhead.py':q.digest(ROOT/'analysis/trace_overhead.py')},
        qualification_source_sha256=reference['source_sha256'],compiled_sha256=reference['compiled_sha256'],
        observer_and_workload_binaries_unchanged=True,fixture_unchanged=True,private_fixture_cache_eviction_only=True,
        global_trace_state_unchanged=True,drive_policy_unchanged=True,nvme_qos_us=5000,
        unrelated_program_inventory_unchanged=q.programs()==before_programs,observer_programs_gone=True,
        measured_conditions='Two synthetic direct-read controls on this kernel, 2 CPU-equivalent bounded process group',
        new_accelerator_throughput_comparison_performed=False,completed_unix=time.time())
    save(area/'result.json',result);print(json.dumps(summary),flush=True)


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('step',choices=('run','_host'))
    parser.add_argument('--qualified',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();require(sys.platform=='linux' and os.geteuid()==0,'Requires Linux root')
    if args.step=='_host':host(args);return
    unit='bc250-trace-overhead-'+uuid.uuid4().hex[:12];print(json.dumps(dict(parent_unit=unit)),flush=True)
    subprocess.run(['systemd-run','--quiet','--wait','--pipe','--collect','--unit='+unit,
        '--property=MemoryMax=2G','--property=MemoryHigh=1536M','--property=MemorySwapMax=0','--property=CPUQuota=200%',
        '--property=RuntimeMaxSec=300','--property=KillMode=control-group','--property=TimeoutStopSec=15',
        '/usr/bin/unshare','--mount','--propagation','private','/usr/bin/python3',str(Path(__file__).resolve()),'_host',
        '--qualified',str(args.qualified),'--output',str(args.output)],check=True,timeout=330)


if __name__=='__main__':main()
