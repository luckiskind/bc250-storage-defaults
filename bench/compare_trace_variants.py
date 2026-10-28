#!/usr/bin/env python3
"""Freeze one off/raw/batched experiment using one physical read fixture.

24 balanced randomized blocks, unchanged 3%/5% overhead screen. Keep all
trials, failed captures and exclusions. Never install an observer or reset quotas.
"""
import argparse
import copy
import fcntl
import itertools
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
import qualify_batched_trace as variant
from trace_variants import summarize

q=pilot.q
ROOT=Path(__file__).resolve().parents[1]
CONTRACT=copy.deepcopy(pilot.CONTRACT)
CONTRACT.update(version=3,seed=251,blocks=24,minimum_valid_blocks=20,
    scenarios={'serial-strided':CONTRACT['scenarios']['serial-strided']},
    conditions=['off','raw','batched'],
    ordering='All six permutations, four blocks each; randomized before collection',
    exclusion_scope='Entire three-condition block; strict whole-capture flags retained',
    scope='Exploratory synthetic serial observer comparison; not application overhead or an accelerator gain')
CONTRACT.pop('pairs_per_scenario');CONTRACT.pop('minimum_valid_pairs')


def prepare(area,baseline,batched):
    q.native.confined();q.native.private_area(area,creating=True);q.native.private_area(baseline);q.native.private_area(batched)
    q.native.host_space(area.parent)
    original=pilot.ownership.safe_json(baseline/'result.json')
    candidate=pilot.ownership.safe_json(batched/'result.json')
    q.require(original['passed'] and original['case_count']==5,'Original qualification required')
    q.require(candidate['passed'] and candidate['case_count']==7 and candidate['known_read_window_accounting_passed'],
        'Seven-case batched qualification required')
    q.require(candidate['variant']=='batched-no-wakeup-50ms','Unexpected variant')
    q.require(os.uname().release==original['kernel']==candidate['kernel'],'Qualified kernel changed')
    for report in (original,candidate):
        for name,value in report['source_sha256'].items():q.require(q.digest(ROOT/name)==value,'Qualified source changed')
    q.require(candidate['driver_sha256']==q.digest(ROOT/'bench/qualify_batched_trace.py'),'Variant driver changed')
    for name,value in candidate['derived_source_sha256'].items():
        q.require(q.digest(batched/Path(name).name)==value,'Derived candidate source changed')
    area.mkdir(mode=0o700)
    for label,source,report in [('raw',baseline,original),('batched',batched,candidate)]:
        (area/label).mkdir(mode=0o700)
        for name,value in report['compiled_sha256'].items():
            q.require(q.digest(source/name)==value,'Qualified binary changed')
            shutil.copyfile(source/name,area/label/name);(area/label/name).chmod(0o700 if name!='request_trace.bpf.o' else 0o600)
    shutil.copyfile(area/'raw/direct-probe',area/'direct-probe');(area/'direct-probe').chmod(0o700)
    source=baseline/'fixture.bin';info=source.lstat()
    q.require(stat.S_ISREG(info.st_mode) and info.st_uid==0 and info.st_nlink==1 and info.st_size==64*2**20,'Unsafe source fixture')
    fixture=area/'fixture.bin';fd=os.open(fixture,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        inode=os.fstat(fd);flags=bytearray(8);fcntl.ioctl(fd,0x80086601,flags,True)
        fcntl.ioctl(fd,0x40086602,struct.pack('=Q',struct.unpack('=Q',flags)[0]|0x800000))
        fcntl.ioctl(fd,0x80086601,flags,True);q.require(struct.unpack('=Q',flags)[0]&0x800000,'NOCOW not set')
    finally:os.close(fd)
    q.command('cp','--reflink=never','--sparse=never',source,fixture)
    now=fixture.lstat();q.require((now.st_dev,now.st_ino)==(inode.st_dev,inode.st_ino),'Fixture replaced')
    fd=os.open(fixture,os.O_RDONLY|os.O_NOFOLLOW)
    try:q.require(not any(flags&(8|0x2000) for _,_,flags in q.native.repack.extents(fd,now.st_size)),'Shared/encoded fixture')
    finally:os.close(fd)
    sha=q.digest(source);q.require(q.digest(fixture)==sha,'Fixture contents differ');q.command('sync','-f',fixture)
    return original,candidate,sha


def one(area,device,condition,block,warmup):
    original_start=q.start
    def start(_area,*args):return original_start(area/condition,*args)
    try:
        if condition!='off':q.start=start
        row,trace,log=pilot.trial(area,device,'serial-strided',block,'off' if condition=='off' else 'on',warmup)
        row['condition']=condition
        return row,trace,log
    finally:q.start=original_start


def host(args):
    area=args.output.absolute();baseline=args.original.absolute();batched=args.batched.absolute()
    device=q.block_device(area.parent);q.require(device==q.block_device(Path('/')),'Different physical namespace')
    ns=(Path('/sys/class/block')/device.name).resolve(strict=True);linked=(ns/'device').resolve(strict=True)
    controllers=[p for p in Path('/sys/class/nvme').iterdir() if p.resolve() in ns.parents or p.resolve()==linked]
    q.require(len(controllers)==1,'Ambiguous controller');qos=controllers[0]/'power/pm_qos_latency_tolerance_us'
    q.require(qos.read_text().strip()=='5000','Drive policy changed')
    before_trace=q.trace_state();before_programs=q.programs()
    original,candidate,fixture_sha=prepare(area,baseline,batched)
    pilot.CONTRACT=CONTRACT
    orders=list(itertools.permutations(CONTRACT['conditions']))*4
    random.Random(CONTRACT['seed']).shuffle(orders)
    order=[dict(block=-1,condition=c,warmup=True) for c in CONTRACT['conditions']]
    order += [dict(block=i,condition=c,warmup=False) for i,sequence in enumerate(orders) for c in sequence]
    sources={name:q.digest(ROOT/name) for name in ('bench/compare_trace_variants.py','analysis/trace_variants.py',
        'bench/measure_trace_overhead.py','analysis/trace_overhead.py','bench/qualify_batched_trace.py')}
    contract=dict(CONTRACT,order=order,fixture_sha256=fixture_sha,one_physical_fixture_for_all_conditions=True,
        original_qualification_sha256=q.digest(baseline/'result.json'),batched_qualification_sha256=q.digest(batched/'result.json'),
        source_sha256=sources,original_compiled_sha256=original['compiled_sha256'],
        batched_compiled_sha256=candidate['compiled_sha256'],frozen_unix=time.time())
    pilot.save(area/'contract.json',contract)
    rows=[];raw=[]
    try:
        for item in order:
            row,trace,log=one(area,device,**item);rows.append(row);raw.append((trace,log))
            print(json.dumps(dict(block=row['pair'],condition=row['condition'],warmup=row['warmup'],
                elapsed_ms=row['workload']['elapsed_ns']/1e6,exclusions=row['environment_exclusions'],
                capture_integrity=row['capture_integrity'])),flush=True)
        for block in range(CONTRACT['blocks']):
            group=[r for r in rows if r['pair']==block and not r['warmup']]
            policies={json.dumps(pilot.policy(r[field]),sort_keys=True) for r in group for field in ('before','after')}
            if len(policies)!=1:
                for row in group:row['environment_exclusions'].append('cpu-policy-changed-within-block')
    finally:
        pilot.save(area/'trials-private.json',rows)
        for i,(trace,log) in enumerate(raw):
            if trace is not None:pilot.save(area/('trace-'+str(i)+'-private.json'),trace)
            (area/('trace-'+str(i)+'.loader.log')).write_bytes(log)
        q.require(q.trace_state()==before_trace and qos.read_text().strip()=='5000','Working trace/power state changed')
    q.require(q.digest(area/'fixture.bin')==fixture_sha==q.digest(baseline/'fixture.bin'),'Fixture content changed')
    q.require(q.programs()==before_programs,'Unrelated observer inventory changed')
    q.require(all(q.digest(ROOT/name)==value for name,value in sources.items()),'Experiment source changed')
    result=dict(schema_version=1,collection_complete=True,contract=contract,summary=summarize(rows,CONTRACT),
        fixture_unchanged=True,one_physical_fixture_for_all_conditions=True,
        workload_binary_unchanged=True,all_owned_programs_gone=True,unrelated_program_inventory_unchanged=True,
        global_trace_state_unchanged=True,drive_policy_unchanged=True,nvme_qos_us=5000,
        global_page_cache_reset_performed=False,private_fixture_eviction_only=True,
        production_observer_enabled=False,new_accelerator_throughput_comparison_performed=False,completed_unix=time.time())
    pilot.save(area/'result.json',result);print(json.dumps(result['summary']),flush=True)


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('step',choices=('run','_host'))
    parser.add_argument('--original',type=Path,required=True);parser.add_argument('--batched',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    q.require(sys.platform=='linux' and os.geteuid()==0,'Requires Linux root')
    if args.step=='_host':host(args);return
    unit='bc250-trace-variants-'+uuid.uuid4().hex[:12];print(json.dumps(dict(parent_unit=unit)),flush=True)
    subprocess.run(['systemd-run','--quiet','--wait','--pipe','--collect','--unit='+unit,
        '--property=MemoryMax=2G','--property=MemoryHigh=1536M','--property=MemorySwapMax=0','--property=CPUQuota=200%',
        '--property=RuntimeMaxSec=300','--property=KillMode=control-group','--property=TimeoutStopSec=15',
        '/usr/bin/unshare','--mount','--propagation','private','/usr/bin/python3',str(Path(__file__).resolve()),'_host',
        '--original',str(args.original),'--batched',str(args.batched),'--output',str(args.output)],check=True,timeout=330)


if __name__=='__main__':main()
