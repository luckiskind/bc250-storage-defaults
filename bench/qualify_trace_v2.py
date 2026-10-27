#!/usr/bin/env python3
"""Native opt-in v2 provenance controls on new regular-file data only."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import select
import shutil
import signal
import struct
import subprocess
import sys
import time
import uuid
import qualify_request_trace as q
from qualify_request_lifecycle import type_shape
from request_trace_v2 import validate

ROOT=Path(__file__).resolve().parents[1]


def start(area,device,software=1,internal=1,duration=2,limit=200000):
    proc=subprocess.Popen([str(area/'request-trace-v2'),str(area/'request_trace_v2.bpf.o'),str(device),str(duration),str(limit),str(software),str(internal)],
        stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    os.set_blocking(proc.stderr.fileno(),False);log=b'';deadline=time.monotonic()+10
    try:
        while time.monotonic()<deadline:
            if select.select([proc.stderr],[],[],.1)[0]:
                log+=os.read(proc.stderr.fileno(),65536);q.require(len(log)<=2**20,'Loader diagnostic bound')
                for line in log.splitlines():
                    if line.startswith(b'BC250_TRACE2_READY '):
                        ids=json.loads(line.split(b' ',1)[1])['program_ids'];q.require(len(ids)==len(set(ids))==6,'Six distinct program IDs required')
                        return proc,ids,log
            q.require(proc.poll() is None,'V2 attach failed: '+log.decode(errors='replace')[-4000:])
        raise RuntimeError('V2 readiness timeout')
    except BaseException:
        proc.kill();stdout,stderr=proc.communicate(timeout=5);(area/'failed-start-private.log').write_bytes(log+stderr);raise


def build(area):
    names=('request_trace_v2.bpf.c','request_trace_v2.c','request_trace_v2.h','trace2_protocol.h','trace2_protocol_probe.c','direct_probe.c')
    for name in names:shutil.copyfile(ROOT/'bench'/name,area/name)
    with (area/'vmlinux.h').open('x') as out:
        subprocess.run(['bpftool','btf','dump','file','/sys/kernel/btf/vmlinux','format','c'],stdout=out,check=True,timeout=30)
    header=(area/'vmlinux.h').read_text()
    patterns=[r'typedef void \(\*btf_trace_block_rq_'+n+r'\)\(void \*, struct request \*\);' for n in ('insert','issue','requeue')]
    patterns.append(r'typedef void \(\*btf_trace_block_rq_complete\)\(void \*, struct request \*, blk_status_t, unsigned int\);')
    q.require(all(re.search(p,header) for p in patterns),'Raw callback ABI differs')
    q.require(re.search(r'__REQ_PREFLUSH\s*=\s*18\b',header) and re.search(r'REQ_OP_FLUSH\s*=\s*2\b',header),'Preflush/operation encoding differs')
    types_header=Path('/usr/lib/modules')/os.uname().release/'build/include/linux/blk_types.h'
    q.require(re.search(r'#define\s+REQ_OP_BITS\s+8\b',types_header.read_text())
        and re.search(r'REQ_OP_READ\s*=\s*0\b',header) and re.search(r'REQ_OP_WRITE\s*=\s*1\b',header),'Read/write operation mask differs')
    raw=q.command('bpftool','-j','btf','dump','file','/sys/kernel/btf/vmlinux','format','raw',timeout=30)
    q.require(len(raw)<=128*2**20,'BTF bound');types={v['id']:v for v in json.loads(raw)['types']}
    fn=next(v for v in types.values() if v['kind']=='FUNC' and v['name']=='blk_insert_flush');proto=types[fn['type_id']]
    q.require(proto['kind']=='FUNC_PROTO' and len(proto['params'])==1,'Flush function prototype differs')
    ret=type_shape(types,proto['ret_type_id']);ptr=type_shape(types,proto['params'][0]['type_id'])
    q.require(ret['kind']=='INT' and ret['name'] in ('bool','_Bool') and ret['size']==1 and ptr['kind']=='PTR' and type_shape(types,ptr['type_id'])['name']=='request','Flush argument/return differs')
    del types,raw
    commands=[['clang','-g','-O2','-Wall','-Werror','-target','bpf','-mcpu=v3','-D__TARGET_ARCH_x86','-I.','-c','request_trace_v2.bpf.c','-o','request_trace_v2.bpf.o'],
        ['gcc','-O2','-g','-Wall','-Wextra','-Werror','request_trace_v2.c','-o','request-trace-v2','-lbpf','-lelf','-lz'],
        ['gcc','-O2','-g','-Wall','-Wextra','-Werror','trace2_protocol_probe.c','-o','trace2-protocol-probe','-pthread'],
        ['gcc','-O2','-g','-Wall','-Wextra','-Werror','direct_probe.c','-o','direct-probe','-pthread']]
    for index,cmd in enumerate(commands):
        with (area/f'build-{index}.log').open('x') as stream:subprocess.run(cmd,cwd=area,stdout=stream,stderr=subprocess.STDOUT,check=True,timeout=60)
    result=json.loads(q.command(area/'trace2-protocol-probe',timeout=30));q.require(result['passed'],'Atomic protocol native control failed')
    return names,result


def capture(area,device,label,work,software=1,internal=1,limit=200000,interrupt=False,stall=False):
    fixture=area/'fixture.bin'
    if work[0]=='read':q.require(q.residency(fixture,evict=True)==0,'New read fixture not data-cold')
    proc,ids,log=start(area,device,software,internal,duration=10 if (stall or interrupt) else 2,limit=limit)
    try:
        if stall:proc.send_signal(signal.SIGSTOP)
        if work[0]=='read':
            pattern=work[3] if len(work)>3 else ('same' if stall else 'stride')
            worker=json.loads(q.command(area/'direct-probe',fixture,work[1],work[2],pattern,timeout=20))
            q.require(worker['passed'] and q.residency(fixture)==0,'Read control failed/populated cache')
        else:
            fd=os.open(fixture,os.O_WRONLY|os.O_NOFOLLOW);markers=[]
            try:
                for index in range(8):
                    started=time.monotonic_ns();q.require(os.pwrite(fd,os.urandom(4096),index*4096)==4096,'Short private update');os.fdatasync(fd)
                    markers.append((started,time.monotonic_ns()))
            finally:os.close(fd)
            worker=dict(passed=True,updates=8,logical_written_bytes=32768,start_monotonic_ns=markers[0][0],finish_monotonic_ns=markers[-1][1])
        if stall:proc.send_signal(signal.SIGCONT)
        if interrupt:proc.send_signal(signal.SIGINT)
        stdout,stderr=proc.communicate(timeout=15);log+=stderr
        (area/(label+'-raw-private.json')).write_bytes(stdout);(area/(label+'-worker-private.json')).write_text(json.dumps(worker,indent=2)+'\n')
        (area/(label+'-loader-private.log')).write_bytes(log)
        q.require(proc.returncode==0 and q.absent(ids),'V2 failed or left owned programs');raw=json.loads(stdout);checked=validate(raw)
        if limit==200000 and not interrupt:q.require(raw['start_ns']<=worker['start_monotonic_ns']<worker['finish_monotonic_ns']<=raw['finish_ns'],'Worker outside capture')
        window=[r for r in raw['records'] if r['issue_ns'] and worker['start_monotonic_ns']<=r['issue_ns']<=r['complete_ns']<=worker['finish_monotonic_ns']]
        if limit<200000:q.require(raw['limit_reached'] and not checked['transport_complete'] and any(r['operation']==0 for r in raw['records']),'Cap not explicit or preceded every read')
        elif stall:q.require(checked['kernel_counters']['ring_lost']>0 and not checked['transport_complete'],'Ring loss not demonstrated')
        elif interrupt:q.require(not checked['transport_complete'] and raw['interrupted'] and checked['read_completed_bytes']==worker['read_bytes'],'Interrupt lost known data or hidden')
        elif work[0]=='read':
            q.require(checked['stream_quality_passed'] and sum(r['operation']==0 for r in window)==work[1]*work[2]
                and sum(r['completed_bytes'] for r in window if r['operation']==0)==worker['read_bytes'],'Known reads/quality incomplete')
        elif not software:q.require(not checked['stream_quality_passed'] and checked['kernel_counters']['orphan_complete']>=8 and not checked['proven_software_sequences'],'Disabled software proof was silently accepted')
        elif not internal:q.require(not checked['stream_quality_passed'] and checked['unresolved_records']>=8 and checked['proven_software_sequences']>=8 and not checked['proven_internal_flushes'],'Disabled internal proof was silently accepted')
        else:q.require(checked['stream_quality_passed'] and checked['proven_internal_flushes']>=8 and checked['proven_software_sequences']>=8,'Expected independent flush classes not proven')
        return dict(case=label,passed=True,validation=checked,events=raw['events'],right_censored_requests=raw['right_censored_requests'],return_contexts=raw['return_contexts'],
            known_read_bytes=worker.get('read_bytes',0),owned_programs_gone=True,software_tracking_enabled=bool(software),internal_tracking_enabled=bool(internal),
            intended_incomplete=bool(interrupt or limit<200000),intentional_proof_removal=not bool(software and internal))
    finally:
        if stall and proc.poll() is None:proc.send_signal(signal.SIGCONT)
        q.finish(proc)


def host(args):
    q.native.confined();area=args.output.absolute();q.native.private_area(area,creating=True);q.native.host_space(area.parent)
    device=q.block_device(area.parent);q.require(device==q.block_device(Path('/')),'Different physical device')
    qos=Path('/sys/class/nvme/nvme0/power/pm_qos_latency_tolerance_us');q.require(qos.read_text().strip()=='5000','Policy differs')
    before=q.trace_state();inventory=q.programs();area.mkdir(mode=0o700);names,protocol=build(area)
    sources={'bench/'+n:q.digest(ROOT/'bench'/n) for n in names}
    for name in ('bench/qualify_trace_v2.py','bench/qualify_request_trace.py','bench/qualify_request_lifecycle.py','analysis/request_trace_v2.py'):sources[name]=q.digest(ROOT/name)
    contract=dict(schema_version=1,kernel=os.uname().release,source_sha256=sources,btf_header_sha256=q.digest(area/'vmlinux.h'),
        identity_map_limit=8192,return_context_map_limit=8192,ring_bytes=4*2**20,max_saved_records=200000,fixture_bytes=64*2**20,
        raw_and_flush_ABI_verified=True,original_v1_results_reinterpreted=False,performance_result=False,
        kernel_completion_before_return_exercised=False,host_atomic_protocol_control=protocol)
    (area/'contract.json').write_text(json.dumps(contract,indent=2)+'\n')
    fd=os.open(area/'fixture.bin',os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        flags=bytearray(8);fcntl.ioctl(fd,0x80086601,flags,True);fcntl.ioctl(fd,0x40086602,struct.pack('=Q',struct.unpack('=Q',flags)[0]|0x800000));fcntl.ioctl(fd,0x80086601,flags,True)
        q.require(struct.unpack('=Q',flags)[0]&0x800000,'NOCOW not established')
        for _ in range(64):
            data=os.urandom(2**20);position=0
            while position<len(data):position+=os.write(fd,data[position:])
        os.fsync(fd)
    finally:os.close(fd)
    cases=[]
    plan=[('serial-read',('read',1,2048),{}),('concurrent-read',('read',4,2048,'same'),{}),
        ('fsync-positive-1',('write',),{}),('software-proof-disabled',('write',),dict(software=0)),
        ('internal-proof-disabled',('write',),dict(internal=0)),('fsync-positive-2',('write',),{}),
        ('record-cap',('read',1,1024),dict(limit=16)),('early-interrupt',('read',1,8),dict(interrupt=True)),
        ('consumer-stalled',('read',4,30000),dict(stall=True,interrupt=True))]
    try:
        for label,work,options in plan:
            value=capture(area,device,label,work,**options);cases.append(value);print(json.dumps(dict(case=label,passed=True,events=value['events'])),flush=True)
        proc,ids,log=start(area,device,duration=10)
        try:proc.kill();stdout,stderr=proc.communicate(timeout=5);q.require(proc.returncode==-signal.SIGKILL and q.absent(ids),'Forced exit failed cleanup')
        finally:q.finish(proc)
        cases.append(dict(case='forced-exit',passed=True,owned_programs_gone=True))
    finally:q.require(q.trace_state()==before and qos.read_text().strip()=='5000','Global trace/power changed')
    q.require(q.programs()==inventory,'Unrelated program inventory changed')
    q.require(all(q.digest(ROOT/name)==sha for name,sha in sources.items()),'Source changed during qualification')
    result=dict(contract,passed=True,cases=cases,case_count=len(cases),all_owned_programs_gone=True,global_trace_state_unchanged=True,
        unrelated_program_inventory_unchanged=True,nvme_qos_us=5000,overhead_qualified=False,foreground_attribution_qualified=False,
        error_partial_requeue_paths_qualified=False,compiled_sha256={n:q.digest(area/n) for n in ('request_trace_v2.bpf.o','request-trace-v2','direct-probe','trace2-protocol-probe')},completed_unix=time.time())
    (area/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(dict(passed=True,cases=len(cases))),flush=True)


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('step',choices=('run','_host'));parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    q.require(sys.platform=='linux' and os.geteuid()==0,'Linux root required')
    if args.step=='_host':host(args);return
    unit='bc250-trace2-'+uuid.uuid4().hex[:12]
    subprocess.run(['systemd-run','--quiet','--wait','--pipe','--collect','--unit='+unit,'--property=MemoryMax=2G','--property=MemorySwapMax=0','--property=CPUQuota=200%',
        '--property=TasksMax=128','--property=RuntimeMaxSec=300','--property=KillMode=control-group','/usr/bin/unshare','--mount','--propagation','private',
        '/usr/bin/python3','-B',str(Path(__file__).resolve()),'_host','--output',str(args.output)],check=True,timeout=330)


if __name__=='__main__':main()
