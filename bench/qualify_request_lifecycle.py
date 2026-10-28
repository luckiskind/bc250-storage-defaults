#!/usr/bin/env python3
"""Diagnose flush callbacks using six temporary read-only BPF programs.

Writes only a new 8 MiB regular fixture and eight 4 KiB updates per fsync case.
No global cache reset, device flush ioctl, device formatting or policy change.
This does not replace the frozen timing observer or reclassify its failures.
"""
import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import select
import shutil
import struct
import subprocess
import sys
import time
import uuid

import qualify_request_trace as q

ROOT=Path(__file__).resolve().parents[1]


def start(area,device):
    proc=subprocess.Popen([str(area/'request-lifecycle'),str(area/'request_lifecycle.bpf.o'),str(device),'3','50000'],
        stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    os.set_blocking(proc.stderr.fileno(),False);log=b'';deadline=time.monotonic()+10
    try:
        while time.monotonic()<deadline:
            if select.select([proc.stderr],[],[],.1)[0]:
                log+=os.read(proc.stderr.fileno(),65536);q.require(len(log)<=2**20,'Loader diagnostics bound')
                for line in log.splitlines():
                    if line.startswith(b'BC250_LIFECYCLE_READY '):
                        ids=json.loads(line.split(b' ',1)[1])['program_ids']
                        q.require(len(ids)==len(set(ids))==6,'Six distinct owned programs required');return proc,ids,log
            q.require(proc.poll() is None,'Lifecycle attachment failed: '+log.decode(errors='replace')[-4000:])
        raise RuntimeError('Lifecycle readiness timeout')
    except BaseException:
        proc.kill();proc.communicate(timeout=5);(area/'failed-start-private.log').write_bytes(log);raise


def type_shape(types,index):
    value=types[index]
    while value['kind'] in ('TYPEDEF','CONST','VOLATILE','RESTRICT','TYPE_TAG'):
        value=types[value['type_id']]
    return value


def host(args):
    q.native.confined();area=args.output.absolute();q.native.private_area(area,creating=True);q.native.host_space(area.parent)
    device=q.block_device(area.parent);q.require(device==q.block_device(Path('/')),'Wrong observed NVMe mapping')
    qos=Path('/sys/class/nvme/nvme0/power/pm_qos_latency_tolerance_us');q.require(qos.read_text().strip()=='5000','Drive policy changed')
    before=q.trace_state();programs=q.programs();area.mkdir(mode=0o700)
    names=('request_lifecycle.bpf.c','request_lifecycle.c','request_lifecycle.h','direct_probe.c')
    sources={'bench/'+name:q.digest(ROOT/'bench'/name) for name in names}
    sources.update({'bench/qualify_request_lifecycle.py':q.digest(Path(__file__)),'bench/qualify_request_trace.py':q.digest(ROOT/'bench/qualify_request_trace.py')})
    for name in names:shutil.copyfile(ROOT/'bench'/name,area/name)
    with (area/'vmlinux.h').open('x') as stream:
        subprocess.run(['bpftool','btf','dump','file','/sys/kernel/btf/vmlinux','format','c'],stdout=stream,check=True,timeout=30)
    header=(area/'vmlinux.h').read_text()
    patterns=[r'typedef void \(\*btf_trace_block_rq_'+name+r'\)\(void \*, struct request \*\);' for name in ('insert','issue','requeue')]
    patterns.append(r'typedef void \(\*btf_trace_block_rq_complete\)\(void \*, struct request \*, blk_status_t, unsigned int\);')
    q.require(all(re.search(p,header) for p in patterns),'Raw tracepoint ABI changed')
    raw=q.command('bpftool','-j','btf','dump','file','/sys/kernel/btf/vmlinux','format','raw',timeout=30)
    q.require(len(raw)<=128*2**20,'BTF metadata bound');types={v['id']:v for v in json.loads(raw)['types']}
    function=next(v for v in types.values() if v['kind']=='FUNC' and v['name']=='blk_insert_flush')
    proto=types[function['type_id']];q.require(proto['kind']=='FUNC_PROTO' and len(proto['params'])==1,'Flush function prototype changed')
    ret=type_shape(types,proto['ret_type_id']);ptr=type_shape(types,proto['params'][0]['type_id'])
    q.require(ret['kind']=='INT' and ret['name'] in ('bool','_Bool') and ret['size']==1,'Flush return type changed')
    q.require(ptr['kind']=='PTR' and type_shape(types,ptr['type_id'])['name']=='request','Flush argument type changed')
    build_root=Path('/usr/lib/modules')/os.uname().release/'build/include'
    q.require(re.search(r'#define\s+REQ_OP_BITS\s+8\b',(build_root/'linux/blk_types.h').read_text()),'Operation mask changed')
    q.require(re.search(r'REQ_OP_FLUSH\s*=\s*2\b',header),'Flush operation value changed')
    del types,raw
    builds=[['clang','-g','-O2','-Wall','-Werror','-target','bpf','-mcpu=v3','-D__TARGET_ARCH_x86','-I.',
        '-c','request_lifecycle.bpf.c','-o','request_lifecycle.bpf.o'],
        ['gcc','-O2','-g','-Wall','-Wextra','-Werror','request_lifecycle.c','-o','request-lifecycle','-lbpf','-lelf','-lz'],
        ['gcc','-O2','-g','-Wall','-Wextra','-Werror','direct_probe.c','-o','direct-probe','-pthread']]
    for index,build in enumerate(builds):
        with (area/f'build-{index}.log').open('x') as stream:
            subprocess.run(build,cwd=area,stdout=stream,stderr=subprocess.STDOUT,check=True,timeout=60)
    contract=dict(schema_version=1,source_sha256=sources,kernel=os.uname().release,order=['direct-read-control','fsync-sequence-1','fsync-sequence-2'],
        BTF_raw_callback_ABI_verified=True,flush_entry_return_ABI_verified=True,flush_function_type='bool blk_insert_flush(struct request *)',
        btf_header_sha256=q.digest(area/'vmlinux.h'),trace_header_sha256=q.digest(build_root/'trace/events/block.h'),
        request_header_sha256=q.digest(build_root/'linux/blk-mq.h'),fixture_bytes=8*2**20,fsync_updates_per_case=8,
        update_bytes=4096,window_seconds=3,max_saved_callbacks=50000,identity_map_limit=8192,
        performance_result=False,original_timing_observer_changed=False,old_verdicts_changed=False)
    (area/'contract.json').write_text(json.dumps(contract,indent=2)+'\n')
    fixture=area/'fixture.bin';fd=os.open(fixture,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        flags=bytearray(8);fcntl.ioctl(fd,0x80086601,flags,True)
        fcntl.ioctl(fd,0x40086602,struct.pack('=Q',struct.unpack('=Q',flags)[0]|0x800000));fcntl.ioctl(fd,0x80086601,flags,True)
        q.require(struct.unpack('=Q',flags)[0]&0x800000,'Fixture NOCOW not established')
        for _ in range(8):
            data=os.urandom(2**20);position=0
            while position<len(data):position+=os.write(fd,data[position:])
        os.fsync(fd)
    finally:os.close(fd)
    cases=[]
    try:
        for label in contract['order']:
            if label=='direct-read-control':q.require(q.residency(fixture,evict=True)==0,'Read control cache not cold')
            proc,ids,log=start(area,device)
            try:
                if label=='direct-read-control':
                    work=json.loads(q.command(area/'direct-probe',fixture,'1','256','stride',timeout=15));q.require(work['passed'],'Read control failed')
                    q.require(q.residency(fixture)==0,'Direct reads populated page cache')
                else:
                    markers=[];fd=os.open(fixture,os.O_WRONLY|os.O_NOFOLLOW)
                    try:
                        for index in range(8):
                            started=time.monotonic_ns();data=os.urandom(4096);q.require(os.pwrite(fd,data,index*4096)==4096,'Short fixture update')
                            os.fdatasync(fd);markers.append(dict(start_ns=started,finish_ns=time.monotonic_ns()))
                    finally:os.close(fd)
                    work=dict(passed=True,updates=8,logical_written_bytes=32768,start_monotonic_ns=markers[0]['start_ns'],
                        finish_monotonic_ns=markers[-1]['finish_ns'],markers=markers,foreground_request_attribution_claimed=False)
                stdout,stderr=proc.communicate(timeout=15);log+=stderr
                (area/(label+'-raw-private.json')).write_bytes(stdout);(area/(label+'-workload-private.json')).write_text(json.dumps(work,indent=2)+'\n')
                (area/(label+'-loader-private.log')).write_bytes(log)
                q.require(proc.returncode==0 and q.absent(ids),'Diagnostic failed or left owned programs')
                raw=json.loads(stdout);q.require(raw['kind']=='bc250-request-lifecycle-diagnostic','Wrong diagnostic format')
                q.require(raw['counters']==[raw['events'],0,0,0] and not any(raw[k] for k in ('malformed','discarded','interrupted','limit_reached')),'Incomplete diagnostic transport')
                q.require(raw['start_ns']<=work['start_monotonic_ns']<work['finish_monotonic_ns']<=raw['finish_ns'],'Work outside capture window')
                cases.append(dict(case=label,passed=True,events=raw['events'],transport_complete=True,owned_programs_gone=True))
                print(json.dumps(cases[-1]),flush=True)
            finally:q.finish(proc)
    finally:
        q.require(q.trace_state()==before,'Global trace state changed');q.require(qos.read_text().strip()=='5000','Drive policy changed')
    q.require(q.programs()==programs,'Unrelated program inventory changed')
    q.require(all(q.digest(ROOT/name)==sha for name,sha in sources.items()),'Source changed')
    result=dict(contract,passed=True,cases=cases,all_owned_programs_gone=True,global_trace_state_unchanged=True,
        unrelated_program_inventory_unchanged=True,drive_policy_unchanged=True,physical_device_formatted=False,
        full_lifecycle_interpretation_qualified=False,foreground_attribution_qualified=False,completed_unix=time.time(),
        compiled_sha256={name:q.digest(area/name) for name in ('request_lifecycle.bpf.o','request-lifecycle','direct-probe')})
    (area/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(dict(passed=True,cases=len(cases))),flush=True)


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('step',choices=('run','_host'));parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();q.require(sys.platform=='linux' and os.geteuid()==0,'Linux root required')
    if args.step=='_host':host(args);return
    unit='bc250-lifecycle-'+uuid.uuid4().hex[:12]
    subprocess.run(['systemd-run','--quiet','--wait','--pipe','--collect','--unit='+unit,'--property=MemoryMax=2G','--property=MemorySwapMax=0',
        '--property=CPUQuota=200%','--property=TasksMax=128','--property=RuntimeMaxSec=180','--property=KillMode=control-group',
        '/usr/bin/unshare','--mount','--propagation','private','/usr/bin/python3','-B',str(Path(__file__).resolve()),'_host','--output',str(args.output)],check=True,timeout=210)


if __name__=='__main__':main()
