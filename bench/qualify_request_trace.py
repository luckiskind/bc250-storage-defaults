#!/usr/bin/env python3
"""Build and qualify a bounded, temporary request observer on disposable data.

Writes one new 64 MiB NOCOW regular fixture; reads it with aligned O_DIRECT.
Never formats a device, clears global caches, modifies requests, changes drive
policy, pins BPF objects or changes tracefs configuration. No speed claim follows.
"""
import argparse
import ctypes
import fcntl
import hashlib
import json
import mmap
import os
from pathlib import Path
import re
import select
import shutil
import signal
import stat
import struct
import subprocess
import sys
import time
import uuid

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'));sys.path.insert(0,str(ROOT/'analysis'))
import native_volume_lab as native
from request_trace import validate


def require(value,message):
    if not value:raise RuntimeError(message)


def digest(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def command(*args,timeout=60):
    return subprocess.check_output(list(map(str,args)),stderr=subprocess.STDOUT,text=True,timeout=timeout).strip()


def trace_state():
    root=Path('/sys/kernel/tracing')
    return {name:(root/name).read_text().strip() for name in ('tracing_on','current_tracer','trace_clock','events/enable')}


def block_device(path):
    source=command('findmnt','-n','-o','SOURCE','--target',path).split('[')[0]
    info=Path(source).stat();require(stat.S_ISBLK(info.st_mode),'Requires a direct block-backed filesystem')
    sysdev=(Path('/sys/dev/block')/(str(os.major(info.st_rdev))+':'+str(os.minor(info.st_rdev)))).resolve(strict=True)
    disk=sysdev.parent.name if (sysdev/'partition').exists() else sysdev.name
    require(re.fullmatch(r'nvme\d+n\d+',disk),'Only the observed NVMe namespace is qualified')
    device=Path('/dev')/disk;require(stat.S_ISBLK(device.stat().st_mode),'NVMe namespace unavailable')
    return device


def programs():return {row['id']:row.get('name','') for row in json.loads(command('bpftool','-j','prog','show'))}


def absent(ids):
    deadline=time.monotonic()+3
    while time.monotonic()<deadline:
        if not set(ids)&programs().keys():return True
        time.sleep(.05)
    return False


def residency(path,evict=False):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        size=os.fstat(fd).st_size
        if evict:os.posix_fadvise(fd,0,size,os.POSIX_FADV_DONTNEED)
        page=os.sysconf('SC_PAGE_SIZE');count=(size+page-1)//page
        with mmap.mmap(fd,size,access=mmap.ACCESS_COPY) as mapping:
            address=ctypes.addressof(ctypes.c_char.from_buffer(mapping))
            flags=(ctypes.c_ubyte*count)();libc=ctypes.CDLL(None,use_errno=True)
            libc.mincore.argtypes=(ctypes.c_void_p,ctypes.c_size_t,ctypes.c_void_p)
            require(libc.mincore(address,size,flags)==0,'Cannot verify fixture residency')
            return sum(bool(flag&1) for flag in flags)*page
    finally:os.close(fd)


def start(area,device,duration,limit):
    proc=subprocess.Popen([str(area/'request-trace'),str(area/'request_trace.bpf.o'),str(device),str(duration),str(limit),'1'],
        stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    os.set_blocking(proc.stderr.fileno(),False)
    log=b'';deadline=time.monotonic()+10
    try:
        while time.monotonic()<deadline:
            if select.select([proc.stderr],[],[],.1)[0]:
                chunk=os.read(proc.stderr.fileno(),65536);log+=chunk
                require(len(log)<2**20,'Bounded loader diagnostic limit')
                for line in log.splitlines():
                    if line.startswith(b'BC250_TRACE_READY '):
                        ids=json.loads(line.split(b' ',1)[1])['program_ids']
                        require(len(ids)==4 and len(set(ids))==4,'Four unique programs required')
                        return proc,ids,log
            require(proc.poll() is None,'Observer failed to attach: '+log.decode(errors='replace')[-3000:])
        raise RuntimeError('Observer readiness deadline')
    except BaseException:
        proc.kill();proc.communicate(timeout=5);raise


def finish(proc):
    if proc.poll() is None:
        proc.send_signal(signal.SIGINT)
        try:proc.communicate(timeout=3)
        except subprocess.TimeoutExpired:proc.kill();proc.communicate(timeout=5)


def run_case(area,device,label,work=None,limit=200000,expect_cap=False):
    cold=residency(area/'fixture.bin',evict=True) if work else None
    if work:require(cold==0,'Private fixture did not become cache-cold')
    proc,ids,log=start(area,device,2,limit)
    try:
        require(set(ids)<=programs().keys(),'Observer program identity disappeared')
        workload=None
        if work:
            threads,ops,pattern=work
            workload=json.loads(command(area/'direct-probe',area/'fixture.bin',threads,ops,pattern,timeout=15))
            require(workload['passed'] and workload['operations']==threads*ops,'Known read workload failed')
            workload.update(resident_before_bytes=cold,resident_after_bytes=residency(area/'fixture.bin'))
        stdout,stderr=proc.communicate(timeout=10);log+=stderr
        # Preserve evidence before any parser or qualification assertion fails.
        (area/(label+'-raw-private.json')).write_bytes(stdout)
        (area/(label+'-workload-private.json')).write_text(json.dumps(workload,indent=2)+'\n')
        (area/(label+'.loader.log')).write_bytes(log)
        require(proc.returncode==0,'Observer failed: '+log.decode(errors='replace')[-3000:])
        report=json.loads(stdout);checked=validate(report)
        require(absent(ids),'Owned observer programs remain after exit')
        if expect_cap:
            require(report['event_limit_reached'] and not checked['transport_complete'],'Cap must remain an explicit incomplete capture')
        else:
            require(checked['transport_complete'],'Capture transport is incomplete')
            if work:
                require(report['read_completed_bytes']>=workload['read_bytes'] and checked['qualified_full_requests']>0,
                    'Known physical reads not observed')
                require(workload['resident_after_bytes']==0,'Direct-read control populated page cache')
                require(sum(r['operation']==0 for r in report['records'])>=workload['operations'],
                    'Known direct read request count is incomplete')
                require(report['start_monotonic_ns']<=workload['start_monotonic_ns']<workload['finish_monotonic_ns']
                    <=report['start_monotonic_ns']+report['elapsed_ns'],'Workload outside active capture')
        (area/(label+'-private.json')).write_text(json.dumps(dict(trace=report,validation=checked,workload=workload),indent=2)+'\n')
        (area/(label+'.loader.log')).write_bytes(log)
        return dict(case=label,passed=True,events=report['events'],qualified_full_requests=report['qualified_full_requests'],
            flagged_requests=report['flagged_events'],kernel_counters=checked['kernel_counters'],
            right_censored_requests=report['right_censored_requests'],event_limit_reached=report['event_limit_reached'],
            transport_complete=checked['transport_complete'],wire_consistent=True,owned_programs_gone=True,
            known_direct_read_bytes=workload['read_bytes'] if workload else 0,
            fixture_resident_before_bytes=cold,fixture_resident_after_bytes=workload['resident_after_bytes'] if workload else None,
            read_completed_bytes=report['read_completed_bytes'],unique_request_ids=checked['unique_request_ids'],
            partial_requeue_error_paths_qualified=False,foreground_attribution_qualified=False)
    finally:finish(proc)


def host(args):
    native.confined();area=args.output.absolute();native.private_area(area,creating=True);native.host_space(area.parent)
    require(command('findmnt','-n','-o','FSTYPE','--target',area.parent)=='btrfs','Requires disposable Btrfs fixture')
    device=block_device(area.parent);require(device==block_device(Path('/')),'Fixture must use the observed root NVMe')
    before=trace_state();before_programs=programs()
    namespace=(Path('/sys/class/block')/device.name).resolve(strict=True)
    linked=(namespace/'device').resolve(strict=True)
    controllers=[p for p in Path('/sys/class/nvme').iterdir()
        if p.resolve() in namespace.parents or p.resolve()==linked]
    require(len(controllers)==1,'Ambiguous NVMe controller relationship')
    qos=controllers[0]/'power/pm_qos_latency_tolerance_us'
    require(qos.read_text().strip()=='5000','Actual power policy differs from reference')
    area.mkdir(mode=0o700)
    names=('request_trace.bpf.c','request_trace.c','request_trace.h','direct_probe.c')
    hashes={name:digest(ROOT/'bench'/name) for name in names}
    for name in names:shutil.copyfile(ROOT/'bench'/name,area/name)
    with (area/'vmlinux.h').open('x') as stream:
        subprocess.run(['bpftool','btf','dump','file','/sys/kernel/btf/vmlinux','format','c'],stdout=stream,check=True,timeout=30)
    header=(area/'vmlinux.h').read_text()
    expected=[r'typedef void \(\*btf_trace_block_rq_'+name+r'\)\(void \*, struct request \*\);'
        for name in ('insert','issue','requeue')]
    expected+=[r'typedef void \(\*btf_trace_block_rq_complete\)\(void \*, struct request \*, blk_status_t, unsigned int\);']
    require(all(re.search(pattern,header) for pattern in expected),'Running raw tracepoint ABI changed')
    release=os.uname().release;headers=Path('/usr/lib/modules')/release/'build/include'
    types=(headers/'linux/blk_types.h').read_text()
    require(re.search(r'#define\s+REQ_OP_BITS\s+8\b',types) is not None,'Request operation bit mask changed')
    require(re.search(r'REQ_OP_READ\s*=\s*0\b',header) and re.search(r'REQ_OP_WRITE\s*=\s*1\b',header),'Request op values changed')
    builds=[['clang','-g','-O2','-Wall','-Werror','-target','bpf','-mcpu=v3','-D__TARGET_ARCH_x86','-I.',
        '-c','request_trace.bpf.c','-o','request_trace.bpf.o'],
        ['gcc','-O2','-g','-Wall','-Wextra','-Werror','request_trace.c','-o','request-trace','-lbpf','-lelf','-lz'],
        ['gcc','-O2','-g','-Wall','-Wextra','-Werror','direct_probe.c','-o','direct-probe','-pthread']]
    for i,build in enumerate(builds):
        with (area/('build-'+str(i)+'.log')).open('x') as stream:
            subprocess.run(build,cwd=area,stdout=stream,stderr=subprocess.STDOUT,check=True,timeout=60)
    fixture=area/'fixture.bin';fd=os.open(fixture,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        flags=bytearray(8);fcntl.ioctl(fd,0x80086601,flags,True)
        fcntl.ioctl(fd,0x40086602,struct.pack('=Q',struct.unpack('=Q',flags)[0]|0x800000))
        fcntl.ioctl(fd,0x80086601,flags,True);require(struct.unpack('=Q',flags)[0]&0x800000,'Fixture NOCOW not established')
        for _ in range(64):
            data=os.urandom(2**20);position=0
            while position<len(data):position+=os.write(fd,data[position:])
        os.fsync(fd)
    finally:os.close(fd)
    fixture_sha=digest(fixture);cases=[]
    try:
        for label,work,limit,cap in [('idle',None,200000,False),('serial-direct',(1,2048,'stride'),200000,False),
                ('overlapping-direct',(4,2048,'same'),200000,False),('event-cap',(2,512,'same'),16,True)]:
            cases.append(run_case(area,device,label,work,limit,cap));print(json.dumps(cases[-1]),flush=True)
        proc,ids,log=start(area,device,10,200000)
        try:
            proc.kill();stdout,stderr=proc.communicate(timeout=5)
            require(proc.returncode==-signal.SIGKILL and absent(ids),'Forced exit did not release owned observer programs')
            cases.append(dict(case='forced-observer-exit',passed=True,owned_programs_gone=True,signal='SIGKILL',performance_result=False))
            (area/'forced-exit.loader.log').write_bytes(log+stderr)
        finally:finish(proc)
    finally:
        require(trace_state()==before,'Global trace configuration changed')
        require(qos.read_text().strip()=='5000','Working drive policy changed')
    require(digest(fixture)==fixture_sha,'Read-only fixture content changed')
    after_programs=programs()
    require(all(digest(ROOT/'bench'/name)==sha for name,sha in hashes.items()),'Source changed during qualification')
    report=dict(schema_version=1,passed=True,kernel=release,cases=cases,case_count=len(cases),
        request_identity='Internal request pointer plus nonzero allocation start_time_ns; anonymous issue sequence in output',
        raw_tracepoint_signatures_validated=True,operation_mask_and_values_validated=True,
        build_commands=builds,toolchain=dict(clang=command('clang','--version').splitlines()[0],
            gcc=command('gcc','--version').splitlines()[0],libbpf=command('pkg-config','--modversion','libbpf')),
        btf_header_sha256=digest(area/'vmlinux.h'),block_trace_header_sha256=digest(headers/'trace/events/block.h'),
        source_sha256={**{'bench/'+name:sha for name,sha in hashes.items()},
            'bench/qualify_request_trace.py':digest(Path(__file__)),'analysis/request_trace.py':digest(ROOT/'analysis/request_trace.py')},
        compiled_sha256={name:digest(area/name) for name in ('request_trace.bpf.o','request-trace','direct-probe')},
        map_entries_limit=8192,ring_buffer_bytes=4*2**20,max_saved_records=200000,fixture_bytes=64*2**20,
        fixture_unchanged=True,all_owned_programs_gone=True,bpf_pins_created=False,global_trace_state_unchanged=True,
        unrelated_program_inventory_unchanged=after_programs==before_programs,
        drive_policy_unchanged=True,nvme_qos_us=5000,host_cache_reset_performed=False,
        tracing_overhead_quantified=False,foreground_attribution_qualified=False,partial_requeue_error_paths_qualified=False,
        hardware_device_only_latency_qualified=False,new_throughput_comparison_performed=False,completed_unix=time.time())
    (area/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(dict(passed=True,cases=len(cases),report=str(area/'result.json'))),flush=True)


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('step',choices=('run','_host'))
    parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    require(sys.platform=='linux' and os.geteuid()==0,'Requires root on Linux')
    if args.step=='_host':host(args);return
    unit='bc250-request-qualification-'+uuid.uuid4().hex[:12];print(json.dumps(dict(parent_unit=unit)),flush=True)
    subprocess.run(['systemd-run','--quiet','--wait','--pipe','--collect','--unit='+unit,
        '--property=MemoryMax=2G','--property=MemoryHigh=1536M','--property=MemorySwapMax=0','--property=CPUQuota=200%',
        '--property=RuntimeMaxSec=300','--property=KillMode=control-group','--property=TimeoutStopSec=15',
        '/usr/bin/unshare','--mount','--propagation','private','/usr/bin/python3',str(Path(__file__).resolve()),'_host',
        '--output',str(args.output)],check=True,timeout=330)


if __name__=='__main__':main()
