#!/usr/bin/env python3
"""Opt-in Btrfs read/decompression lineage on two new regular-file fixtures."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import select
import shutil
import signal
import struct
import subprocess
import sys
import time
import uuid
import qualify_request_trace as q
from read_lineage import validate

ROOT=Path(__file__).resolve().parents[1]


def shape(types,index):
    if not index:return 'void'
    value=types[index]
    while value['kind'] in ('TYPEDEF','CONST','VOLATILE','RESTRICT','TYPE_TAG'):value=types[value['type_id']]
    return '*'+shape(types,value['type_id']) if value['kind']=='PTR' else value.get('name',value['kind'])


def build(area):
    names=('read_lineage.bpf.c','read_lineage.c','read_lineage.h','read_lineage_probe.c')
    for name in names:shutil.copyfile(ROOT/'bench'/name,area/name)
    with (area/'vmlinux.h').open('x') as out:subprocess.run(['bpftool','btf','dump','file','/sys/kernel/btf/vmlinux','format','c'],stdout=out,check=True,timeout=30)
    raw=json.loads(q.command('bpftool','-j','btf','dump','file','/sys/kernel/btf/vmlinux','format','raw',timeout=30));types={r['id']:r for r in raw['types']}
    expected={'filemap_read':('long int',['*kiocb','*iov_iter','long int']), 'filemap_fault':('unsigned int',['*vm_fault']),
        'filemap_map_pages':('unsigned int',['*vm_fault','long unsigned int','long unsigned int']),
        'submit_one_bio':('void',['*btrfs_bio_ctrl']),'btrfs_submit_compressed_read':('void',['*btrfs_bio']),
        'end_bbio_compressed_read':('void',['*btrfs_bio']),'zstd_decompress_bio':('int',['*list_head','*compressed_bio']),
        'end_bbio_data_read':('void',['*btrfs_bio']),'io_schedule':('void',[]),'folio_unlock':('void',['*folio'])}
    observed={}
    for name,want in expected.items():
        functions=[r for r in types.values() if r['kind']=='FUNC' and r['name']==name];q.require(len(functions)==1,'Ambiguous/missing BTF function: '+name)
        proto=types[functions[0]['type_id']];actual=(shape(types,proto['ret_type_id']),[shape(types,r['type_id']) for r in proto['params']])
        q.require(actual==want,'Function ABI differs: '+name);observed[name]=dict(returns=actual[0],parameters=actual[1])
    commands=[['clang','-g','-O2','-Wall','-Werror','-target','bpf','-mcpu=v3','-D__TARGET_ARCH_x86','-I.','-c','read_lineage.bpf.c','-o','read_lineage.bpf.o'],
        ['gcc','-g','-O2','-Wall','-Wextra','-Werror','read_lineage.c','-o','read-lineage','-lbpf','-lelf','-lz'],
        ['gcc','-g','-O2','-Wall','-Wextra','-Werror','read_lineage_probe.c','-o','read-lineage-probe']]
    for index,command in enumerate(commands):
        with (area/('build-%d.log'%index)).open('x') as out:subprocess.run(command,cwd=area,stdout=out,stderr=subprocess.STDOUT,check=True,timeout=60)
    return names,observed


def start(area,pid,fd,limit=50000):
    proc=subprocess.Popen([str(area/'read-lineage'),str(area/'read_lineage.bpf.o'),str(pid),str(fd),'3',str(limit)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    os.set_blocking(proc.stderr.fileno(),False);log=b'';deadline=time.monotonic()+12
    try:
        while time.monotonic()<deadline:
            if select.select([proc.stderr],[],[],.1)[0]:
                log+=os.read(proc.stderr.fileno(),65536);q.require(len(log)<2**20,'Diagnostic log bound')
                for line in log.splitlines():
                    if line.startswith(b'BC250_READ_LINEAGE_READY '):
                        ids=json.loads(line.split(b' ',1)[1])['program_ids'];q.require(len(ids)==len(set(ids))==16,'Sixteen program IDs required');return proc,ids,log
            q.require(proc.poll() is None,'Read-lineage attach failed: '+log.decode(errors='replace')[-4000:])
        raise RuntimeError('Read-lineage readiness deadline')
    except BaseException:
        q.finish(proc);(area/'failed-start-private.log').write_bytes(log);raise


def line(proc,timeout=10):
    q.require(select.select([proc.stdout],[],[],timeout)[0],'Worker response deadline')
    value=proc.stdout.readline();q.require(0<len(value)<4096,'Worker response bound');return value


def capture(area,path,label,mode,warm,expected_hash,wrong_fd=False,limit=50000,kill=False):
    if warm:q.digest(path)
    resident=q.residency(path,evict=not warm);q.require(resident==(path.stat().st_size if warm else 0),'Fixture cache state differs')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW);other=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    # Different open file descriptions of the SAME inode must not substitute
    # for the actual inherited file descriptor used by this worker.
    worker=subprocess.Popen([str(area/'read-lineage-probe'),str(fd),mode],pass_fds=(fd,other),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    trace=None;ids=[];log=b''
    try:
        q.require(line(worker)==b'BC250_READ_WORKER_READY\n','Worker not ready')
        trace,ids,log=start(area,worker.pid,other if wrong_fd else fd,limit)
        if kill:
            trace.kill();trace.communicate(timeout=5);q.require(q.absent(ids),'Forced exit left programs')
            return dict(case=label,passed=True,owned_programs_gone=True,forced_exit=True)
        worker.stdin.write(b'G');worker.stdin.flush();work=json.loads(line(worker));q.require(work['passed'] and work['logical_bytes']==2*2**20 and work['fnv64']==expected_hash,'Read/hash failed')
        out,err=trace.communicate(timeout=10);log+=err
        (area/(label+'-raw-private.json')).write_bytes(out);(area/(label+'-loader-private.log')).write_bytes(log);(area/(label+'-worker-private.json')).write_text(json.dumps(work,indent=2)+'\n')
        q.require(trace.returncode==0 and q.absent(ids) and worker.poll() is None,'Trace or pinned worker lifetime failed')
        raw=json.loads(out);result=validate(raw)
        q.require(raw['start_ns']<=work['start_ns']<work['finish_ns']<=raw['finish_ns'] or limit<50000,'Worker outside capture')
        if wrong_fd:q.require(raw['events']==0 and result['identity_rejections']>0,'Same-inode wrong descriptor accepted')
        elif limit<50000:q.require(raw['limit_reached'] and not result['transport_complete'],'Cap not explicit')
        else:
            q.require(result['stream_quality_passed'] and result['demand_attempts']>0,'Lineage quality/demand absent')
            if mode=='read':q.require(result['buffered_read_returned_bytes']==work['logical_bytes'],'Buffered read return accounting differs')
            if warm:q.require(result['original_data_bios']==result['decompression_spans']==0,'Warm data unexpectedly submitted I/O')
            elif path.name=='compressed.bin':q.require(result['compressed_original_bios']>0 and result['decompression_spans']>0,'Compressed cold path not observed')
            else:q.require(result['original_data_bios']>0 and result['compressed_original_bios']==result['decompression_spans']==0,'Plain cold path differs')
        worker.stdin.write(b'D');worker.stdin.flush();worker.communicate(timeout=5);q.require(worker.returncode==0,'Worker exit failed')
        return dict(case=label,passed=True,mode=mode,warm=warm,resident_before_bytes=resident,validation=result,events=raw['events'],
            known_logical_bytes=work['logical_bytes'],content_checked=True,owned_programs_gone=True,pinned_descriptor_lifetime_verified=True,
            intended_incomplete=limit<50000,identity_negative=wrong_fd,runtime_libbpf=raw['libbpf'])
    finally:
        if trace:q.finish(trace);q.require(q.absent(ids),'Owned diagnostic programs remain')
        if worker.poll() is None:worker.kill();worker.communicate(timeout=5)
        os.close(fd);os.close(other)


def host(args):
    q.native.confined();area=args.output.absolute();q.native.private_area(area,creating=True);q.native.host_space(area.parent)
    q.require(q.block_device(area.parent)==q.block_device(Path('/')),'Different physical device')
    qos=Path('/sys/class/nvme/nvme0/power/pm_qos_latency_tolerance_us');q.require(qos.read_text().strip()=='5000','Power policy differs')
    state,inventory=q.trace_state(),q.programs();area.mkdir(mode=0o700);names,abi=build(area)
    content=os.urandom(8192)*1024;expected=14695981039346656037
    for byte in content[:2*2**20]:expected=((expected^byte)*1099511628211)&((1<<64)-1)
    expected=f'{expected:016x}';fixtures={}
    for name,nocow in [('plain.bin',True),('compressed.bin',False)]:
        path=area/name;fd=os.open(path,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        try:
            if nocow:
                flags=bytearray(8);fcntl.ioctl(fd,0x80086601,flags,True);fcntl.ioctl(fd,0x40086602,struct.pack('=Q',struct.unpack('=Q',flags)[0]|0x800000))
            with os.fdopen(os.dup(fd),'wb') as out:out.write(content);out.flush();os.fsync(out.fileno())
            spans=q.native.repack.extents(fd,len(content));encoded=sum(bool(flags&8) for _,_,flags in spans)
            q.require(bool(encoded)==(not nocow) and not any(flags&0x2000 for _,_,flags in spans),'Fixture encoding/sharing differs')
            fixtures[name]=dict(bytes=len(content),sha256=q.digest(path),encoded_extents=encoded,shared_extents=0)
        finally:os.close(fd)
    source_names=['bench/'+n for n in names]+['bench/qualify_read_lineage.py','analysis/read_lineage.py','bench/qualify_request_trace.py']
    sources={name:q.digest(ROOT/name) for name in source_names}
    contract=dict(schema_version=1,kernel=os.uname().release,source_sha256=sources,verified_function_abi=abi,fixtures=fixtures,
        pinning='Inherited actual open file description; parent and worker retain descriptors through observer detach',
        maps_temporary_unpinned=True,map_entries_each=4096,owned_program_count=16,ring_bytes=4*2**20,duration_seconds=3,max_saved_records=50000,
        raw_addresses_or_task_ids_exported=False,performance_result=False,critical_path_attribution_qualified=False)
    (area/'contract.json').write_text(json.dumps(contract,indent=2)+'\n');rows=[]
    try:
        for name in fixtures:
            for mode in ('read','mmap'):
                for warm in (False,True):
                    label=name.split('.')[0]+'-'+mode+('-warm' if warm else '-cold')
                    rows.append(capture(area,area/name,label,mode,warm,expected))
        rows.append(capture(area,area/'compressed.bin','same-inode-wrong-descriptor','read',False,expected,wrong_fd=True))
        rows.append(capture(area,area/'compressed.bin','record-cap','read',False,expected,limit=4))
        rows.append(capture(area,area/'compressed.bin','forced-exit','read',False,expected,kill=True))
    finally:
        (area/'completed-cases.json').write_text(json.dumps(rows,indent=2)+'\n')
        q.require(q.trace_state()==state and q.programs()==inventory and qos.read_text().strip()=='5000','Global state changed')
    for name,entry in fixtures.items():q.require(q.digest(area/name)==entry['sha256'],'Fixture changed')
    for name,sha in sources.items():q.require(q.digest(ROOT/name)==sha,'Source changed')
    result=dict(passed=True,case_count=len(rows),cases=rows,contract=contract,all_owned_programs_gone=True,
        global_trace_state_unchanged=True,unrelated_program_inventory_unchanged=True,nvme_qos_us=5000,fixture_contents_unchanged=True,
        compiled_sha256={n:q.digest(area/n) for n in ('read-lineage','read_lineage.bpf.o','read-lineage-probe')},
        full_folio_bio_request_wait_chain_qualified=False,overhead_qualified=False,stage1_gate_passed=False)
    (area/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result),flush=True)


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('step',choices=('run','_host'));parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    q.require(sys.platform=='linux' and os.geteuid()==0,'Linux root required')
    if args.step=='_host':host(args);return
    unit='bc250-read-lineage-'+uuid.uuid4().hex[:12]
    subprocess.run(['systemd-run','--quiet','--wait','--pipe','--collect','--unit='+unit,'--property=MemoryMax=2G','--property=CPUQuota=200%',
        '--property=MemorySwapMax=0','--property=TasksMax=128','--property=RuntimeMaxSec=300','--property=KillMode=control-group',
        '/usr/bin/unshare','--mount','--propagation','private','python3','-B',str(Path(__file__).resolve()),'_host','--output',str(args.output)],check=True,timeout=330)


if __name__=='__main__':main()
