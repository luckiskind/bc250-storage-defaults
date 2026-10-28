#!/usr/bin/env python3
"""Finite independent wake witness on 256 cold private-file accesses."""
import argparse,fcntl,json,os,select,shutil,struct,subprocess,sys,time,uuid
from pathlib import Path
import qualify_handoff_wait as handoff
from wake_witness_loader import generate,ready_ids
from wake_witness import validate

q=handoff.q;ROOT=handoff.ROOT;base=handoff.full.base


def build(area,reference):
    old=json.loads((reference/'result.json').read_text())
    q.require(old['kind']=='bc250-handoff-wait-qualification' and old['handoff_wait_controls_passed'] and old['case_count']==16,'Qualified handoff reference required')
    q.require(old['extension']['scheduler_timestamp_basis']=='hook-entry-v1','Wrong reference clocks')
    for name,sha in old['contract']['source_sha256'].items():q.require(q.digest(ROOT/name)==sha,'Frozen handoff source changed: '+name)
    for name,sha in {**old['compiled_sha256'],**old['extension']['compiled_sha256']}.items():q.require(q.digest(reference/name)==sha,'Frozen handoff binary changed: '+name)
    # Exact compiled inputs from the qualification, no old rebuild or edit.
    files=[p for p in reference.iterdir() if p.is_file() and p.suffix in ('.c','.h')]
    for p in files:shutil.copyfile(p,area/p.name)
    own=('wake_witness.bpf.c','wake_witness_loader.py','qualify_wake_witness.py','wake_overlap_probe.c')
    for name in own:shutil.copyfile(ROOT/'bench'/name,area/name)
    (area/'wake_witness.generated.c').write_text(generate((area/'read_lineage.c').read_text()))
    types=json.loads(q.command('bpftool','-j','btf','dump','file','/sys/kernel/btf/vmlinux','format','raw',timeout=30))['types'];lookup={v['id']:v for v in types}
    funcs=[v for v in types if v['kind']=='FUNC' and v['name']=='try_to_wake_up'];q.require(len(funcs)==1,'Missing/ambiguous wake function BTF')
    proto=lookup[funcs[0]['type_id']];actual=(base.shape(lookup,proto['ret_type_id']),[base.shape(lookup,v['type_id']) for v in proto['params']])
    q.require(actual==('int',['*task_struct','unsigned int','int']),'Wake function ABI differs')
    tasks=[v for v in types if v['kind']=='STRUCT' and v['name']=='task_struct'];q.require(len(tasks)==1,'Missing task layout')
    fields={m['name']:m for m in tasks[0]['members']}
    for name in ('on_cpu','on_rq'):
        q.require(name in fields and base.shape(lookup,fields[name]['type_id'])=='unsigned char','Task state type differs')
    commands=[['clang','-g','-O2','-Wall','-Werror','-target','bpf','-mcpu=v3','-D__TARGET_ARCH_x86','-I.','-c','wake_witness.bpf.c','-o','wake_witness.bpf.o'],
        ['gcc','-g','-O2','-Wall','-Wextra','-Werror','wake_witness.generated.c','-o','wake-witness','-lbpf','-lelf','-lz'],
        ['gcc','-O2','-Wall','-Wextra','-Werror','wake_overlap_probe.c','-o','wake-overlap-probe']]
    for i,command in enumerate(commands):
        with (area/('witness-build-%d.log'%i)).open('x') as out:subprocess.run(command,cwd=area,stdout=out,stderr=subprocess.STDOUT,check=True,timeout=60)
    return dict(reference_result_sha256=q.digest(reference/'result.json'),reference_kind=old['kind'],
        inherited_input_sha256={p.name:q.digest(area/p.name) for p in files},
        source_sha256={n:q.digest(ROOT/n) for n in ['bench/'+s for s in own]+['analysis/wake_witness.py']},
        compiled_sha256={n:q.digest(area/n) for n in ('wake-witness','wake_witness.bpf.o','wake-overlap-probe')},
        generated_loader_sha256=q.digest(area/'wake_witness.generated.c'),verified_wake_function_abi=actual,
        task_state_layout={n:dict(bits_offset=fields[n]['bits_offset'],type=base.shape(lookup,fields[n]['type_id'])) for n in ('on_cpu','on_rq')})


def start(area,pid,fd,limit,witness):
    proc=subprocess.Popen([str(area/'wake-witness'),str(area/'wake_witness.bpf.o'),str(pid),str(fd),'3',str(limit),'1',str(q.block_device(area)),'1','1','1',str(int(witness))],
        stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    os.set_blocking(proc.stderr.fileno(),False);log=b'';deadline=time.monotonic()+15;seeded=False
    try:
        while time.monotonic()<deadline:
            if select.select([proc.stderr],[],[],.1)[0]:
                log+=os.read(proc.stderr.fileno(),65536);q.require(len(log)<2**20,'Witness loader log bound')
                if not seeded and b'BC250_PHYSICAL_SEED_READY\n' in log:
                    q.require(q.residency(area/'compressed.bin',evict=True)==0,'Calibration not cold');q.digest(area/'compressed.bin')
                    proc.stdin.write(b'G');proc.stdin.flush();seeded=True
                ids=ready_ids(log)
                if ids is not None:q.require(seeded,'Missing witness calibration');return proc,ids,log
            q.require(proc.poll() is None,'Witness attach failed: '+log.decode(errors='replace')[-2500:])
        raise RuntimeError('Witness readiness deadline')
    except BaseException:
        q.finish(proc);(area/'failed-start-private.log').write_bytes(log);raise


def capture(area,path,label,mode,expected,wrong=False,limit=50000,witness=True,kill=False):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW);other=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    worker=subprocess.Popen([str(area/'wake-overlap-probe'),str(fd),mode],pass_fds=(fd,other),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    trace=None;ids=[]
    try:
        q.require(base.line(worker)==b'BC250_READ_WORKER_READY\n','Overlap worker handshake absent')
        affinity={min(os.sched_getaffinity(0))};os.sched_setaffinity(worker.pid,affinity);q.require(os.sched_getaffinity(worker.pid)==affinity,'Worker affinity differs')
        trace,ids,log=start(area,worker.pid,other if wrong else fd,limit,witness)
        if kill:
            trace.kill();trace.communicate(timeout=5);q.require(q.absent(ids),'Forced exit left owned hooks')
            return dict(case=label,passed=True,forced_exit=True,owned_programs_gone=True)
        worker.stdin.write(b'G');worker.stdin.flush();work=json.loads(base.line(worker))
        q.require(work['passed'] and work['logical_bytes']==262144 and work['passes']==work['zero_resident_checks']==64 and work['fnv64']==expected,'Small-read cold/content contract failed')
        out,err=trace.communicate(timeout=10);log+=err
        q.require(len(out)+len(log)<16*2**20,'Witness capture storage bound')
        (area/(label+'-raw-private.json')).write_bytes(out);(area/(label+'-loader-private.log')).write_bytes(log)
        (area/(label+'-worker-private.json')).write_text(json.dumps(work,indent=2)+'\n')
        q.require(trace.returncode==0 and q.absent(ids) and worker.poll() is None,'Witness/worker pinned lifetime failed')
        raw=json.loads(out);v=validate(raw)
        q.require(raw['start_ns']<=work['start_ns']<work['finish_ns']<=raw['finish_ns'] or limit<50000,'Small worker outside capture')
        if wrong:q.require(raw['events']==0 and v['identity_rejections']>0,'Wrong-open negative failed')
        elif limit<50000:q.require(raw['limit_reached'] and not v['transport_complete'],'Cap not explicit')
        elif not witness:q.require(not v['stream_quality_passed'] and v['missing_wake_function_witnesses']>0 and not any(raw['witness_counters']),'Witness omission not detected')
        else:
            q.require(v['stream_quality_passed'] and v['demand_attempts']>=64 and v['waking_records_with_function_witness']>0,'Witness quality/demand absent')
            q.require(v['blocked_switch_segments']==v['resolved_request_folio_blocked_segments']>0,'Request-backed wait coverage absent')
            if mode=='read':q.require(v['buffered_read_returned_bytes']==work['logical_bytes'],'Small-read byte count differs')
            if path.name=='compressed.bin':q.require(v['compressed_original_bios']>0 and v['decompression_spans']>0,'Encoded path absent')
            else:q.require(v['original_data_bios']>0 and v['compressed_original_bios']==v['decompression_spans']==0,'Plain path differs')
        worker.stdin.write(b'D');worker.stdin.flush();worker.communicate(timeout=5);q.require(worker.returncode==0,'Overlap worker normal close failed')
        return dict(case=label,passed=True,mode=mode,cold_accesses=64,logical_bytes=262144,wrong_open=wrong,intended_incomplete=limit<50000,
            witness_enabled=witness,content_checked=True,pinned_worker_affinity_verified=True,owned_programs_gone=True,validation=v)
    finally:
        if trace:q.finish(trace);q.require(q.absent(ids),'Owned witness programs remain')
        if worker.poll() is None:worker.kill();worker.communicate(timeout=5)
        os.close(fd);os.close(other)


def host(args):
    q.native.confined();area=args.output.absolute();q.native.private_area(area,creating=True);q.native.host_space(area.parent)
    q.require(q.block_device(area.parent)==q.block_device(Path('/')),'Different physical device')
    reference=args.handoff_reference.absolute();q.native.private_area(reference)
    before=dict(trace=q.trace_state(),programs=q.programs(),qos=Path('/sys/class/nvme/nvme0/power/pm_qos_latency_tolerance_us').read_text().strip())
    q.require(before['qos']=='5000','Qualified power policy required');area.mkdir(mode=0o700)
    contract=build(area,reference);content=os.urandom(8192)*1024;fixtures={};expected=14695981039346656037
    for i in range(64):
        at=((i*37)%2048)*4096
        for byte in content[at:at+4096]:expected=((expected^byte)*1099511628211)&((1<<64)-1)
    expected=f'{expected:016x}'
    for name,nocow in [('plain.bin',True),('compressed.bin',False)]:
        path=area/name;fd=os.open(path,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        try:
            if nocow:
                flags=bytearray(8);fcntl.ioctl(fd,0x80086601,flags,True);fcntl.ioctl(fd,0x40086602,struct.pack('=Q',struct.unpack('=Q',flags)[0]|0x800000))
            with os.fdopen(os.dup(fd),'wb') as out:out.write(content);out.flush();os.fsync(out.fileno())
            spans=q.native.repack.extents(fd,len(content));encoded=sum(bool(flags&8) for _,_,flags in spans)
            q.require(bool(encoded)==(not nocow) and not any(flags&0x2000 for _,_,flags in spans),'Witness fixture encoding/sharing differs')
            fixtures[name]=dict(bytes=len(content),sha256=q.digest(path),encoded_extents=encoded,shared_extents=0)
        finally:os.close(fd)
    schedule=[(name,mode) for name in fixtures for mode in ('read','mmap')]
    contract.update(fixtures=fixtures,positive_schedule=schedule,positive_accesses=256,passes_per_worker=64,chunk_bytes=4096,
        offset_sequence='((pass*37)%2048)*4096',schedule_frozen_before_collection=True,active_program_count=31,pending_context_maps=14,
        duration_seconds=3,max_records=50000,ring_bytes=4*2**20,retain_bytes_limit=128*2**20,whole_application_critical_path_qualified=False,overhead_qualified=False)
    (area/'contract.json').write_text(json.dumps(contract,indent=2)+'\n')
    with (area/'contract.json').open('rb') as stream:os.fsync(stream.fileno())
    rows=[]
    try:
        for name,mode in schedule:rows.append(capture(area,area/name,name.split('.')[0]+'-'+mode+'-cold',mode,expected))
        rows.append(capture(area,area/'plain.bin','same-inode-wrong-open','read',expected,wrong=True))
        rows.append(capture(area,area/'plain.bin','witness-proof-disabled','read',expected,witness=False))
        rows.append(capture(area,area/'plain.bin','record-cap','read',expected,limit=4))
        rows.append(capture(area,area/'plain.bin','forced-exit','read',expected,kill=True))
    finally:
        (area/'completed-cases-private.json').write_text(json.dumps(rows,indent=2)+'\n')
        after=dict(trace=q.trace_state(),programs=q.programs(),qos=Path('/sys/class/nvme/nvme0/power/pm_qos_latency_tolerance_us').read_text().strip())
        for name,value in [('global-state-before-private.json',before),('global-state-after-private.json',after)]:
            (area/name).write_text(json.dumps(value,indent=2)+'\n')
        q.require(before==after,'Witness global state changed')
    for n,h in contract['source_sha256'].items():q.require(q.digest(ROOT/n)==h,'Witness source changed')
    for n,h in {**contract['inherited_input_sha256'],**contract['compiled_sha256']}.items():q.require(q.digest(area/n)==h,'Witness compiled input changed')
    for n,f in fixtures.items():q.require(q.digest(area/n)==f['sha256'],'Witness fixture changed')
    q.require(q.digest(reference/'result.json')==contract['reference_result_sha256'],'Handoff reference changed')
    q.require(sum(p.stat().st_size for p in area.iterdir() if p.is_file())<=128*2**20,'Witness retention bound exceeded')
    early=sum(row['validation']['early_wake_overlap_witness_segments'] for row in rows[:4])
    result=dict(kind='bc250-wake-witness-qualification',passed=True,case_count=8,cases=rows,contract=contract,
        all_owned_programs_gone=True,global_state_unchanged=True,independent_early_wake_segments=early,
        native_early_wake_overlap_observed=early>0,total_observer_cost_qualified=False,stage1_gate_passed=False,new_accelerator_gain_claimed=False)
    (area/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(dict(passed=True,cases=8,positive_accesses=256,early_wake_overlap_segments=early)),flush=True)


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('step',choices=('run','_host'))
    p.add_argument('--handoff-reference',type=Path,required=True);p.add_argument('--output',type=Path,required=True);args=p.parse_args()
    q.require(sys.platform=='linux' and os.geteuid()==0,'Linux root required')
    if args.step=='_host':host(args);return
    unit='bc250-wake-witness-'+uuid.uuid4().hex[:12]
    subprocess.run(['systemd-run','--quiet','--wait','--pipe','--collect','--unit='+unit,'--property=MemoryMax=2G','--property=MemorySwapMax=0',
        '--property=CPUQuota=200%','--property=TasksMax=128','--property=RuntimeMaxSec=180','--property=KillMode=control-group',
        '/usr/bin/unshare','--mount','--propagation','private','/usr/bin/python3','-B',str(Path(__file__).resolve()),'_host',
        '--handoff-reference',str(args.handoff_reference),'--output',str(args.output)],check=True,timeout=210)


if __name__=='__main__':main()
