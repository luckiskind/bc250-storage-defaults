#!/usr/bin/env python3
"""Bounded task-storage capability and lifecycle controls; no speed claim."""
import argparse,fcntl,json,os,re,select,shutil,signal,struct,subprocess,sys,time,uuid
from pathlib import Path
import qualify_read_lineage as read
from task_context import validate
q=read.q;ROOT=read.ROOT


def build(area,reference):
    old=json.loads((reference/'result.json').read_text());q.require(old['kind']=='bc250-handoff-wait-qualification' and old['handoff_wait_controls_passed'],'Frozen handoff reference required')
    q.require(old['contract']['kernel']==os.uname().release and os.uname().machine=='x86_64','Qualified kernel/marker ABI required')
    for n,h in old['contract']['source_sha256'].items():q.require(q.digest(ROOT/n)==h,'Frozen source changed: '+n)
    for n,h in {**old['compiled_sha256'],**old['extension']['compiled_sha256']}.items():q.require(q.digest(reference/n)==h,'Frozen binary changed: '+n)
    own=('task_context_feature.bpf.c','task_context_feature.c','task_context_worker.c','qualify_task_context.py')
    for n in own:shutil.copyfile(ROOT/'bench'/n,area/n)
    shutil.copyfile(ROOT/'analysis/task_context.py',area/'task_context.py')
    with (area/'vmlinux.h').open('x') as out:subprocess.run(['bpftool','btf','dump','file','/sys/kernel/btf/vmlinux','format','c'],stdout=out,check=True,timeout=30)
    raw=json.loads(q.command('bpftool','-j','btf','dump','file','/sys/kernel/btf/vmlinux','format','raw',timeout=30));types={v['id']:v for v in raw['types']}
    expected={'io_schedule':('void',[]),'btf_trace_sched_switch':('void',['*void','_Bool','*task_struct','*task_struct','unsigned int']),
        'btf_trace_sched_waking':('void',['*void','*task_struct']),'btf_trace_sched_wakeup':('void',['*void','*task_struct']),
        'btf_trace_sys_enter':('void',['*void','*pt_regs','long int'])};abi={}
    for name,want in expected.items():
        found=[v for v in types.values() if v['kind'] in ('FUNC','TYPEDEF') and v['name']==name];q.require(len(found)==1,'Missing/ambiguous task-context ABI: '+name)
        p=types[found[0]['type_id']]
        for _ in range(8):
            if p['kind']=='FUNC_PROTO':break
            p=types[p['type_id']]
        actual=(read.shape(types,p['ret_type_id']),[read.shape(types,x['type_id']) for x in p['params']])
        q.require(actual==want,'Task-context ABI differs: '+name);abi[name]=actual
    commands=[['clang','-g','-O2','-Wall','-Werror','-target','bpf','-mcpu=v3','-D__TARGET_ARCH_x86','-I.','-c','task_context_feature.bpf.c','-o','task_context_feature.bpf.o'],
        ['gcc','-g','-O2','-Wall','-Wextra','-Werror','task_context_feature.c','-o','task-context-feature','-lbpf','-lelf','-lz'],
        ['gcc','-O2','-Wall','-Wextra','-Werror','-pthread','task_context_worker.c','-o','task-context-worker']]
    for i,command in enumerate(commands):
        with (area/('task-context-build-%d.log'%i)).open('x') as out:subprocess.run(command,cwd=area,stdout=out,stderr=subprocess.STDOUT,check=True,timeout=60)
    return dict(reference_result_sha256=q.digest(reference/'result.json'),source_sha256={n:q.digest(ROOT/n) for n in ['bench/'+s for s in own]+['analysis/task_context.py']},
        compiled_sha256={n:q.digest(area/n) for n in ('task-context-feature','task_context_feature.bpf.o','task-context-worker')},verified_function_abi=abi,
        vmlinux_header_sha256=q.digest(area/'vmlinux.h'),active_programs=6,task_storage_map_count=1,independent_expected_hash_retained=True,
        task_or_thread_ids_exported=False,control_marker_syscalls_are_read_only=True,observer_cost_qualified=False,io_causality_qualified=False)


def start(area,pid,create,control,limit):
    p=subprocess.Popen([str(area/'task-context-feature'),str(area/'task_context_feature.bpf.o'),str(pid),str(int(create)),str(int(control)),'3',str(limit)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    os.set_blocking(p.stderr.fileno(),False);log=b'';deadline=time.monotonic()+15
    try:
        while time.monotonic()<deadline:
            if select.select([p.stderr],[],[],.1)[0]:
                log+=os.read(p.stderr.fileno(),65536);q.require(len(log)<2**20,'Task-context loader log bound')
                for line in log.split(b'\n')[:-1]:
                    if line.startswith(b'BC250_TASK_CONTEXT_READY '):
                        ids=json.loads(line.split(b' ',1)[1])['program_ids'];q.require(len(ids)==len(set(ids))==6 and all(type(n) is int and n>0 for n in ids),'Six owned IDs required');return p,ids,log
            q.require(p.poll() is None,'Task-context attach failed: '+log.decode(errors='replace')[-3500:])
        raise RuntimeError('Task-context readiness deadline')
    except BaseException:
        q.finish(p);(area/'failed-start-private.log').write_bytes(log);raise


def capture(area,label,kind,mode,threads,expected,create=True,limit=32768,kill_worker=False,kill_observer=False):
    paths=[area/(kind+'-'+str(i)+'.bin') for i in (0,1)];fds=[os.open(p,os.O_RDONLY|os.O_NOFOLLOW) for p in paths]
    worker=subprocess.Popen([str(area/'task-context-worker'),str(fds[0]),str(fds[1]),mode,str(threads)],pass_fds=tuple(fds),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    trace=None;ids=[];work=None;control=mode in ('hold','none')
    try:
        q.require(read.line(worker)==b'BC250_TASK_WORKER_READY\n','Task worker handshake absent')
        trace,ids,log=start(area,worker.pid,create,control,limit)
        worker.stdin.write(b'G');worker.stdin.flush()
        if control:
            q.require(read.line(worker)==b'BC250_TASK_CONTEXTS_HELD\n','Task marker barrier absent');time.sleep(.15)
            if kill_worker:worker.kill();worker.communicate(timeout=5);q.require(worker.returncode<0,'Worker death control failed')
            elif kill_observer:
                trace.kill();trace.communicate(timeout=5);q.require(q.absent(ids),'Forced observer left programs')
                worker.stdin.write(b'D');worker.stdin.flush();work=json.loads(read.line(worker));worker.communicate(timeout=5)
                q.require(work['passed'] and worker.returncode==0,'Held worker cleanup failed')
                return dict(case=label,passed=True,forced_observer_exit=True,owned_programs_gone=True)
            else:
                worker.stdin.write(b'D');worker.stdin.flush();work=json.loads(read.line(worker));worker.communicate(timeout=5);q.require(worker.returncode==0,'Marker worker close failed')
        else:
            work=json.loads(read.line(worker));q.require(work['passed'] and work['threads']==threads and work['passes_per_thread']==8 and work['logical_bytes']==threads*8*2*2**20,'Task worker read contract failed')
            q.require(work['cold_checks'][:threads]==[8]*threads and work['hashes'][:threads]==[expected]*threads,'Task worker cache/content control failed')
        out,err=trace.communicate(timeout=10);log+=err;q.require(len(out)+len(log)<8*2**20,'Task-context output bound')
        (area/(label+'-raw-private.json')).write_bytes(out);(area/(label+'-loader-private.log')).write_bytes(log)
        q.require(trace.returncode==0 and q.absent(ids),'Task-context loader cleanup failed')
        raw=json.loads(out);v=validate(raw)
        if kill_worker:q.require(v['transport_complete'] and not v['contexts_complete'] and v['pending_expected']==v['active_ledger']==2 and not v['stream_quality_passed'],'Task destruction manufactured closure')
        elif limit<32768:q.require(raw['limit_reached'] and not v['transport_complete'],'Feature cap not explicit')
        elif not create:q.require(not v['stream_quality_passed'] and v['task_storage_creations']==v['task_storage_deletions']==0 and v['contexts_complete'],'Creation omission not detected')
        elif mode=='none':q.require(v['stream_quality_passed'] and raw['events']==v['context_entries']==v['threads_observed']==0,'No-slot control differs')
        else:
            q.require(v['stream_quality_passed'] and v['threads_observed']==threads and v['scheduler_observations']>0,'Task-local capability/identity absent')
            if mode=='hold':q.require(v['context_entries']==v['context_returns']==threads and v['max_simultaneous_contexts']==2,'Two-task coexistence absent')
            else:q.require(v['blocked_switch_outs']>0 and v['context_entries']>=8*threads,'Native I/O sleep path absent')
        if not control:
            q.require(worker.poll() is None,'Task worker lifetime ended early');worker.stdin.write(b'D');worker.stdin.flush();worker.communicate(timeout=5);q.require(worker.returncode==0,'I/O worker close failed')
        return dict(case=label,passed=True,mode=mode,threads=threads,creation_enabled=create,intended_incomplete=limit<32768,
            intended_worker_exit=kill_worker,controlled_marker=control,worker=work,validation=v,owned_programs_gone=True)
    except BaseException:
        if trace:
            if trace.poll() is None:trace.send_signal(signal.SIGINT)
            try:
                out,err=trace.communicate(timeout=5)
                (area/(label+'-failed-raw-private.json')).write_bytes(out);(area/(label+'-failed-loader-private.log')).write_bytes(err)
            except subprocess.TimeoutExpired:trace.kill();trace.communicate(timeout=5)
        if worker.poll() is None:worker.kill()
        out,err=worker.communicate(timeout=5)
        (area/(label+'-failed-worker-private.json')).write_text(json.dumps(dict(returncode=worker.returncode,stdout=out.decode(errors='replace')[-3000:],stderr=err.decode(errors='replace')[-3000:]),indent=2)+'\n')
        raise
    finally:
        if trace:q.finish(trace);q.require(q.absent(ids),'Owned feature programs remain')
        if worker.poll() is None:worker.kill();worker.communicate(timeout=5)
        for fd in fds:os.close(fd)


def host(args):
    q.native.confined();area=args.output.absolute();q.native.private_area(area,creating=True);q.native.host_space(area.parent)
    q.require(q.block_device(area.parent)==q.block_device(Path('/')),'Different physical device');reference=args.handoff_reference.absolute();q.native.private_area(reference)
    def state():return dict(trace=q.trace_state(),programs=q.programs(),qos=Path('/sys/class/nvme/nvme0/power/pm_qos_latency_tolerance_us').read_text().strip())
    before=state();q.require(before['qos']=='5000','Qualified power policy required');area.mkdir(mode=0o700);contract=build(area,reference)
    content=os.urandom(8192)*1024;expected=14695981039346656037
    for byte in content[:2*2**20]:expected=((expected^byte)*1099511628211)&((1<<64)-1)
    expected=f'{expected:016x}';fixtures={}
    for kind in ('plain','encoded'):
        for i in (0,1):
            name=kind+'-'+str(i)+'.bin';path=area/name;fd=os.open(path,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            try:
                if kind=='plain':
                    flags=bytearray(8);fcntl.ioctl(fd,0x80086601,flags,True);fcntl.ioctl(fd,0x40086602,struct.pack('=Q',struct.unpack('=Q',flags)[0]|0x800000))
                with os.fdopen(os.dup(fd),'wb') as out:out.write(content);out.flush();os.fsync(out.fileno())
                spans=q.native.repack.extents(fd,len(content));encoded=sum(bool(flags&8) for _,_,flags in spans)
                q.require(bool(encoded)==(kind=='encoded') and not any(flags&0x2000 for _,_,flags in spans),'Task-context fixture encoding/sharing differs')
                fixtures[name]=dict(bytes=len(content),sha256=q.digest(path),encoded_extents=encoded,shared_extents=0)
            finally:os.close(fd)
    schedule=[dict(label=kind+'-'+mode,kind=kind,mode=mode,threads=1) for kind in ('plain','encoded') for mode in ('read','mmap')]
    schedule += [dict(label='two-thread-read',kind='plain',mode='read',threads=2),dict(label='two-thread-held',kind='plain',mode='hold',threads=2),
        dict(label='creation-omitted',kind='plain',mode='hold',threads=2,create=False),dict(label='no-slot',kind='plain',mode='none',threads=2),
        dict(label='worker-exit-held',kind='plain',mode='hold',threads=2,kill_worker=True),dict(label='observer-forced-exit',kind='plain',mode='hold',threads=2,kill_observer=True),
        dict(label='record-cap',kind='plain',mode='hold',threads=2,limit=2)]
    contract.update(fixtures=fixtures,schedule=schedule,case_count=11,schedule_frozen_before_collection=True,kernel=os.uname().release,
        duration_seconds=3,ring_bytes=4*2**20,max_records=32768,retain_bytes_limit=128*2**20,
        mapped_worker_advice='MADV_RANDOM on private mapping; full 2 MiB demand retained',
        record_budget_reason='More individual cold faults after disabling mapping read-ahead; no performance comparison')
    (area/'contract.json').write_text(json.dumps(contract,indent=2)+'\n')
    with (area/'contract.json').open('rb') as stream:os.fsync(stream.fileno())
    rows=[]
    try:
        for case in schedule:rows.append(capture(area,expected=expected,**case))
    finally:
        (area/'completed-cases-private.json').write_text(json.dumps(rows,indent=2)+'\n');after=state()
        for name,value in [('global-state-before-private.json',before),('global-state-after-private.json',after)]:
            (area/name).write_text(json.dumps(value,indent=2)+'\n')
        q.require(before==after,'Task-context shared state changed')
    for n,h in contract['source_sha256'].items():q.require(q.digest(ROOT/n)==h,'Feature source changed')
    for n,h in contract['compiled_sha256'].items():q.require(q.digest(area/n)==h,'Feature binary changed')
    for n,f in fixtures.items():q.require(q.digest(area/n)==f['sha256'],'Feature fixture changed')
    q.require(q.digest(reference/'result.json')==contract['reference_result_sha256'],'Handoff reference changed')
    q.require(sum(p.stat().st_size for p in area.iterdir() if p.is_file())<=128*2**20,'Feature retention bound')
    result=dict(kind='bc250-task-context-qualification',passed=True,case_count=len(rows),cases=rows,contract=contract,
        all_owned_programs_gone=True,shared_state_unchanged=True,task_storage_capability_controls_passed=True,
        full_observer_replacement_qualified=False,observer_cost_qualified=False,stage1_gate_passed=False,new_accelerator_gain_claimed=False)
    (area/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(dict(passed=True,cases=len(rows),task_storage_supported=True,observer_replacement_qualified=False)),flush=True)


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('step',choices=('run','_host'));p.add_argument('--handoff-reference',type=Path,required=True);p.add_argument('--output',type=Path,required=True);args=p.parse_args()
    q.require(sys.platform=='linux' and os.geteuid()==0,'Linux root required')
    if args.step=='_host':host(args);return
    unit='bc250-task-context-'+uuid.uuid4().hex[:12]
    subprocess.run(['systemd-run','--quiet','--wait','--pipe','--collect','--unit='+unit,'--property=MemoryMax=2G','--property=MemorySwapMax=0','--property=CPUQuota=200%',
        '--property=TasksMax=128','--property=RuntimeMaxSec=180','--property=KillMode=control-group','/usr/bin/unshare','--mount','--propagation','private',
        '/usr/bin/python3','-B',str(Path(__file__).resolve()),'_host','--handoff-reference',str(args.handoff_reference),'--output',str(args.output)],check=True,timeout=210)


if __name__=='__main__':main()
