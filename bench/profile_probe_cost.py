#!/usr/bin/env python3
"""Finite accounting-only profile of the exact qualified handoff BPF binary."""
import argparse,ctypes,fcntl,hashlib,json,os,random,re,shutil,struct,subprocess,sys,time,uuid
from pathlib import Path
import qualify_handoff_wait as handoff
from probe_cost import analyze

q=handoff.q;ROOT=handoff.ROOT;base=handoff.full.base


class Sample(ctypes.Structure):
    _fields_=[(n,ctypes.c_uint64) for n in ('begin_ns','end_ns','run_time_ns','run_cnt','recursion_misses')]+[(n,ctypes.c_uint32) for n in ('id','type','info_length','xlated_bytes')]+[('name',ctypes.c_char*16)]


def library(path):
    lib=ctypes.CDLL(str(path),use_errno=True)
    lib.bc_sample_size.argtypes=[];lib.bc_sample_size.restype=ctypes.c_uint
    lib.bc_stats_open.argtypes=[];lib.bc_stats_open.restype=ctypes.c_int
    lib.bc_program_open.argtypes=[ctypes.c_uint32];lib.bc_program_open.restype=ctypes.c_int
    lib.bc_snapshot.argtypes=[ctypes.c_int,ctypes.c_uint32,ctypes.POINTER(Sample)];lib.bc_snapshot.restype=ctypes.c_int
    q.require(lib.bc_sample_size()==ctypes.sizeof(Sample),'Profiling sample ABI differs');return lib


def snapshot(lib,fd,identity):
    s=Sample();q.require(lib.bc_snapshot(fd,identity,ctypes.byref(s))==0,'Owned counter snapshot failed: '+str(ctypes.get_errno()))
    return {n:(bytes(s.name).decode('ascii') if n=='name' else getattr(s,n)) for n,_ in Sample._fields_}


def kernel_audit():
    image=Path('/usr/lib/modules')/os.uname().release/'build/vmlinux'
    sha=q.digest(image);q.require(sha=='005da4aa166074a976656923f4a736ac83ae457883c636e54b4b4f859bb78408','Unaudited kernel image')
    notes=Path('/sys/kernel/notes').read_bytes();pos=0;live=[]
    while pos+12<=len(notes):
        ns,ds,kind=struct.unpack_from('<III',notes,pos);pos+=12;q.require(ns<2**20 and ds<2**20,'Kernel note bound')
        name=notes[pos:pos+ns].rstrip(b'\0');pos+=(ns+3)&~3;desc=notes[pos:pos+ds];pos+=(ds+3)&~3
        if name==b'GNU' and kind==3:live.append(desc.hex())
    ids=re.findall(r'Build ID: ([a-f0-9]+)',q.command('readelf','-n',str(image),timeout=30));q.require(len(ids)==1 and ids==live,'Installed/running image differs')
    symbols={line.split()[-1]:line.split()[0] for line in q.command('nm',str(image),timeout=30).splitlines() if len(line.split())==3}
    key='0x'+symbols['bpf_stats_enabled_key'];fops='0x'+symbols['bpf_stats_fops']
    release=q.command('objdump','-d','--no-show-raw-insn','--disassemble=bpf_stats_release',str(image),timeout=30)
    enable=q.command('objdump','-d','--no-show-raw-insn','--disassemble=__sys_bpf',str(image),timeout=30)
    q.require(key in release and '<static_key_slow_dec>' in release,'Unknown stats release implementation')
    pattern=re.escape(fops)+r'.{0,250}<anon_inode_getfd>.{0,400}'+re.escape(key)+r'.{0,250}<static_key_slow_inc>'
    q.require(re.search(pattern,enable,re.S) is not None,'Unknown stats descriptor enable implementation')
    return dict(image_sha256=sha,running_image_build_id_matches=True,shared_reference_enable_release_audited=True,
        installed_sysctl_before=Path('/proc/sys/kernel/bpf_stats_enabled').read_text().strip(),sysctl_is_not_a_census_of_other_stats_descriptors=True)


def build(area,reference):
    old=json.loads((reference/'result.json').read_text());q.require(old['kind']=='bc250-handoff-wait-qualification' and old['handoff_wait_controls_passed'],'Qualified handoff reference required')
    q.require(old['contract']['kernel']==os.uname().release,'Reference kernel differs')
    for n,h in old['contract']['source_sha256'].items():q.require(q.digest(ROOT/n)==h,'Frozen handoff source changed: '+n)
    for n,h in {**old['compiled_sha256'],**old['extension']['compiled_sha256']}.items():q.require(q.digest(reference/n)==h,'Qualified binary changed: '+n)
    for n in ('handoff-wait','handoff_wait.bpf.o','read-lineage-probe'):shutil.copyfile(reference/n,area/n);(area/n).chmod(0o700)
    text=(reference/'handoff_wait.generated.c').read_text();match=re.search(r'const char \*names\[\]=\{([^;]+)\};',text)
    q.require(match is not None,'Qualified attach list absent');names=re.findall(r'"([a-z_]+)"',match[1]);q.require(len(names)==len(set(names))==28,'Exact qualified attach list required')
    for n in ('bench/probe_cost_stats.c','bench/profile_probe_cost.py','analysis/probe_cost.py'):shutil.copyfile(ROOT/n,area/Path(n).name)
    with (area/'stats-build.log').open('x') as out:subprocess.run(['gcc','-O2','-Wall','-Wextra','-Werror','-shared','-fPIC','probe_cost_stats.c','-o','probe-cost-stats.so','-lbpf'],cwd=area,stdout=out,stderr=subprocess.STDOUT,check=True,timeout=60)
    audit=kernel_audit();lib=library(area/'probe-cost-stats.so')
    bad=Sample();q.require(lib.bc_snapshot(-1,1,ctypes.byref(bad))<0,'Bad-descriptor control accepted')
    return names,lib,dict(reference_result_sha256=q.digest(reference/'result.json'),reference_kind=old['kind'],kernel_audit=audit,
        source_sha256={n:q.digest(ROOT/n) for n in ('bench/profile_probe_cost.py','bench/probe_cost_stats.c','analysis/probe_cost.py')},
        compiled_sha256={n:q.digest(area/n) for n in ('handoff-wait','handoff_wait.bpf.o','read-lineage-probe','probe-cost-stats.so')},
        qualified_attach_list_sha256=q.digest(reference/'handoff_wait.generated.c'),program_names=names,bad_descriptor_rejected=True)


def holder_control(area):
    code='import ctypes,os,sys;lib=ctypes.CDLL(sys.argv[1]);lib.bc_stats_open.restype=ctypes.c_int;fd=lib.bc_stats_open();assert fd>=0;print(fd,flush=True);os.read(0,1)'
    p=subprocess.Popen(['/usr/bin/python3','-B','-c',code,str(area/'probe-cost-stats.so')],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    try:
        fd=int(base.line(p).strip());link=Path('/proc')/str(p.pid)/'fd'/str(fd)
        q.require('bpf-stats' in str(link.readlink()),'Stats holder did not own descriptor')
        p.kill();p.communicate(timeout=5);q.require(p.returncode<0 and not link.exists(),'Killed holder descriptor remains')
        return dict(killed_owned_holder_descriptor_closed=True,no_unrelated_descriptors_closed=True)
    finally:
        if p.poll() is None:p.kill();p.communicate(timeout=5)


def capture(area,path,label,mode,active,expected,names,lib,order):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW);worker=subprocess.Popen([str(area/'read-lineage-probe'),str(fd),mode],pass_fds=(fd,),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    trace=None;ids=[];statsfd=-1;programfds=[];closed=False;work=None
    before={};after={};start=None;finish=None;recorded=False
    try:
        q.require(base.line(worker)==b'BC250_READ_WORKER_READY\n','Profile worker handshake absent')
        trace,ids,log=handoff.start(area,worker.pid,fd,50000,True,True,True,True)
        q.require(q.residency(path,evict=True)==0,'Final private data not cold')
        statsfd=lib.bc_stats_open();q.require(statsfd>=0,'Runtime accounting unavailable')
        start=time.monotonic_ns();q.require(fcntl.fcntl(statsfd,fcntl.F_GETFD)&fcntl.FD_CLOEXEC,'Stats reference can leak across exec')
        q.require('bpf-stats' in str(Path('/proc/self/fd',str(statsfd)).readlink()),'Unexpected statistics handle')
        for identity in ids:
            handle=lib.bc_program_open(identity);q.require(handle>=0,'Owned program reference unavailable');programfds.append(handle)
        before={i:snapshot(lib,programfds[i],ids[i]) for i in order}
        hold_start=time.monotonic_ns();target=hold_start+10**9
        if active:
            worker.stdin.write(b'G');worker.stdin.flush();work=json.loads(base.line(worker))
            q.require(work['passed'] and work['logical_bytes']==2*2**20 and work['fnv64']==expected,'Profile worker content failed')
        time.sleep(max(0,(target-time.monotonic_ns())/10**9))
        after={i:snapshot(lib,programfds[i],ids[i]) for i in reversed(order)}
        finish=time.monotonic_ns();q.require(trace.poll() is None,'Profile observer ended before counters')
        os.close(statsfd);statsfd=-1;closed=True
        for handle in programfds:os.close(handle)
        programfds=[]
        owned=[dict(id=identity,name=name) for identity,name in zip(ids,names)]
        pairs=[dict(before=before[i],after=after[i]) for i in range(28)]
        (area/(label+'-accounting-private.json')).write_text(json.dumps(dict(owned=owned,samples=pairs,profile_start_ns=start,profile_finish_ns=finish,worker=work),indent=2)+'\n')
        summary=analyze(pairs,owned,start,finish,(work['start_ns'],work['finish_ns']) if work else None)
        q.require(summary['aggregate_owned_runtime_ns']>0 and summary['aggregate_owned_invocations']>0,'No runtime accounting observed')
        out,err=trace.communicate(timeout=10);log+=err
        q.require(len(out)+len(log)<16*2**20,'Profile capture storage bound')
        (area/(label+'-raw-private.json')).write_bytes(out);(area/(label+'-loader-private.log')).write_bytes(log)
        raw=json.loads(out);v=handoff.validate(raw)
        q.require(trace.returncode==0 and q.absent(ids) and worker.poll() is None,'Profile observer/pinned worker lifetime failed')
        if active:
            q.require(raw['start_ns']<=work['start_ns']<work['finish_ns']<=raw['finish_ns'],'Profile worker outside capture')
            causal_quality=bool(v['stream_quality_passed'] and v['demand_attempts']>0 and v['resolved_request_folio_blocked_segments']>0)
        else:
            q.require(raw['events']==0 and v['stream_quality_passed'],'Owned idle slot emitted selected events')
            causal_quality=True
            worker.stdin.write(b'G');worker.stdin.flush();work=json.loads(base.line(worker))
            q.require(work['passed'] and work['logical_bytes']==2*2**20 and work['fnv64']==expected and work['start_ns']>raw['detached_ns'],'Idle validation read leaked into profile')
        worker.stdin.write(b'D');worker.stdin.flush();worker.communicate(timeout=5);q.require(worker.returncode==0,'Profile worker normal close failed')
        row=dict(label=label,mode=mode,active=active,profile_start_ns=start,profile_finish_ns=finish,hold_start_ns=hold_start,
            intended_hold_ns=10**9,owned=owned,samples=pairs,summary=summary,validation=v,worker=work,
            causal_quality_passed=causal_quality,
            statistics_reference_closed=closed,all_owned_program_references_closed=True,all_owned_programs_detached=True)
        (area/(label+'-profile-private.json')).write_text(json.dumps(row,indent=2)+'\n')
        recorded=True
        return row
    finally:
        if statsfd>=0:os.close(statsfd)
        for handle in programfds:os.close(handle)
        if trace:q.finish(trace);q.require(q.absent(ids),'Owned profile probes remain')
        if worker.poll() is None:worker.kill();worker.communicate(timeout=5)
        os.close(fd)
        if not recorded:
            (area/(label+'-partial-accounting-private.json')).write_text(json.dumps(dict(owned_ids=ids,before=before,after=after,profile_start_ns=start,profile_finish_ns=finish,worker=work,complete=False),indent=2)+'\n')


def host(args):
    q.native.confined();area=args.output.absolute();q.native.private_area(area,creating=True);q.native.host_space(area.parent)
    q.require(q.block_device(area.parent)==q.block_device(Path('/')),'Different physical device')
    reference=args.handoff_reference.absolute();q.native.private_area(reference)
    def state():return dict(trace=q.trace_state(),programs=q.programs(),qos=Path('/sys/class/nvme/nvme0/power/pm_qos_latency_tolerance_us').read_text().strip(),stats_sysctl=Path('/proc/sys/kernel/bpf_stats_enabled').read_text().strip())
    before=state();q.require(before['qos']=='5000','Qualified power policy required');area.mkdir(mode=0o700)
    names,lib,contract=build(area,reference)
    fixtures={}
    for name in ('plain.bin','compressed.bin'):
        content=(reference/name).read_bytes();path=area/name;fd=os.open(path,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        try:
            if name=='plain.bin':
                flags=bytearray(8);fcntl.ioctl(fd,0x80086601,flags,True);fcntl.ioctl(fd,0x40086602,struct.pack('=Q',struct.unpack('=Q',flags)[0]|0x800000))
            with os.fdopen(os.dup(fd),'wb') as out:out.write(content);out.flush();os.fsync(out.fileno())
            spans=q.native.repack.extents(fd,len(content));encoded=sum(bool(flags&8) for _,_,flags in spans)
            q.require(bool(encoded)==(name=='compressed.bin') and not any(flags&0x2000 for _,_,flags in spans),'Profile fixture encoding/sharing differs')
            fixtures[name]=dict(sha256=q.digest(path),bytes=len(content),encoded_extents=encoded,shared_extents=0)
        finally:os.close(fd)
    rng=random.Random(256);blocks=[(name,mode,order) for name in fixtures for mode in ('read','mmap') for order in ((True,False),(False,True))];rng.shuffle(blocks)
    schedule=[]
    for name,mode,arms in blocks:
        for active in arms:
            order=list(range(28));rng.shuffle(order);schedule.append(dict(fixture=name,mode=mode,active=active,program_snapshot_order=order))
    contract.update(fixtures=fixtures,schedule=schedule,schedule_seed=256,fixed_slots=16,work_slots=8,idle_slots=8,
        intended_hold_ns=10**9,stats_scope='Shared kernel accounting reference; retain only owned program counters',
        profiling_overhead_present=True,snapshot_windows_are_not_simultaneous=True,qualified_bpf_binary_reused=True,endpoint_speed_comparison=False)
    (area/'contract.json').write_text(json.dumps(contract,indent=2)+'\n')
    with (area/'contract.json').open('rb') as stream:os.fsync(stream.fileno())
    controls=holder_control(area);rows=[]
    expected=14695981039346656037
    for byte in (area/'plain.bin').read_bytes()[:2*2**20]:expected=((expected^byte)*1099511628211)&((1<<64)-1)
    expected=f'{expected:016x}'
    try:
        for i,slot in enumerate(schedule):rows.append(capture(area,area/slot['fixture'],'slot-%02d'%i,slot['mode'],slot['active'],expected,names,lib,slot['program_snapshot_order']))
    finally:
        (area/'completed-profiles-private.json').write_text(json.dumps(rows,indent=2)+'\n');after=state()
        for name,value in [('global-state-before-private.json',before),('global-state-after-private.json',after)]:
            (area/name).write_text(json.dumps(value,indent=2)+'\n')
        q.require(before==after,'Profile changed shared state')
    for n,h in contract['source_sha256'].items():q.require(q.digest(ROOT/n)==h,'Profile source changed')
    for n,h in contract['compiled_sha256'].items():q.require(q.digest(area/n)==h,'Profile binary changed')
    for n,f in fixtures.items():q.require(q.digest(area/n)==f['sha256'],'Profile fixture changed')
    q.require(q.digest(reference/'result.json')==contract['reference_result_sha256'],'Handoff reference changed')
    q.require(sum(p.stat().st_size for p in area.iterdir() if p.is_file())<=128*2**20,'Profile retention bound exceeded')
    result=dict(kind='bc250-probe-cost-profile',collection_complete=True,slots=len(rows),contract=contract,controls=controls,profiles=rows,
        all_owned_handles_closed=True,shared_state_unchanged=True,all_accounting_screens_passed=all(r['summary']['accounting_quality_passed'] for r in rows),
        all_causal_screens_passed=all(r['causal_quality_passed'] for r in rows),
        new_accelerator_gain_claimed=False,endpoint_speed_comparison=False,stage1_gate_passed=False)
    (area/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(dict(complete=True,slots=16,accounting_screens_passed=result['all_accounting_screens_passed'])),flush=True)


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('step',choices=('run','_host'));p.add_argument('--handoff-reference',type=Path,required=True);p.add_argument('--output',type=Path,required=True);args=p.parse_args()
    q.require(sys.platform=='linux' and os.geteuid()==0,'Linux root required')
    if args.step=='_host':host(args);return
    unit='bc250-probe-cost-'+uuid.uuid4().hex[:12]
    subprocess.run(['systemd-run','--quiet','--wait','--pipe','--collect','--unit='+unit,'--property=MemoryMax=2G','--property=MemorySwapMax=0','--property=CPUQuota=200%',
        '--property=TasksMax=128','--property=RuntimeMaxSec=180','--property=KillMode=control-group','/usr/bin/unshare','--mount','--propagation','private',
        '/usr/bin/python3','-B',str(Path(__file__).resolve()),'_host','--handoff-reference',str(args.handoff_reference),'--output',str(args.output)],check=True,timeout=210)


if __name__=='__main__':main()
