#!/usr/bin/env python3
"""Private request-generation/member qualification; no system tuning changes."""
import argparse
import json
import os
from pathlib import Path
import select
import shutil
import subprocess
import sys
import time
import uuid
from unittest.mock import patch
import qualify_physical_bio_lineage as physical
from request_bio_loader import generate,ready_ids
from request_bio_lineage import validate

base=physical.base;q=base.q;ROOT=physical.ROOT


def build(area):
    names,observed=physical.extended_build(area)
    shutil.copyfile(area/'extension-contract.json',area/'physical-reference-build-contract.json')
    raw=json.loads(q.command('bpftool','-j','btf','dump','file','/sys/kernel/btf/vmlinux','format','raw',timeout=30));types={v['id']:v for v in raw['types']}
    for name in ('btf_trace_block_rq_issue','btf_trace_block_rq_requeue'):
        found=[v for v in types.values() if v['kind'] in ('FUNC','TYPEDEF') and v['name']==name];q.require(len(found)==1,'Missing/ambiguous request BTF')
        proto=types[found[0]['type_id']]
        for _ in range(8):
            if proto['kind']=='FUNC_PROTO':break
            proto=types[proto['type_id']]
        q.require(proto['kind']=='FUNC_PROTO','Unresolved request prototype')
        actual=(base.shape(types,proto['ret_type_id']),[base.shape(types,x['type_id']) for x in proto['params']])
        q.require(actual==('void',['*void','*request']),'Request ABI differs: '+name);observed[name]=dict(returns=actual[0],parameters=actual[1])
    own=('request_bio_lineage.bpf.c','request_bio_loader.py','qualify_request_bio_lineage.py','request_bio_repeat_probe.c')
    for name in own:shutil.copyfile(ROOT/'bench'/name,area/name)
    (area/'request_bio_lineage.generated.c').write_text(generate((area/'read_lineage.c').read_text()))
    commands=[['clang','-g','-O2','-Wall','-Werror','-target','bpf','-mcpu=v3','-D__TARGET_ARCH_x86','-I.','-c','request_bio_lineage.bpf.c','-o','request_bio_lineage.bpf.o'],
        ['gcc','-g','-O2','-Wall','-Wextra','-Werror','request_bio_lineage.generated.c','-o','request-bio-lineage','-lbpf','-lelf','-lz'],
        ['gcc','-g','-O2','-Wall','-Wextra','-Werror','request_bio_repeat_probe.c','-o','request-bio-repeat-probe']]
    for i,command in enumerate(commands):
        with (area/('request-build-%d.log'%i)).open('x') as out:subprocess.run(command,cwd=area,stdout=out,stderr=subprocess.STDOUT,check=True,timeout=60)
    contract=json.loads((area/'extension-contract.json').read_text())
    contract.update(source_sha256={**contract['source_sha256'],**{name:q.digest(ROOT/name) for name in ['bench/'+n for n in own]+['analysis/request_bio_lineage.py']}},
        generated_loader_sha256=q.digest(area/'request_bio_lineage.generated.c'),
        compiled_sha256={n:q.digest(area/n) for n in ('request-bio-lineage','request_bio_lineage.bpf.o','request-bio-repeat-probe')},
        verified_function_abi=observed,active_program_count=24,private_context_maps=9,
        reference_physical_completion_program_loaded=False,request_key='Private request object plus nonzero start_time_ns generation; anonymous output ID',
        issue_membership='Actual complete issue-time chain, at most 64 nodes, including unselected members',
        request_pointer_history_entries=4096,request_history_is_lifetime_registry_not_pending_context=True,
        serialized_reuse_worker=dict(passes=8,logical_bytes_per_pass=2097152,private_fixture_bytes=8388608,
            zero_resident_check_before_every_pass=True,between_pass_delay_ns=20000000,affinity='One inherited allowed CPU, repeat worker only'),
        physical_bio_request_edges_qualified=False,merge_history_qualified=False,overhead_qualified=False)
    (area/'extension-contract.json').write_text(json.dumps(contract,indent=2)+'\n')
    with (area/'extension-contract.json').open('rb') as stream:os.fsync(stream.fileno())
    return (*names,*own),observed


def start(area,pid,fd,limit,proof,issue):
    proc=subprocess.Popen([str(area/'request-bio-lineage'),str(area/'request_bio_lineage.bpf.o'),str(pid),str(fd),'3',str(limit),str(int(proof)),str(q.block_device(area)),str(int(issue))],
        stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    os.set_blocking(proc.stderr.fileno(),False);log=b'';deadline=time.monotonic()+15;seeded=False
    try:
        while time.monotonic()<deadline:
            if select.select([proc.stderr],[],[],.1)[0]:
                log+=os.read(proc.stderr.fileno(),65536);q.require(len(log)<2**20,'Bounded request loader log')
                if not seeded and b'BC250_PHYSICAL_SEED_READY\n' in log:
                    seed=area/'compressed.bin';q.require(q.residency(seed,evict=True)==0,'Private calibration not cold');q.digest(seed)
                    proc.stdin.write(b'G');proc.stdin.flush();seeded=True
                ids=ready_ids(log)
                if ids is not None:q.require(seeded,'Calibration handshake missing');return proc,ids,log
            q.require(proc.poll() is None,'Request attach/calibration failed: '+log.decode(errors='replace')[-3000:])
        raise RuntimeError('Request readiness deadline')
    except BaseException:
        q.finish(proc);(area/'request-failed-start-private.log').write_bytes(log);raise


def capture(area,path,label,mode,warm,expected_hash,wrong_fd=False,limit=50000,kill=False,proof=True,issue=True):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW);other=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    repeat=mode=='repeat';logical_bytes=(8 if repeat else 1)*2*2**20
    worker=subprocess.Popen([str(area/('request-bio-repeat-probe' if repeat else 'read-lineage-probe')),str(fd),mode],pass_fds=(fd,other),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    trace=None;ids=[];log=b''
    try:
        q.require(base.line(worker)==b'BC250_READ_WORKER_READY\n','Worker not ready')
        if repeat:
            affinity={min(os.sched_getaffinity(0))};os.sched_setaffinity(worker.pid,affinity);q.require(os.sched_getaffinity(worker.pid)==affinity,'Repeat worker affinity differs')
        trace,ids,log=start(area,worker.pid,other if wrong_fd else fd,limit,proof,issue)
        if warm:q.digest(path)
        resident=q.residency(path,evict=not warm);q.require(resident==(path.stat().st_size if warm else 0),'Final private cache state differs')
        if kill:
            trace.kill();trace.communicate(timeout=5);q.require(q.absent(ids),'Forced exit left programs')
            return dict(case=label,passed=True,forced_exit=True,owned_programs_gone=True)
        worker.stdin.write(b'G');worker.stdin.flush();work=json.loads(base.line(worker));q.require(work['passed'] and work['logical_bytes']==logical_bytes and work['fnv64']==expected_hash,'Worker content/read failed')
        if repeat:q.require(work['passes']==work['zero_resident_checks']==8,'Repeat cold/content controls absent')
        out,err=trace.communicate(timeout=10);log+=err
        (area/(label+'-raw-private.json')).write_bytes(out);(area/(label+'-loader-private.log')).write_bytes(log)
        (area/(label+'-worker-private.json')).write_text(json.dumps(work,indent=2)+'\n')
        q.require(trace.returncode==0 and q.absent(ids) and worker.poll() is None,'Observer/pinned worker lifetime failed')
        raw=json.loads(out);result=validate(raw)
        q.require(raw['start_ns']<=work['start_ns']<work['finish_ns']<=raw['finish_ns'] or limit<50000,'Worker outside capture')
        if wrong_fd:q.require(raw['events']==0 and result['identity_rejections']>0,'Wrong-open identity negative failed')
        elif limit<50000:q.require(raw['limit_reached'] and not result['transport_complete'],'Cap not explicit')
        elif not proof:q.require(not result['stream_quality_passed'] and result['uncovered_original_bios']>0 and raw['physical_counters'][2]>0,'Callback-proof negative failed')
        elif not issue:q.require(not result['stream_quality_passed'] and result['request_uncovered_physical_bios']>0 and raw['request_counters'][7]>0 and raw['request_counters'][14]>0,'Issue-proof negative failed')
        else:
            q.require(result['stream_quality_passed'] and result['demand_attempts']>0,'Request generation quality/coverage failed')
            if mode in ('read','repeat'):q.require(result['buffered_read_returned_bytes']==work['logical_bytes'],'Buffered return differs')
            if warm:q.require(result['original_data_bios']==result['physical_root_bios']==result['request_generations']==0,'Warm path submitted data')
            else:
                q.require(result['selected_physical_bio_request_generations_qualified'] and result['request_generations']>0,'Cold request identity absent')
                q.require(result['selected_request_members']==result['physical_bio_completions']>0 and result['selected_request_member_bytes']==result['physical_completed_bytes'],'Selected request/physical bytes differ')
                q.require(result['physical_root_bios']==result['original_data_bios']>0,'Original physical coverage absent')
                if repeat:q.require(result['request_address_reuses_with_changed_generation']>0 and result['request_generations']>=8,'Native changed-generation request reuse not exercised')
        worker.stdin.write(b'D');worker.stdin.flush();worker.communicate(timeout=5);q.require(worker.returncode==0,'Worker normal close failed')
        return dict(case=label,passed=True,mode=mode,warm=warm,resident_before_bytes=resident,validation=result,events=raw['events'],
            known_logical_bytes=work['logical_bytes'],content_checked=True,owned_programs_gone=True,pinned_descriptor_lifetime_verified=True,
            serialized_passes=8 if repeat else 1,repeat_private_zero_resident_checks=8 if repeat else 0,repeat_worker_affinity_verified=repeat,
            intended_incomplete=limit<50000,identity_negative=wrong_fd,callback_proof_enabled=proof,issue_proof_enabled=issue,
            intended_missing_proof=not proof or not issue,runtime_libbpf=raw['libbpf'])
    finally:
        if trace:q.finish(trace);q.require(q.absent(ids),'Owned request programs remain')
        if worker.poll() is None:worker.kill();worker.communicate(timeout=5)
        os.close(fd);os.close(other)


def host(args):
    refs={}
    for reference,count in [(args.reference,11),(args.physical_reference,12)]:
        reference=reference.absolute();q.native.private_area(reference);old=json.loads((reference/'result.json').read_text());q.require(old['passed'] and old['case_count']==count,'Qualified reference missing')
        for name,sha in old['contract']['source_sha256'].items():q.require(q.digest(ROOT/name)==sha,'Frozen source differs: '+name)
        hashes=dict(old['compiled_sha256']);hashes.update(old.get('extension',{}).get('compiled_sha256',{}))
        for name,sha in hashes.items():q.require(q.digest(reference/name)==sha,'Frozen reference binary differs')
        refs[reference.name]=q.digest(reference/'result.json')
    area=args.output.absolute();state,inventory=q.trace_state(),q.programs()
    with patch.object(base,'build',build),patch.object(base,'capture',capture):base.host(args)
    core=json.loads((area/'result.json').read_text());shutil.copyfile(area/'result.json',area/'shared-harness-result-private.json')
    extension=json.loads((area/'extension-contract.json').read_text());expected=json.loads((area/'compressed-read-cold-worker-private.json').read_text())['fnv64'];rows=list(core['cases'])
    try:
        rows.append(capture(area,area/'compressed.bin','callback-proof-disabled','read',False,expected,proof=False))
        rows.append(capture(area,area/'compressed.bin','issue-proof-disabled','read',False,expected,issue=False))
        rows.append(capture(area,area/'plain.bin','serialized-cold-reuse','repeat',False,expected))
    finally:
        (area/'extension-completed-cases.json').write_text(json.dumps(rows,indent=2)+'\n');q.require(q.trace_state()==state and q.programs()==inventory,'Global tracing/program inventory changed')
    for name,sha in extension['source_sha256'].items():q.require(q.digest(ROOT/name)==sha,'Extension source changed')
    for name,sha in extension['compiled_sha256'].items():q.require(q.digest(area/name)==sha,'Extension binary changed')
    q.require(q.digest(area/'request_bio_lineage.generated.c')==extension['generated_loader_sha256'],'Generated loader changed')
    for name,entry in core['contract']['fixtures'].items():q.require(q.digest(area/name)==entry['sha256'],'Fixture changed')
    core.update(kind='bc250-request-bio-qualification',case_count=len(rows),cases=rows,extension=extension,reference_result_sha256=refs,
        reference_sources_and_binaries_unchanged=True,selected_request_generation_controls_passed=True,
        full_folio_bio_request_wait_chain_qualified=False,broader_native_requeue_partial_reuse_qualified=False,
        whole_application_critical_path_qualified=False,overhead_qualified=False)
    core['contract'].update(owned_program_count=24,map_context_count=9,source_sha256={**core['contract']['source_sha256'],**extension['source_sha256']})
    (area/'result.json').write_text(json.dumps(core,indent=2)+'\n');print(json.dumps(dict(passed=True,cases=len(rows),full_wait_chain_qualified=False)),flush=True)


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('step',choices=('run','_host'))
    for name in ('reference','physical-reference','output'):parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args();q.require(sys.platform=='linux' and os.geteuid()==0,'Linux root required')
    if args.step=='_host':host(args);return
    unit='bc250-request-bio-'+uuid.uuid4().hex[:12]
    subprocess.run(['systemd-run','--quiet','--wait','--pipe','--collect','--unit='+unit,'--property=MemoryMax=2G','--property=CPUQuota=200%',
        '--property=MemorySwapMax=0','--property=TasksMax=128','--property=RuntimeMaxSec=300','--property=KillMode=control-group',
        '/usr/bin/unshare','--mount','--propagation','private','python3','-B',str(Path(__file__).resolve()),'_host',
        '--reference',str(args.reference),'--physical-reference',str(args.physical_reference),'--output',str(args.output)],check=True,timeout=330)


if __name__=='__main__':main()
