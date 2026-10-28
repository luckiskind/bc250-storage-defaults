#!/usr/bin/env python3
"""Private combined request/vector/folio qualification; no tuning changes."""
import argparse
import gzip
import json
import os
from pathlib import Path
import re
import select
import shutil
import subprocess
import sys
import time
import uuid
from unittest.mock import patch
import qualify_request_bio_lineage as reference
from combined_wait_loader import generate,folio_extension,ready_ids
from combined_wait import validate

base=reference.base;q=reference.q;ROOT=reference.ROOT


def build(area):
    names,observed=reference.build(area)
    shutil.copyfile(area/'extension-contract.json',area/'request-reference-build-contract.json')
    raw=json.loads(q.command('bpftool','-j','btf','dump','file','/sys/kernel/btf/vmlinux','format','raw',timeout=30));types={v['id']:v for v in raw['types']}
    expected={'wake_page_function':('int',['*wait_queue_entry','unsigned int','int','*void']),
        'btf_trace_sched_switch':('void',['*void','_Bool','*task_struct','*task_struct','unsigned int']),
        'btf_trace_sched_waking':('void',['*void','*task_struct']),'btf_trace_sched_wakeup':('void',['*void','*task_struct'])}
    for name,want in expected.items():
        found=[v for v in types.values() if v['kind'] in ('FUNC','TYPEDEF') and v['name']==name];q.require(len(found)==1,'Missing/ambiguous combined BTF')
        proto=types[found[0]['type_id']]
        for _ in range(8):
            if proto['kind']=='FUNC_PROTO':break
            proto=types[proto['type_id']]
        q.require(proto['kind']=='FUNC_PROTO','Unresolved combined prototype')
        actual=(base.shape(types,proto['ret_type_id']),[base.shape(types,x['type_id']) for x in proto['params']])
        q.require(actual==want,'Combined ABI differs: '+name);observed[name]=dict(returns=actual[0],parameters=actual[1])
    def resolve(i):
        v=types[i]
        while v['kind'] in ('TYPEDEF','CONST','VOLATILE','RESTRICT','TYPE_TAG'):v=types[v['type_id']]
        return v
    def fields(i,offset=0,prefix=''):
        v=resolve(i);out={}
        for m in v.get('members',[]):
            name=m['name'];at=offset+m['bits_offset'];child=resolve(m['type_id'])
            if name in ('','(anon)'):out.update(fields(m['type_id'],at,prefix))
            else:
                out[prefix+name]=at
                if name=='flags' and child['kind'] in ('STRUCT','UNION'):out.update(fields(m['type_id'],at,prefix+name+'.'))
        return out
    layout={}
    for name,size,wanted in [('bio_vec',16,{'bv_page':0,'bv_len':64,'bv_offset':96}),('page',64,{'flags.f':0,'compound_info':64}),('folio',256,{'flags.f':0,'page':0,'mapping':192,'index':256,'_nr_pages':960})]:
        found=[v for v in types.values() if v['kind']=='STRUCT' and v['name']==name];q.require(len(found)==1,'Missing/ambiguous geometry type')
        v=found[0];actual=fields(v['id']);q.require(v['size']==size and all(actual.get(k)==n for k,n in wanted.items()),'Unsupported vector/folio layout')
        layout[name]=dict(size_bytes=size,field_offsets_bits=wanted)
    config=gzip.decompress(Path('/proc/config.gz').read_bytes()).decode();q.require('CONFIG_SPARSEMEM_VMEMMAP=y\n' in config and os.sysconf('SC_PAGE_SIZE')==4096,'VMEMMAP/4K pages required')
    headers=Path('/usr/lib/modules')/os.uname().release/'build/include/linux';wait=(headers/'wait.h').read_text();page=(headers/'page-flags.h').read_text()
    q.require(re.search(r'#define\s+WQ_FLAG_EXCLUSIVE\s+0x01\b',wait) and re.search(r'PG_locked\s*=\s*0\b',(area/'vmlinux.h').read_text()),'Folio/wait bit encoding differs')
    # Actual installed source defines the tail marker even when HVO changes
    # the remaining compound_info bits into a mask. Never decode it as head+1.
    q.require(re.search(r'PageTail\(const struct page \*page\)\s*\{\s*return READ_ONCE\(page->compound_info\) & 1;',page),'Compound tail marker source differs')
    own=('combined_wait.bpf.c','combined_wait_loader.py','qualify_combined_wait.py','folio_vector_math.h','folio_vector_math_probe.c','folio_wait_lineage.bpf.c')
    for name in own:shutil.copyfile(ROOT/'bench'/name,area/name)
    (area/'combined_folio.generated.h').write_text(folio_extension((area/'folio_wait_lineage.bpf.c').read_text()))
    (area/'combined_wait.generated.c').write_text(generate((area/'read_lineage.c').read_text()))
    commands=[['clang','-g','-O2','-Wall','-Werror','-target','bpf','-mcpu=v3','-D__TARGET_ARCH_x86','-I.','-c','combined_wait.bpf.c','-o','combined_wait.bpf.o'],
        ['gcc','-g','-O2','-Wall','-Wextra','-Werror','combined_wait.generated.c','-o','combined-wait','-lbpf','-lelf','-lz'],
        ['gcc','-O2','-Wall','-Wextra','-Werror','folio_vector_math_probe.c','-o','folio-vector-math-probe']]
    for i,command in enumerate(commands):
        with (area/('combined-build-%d.log'%i)).open('x') as out:subprocess.run(command,cwd=area,stdout=out,stderr=subprocess.STDOUT,check=True,timeout=60)
    contract=json.loads((area/'extension-contract.json').read_text())
    contract.update(source_sha256={**contract['source_sha256'],**{name:q.digest(ROOT/name) for name in ['bench/'+n for n in own]+['analysis/combined_wait.py','analysis/request_bio_accounting.py','analysis/folio_wait_lineage.py']}},
        generated_loader_sha256=q.digest(area/'combined_wait.generated.c'),generated_folio_sha256=q.digest(area/'combined_folio.generated.h'),
        compiled_sha256={**contract['compiled_sha256'],**{n:q.digest(area/n) for n in ('combined-wait','combined_wait.bpf.o','folio-vector-math-probe')}},
        verified_function_abi=observed,active_program_count=29,private_context_maps=13,vector_limit=256,page_size=4096,struct_layouts=layout,
        installed_header_sha256={n:q.digest(headers/n) for n in ('wait.h','page-flags.h','bvec.h')},
        vmemmap_verified=True,compound_tail_marker='low bit only; no compound head pointer decoding',
        original_iterator_bookmarked=True,reference_bio_data_sleep_programs_loaded=False,
        native_large_or_partial_folio_qualified=False,whole_application_critical_path_qualified=False,overhead_qualified=False)
    (area/'extension-contract.json').write_text(json.dumps(contract,indent=2)+'\n')
    with (area/'extension-contract.json').open('rb') as stream:os.fsync(stream.fileno())
    return (*names,*own),observed


def start(area,pid,fd,limit,proof,issue,vector,folio):
    proc=subprocess.Popen([str(area/'combined-wait'),str(area/'combined_wait.bpf.o'),str(pid),str(fd),'3',str(limit),str(int(proof)),str(q.block_device(area)),str(int(issue)),str(int(vector)),str(int(folio))],
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


def capture(area,path,label,mode,warm,expected_hash,wrong_fd=False,limit=50000,kill=False,proof=True,issue=True,vector=True,folio=True):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW);other=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    repeat=mode=='repeat';logical_bytes=(8 if repeat else 1)*2*2**20
    worker=subprocess.Popen([str(area/('request-bio-repeat-probe' if repeat else 'read-lineage-probe')),str(fd),mode],pass_fds=(fd,other),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    trace=None;ids=[];log=b''
    try:
        q.require(base.line(worker)==b'BC250_READ_WORKER_READY\n','Worker not ready')
        if repeat:
            affinity={min(os.sched_getaffinity(0))};os.sched_setaffinity(worker.pid,affinity);q.require(os.sched_getaffinity(worker.pid)==affinity,'Repeat worker affinity differs')
        trace,ids,log=start(area,worker.pid,other if wrong_fd else fd,limit,proof,issue,vector,folio)
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
        elif not folio:
            q.require(not result['stream_quality_passed'] and result['blocked_switch_segments']>0 and result['unresolved_wait_edges']>0,'Missing folio proof accepted/unexercised')
        elif not vector:
            q.require(not result['stream_quality_passed'] and result['resolved_folio_blocked_segments']>0 and result['missing_vector_edges']>0 and raw['vector_counters'][7]>0,'Missing vector proof accepted/unexercised')
        else:
            q.require(result['stream_quality_passed'] and result['demand_attempts']>0,'Request generation quality/coverage failed')
            if mode in ('read','repeat'):q.require(result['buffered_read_returned_bytes']==work['logical_bytes'],'Buffered return differs')
            if warm:q.require(result['original_data_bios']==result['physical_root_bios']==result['request_generations']==0,'Warm path submitted data')
            else:
                q.require(result['selected_physical_bio_request_generations_qualified'] and result['request_generations']>0,'Cold request identity absent')
                q.require(result['selected_request_members']==result['physical_bio_completions']>0 and result['selected_request_member_bytes']==result['physical_completed_bytes'],'Selected request/physical bytes differ')
                q.require(result['physical_root_bios']==result['original_data_bios']>0,'Original physical coverage absent')
                q.require(result['blocked_switch_segments']>0 and result['resolved_request_folio_blocked_segments']==result['blocked_switch_segments'],'Cold request/folio blocked chain absent')
                if repeat:q.require(result['request_address_reuses_with_changed_generation']>0 and result['request_generations']>=8,'Native changed-generation request reuse not exercised')
        worker.stdin.write(b'D');worker.stdin.flush();worker.communicate(timeout=5);q.require(worker.returncode==0,'Worker normal close failed')
        return dict(case=label,passed=True,mode=mode,warm=warm,resident_before_bytes=resident,validation=result,events=raw['events'],
            known_logical_bytes=work['logical_bytes'],content_checked=True,owned_programs_gone=True,pinned_descriptor_lifetime_verified=True,
            serialized_passes=8 if repeat else 1,repeat_private_zero_resident_checks=8 if repeat else 0,repeat_worker_affinity_verified=repeat,
            intended_incomplete=limit<50000,identity_negative=wrong_fd,callback_proof_enabled=proof,issue_proof_enabled=issue,
            vector_proof_enabled=vector,folio_proof_enabled=folio,intended_missing_proof=not proof or not issue or not vector or not folio,runtime_libbpf=raw['libbpf'])
    finally:
        if trace:q.finish(trace);q.require(q.absent(ids),'Owned request programs remain')
        if worker.poll() is None:worker.kill();worker.communicate(timeout=5)
        os.close(fd);os.close(other)


def host(args):
    refs={}
    for path,count in [(args.reference,11),(args.physical_reference,12),(args.request_reference,14),(args.folio_reference,12)]:
        path=path.absolute();q.native.private_area(path);old=json.loads((path/'result.json').read_text());q.require(old['passed'] and old['case_count']==count,'Qualified combined reference missing')
        for name,sha in old['contract']['source_sha256'].items():q.require(q.digest(ROOT/name)==sha,'Frozen combined source differs: '+name)
        hashes=dict(old['compiled_sha256']);hashes.update(old.get('extension',{}).get('compiled_sha256',{}))
        for name,sha in hashes.items():q.require(q.digest(path/name)==sha,'Frozen reference binary differs')
        refs[path.name]=q.digest(path/'result.json')
    area=args.output.absolute();state,inventory=q.trace_state(),q.programs()
    with patch.object(base,'build',build),patch.object(base,'capture',capture):base.host(args)
    core=json.loads((area/'result.json').read_text());shutil.copyfile(area/'result.json',area/'shared-harness-result-private.json')
    extension=json.loads((area/'extension-contract.json').read_text());expected=json.loads((area/'compressed-read-cold-worker-private.json').read_text())['fnv64'];rows=list(core['cases'])
    try:
        rows.append(capture(area,area/'compressed.bin','callback-proof-disabled','read',False,expected,proof=False))
        rows.append(capture(area,area/'compressed.bin','issue-proof-disabled','read',False,expected,issue=False))
        rows.append(capture(area,area/'plain.bin','serialized-cold-reuse','repeat',False,expected))
        rows.append(capture(area,area/'compressed.bin','folio-proof-disabled','read',False,expected,folio=False))
        rows.append(capture(area,area/'compressed.bin','vector-proof-disabled','read',False,expected,vector=False))
    finally:
        (area/'extension-completed-cases.json').write_text(json.dumps(rows,indent=2)+'\n')
        q.require(q.trace_state()==state and q.programs()==inventory,'Combined observer changed global tracing/program state')
    for name,sha in extension['source_sha256'].items():q.require(q.digest(ROOT/name)==sha,'Combined source changed')
    for name,sha in extension['compiled_sha256'].items():q.require(q.digest(area/name)==sha,'Combined binary changed')
    for name,key in [('combined_wait.generated.c','generated_loader_sha256'),('combined_folio.generated.h','generated_folio_sha256')]:q.require(q.digest(area/name)==extension[key],'Generated combined source changed')
    for name,entry in core['contract']['fixtures'].items():q.require(q.digest(area/name)==entry['sha256'],'Fixture changed')
    core.update(kind='bc250-combined-wait-qualification',case_count=len(rows),cases=rows,extension=extension,reference_result_sha256=refs,
        reference_sources_and_binaries_unchanged=True,selected_worker_request_folio_wait_controls_passed=True,
        full_folio_bio_request_wait_chain_qualified=False,broader_native_requeue_partial_reuse_qualified=False,
        whole_application_critical_path_qualified=False,overhead_qualified=False,stage1_gate_passed=False)
    core['contract'].update(owned_program_count=29,map_context_count=13,source_sha256={**core['contract']['source_sha256'],**extension['source_sha256']})
    (area/'result.json').write_text(json.dumps(core,indent=2)+'\n');print(json.dumps(dict(passed=True,cases=len(rows),full_wait_chain_qualified=False)),flush=True)


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('step',choices=('run','_host'))
    for name in ('reference','physical-reference','request-reference','folio-reference','output'):parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args();q.require(sys.platform=='linux' and os.geteuid()==0,'Linux root required')
    if args.step=='_host':host(args);return
    unit='bc250-combined-wait-'+uuid.uuid4().hex[:12];paths=[]
    for name in ('reference','physical_reference','request_reference','folio_reference','output'):paths+=['--'+name.replace('_','-'),str(getattr(args,name))]
    subprocess.run(['systemd-run','--quiet','--wait','--pipe','--collect','--unit='+unit,'--property=MemoryMax=2G','--property=CPUQuota=200%',
        '--property=MemorySwapMax=0','--property=TasksMax=128','--property=RuntimeMaxSec=300','--property=KillMode=control-group',
        '/usr/bin/unshare','--mount','--propagation','private','python3','-B',str(Path(__file__).resolve()),'_host',*paths],check=True,timeout=330)


if __name__=='__main__':main()

