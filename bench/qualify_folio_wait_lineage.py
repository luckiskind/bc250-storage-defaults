#!/usr/bin/env python3
"""Separate selected-worker folio wake/scheduler diagnostic on private data."""
import argparse
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
import qualify_read_lineage as base
from folio_wait_loader import generate
from folio_wait_lineage import validate

q=base.q
ROOT=Path(__file__).resolve().parents[1]
ORIGINAL_BUILD=base.build


def extended_build(area):
    names,observed=ORIGINAL_BUILD(area)
    raw=json.loads(q.command('bpftool','-j','btf','dump','file','/sys/kernel/btf/vmlinux','format','raw',timeout=30));types={r['id']:r for r in raw['types']}
    expected={'wake_page_function':('int',['*wait_queue_entry','unsigned int','int','*void']),
        'btf_trace_sched_switch':('void',['*void','_Bool','*task_struct','*task_struct','unsigned int']),
        'btf_trace_sched_waking':('void',['*void','*task_struct']),'btf_trace_sched_wakeup':('void',['*void','*task_struct'])}
    for name,want in expected.items():
        found=[r for r in types.values() if r['kind'] in ('TYPEDEF','FUNC') and r['name']==name];q.require(len(found)==1,'Ambiguous/missing scheduler/wake BTF')
        proto=types[found[0]['type_id']]
        for _ in range(8):
            if proto['kind']=='FUNC_PROTO':break
            proto=types[proto['type_id']]
        q.require(proto['kind']=='FUNC_PROTO','Unresolved function prototype')
        actual=(base.shape(types,proto['ret_type_id']),[base.shape(types,x['type_id']) for x in proto['params']])
        q.require(actual==want,'Scheduler/wake ABI differs: '+name);observed[name]=dict(returns=actual[0],parameters=actual[1])
    header=(area/'vmlinux.h').read_text();q.require(re.search(r'PG_locked\s*=\s*0\b',header),'Locked folio bit differs')
    wait_header=Path('/usr/lib/modules')/os.uname().release/'build/include/linux/wait.h'
    q.require(re.search(r'#define\s+WQ_FLAG_EXCLUSIVE\s+0x01\b',wait_header.read_text()),'Exclusive wait encoding differs')
    own=('folio_wait_lineage.bpf.c','folio_wait_loader.py','qualify_folio_wait_lineage.py')
    for name in own:shutil.copyfile(ROOT/'bench'/name,area/name)
    generated=generate((area/'read_lineage.c').read_text());(area/'folio_wait_lineage.generated.c').write_text(generated)
    commands=[['clang','-g','-O2','-Wall','-Werror','-target','bpf','-mcpu=v3','-D__TARGET_ARCH_x86','-I.','-c','folio_wait_lineage.bpf.c','-o','folio_wait_lineage.bpf.o'],
        ['gcc','-g','-O2','-Wall','-Wextra','-Werror','folio_wait_lineage.generated.c','-o','folio-wait-lineage','-lbpf','-lelf','-lz']]
    for index,command in enumerate(commands):
        with (area/('extension-build-%d.log'%index)).open('x') as out:subprocess.run(command,cwd=area,stdout=out,stderr=subprocess.STDOUT,check=True,timeout=60)
    sources={name:q.digest(ROOT/name) for name in ['bench/'+n for n in own]+['analysis/folio_wait_lineage.py']}
    contract=dict(source_sha256=sources,generated_loader_sha256=q.digest(area/'folio_wait_lineage.generated.c'),
        btf_header_sha256=q.digest(area/'vmlinux.h'),verified_function_abi=observed,active_program_count=21,
        reference_sleep_programs_loaded=False,private_context_maps=7,queued_folio_bit=0,exclusive_wait_flag=1,
        identity_and_range_proof_mask=0xf0000,raw_addresses_or_task_ids_exported=False,
        compiled_sha256={n:q.digest(area/n) for n in ('folio-wait-lineage','folio_wait_lineage.bpf.o')},
        frozen_before_collection=True,exact_device_request_edges_qualified=False,overhead_qualified=False)
    (area/'extension-contract.json').write_text(json.dumps(contract,indent=2)+'\n')
    with (area/'extension-contract.json').open('rb') as stream:os.fsync(stream.fileno())
    return (*names,*own),observed


def start(area,pid,fd,limit=50000,proof=True):
    proc=subprocess.Popen([str(area/'folio-wait-lineage'),str(area/'folio_wait_lineage.bpf.o'),str(pid),str(fd),'3',str(limit),str(int(proof))],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    os.set_blocking(proc.stderr.fileno(),False);log=b'';deadline=time.monotonic()+12
    try:
        while time.monotonic()<deadline:
            if select.select([proc.stderr],[],[],.1)[0]:
                log+=os.read(proc.stderr.fileno(),65536);q.require(len(log)<2**20,'Bounded extension log')
                for line in log.splitlines():
                    if line.startswith(b'BC250_FOLIO_WAIT_READY '):
                        ids=json.loads(line.split(b' ',1)[1])['program_ids'];q.require(len(ids)==len(set(ids))==21,'Twenty-one owned programs required');return proc,ids,log
            q.require(proc.poll() is None,'Folio wait attach failed: '+log.decode(errors='replace')[-4000:])
        raise RuntimeError('Folio wait readiness timeout')
    except BaseException:
        q.finish(proc);(area/'extension-failed-start-private.log').write_bytes(log);raise


def capture(area,path,label,mode,warm,expected_hash,wrong_fd=False,limit=50000,kill=False,proof=True):
    if warm:q.digest(path)
    resident=q.residency(path,evict=not warm);q.require(resident==(path.stat().st_size if warm else 0),'Private cache condition differs')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW);other=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    worker=subprocess.Popen([str(area/'read-lineage-probe'),str(fd),mode],pass_fds=(fd,other),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    trace=None;ids=[];log=b''
    try:
        q.require(base.line(worker)==b'BC250_READ_WORKER_READY\n','Owned worker not ready')
        trace,ids,log=start(area,worker.pid,other if wrong_fd else fd,limit,proof)
        if kill:
            trace.kill();trace.communicate(timeout=5);q.require(q.absent(ids),'Forced exit left probes')
            return dict(case=label,passed=True,owned_programs_gone=True,forced_exit=True)
        worker.stdin.write(b'G');worker.stdin.flush();work=json.loads(base.line(worker))
        q.require(work['passed'] and work['logical_bytes']==2*2**20 and work['fnv64']==expected_hash,'Worker read/content failed')
        out,err=trace.communicate(timeout=10);log+=err
        (area/(label+'-raw-private.json')).write_bytes(out);(area/(label+'-loader-private.log')).write_bytes(log)
        (area/(label+'-worker-private.json')).write_text(json.dumps(work,indent=2)+'\n')
        q.require(trace.returncode==0 and q.absent(ids) and worker.poll() is None,'Observer/pinned worker lifetime failed')
        raw=json.loads(out);result=validate(raw)
        q.require(raw['start_ns']<=work['start_ns']<work['finish_ns']<=raw['finish_ns'] or limit<50000,'Worker outside observation')
        if wrong_fd:q.require(raw['events']==0 and result['identity_rejections']>0,'Same-inode different-open negative failed')
        elif limit<50000:q.require(raw['limit_reached'] and not result['transport_complete'],'Cap not explicit')
        elif not proof:q.require(not result['stream_quality_passed'] and result['blocked_switch_segments']>0 and result['unresolved_wait_edges']>0,'Missing folio proof silently accepted or no blocked wait exercised')
        else:
            q.require(result['stream_quality_passed'] and result['demand_attempts']>0,'Wait graph quality/coverage failed')
            if mode=='read':q.require(result['buffered_read_returned_bytes']==work['logical_bytes'],'Buffered return differs')
            if warm:q.require(result['original_data_bios']==result['decompression_spans']==result['blocked_switch_segments']==0,'Warm path unexpectedly blocked/submitted data')
            else:
                q.require(result['blocked_switch_segments']>0 and result['resolved_folio_blocked_segments']==result['blocked_switch_segments'],'Cold folio blocking not positively exercised')
                if path.name=='compressed.bin':q.require(result['compressed_original_bios']>0 and result['decompression_spans']>0,'Compressed path absent')
                else:q.require(result['original_data_bios']>0 and result['decompression_spans']==0,'Plain path differs')
        worker.stdin.write(b'D');worker.stdin.flush();worker.communicate(timeout=5);q.require(worker.returncode==0,'Owned worker failed normal close')
        return dict(case=label,passed=True,mode=mode,warm=warm,resident_before_bytes=resident,validation=result,events=raw['events'],
            known_logical_bytes=work['logical_bytes'],content_checked=True,owned_programs_gone=True,pinned_descriptor_lifetime_verified=True,
            intended_incomplete=limit<50000,identity_negative=wrong_fd,folio_proof_enabled=proof,intended_missing_proof=not proof,runtime_libbpf=raw['libbpf'])
    finally:
        if trace:q.finish(trace);q.require(q.absent(ids),'Owned extension probes remain')
        if worker.poll() is None:worker.kill();worker.communicate(timeout=5)
        os.close(fd);os.close(other)


def host(args):
    reference=args.reference.absolute();q.native.private_area(reference)
    previous=json.loads((reference/'result.json').read_text());q.require(previous['passed'] and previous['case_count']==11,'Prior read qualification missing')
    for name,sha in previous['contract']['source_sha256'].items():q.require(q.digest(ROOT/name)==sha,'Frozen read source differs: '+name)
    for name,sha in previous['compiled_sha256'].items():q.require(q.digest(reference/name)==sha,'Prior read binary differs')
    state,inventory=q.trace_state(),q.programs();area=args.output.absolute()
    with patch.object(base,'build',extended_build),patch.object(base,'capture',capture):base.host(args)
    core=json.loads((area/'result.json').read_text());shutil.copyfile(area/'result.json',area/'shared-harness-result-private.json')
    extension=json.loads((area/'extension-contract.json').read_text());expected=json.loads((area/'compressed-read-cold-worker-private.json').read_text())['fnv64']
    rows=list(core['cases'])
    try:rows.append(capture(area,area/'compressed.bin','folio-proof-disabled','read',False,expected,proof=False))
    finally:
        (area/'extension-completed-cases.json').write_text(json.dumps(rows,indent=2)+'\n')
        q.require(q.trace_state()==state and q.programs()==inventory,'Extension changed global tracing/program state')
    for name,sha in extension['source_sha256'].items():q.require(q.digest(ROOT/name)==sha,'Extension source changed')
    for name,sha in extension['compiled_sha256'].items():q.require(q.digest(area/name)==sha,'Extension binary changed')
    q.require(q.digest(area/'folio_wait_lineage.generated.c')==extension['generated_loader_sha256'],'Generated loader changed')
    for name,entry in core['contract']['fixtures'].items():q.require(q.digest(area/name)==entry['sha256'],'Fixture changed')
    core.update(case_count=len(rows),cases=rows,kind='bc250-folio-wait-qualification',shared_reference_qualification_sha256=q.digest(reference/'result.json'),
        extension=extension,reference_sources_and_binaries_unchanged=True,full_folio_bio_request_wait_chain_qualified=False,
        selected_worker_folio_wake_controls_passed=True,whole_application_critical_path_qualified=False,overhead_qualified=False)
    core['contract'].update(owned_program_count=21,map_context_count=7,source_sha256={**core['contract']['source_sha256'],**extension['source_sha256']})
    (area/'result.json').write_text(json.dumps(core,indent=2)+'\n');print(json.dumps(dict(passed=True,cases=len(rows),full_wait_chain_qualified=False)),flush=True)


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('step',choices=('run','_host'))
    for name in ('reference','output'):parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args();q.require(sys.platform=='linux' and os.geteuid()==0,'Linux root required')
    if args.step=='_host':host(args);return
    unit='bc250-folio-wait-'+uuid.uuid4().hex[:12]
    subprocess.run(['systemd-run','--quiet','--wait','--pipe','--collect','--unit='+unit,'--property=MemoryMax=2G','--property=CPUQuota=200%',
        '--property=MemorySwapMax=0','--property=TasksMax=128','--property=RuntimeMaxSec=300','--property=KillMode=control-group',
        '/usr/bin/unshare','--mount','--propagation','private','python3','-B',str(Path(__file__).resolve()),'_host',
        '--reference',str(args.reference),'--output',str(args.output)],check=True,timeout=330)


if __name__=='__main__':main()
