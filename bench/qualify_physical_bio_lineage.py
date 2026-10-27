#!/usr/bin/env python3
"""Private original-to-physical bio bridge; request and critical-path gates stay open."""
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
import qualify_read_lineage as base
from physical_bio_loader import generate,ready_ids
from physical_bio_lineage import validate

q=base.q
ROOT=Path(__file__).resolve().parents[1]
ORIGINAL_BUILD=base.build


def extended_build(area):
    names,observed=ORIGINAL_BUILD(area)
    raw=json.loads(q.command('bpftool','-j','btf','dump','file','/sys/kernel/btf/vmlinux','format','raw',timeout=30));types={v['id']:v for v in raw['types']}
    expected={'btrfs_submit_bbio':('void',['*btrfs_bio','int']),
        'bio_split':('*bio',['*bio','int','unsigned int','*bio_set']),
        'btf_trace_block_bio_queue':('void',['*void','*bio']),
        'btf_trace_block_rq_complete':('void',['*void','*request','unsigned char','unsigned int'])}
    for name,want in expected.items():
        found=[v for v in types.values() if v['kind'] in ('FUNC','TYPEDEF') and v['name']==name];q.require(len(found)==1,'Missing/ambiguous physical-bio BTF')
        proto=types[found[0]['type_id']]
        for _ in range(8):
            if proto['kind']=='FUNC_PROTO':break
            proto=types[proto['type_id']]
        q.require(proto['kind']=='FUNC_PROTO','Unresolved physical prototype')
        actual=(base.shape(types,proto['ret_type_id']),[base.shape(types,x['type_id']) for x in proto['params']])
        q.require(actual==want,'Physical ABI differs: '+name);observed[name]=dict(returns=actual[0],parameters=actual[1])
    own=('physical_bio_lineage.bpf.c','physical_bio_loader.py','qualify_physical_bio_lineage.py')
    for name in own:shutil.copyfile(ROOT/'bench'/name,area/name)
    (area/'physical_bio_lineage.generated.c').write_text(generate((area/'read_lineage.c').read_text()))
    commands=[['clang','-g','-O2','-Wall','-Werror','-target','bpf','-mcpu=v3','-D__TARGET_ARCH_x86','-I.','-c','physical_bio_lineage.bpf.c','-o','physical_bio_lineage.bpf.o'],
        ['gcc','-g','-O2','-Wall','-Wextra','-Werror','physical_bio_lineage.generated.c','-o','physical-bio-lineage','-lbpf','-lelf','-lz']]
    for index,command in enumerate(commands):
        with (area/('extension-build-%d.log'%index)).open('x') as out:subprocess.run(command,cwd=area,stdout=out,stderr=subprocess.STDOUT,check=True,timeout=60)
    contract=dict(source_sha256={name:q.digest(ROOT/name) for name in ['bench/'+n for n in own]+['analysis/physical_bio_lineage.py']},
        generated_loader_sha256=q.digest(area/'physical_bio_lineage.generated.c'),btf_header_sha256=q.digest(area/'vmlinux.h'),
        compiled_sha256={n:q.digest(area/n) for n in ('physical-bio-lineage','physical_bio_lineage.bpf.o')},
        verified_function_abi=observed,active_program_count=22,private_context_maps=7,
        callback_identity_source='Own BTF-attached callback entry bpf_get_func_ip; private calibration before selection enabled',
        callback_identity_exported=False,kallsyms_required=False,security_settings_changed=False,
        completion_source='Actual bio-chain prefix at raw request completion before advancement; maximum 64 bios',
        bio_chain_walk_limit=64,raw_bio_complete_is_a_census=False,
        frozen_before_collection=True,physical_bio_request_edges_qualified=False,overhead_qualified=False)
    (area/'extension-contract.json').write_text(json.dumps(contract,indent=2)+'\n')
    with (area/'extension-contract.json').open('rb') as stream:os.fsync(stream.fileno())
    return (*names,*own),observed


def start(area,pid,fd,limit,proof):
    proc=subprocess.Popen([str(area/'physical-bio-lineage'),str(area/'physical_bio_lineage.bpf.o'),str(pid),str(fd),'3',str(limit),str(int(proof)),str(q.block_device(area))],
        stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    os.set_blocking(proc.stderr.fileno(),False);log=b'';deadline=time.monotonic()+15;seeded=False
    try:
        while time.monotonic()<deadline:
            if select.select([proc.stderr],[],[],.1)[0]:
                log+=os.read(proc.stderr.fileno(),65536);q.require(len(log)<2**20,'Bounded physical loader log')
                if not seeded and b'BC250_PHYSICAL_SEED_READY\n' in log:
                    seed=area/'compressed.bin';q.require(q.residency(seed,evict=True)==0,'Private calibration not cold');q.digest(seed)
                    proc.stdin.write(b'G');proc.stdin.flush();seeded=True
                ids=ready_ids(log)
                if ids is not None:q.require(seeded,'Calibration handshake missing');return proc,ids,log
            q.require(proc.poll() is None,'Physical attach/identity calibration failed: '+log.decode(errors='replace')[-3000:])
        raise RuntimeError('Physical readiness deadline')
    except BaseException:
        q.finish(proc);(area/'extension-failed-start-private.log').write_bytes(log);raise


def capture(area,path,label,mode,warm,expected_hash,wrong_fd=False,limit=50000,kill=False,proof=True):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW);other=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    worker=subprocess.Popen([str(area/'read-lineage-probe'),str(fd),mode],pass_fds=(fd,other),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    trace=None;ids=[];log=b''
    try:
        q.require(base.line(worker)==b'BC250_READ_WORKER_READY\n','Owned worker not ready')
        trace,ids,log=start(area,worker.pid,other if wrong_fd else fd,limit,proof)
        # Calibration can warm the compressed file. Re-establish and measure the
        # selected target's private cache condition AFTER it, before worker G.
        if warm:q.digest(path)
        resident=q.residency(path,evict=not warm);q.require(resident==(path.stat().st_size if warm else 0),'Final private cache condition differs')
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
        if wrong_fd:q.require(raw['events']==0 and result['identity_rejections']>0,'Wrong-open negative failed')
        elif limit<50000:q.require(raw['limit_reached'] and not result['transport_complete'],'Cap not explicit')
        elif not proof:q.require(not result['stream_quality_passed'] and result['uncovered_original_bios']>0 and raw['physical_counters'][2]>0,'Missing callback proof silently accepted')
        else:
            q.require(result['stream_quality_passed'] and result['demand_attempts']>0,'Physical bridge quality/coverage failed')
            if mode=='read':q.require(result['buffered_read_returned_bytes']==work['logical_bytes'],'Buffered return differs')
            if warm:q.require(result['original_data_bios']==result['physical_root_bios']==0,'Warm path submitted data')
            else:
                q.require(result['original_data_bios']==result['physical_root_bios']>0 and result['selected_original_to_physical_bio_edges_qualified'],'Cold physical edges absent')
                q.require(result['physical_completed_bytes']==result['physical_root_input_bytes']>0,'Physical byte conservation differs')
                if path.name=='compressed.bin':q.require(result['compressed_physical_roots']==result['physical_root_bios'] and result['decompression_spans']>0,'Compressed path absent')
                else:q.require(result['compressed_physical_roots']==result['decompression_spans']==0,'Plain path differs')
        worker.stdin.write(b'D');worker.stdin.flush();worker.communicate(timeout=5);q.require(worker.returncode==0,'Owned worker close failed')
        return dict(case=label,passed=True,mode=mode,warm=warm,resident_before_bytes=resident,validation=result,events=raw['events'],
            known_logical_bytes=work['logical_bytes'],content_checked=True,owned_programs_gone=True,pinned_descriptor_lifetime_verified=True,
            intended_incomplete=limit<50000,identity_negative=wrong_fd,callback_proof_enabled=proof,intended_missing_proof=not proof,runtime_libbpf=raw['libbpf'])
    finally:
        if trace:q.finish(trace);q.require(q.absent(ids),'Owned physical programs remain')
        if worker.poll() is None:worker.kill();worker.communicate(timeout=5)
        os.close(fd);os.close(other)


def host(args):
    reference=args.reference.absolute();q.native.private_area(reference)
    previous=json.loads((reference/'result.json').read_text());q.require(previous['passed'] and previous['case_count']==11,'Prior read reference missing')
    for name,sha in previous['contract']['source_sha256'].items():q.require(q.digest(ROOT/name)==sha,'Frozen read source differs: '+name)
    for name,sha in previous['compiled_sha256'].items():q.require(q.digest(reference/name)==sha,'Prior read binary differs')
    state,inventory=q.trace_state(),q.programs();area=args.output.absolute()
    with patch.object(base,'build',extended_build),patch.object(base,'capture',capture):base.host(args)
    core=json.loads((area/'result.json').read_text());shutil.copyfile(area/'result.json',area/'shared-harness-result-private.json')
    extension=json.loads((area/'extension-contract.json').read_text());expected=json.loads((area/'compressed-read-cold-worker-private.json').read_text())['fnv64']
    rows=list(core['cases'])
    try:rows.append(capture(area,area/'compressed.bin','callback-proof-disabled','read',False,expected,proof=False))
    finally:
        (area/'extension-completed-cases.json').write_text(json.dumps(rows,indent=2)+'\n')
        q.require(q.trace_state()==state and q.programs()==inventory,'Extension changed global tracing/program state')
    for name,sha in extension['source_sha256'].items():q.require(q.digest(ROOT/name)==sha,'Extension source changed')
    for name,sha in extension['compiled_sha256'].items():q.require(q.digest(area/name)==sha,'Extension binary changed')
    q.require(q.digest(area/'physical_bio_lineage.generated.c')==extension['generated_loader_sha256'],'Generated loader changed')
    for name,entry in core['contract']['fixtures'].items():q.require(q.digest(area/name)==entry['sha256'],'Fixture changed')
    core.update(case_count=len(rows),cases=rows,kind='bc250-physical-bio-qualification',extension=extension,
        shared_reference_qualification_sha256=q.digest(reference/'result.json'),reference_sources_and_binaries_unchanged=True,
        selected_original_to_physical_bio_controls_passed=True,physical_bio_request_edges_qualified=False,
        split_and_merge_native_coverage_qualified=False,whole_application_critical_path_qualified=False,overhead_qualified=False)
    core['contract'].update(owned_program_count=22,map_context_count=7,source_sha256={**core['contract']['source_sha256'],**extension['source_sha256']})
    (area/'result.json').write_text(json.dumps(core,indent=2)+'\n');print(json.dumps(dict(passed=True,cases=len(rows),request_edges_qualified=False)),flush=True)


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('step',choices=('run','_host'))
    for name in ('reference','output'):parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args();q.require(sys.platform=='linux' and os.geteuid()==0,'Linux root required')
    if args.step=='_host':host(args);return
    unit='bc250-physical-bio-'+uuid.uuid4().hex[:12]
    subprocess.run(['systemd-run','--quiet','--wait','--pipe','--collect','--unit='+unit,'--property=MemoryMax=2G','--property=CPUQuota=200%',
        '--property=MemorySwapMax=0','--property=TasksMax=128','--property=RuntimeMaxSec=300','--property=KillMode=control-group',
        '/usr/bin/unshare','--mount','--propagation','private','python3','-B',str(Path(__file__).resolve()),'_host',
        '--reference',str(args.reference),'--output',str(args.output)],check=True,timeout=330)


if __name__=='__main__':main()
