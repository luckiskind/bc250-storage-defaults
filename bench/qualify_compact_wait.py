#!/usr/bin/env python3
"""Qualify optional unlock-hook omission with every frozen causal control."""
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
import qualify_combined_wait as full
from compact_wait_loader import generate,ready_ids
from compact_wait import validate

q=full.q;ROOT=full.ROOT;FROZEN_BUILD=full.build;FROZEN_CAPTURE=full.capture;FROZEN_HOST=full.host


def build(area,full_result_sha256,reference,worker_sha256):
    names,abi=FROZEN_BUILD(area)
    shutil.copyfile(area/'extension-contract.json',area/'combined-reference-build-contract.json')
    # Use the exact full-qualified worker for both versions' later comparison.
    # Retain the unused fresh build separately; it supplies no native result.
    shutil.copyfile(area/'read-lineage-probe',area/'read-lineage-probe-fresh-unused')
    q.require(q.digest(reference/'read-lineage-probe')==worker_sha256,'Shared qualified worker changed')
    shutil.copyfile(reference/'read-lineage-probe',area/'read-lineage-probe');(area/'read-lineage-probe').chmod(0o700)
    own=('compact_wait.bpf.c','compact_wait_loader.py','qualify_compact_wait.py')
    for name in own:shutil.copyfile(ROOT/'bench'/name,area/name)
    (area/'compact_wait.generated.c').write_text(generate((area/'read_lineage.c').read_text()))
    commands=[['clang','-g','-O2','-Wall','-Werror','-target','bpf','-mcpu=v3','-D__TARGET_ARCH_x86','-I.','-c','compact_wait.bpf.c','-o','compact_wait.bpf.o'],
        ['gcc','-g','-O2','-Wall','-Wextra','-Werror','compact_wait.generated.c','-o','compact-wait','-lbpf','-lelf','-lz']]
    for i,command in enumerate(commands):
        with (area/('compact-build-%d.log'%i)).open('x') as out:subprocess.run(command,cwd=area,stdout=out,stderr=subprocess.STDOUT,check=True,timeout=60)
    contract=json.loads((area/'extension-contract.json').read_text())
    contract.update(source_sha256={**contract['source_sha256'],**{n:q.digest(ROOT/n) for n in ['bench/'+s for s in own]+['analysis/compact_wait.py']}},
        compact_generated_loader_sha256=q.digest(area/'compact_wait.generated.c'),
        compiled_sha256={**contract['compiled_sha256'],**{n:q.digest(area/n) for n in ('compact-wait','compact_wait.bpf.o','read-lineage-probe','read-lineage-probe-fresh-unused')}},
        active_program_count=28,private_context_maps=13,unlock_hook_loaded=False,unlock_count_available=False,
        only_additionally_omitted_program='unlock_call',all_causal_programs_retained=True,
        full_reference_result_sha256=full_result_sha256,shared_functional_capture_harness_frozen=True,
        shared_worker_reused_from_full_reference=True,shared_worker_sha256=worker_sha256,
        compact_overhead_qualified=False,whole_application_critical_path_qualified=False)
    (area/'extension-contract.json').write_text(json.dumps(contract,indent=2)+'\n')
    with (area/'extension-contract.json').open('rb') as stream:os.fsync(stream.fileno())
    return (*names,*own),abi


def start(area,pid,fd,limit,proof,issue,vector,folio):
    proc=subprocess.Popen([str(area/'compact-wait'),str(area/'compact_wait.bpf.o'),str(pid),str(fd),'3',str(limit),str(int(proof)),str(q.block_device(area)),str(int(issue)),str(int(vector)),str(int(folio))],
        stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    os.set_blocking(proc.stderr.fileno(),False);log=b'';deadline=time.monotonic()+15;seeded=False
    try:
        while time.monotonic()<deadline:
            if select.select([proc.stderr],[],[],.1)[0]:
                log+=os.read(proc.stderr.fileno(),65536);q.require(len(log)<2**20,'Bounded compact loader log')
                if not seeded and b'BC250_PHYSICAL_SEED_READY\n' in log:
                    seed=area/'compressed.bin';q.require(q.residency(seed,evict=True)==0,'Private compact calibration not cold');q.digest(seed)
                    proc.stdin.write(b'G');proc.stdin.flush();seeded=True
                ids=ready_ids(log)
                if ids is not None:q.require(seeded,'Compact calibration handshake missing');return proc,ids,log
            q.require(proc.poll() is None,'Compact attach/calibration failed: '+log.decode(errors='replace')[-3000:])
        raise RuntimeError('Compact readiness deadline')
    except BaseException:
        q.finish(proc);(area/'compact-failed-start-private.log').write_bytes(log);raise


def capture(*args,**kwargs):
    # Frozen capture code still performs every descriptor/cache/content,
    # proof-removal, completion-prefix, reuse, cap and cleanup assertion.
    with patch.object(full,'start',start),patch.object(full,'validate',validate):return FROZEN_CAPTURE(*args,**kwargs)


def host(args):
    reference=args.combined_reference.absolute();q.native.private_area(reference);old=json.loads((reference/'result.json').read_text())
    q.require(old['passed'] and old['case_count']==16 and old['extension']['active_program_count']==29,'Full combined qualification required')
    for n,h in old['contract']['source_sha256'].items():q.require(q.digest(ROOT/n)==h,'Frozen full source changed: '+n)
    hashes={**old['compiled_sha256'],**old['extension']['compiled_sha256']}
    for n,h in hashes.items():q.require(q.digest(reference/n)==h,'Frozen full binary changed')
    sha=q.digest(reference/'result.json')
    area=args.output.absolute()
    def snapshot():return dict(trace=q.trace_state(),programs=q.programs(),qos=Path('/sys/class/nvme/nvme0/power/pm_qos_latency_tolerance_us').read_text().strip())
    before=snapshot()
    try:
        with patch.object(full,'build',lambda target:build(target,sha,reference,old['compiled_sha256']['read-lineage-probe'])),patch.object(full,'capture',capture):FROZEN_HOST(args)
    finally:
        after=snapshot()
        if area.is_dir():
            for name,value in [('global-state-before-private.json',before),('global-state-after-private.json',after)]:
                (area/name).write_text(json.dumps(value,indent=2)+'\n')
    q.require(before==after,'Compact outer global state changed')
    core=json.loads((area/'result.json').read_text());extension=core['extension']
    q.require(extension['active_program_count']==28 and extension['unlock_hook_loaded'] is False,'Compact program contract differs')
    for row in core['cases']:
        if row.get('forced_exit'):continue
        q.require(row['validation']['folio_unlock_hook_loaded'] is False and row['validation']['folio_unlock_calls'] is None,'Unlock count misrepresented')
    q.require(q.digest(area/'compact_wait.generated.c')==extension['compact_generated_loader_sha256'],'Compact generated loader changed')
    q.require(q.digest(reference/'result.json')==sha,'Full qualification changed')
    core.update(kind='bc250-compact-wait-qualification',compact_wait_controls_passed=True,unlock_hook_loaded=False,
        full_combined_reference_sha256=sha,reference_sources_and_binaries_unchanged=True,compact_overhead_qualified=False,
        global_state_snapshots_unchanged=True,shared_worker_binary_unchanged=True)
    core['contract'].update(owned_program_count=28,unlock_hook_loaded=False,unlock_count_available=False)
    (area/'result.json').write_text(json.dumps(core,indent=2)+'\n');print(json.dumps(dict(passed=True,cases=core['case_count'],owned_programs=28,overhead_qualified=False)),flush=True)


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('step',choices=('run','_host'))
    names=('reference','physical-reference','request-reference','folio-reference','combined-reference','output')
    for name in names:p.add_argument('--'+name,type=Path,required=True)
    args=p.parse_args();q.require(sys.platform=='linux' and os.geteuid()==0,'Linux root required')
    if args.step=='_host':host(args);return
    paths=[]
    for name in names:paths+=['--'+name,str(getattr(args,name.replace('-','_')))]
    unit='bc250-compact-wait-'+uuid.uuid4().hex[:12]
    subprocess.run(['systemd-run','--quiet','--wait','--pipe','--collect','--unit='+unit,'--property=MemoryMax=2G','--property=CPUQuota=200%',
        '--property=MemorySwapMax=0','--property=TasksMax=128','--property=RuntimeMaxSec=300','--property=KillMode=control-group',
        '/usr/bin/unshare','--mount','--propagation','private','/usr/bin/python3','-B',str(Path(__file__).resolve()),'_host',*paths],check=True,timeout=330)


if __name__=='__main__':main()
