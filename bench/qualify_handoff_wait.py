#!/usr/bin/env python3
"""Separate scheduler-entry diagnostic; every old causal control remains."""
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
import qualify_compact_wait as compact
from handoff_wait_loader import generate,folio_extension,vector_extension,ready_ids
from handoff_wait import validate

full=compact.full;q=compact.q;ROOT=compact.ROOT
COMPACT_BUILD=compact.build;COMPACT_HOST=compact.host;FROZEN_CAPTURE=compact.FROZEN_CAPTURE


def build(area,full_sha,reference,worker_sha,compact_sha):
    names,abi=COMPACT_BUILD(area,full_sha,reference,worker_sha)
    shutil.copyfile(area/'extension-contract.json',area/'compact-reference-build-contract.json')
    own=('handoff_wait.bpf.c','handoff_wait_loader.py','qualify_handoff_wait.py')
    for name in own:shutil.copyfile(ROOT/'bench'/name,area/name)
    (area/'handoff_vector.generated.h').write_text(vector_extension((area/'combined_wait.bpf.c').read_text()))
    (area/'handoff_folio.generated.h').write_text(folio_extension((area/'folio_wait_lineage.bpf.c').read_text()))
    (area/'handoff_wait.generated.c').write_text(generate((area/'read_lineage.c').read_text()))
    commands=[['clang','-g','-O2','-Wall','-Werror','-target','bpf','-mcpu=v3','-D__TARGET_ARCH_x86','-I.','-c','handoff_wait.bpf.c','-o','handoff_wait.bpf.o'],
        ['gcc','-g','-O2','-Wall','-Wextra','-Werror','handoff_wait.generated.c','-o','handoff-wait','-lbpf','-lelf','-lz']]
    for i,command in enumerate(commands):
        with (area/('handoff-build-%d.log'%i)).open('x') as out:subprocess.run(command,cwd=area,stdout=out,stderr=subprocess.STDOUT,check=True,timeout=60)
    contract=json.loads((area/'extension-contract.json').read_text())
    contract.update(source_sha256={**contract['source_sha256'],**{n:q.digest(ROOT/n) for n in ['bench/'+s for s in own]+['analysis/handoff_wait.py','analysis/handoff_folio.py']}},
        handoff_generated_sha256={n:q.digest(area/n) for n in ('handoff_vector.generated.h','handoff_folio.generated.h','handoff_wait.generated.c')},
        compiled_sha256={**contract['compiled_sha256'],**{n:q.digest(area/n) for n in ('handoff-wait','handoff_wait.bpf.o')}},
        scheduler_timestamp_basis='hook-entry-v1',handoff_schema_version=2,compact_reference_result_sha256=compact_sha,
        early_wake_duration_is_unknown=True,native_early_wake_order_qualified=False,
        handoff_overhead_qualified=False)
    (area/'extension-contract.json').write_text(json.dumps(contract,indent=2)+'\n')
    with (area/'extension-contract.json').open('rb') as stream:os.fsync(stream.fileno())
    return (*names,*own),abi


def start(area,pid,fd,limit,proof,issue,vector,folio):
    proc=subprocess.Popen([str(area/'handoff-wait'),str(area/'handoff_wait.bpf.o'),str(pid),str(fd),'3',str(limit),str(int(proof)),str(q.block_device(area)),str(int(issue)),str(int(vector)),str(int(folio))],
        stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    os.set_blocking(proc.stderr.fileno(),False);log=b'';deadline=time.monotonic()+15;seeded=False
    try:
        while time.monotonic()<deadline:
            if select.select([proc.stderr],[],[],.1)[0]:
                log+=os.read(proc.stderr.fileno(),65536);q.require(len(log)<2**20,'Bounded handoff loader log')
                if not seeded and b'BC250_PHYSICAL_SEED_READY\n' in log:
                    seed=area/'compressed.bin';q.require(q.residency(seed,evict=True)==0,'Private handoff calibration not cold');q.digest(seed)
                    proc.stdin.write(b'G');proc.stdin.flush();seeded=True
                ids=ready_ids(log)
                if ids is not None:q.require(seeded,'Handoff calibration handshake missing');return proc,ids,log
            q.require(proc.poll() is None,'Handoff attach/calibration failed: '+log.decode(errors='replace')[-3000:])
        raise RuntimeError('Handoff readiness deadline')
    except BaseException:
        q.finish(proc);(area/'handoff-failed-start-private.log').write_bytes(log);raise


def capture(*args,**kwargs):
    with patch.object(full,'start',start),patch.object(full,'validate',validate):return FROZEN_CAPTURE(*args,**kwargs)


def host(args):
    reference=args.compact_reference.absolute();q.native.private_area(reference)
    old=json.loads((reference/'result.json').read_text());q.require(old['compact_wait_controls_passed'] and old['case_count']==16,'Qualified compact reference required')
    for n,h in old['extension']['source_sha256'].items():q.require(q.digest(ROOT/n)==h,'Frozen compact source changed: '+n)
    for n,h in old['extension']['compiled_sha256'].items():q.require(q.digest(reference/n)==h,'Frozen compact binary changed: '+n)
    sha=q.digest(reference/'result.json')
    with patch.object(compact,'build',lambda a,f,r,w:build(a,f,r,w,sha)),patch.object(compact,'capture',capture):COMPACT_HOST(args)
    area=args.output.absolute();core=json.loads((area/'result.json').read_text())
    for n,h in core['extension']['handoff_generated_sha256'].items():q.require(q.digest(area/n)==h,'Generated handoff source changed')
    q.require(q.digest(reference/'result.json')==sha,'Compact qualification changed')
    positive=[row['validation'] for row in core['cases'] if row.get('validation',{}).get('stream_quality_passed')]
    early=sum(v['early_wake_handoff_segments'] for v in positive)
    core.update(kind='bc250-handoff-wait-qualification',handoff_wait_controls_passed=True,
        scheduler_timestamp_basis='hook-entry-v1',native_early_wake_segments_observed=early,
        native_early_wake_order_qualified=False,early_wake_independent_overlap_witness_qualified=False,
        handoff_overhead_qualified=False,compact_reference_result_sha256=sha)
    (area/'result.json').write_text(json.dumps(core,indent=2)+'\n')
    print(json.dumps(dict(passed=True,cases=core['case_count'],owned_programs=28,early_segments_observed=early,
        native_early_wake_qualified=False,overhead_qualified=False)),flush=True)


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('step',choices=('run','_host'))
    names=('reference','physical-reference','request-reference','folio-reference','combined-reference','compact-reference','output')
    for name in names:p.add_argument('--'+name,type=Path,required=True)
    args=p.parse_args();q.require(sys.platform=='linux' and os.geteuid()==0,'Linux root required')
    if args.step=='_host':host(args);return
    paths=[]
    for name in names:paths+=['--'+name,str(getattr(args,name.replace('-','_')))]
    unit='bc250-handoff-wait-'+uuid.uuid4().hex[:12]
    subprocess.run(['systemd-run','--quiet','--wait','--pipe','--collect','--unit='+unit,'--property=MemoryMax=2G','--property=CPUQuota=200%',
        '--property=MemorySwapMax=0','--property=TasksMax=128','--property=RuntimeMaxSec=360','--property=KillMode=control-group',
        '/usr/bin/unshare','--mount','--propagation','private','/usr/bin/python3','-B',str(Path(__file__).resolve()),'_host',*paths],check=True,timeout=390)


if __name__=='__main__':main()
