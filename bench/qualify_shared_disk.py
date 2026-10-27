#!/usr/bin/env python3
"""Qualify one cached disk-pointer traversal per request callback.

The original source, loader, flags, wire format and qualification stay frozen.
This separate variant removes duplicate CO-RE pointer traversal only. It is an
opt-in measurement experiment, never a production service or acceleration claim.
"""
import argparse
import collections
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import uuid

import qualify_batched_trace as controls

q=controls.q
ROOT=Path(__file__).resolve().parents[1]
OLD='''    if (BPF_CORE_READ(rq,q,disk,major)!=cfg->major ||
        BPF_CORE_READ(rq,q,disk,first_minor)!=cfg->minor)return false;'''
NEW='''    struct gendisk *disk=BPF_CORE_READ(rq,q,disk);
    if (BPF_CORE_READ(disk,major)!=cfg->major ||
        BPF_CORE_READ(disk,first_minor)!=cfg->minor)return false;'''


def derive(text):
    if text.count(OLD)!=1:raise ValueError('Expected exactly one frozen disk lookup anchor')
    return text.replace(OLD,NEW,1)


def helper_sites(path):
    text=q.command('llvm-objdump','-d',path);sections={};name=None
    for line in text.splitlines():
        match=re.fullmatch('Disassembly of section (.+):',line)
        if match:name=match[1];sections[name]=collections.Counter()
        helper=re.search(r'\bcall\s+(0x[0-9a-f]+|[0-9]+)',line)
        if helper and name:sections[name][str(int(helper[1],0))]+=1
    return {key:dict(value) for key,value in sections.items()}


def host(args):
    q.native.confined();output=args.output.absolute();qualified=args.qualified.absolute()
    q.native.private_area(output,creating=True);q.native.private_area(qualified);q.native.host_space(output.parent)
    reference=controls.ownership.safe_json(qualified/'result.json')
    q.require(reference['passed'] and reference['case_count']==5 and reference['all_owned_programs_gone'],'Use the original passing qualification')
    q.require(os.uname().release==reference['kernel'],'Original qualified kernel changed')
    for name,sha in reference['source_sha256'].items():q.require(q.digest(ROOT/name)==sha,'Frozen original source changed: '+name)
    for name,sha in reference['compiled_sha256'].items():q.require(q.digest(qualified/name)==sha,'Frozen original binary changed')
    source=output.with_name(output.name+'-sources');q.native.private_area(source,creating=True)
    source.mkdir(mode=0o700);(source/'bench').mkdir();(source/'analysis').mkdir()
    names=('request_trace.bpf.c','request_trace.c','request_trace.h','direct_probe.c')
    for name in names:
        text=(ROOT/'bench'/name).read_text()
        (source/'bench'/name).write_text(derive(text) if name=='request_trace.bpf.c' else text)
    shutil.copyfile(ROOT/'analysis/request_trace.py',source/'analysis/request_trace.py')
    manifest=dict(schema_version=1,variant='shared-disk-pointer',baseline_source_sha256=reference['source_sha256'],
        baseline_compiled_sha256=reference['compiled_sha256'],baseline_qualification_report_sha256=q.digest(qualified/'result.json'),
        driver_sha256=q.digest(Path(__file__)),shared_control_helpers_sha256=q.digest(ROOT/'bench/qualify_batched_trace.py'),
        derived_source_sha256={'bench/'+name:q.digest(source/'bench'/name) for name in names},
        changed_source_files=['bench/request_trace.bpf.c'],notification_mode='original-adaptive',loader_changed=False,
        request_identity_timestamp_flags_schema_changed=False,operation_coverage_changed=False,production_observer_enabled=False)
    (source/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    q.ROOT=source;original_case=q.run_case
    def run_case(area,device,label,work=None,limit=200000,expect_cap=False):
        if expect_cap:return controls.cap_control(area,device,label,work,limit,expect_cap)
        return original_case(area,device,label,work,limit,expect_cap)
    q.run_case=run_case;q.host(args)
    path=output/'result.json';report=json.loads(path.read_text());path.rename(output/'ordinary-qualification.json')
    controls.read_controls(output,report)
    before=q.trace_state();inventory=q.programs();device=q.block_device(output);fixture_sha=q.digest(output/'fixture.bin')
    edges=controls.consumption_edges(output,device)
    q.require(q.trace_state()==before and q.programs()==inventory,'Edge controls changed unrelated tracing')
    q.require(q.digest(output/'fixture.bin')==fixture_sha,'Edge control changed fixture contents')
    q.require(Path('/sys/class/nvme/nvme0/power/pm_qos_latency_tolerance_us').read_text().strip()=='5000','Drive policy changed')
    original_sites=helper_sites(qualified/'request_trace.bpf.o');derived_sites=helper_sites(output/'request_trace.bpf.o')
    for name in ('insert','issue','requeue','complete'):
        section='raw_tp/block_rq_'+name
        q.require(derived_sites[section].get('113',0)==original_sites[section].get('113',0)-2,'Expected helper-site reduction not compiled')
    report['cases'].extend(edges);report['case_count']=len(report['cases'])
    report['derived_qualification_source_sha256']=report.pop('source_sha256');report.update(manifest)
    report['source_sha256']={'bench/qualify_shared_disk.py':q.digest(Path(__file__)),
        'bench/qualify_batched_trace.py':q.digest(ROOT/'bench/qualify_batched_trace.py')}
    report.update(static_original_helper_sites=original_sites,static_derived_helper_sites=derived_sites,
        helper_site_counts_are_runtime_measurements=False,overhead_screen_passed=False)
    q.require(all(q.digest(ROOT/name)==sha for name,sha in reference['source_sha256'].items()),'Original source changed during qualification')
    q.require(all(q.digest(output/name)==manifest['derived_source_sha256']['bench/'+name] for name in names),'Derived source changed')
    path.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(dict(passed=True,variant=manifest['variant'],cases=report['case_count'])),flush=True)


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('step',choices=('run','_host'))
    parser.add_argument('--qualified',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    q.require(os.geteuid()==0,'Linux root required')
    if args.step=='_host':host(args);return
    unit='bc250-disk-lookup-'+uuid.uuid4().hex[:12]
    subprocess.run(['systemd-run','--quiet','--wait','--pipe','--collect','--unit='+unit,'--property=MemoryMax=2G',
        '--property=MemorySwapMax=0','--property=CPUQuota=200%','--property=TasksMax=128','--property=RuntimeMaxSec=300',
        '--property=KillMode=control-group','/usr/bin/unshare','--mount','--propagation','private','/usr/bin/python3','-B',
        str(Path(__file__).resolve()),'_host','--qualified',str(args.qualified),'--output',str(args.output)],check=True,timeout=330)


if __name__=='__main__':main()
