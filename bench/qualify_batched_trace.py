#!/usr/bin/env python3
"""Derive and qualify an opt-in batched observer without editing its baseline.

The generated sources differ only in ring notification/consumption. Reuse the
original five-case qualification, pin both source versions, preserve failures.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import uuid

import qualify_request_trace as q
import native_trial_lab as ownership

ROOT=Path(__file__).resolve().parents[1]


def replace_once(text,old,new):
    q.require(text.count(old)==1,'Expected exactly one frozen source anchor')
    return text.replace(old,new)


def derived_text(name):
    text=(ROOT/'bench'/name).read_text()
    if name=='request_trace.bpf.c':
        return replace_once(text,'bpf_ringbuf_output(&events,&event,sizeof(event),0)',
            'bpf_ringbuf_output(&events,&event,sizeof(event),BPF_RB_NO_WAKEUP)')
    if name=='request_trace.c':
        text=replace_once(text,
            '        if(result<0 && result!=-EINTR)goto cleanup;\n',
            '        if(result<0 && result!=-EINTR)goto cleanup;\n'
            '        /* NO_WAKEUP records need explicit bounded periodic consumption. */\n'
            '        if(ring_buffer__consume(ring)<0)goto cleanup;\n')
        return replace_once(text,'    while(ring_buffer__consume(ring)>0){}\n',
            '    int drained;\n'
            '    do {drained=ring_buffer__consume(ring);if(drained<0)goto cleanup;} while(drained>0);\n')
    return text


def read_controls(area,report):
    checks=[]
    for label,expected in [('serial-direct',2048),('overlapping-direct',8192)]:
        raw=json.loads((area/(label+'-raw-private.json')).read_text())
        work=json.loads((area/(label+'-workload-private.json')).read_text())
        reads=[r for r in raw['records'] if r['operation']==0]
        window=[r for r in reads if work['start_monotonic_ns']<=r['issue_ns']
            <=r['complete_ns']<=work['finish_monotonic_ns']]
        check=dict(case=label,expected_reads=expected,captured_reads=len(reads),
            expected_read_bytes=expected*4096,captured_read_bytes=raw['read_completed_bytes'],
            flagged_read_records=sum(bool(r['flags']) for r in reads),
            other_records=raw['events']-len(reads),whole_window_flagged_records=raw['flagged_events'],
            timed_window_reads=len(window),timed_window_bytes=sum(r['completed_bytes'] for r in window),
            timed_window_flagged_reads=sum(bool(r['flags']) for r in window),
            whole_capture_exact_read_accounting_passed=len(reads)==expected
                and raw['read_completed_bytes']==expected*4096 and not any(r['flags'] for r in reads))
        checks.append(check)
        q.require(len(window)==expected and check['timed_window_bytes']==expected*4096
            and not check['timed_window_flagged_reads'],'Timed-window known read accounting failed')
    report.update(read_control_checks=checks,known_read_window_accounting_passed=True,
        whole_capture_exact_read_accounting_passed=all(r['whole_capture_exact_read_accounting_passed'] for r in checks),
        whole_window_quality_screen_passed=all(not r['whole_window_flagged_records'] for r in checks),
        accounting_scope='Synthetic worker start/finish markers; whole-capture counts retained separately; no foreground attribution',
        application_tracing_qualified=False,overhead_screen_passed=False)


def cap_control(area,device,label,work,limit,expect_cap):
    """Start reads immediately; inventory collection can outlive a small cap."""
    q.require(expect_cap and work is not None,'Cap-only helper')
    cold=q.residency(area/'fixture.bin',evict=True);q.require(cold==0,'Cap fixture not cache-cold')
    proc,ids,log=q.start(area,device,2,limit)
    try:
        threads,ops,pattern=work
        workload=json.loads(q.command(area/'direct-probe',area/'fixture.bin',threads,ops,pattern,timeout=15))
        stdout,stderr=proc.communicate(timeout=10);log+=stderr
        (area/(label+'-raw-private.json')).write_bytes(stdout)
        (area/(label+'-workload-private.json')).write_text(json.dumps(workload,indent=2)+'\n')
        (area/(label+'.loader.log')).write_bytes(log)
        q.require(proc.returncode==0 and workload['passed'],'Cap observer/workload failed')
        raw=json.loads(stdout);checked=q.validate(raw)
        q.require(raw['event_limit_reached'] and not checked['transport_complete'],'Cap hidden')
        q.require(sum(r['operation']==0 for r in raw['records'])>0,'Cap preceded all dedicated reads')
        q.require(q.absent(ids),'Owned cap observer programs remain')
        resident=q.residency(area/'fixture.bin');q.require(resident==0,'Cap fixture became resident')
        return dict(case=label,passed=True,events=raw['events'],kernel_counters=checked['kernel_counters'],
            limit_discarded_records=raw['limit_discarded_records'],right_censored_requests=raw['right_censored_requests'],
            transport_complete=False,event_limit_reached=True,wire_consistent=True,owned_programs_gone=True,
            known_direct_read_bytes=workload['read_bytes'],read_completed_bytes=raw['read_completed_bytes'],
            fixture_resident_before_bytes=cold,fixture_resident_after_bytes=resident,
            pre_workload_inventory_query_omitted=True)
    finally:q.finish(proc)


def consumption_edges(area,device):
    """Stress only the owned observer and the disposable read fixture."""
    cases=[]
    for label,threads,operations,stall in [('early-interrupt-drain',1,8,False),
            ('stalled-consumer-ring-overflow',4,30000,True)]:
        q.require(q.residency(area/'fixture.bin',evict=True)==0,'Private fixture not cache-cold')
        proc,ids,log=q.start(area,device,10,200000)
        try:
            if stall:proc.send_signal(signal.SIGSTOP)
            work=json.loads(q.command(area/'direct-probe',area/'fixture.bin',threads,operations,'same',timeout=15))
            q.require(work['passed'] and work['operations']==threads*operations,'Known edge workload failed')
            if stall:proc.send_signal(signal.SIGCONT)
            # Terminate intentionally. The trace stays explicitly interrupted,
            # while its final transport accounting must remain self-consistent.
            proc.send_signal(signal.SIGINT)
            stdout,stderr=proc.communicate(timeout=15);log+=stderr
            (area/(label+'-raw-private.json')).write_bytes(stdout)
            (area/(label+'.loader.log')).write_bytes(log)
            (area/(label+'-workload-private.json')).write_text(json.dumps(work,indent=2)+'\n')
            q.require(proc.returncode==0 and q.absent(ids),'Edge observer failed or left programs')
            raw=json.loads(stdout);checked=q.validate(raw);stats=checked['kernel_counters']
            q.require(raw['interrupted'] and not checked['transport_complete'],'Intentional interruption hidden')
            resident=q.residency(area/'fixture.bin');q.require(resident==0,'Read edge populated fixture cache')
            if stall:
                q.require(stats['ring_lost']>0 and stats['final']>=threads*operations,
                    'Stopped consumer did not demonstrate explicit ring overflow')
            else:
                q.require(raw['elapsed_ns']<50*10**6,'Early termination did not precede first poll timeout')
                reads=[r for r in raw['records'] if r['operation']==0]
                q.require(len(reads)==operations and raw['read_completed_bytes']==work['read_bytes']
                    and not any(r['flags'] for r in reads) and not stats['ring_lost'],
                    'Early final drain lost known reads')
            cases.append(dict(case=label,passed=True,expected_read_operations=threads*operations,
                expected_read_bytes=work['read_bytes'],saved_records=raw['events'],
                captured_read_bytes=raw['read_completed_bytes'],kernel_counters=stats,
                elapsed_ns=raw['elapsed_ns'],transport_complete=False,intentionally_interrupted=True,
                wire_consistent=True,owned_programs_gone=True,fixture_resident_after_bytes=resident))
            print(json.dumps(cases[-1]),flush=True)
        finally:
            if proc.poll() is None:proc.send_signal(signal.SIGCONT)
            q.finish(proc)
    return cases


def host(args):
    q.native.confined();output=args.output.absolute();qualified=args.qualified.absolute()
    q.native.private_area(output,creating=True);q.native.private_area(qualified)
    reference=ownership.safe_json(qualified/'result.json')
    q.require(reference['passed'] and reference['case_count']==5 and reference['all_owned_programs_gone'],
        'Use a passing original observer qualification')
    q.require(os.uname().release==reference['kernel'],'Qualified kernel changed')
    for name,value in reference['source_sha256'].items():
        q.require(q.digest(ROOT/name)==value,'Original qualified source changed: '+name)
    for name,value in reference['compiled_sha256'].items():
        q.require(q.digest(qualified/name)==value,'Original qualified binary changed')
    source=output.with_name(output.name+'-sources')
    q.native.private_area(source,creating=True);q.native.host_space(output.parent)
    source.mkdir(mode=0o700);(source/'bench').mkdir();(source/'analysis').mkdir()
    names=('request_trace.bpf.c','request_trace.c','request_trace.h','direct_probe.c')
    for name in names:(source/'bench'/name).write_text(derived_text(name))
    shutil.copyfile(ROOT/'analysis/request_trace.py',source/'analysis/request_trace.py')
    manifest=dict(variant='batched-no-wakeup-50ms',schema_version=1,
        baseline_source_sha256=reference['source_sha256'],baseline_compiled_sha256=reference['compiled_sha256'],
        baseline_qualification_report_sha256=q.digest(qualified/'result.json'),
        driver_sha256=q.digest(Path(__file__)),
        derived_source_sha256={'bench/'+name:q.digest(source/'bench'/name) for name in names},
        notification_mode='BPF_RB_NO_WAKEUP',consume_poll_timeout_ms=50,
        explicit_consume_each_poll=True,checked_final_drain_after_detach=True,
        request_identity_or_timestamp_logic_changed=False,production_observer_enabled=False)
    (source/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    # Keep ABI/build/fixture/ordinary-read/forced-exit logic unchanged. For the
    # deliberately tiny cap, a synchronous inventory query after READY races
    # background I/O; validate cleanup after immediate dedicated reads instead.
    q.ROOT=source
    original_case=q.run_case
    def run_case(area,device,label,work=None,limit=200000,expect_cap=False):
        if expect_cap:return cap_control(area,device,label,work,limit,expect_cap)
        return original_case(area,device,label,work,limit,expect_cap)
    q.run_case=run_case
    q.host(args)
    path=output/'result.json';report=json.loads(path.read_text())
    # Preserve the original five-case result separately. A later edge failure
    # must not leave the broad variant verdict looking complete.
    path.rename(output/'ordinary-qualification.json')
    read_controls(output,report)
    before=q.trace_state();inventory=q.programs();device=q.block_device(output)
    fixture_sha=q.digest(output/'fixture.bin')
    edges=consumption_edges(output,device)
    q.require(q.trace_state()==before and q.programs()==inventory,'Edge test changed unrelated tracing')
    q.require(q.digest(output/'fixture.bin')==fixture_sha,'Edge fixture changed')
    ns=(Path('/sys/class/block')/device.name).resolve(strict=True);linked=(ns/'device').resolve(strict=True)
    controllers=[p for p in Path('/sys/class/nvme').iterdir() if p.resolve() in ns.parents or p.resolve()==linked]
    q.require(len(controllers)==1 and (controllers[0]/'power/pm_qos_latency_tolerance_us').read_text().strip()=='5000',
        'Working drive policy changed during edge tests')
    report['cases'].extend(edges);report['case_count']=len(report['cases'])
    report['derived_qualification_source_sha256']=report.pop('source_sha256')
    report.update(manifest)
    report['source_sha256']={'bench/qualify_batched_trace.py':q.digest(Path(__file__))}
    q.require(all(q.digest(ROOT/name)==value for name,value in reference['source_sha256'].items()),
        'Original source changed during qualification')
    q.require(all(q.digest(output/name)==manifest['derived_source_sha256']['bench/'+name] for name in names),
        'Compiled source does not match derived manifest')
    path.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(dict(variant=manifest['variant'],passed=True,cases=report['case_count'])),flush=True)


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('step',choices=('run','_host'))
    parser.add_argument('--qualified',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();q.require(sys.platform=='linux' and os.geteuid()==0,'Requires root on Linux')
    if args.step=='_host':host(args);return
    unit='bc250-batched-qualification-'+uuid.uuid4().hex[:12]
    print(json.dumps(dict(parent_unit=unit)),flush=True)
    subprocess.run(['systemd-run','--quiet','--wait','--pipe','--collect','--unit='+unit,
        '--property=MemoryMax=2G','--property=MemoryHigh=1536M','--property=MemorySwapMax=0',
        '--property=CPUQuota=200%','--property=RuntimeMaxSec=300','--property=KillMode=control-group',
        '--property=TimeoutStopSec=15','/usr/bin/unshare','--mount','--propagation','private',
        '/usr/bin/python3',str(Path(__file__).resolve()),'_host','--qualified',str(args.qualified),
        '--output',str(args.output)],check=True,timeout=330)


if __name__=='__main__':main()
