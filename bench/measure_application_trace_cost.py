#!/usr/bin/env python3
"""Fixed off/v2 pairs using the unchanged native Konsole endpoint and corpus.

Only selected private copied data is conditioned. No production cache reset,
drive setting, installed service or boot change. Private traces are deferred
until collection ends. This is incremental tracing cost, not absolute fixture
cost or foreground attribution.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
import uuid
from unittest.mock import patch

import native_application_inputs as native
import qualify_trace_v2 as observer
import measure_trace_overhead as pilot
from application_trace_v2 import review_capture
from application_trace_cost import CONTRACT, planned_order, summarize

q=native.q
ROOT=Path(__file__).resolve().parents[1]


def admit(peer,message,expected,nonce,phase):
    q.require(peer[:2]==(expected['pid'],expected['uid']), 'Unowned cost-control client')
    q.require(message==dict(nonce=nonce,phase=phase), 'Invalid cost-control phase/nonce')


def protocol(order):
    result=[]
    for scenario,outer in zip(CONTRACT['scenarios'],('cold','warm')):
        result.append((outer+'-before',None,'outer'))
        for index,item in enumerate(order):
            if item['scenario']==scenario:
                result.extend((('measure-%d-before'%index,index,'before'),('measure-%d-after'%index,index,'after')))
        result.append((outer+'-after',None,'outer'))
    return result


def condition(rows,warm):
    private=[dict(copy=r['copy'],bytes=r['bytes']) for r in rows]
    if warm:
        # Warming is outside the common quiet interval and endpoint.
        for row in rows:q.require(q.digest(Path(row['copy']))==row['sha256'],'Copied input changed')
    state=native.cache_state(private,evict=not warm)
    q.require(state['resident_bytes']==(state['page_rounded_bytes'] if warm else 0),'Selected data cache precondition failed')
    return state


def exclusions(quiet,before,after):
    delta=[b-a for a,b in zip(quiet['cpu'],before['cpu'])];total=sum(delta[:8]);idle=delta[3]+delta[4]
    busy=(total-idle)/total if total else 0
    pre_io=((before['disk'][2]-quiet['disk'][2])+(before['disk'][6]-quiet['disk'][6]))*512
    reasons=[]
    if busy>CONTRACT['background_cpu_fraction_max']:reasons.append('pre-workload-cpu-busy')
    if pre_io>CONTRACT['pre_workload_device_bytes_max']:reasons.append('pre-workload-device-busy')
    if min(before['memory']['MemAvailable'],after['memory']['MemAvailable'])<CONTRACT['minimum_available_bytes']:reasons.append('low-available-memory')
    if pilot.policy(before)!=pilot.policy(after):reasons.append('cpu-policy-changed')
    def throttle(value):return int(dict(line.split() for line in value['cgroup_cpu_stat'].splitlines()).get('nr_throttled',0))
    throttled=throttle(after)-throttle(before)
    if throttled:reasons.append('parent-cgroup-cpu-throttled')
    return reasons,busy,pre_io,throttled


def view(args):
    cfg=json.loads((args.output/'view-private.json').read_text());desktop=Path(cfg['desktop'])
    order=json.loads((args.output/'cost-order.json').read_text());original=native.terminal.trial
    def sweep(area,outer_index,env,timeout,hold):
        scenario=CONTRACT['scenarios'][outer_index];last=None
        for index,item in enumerate(order):
            if item['scenario']!=scenario:continue
            native.cache_request(cfg,'measure-%d-before'%index)
            start=time.monotonic_ns()
            try:last=original(area,index,env,timeout,hold)
            finally:
                native.terminal.save(desktop/('envelope-%d-private.json'%index),dict(start_ns=start,finish_ns=time.monotonic_ns()))
            native.cache_request(cfg,'measure-%d-after'%index)
        q.require(last is not None,'Empty scenario sweep')
        return last
    with patch.object(native.terminal,'trial',sweep):native.view(args)


class Collector:
    def __init__(self,area,desktop,inputs,device,order):
        self.area,self.desktop,self.inputs,self.device,self.order=area,desktop,inputs,device,order
        self.rows=[];self.captures=[];self.active=None;self.pending=None

    def before(self,index):
        q.require(self.pending is None and self.active is None,'Previous trial not closed')
        item=self.order[index];state=condition(self.inputs,item['scenario']=='selected-data-warm')
        slot=time.monotonic_ns();startup=None
        if item['condition']=='v2':
            self.active=observer.start(self.area/'observer',self.device,duration=CONTRACT['capture_seconds'],limit=CONTRACT['max_saved_records'])
            startup=time.monotonic_ns()-slot
        else:q.programs()
        # Verify selected-page state once more after attach/inventory, before
        # the common quiet interval. Never infer it from an ordinary UID probe.
        verified=native.cache_state([dict(copy=r['copy'],bytes=r['bytes']) for r in self.inputs])
        q.require(verified['resident_bytes']==state['resident_bytes'],'Cache state changed during observer setup')
        quiet=pilot.environment(self.device);time.sleep(CONTRACT['post_setup_idle_seconds']);before=pilot.environment(self.device)
        self.pending=dict(index=index,item=item,state=state,slot=slot,startup=startup,quiet=quiet,before=before)
        return state

    def after(self,index):
        q.require(self.pending is not None and self.pending['index']==index,'Unexpected trial completion')
        after=pilot.environment(self.device);pending=self.pending;raw=None;log=b'';checked=None
        envelope=json.loads((self.desktop/('envelope-%d-private.json'%index)).read_text())
        trial=json.loads((self.desktop/('trial-%02d/result-private.json'%index)).read_text())
        q.require(trial['passed'] and trial['normal_close_verified'] and trial['owned_terminal_gone'],'Application endpoint or cleanup failed')
        integrity=bool(trial['cpu_policy_unchanged'])
        if self.active:
            proc,ids,log=self.active
            out,err=proc.communicate(timeout=10);log+=err
            self.captures.append((out,log))
            q.require(sum(len(value or b'') for value,_ in self.captures)<=CONTRACT['maximum_retained_raw_bytes'], 'Aggregate private capture bound')
            q.require(proc.returncode==0 and q.absent(ids),'Observer failed or left programs')
            raw=json.loads(out);checked=review_capture(raw,envelope,trial)
            integrity=bool(integrity and checked['capture_integration_passed'])
            self.active=None
        else:
            self.captures.append((None,b''))
            remaining=CONTRACT['capture_seconds']-(time.monotonic_ns()-pending['slot'])/1e9
            if remaining>0:time.sleep(remaining)
        state=native.cache_state([dict(copy=r['copy'],bytes=r['bytes']) for r in self.inputs])
        reasons,busy,pre_io,throttled=exclusions(pending['quiet'],pending['before'],after)
        row=dict(pending['item'],workload=dict(elapsed_ns=trial['launch_to_pty_ready_ns']),capture_integrity=integrity,
            environment_exclusions=reasons,pre_workload_cpu_fraction=busy,pre_workload_device_bytes=pre_io,
            parent_cgroup_throttled_periods_delta=throttled,cache_before=pending['state'],cache_after=state,
            observer_startup_ns=pending['startup'],capture_review=checked,before=pending['before'],after=after,
            endpoint_passed=True,normal_close_verified=True,owned_terminal_gone=True,
            trial_envelope_ns=envelope['finish_ns']-envelope['start_ns'])
        self.rows.append(row);self.pending=None
        return state

    def cleanup(self):
        if self.active:
            proc,ids,_=self.active;q.finish(proc);q.require(q.absent(ids),'Owned programs remain');self.active=None

    def serve(self,server,expected,nonce,errors):
        try:
            for phase,index,kind in protocol(self.order):
                channel,_=server.accept()
                with channel:
                    channel.settimeout(10)
                    peer=struct.unpack('3i',channel.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
                    message=native.terminal.receive_marker(channel)
                    admit(peer,message,expected,nonce,phase)
                    if kind=='before':state=self.before(index)
                    elif kind=='after':state=self.after(index)
                    elif phase.endswith('-before'):state=condition(self.inputs,phase=='warm-before')
                    else:state=native.cache_state([dict(copy=r['copy'],bytes=r['bytes']) for r in self.inputs])
                    channel.sendall(json.dumps(dict(state=state)).encode()+b'\n')
        except BaseException as exc:errors.append(repr(exc))


def prepare(area,desktop,native_qualified,qualified):
    """Reuse only the verified private corpus through new read-only bindings."""
    for path in (native_qualified,qualified):q.native.private_area(path)
    report=json.loads((native_qualified/'result.json').read_text())
    q.require(report['passed'] and report['source_and_corpus_unchanged'] and report['normal_close_left_no_view_processes'],'Native reference differs')
    for name,sha in report['source_sha256'].items():q.require(q.digest(ROOT/'bench'/name)==sha,'Native source differs: '+name)
    manifest=json.loads((native_qualified/'manifest-private.json').read_text())
    q.require(native.inventory(native_qualified/'corpus',set(manifest))==manifest,'Native copied reference changed')
    reference=json.loads((qualified/'result.json').read_text())
    q.require(reference['passed'] and reference['case_count']==10 and reference['kernel']==os.uname().release,'V2 qualification differs')
    for name,sha in reference['source_sha256'].items():q.require(q.digest(ROOT/name)==sha,'V2 source differs: '+name)
    old_cfg=json.loads((native_qualified/'view-private.json').read_text());uid=old_cfg['uid'];gid=old_cfg['gid']
    for name in ('view-root','runtime','private-tmp','private-vartmp'):(area/name).mkdir(mode=0o755)
    (area/'private-tmp').chmod(0o1777);(area/'private-vartmp').chmod(0o1777)
    (area/'corpus').symlink_to(native_qualified/'corpus',target_is_directory=True)
    for name in ('mount-helper.so','utmp-check'):shutil.copyfile(native_qualified/name,area/name);(area/name).chmod(0o755)
    q.require(q.digest(area/'mount-helper.so')==q.digest(native_qualified/'mount-helper.so') and
              q.digest(area/'utmp-check')==q.digest(native_qualified/'utmp-check'),'Native helpers differ')
    for name in ('utmp','wtmp'):
        target=area/'runtime'/name;target.touch(mode=0o664);os.chown(target,0,(native_qualified/'runtime'/name).stat().st_gid);target.chmod(0o664)
    desktop.mkdir(mode=0o700);os.chown(desktop,uid,gid);(desktop/'home').mkdir(mode=0o700);os.chown(desktop/'home',uid,gid)
    cfg=dict(old_cfg,desktop=str(desktop),parent_mount=os.readlink('/proc/self/ns/mnt'),observer_pid=os.getpid(),observer_nonce=uuid.uuid4().hex)
    native.terminal.save(area/'view-private.json',cfg)
    (area/'observer').mkdir(mode=0o700)
    for name in ('request-trace-v2','request_trace_v2.bpf.o'):
        sha=reference['compiled_sha256'][name];q.require(q.digest(qualified/name)==sha,'V2 binary differs')
        shutil.copyfile(qualified/name,area/'observer'/name);(area/'observer'/name).chmod(0o700 if name=='request-trace-v2' else 0o600)
    inputs=[dict(row,copy=str(native_qualified/'corpus'/row['target'].lstrip('/'))) for row in cfg['regular_inputs']]
    for row in inputs:
        info=Path(row['copy']).stat();q.require((info.st_dev,info.st_ino,info.st_size)==(row['device'],row['inode'],row['bytes']),'Prepared inode differs')
    return cfg,inputs,manifest,reference


def host(args):
    q.native.confined();area=args.output.absolute();desktop=args.desktop_output.absolute()
    q.native.private_area(area,creating=True);q.native.private_area(desktop,creating=True);q.native.host_space(area.parent)
    device=q.block_device(area.parent);q.require(device==q.block_device(Path('/')),'Physical namespace differs')
    qos=Path('/sys/class/nvme/nvme0/power/pm_qos_latency_tolerance_us');q.require(qos.read_text().strip()=='5000','Power policy differs')
    state,inventory=q.trace_state(),q.programs();area.mkdir(mode=0o700)
    cfg,inputs,manifest,reference=prepare(area,desktop,args.native_qualified.absolute(),args.qualified.absolute())
    order=planned_order();native.terminal.save(area/'cost-order.json',order)
    names=('bench/measure_application_trace_cost.py','analysis/application_trace_cost.py','bench/native_application_inputs.py',
        'bench/terminal_endpoint.py','bench/copied_input_probe.py','bench/measure_trace_overhead.py','analysis/application_trace_v2.py',
        'analysis/trace_v2_overhead.py','analysis/trace_overhead.py','analysis/request_trace_v2.py','bench/qualify_trace_v2.py')
    sources={name:q.digest(ROOT/name) for name in names}
    contract=dict(CONTRACT,order=order,source_sha256=sources,kernel=os.uname().release,
        native_reference_sha256=q.digest(args.native_qualified/'result.json'),v2_reference_sha256=q.digest(args.qualified/'result.json'),
        compiled_sha256=reference['compiled_sha256'],native_manifest_sha256=q.digest(args.native_qualified/'manifest-private.json'),
        contract_fsynced_before_collection=True,progress_and_trace_output_deferred=True,
        timed_interval_additional_io_attribution_unqualified=True,foreground_cgroup_limits_qualified=False)
    native.terminal.save(area/'contract.json',contract)
    with (area/'contract.json').open('rb') as stream:os.fsync(stream.fileno())
    collector=Collector(area,desktop,inputs,device,order);errors=[];expected=dict(pid=None,uid=cfg['uid'])
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as server:
        sock=desktop/'cache-observer.sock';server.bind(str(sock));os.chown(sock,cfg['uid'],cfg['gid']);sock.chmod(0o600);server.listen(1);server.settimeout(30)
        child=subprocess.Popen(['unshare','--mount','--propagation','private','python3','-B',str(Path(__file__).resolve()),'_view','--output',str(area)],
            stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
        expected['pid']=child.pid;thread=threading.Thread(target=collector.serve,args=(server,expected,cfg['observer_nonce'],errors),daemon=True);thread.start()
        try:
            output,_=child.communicate(timeout=840);(area/'view-private.log').write_text(output)
            thread.join(timeout=2);q.require(child.returncode==0 and not thread.is_alive() and not errors,'View/collector failed: '+str(errors))
        finally:
            if child.poll() is None:child.kill();child.wait(timeout=10)
            server.close();thread.join(timeout=2);collector.cleanup()
            native.terminal.save(area/'cleanup.json',dict(remaining_view_processes=0,signals_sent=native.cleanup_view(area)))
            sock.unlink()
            native.terminal.save(area/'trials-private.json',collector.rows)
            for index,(raw,log) in enumerate(collector.captures):
                if raw is not None:(area/('trace-%d-private.json'%index)).write_bytes(raw)
                (area/('trace-%d-loader-private.log'%index)).write_bytes(log)
            q.require(q.trace_state()==state and q.programs()==inventory and qos.read_text().strip()=='5000','Trace/program/power state differs')
    # Pair-wide policy drift disqualifies both members, without deleting them.
    for scenario in CONTRACT['scenarios']:
        for pair in range(CONTRACT['pairs_per_scenario']):
            group=[r for r in collector.rows if r['scenario']==scenario and r['pair']==pair and not r['warmup']]
            policies={json.dumps(pilot.policy(r[phase]),sort_keys=True) for r in group for phase in ('before','after')}
            if len(policies)!=1:
                for row in group:row['environment_exclusions'].append('cpu-policy-changed-within-pair')
    q.require(native.inventory(args.native_qualified/'corpus',set(manifest))==manifest,'Prepared corpus changed')
    for name,sha in sources.items():q.require(q.digest(ROOT/name)==sha,'Source changed: '+name)
    for name in ('request-trace-v2','request_trace_v2.bpf.o'):q.require(q.digest(area/'observer'/name)==reference['compiled_sha256'][name],'Copied observer changed')
    native_result=json.loads((desktop/'result.json').read_text())
    q.require(native_result['passed'] and len(native_result['private_session_checks'])==len(order),'Incomplete native session checks')
    native.terminal.save(area/'trials-final-private.json',collector.rows)
    result=dict(collection_complete=True,contract=contract,summary=summarize(collector.rows,contract),
        private_selected_corpus_unchanged=True,one_prepared_corpus_for_both_conditions=True,owned_processes_remaining=0,
        all_owned_programs_gone=True,global_trace_state_unchanged=True,unrelated_program_inventory_unchanged=True,
        readonly_binding_checks_per_trial=len(inputs),private_owned_session_checks=len(order),
        controller_capabilities_zero=native_result['controller_capabilities_zero'],nvme_qos_us=5000,
        production_observer_enabled=False,global_cache_reset_performed=False,accelerator_gain_comparison=False,stage1_gate_passed=False)
    native.terminal.save(area/'result.json',result);print(json.dumps(result['summary']),flush=True)


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('step',choices=('run','_host','_view'))
    for name in ('output','desktop-output','native-qualified','qualified'):parser.add_argument('--'+name,type=Path,required=name=='output')
    args=parser.parse_args();q.require(sys.platform=='linux' and os.geteuid()==0,'Linux root setup required')
    if args.step=='_view':view(args);return
    q.require(all((args.desktop_output,args.native_qualified,args.qualified)),'All fixture paths required')
    if args.step=='_host':host(args);return
    unit='bc250-application-cost-'+uuid.uuid4().hex[:12]
    subprocess.run(['systemd-run','--quiet','--wait','--pipe','--collect','--unit='+unit,'--property=MemoryMax=2G',
        '--property=MemorySwapMax=0','--property=CPUQuota=200%','--property=TasksMax=128','--property=RuntimeMaxSec=900',
        '--property=KillMode=control-group','/usr/bin/unshare','--mount','--propagation','private','/usr/bin/python3','-B',
        str(Path(__file__).resolve()),'_host','--output',str(args.output),'--desktop-output',str(args.desktop_output),
        '--native-qualified',str(args.native_qualified),'--qualified',str(args.qualified)],check=True,timeout=930)


if __name__=='__main__':main()
