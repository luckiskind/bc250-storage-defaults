#!/usr/bin/env python3
"""Temporary authenticated root observer for an unchanged private Firefox audit.

Only the fixed trial cgroup may request two mapping captures and finish. The
protocol accepts no caller-selected PIDs or paths. GUI processes stay nonroot.
"""
import argparse
import hmac
import json
import os
from pathlib import Path
import pwd
import re
import socket
import struct
import subprocess
import sys
import threading
import time
import uuid

import browser_inputs as audit
import browser_endpoint as browser
import mapped_identity as identity
import terminal_endpoint as terminal

ROOT=Path(__file__).resolve().parent


class Rejected(RuntimeError):pass


def authorize(message,uid,pid,phase,cfg,scoped,controller=None):
    if type(message) is not dict or set(message)!={'nonce','phase'}:raise Rejected('schema')
    if type(message['nonce']) is not str or not hmac.compare_digest(message['nonce'],cfg['nonce']):raise Rejected('nonce')
    if message['phase']!=phase:raise Rejected('phase')
    if uid!=cfg['uid']:raise Rejected('uid')
    if controller is not None and pid!=controller:raise Rejected('controller')
    if not scoped(pid):raise Rejected('scope')


def translated_root_uid():
    for line in Path('/proc/self/uid_map').read_text().splitlines():
        inside,outside,count=map(int,line.split())
        if outside==0:return inside
    return int(Path('/proc/sys/kernel/overflowuid').read_text())


def request(cfg,message):
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as channel:
        channel.settimeout(60);channel.connect(cfg['socket'])
        pid,uid,_=struct.unpack('3i',channel.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
        terminal.require(pid==cfg['observer_pid'] and uid==translated_root_uid(),'Unexpected root observer')
        channel.sendall(json.dumps(message).encode()+b'\n');reply=terminal.receive_marker(channel)
        terminal.require(type(reply) is dict and type(reply.get('ok')) is bool,'Malformed observer response')
        return reply


def rpc(cfg,phase):
    value=request(cfg,dict(nonce=cfg['nonce'],phase=phase))
    terminal.require(value['ok'],'Observer rejected capture: '+str(value.get('reason')))
    return value


def scope_group(pid,cfg):
    try:
        relative=next(line.split('::',1)[1] for line in Path('/proc',str(pid),'cgroup').read_text().splitlines() if line.startswith('0::'))
        if Path(relative).name!=cfg['unit']+'.service':return None
        group=Path('/sys/fs/cgroup')/relative.lstrip('/')
        if group.resolve(strict=True)!=group or pid not in browser.members(group):return None
        uid=int(next(line.split()[1] for line in Path('/proc',str(pid),'status').read_text().splitlines() if line.startswith('Uid:')))
        return group if uid==cfg['uid'] else None
    except (OSError,StopIteration,ValueError):return None


def collect(peer,cfg,area,index,lib):
    group=scope_group(peer,cfg);terminal.require(group is not None,'Controller left trial scope')
    members=browser.members(group)-{peer};terminal.require(0<len(members)<=64,'Observer process-sample bound')
    samples=[];unavailable=[];mains=[]
    for pid in sorted(members):
        try:
            terminal.require(scope_group(pid,cfg)==group,'Trial member identity changed')
            executable=os.readlink(f'/proc/{pid}/exe')
            if executable=='/usr/bin/strace':continue
            snapshot=identity.inspect(pid,lambda n:scope_group(n,cfg)==group,lib);samples.append(snapshot)
            snapshot['root_description']=os.readlink(f'/proc/{pid}/root')
            snapshot['root_is_proc_fdinfo']=re.fullmatch(r'/proc/[0-9]+/fdinfo(?: \(deleted\))?',snapshot['root_description']) is not None
            if executable=='/usr/lib/firefox/firefox':
                status=Path('/proc',str(pid),'status').read_text()
                parent=int(next(line.split()[1] for line in status.splitlines() if line.startswith('PPid:')))
                try:is_main=os.readlink(f'/proc/{parent}/exe')=='/usr/bin/strace'
                except OSError:is_main=False
                if is_main:
                    caps=[line.split()[1] for line in status.splitlines() if line.startswith(('CapEff:','CapPrm:','CapAmb:'))]
                    terminal.require(len(caps)==3 and all(int(value,16)==0 for value in caps),'Actual browser main retains capabilities')
                    terminal.require(any(row['status']=='same_host_object' and row['path']=='/usr/lib/firefox/firefox'
                        for row in snapshot['records']),'Browser main executable identity not verified')
                    mains.append(pid)
        except (FileNotFoundError,ProcessLookupError):unavailable.append(dict(pid=pid,reason='process_disappeared'))
        except PermissionError:unavailable.append(dict(pid=pid,reason='permission_denied'))
    terminal.require(len(mains)==1,'Missing or ambiguous verified Firefox main')
    terminal.require(scope_group(peer,cfg)==group,'Controller left trial scope')
    summary=identity.summarize(samples)
    summary.update(main_executable_identity_verified=True,main_capabilities_zero=True,unavailable_processes=len(unavailable))
    summary['proc_fdinfo_root_processes']=sum(s['root_is_proc_fdinfo'] for s in samples)
    path=area/f'capture-{index}-private.json'
    terminal.save(path,dict(samples=samples,unavailable=unavailable,summary=summary))
    return dict(summary=summary,private_capture_sha256=terminal.digest(path))


def serve(server,cfg,area,lib,state,done):
    phases=('capture-0','capture-1','finish');next_phase=0;controller=None
    try:
        while not done.is_set() and next_phase<len(phases):
            try:channel,_=server.accept()
            except socket.timeout:continue
            with channel:
                channel.settimeout(10)
                pid,uid,_=struct.unpack('3i',channel.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
                try:
                    message=terminal.receive_marker(channel)
                    authorize(message,uid,pid,phases[next_phase],cfg,lambda n:scope_group(n,cfg) is not None,controller)
                except (Rejected,ValueError,RuntimeError) as exc:
                    reason=str(exc) if isinstance(exc,Rejected) else 'framing'
                    state['rejections'].append(reason);channel.sendall(json.dumps(dict(ok=False,reason=reason)).encode()+b'\n')
                    terminal.require(len(state['rejections'])<=16,'Rejection bound');continue
                controller=pid
                if next_phase<2:
                    value=collect(pid,cfg,area,next_phase,lib);state['captures'].append(value)
                else:
                    group=scope_group(pid,cfg);terminal.require(group is not None and browser.members(group)=={pid},'Browser group not cleaned')
                    value=dict(browser_group_empty_except_controller=True)
                channel.sendall(json.dumps(dict(ok=True,**value)).encode()+b'\n');next_phase+=1
        state['finished']=next_phase==3
    except BaseException as exc:state['errors'].append(str(exc))
    finally:done.set()


def user_host(args):
    cfg=json.loads(args.config.read_text());original=audit.capture_owned;captures=[];rejected=[]
    def checked_capture(group,supervisor):
        value=original(group,supervisor);index=len(captures)
        if index==0:
            for message,reason in [(dict(nonce='wrong',phase='capture-0'),'nonce'),
                (dict(nonce=cfg['nonce'],phase='capture-0',pid=1),'schema')]:
                reply=request(cfg,message);terminal.require(reply==dict(ok=False,reason=reason),'Negative request accepted')
                rejected.append(reason)
        reply=rpc(cfg,'capture-'+str(index));captures.append(reply)
        if index==0:
            replay=request(cfg,dict(nonce=cfg['nonce'],phase='capture-0'))
            terminal.require(replay==dict(ok=False,reason='phase'),'Capture replay accepted');rejected.append('phase')
        value['root_identity_summary']=reply['summary'];return value
    audit.capture_owned=checked_capture
    try:audit.host(argparse.Namespace(output=Path(cfg['desktop'])/'audit',parent_net=args.parent_net))
    finally:audit.capture_owned=original
    terminal.require(len(captures)==2,'Missing root identity captures')
    finish=rpc(cfg,'finish');terminal.require(finish['browser_group_empty_except_controller'],'Browser cleanup not verified')
    terminal.save(Path(cfg['desktop'])/'observer-client-result.json',dict(passed=True,captures=captures,rejected=rejected,
        browser_group_empty_except_controller=True,root_peer_verified_with_uid_translation=True))


def user_run(args):
    cfg=json.loads(args.config.read_text());before=os.readlink('/proc/self/ns/net');env=terminal.desktop_environment()
    subprocess.run(['systemd-run','--user','--quiet','--wait','--pipe','--collect','--unit='+cfg['unit'],
        '--property=MemoryMax=3G','--property=MemorySwapMax=0','--property=TasksMax=512',
        '--property=RuntimeMaxSec=180','--property=KillMode=control-group','--property=TimeoutStopSec=15',
        '/usr/bin/unshare','--user','--map-current-user','--net','--keep-caps','/usr/bin/python3','-B',str(Path(__file__).resolve()),
        '_user-host','--config',str(args.config),'--parent-net',before],env=env,check=True,timeout=210)
    terminal.require(os.readlink('/proc/self/ns/net')==before,'Parent network namespace changed')


def orchestrate(args):
    terminal.require(args.uid>0,'GUI user cannot be root');account=pwd.getpwuid(args.uid)
    area=args.output.absolute();desktop=args.desktop_output.absolute()
    for path in (area,desktop):
        terminal.require(path.parent.resolve(strict=True)==path.parent,'Noncanonical output parent')
        info=path.parent.stat();terminal.require(info.st_uid in (0,args.uid) and not info.st_mode&0o022,'Unsafe output parent')
    area.mkdir(mode=0o700);desktop.mkdir(mode=0o700);os.chown(desktop,args.uid,account.pw_gid)
    terminal.require(os.readlink('/proc/self/ns/user')==os.readlink('/proc/1/ns/user'),'Observer must use initial user namespace')
    names=('browser_identity.py','browser_inputs.py','mapped_identity.py','mapped_identity.c','application_inputs.py',
        'browser_endpoint.py','terminal_endpoint.py','browser-ready.html','browser-ready.svg')
    sources={name:terminal.digest(ROOT/name) for name in names};lib=identity.compile_library(area/'rooted.so')
    cfg=dict(uid=args.uid,nonce=uuid.uuid4().hex,observer_pid=os.getpid(),desktop=str(desktop),socket=str(desktop/'observer.sock'),
        unit='bc250-browser-endpoint-audit-'+uuid.uuid4().hex[:12])
    terminal.require(len(cfg['socket'].encode())<104,'Observer socket path too long')
    config=desktop/'observer-config-private.json';terminal.save(config,cfg);config.chmod(0o600);os.chown(config,args.uid,account.pw_gid)
    state=dict(rejections=[],captures=[],errors=[],finished=False);done=threading.Event();process=None
    user_command=['runuser','-u',account.pw_name,'--','env',f'XDG_RUNTIME_DIR=/run/user/{args.uid}',
        f'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{args.uid}/bus','PYTHONDONTWRITEBYTECODE=1','/usr/bin/python3','-B',
        str(Path(__file__).resolve())]
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as server:
        server.bind(cfg['socket']);os.chown(cfg['socket'],args.uid,account.pw_gid);os.chmod(cfg['socket'],0o600)
        server.listen(2);server.settimeout(.5)
        thread=threading.Thread(target=serve,args=(server,cfg,area,lib,state,done),daemon=True);thread.start()
        try:
            wrong_uid=request(cfg,dict(nonce=cfg['nonce'],phase='capture-0'))
            terminal.require(wrong_uid==dict(ok=False,reason='uid'),'Root outsider accepted')
            subprocess.run([*user_command,'_outside-probe','--config',str(config)],check=True,timeout=10)
            process=subprocess.Popen([*user_command,'_user-run','--config',str(config)],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
            output,_=process.communicate(timeout=215);print(output,flush=True)
            terminal.require(process.returncode==0,'User audit failed');thread.join(timeout=2)
            terminal.require(not thread.is_alive() and state['finished'] and not state['errors'],'Root observer did not finish: '+str(state['errors']))
        finally:
            done.set();thread.join(timeout=2)
            if process is not None and process.poll() is None:process.terminate();process.wait(timeout=10)
            terminal.save(area/'observer-state-private.json',state);Path(cfg['socket']).unlink()
    terminal.require(state['rejections']==['uid','scope','nonce','schema','phase'],'Missing or unexpected protocol checks')
    audit_result=json.loads((desktop/'audit/result.json').read_text());client=json.loads((desktop/'observer-client-result.json').read_text())
    terminal.require(audit_result['passed'] and client['passed'],'Browser identity audit failed')
    terminal.require(all(terminal.digest(ROOT/name)==digest for name,digest in sources.items()),'Observer/audit source changed')
    result=dict(schema_version=1,passed=True,source_sha256=sources,kernel=os.uname().release,
        capture_summaries=[row['summary'] for row in state['captures']],rejected_requests=state['rejections'],
        functional_launches=audit_result['functional_endpoint_trials'],private_seed_identical=audit_result['private_seed_identical'],
        all_owned_browser_processes_gone=audit_result['all_owned_browser_processes_gone'],
        browser_group_empty_except_controller=True,root_observer_temporary=True,browser_main_capabilities_zero=True,
        unchanged_audit_source=True,namespace_aware_file_identity_qualified=False,complete_application_input_closure=False,
        cache_state_qualified=False,performance_result=False,stage1_gate_passed=False,completed_unix=time.time())
    terminal.save(area/'result.json',result);print(json.dumps(result),flush=True)


def main():
    parser=argparse.ArgumentParser(description=__doc__);steps=parser.add_subparsers(dest='step',required=True)
    for name in ('run','_orchestrate'):
        step=steps.add_parser(name);step.add_argument('--output',type=Path,required=True)
        step.add_argument('--desktop-output',type=Path,required=True);step.add_argument('--uid',type=int,default=1000)
    for name in ('_user-run','_user-host','_outside-probe'):
        step=steps.add_parser(name);step.add_argument('--config',type=Path,required=True)
        if name=='_user-host':step.add_argument('--parent-net',required=True)
    args=parser.parse_args();terminal.require(sys.platform=='linux','Linux required')
    if args.step.startswith('_user') or args.step=='_outside-probe':
        terminal.require(os.geteuid()!=0,'GUI/client must be unprivileged')
        if args.step=='_outside-probe':
            cfg=json.loads(args.config.read_text());terminal.require(request(cfg,dict(nonce=cfg['nonce'],phase='capture-0'))==dict(ok=False,reason='scope'),'Outsider accepted');return
        if args.step=='_user-run':user_run(args)
        else:user_host(args)
        return
    terminal.require(os.geteuid()==0,'Initial-namespace root setup required')
    if args.step=='_orchestrate':orchestrate(args);return
    unit='bc250-browser-identity-'+uuid.uuid4().hex[:12]
    subprocess.run(['systemd-run','--quiet','--wait','--pipe','--collect','--unit='+unit,
        '--property=MemoryMax=512M','--property=MemorySwapMax=0','--property=CPUQuota=100%',
        '--property=TasksMax=64','--property=RuntimeMaxSec=240','--property=KillMode=control-group',
        '/usr/bin/python3','-B',str(Path(__file__).resolve()),'_orchestrate','--output',str(args.output),
        '--desktop-output',str(args.desktop_output),'--uid',str(args.uid)],check=True,timeout=270)


if __name__=='__main__':main()
