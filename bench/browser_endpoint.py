#!/usr/bin/env python3
"""Private Firefox visible-document endpoint, isolated loopback networking.

Functional qualification only: fresh private HOME/profile; uncontrolled system
cache; no first-composited-frame, trusted-input or acceleration claim.
"""
import argparse
import ctypes
import hashlib
from http.server import BaseHTTPRequestHandler,HTTPServer
import json
import math
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import uuid

import terminal_endpoint as terminal

ROOT=Path(__file__).resolve().parent
PREFS={
    'browser.aboutwelcome.enabled':False,
    'browser.shell.checkDefaultBrowser':False,
    'browser.startup.homepage_override.mstone':'ignore',
    'startup.homepage_welcome_url':'',
    'startup.homepage_welcome_url.additional':''}
MARKER_KEYS={'nonce','document_complete','visibility','image_decoded','fonts_loaded','scripted_clicks',
    'status_text','frames_waited','distinct_frame_timestamps','inner_width','inner_height','page_elapsed_ms'}


def validate_marker(value,nonce):
    terminal.require(type(value) is dict and set(value)==MARKER_KEYS,'Unexpected marker fields')
    terminal.require(value['nonce']==nonce,'Wrong marker nonce')
    for key in ('document_complete','image_decoded','fonts_loaded','distinct_frame_timestamps'):
        terminal.require(value[key] is True,'Unready document: '+key)
    terminal.require(value['visibility']=='visible' and value['status_text']=='Ready 1','Document hidden or unresponsive')
    for key,expected in [('scripted_clicks',1),('frames_waited',2)]:
        terminal.require(type(value[key]) is int and value[key]==expected,'Invalid scripted readiness count')
    for key in ('inner_width','inner_height'):
        terminal.require(type(value[key]) is int and 100<value[key]<=16384,'Invalid viewport')
    elapsed=value['page_elapsed_ms']
    terminal.require(type(elapsed) in (int,float) and math.isfinite(elapsed) and 0<=elapsed<=120000,'Invalid browser clock')
    return value


def group_path():
    rows=Path('/proc/self/cgroup').read_text().splitlines()
    relative=next(line.split('::',1)[1] for line in rows if line.startswith('0::'))
    terminal.require('/bc250-browser-endpoint-' in relative,'Requires its own transient test cgroup')
    path=Path('/sys/fs/cgroup')/relative.lstrip('/')
    terminal.require(path.is_dir(),'Test cgroup unavailable')
    return path


def members(group):
    return {int(n) for n in (group/'cgroup.procs').read_text().split()}


def signal_owned(pid,group,signum):
    """Pin identity before checking cgroup membership and signalling."""
    try:fd=os.pidfd_open(pid)
    except ProcessLookupError:return
    try:
        terminal.require(pid!=os.getpid(),'Refuse to signal the endpoint controller')
        # A member may exit between enumeration and pidfd acquisition. If it is
        # no longer in the owned group, never signal it (including PID reuse).
        if pid not in members(group):return
        signal.pidfd_send_signal(fd,signum)
    except ProcessLookupError:pass
    finally:os.close(fd)


def cleanup(proc,group):
    owned=members(group)-{os.getpid()}
    for pid in owned:signal_owned(pid,group,signal.SIGTERM)
    deadline=time.monotonic()+10
    while members(group)-{os.getpid()} and time.monotonic()<deadline:time.sleep(.05)
    forced=members(group)-{os.getpid()}
    for pid in forced:signal_owned(pid,group,signal.SIGKILL)
    if proc is not None:proc.wait(timeout=5)
    deadline=time.monotonic()+3
    while members(group)-{os.getpid()} and time.monotonic()<deadline:time.sleep(.05)
    terminal.require(members(group)=={os.getpid()},'Owned browser processes remain')
    return dict(owned_browser_processes_gone=True,forced_cleanup_required=bool(forced),
        termination='SIGTERM to owned disposable test cgroup members after measurement')


class Handler(BaseHTTPRequestHandler):
    def setup(self):super().setup();self.connection.settimeout(2)
    def log_message(self,*args):pass
    def reply(self,status,body=b'',kind='text/plain'):
        self.send_response(status);self.send_header('Content-Type',kind);self.send_header('Content-Length',str(len(body)))
        self.send_header('Cache-Control','no-store')
        self.send_header('Content-Security-Policy',"default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src 'self'; connect-src 'self'; frame-ancestors 'none'")
        self.end_headers();self.wfile.write(body)
    def do_GET(self):
        prefix='/'+self.server.nonce+'/'
        if self.path==prefix+'page':self.reply(200,self.server.html,'text/html; charset=utf-8')
        elif self.path==prefix+'image.svg':self.reply(200,self.server.svg,'image/svg+xml')
        else:self.reply(404)
    def do_POST(self):
        try:
            length=int(self.headers.get('Content-Length','0'))
            terminal.require(0<length<=4096,'Bad marker length');data=self.rfile.read(length)
            if self.path=='/'+self.server.nonce+'/error':
                self.server.page_error=data.decode(errors='replace')[:80];self.reply(400);return
            terminal.require(self.path=='/'+self.server.nonce+'/ready','Unexpected marker path')
            terminal.require(self.headers.get('Content-Type')=='application/json','Wrong marker content type')
            marker=validate_marker(json.loads(data),self.server.nonce)
            terminal.require(self.server.marker is None,'Repeated ready marker')
            self.server.marker=marker;self.server.ready_received_ns=time.monotonic_ns();self.reply(200,b'ok')
        except (ValueError,RuntimeError) as exc:
            self.server.invalid_markers+=1;self.reply(400,str(exc).encode())


def namespace_state():
    links=json.loads(subprocess.check_output(['ip','-j','link','show'],text=True))
    routes=[]
    for family in ('-4','-6'):
        routes+=json.loads(subprocess.check_output(['ip',family,'-j','route','show','table','all'],text=True))
    names=sorted(row['ifname'] for row in links)
    terminal.require(names==['lo'] and not any(r.get('dst')=='default' for r in routes),'Namespace has external networking')
    return dict(interfaces=names,default_route_present=False)


def trial(area,index,env,group,hold):
    folder=area/f'trial-{index:02}';folder.mkdir(mode=0o700);home=folder/'home';home.mkdir(mode=0o700)
    for name in ('profile','config','data','cache'):(home/name).mkdir(mode=0o700)
    with (home/'profile/user.js').open('x') as stream:
        stream.write(''.join('user_pref('+json.dumps(k)+','+json.dumps(v)+');\n' for k,v in PREFS.items()))
    variables=dict(env,HOME=str(home),XDG_CONFIG_HOME=str(home/'config'),XDG_DATA_HOME=str(home/'data'),XDG_CACHE_HOME=str(home/'cache'))
    terminal.require('MOZ_DISABLE_CONTENT_SANDBOX' not in variables,'Caller disables the browser sandbox')
    terminal.require(members(group)=={os.getpid()},'Unexpected preexisting test cgroup process')
    proc=None;record={};error=None
    with HTTPServer(('127.0.0.1',0),Handler) as server,(folder/'browser-private.log').open('xb') as log:
        server.timeout=.1;server.nonce=uuid.uuid4().hex;server.html=(ROOT/'browser-ready.html').read_bytes()
        server.svg=(ROOT/'browser-ready.svg').read_bytes();server.marker=None;server.page_error=None;server.invalid_markers=0
        url=f'http://127.0.0.1:{server.server_port}/{server.nonce}/page'
        before=terminal.snapshot();started=time.monotonic_ns()
        try:
            proc=subprocess.Popen(['firefox','--no-remote','--new-instance','--profile',str(home/'profile'),url],
                env=variables,stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
            deadline=time.monotonic()+45
            while server.marker is None and time.monotonic()<deadline:
                terminal.require(proc.poll() is None,'Browser exited before document marker')
                server.handle_request();terminal.require(server.page_error is None,'Page script failed: '+str(server.page_error))
            terminal.require(server.marker is not None,'Visible-document readiness deadline')
            after=terminal.snapshot();caps=[line.split()[1] for line in Path('/proc',str(proc.pid),'status').read_text().splitlines()
                if line.startswith(('CapEff:','CapPrm:','CapAmb:'))]
            terminal.require(len(caps)==3 and all(int(n,16)==0 for n in caps),'Browser parent retains capabilities')
            terminal.require(proc.pid in members(group),'Browser parent left the owned test group')
            marker={k:v for k,v in server.marker.items() if k!='nonce'}
            record=dict(trial=index,passed=True,launch_to_marker_received_ns=server.ready_received_ns-started,
                marker=marker,invalid_markers=server.invalid_markers,browser_parent_capabilities_zero=True,
                browser_parent_in_owned_test_group=True,
                cpu_policy_unchanged=before['cpu_policies']==after['cpu_policies'],before=before,after=after)
            if hold:time.sleep(hold)
        except BaseException as exc:error=exc;record.update(trial=index,passed=False,error=str(exc))
        finally:
            record.update(cleanup(proc,group));record['browser_exit_code']=proc.returncode if proc else None
            terminal.save(folder/'result-private.json',record)
    if error:raise error
    return record


def host(args):
    terminal.require(os.geteuid()!=0,'Run as the desktop user')
    terminal.require(os.readlink('/proc/self/ns/net')!=args.parent_net,'Network namespace was not isolated')
    namespace_state();subprocess.run(['ip','link','set','dev','lo','up'],check=True);net=namespace_state()
    libc=ctypes.CDLL(None,use_errno=True)
    terminal.require(libc.prctl(47,4,0,0,0)==0,'Cannot clear ambient capabilities before browser execution')
    group=group_path();env=terminal.desktop_environment();area=args.output.absolute()
    terminal.require(area.parent.resolve(strict=True)==area.parent,'Output parent must be canonical')
    info=area.parent.stat();terminal.require(info.st_uid==os.getuid() and not info.st_mode&0o022,'Unsafe output parent')
    area.mkdir(mode=0o700)
    files={name:terminal.digest(ROOT/name) for name in ('browser_endpoint.py','terminal_endpoint.py','browser-ready.html','browser-ready.svg')}
    contract=dict(schema_version=1,workload='firefox-private-visible-document-v1',source_sha256=files,
        package=subprocess.check_output(['pacman','-Q','firefox'],text=True,timeout=10).strip(),
        firefox_full_version=subprocess.check_output(['firefox','--full-version'],text=True,timeout=10).strip(),
        kernel=os.uname().release,trials=args.trials,network_namespace_isolated=True,network=net,
        private_home_and_profile=True,private_preferences=PREFS,remote_agent_enabled=False,
        endpoint='Controller receives valid visible-document/load/image/font/scripted-click/two-frame marker',
        endpoint_does_not_prove_first_composited_frame=True,trusted_input_qualified=False,
        cache_state='Fresh private HOME/profile/config/data/cache; local document preloaded into server RAM; system page cache uncontrolled',
        cache_eviction_performed=False,system_wide_settings_changed=False,benchmark_comparison_performed=False,
        application_suite_frozen=False,stage1_gate_passed=False)
    terminal.save(area/'contract.json',contract);rows=[]
    try:
        for index in range(args.trials):
            row=trial(area,index,env,group,args.hold_seconds);rows.append(row)
            print(json.dumps({k:row[k] for k in ('trial','passed','launch_to_marker_received_ns','owned_browser_processes_gone')}),flush=True)
    finally:terminal.save(area/'completed-trials-private.json',rows)
    terminal.require(all(r['cpu_policy_unchanged'] and not r['forced_cleanup_required'] for r in rows),'Policy or cleanup qualification failed')
    terminal.require(all(terminal.digest(ROOT/name)==value for name,value in files.items()),'Endpoint source changed')
    namespace_state()
    terminal.save(area/'result.json',dict(contract,passed=True,completed_trials=len(rows),
        trials=[{k:v for k,v in row.items() if k not in ('before','after')} for row in rows],
        all_owned_browser_processes_gone=True,completed_unix=time.time()))


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('step',choices=('run','_host'))
    parser.add_argument('--output',type=Path,required=True);parser.add_argument('--trials',type=int,choices=range(1,4),default=3)
    parser.add_argument('--hold-seconds',type=float,choices=(0.,3.),default=0.);parser.add_argument('--parent-net')
    args=parser.parse_args();terminal.require(sys.platform=='linux' and os.geteuid()!=0,'Requires the Linux desktop user')
    if args.step=='_host':host(args);return
    before=os.readlink('/proc/self/ns/net');unit='bc250-browser-endpoint-'+uuid.uuid4().hex[:12]
    env=terminal.desktop_environment()
    print(json.dumps(dict(parent_unit=unit)),flush=True)
    subprocess.run(['systemd-run','--user','--quiet','--wait','--pipe','--collect','--unit='+unit,
        '--property=MemoryMax=3G','--property=MemorySwapMax=0','--property=TasksMax=512',
        '--property=RuntimeMaxSec=180','--property=KillMode=control-group','--property=TimeoutStopSec=15',
        '/usr/bin/unshare','--user','--map-current-user','--net','--keep-caps','/usr/bin/python3',
        str(Path(__file__).resolve()),'_host','--output',str(args.output),'--trials',str(args.trials),
        '--hold-seconds',str(args.hold_seconds),'--parent-net',before],env=env,check=True,timeout=210)
    terminal.require(os.readlink('/proc/self/ns/net')==before,'Parent network namespace changed')


if __name__=='__main__':main()
