#!/usr/bin/env python3
"""Qualify a private Konsole PTY-ready endpoint on an existing KDE session.

This is endpoint development, not a cold-cache or B0/B1/B2 performance result.
New private settings/cache/data directories isolate user terminal preferences.
Only the separately launched test window and its child are stopped.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import select
import shutil
import socket
import stat
import struct
import subprocess
import sys
import termios
import time
import tty
import uuid


def require(value,message):
    if not value:raise RuntimeError(message)


def save(path,value):
    with path.open('x') as stream:json.dump(value,stream,indent=2);stream.write('\n')


def digest(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def receive_marker(channel):
    data=b''
    while not data.endswith(b'\n'):
        chunk=channel.recv(4096)
        require(chunk,'Marker connection closed before newline')
        data+=chunk;require(len(data)<=4096,'Invalid marker frame size')
    return json.loads(data)


def snapshot():
    memory={line.split(':')[0]:int(line.split()[1])*1024 for line in Path('/proc/meminfo').read_text().splitlines()
        if line.startswith(('MemAvailable:','Dirty:','Writeback:'))}
    policies={}
    for p in sorted(Path('/sys/devices/system/cpu/cpufreq').glob('policy*')):
        policies[p.name]={name:(p/name).read_text().strip() for name in
            ('scaling_governor','scaling_min_freq','scaling_max_freq') if (p/name).exists()}
    return dict(monotonic_ns=time.monotonic_ns(),cpu=list(map(int,Path('/proc/stat').read_text().splitlines()[0].split()[1:])),
        memory=memory,cpu_policies=policies,
        pressure={name:Path('/proc/pressure',name).read_text() for name in ('cpu','io','memory')})


def desktop_environment():
    text=subprocess.check_output(['systemctl','--user','show-environment'],text=True,timeout=10)
    selected={key:value for line in text.splitlines() for key,_,value in [line.partition('=')]
        if key in ('DISPLAY','WAYLAND_DISPLAY','XDG_RUNTIME_DIR','DBUS_SESSION_BUS_ADDRESS','XDG_SESSION_TYPE','XDG_CURRENT_DESKTOP')}
    require(selected.get('XDG_SESSION_TYPE')=='wayland' and selected.get('XDG_CURRENT_DESKTOP')=='KDE',
        'Requires the observed KDE Wayland session')
    require(selected.get('XDG_RUNTIME_DIR')==f'/run/user/{os.getuid()}','Unexpected desktop owner')
    return dict(os.environ,**selected)


def owns_descendant(pid,parent):
    seen=set()
    for _ in range(64):
        if pid==parent:return True
        if pid<=1 or pid in seen:return False
        seen.add(pid)
        try:
            text=Path('/proc',str(pid),'status').read_text()
            require(int(re.search(r'^Uid:\s+(\d+)',text,re.M).group(1))==os.getuid(),'Unexpected child owner')
            pid=int(re.search(r'^PPid:\s+(\d+)',text,re.M).group(1))
        except (OSError,AttributeError):return False
    return False


def child(args):
    require(os.isatty(0) and os.isatty(1),'Helper did not receive a terminal')
    original=termios.tcgetattr(0);response=b''
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as channel:
        channel.settimeout(15);channel.connect(str(args.socket))
        try:
            tty.setcbreak(0);os.write(1,b'\x1b[2J\x1b[HBC-250 terminal endpoint control\r\n\x1b[6n')
            started=time.monotonic_ns();deadline=time.monotonic()+8
            while time.monotonic()<deadline:
                if select.select([0],[],[],.1)[0]:
                    response+=os.read(0,128)
                    require(len(response)<=256,'Unexpected terminal response size')
                    if re.search(rb'\x1b\[[1-9][0-9]*;[1-9][0-9]*R',response):break
            else:raise RuntimeError('Terminal did not answer cursor-position query')
            rows,columns,_,_=struct.unpack('HHHH',__import__('fcntl').ioctl(0,termios.TIOCGWINSZ,b'\0'*8))
            ready=time.monotonic_ns();require(rows>0 and columns>0,'Zero-size terminal')
            os.write(1,b'\r\nPTY ready: cursor response received.\r\n')
            marker=dict(nonce=args.nonce,ready_monotonic_ns=ready,cursor_query_elapsed_ns=ready-started,
                cursor_reply_valid=True,terminal_rows=rows,terminal_columns=columns,tty_present=True)
            channel.sendall(json.dumps(marker).encode()+b'\n')
            require(channel.recv(16)==b'finish\n','Endpoint controller did not finish normally')
        finally:termios.tcsetattr(0,termios.TCSANOW,original)


def trial(area,index,env,timeout,hold):
    folder=area/f'trial-{index:02}';folder.mkdir(mode=0o700)
    for name in ('config','data','cache'):(folder/name).mkdir(mode=0o700)
    variables=dict(env,XDG_CONFIG_HOME=str(folder/'config'),XDG_DATA_HOME=str(folder/'data'),XDG_CACHE_HOME=str(folder/'cache'))
    sock=folder/'ready.sock';require(len(str(sock).encode())<104,'Private socket path too long')
    nonce=uuid.uuid4().hex;proc=None;channel=None;record={};error=None
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as server,(folder/'launcher-private.log').open('xb') as log:
        server.bind(str(sock));server.listen(1);server.settimeout(timeout)
        command=['konsole','--separate','--nofork','--workdir',str(folder),'-e',sys.executable,
            str(Path(__file__).resolve()),'_child','--socket',str(sock),'--nonce',nonce]
        before=snapshot();started=time.monotonic_ns()
        try:
            proc=subprocess.Popen(command,env=variables,stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,
                start_new_session=True)
            channel,_=server.accept();channel.settimeout(timeout)
            peer_pid,peer_uid,_=struct.unpack('3i',channel.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
            require(peer_uid==os.getuid() and owns_descendant(peer_pid,proc.pid),'Marker is not from the owned terminal child')
            marker=receive_marker(channel);received=time.monotonic_ns()
            require(marker['nonce']==nonce and marker['cursor_reply_valid'] and marker['tty_present'],'Invalid ready marker')
            require(started<marker['ready_monotonic_ns']<=received,'Ready clock order invalid')
            after=snapshot();require(proc.poll() is None,'Terminal exited before readiness validation')
            mapped=[]
            for line in Path('/proc',str(proc.pid),'maps').read_text().splitlines():
                fields=line.split(maxsplit=5)
                if len(fields)==6 and fields[5].startswith('/usr/') and not fields[5].endswith(' (deleted)'):
                    mapped.append(fields[5])
            save(folder/'mapped-files-private.json',sorted(set(mapped)))
            record=dict(trial=index,passed=True,launch_to_pty_ready_ns=marker['ready_monotonic_ns']-started,
                launch_to_marker_received_ns=received-started,cursor_query_elapsed_ns=marker['cursor_query_elapsed_ns'],
                terminal_rows=marker['terminal_rows'],terminal_columns=marker['terminal_columns'],
                cursor_reply_valid=True,owned_child_verified=True,terminal_alive_at_marker=True,
                cpu_policy_unchanged=before['cpu_policies']==after['cpu_policies'],before=before,after=after)
            save(folder/'process-private.json',dict(terminal_pid=proc.pid,helper_pid=peer_pid))
            if hold:time.sleep(hold)
            channel.sendall(b'finish\n');channel.close();channel=None
            code=proc.wait(timeout=timeout);require(code==0,'Terminal did not close cleanly after child exit')
            record.update(normal_close_verified=True,terminal_exit_code=code)
        except BaseException as exc:
            error=exc;record.update(trial=index,passed=False,error=str(exc))
        finally:
            if channel is not None:
                try:channel.sendall(b'finish\n')
                except OSError:pass
                channel.close()
            if proc is not None and proc.poll() is None:
                proc.terminate()
                try:proc.wait(timeout=20)
                except subprocess.TimeoutExpired:record['owned_terminal_cleanup_failed']=True
            record['owned_terminal_gone']=proc is not None and proc.poll() is not None
            save(folder/'result-private.json',record)
            # Remove only this owned transient socket; keep every data/log file.
            info=sock.lstat()
            if stat.S_ISSOCK(info.st_mode) and info.st_uid==os.getuid():sock.unlink()
    if error:raise error
    return record


def run(args):
    require(sys.platform=='linux' and os.geteuid()!=0,'Run as the desktop user, not root')
    require(shutil.which('konsole') is not None,'Konsole unavailable')
    area=args.output.absolute();require(area.parent.resolve(strict=True)==area.parent,'Output parent must be canonical')
    info=area.parent.stat();require(info.st_uid==os.getuid() and not info.st_mode&0o022,'Unsafe output parent')
    area.mkdir(mode=0o700);env=desktop_environment()
    manifest=dict(schema_version=1,workload='konsole-private-pty-ready-v1',source_sha256=digest(Path(__file__)),
        binaries_sha256={name:digest(Path(shutil.which(name)).resolve()) for name in ('konsole','python3')},
        package=subprocess.check_output(['pacman','-Q','konsole'],text=True,timeout=10).strip(),
        kernel=os.uname().release,trials=args.trials,timeout_seconds=20,
        endpoint='Owned child receives a valid cursor-position reply through the Konsole PTY',
        endpoint_does_not_prove_first_composited_frame=True,
        cache_state='Fresh private settings/data/cache per launch; system page cache uncontrolled',
        cache_eviction_performed=False,drive_policy_changed=False,global_trace_changed=False,
        benchmark_comparison_performed=False,application_suite_frozen=False,stage1_gate_passed=False)
    save(area/'contract.json',manifest);rows=[]
    try:
        for index in range(args.trials):
            row=trial(area,index,env,20,args.hold_seconds);rows.append(row)
            print(json.dumps({k:row[k] for k in ('trial','passed','launch_to_pty_ready_ns','normal_close_verified')}),flush=True)
    finally:save(area/'completed-trials-private.json',rows)
    require(all(r['cpu_policy_unchanged'] and r['owned_terminal_gone'] for r in rows),'Environment/cleanup failed')
    require(digest(Path(__file__))==manifest['source_sha256'],'Endpoint source changed')
    result=dict(manifest,passed=True,completed_trials=len(rows),
        trials=[{k:v for k,v in row.items() if k not in ('before','after')} for row in rows],
        all_owned_terminal_processes_gone=True,completed_unix=time.time())
    save(area/'result.json',result)


def main():
    parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest='step',required=True)
    parent=sub.add_parser('run');parent.add_argument('--output',type=Path,required=True)
    parent.add_argument('--trials',type=int,choices=range(1,7),default=3)
    parent.add_argument('--hold-seconds',type=float,choices=(0.,1.,3.,5.),default=0.)
    helper=sub.add_parser('_child');helper.add_argument('--socket',type=Path,required=True);helper.add_argument('--nonce',required=True)
    args=parser.parse_args()
    if args.step=='_child':child(args)
    else:run(args)


if __name__=='__main__':main()
