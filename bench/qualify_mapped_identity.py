#!/usr/bin/env python3
"""Qualify same-path mapping identity with two private bind-mount controls."""
import argparse
import json
import mmap
import os
import pwd
from pathlib import Path
import socket
import struct
import subprocess
import sys
import time
import uuid

import mapped_identity as identity
import terminal_endpoint as terminal


def owned_worker(pid,parent,uid):
    seen=set()
    for _ in range(64):
        if pid==parent:return True
        if pid<=1 or pid in seen:return False
        seen.add(pid)
        try:
            text=Path('/proc',str(pid),'status').read_text()
            values={line.split(':')[0]:line.split()[1] for line in text.splitlines() if line.startswith(('Uid:','PPid:'))}
            if int(values['Uid']) not in (0,uid):return False
            pid=int(values['PPid'])
        except (OSError,KeyError):return False
    return False


def worker(args):
    with args.input.open('rb') as stream,mmap.mmap(stream.fileno(),0,access=mmap.ACCESS_READ),\
            socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as channel:
        channel.settimeout(15);channel.connect(str(args.socket))
        channel.sendall(json.dumps(dict(nonce=args.nonce)).encode()+b'\n')
        terminal.require(channel.recv(16)==b'finish\n','Mapping control did not finish normally')


def host(args):
    area=args.output.absolute();terminal.require(area.parent.resolve(strict=True)==area.parent,'Noncanonical output parent')
    info=area.parent.stat();terminal.require(info.st_uid in (0,args.uid) and not info.st_mode&0o022,'Unsafe output parent')
    terminal.require(args.uid>0,'Control worker must be unprivileged');account=pwd.getpwuid(args.uid)
    area.mkdir(mode=0o700);os.chown(area,args.uid,account.pw_gid)
    sources={name:terminal.digest(Path(__file__).parent/name) for name in
        ('qualify_mapped_identity.py','mapped_identity.py','mapped_identity.c','terminal_endpoint.py')}
    lib=identity.compile_library(area/'rooted.so');original=area/'canonical';replacement=area/'replacement'
    original.write_bytes(b'a'*4096);replacement.write_bytes(b'b'*4096)
    terminal.require(identity.identity(original.stat())!=identity.identity(replacement.stat()),'Control files alias')
    left=area/'subvolume-left';right=area/'subvolume-right'
    for root,value in ((left,b'l'),(right,b'r')):
        subprocess.run(['btrfs','subvolume','create',str(root)],check=True,capture_output=True,timeout=10)
        (root/'mapped').write_bytes(value*4096)
    terminal.require((left/'mapped').stat().st_ino==(right/'mapped').stat().st_ino and
        (left/'mapped').stat().st_dev!=(right/'mapped').stat().st_dev,'No Btrfs cross-subvolume inode collision')
    before=os.readlink('/proc/self/ns/mnt');results=[]
    for index,(target,source,replace) in enumerate(((original,replacement,False),(original,replacement,True),
            (left/'mapped',right/'mapped',False),(left/'mapped',right/'mapped',True))):
        sock=area/f'control-{index}.sock';nonce=uuid.uuid4().hex
        terminal.require(len(str(sock).encode())<104,'Control socket path too long')
        proc=None;channel=None
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as server,(area/f'worker-{index}-private.log').open('xb') as log:
            server.bind(str(sock));os.chown(sock,args.uid,account.pw_gid);sock.chmod(0o600);server.listen(1);server.settimeout(15)
            command=['runuser','-u',account.pw_name,'--','bwrap','--die-with-parent','--new-session','--unshare-user','--uid',str(args.uid),
                '--gid',str(account.pw_gid),'--unshare-net','--ro-bind','/','/']
            if replace:command+=['--ro-bind',str(source),str(target)]
            command+=['--','/usr/bin/python3',str(Path(__file__).resolve()),'_worker','--input',str(target),
                '--socket',str(sock),'--nonce',nonce]
            try:
                proc=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT)
                channel,_=server.accept();channel.settimeout(15)
                pid,uid,_=struct.unpack('3i',channel.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
                terminal.require(uid==args.uid and owned_worker(pid,proc.pid,args.uid),'Unowned mapping worker')
                terminal.require(terminal.receive_marker(channel)==dict(nonce=nonce),'Invalid mapping control marker')
                sample=identity.inspect(pid,lambda n:n==pid and owned_worker(n,proc.pid,args.uid),lib)
                terminal.save(area/f'identity-{index}-private.json',sample)
                rows=[row for row in sample['records'] if row['path']==str(target)]
                terminal.require(len(rows)==1,'Control mapping missing or ambiguous')
                row=rows[0];expected='different_host_object' if replace else 'same_host_object'
                terminal.require(row['status']==expected and row['view_identity_matches_mapping'],'Control identity decision failed')
                wanted=source if replace else target
                terminal.require((row['reference_device'],row['reference_inode'])==identity.identity(wanted.stat()),'Wrong control inode identified')
                terminal.require(sample['mount_namespace']!=before,'Control mount namespace not private')
                channel.sendall(b'finish\n');channel.close();channel=None
                terminal.require(proc.wait(timeout=10)==0,'Mapping worker did not exit normally')
                results.append(dict(private_mount_namespace=True,view_matches_expected_inode=True,
                    host_path_alias_accepted=not replace,status=expected,worker_normal_exit=True,
                    raw_maps_device=row['device'],raw_maps_inode=row['inode']))
            finally:
                if channel is not None:
                    try:channel.sendall(b'finish\n')
                    except OSError:pass
                    channel.close()
                if proc is not None and proc.poll() is None:
                    proc.terminate()
                    try:proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:proc.kill();proc.wait(timeout=5)
                sock.unlink()
    terminal.require(original.read_bytes()==b'a'*4096 and replacement.read_bytes()==b'b'*4096,'Private control content changed')
    terminal.require((left/'mapped').read_bytes()==b'l'*4096 and (right/'mapped').read_bytes()==b'r'*4096,'Subvolume control changed')
    raw_collision=all(results[2][key]==results[3][key] for key in ('raw_maps_device','raw_maps_inode'))
    terminal.require(raw_collision,'Raw map fields did not collide across subvolumes')
    for row in results:
        del row['raw_maps_device'];del row['raw_maps_inode']
    terminal.require(os.readlink('/proc/self/ns/mnt')==before,'Parent mount namespace changed')
    terminal.require(all(terminal.digest(Path(__file__).parent/name)==digest for name,digest in sources.items()),'Control source changed')
    result=dict(schema_version=1,passed=True,source_sha256=sources,kernel=os.uname().release,cases=results,
        same_path_different_inode_rejected=True,parent_mount_namespace_unchanged=True,private_control_content_unchanged=True,
        bytes_per_file=4096,production_files_changed=False,cache_eviction_performed=False,performance_result=False,
        raw_maps_identity_collision_across_btrfs_subvolumes=True,initial_namespace_root_observer=True,worker_uid_unprivileged=True,
        complete_application_input_closure=False,stage1_gate_passed=False,completed_unix=time.time())
    terminal.save(area/'result.json',result);print(json.dumps(result),flush=True)


def main():
    parser=argparse.ArgumentParser(description=__doc__);steps=parser.add_subparsers(dest='step',required=True)
    for name in ('run','_host'):
        step=steps.add_parser(name);step.add_argument('--output',type=Path,required=True);step.add_argument('--uid',type=int,default=1000)
    step=steps.add_parser('_worker');step.add_argument('--input',type=Path,required=True)
    step.add_argument('--socket',type=Path,required=True);step.add_argument('--nonce',required=True)
    args=parser.parse_args();terminal.require(sys.platform=='linux','Linux required')
    if args.step=='_worker':
        terminal.require(os.geteuid()!=0,'Worker cannot be root');worker(args);return
    terminal.require(os.geteuid()==0,'Initial-namespace root observer required')
    if args.step=='_host':host(args);return
    unit='bc250-map-identity-'+uuid.uuid4().hex[:12]
    subprocess.run(['systemd-run','--quiet','--wait','--pipe','--collect','--unit='+unit,
        '--property=MemoryMax=512M','--property=MemorySwapMax=0','--property=CPUQuota=100%',
        '--property=TasksMax=64','--property=RuntimeMaxSec=60','--property=KillMode=control-group',
        '/usr/bin/python3',str(Path(__file__).resolve()),'_host','--output',str(args.output),'--uid',str(args.uid)],check=True,timeout=80)


if __name__=='__main__':main()
