#!/usr/bin/env python3
"""Preserve selected native application-input metadata and private accounting.

Root construction and private mount setup only; GUI runs after dropping to the
desktop user's real IDs/groups. Host session files remain read-only. No boot,
drive policy, host-cache reset, full-input-closure or performance claim.
"""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import pwd
import signal
import socket
import stat
import subprocess
import sys
import tarfile
import threading
import time
import uuid

import terminal_endpoint as terminal
import qualify_request_trace as q
from copied_input_probe import cache_state,verify_process_bindings

ROOT=Path(__file__).resolve().parent
ETC={'/etc/fonts/fonts.conf','/etc/ld.so.cache','/etc/machine-id','/etc/nsswitch.conf',
    '/etc/passwd','/etc/group','/etc/ssl/openssl.cnf'}
LIMIT=512*2**20


def run(*args,**kwargs):
    try:return subprocess.check_output(list(map(str,args)),text=True,stderr=subprocess.STDOUT,**kwargs).strip()
    except subprocess.CalledProcessError as exc:
        print(json.dumps(dict(subprocess_failure_output=exc.output[-16000:])),file=sys.stderr,flush=True)
        raise


def cache_request(cfg,phase):
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as channel:
        channel.settimeout(30);channel.connect(str(Path(cfg['desktop'])/'cache-observer.sock'))
        import struct
        pid,uid,_=struct.unpack('3i',channel.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
        terminal.require(uid==0 and pid==cfg['observer_pid'],'Unexpected cache observer identity')
        channel.sendall(json.dumps(dict(nonce=cfg['observer_nonce'],phase=phase)).encode()+b'\n')
        value=terminal.receive_marker(channel);terminal.require('state' in value,'Cache observer failed')
        return value['state']


def serve_cache(server,area,rows,expected,nonce,errors):
    import struct
    try:
        for phase in ('cold-before','cold-after','warm-before','warm-after'):
            channel,_=server.accept()
            with channel:
                channel.settimeout(10)
                pid,uid,_=struct.unpack('3i',channel.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
                terminal.require(uid==expected['uid'] and pid==expected['pid'],'Unowned cache client')
                message=terminal.receive_marker(channel)
                terminal.require(message==dict(nonce=nonce,phase=phase),'Invalid cache phase/nonce')
                private=[dict(copy=str(area/'corpus'/r['target'].lstrip('/')),bytes=r['bytes']) for r in rows]
                if phase=='warm-before':
                    for row,p in zip(rows,private):terminal.require(terminal.digest(Path(p['copy']))==row['sha256'],'Native corpus changed')
                state=cache_state(private,evict=phase=='cold-before')
                channel.sendall(json.dumps(dict(state=state)).encode()+b'\n')
    except BaseException as exc:errors.append(str(exc))


def node(path):
    info=path.lstat();value=dict(mode=stat.S_IMODE(info.st_mode),uid=info.st_uid,gid=info.st_gid,
        xattrs={key:hashlib.sha256(os.getxattr(path,key,follow_symlinks=False)).hexdigest()
            for key in sorted(os.listxattr(path,follow_symlinks=False))})
    if stat.S_ISREG(info.st_mode):value.update(kind='file',bytes=info.st_size,mtime_ns=info.st_mtime_ns,sha256=terminal.digest(path))
    elif stat.S_ISLNK(info.st_mode):value.update(kind='symlink',target=os.readlink(path))
    elif stat.S_ISDIR(info.st_mode):value.update(kind='directory')
    else:raise RuntimeError('Unsupported selected node')
    return value


def inventory(root,names):
    result={};links={}
    for name in sorted(names):
        path=root/name;row=node(path);info=path.lstat()
        if row['kind']=='file':
            key=(info.st_dev,info.st_ino);links.setdefault(key,name);row['hardlink_anchor']=links[key]
        result[name]=row
    return result


def validate_archive(entries,names):
    by_name={m.name:m for m in entries}
    terminal.require(len(entries)==len(by_name) and set(by_name)==names,'Generated archive node set changed')
    for member in entries:
        path=Path(member.name)
        terminal.require(not path.is_absolute() and '..' not in path.parts and
            (member.isfile() or member.isdir() or member.issym() or member.islnk()),'Unsafe generated member')
        terminal.require(not any(str(p) in by_name and by_name[str(p)].issym() for p in path.parents),
            'Symlink ancestor in generated archive')
        if member.islnk():terminal.require(member.linkname in names and not Path(member.linkname).is_absolute(),'Unsafe hardlink')


def namespace_processes(namespace):
    terminal.require(namespace!=os.readlink('/proc/self/ns/mnt'),'Refuse controller namespace')
    found=[]
    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit():continue
        try:
            if os.readlink(entry/'ns/mnt')==namespace:found.append(int(entry.name))
        except OSError:pass
    return found


def cleanup_view(area):
    marker=area/'view-namespace-private.json'
    if not marker.exists():return 0
    namespace=json.loads(marker.read_text())['mount_namespace'];count=0
    for sig in (signal.SIGTERM,signal.SIGKILL):
        for pid in namespace_processes(namespace):
            try:
                descriptor=os.pidfd_open(pid)
                try:
                    if os.readlink(f'/proc/{pid}/ns/mnt')==namespace:
                        signal.pidfd_send_signal(descriptor,sig);count+=1
                finally:os.close(descriptor)
            except ProcessLookupError:pass
            except FileNotFoundError:pass
        deadline=time.monotonic()+2
        while namespace_processes(namespace) and time.monotonic()<deadline:time.sleep(.05)
    terminal.require(not namespace_processes(namespace),'Owned view processes remain')
    return count


def choose(audit):
    report=json.loads((audit/'result.json').read_text());manifest=audit/'input-manifest-private.json'
    terminal.require(report['passed'] and terminal.digest(manifest)==report['manifest_sha256'],'Audit changed')
    records=json.loads(manifest.read_text())['records'];paths=set()
    for row in records:
        if row.get('regular_file') and row['category']=='system_usr':
            path=Path(row['resolved_path'])
            terminal.require(path.is_relative_to('/usr') and path.resolve(strict=True)==path,'Unsafe /usr source')
            terminal.require(terminal.digest(path)==row['sha256'],'Audited content changed')
            paths.add(path)
        elif row['path'].startswith('/var/cache/fontconfig/'):
            path=Path(row['path']);terminal.require(path.parent==Path('/var/cache/fontconfig') and path.resolve(strict=True)==path,
                'Unsafe font-cache path')
            terminal.require(path.is_file(),'Nonregular font-cache input');paths.add(path)
    paths.update(Path(p) for p in ETC);paths.add(Path(terminal.__file__).resolve())
    fonts=Path('/etc/fonts/conf.d');paths.add(fonts)
    for path in fonts.iterdir():
        terminal.require(path.is_symlink() or path.is_file(),'Unsupported font configuration node');paths.add(path)
        if path.is_symlink():
            target=path.resolve(strict=True);terminal.require(target.is_relative_to('/usr') and target.is_file(),'Unexpected font link target')
            paths.add(target)
    regular=[p for p in paths if not p.is_symlink() and p.is_file()]
    terminal.require(len(paths)<=2048 and sum(p.stat().st_size for p in regular)<=LIMIT,'Native corpus bound')
    for path in list(paths):
        terminal.require(path.is_absolute() and '..' not in path.parts,'Unsafe source path')
        paths.update(p for p in path.parents if p!=Path('/'))
    return {str(p).lstrip('/') for p in paths},report


def mount_library(area):
    library=ctypes.CDLL(str(area/'mount-helper.so'))
    library.bc_bind.argtypes=[ctypes.c_char_p,ctypes.c_char_p,ctypes.c_int,ctypes.c_int]
    library.bc_readonly_tree.argtypes=[ctypes.c_char_p];library.bc_tmpfs.argtypes=[ctypes.c_char_p]
    return library


def checked_mount(fn,*args):
    converted=[os.fsencode(v) if isinstance(v,(str,Path)) else v for v in args]
    error=fn(*converted)
    if error:raise OSError(error,os.strerror(error))


def view(args):
    area=args.output.absolute();cfg=json.loads((area/'view-private.json').read_text());desktop=Path(cfg['desktop'])
    lib=mount_library(area);root=area/'view-root'
    terminal.require(os.geteuid()==0 and os.readlink('/proc/self/ns/mnt')!=cfg['parent_mount'],'Private root setup required')
    terminal.save(area/'view-namespace-private.json',dict(mount_namespace=os.readlink('/proc/self/ns/mnt')))
    checked_mount(lib.bc_bind,'/',root,1,0)
    for relative in ('run','var/log','tmp','var/tmp'):checked_mount(lib.bc_tmpfs,root/relative)
    for relative in (f'run/user/{cfg["uid"]}','run/bc250-native-control'):(root/relative).mkdir(parents=True,exist_ok=True)
    for relative in ('run/utmp','var/log/wtmp','run/bc250-native-control/utmp-check'):(root/relative).touch(exist_ok=False)
    checked_mount(lib.bc_readonly_tree,root)
    checked_mount(lib.bc_bind,'/dev',root/'dev',1,0)
    for source,target in [(desktop,str(desktop).lstrip('/')),
        (f'/run/user/{cfg["uid"]}',f'run/user/{cfg["uid"]}'),
        (area/'private-tmp','tmp'),(area/'private-vartmp','var/tmp'),
        (area/'runtime/utmp','run/utmp'),(area/'runtime/wtmp','var/log/wtmp')]:
        checked_mount(lib.bc_bind,source,root/target,1 if Path(source).is_dir() else 0,0)
    cgroup=Path('/sys/fs/cgroup/user.slice')/f'user-{cfg["uid"]}.slice'
    terminal.require(cgroup.is_dir(),'Expected user cgroup context absent')
    checked_mount(lib.bc_bind,cgroup,root/str(cgroup).lstrip('/'),1,0)
    for target in cfg['bindings']:
        checked_mount(lib.bc_bind,area/'corpus'/target.lstrip('/'),root/target.lstrip('/'),0,1)
    checked_mount(lib.bc_bind,area/'corpus/etc/fonts/conf.d',root/'etc/fonts/conf.d',0,1)
    checked_mount(lib.bc_bind,area/'utmp-check',root/'run/bc250-native-control/utmp-check',0,1)
    rows=cfg['regular_inputs']
    for row in rows:
        info=(root/row['target'].lstrip('/')).stat()
        terminal.require((info.st_dev,info.st_ino)==(row['device'],row['inode']),'Native binding identity mismatch')
        terminal.require(os.statvfs(root/row['target'].lstrip('/')).f_flag&os.ST_RDONLY,'Native input is writable')
    terminal.require(not os.statvfs(root/'usr/lib/utempter/utempter').f_flag&os.ST_NOSUID,'Helper mount forbids native setgid semantics')
    os.setgroups(cfg['groups']);os.setgid(cfg['gid']);os.chroot(root);os.chdir(desktop);os.setuid(cfg['uid'])
    libc=ctypes.CDLL(None);terminal.require(libc.prctl(1,signal.SIGKILL)==0,'Cannot bind view-controller lifetime')
    status=Path('/proc/self/status').read_text()
    terminal.require(all(int(line.split()[1],16)==0 for line in status.splitlines() if line.startswith(('CapEff:','CapPrm:','CapAmb:'))),
        'Controller retained capabilities')
    terminal.require('NoNewPrivs:\t0' in status,'Native helper privilege semantics were disabled')
    env=cfg['environment'];env['HOME']=str(desktop/'home');results=[];proofs=[]
    original=terminal.owns_descendant
    def owned(pid,parent):
        valid=original(pid,parent)
        if valid:
            verify_process_bindings(pid,rows,cfg['parent_mount'])
            tty=os.readlink(f'/proc/{pid}/fd/0');terminal.require(tty.startswith('/dev/pts/'),'Unexpected owned terminal')
            proof=json.loads(run('/run/bc250-native-control/utmp-check',tty.removeprefix('/dev/')))
            terminal.require(proof['owned_user_tty_records']==1,'Private native session accounting failed')
            proofs.append(proof)
        return valid
    terminal.owns_descendant=owned
    try:
        for index,label in enumerate(('native-data-cold','native-data-warm')):
            before=cache_request(cfg,'warm-before' if index else 'cold-before')
            terminal.require(before['resident_bytes']==(0 if not index else before['page_rounded_bytes']),'Native cache condition failed')
            result=terminal.trial(desktop,index,env,20,0.)
            after=cache_request(cfg,'warm-after' if index else 'cold-after')
            terminal.require(result['normal_close_verified'] and result['cpu_policy_unchanged'],'Native endpoint or policy failure')
            results.append(dict(condition=label,before=before,after=after,endpoint_passed=True,normal_close_verified=True,
                private_owned_session_record_verified=True,readonly_bindings_verified=len(rows)))
            print(json.dumps(results[-1]),flush=True)
    finally:terminal.owns_descendant=original;terminal.save(desktop/'completed-conditions.json',results)
    terminal.save(desktop/'result.json',dict(passed=True,conditions=results,private_session_checks=proofs,
        controller_uid_correct=os.geteuid()==cfg['uid'],controller_capabilities_zero=True,no_new_privs=False,
        performance_result=False,complete_application_input_closure=False,stage1_gate_passed=False))


def build(args):
    q.native.confined();area=args.output.absolute();desktop=args.desktop_output.absolute();audit=args.audit.absolute()
    q.native.private_area(area,creating=True);q.native.private_area(desktop,creating=True);q.native.host_space(area.parent)
    account=pwd.getpwuid(args.uid);terminal.require(args.uid>0 and account.pw_dir.startswith('/home/'),'Use existing desktop user')
    names,_=choose(audit);before=inventory(Path('/'),names)
    area.mkdir(mode=0o700);desktop.mkdir(mode=0o700);os.chown(desktop,args.uid,account.pw_gid)
    for p in ('home',):
        (desktop/p).mkdir(mode=0o700);os.chown(desktop/p,args.uid,account.pw_gid)
    for p in ('corpus','view-root','runtime','private-tmp','private-vartmp'):(area/p).mkdir(mode=0o755)
    (area/'private-tmp').chmod(0o1777);(area/'private-vartmp').chmod(0o1777)
    filelist=area/'filelist-private.nul';filelist.write_bytes(b''.join(os.fsencode(n)+b'\0' for n in sorted(names)))
    archive=area/'source-private.tar'
    run('tar','--create','--file',archive,'--numeric-owner','--acls','--xattrs','--xattrs-include=*',
        '--no-recursion','--null','--verbatim-files-from','--directory','/','--files-from',filelist,timeout=120)
    terminal.require(archive.stat().st_size<=LIMIT+16*2**20,'Archive bound')
    with tarfile.open(archive) as stream:
        validate_archive(stream.getmembers(),names)
    run('tar','--extract','--file',archive,'--directory',area/'corpus','--numeric-owner','--same-owner',
        '--same-permissions','--acls','--xattrs','--xattrs-include=*',timeout=120)
    after=inventory(area/'corpus',names);terminal.require(after==before,'Selected metadata/content/topology differs')
    terminal.require(inventory(Path('/'),names)==before,'Original inputs changed during construction')
    terminal.save(area/'manifest-private.json',before)
    rows=[]
    for name,row in before.items():
        if row['kind']!='file':continue
        target=area/'corpus'/name;info=target.stat();fd=os.open(target,os.O_RDONLY|os.O_NOFOLLOW)
        try:
            os.fsync(fd);spans=q.native.repack.extents(fd,info.st_size) if info.st_size else []
            terminal.require(not any(flags&0x2000 for _,_,flags in spans),'Native copied extent shares data')
        finally:os.close(fd)
        rows.append(dict(target='/'+name,device=info.st_dev,inode=info.st_ino,bytes=info.st_size,sha256=row['sha256']))
    terminal.require(sum(r['bytes'] for r in rows)<=LIMIT,'Final data bound')
    for path,flags in [('native_input_mount.c',['-shared','-fPIC']),('native_input_utmp.c',[])]:
        output=area/('mount-helper.so' if flags else 'utmp-check')
        run('gcc','-O2','-Wall','-Wextra','-Werror',*flags,ROOT/path,'-o',output,timeout=60)
    utmp_group=(Path('/run/utmp').stat().st_gid if Path('/run/utmp').exists() else 22)
    for name in ('utmp','wtmp'):
        path=area/'runtime'/name;path.touch(mode=0o664);os.chown(path,0,utmp_group);path.chmod(0o664)
    text=run('runuser','-u',account.pw_name,'--','env',f'XDG_RUNTIME_DIR=/run/user/{args.uid}',
        f'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{args.uid}/bus','systemctl','--user','show-environment',timeout=10)
    environment={key:value for line in text.splitlines() for key,_,value in [line.partition('=')]
        if key in ('DISPLAY','WAYLAND_DISPLAY','XDG_RUNTIME_DIR','DBUS_SESSION_BUS_ADDRESS','XDG_SESSION_TYPE','XDG_CURRENT_DESKTOP')}
    terminal.require(environment.get('XDG_SESSION_TYPE')=='wayland','Expected desktop unavailable')
    environment.update(PATH='/usr/bin',LANG='C.UTF-8',USER=account.pw_name,LOGNAME=account.pw_name)
    cfg=dict(uid=args.uid,gid=account.pw_gid,groups=os.getgrouplist(account.pw_name,account.pw_gid),
        desktop=str(desktop),environment=environment,bindings=[r['target'] for r in rows],regular_inputs=rows,
        parent_mount=os.readlink('/proc/self/ns/mnt'),observer_pid=os.getpid(),observer_nonce=uuid.uuid4().hex)
    terminal.save(area/'view-private.json',cfg)
    source={name:terminal.digest(ROOT/name) for name in ('native_application_inputs.py','native_input_mount.c',
        'native_input_utmp.c','terminal_endpoint.py','copied_input_probe.py')}
    terminal.save(area/'contract.json',dict(schema_version=1,source_sha256=source,logical_file_bytes=sum(r['bytes'] for r in rows),
        selected_nodes=len(names),regular_files=len(rows),metadata_scope='Selected file/dir/link nodes; hardlink relations within selected set',
        max_logical_bytes=LIMIT,performance_result=False,complete_os_baseline=False,stage1_gate_passed=False))
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as server:
        sock=desktop/'cache-observer.sock';server.bind(str(sock));os.chown(sock,args.uid,account.pw_gid);sock.chmod(0o600)
        server.listen(1);server.settimeout(120);errors=[];expected=dict(uid=args.uid,pid=None)
        child=subprocess.Popen(['unshare','--mount','--propagation','private','python3',str(Path(__file__).resolve()),
            '_view','--output',str(area),'--uid',str(args.uid)],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
        expected['pid']=child.pid
        observer=threading.Thread(target=serve_cache,args=(server,area,rows,expected,cfg['observer_nonce'],errors),daemon=True)
        observer.start()
        try:
            output,_=child.communicate(timeout=120);print(output,flush=True)
            terminal.require(child.returncode==0,'Native view failed')
            observer.join(timeout=2);terminal.require(not observer.is_alive() and not errors,'Cache observer incomplete: '+str(errors))
        finally:
            if child.poll() is None:child.kill();child.wait(timeout=10)
            cleaned=cleanup_view(area)
            terminal.save(area/'cleanup.json',dict(remaining_view_processes=0,signals_sent=cleaned))
            sock.unlink()
    result=json.loads((desktop/'result.json').read_text());terminal.require(result['passed'],'Native GUI qualification failed')
    terminal.require(inventory(area/'corpus',names)==before and inventory(Path('/'),names)==before,'Post-run input metadata changed')
    result.update(schema_version=1,source_sha256=source,logical_file_bytes=sum(r['bytes'] for r in rows),selected_nodes=len(names),
        regular_files=len(rows),selected_metadata_matches_source=True,source_and_corpus_unchanged=True,shared_extent_count=0,
        private_session_files_used=True,metadata_scope='Selected nodes and selected-set hardlink relations; not a complete OS baseline',
        normal_close_left_no_view_processes=cleaned==0,remaining_view_processes=0,
        owned_process_root_bindings_verified=True,foreground_cgroup_limits_qualified=False,
        complete_os_baseline=False,completed_unix=time.time())
    terminal.save(area/'result.json',result);print(json.dumps(result),flush=True)


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('step',choices=('run','_build','_view'))
    parser.add_argument('--audit',type=Path);parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--desktop-output',type=Path);parser.add_argument('--uid',type=int,default=1000)
    args=parser.parse_args();terminal.require(sys.platform=='linux' and os.geteuid()==0,'Root setup required')
    if args.step=='_view':view(args);return
    if args.step=='_build':build(args);return
    unit='bc250-native-input-'+uuid.uuid4().hex[:12];print(json.dumps(dict(parent_unit=unit)),flush=True)
    subprocess.run(['systemd-run','--quiet','--wait','--pipe','--collect','--unit='+unit,'--property=MemoryMax=2G',
        '--property=MemorySwapMax=0','--property=CPUQuota=200%','--property=RuntimeMaxSec=300','--property=KillMode=control-group',
        '/usr/bin/unshare','--mount','--propagation','private','python3',str(Path(__file__).resolve()),'_build',
        '--audit',str(args.audit),'--output',str(args.output),'--desktop-output',str(args.desktop_output),
        '--uid',str(args.uid)],check=True,timeout=330)


if __name__=='__main__':main()
