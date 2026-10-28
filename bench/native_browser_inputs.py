#!/usr/bin/env python3
"""Independent selected native Firefox inputs with scoped cache/mapping checks.

One private corpus, no original-file eviction or system policy changes. This is
not a full OS baseline, complete application cold state or speed comparison.
"""
import argparse
import ctypes
import json
import os
from pathlib import Path
import pwd
import signal
import socket
import stat
import struct
import subprocess
import sys
import tarfile
import threading
import time
import uuid

import browser_endpoint as browser
import browser_inputs as audit
import browser_identity as observer
import copied_input_probe as copied
import mapped_identity as identity
import native_application_inputs as native
import qualify_request_trace as q
import terminal_endpoint as terminal

ROOT=Path(__file__).resolve().parent
LIMIT=1024*2**20
PHASES=('cold-before','cold-capture','cold-after','warm-before','warm-capture','warm-after','finish')


def source_path(value,roots=('/usr','/etc')):
    path=Path(value)
    terminal.require(path.is_absolute() and '..' not in path.parts and str(path)==value and
        any(path.is_relative_to(root) for root in roots),'Unsafe input source')
    terminal.require(path.resolve(strict=True)==path and path.is_file(),'Noncanonical regular input')
    return path


def choose(audit_area,identity_area):
    report=json.loads((audit_area/'result.json').read_text());manifest=audit_area/'input-manifest-private.json'
    terminal.require(report['passed'] and terminal.digest(manifest)==report['manifest_sha256'],'Changed browser audit')
    proof=json.loads((identity_area/'result.json').read_text());state=json.loads((identity_area/'observer-state-private.json').read_text())
    terminal.require(proof['passed'] and state['finished'] and not state['errors'],'Missing identity qualification')
    paths=set();audited={}
    for row in json.loads(manifest.read_text())['records']:
        if row.get('regular_file') and row['category'] in ('system_usr','system_etc_context'):
            path=source_path(row['resolved_path']);info=path.stat()
            terminal.require((info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns)==
                tuple(row[key] for key in ('device','inode','bytes','mtime_ns','ctime_ns')),'Audited input identity changed')
            terminal.require(terminal.digest(path)==row['sha256'],'Audited input content changed');paths.add(path);audited[str(path)]=row
        elif row['path'].startswith('/var/cache/fontconfig/'):
            path=source_path(row['path'],('/var/cache/fontconfig',));terminal.require(path.parent==Path('/var/cache/fontconfig'),'Unexpected font cache')
            paths.add(path)
    verified=set()
    for index,capture in enumerate(state['captures']):
        path=identity_area/f'capture-{index}-private.json'
        terminal.require(terminal.digest(path)==capture['private_capture_sha256'],'Mapping capture changed')
        for sample in json.loads(path.read_text())['samples']:
            for row in sample['records']:
                if not row.get('host_identity_matches_mapping') or row['path'] not in audited:continue
                actual=Path(row['path']).stat()
                terminal.require((actual.st_dev,actual.st_ino)==(row['reference_device'],row['reference_inode']),
                    'Verified host mapping identity changed');verified.add(row['path'])
    terminal.require('/usr/lib/firefox/firefox' in verified and len(verified)>100,'Insufficient verified browser mappings')
    fonts=Path('/etc/fonts/conf.d');paths.add(fonts)
    for path in fonts.iterdir():
        terminal.require(path.is_symlink() or path.is_file(),'Unsupported font configuration node');paths.add(path)
        if path.is_symlink():paths.add(source_path(str(path.resolve(strict=True)),('/usr',)))
    regular=[path for path in paths if path.is_file() and not path.is_symlink()]
    terminal.require(0<len(paths)<=2048 and sum(path.stat().st_size for path in regular)<=LIMIT,'Browser corpus bound')
    for path in list(paths):paths.update(parent for parent in path.parents if parent!=Path('/'))
    terminal.require(len(paths)<=4096,'Selected node bound')
    return {str(path).lstrip('/') for path in paths},len(verified)


def construct(area,names):
    before=native.inventory(Path('/'),names)
    for name in ('corpus','view-root','private-tmp','private-vartmp'):(area/name).mkdir(mode=0o755)
    for name in ('private-tmp','private-vartmp'):(area/name).chmod(0o1777)
    listing=area/'filelist-private.nul';listing.write_bytes(b''.join(os.fsencode(name)+b'\0' for name in sorted(names)))
    archive=area/'source-private.tar'
    native.run('tar','--create','--file',archive,'--numeric-owner','--acls','--xattrs','--xattrs-include=*',
        '--no-recursion','--null','--verbatim-files-from','--directory','/','--files-from',listing,timeout=120)
    terminal.require(archive.stat().st_size<=LIMIT+16*2**20,'Archive bound')
    with tarfile.open(archive) as stream:native.validate_archive(stream.getmembers(),names)
    native.run('tar','--extract','--file',archive,'--directory',area/'corpus','--numeric-owner','--same-owner',
        '--same-permissions','--acls','--xattrs','--xattrs-include=*',timeout=120)
    terminal.require(native.inventory(area/'corpus',names)==before and native.inventory(Path('/'),names)==before,
        'Selected metadata/content/link topology differs')
    terminal.save(area/'manifest-private.json',before);rows=[]
    for name,row in before.items():
        if row['kind']!='file':continue
        path=area/'corpus'/name;info=path.stat();original=(Path('/')/name).stat()
        terminal.require((info.st_dev,info.st_ino)!=(original.st_dev,original.st_ino),'Copy aliases original inode')
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
        try:
            os.fsync(fd);spans=q.native.repack.extents(fd,info.st_size) if info.st_size else []
            terminal.require(not any(flags&0x2000 for _,_,flags in spans),'Copied extent shares data')
        finally:os.close(fd)
        rows.append(dict(target='/'+name,copy=str(path),bytes=info.st_size,sha256=row['sha256'],
            device=info.st_dev,inode=info.st_ino,original_device=original.st_dev,original_inode=original.st_ino))
    terminal.require(sum(row['bytes'] for row in rows)<=LIMIT,'Final corpus bound')
    return before,rows


def copied_mappings(rows,records):
    expected={row['target']:(row['device'],row['inode']) for row in rows}
    identities={value:path for path,value in expected.items()}
    originals={(row['original_device'],row['original_inode']) for row in rows};matched=set()
    for row in records:
        if 'reference_device' not in row:continue
        actual=(row['reference_device'],row['reference_inode'])
        terminal.require(actual not in originals,'Selected original source remains mapped by foreground')
        if row['path'] in expected:terminal.require(actual==expected[row['path']],'Selected mapping does not reference copied inode')
        if actual in identities:matched.add(identities[actual])
    return matched


def sandbox_log_accepted(text):
    lowered=text.lower()
    terminal.require('without sandbox' not in lowered and 'cancreateusernamespace() clone() failure' not in lowered,
        'Browser/decoder sandbox fallback detected')


def capture(peer,cfg,area,index,lib,rows):
    group=observer.scope_group(peer,cfg);terminal.require(group is not None,'View controller left owned group')
    members=browser.members(group)-{peer};terminal.require(0<len(members)<=64,'Mapping process bound')
    expected={row['target']:(row['device'],row['inode']) for row in rows}
    samples=[];unavailable=[];main=[];matched=set()
    for pid in sorted(members):
        try:
            terminal.require(observer.scope_group(pid,cfg)==group,'Process left view group')
            sample=identity.inspect(pid,lambda n:observer.scope_group(n,cfg)==group,lib);samples.append(sample)
            sample['root_description']=os.readlink(f'/proc/{pid}/root')
            matched.update(copied_mappings(rows,sample['records']))
            status=Path('/proc',str(pid),'status').read_text()
            parent=int(next(line.split()[1] for line in status.splitlines() if line.startswith('PPid:')))
            if parent==peer:
                fd=os.open(f'/proc/{pid}/exe',os.O_PATH|os.O_CLOEXEC)
                try:exe=os.fstat(fd)
                finally:os.close(fd)
                if (exe.st_dev,exe.st_ino)==expected['/usr/lib/firefox/firefox']:main.append(pid)
        except (FileNotFoundError,ProcessLookupError):unavailable.append('process_disappeared')
    terminal.require(len(main)==1 and '/usr/lib/firefox/firefox' in matched,'Actual copied Firefox main not verified')
    copied.verify_process_bindings(main[0],rows,cfg['parent_mount'])
    terminal.save(area/f'mapping-{index}-private.json',dict(samples=samples,unavailable=unavailable,selected_mapped_paths=sorted(matched)))
    return dict(process_samples=len(samples),selected_mapped_files_verified=len(matched),
        mount_namespace_count=len({sample['mount_namespace'] for sample in samples}),
        selected_original_mapping_count=0,copied_main_executable_verified=True,unavailable_processes=len(unavailable))


def serve(server,cfg,area,rows,lib,state,done):
    controller=None
    try:
        for phase in PHASES:
            if done.is_set():return
            channel,_=server.accept()
            with channel:
                channel.settimeout(10)
                pid,uid,_=struct.unpack('3i',channel.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
                observer.authorize(terminal.receive_marker(channel),uid,pid,phase,cfg,
                    lambda n:observer.scope_group(n,cfg) is not None,controller);controller=pid
                if phase.endswith('capture'):
                    value=dict(mapping=capture(pid,cfg,area,0 if phase.startswith('cold') else 1,lib,rows))
                elif phase=='finish':
                    group=observer.scope_group(pid,cfg);terminal.require(browser.members(group)=={pid},'Foreground processes remain')
                    value=dict(foreground_empty_except_controller=True)
                else:
                    if phase=='warm-before':
                        for row in rows:terminal.require(terminal.digest(Path(row['copy']))==row['sha256'],'Copy content changed')
                    value=dict(cache=copied.cache_state(rows,evict=phase=='cold-before'))
                state['phases'].append(dict(phase=phase,**value))
                channel.sendall(json.dumps(dict(ok=True,**value)).encode()+b'\n')
        state['finished']=True
    except BaseException as exc:state['errors'].append(str(exc))
    finally:done.set()


def view(args):
    area=args.output.absolute();cfg=json.loads((area/'view-private.json').read_text());desktop=Path(cfg['desktop'])
    terminal.require(os.geteuid()==0 and os.readlink('/proc/self/ns/mnt')!=os.readlink('/proc/1/ns/mnt'),'Private root setup required')
    browser.namespace_state();subprocess.run(['ip','link','set','lo','up'],check=True);net=browser.namespace_state()
    terminal.save(area/'view-namespace-private.json',dict(mount_namespace=os.readlink('/proc/self/ns/mnt')))
    lib=native.mount_library(area);root=area/'view-root';native.checked_mount(lib.bc_bind,'/',root,1,0)
    for name in ('run','var/log','tmp','var/tmp'):native.checked_mount(lib.bc_tmpfs,root/name)
    (root/f'run/user/{cfg["uid"]}').mkdir(parents=True,exist_ok=True)
    native.checked_mount(lib.bc_readonly_tree,root);native.checked_mount(lib.bc_bind,'/dev',root/'dev',1,0)
    native.checked_mount(lib.bc_bind,'/proc',root/'proc',1,0)
    native.checked_mount(lib.bc_bind,'/proc/sys',root/'proc/sys',1,1)
    native.checked_mount(lib.bc_bind,'/proc/sysrq-trigger',root/'proc/sysrq-trigger',0,1)
    for source,target in ((desktop,str(desktop).lstrip('/')),(f'/run/user/{cfg["uid"]}',f'run/user/{cfg["uid"]}'),
        (area/'private-tmp','tmp'),(area/'private-vartmp','var/tmp')):
        native.checked_mount(lib.bc_bind,source,root/target,1,0)
    # Existing desktop services are explicit shared context. Only this new
    # transient unit's members are observed/stopped by the endpoint.
    for row in cfg['rows']:native.checked_mount(lib.bc_bind,row['copy'],root/row['target'].lstrip('/'),0,1)
    native.checked_mount(lib.bc_bind,area/'corpus/etc/fonts/conf.d',root/'etc/fonts/conf.d',0,1)
    for row in cfg['rows']:
        info=(root/row['target'].lstrip('/')).stat()
        terminal.require((info.st_dev,info.st_ino)==(row['device'],row['inode']),'Prelaunch binding identity differs')
        terminal.require(os.statvfs(root/row['target'].lstrip('/')).f_flag&os.ST_RDONLY,'Selected input writable')
    lib.bc_pivot.argtypes=[ctypes.c_char_p];native.checked_mount(lib.bc_pivot,root)
    os.setgroups(cfg['groups']);os.setgid(cfg['gid']);os.chdir(desktop);os.setuid(cfg['uid'])
    libc=ctypes.CDLL(None);terminal.require(libc.prctl(1,signal.SIGKILL)==0,'View lifetime not bound')
    status=Path('/proc/self/status').read_text()
    terminal.require(all(int(line.split()[1],16)==0 for line in status.splitlines()
        if line.startswith(('CapEff:','CapPrm:','CapAmb:'))),'View controller retains capabilities')
    terminal.require(not os.statvfs('/proc').f_flag&os.ST_RDONLY and os.statvfs('/proc/sys').f_flag&os.ST_RDONLY,
        'Expected writable per-process proc controls and read-only sysctls')
    probe=subprocess.run(['unshare','--user','--map-current-user','--','/usr/bin/true'],capture_output=True,text=True,timeout=10)
    terminal.save(desktop/'user-namespace-probe.json',dict(exit_code=probe.returncode,stderr=probe.stderr[:1000]))
    terminal.require(probe.returncode==0,'Nested user-namespace probe failed: '+probe.stderr[:300])
    group=observer.scope_group(os.getpid(),cfg);terminal.require(group is not None,'Wrong foreground group')
    env=cfg['environment'];results=[];seeds=[];mappings=[];old_popen=subprocess.Popen;old_cleanup=browser.cleanup
    def launch(command,*positional,**keywords):
        terminal.require(command[:1]==['firefox'],'Unexpected endpoint subprocess')
        home=Path(command[command.index('--profile')+1]).parent;seeds.append(audit.seed_manifest(home))
        return old_popen(command,*positional,**keywords)
    def checked_cleanup(proc,owned_group):
        try:
            if proc is not None and proc.poll() is None:mappings.append(observer.rpc(cfg,'cold-capture' if not mappings else 'warm-capture')['mapping'])
        finally:value=old_cleanup(proc,owned_group)
        return value
    try:
        subprocess.Popen=launch;browser.cleanup=checked_cleanup
        for index,label in enumerate(('selected-data-cold','selected-data-warm')):
            before=observer.rpc(cfg,'cold-before' if not index else 'warm-before')['cache']
            terminal.require(before['resident_bytes']==(0 if not index else before['page_rounded_bytes']),'Selected cache condition failed')
            result=browser.trial(desktop,index,env,group,0.)
            sandbox_log_accepted((desktop/f'trial-{index:02}/browser-private.log').read_text(errors='replace'))
            after=observer.rpc(cfg,'cold-after' if not index else 'warm-after')['cache']
            terminal.require(result['cpu_policy_unchanged'] and result['owned_browser_processes_gone'] and not result['forced_cleanup_required'],
                'Endpoint policy or cleanup failed')
            terminal.require(len(mappings)==index+1,'Mapping capture missing')
            results.append(dict(condition=label,before=before,after=after,mapping=mappings[-1],functional_endpoint_passed=True))
            print(json.dumps(results[-1]),flush=True)
    finally:
        subprocess.Popen=old_popen;browser.cleanup=old_cleanup;terminal.save(desktop/'completed-conditions.json',results)
    terminal.require(len(seeds)==2 and seeds[0]==seeds[1],'Fresh private seeds differ')
    finish=observer.rpc(cfg,'finish');terminal.require(finish['foreground_empty_except_controller'],'Foreground cleanup failed')
    terminal.save(desktop/'result.json',dict(passed=True,conditions=results,private_seeds_identical=True,
        selected_readonly_bindings_verified=len(cfg['rows']),controller_capabilities_zero=True,network=net,
        nested_user_namespace_probe_passed=True,sandbox_fallback_warnings_absent=True,private_namespace_root_pivoted=True,
        per_process_proc_controls_writable=True,proc_sys_readonly=True,
        foreground_empty_except_controller=True,performance_result=False,cache_scope='Selected copied file data only',
        complete_application_input_closure=False,complete_os_baseline=False,stage1_gate_passed=False))


def build(args):
    q.native.confined();area=args.output.absolute();desktop=args.desktop_output.absolute()
    q.native.private_area(area,creating=True);q.native.private_area(desktop,creating=True);q.native.host_space(area.parent)
    terminal.require(terminal.snapshot()['memory']['MemAvailable']>=7*2**30,'Need 7 GiB available memory for combined lab units')
    names,verified=choose(args.audit,args.identity);account=pwd.getpwuid(args.uid)
    terminal.require(args.uid>0 and account.pw_dir.startswith('/home/'),'Use existing desktop user')
    area.mkdir(mode=0o700);desktop.mkdir(mode=0o700);os.chown(desktop,args.uid,account.pw_gid)
    before,rows=construct(area,names);q.native.host_space(area.parent)
    native.run('cc','-O2','-Wall','-Wextra','-Werror','-shared','-fPIC',ROOT/'native_browser_mount.c','-o',area/'mount-helper.so')
    lib=identity.compile_library(area/'rooted.so')
    text=native.run('runuser','-u',account.pw_name,'--','env',f'XDG_RUNTIME_DIR=/run/user/{args.uid}',
        f'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{args.uid}/bus','systemctl','--user','show-environment',timeout=10)
    env={key:value for line in text.splitlines() for key,_,value in [line.partition('=')]
        if key in ('DISPLAY','WAYLAND_DISPLAY','XDG_RUNTIME_DIR','DBUS_SESSION_BUS_ADDRESS','XDG_SESSION_TYPE','XDG_CURRENT_DESKTOP')}
    terminal.require(env.get('XDG_SESSION_TYPE')=='wayland','Expected desktop unavailable')
    env.update(PATH='/usr/bin',LANG='C.UTF-8',USER=account.pw_name,LOGNAME=account.pw_name,PYTHONDONTWRITEBYTECODE='1')
    cfg=dict(uid=args.uid,gid=account.pw_gid,groups=os.getgrouplist(account.pw_name,account.pw_gid),desktop=str(desktop),
        environment=env,rows=rows,nonce=uuid.uuid4().hex,observer_pid=os.getpid(),socket=str(desktop/'observer.sock'),
        parent_mount=os.readlink('/proc/self/ns/mnt'),
        unit='bc250-native-browser-view-'+uuid.uuid4().hex[:12])
    terminal.require(len(cfg['socket'].encode())<104,'Observer socket path too long');terminal.save(area/'view-private.json',cfg)
    sources={name:terminal.digest(ROOT/name) for name in ('native_browser_inputs.py','native_browser_mount.c','native_application_inputs.py','native_input_mount.c',
        'browser_endpoint.py','browser_inputs.py','browser_identity.py','mapped_identity.py','mapped_identity.c','copied_input_probe.py','terminal_endpoint.py')}
    state=dict(phases=[],errors=[],finished=False);done=threading.Event();process=None
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as server:
        server.bind(cfg['socket']);os.chown(cfg['socket'],args.uid,account.pw_gid);os.chmod(cfg['socket'],0o600);server.listen(1);server.settimeout(180)
        thread=threading.Thread(target=serve,args=(server,cfg,area,rows,lib,state,done),daemon=True);thread.start()
        try:
            process=subprocess.Popen(['systemd-run','--quiet','--wait','--pipe','--collect','--unit='+cfg['unit'],
                '--property=MemoryMax=3G','--property=MemorySwapMax=0','--property=TasksMax=512','--property=RuntimeMaxSec=180',
                '--property=KillMode=control-group','--property=TimeoutStopSec=15','/usr/bin/unshare','--mount','--net','--propagation','private',
                '/usr/bin/python3','-B',str(Path(__file__).resolve()),'_view','--output',str(area)],
                stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
            output,_=process.communicate(timeout=210);print(output,flush=True)
            terminal.require(process.returncode==0,'Native browser view failed');thread.join(timeout=2)
            terminal.require(not thread.is_alive() and state['finished'] and not state['errors'],'Observer incomplete: '+str(state['errors']))
        finally:
            done.set()
            if process is not None and process.poll() is None:process.terminate();process.wait(timeout=10)
            subprocess.run(['systemctl','stop',cfg['unit']+'.service'],capture_output=True,timeout=25)
            cleaned=native.cleanup_view(area);terminal.save(area/'observer-state-private.json',state)
            Path(cfg['socket']).unlink()
    terminal.require(cleaned==0,'Additional namespace cleanup was needed')
    terminal.require(native.inventory(area/'corpus',names)==before and native.inventory(Path('/'),names)==before,'Post-run selected metadata changed')
    terminal.require(all(terminal.digest(ROOT/name)==digest for name,digest in sources.items()),'Fixture source changed')
    result=json.loads((desktop/'result.json').read_text());result.update(schema_version=1,source_sha256=sources,
        regular_files=len(rows),selected_nodes=len(names),logical_bytes=sum(row['bytes'] for row in rows),
        prior_verified_audited_sources=verified,max_corpus_bytes=LIMIT,selected_metadata_preserved=True,
        original_and_copy_metadata_unchanged=True,shared_extent_count=0,remaining_view_processes=0,
        additional_namespace_cleanup_signals=cleaned,completed_unix=time.time())
    terminal.save(area/'result.json',result);print(json.dumps(result),flush=True)


def main():
    parser=argparse.ArgumentParser(description=__doc__);steps=parser.add_subparsers(dest='step',required=True)
    for name in ('run','_build'):
        step=steps.add_parser(name);step.add_argument('--audit',type=Path,required=True);step.add_argument('--identity',type=Path,required=True)
        step.add_argument('--output',type=Path,required=True);step.add_argument('--desktop-output',type=Path,required=True)
        step.add_argument('--uid',type=int,default=1000)
    step=steps.add_parser('_view');step.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();terminal.require(sys.platform=='linux' and os.geteuid()==0,'Root setup required')
    if args.step=='_view':view(args);return
    if args.step=='_build':build(args);return
    unit='bc250-native-browser-'+uuid.uuid4().hex[:12]
    subprocess.run(['systemd-run','--quiet','--wait','--pipe','--collect','--unit='+unit,'--property=MemoryMax=2G',
        '--property=MemorySwapMax=0','--property=CPUQuota=200%','--property=TasksMax=64','--property=RuntimeMaxSec=360',
        '--property=KillMode=control-group','/usr/bin/unshare','--mount','--propagation','private','/usr/bin/python3','-B',
        str(Path(__file__).resolve()),'_build','--audit',str(args.audit),'--identity',str(args.identity),
        '--output',str(args.output),'--desktop-output',str(args.desktop_output),'--uid',str(args.uid)],check=True,timeout=390)


if __name__=='__main__':main()
