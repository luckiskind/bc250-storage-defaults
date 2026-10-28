#!/usr/bin/env python3
"""Qualify cold/warm page-cache states for copied audited /usr inputs.

One bounded independent Btrfs data corpus; no host cache eviction or drive
changes. Private mount bindings expose copies at normal application paths.
This is a partial input fixture, not a complete OS baseline or speed result.
"""
import argparse
import json
import os
from pathlib import Path,PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import time

import terminal_endpoint as terminal
import qualify_request_trace as q

ROOT=Path(__file__).resolve().parent
MAX_BYTES=512*2**20


def select_records(manifest,shared_privileged=()):
    chosen={}
    for row in manifest['records']:
        if row['category']!='system_usr' or not row.get('regular_file'):continue
        path=PurePosixPath(row['resolved_path'])
        terminal.require(path.is_absolute() and path.parts[1:2]==('usr',) and '..' not in path.parts
            and str(path)==row['resolved_path'],'Unsafe /usr input path')
        terminal.require(type(row['bytes']) is int and 0<=row['bytes']<=256*2**20,'Input size limit')
        terminal.require(re.fullmatch('[a-f0-9]{64}',row['sha256']) is not None,'Invalid input digest')
        if str(path) in chosen:
            old=chosen[str(path)]
            terminal.require(all(old[key]==row[key] for key in ('bytes','sha256','device','inode','mtime_ns','ctime_ns','mode')),
                'Conflicting aliases for one canonical input')
        else:chosen[str(path)]=row
    requested=set(shared_privileged)
    terminal.require(requested<=chosen.keys(),'Unknown shared-context input')
    terminal.require(all(chosen[p]['mode']&0o6000 for p in requested),'Shared exception is for privileged inputs only')
    rows=[r for p,r in chosen.items() if p not in requested]
    terminal.require(all(not r['mode']&0o6000 for r in rows),'Privileged input mode is not supported')
    terminal.require(0<len(rows)<=1024 and sum(r['bytes'] for r in rows)<=MAX_BYTES,'Corpus bounds exceeded')
    return sorted(rows,key=lambda r:r['resolved_path'])


def identity(info):return (info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns)


def copy_inputs(area,rows):
    copied=[];(area/'corpus').mkdir(mode=0o700)
    for row in rows:
        source=Path(row['resolved_path']);target=area/'corpus'/source.relative_to('/')
        terminal.require(source.resolve(strict=True)==source,'Canonical source changed')
        target.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        src=os.open(source,os.O_RDONLY|os.O_NOFOLLOW)
        try:
            before=os.fstat(src)
            terminal.require(stat.S_ISREG(before.st_mode) and identity(before)==tuple(row[k] for k in
                ('device','inode','bytes','mtime_ns','ctime_ns')),'Source identity changed since audit')
            try:cap=os.getxattr(source,'security.capability')
            except OSError as exc:
                if exc.errno!=61:raise
                cap=b''
            terminal.require(not cap,'Capability-bearing input is unsupported')
            out=os.open(target,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            try:
                position=0
                while position<before.st_size:
                    block=os.pread(src,min(2**20,before.st_size-position),position)
                    terminal.require(block,'Source truncated')
                    offset=0
                    while offset<len(block):offset+=os.write(out,block[offset:])
                    position+=len(block)
                os.fchmod(out,row['mode']&0o777);os.utime(out,ns=(before.st_atime_ns,before.st_mtime_ns));os.fsync(out)
                current=os.fstat(out)
                spans=q.native.repack.extents(out,current.st_size) if current.st_size else []
                terminal.require(not any(flags&0x2000 for _,_,flags in spans),'Copied extents are shared')
                terminal.require((current.st_dev,current.st_ino)!=(before.st_dev,before.st_ino),'Copy aliases original inode')
            finally:os.close(out)
            terminal.require(identity(os.fstat(src))==identity(before),'Source changed while copying')
            terminal.require(terminal.digest(target)==row['sha256'],'Copied content mismatch')
            copied.append(dict(target=str(source),copy=str(target),device=current.st_dev,inode=current.st_ino,
                bytes=current.st_size,sha256=row['sha256'],shared_extents=0,
                encoded_extents=sum(bool(flags&8) for _,_,flags in spans)))
        finally:os.close(src)
    terminal.save(area/'bindings-private.json',copied)
    return copied


def verify_process_bindings(pid,rows,parent_mount):
    root=Path('/proc')/str(pid)/'root'
    terminal.require(os.readlink(f'/proc/{pid}/ns/mnt')!=parent_mount,'Mount namespace not isolated')
    for row in rows:
        path=root/Path(row['target']).relative_to('/')
        info=path.stat()
        terminal.require((info.st_dev,info.st_ino,info.st_size)==(row['device'],row['inode'],row['bytes']),
            'Application path does not expose expected copied inode')
        terminal.require(os.statvfs(path).f_flag&os.ST_RDONLY,'Input binding is writable')
    return dict(passed=True,verified_readonly_bindings=len(rows),mount_namespace_different=True,
        verified_from_controller_through_owned_process_root=True)


def cache_state(rows,evict=False):
    entries=[]
    for row in rows:
        resident=q.residency(Path(row['copy']),evict=evict) if row['bytes'] else 0
        rounded=((row['bytes']+4095)//4096)*4096
        entries.append(dict(bytes=row['bytes'],page_rounded_bytes=rounded,resident_bytes=resident))
    return dict(files=len(entries),page_rounded_bytes=sum(r['page_rounded_bytes'] for r in entries),
        resident_bytes=sum(r['resident_bytes'] for r in entries),
        zero_resident_files=sum(r['resident_bytes']==0 for r in entries),
        fully_resident_files=sum(r['resident_bytes']==r['page_rounded_bytes'] for r in entries))


def run(args):
    terminal.require(sys.platform=='linux' and os.geteuid()!=0,'Use desktop user')
    audit=args.audit.absolute();area=args.output.absolute()
    terminal.require(area.parent.resolve(strict=True)==area.parent,'Output parent not canonical')
    info=area.parent.stat();terminal.require(info.st_uid==os.getuid() and not info.st_mode&0o022,'Unsafe output parent')
    reference=json.loads((audit/'result.json').read_text());manifest_path=audit/'input-manifest-private.json'
    terminal.require(reference['passed'] and terminal.digest(manifest_path)==reference['manifest_sha256'],'Invalid audit manifest')
    terminal.require(reference['endpoint_source_sha256']==terminal.digest(Path(terminal.__file__)),'Endpoint source changed')
    rows=select_records(json.loads(manifest_path.read_text()),args.leave_shared_privileged)
    terminal.require(shutil.disk_usage(area.parent).free>=64*2**30+2*sum(r['bytes'] for r in rows),'Free-space floor')
    terminal.require(q.command('findmnt','-n','-o','FSTYPE','--target',area.parent)=='btrfs','Requires Btrfs disposable data')
    area.mkdir(mode=0o700);(area/'bin').mkdir(mode=0o700);(area/'home').mkdir(mode=0o700)
    sources={name:terminal.digest(ROOT/name) for name in ('copied_input_probe.py','application_inputs.py',
        'terminal_endpoint.py','qualify_request_trace.py')}
    copied=copy_inputs(area,rows);parent_mount=os.readlink('/proc/self/ns/mnt')
    bwrap=shutil.which('bwrap');terminal.require(bwrap is not None,'bwrap unavailable')
    command=[bwrap,'--die-with-parent','--new-session','--unshare-user','--uid',str(os.getuid()),'--gid',str(os.getgid()),
        '--ro-bind','/','/','--dev-bind','/dev','/dev','--proc','/proc','--tmpfs','/tmp',
        '--bind',str(area),str(area),'--bind',f'/run/user/{os.getuid()}',f'/run/user/{os.getuid()}']
    for row in copied:command+=['--ro-bind',row['copy'],row['target']]
    command+=['--','/usr/bin/konsole']
    shim=area/'bin/konsole';shim.write_text('#!/usr/bin/python3\nimport os,sys\nos.execv('+repr(bwrap)+','+repr(command)+'+sys.argv[1:])\n');shim.chmod(0o700)
    contract=dict(schema_version=1,mode='partial-copied-usr-cache-qualification',source_sha256=sources,
        audit_result_sha256=terminal.digest(audit/'result.json'),files=len(copied),logical_bytes=sum(r['bytes'] for r in copied),
        max_logical_copy_bytes=MAX_BYTES,free_space_floor_bytes=64*2**30,ordinary_independent_copies=True,
        shared_extent_count=0,copy_modes_and_mtimes_preserved=True,source_ownership_not_preserved=True,
        xattrs_not_preserved=True,complete_os_or_application_baseline=False,complete_application_input_closure=False,
        context='Host /etc/runtime/IPC and unaudited dependencies remain shared; copied file data only',
        explicitly_shared_privileged_input_count=len(set(args.leave_shared_privileged)),
        privileged_helper_functionality_qualified=False,
        original_endpoint_helper_unchanged=True,binding_checks_in_controller_after_ready_timestamp=True,
        performance_result=False,global_page_cache_reset_performed=False,
        original_file_cache_evicted=False,drive_policy_changed=False,stage1_gate_passed=False)
    terminal.save(area/'contract.json',contract)
    env=terminal.desktop_environment();env.update(PATH=str(area/'bin')+':'+env['PATH'],HOME=str(area/'home'))
    original_owned=terminal.owns_descendant;proofs=[];results=[]
    def verify_owned(pid,parent):
        valid=original_owned(pid,parent)
        if valid:proofs.append(verify_process_bindings(pid,copied,parent_mount))
        return valid
    try:
        terminal.owns_descendant=verify_owned
        for index,label in enumerate(('copied-data-cold','copied-data-warm')):
            if index==0:before=cache_state(copied,evict=True);terminal.require(before['resident_bytes']==0,'Copied data not cold')
            else:
                for row in copied:terminal.require(terminal.digest(Path(row['copy']))==row['sha256'],'Copied content changed')
                before=cache_state(copied);terminal.require(before['fully_resident_files']==len(copied),'Copied set not fully warm')
            row=terminal.trial(area,index,env,20,0.)
            after=cache_state(copied)
            terminal.require(len(proofs)==index+1,'Unexpected marker ownership checks')
            proof=proofs[-1]
            terminal.require(proof['passed'] and proof['verified_readonly_bindings']==len(copied),'Binding proof missing')
            terminal.require(row['normal_close_verified'] and row['cpu_policy_unchanged'],'Endpoint or policy failed')
            results.append(dict(condition=label,before=before,after=after,endpoint_passed=True,
                normal_close_verified=True,readonly_bindings_verified=len(copied)))
            print(json.dumps(results[-1]),flush=True)
    finally:terminal.owns_descendant=original_owned;terminal.save(area/'completed-conditions.json',results)
    for row in copied:terminal.require(terminal.digest(Path(row['copy']))==row['sha256'],'Final copied content changed')
    for row in rows:
        terminal.require(terminal.digest(Path(row['resolved_path']))==row['sha256'],'Original source content changed')
    terminal.require(all(terminal.digest(ROOT/name)==value for name,value in sources.items()),'Probe source changed')
    terminal.require(os.readlink('/proc/self/ns/mnt')==parent_mount,'Parent mount namespace changed')
    terminal.save(area/'result.json',dict(contract,passed=True,conditions=results,copied_and_source_content_unchanged=True,
        parent_mount_namespace_unchanged=True,completed_unix=time.time()))


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('step',choices=('run',))
    parser.add_argument('--audit',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--leave-shared-privileged',action='append',default=[],
        help='Explicitly retain a privileged /usr input as host context; never copy or strip its mode')
    run(parser.parse_args())


if __name__=='__main__':main()
