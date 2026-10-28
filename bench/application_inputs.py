#!/usr/bin/env python3
"""Audit Konsole startup file inputs in a separate, instrumented private launch.

strace records pathname syscalls/mappings, not read/write payloads. Raw logs and
the full path/hash manifest stay private. This is not performance evidence or a
claim that IPC, directory entries and failed-path dependencies are frozen.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import time

import terminal_endpoint as terminal


def annotated_paths(text):
    """Conservative successful FD paths; mapped-process inventory supplements exec."""
    paths=set();unresolved=0
    for line in text.splitlines():
        if ' = -1 ' in line or '<unfinished ...>' in line:continue
        for value in re.findall(r'<(/[^<>]*)>',line):
            if '\\' in value or value.endswith(' (deleted)'):unresolved+=1;continue
            paths.add(value)
        # exec loads its executable/interpreter without an ordinary open call.
        match=re.search(r'\bexecve\("([^"\\]+)".*\)\s*=\s*0\s*$',line)
        if match and match[1].startswith('/'):paths.add(match[1])
    return paths,unresolved


def kind(path,area):
    if path.is_relative_to(area):return 'private_generated_fixture'
    if path.is_relative_to(Path('/usr')):return 'system_usr'
    if path.is_relative_to(Path('/etc')):return 'system_etc_context'
    if any(path.is_relative_to(Path(p)) for p in ('/proc','/sys','/dev','/run','/tmp')):return 'runtime_or_kernel_context'
    return 'outside_approved_input_roots'


def file_record(path,area):
    category=kind(path,area)
    if category not in ('system_usr','system_etc_context'):return dict(path=str(path),category=category)
    try:
        resolved=path.resolve(strict=True);info=resolved.stat()
    except OSError:return dict(path=str(path),category=category,regular_file=False,unavailable=True)
    if not stat.S_ISREG(info.st_mode):return dict(path=str(path),category=category,regular_file=False)
    fd=os.open(resolved,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        before=os.fstat(fd);digest=hashlib.sha256()
        terminal.require(before.st_size<=256*2**20,'Single audited input exceeds 256 MiB')
        with os.fdopen(os.dup(fd),'rb') as stream:
            while block:=stream.read(2**20):digest.update(block)
        after=os.fstat(fd)
        terminal.require((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==
            (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns),'Input changed while hashing')
        return dict(path=str(path),resolved_path=str(resolved),category=category,regular_file=True,
            bytes=before.st_size,sha256=digest.hexdigest(),device=before.st_dev,inode=before.st_ino,
            mtime_ns=before.st_mtime_ns,ctime_ns=before.st_ctime_ns,mode=stat.S_IMODE(before.st_mode),
            uid=before.st_uid,gid=before.st_gid,nlink=before.st_nlink)
    finally:os.close(fd)


def audit(args):
    terminal.require(sys.platform=='linux' and os.geteuid()!=0,'Use the desktop user')
    area=args.output.absolute();terminal.require(area.parent.resolve(strict=True)==area.parent,'Parent not canonical')
    info=area.parent.stat();terminal.require(info.st_uid==os.getuid() and not info.st_mode&0o022,'Unsafe output parent')
    strace=Path(shutil.which('strace') or '');konsole=Path(shutil.which('konsole') or '')
    terminal.require(strace.is_file() and konsole.is_file(),'strace/Konsole unavailable')
    area.mkdir(mode=0o700);(area/'bin').mkdir(mode=0o700);(area/'home').mkdir(mode=0o700)
    source_sha=terminal.digest(Path(__file__));endpoint_sha=terminal.digest(Path(terminal.__file__))
    command=[str(strace),'--follow-forks','--output-separately','--decode-fds=path','--string-limit=4096',
        '--trace=%file,mmap','--output='+str(area/'trace-private'),'--',str(konsole)]
    shim=area/'bin/konsole'
    shim.write_text('#!/usr/bin/python3\nimport os,sys\nos.execv('+repr(str(strace))+','+repr(command)+'+sys.argv[1:])\n')
    shim.chmod(0o700)
    old_env=dict(os.environ);original=terminal.owns_descendant;mapped=set();process_roles=[]
    def inspect_owned(pid,parent):
        valid=original(pid,parent)
        if valid:
            for _ in range(32):
                if pid==parent:break # Do not include the strace supervisor itself.
                text=Path('/proc',str(pid),'status').read_text()
                exe=os.readlink(f'/proc/{pid}/exe');process_roles.append(exe)
                for line in Path('/proc',str(pid),'maps').read_text().splitlines():
                    fields=line.split(maxsplit=5)
                    if len(fields)==6 and fields[5].startswith('/') and not fields[5].endswith(' (deleted)'):
                        mapped.add(fields[5])
                mapped.add(exe);pid=int(re.search(r'^PPid:\s+(\d+)',text,re.M).group(1))
        return valid
    contract=dict(schema_version=1,mode='ptrace-file-inventory-only',source_sha256=source_sha,
        endpoint_source_sha256=endpoint_sha,strace_version=subprocess.check_output([str(strace),'--version'],text=True).splitlines()[0],
        real_konsole_sha256=terminal.digest(konsole.resolve()),trace_read_write_payloads=False,
        private_home=True,performance_result=False,max_aggregate_trace_bytes=64*2**20,max_input_paths=4096)
    terminal.save(area/'contract.json',contract)
    try:
        os.environ['PATH']=str(area/'bin')+':'+old_env.get('PATH','/usr/bin')
        os.environ['HOME']=str(area/'home');terminal.owns_descendant=inspect_owned
        terminal.run(argparse.Namespace(output=area/'endpoint',trials=1,hold_seconds=0.))
    finally:
        terminal.owns_descendant=original;os.environ.clear();os.environ.update(old_env)
    paths=set(mapped);trace_files=sorted(area.glob('trace-private.*'))
    terminal.require(0<len(trace_files)<=512,'Unexpected trace process/file count')
    total=sum(p.stat().st_size for p in trace_files);terminal.require(total<=contract['max_aggregate_trace_bytes'],'Trace size limit')
    unresolved=0
    for path in trace_files:
        found,count=annotated_paths(path.read_text());paths.update(found);unresolved+=count
    terminal.require(len(paths)<=contract['max_input_paths'],'Input path count limit')
    records=[file_record(Path(p),area) for p in sorted(paths)]
    terminal.save(area/'input-manifest-private.json',dict(records=records,mapped_paths=sorted(mapped),process_roles=process_roles))
    unique={r['resolved_path']:r for r in records if r.get('regular_file')}
    usr=[r for r in unique.values() if r['category']=='system_usr'];etc=[r for r in unique.values() if r['category']=='system_etc_context']
    counts={category:sum(r['category']==category for r in records) for category in sorted({r['category'] for r in records})}
    terminal.require(str(konsole.resolve()) in {r['resolved_path'] for r in usr},'Real Konsole missing from inventory')
    terminal.require(terminal.digest(Path(__file__))==source_sha and terminal.digest(Path(terminal.__file__))==endpoint_sha,'Source changed')
    result=dict(contract,passed=True,kernel=os.uname().release,trace_files=len(trace_files),trace_bytes=total,
        observed_path_count=len(paths),path_categories=counts,unique_regular_usr_files=len(usr),usr_logical_bytes=sum(r['bytes'] for r in usr),
        unique_regular_etc_files=len(etc),etc_logical_bytes=sum(r['bytes'] for r in etc),
        manifest_sha256=terminal.digest(area/'input-manifest-private.json'),unresolved_escaped_or_deleted_annotations=unresolved,
        source_files_modified=False,cache_eviction_performed=False,complete_application_input_closure=False,
        directory_enumeration_qualified=False,failed_path_dependencies_frozen=False,ipc_inputs_frozen=False,
        stage1_gate_passed=False,completed_unix=time.time())
    terminal.save(area/'result.json',result);print(json.dumps(result),flush=True)


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('step',choices=('audit',))
    parser.add_argument('--output',type=Path,required=True);args=parser.parse_args();audit(args)


if __name__=='__main__':main()
