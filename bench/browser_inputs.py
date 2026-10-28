#!/usr/bin/env python3
"""Separate Firefox pathname/mapping audit with repeatable private profile seeds.

Uses the unchanged functional endpoint. Traced runs are not timing evidence.
Raw paths, process IDs, maps, logs and content hashes remain private.
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
import uuid

import application_inputs as inputs
import browser_endpoint as browser
import terminal_endpoint as terminal

ROOT=Path(__file__).resolve().parent
TRACE_BYTES=64*2**20
TRACE_FILES=1024
INPUT_BYTES=1024*2**20


def seed_manifest(home):
    """Record relative seed state; never follow symlinks in a generated profile."""
    rows={}
    for path in [home,*sorted(home.rglob('*'))]:
        info=path.lstat();terminal.require(not path.is_symlink(),'Symlink in initial private profile')
        row=dict(mode=stat.S_IMODE(info.st_mode),uid=info.st_uid,gid=info.st_gid)
        if stat.S_ISDIR(info.st_mode):row['kind']='directory'
        else:
            terminal.require(stat.S_ISREG(info.st_mode) and info.st_size<=2**20,'Unexpected initial profile node')
            row.update(kind='file',bytes=info.st_size,sha256=terminal.digest(path))
        rows[str(path.relative_to(home))]=row
    expected={'.','profile','config','data','cache','profile/user.js'}
    terminal.require(set(rows)==expected,'Private profile seed has unexpected inputs')
    expected_text=''.join('user_pref('+json.dumps(k)+','+json.dumps(v)+');\n' for k,v in browser.PREFS.items())
    terminal.require((home/'profile/user.js').read_bytes()==expected_text.encode(),'Private preference seed changed')
    return rows


def trace_inventory(area):
    files=sorted(area.glob('trace-*-private.*'))
    terminal.require(len(files)<=TRACE_FILES,'Trace file count limit')
    total=0
    for path in files:
        info=path.lstat();terminal.require(stat.S_ISREG(info.st_mode) and info.st_uid==os.getuid(),'Unowned trace output')
        total+=info.st_size
    terminal.require(total<=TRACE_BYTES,'Aggregate trace size limit')
    return files,total


def launch(args):
    area=args.output.absolute();arguments=args.arguments
    if arguments[:1]==['--']:arguments=arguments[1:]
    # The unchanged endpoint asks for a version before constructing a trial.
    if arguments==['--full-version']:os.execv('/usr/bin/firefox',['/usr/bin/firefox',*arguments])
    home=Path(os.environ['HOME']);relative=home.relative_to(area/'endpoint')
    terminal.require(len(relative.parts)==2 and relative.parts[1]=='home' and
        re.fullmatch('trial-0[01]',relative.parts[0]),'Unexpected profile seed location')
    terminal.require(home.resolve(strict=True)==home,'Noncanonical private profile')
    seed=seed_manifest(home);index=relative.parts[0][-2:]
    terminal.save(area/f'seed-{index}-private.json',seed)
    os.chdir(home)
    command=['/usr/bin/strace','--follow-forks','--output-separately','--decode-fds=path',
        '--string-limit=4096','--trace=%file,mmap','--interruptible=2','--kill-on-exit',
        '--output='+str(area/f'trace-{index}-private'),'--','/usr/bin/firefox',*arguments]
    os.execv(command[0],command)


def capture_owned(group,supervisor):
    mapped=set();roles=[];unreadable=0;main=[]
    for pid in sorted(browser.members(group)-{os.getpid(),supervisor.pid}):
        try:
            # Cgroup membership, not a global process-name match, defines scope.
            status=Path('/proc',str(pid),'status').read_text()
            uid=int(re.search(r'^Uid:\s+(\d+)',status,re.M).group(1))
            terminal.require(uid==os.getuid(),'Unexpected audit process owner')
            exe=os.readlink(f'/proc/{pid}/exe')
            if pid not in browser.members(group):continue
            roles.append(exe)
            if exe=='/usr/lib/firefox/firefox' and int(re.search(r'^PPid:\s+(\d+)',status,re.M).group(1))==supervisor.pid:
                caps=[line.split()[1] for line in status.splitlines() if line.startswith(('CapEff:','CapPrm:','CapAmb:'))]
                terminal.require(len(caps)==3 and all(int(n,16)==0 for n in caps),'Actual browser main retains capabilities')
                main.append(pid)
            mapped.add(exe)
            for line in Path('/proc',str(pid),'maps').read_text().splitlines():
                fields=line.split(maxsplit=5)
                if len(fields)==6 and fields[5].startswith('/') and not fields[5].endswith(' (deleted)'):mapped.add(fields[5])
        except (FileNotFoundError,ProcessLookupError):continue
        except PermissionError:unreadable+=1
    terminal.require(len(main)==1,'Actual Firefox main process not identified in owned group')
    return dict(mapped_paths=sorted(mapped),process_executables=roles,unreadable_process_snapshots=unreadable,
        actual_browser_main_verified=True,actual_browser_main_capabilities_zero=True)


def capture_then_cleanup(proc,group,ready,snapshots,errors,area,cleanup):
    """Never replace an endpoint failure with an optional audit-capture error."""
    try:
        if proc is not None and proc.poll() is None and ready:
            snapshot=capture_owned(group,proc)
            terminal.save(area/f'process-snapshot-{len(snapshots)+1:02}-private.json',snapshot)
            snapshots.append(snapshot)
    except Exception as exc:
        errors.append(str(exc))
        terminal.save(area/f'capture-error-{len(errors):02}-private.json',dict(error=str(exc)))
    return cleanup(proc,group)


def host(args):
    area=args.output.absolute();terminal.require(os.geteuid()!=0,'Use the desktop user')
    terminal.require(area.parent.resolve(strict=True)==area.parent,'Parent must be canonical')
    info=area.parent.stat();terminal.require(info.st_uid==os.getuid() and not info.st_mode&0o022,'Unsafe output parent')
    terminal.require(shutil.disk_usage(area.parent).free>=64*2**30,'Host free-space floor')
    terminal.require(Path('/usr/bin/strace').is_file(),'strace unavailable')
    area.mkdir(mode=0o700);(area/'bin').mkdir(mode=0o700)
    names=('browser_inputs.py','application_inputs.py','browser_endpoint.py','terminal_endpoint.py','browser-ready.html','browser-ready.svg')
    sources={name:terminal.digest(ROOT/name) for name in names}
    shim=area/'bin/firefox';shim.write_text('#!/usr/bin/python3\nimport os,sys\nos.execv('+repr(sys.executable)+','+
        repr([sys.executable,str(Path(__file__).resolve()),'_launch','--output',str(area),'--'])+'+sys.argv[1:])\n');shim.chmod(0o700)
    contract=dict(schema_version=1,source_sha256=sources,workload='firefox-private-input-audit-v1',
        trace_read_write_payloads=False,strace_version=subprocess.check_output(['/usr/bin/strace','--version'],text=True).splitlines()[0],
        max_aggregate_trace_bytes=TRACE_BYTES,max_trace_files=TRACE_FILES,max_input_paths=8192,
        max_unique_regular_input_bytes=INPUT_BYTES,private_profile_seed_only=True,
        performance_result=False,complete_application_input_closure=False,stage1_gate_passed=False)
    terminal.save(area/'contract.json',contract)
    old_env=dict(os.environ);old_server=browser.HTTPServer;old_cleanup=browser.cleanup;snapshots=[];marker_seen=[];capture_errors=[]
    class BoundedServer(old_server):
        def handle_request(self):
            trace_inventory(area)
            result=super().handle_request()
            if self.marker is not None:marker_seen.append(True)
            return result
    def audited_cleanup(proc,group):
        return capture_then_cleanup(proc,group,len(marker_seen)>len(snapshots),snapshots,capture_errors,area,old_cleanup)
    try:
        os.environ['PATH']=str(area/'bin')+':/usr/bin';os.chdir(area)
        browser.HTTPServer=BoundedServer;browser.cleanup=audited_cleanup
        browser.host(argparse.Namespace(output=area/'endpoint',parent_net=args.parent_net,trials=2,hold_seconds=0.))
    finally:
        browser.HTTPServer=old_server;browser.cleanup=old_cleanup;os.environ.clear();os.environ.update(old_env)
    files,total=trace_inventory(area);terminal.require(not capture_errors,'Browser audit capture failed: '+str(capture_errors))
    terminal.require(files and len(snapshots)==2,'Missing browser audit captures')
    seeds=[json.loads((area/f'seed-{index:02}-private.json').read_text()) for index in range(2)]
    terminal.require(seeds[0]==seeds[1],'Fresh private profile seeds differ')
    paths={path for snapshot in snapshots for path in snapshot['mapped_paths']};unresolved=0
    for path in files:
        found,count=inputs.annotated_paths(path.read_text());paths.update(found);unresolved+=count
    terminal.require(len(paths)<=8192,'Input path count limit')
    # Bound unique regular-file hashing before reading the observed source set.
    unique={}
    for path in sorted(paths):
        if inputs.kind(Path(path),area) not in ('system_usr','system_etc_context'):continue
        try:
            resolved=Path(path).resolve(strict=True);info=resolved.stat()
            if stat.S_ISREG(info.st_mode):unique[str(resolved)]=info.st_size
        except OSError:pass
    terminal.require(sum(unique.values())<=INPUT_BYTES,'Unique input hashing bound')
    records=[inputs.file_record(Path(path),area) for path in sorted(paths)]
    terminal.save(area/'input-manifest-private.json',dict(records=records,snapshots=snapshots))
    unique={r['resolved_path']:r for r in records if r.get('regular_file')}
    usr=[r for r in unique.values() if r['category']=='system_usr'];etc=[r for r in unique.values() if r['category']=='system_etc_context']
    terminal.require('/usr/lib/firefox/firefox' in unique and '/usr/bin/firefox' in unique,'Firefox executable or launcher absent')
    terminal.require(all(terminal.digest(ROOT/name)==digest for name,digest in sources.items()),'Audit source changed')
    endpoint=json.loads((area/'endpoint/result.json').read_text())
    result=dict(contract,passed=True,kernel=os.uname().release,trace_files=len(files),trace_bytes=total,
        observed_path_count=len(paths),path_categories={category:sum(r['category']==category for r in records)
            for category in sorted({r['category'] for r in records})},
        unique_regular_usr_files=len(usr),usr_logical_bytes=sum(r['bytes'] for r in usr),
        unique_regular_etc_files=len(etc),etc_logical_bytes=sum(r['bytes'] for r in etc),
        manifest_sha256=terminal.digest(area/'input-manifest-private.json'),unresolved_escaped_or_deleted_annotations=unresolved,
        unreadable_process_snapshots=sum(s['unreadable_process_snapshots'] for s in snapshots),actual_browser_main_verified_trials=2,
        private_seed_identical=True,seed_manifest_sha256=hashlib.sha256(json.dumps(seeds[0],sort_keys=True).encode()).hexdigest(),
        seed_nodes=len(seeds[0]),functional_endpoint_trials=endpoint['completed_trials'],
        all_owned_browser_processes_gone=endpoint['all_owned_browser_processes_gone'],
        forced_cleanup_required=any(r['forced_cleanup_required'] for r in endpoint['trials']),
        network_namespace_isolated=endpoint['network_namespace_isolated'],network=endpoint['network'],
        cleanup_uses_ptrace_exitkill=True,normal_quit_qualified=False,profile_durability_qualified=False,
        source_files_modified=False,cache_eviction_performed=False,cache_state_qualified=False,
        namespace_aware_file_identity_qualified=False,host_resolvable_candidates_only=True,
        trace_size_limit_is_sampled_not_filesystem_quota=True,
        directory_enumeration_qualified=False,failed_path_dependencies_frozen=False,ipc_inputs_frozen=False,completed_unix=time.time())
    terminal.save(area/'result.json',result);print(json.dumps(result),flush=True)


def main():
    parser=argparse.ArgumentParser(description=__doc__);steps=parser.add_subparsers(dest='step',required=True)
    for name in ('audit','_host','_launch'):
        step=steps.add_parser(name);step.add_argument('--output',type=Path,required=True)
        if name=='_host':step.add_argument('--parent-net',required=True)
        if name=='_launch':step.add_argument('arguments',nargs=argparse.REMAINDER)
    args=parser.parse_args()
    terminal.require(sys.platform=='linux' and os.geteuid()!=0,'Linux desktop user required')
    if args.step=='_launch':launch(args);return
    if args.step=='_host':host(args);return
    before=os.readlink('/proc/self/ns/net');unit='bc250-browser-endpoint-audit-'+uuid.uuid4().hex[:12]
    env=terminal.desktop_environment();print(json.dumps(dict(parent_unit=unit)),flush=True)
    subprocess.run(['systemd-run','--user','--quiet','--wait','--pipe','--collect','--unit='+unit,
        '--property=MemoryMax=3G','--property=MemorySwapMax=0','--property=TasksMax=512',
        '--property=RuntimeMaxSec=180','--property=KillMode=control-group','--property=TimeoutStopSec=15',
        '/usr/bin/unshare','--user','--map-current-user','--net','--keep-caps','/usr/bin/python3',str(Path(__file__).resolve()),
        '_host','--output',str(args.output),'--parent-net',before],env=env,check=True,timeout=210)
    terminal.require(os.readlink('/proc/self/ns/net')==before,'Parent network namespace changed')


if __name__=='__main__':main()
