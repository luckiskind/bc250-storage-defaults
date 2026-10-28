#!/usr/bin/env python3
"""Signed offline tzdata update in a new native loop-backed Btrfs lab volume.

Only a new regular image is formatted. Host packages/database, protected seed
and original caches stay unchanged. Initial endpoint/reset checks, not speed.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path,PurePosixPath
import shutil
import socket
import stat
import subprocess
import sys
import tarfile
import time
import uuid

ROOT=Path(__file__).resolve().parents[1]
PAYLOAD_LIMIT=64*2**20
META={'.PKGINFO','.BUILDINFO','.MTREE'}


def require(value,message):
    if not value:raise RuntimeError(message)


def digest(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def save(path,value):
    with path.open('x') as stream:json.dump(value,stream,indent=2);stream.write('\n')


def command(*args,check=True):
    value=subprocess.run(list(map(str,args)),capture_output=True,text=True,timeout=90)
    if check and value.returncode:raise RuntimeError('Command failed: '+str(args[0])+'\n'+value.stdout[-4000:]+value.stderr[-4000:])
    return value


def package(path):
    require(path.stat().st_size<=64*2**20,'Archive size bound');nodes={};total=0;info={}
    with tarfile.open(path) as archive:
        for member in archive:
            name=PurePosixPath(member.name)
            require(not name.is_absolute() and '..' not in name.parts and str(name)==member.name,'Unsafe package path')
            require(member.name not in nodes and len(nodes)<10000,'Repeated/excessive package nodes')
            require(member.isfile() or member.isdir() or member.issym() or member.islnk(),'Special package node')
            require(member.name!='.INSTALL','Fixture requires a package without an install script')
            row=dict(mode=member.mode,uid=member.uid,gid=member.gid)
            if member.isfile():
                total+=member.size;require(total<=PAYLOAD_LIMIT,'Payload byte bound')
                stream=archive.extractfile(member);require(stream is not None,'Missing package member')
                value=hashlib.file_digest(stream,'sha256').hexdigest()
                row.update(kind='file',bytes=member.size,sha256=value)
                if member.name=='.PKGINFO':
                    stream=archive.extractfile(member);require(member.size<=65536,'Package metadata bound')
                    for line in stream.read().decode().splitlines():
                        key,sep,value=line.partition(' = ')
                        if sep:info.setdefault(key,[]).append(value)
            elif member.isdir():row['kind']='directory'
            else:
                row.update(kind='symlink' if member.issym() else 'hardlink',target=member.linkname)
                if member.islnk():require(not PurePosixPath(member.linkname).is_absolute() and '..' not in PurePosixPath(member.linkname).parts,'Unsafe hardlink')
            nodes[member.name]=row
    require(info.get('pkgname')==['tzdata'] and len(info.get('pkgver',[]))==1 and info.get('arch')==['x86_64_v3'],'Unexpected package metadata')
    require(not info.get('depend'),'Fixture package has required dependencies')
    for name,row in nodes.items():
        require(not any(str(p) in nodes and nodes[str(p)]['kind']=='symlink' for p in PurePosixPath(name).parents),'Symlink package ancestor')
        if row['kind']=='hardlink':require(row['target'] in nodes and nodes[row['target']]['kind']=='file','Missing/nonregular hardlink target')
    payload={name:row for name,row in nodes.items() if name not in META}
    require(all(name=='usr' or name.startswith('usr/') for name in payload),'Unexpected payload root')
    require(not any(name.startswith('usr/share/libalpm/hooks/') for name in payload),'Fixture adds transaction hooks')
    return dict(name='tzdata',version=info['pkgver'][0],arch=info['arch'][0],nodes=payload,logical_bytes=sum(r.get('bytes',0) for r in payload.values()),sha256=digest(path))


def verify_payload(expected):
    files=links=0
    for name,row in expected['nodes'].items():
        path=Path('/')/name;info=path.lstat()
        require(stat.S_IMODE(info.st_mode)==row['mode'] and (info.st_uid,info.st_gid)==(row['uid'],row['gid']),'Installed metadata mismatch')
        if row['kind']=='file':
            require(stat.S_ISREG(info.st_mode) and info.st_size==row['bytes'] and digest(path)==row['sha256'],'Installed content mismatch');files+=1
        elif row['kind']=='directory':require(stat.S_ISDIR(info.st_mode),'Installed directory missing')
        elif row['kind']=='symlink':require(stat.S_ISLNK(info.st_mode) and os.readlink(path)==row['target'],'Installed symlink differs');links+=1
        else:
            target=(Path('/')/row['target']).stat();require((info.st_dev,info.st_ino)==(target.st_dev,target.st_ino),'Installed hardlink differs');links+=1
    return dict(regular_files=files,links=links,all_payload_nodes_verified=len(expected['nodes']))


def tree_digest(root):
    rows=[]
    for path in sorted(root.rglob('*')):
        info=path.lstat();require(not path.is_symlink() and (path.is_file() or path.is_dir()),'Unexpected database node')
        rows.append((str(path.relative_to(root)),stat.S_IMODE(info.st_mode),digest(path) if path.is_file() else None))
    return hashlib.sha256(json.dumps(rows).encode()).hexdigest()


def guest(args):
    plan=json.loads(Path('/run/package-plan.json').read_text());state=Path('/run/package-state')
    require(os.geteuid()==0 and Path('/etc/bc250-package-marker').read_text()==plan['nonce'],'Not the dedicated package root')
    for kind in ('mnt','net','pid','user'):
        require(os.readlink('/proc/self/ns/'+kind)!=plan['parent_namespaces'][kind],'Missing namespace isolation: '+kind)
    require([name for _,name in socket.if_nameindex()]==['lo'],'External network interface present')
    require(not Path('/dev/nvme0n1').exists(),'Host physical block device exposed')
    spec=importlib.util.spec_from_file_location('fixture_ownership','/run/fixture-ownership.py');ownership=importlib.util.module_from_spec(spec);spec.loader.exec_module(ownership)
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
    try:actual=ownership.persistent_identity(fd)
    finally:os.close(fd)
    require(actual['fs_uuid']==plan['fs_uuid'],'Wrong dedicated filesystem')
    cfg='/etc/bc250-pacman-fixture.conf';config=Path(cfg).read_text()
    require('LocalFileSigLevel = Required TrustedOnly' in config and 'SigLevel = Required TrustedOnly' in config,'Signature policy changed')
    # The parent authenticates these manifests before setting cache conditions.
    # Reading/hashing the archives here would invalidate the cold-input trial.
    old=plan['old_package'];new=plan['new_package']
    require(old['sha256']==plan['old_sha256'] and new['sha256']==plan['new_sha256'],'Input manifest changed')
    base=['/usr/bin/pacman','--config',cfg]
    transaction=['-U','--noconfirm','--noprogressbar']
    if args.stage=='init':
        update=command(*base,*transaction,'/run/package-inputs/'+plan['old']);(state/'init-pacman-private.log').write_text(update.stdout+update.stderr)
        require(command(*base,'-Q','tzdata').stdout.strip()=='tzdata '+old['version'],'Old version not installed')
        verify_payload(old);command(*base,'-Qkk','tzdata');command(*base,'-Dk');command('/usr/bin/sync','-f','/')
        save(state/'result.json',dict(passed=True,old_version=old['version'],database_sha256=tree_digest(Path('/var/lib/pacman/local'))));return
    before=tree_digest(Path('/var/lib/pacman/local'));require(before==plan['base_database_sha256'],'Reset database differs')
    verify_payload(old)
    if args.stage=='reject':
        rejected=command(*base,*transaction,'/run/package-inputs/signature-mismatch.pkg.tar.zst',check=False)
        (state/'signature-rejection-private.log').write_text(rejected.stdout+rejected.stderr)
        require(rejected.returncode!=0 and 'PGP signature' in rejected.stdout+rejected.stderr,'Mismatched signature was not rejected')
        require(tree_digest(Path('/var/lib/pacman/local'))==before,'Rejected package changed database');verify_payload(old)
        save(state/'result.json',dict(passed=True,invalid_signature_rejected=True,database_unchanged=True,payload_unchanged=True));return
    started=time.monotonic_ns();update=command(*base,*transaction,'/run/package-inputs/'+plan['new']);returned=time.monotonic_ns()
    (state/'update-pacman-private.log').write_text(update.stdout+update.stderr)
    require('error:' not in (update.stdout+update.stderr).lower(),'Transaction reported an error')
    require(command(*base,'-Q','tzdata').stdout.strip()=='tzdata '+new['version'],'New version missing')
    check=command(*base,'-Qkk','tzdata');(state/'package-check-private.log').write_text(check.stdout+check.stderr)
    command(*base,'-Dk');verified=verify_payload(new)
    removed=[name for name,row in old['nodes'].items() if row['kind']!='directory' and name not in new['nodes']]
    require(all(not os.path.lexists('/'+name) for name in removed),'Obsolete payload remains')
    changed=[name for name,row in new['nodes'].items() if row['kind']=='file' and name in old['nodes']
        and row.get('sha256')!=old['nodes'][name].get('sha256')];require(changed,'Package payload did not change')
    timezone=command('/usr/bin/zdump','-v','-c','2026,2027','Europe/London')
    require('BST' in timezone.stdout and 'GMT' in timezone.stdout,'Updated timezone data not usable')
    command('/usr/bin/sync','-f','/');finished=time.monotonic_ns()
    require(started<returned<finished,'Transaction marker clock order invalid')
    save(state/'result.json',dict(passed=True,old_version=old['version'],new_version=new['version'],
        version_verified=True,package_full_check_passed=True,local_database_check_passed=True,**verified,
        removed_paths_verified=len(removed),changed_regular_files_verified=len(changed),timezone_query_passed=True,guest_syncfs_returned=True,
        start_monotonic_ns=started,transaction_return_monotonic_ns=returned,verified_endpoint_monotonic_ns=finished,
        transaction_elapsed_ns=returned-started,total_verified_elapsed_ns=finished-started,performance_result=False))


def build(args):
    sys.path.insert(0,str(ROOT/'tools'));sys.path.insert(0,str(ROOT/'bench'))
    import native_volume_lab as native
    import copied_input_probe as copied
    native.confined();area=args.output.absolute();native.private_area(area,creating=True);native.host_space(area.parent)
    seed_area=args.seed.absolute();report=json.loads((seed_area/'result.json').read_text());archive=seed_area/'seed-private.tar'
    require(report['passed'] and digest(archive)==report['seed_archive_sha256'],'Protected seed archive changed')
    old=package(args.old);new=package(args.new);require(old['arch']==new['arch'],'Package architectures differ')
    require(int(command('/usr/bin/vercmp',old['version'],new['version']).stdout)<0,'Expected ordered package versions')
    area.mkdir(mode=0o700);inputs=area/'inputs';inputs.mkdir(mode=0o700)
    with tarfile.open(archive) as stream:id_base=stream.getmember('usr').uid
    require(id_base>65535 and id_base%65536==0,'Expected prepared shifted native seed')
    for source in (args.old,args.new,Path(str(args.old)+'.sig'),Path(str(args.new)+'.sig')):
        require(source.resolve(strict=True)==source and source.is_file() and source.stat().st_size<=64*2**20,'Unsafe archive/signature source')
        target=inputs/source.name;shutil.copyfile(source,target);require(digest(source)==digest(target),'Input copy differs')
        os.chown(target,id_base,id_base);target.chmod(0o400)
    shutil.copyfile(inputs/args.old.name,inputs/'signature-mismatch.pkg.tar.zst')
    shutil.copyfile(inputs/(args.new.name+'.sig'),inputs/'signature-mismatch.pkg.tar.zst.sig')
    for p in inputs.iterdir():os.chown(p,id_base,id_base);p.chmod(0o400)
    for p in inputs.iterdir():
        with p.open('rb') as stream:os.fsync(stream.fileno())
    require(digest(inputs/args.old.name)==old['sha256'] and digest(inputs/args.new.name)==new['sha256'],'Parsed package changed during setup')
    os.chown(inputs,id_base,id_base)
    host_db=native.tree_manifest(Path('/var/lib/pacman'),0)['sha256']
    host_payload=native.tree_manifest(Path('/usr/share/zoneinfo'),0)['sha256']
    host_log=digest(Path('/var/log/pacman.log'))
    image=native.new_image(area,'package');point=area/'mount';point.mkdir();mounted=False
    plan=dict(nonce=uuid.uuid4().hex,old=args.old.name,new=args.new.name,old_sha256=old['sha256'],new_sha256=new['sha256'],old_package=old,new_package=new,
        parent_namespaces={name:os.readlink('/proc/self/ns/'+name) for name in ('mnt','net','pid','user')})
    sources={name:digest(ROOT/name) for name in ('bench/package_update.py','tools/native_volume_lab.py','install_transaction.py',
        'bench/copied_input_probe.py','bench/qualify_request_trace.py')}
    try:
        command('mount','-o','loop,compress=zstd:1,noatime,nosuid,nodev',image,point);mounted=True
        fs_uuid=command('findmnt','-n','-o','UUID','--target',point).stdout.strip()
        require(fs_uuid!=command('findmnt','-n','-o','UUID','--target',area).stdout.strip(),'Disposable filesystem matches host')
        plan['fs_uuid']=uuid.UUID(fs_uuid).hex
        base=point/'base';command('btrfs','subvolume','create',base);native.populate(archive,base,id_base,uuid.uuid4().hex)
        keyring=base/'etc/bc250-fixture-keyring';keyring.mkdir(mode=0o700);os.chown(keyring,id_base,id_base)
        for name in ('pubring.gpg','trustdb.gpg'):
            shutil.copyfile(Path('/etc/pacman.d/gnupg')/name,keyring/name);os.chown(keyring/name,id_base,id_base);(keyring/name).chmod(0o600)
        (keyring/'gpg.conf').write_text('no-auto-key-retrieve\n');os.chown(keyring/'gpg.conf',id_base,id_base)
        config=base/'etc/bc250-pacman-fixture.conf'
        config.write_text('[options]\nArchitecture = '+new['arch']+'\nDBPath = /var/lib/pacman\nCacheDir = /var/cache/pacman/pkg\n'+
            'GPGDir = /etc/bc250-fixture-keyring\nLogFile = /var/log/bc250-package-fixture.log\n'+
            'SigLevel = Required TrustedOnly\nLocalFileSigLevel = Required TrustedOnly\nCheckSpace\n')
        marker=base/'etc/bc250-package-marker';marker.write_text(plan['nonce'])
        for p in (config,marker):os.chown(p,id_base,id_base);p.chmod(0o644)
        contract=dict(schema_version=1,source_sha256=sources,package='tzdata',old_version=old['version'],new_version=new['version'],arch=new['arch'],
            package_archive_hashes=[old['sha256'],new['sha256']],new_payload_bytes=new['logical_bytes'],
            endpoint='Native pacman update return, version/DB/full payload/timezone verification, then guest syncfs',
            order=['archive-data-cold','archive-data-warm','archive-data-cold'],signature_policy='Required TrustedOnly',
            input_archive_bytes=(inputs/args.new.name).stat().st_size,input_signature_bytes=(inputs/(args.new.name+'.sig')).stat().st_size,
            cache_setup_reads_archives_before_conditioning=True,guest_pretransaction_does_not_read_archives=True,
            private_native_volume=True,loop_backed=True,snapshot_reset=True,snapshot_extents_shared=True,
            container_kept_in_bounded_parent_unit=True,parent_memory_max_bytes=2*2**30,parent_swap_max_bytes=0,
            parent_cpu_quota_percent=200,parent_tasks_max=128,parent_lifetime_seconds=360,
            whole_os_cache_state_qualified=False,performance_result=False,stage1_gate_passed=False)
        save(area/'contract.json',contract)
        def execute(root,label,stage):
            state=area/('state-'+label);state.mkdir(mode=0o700);os.chown(state,id_base,id_base)
            cfg=area/('plan-'+label+'.json');save(cfg,plan);cfg.chmod(0o644)
            command_line=['systemd-nspawn','--settings=no','--register=no','--keep-unit','--console=pipe','--machine=bc250-package-'+uuid.uuid4().hex[:10],
                '--directory='+str(root),'--private-users='+str(id_base)+':65536','--private-users-ownership=off',
                '--private-network','--resolv-conf=off','--timezone=off','--link-journal=no','--drop-capability=CAP_NET_ADMIN,CAP_NET_RAW',
                '--rlimit=RLIMIT_CORE=0:infinity',
                '--setenv=LC_ALL=C','--setenv=PYTHONDONTWRITEBYTECODE=1','--bind-ro='+str(inputs)+':/run/package-inputs',
                '--bind-ro='+str(cfg)+':/run/package-plan.json','--bind='+str(state)+':/run/package-state',
                '--bind-ro='+str(ROOT/'install_transaction.py')+':/run/fixture-ownership.py',
                '--bind-ro='+str(Path(__file__).resolve())+':/run/package-update.py','/usr/bin/python3','-B','/run/package-update.py','_guest','--stage',stage]
            run=subprocess.run(command_line,capture_output=True,text=True,timeout=120);(area/(label+'-container-private.log')).write_text(run.stdout+run.stderr)
            require(run.returncode==0,'Native container failed: '+label+'\n'+(run.stdout+run.stderr)[-4000:])
            value=json.loads((state/'result.json').read_text());require(value['passed'],'Native transaction endpoint failed');return value
        initial=execute(base,'initialize','init');plan['base_database_sha256']=initial['database_sha256']
        command('btrfs','property','set','-ts',base,'ro','true')
        bad=point/'signature-rejection';command('btrfs','subvolume','snapshot',base,bad);negative=execute(bad,'signature-rejection','reject')
        trials=[];cache_rows=[dict(copy=str(inputs/name),bytes=(inputs/name).stat().st_size) for name in (args.new.name,args.new.name+'.sig')]
        for index,label in enumerate(contract['order']):
            root=point/f'trial-{index:02}';command('btrfs','subvolume','snapshot',base,root)
            if label.endswith('warm'):
                for row in cache_rows:digest(Path(row['copy']))
            before=copied.cache_state(cache_rows,evict=label.endswith('cold'))
            require(before['resident_bytes']==(before['page_rounded_bytes'] if label.endswith('warm') else 0),'Package input cache condition failed')
            trial=execute(root,f'trial-{index:02}','update');trial.update(condition=label,input_cache_before=before,input_cache_after=copied.cache_state(cache_rows))
            trials.append(trial);print(json.dumps(dict(trial=index,passed=trial['passed'],condition=label)),flush=True)
        require(native.tree_manifest(Path('/var/lib/pacman'),0)['sha256']==host_db,'Host package database changed')
        require(native.tree_manifest(Path('/usr/share/zoneinfo'),0)['sha256']==host_payload and digest(Path('/var/log/pacman.log'))==host_log,'Host package payload/log changed')
        require(digest(archive)==report['seed_archive_sha256'] and all(digest(ROOT/name)==sha for name,sha in sources.items()),'Seed/source changed')
        for source in (args.old,args.new):require(digest(source)==digest(inputs/source.name),'Original package/cache copy changed')
        result=dict(contract,passed=True,native_kernel=os.uname().release,completed_trials=len(trials),trials=trials,
            invalid_signature_control=negative,host_database_payload_log_unchanged=True,protected_seed_archive_unchanged=True,
            host_secret_key_material_copied=False,public_verification_store_copied_private=True,physical_device_formatted=False,
            image_virtual_bytes=native.SIZE,sparse_capacity_is_not_host_space_reservation=True,completed_unix=time.time())
        save(area/'result.json',result)
    finally:
        if mounted:command('umount',point)
    image.chmod(0o400);native.host_space(area.parent);print(json.dumps(result),flush=True)


def main():
    parser=argparse.ArgumentParser(description=__doc__);steps=parser.add_subparsers(dest='step',required=True)
    for name in ('run','_build'):
        step=steps.add_parser(name)
        for field in ('output','seed','old','new'):step.add_argument('--'+field,type=Path,required=True)
    step=steps.add_parser('_guest');step.add_argument('--stage',choices=('init','reject','update'),required=True)
    args=parser.parse_args();require(sys.platform=='linux' and os.geteuid()==0,'Linux root in the intended namespace required')
    if args.step=='_guest':guest(args);return
    if args.step=='_build':build(args);return
    unit='bc250-package-update-'+uuid.uuid4().hex[:12]
    subprocess.run(['systemd-run','--quiet','--wait','--pipe','--collect','--unit='+unit,'--property=MemoryMax=2G',
        '--property=MemorySwapMax=0','--property=CPUQuota=200%','--property=TasksMax=128','--property=RuntimeMaxSec=360',
        '--property=KillMode=control-group','/usr/bin/unshare','--mount','--propagation','private','/usr/bin/python3','-B',
        str(Path(__file__).resolve()),'_build',*sum((['--'+field,str(getattr(args,field))] for field in ('output','seed','old','new')),[])],check=True,timeout=390)


if __name__=='__main__':main()
