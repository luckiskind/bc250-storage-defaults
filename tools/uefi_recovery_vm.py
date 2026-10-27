#!/usr/bin/env python3
"""Exercise normal -> one-shot trial -> normal through copied Limine/OVMF.

Only fresh regular-file images and private firmware-variable files are writable.
No host boot config, firmware variable, service or physical device is passed to
QEMU. Two cases check a valid private root and refusal of a replaced identity.
"""
import argparse
import ast
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import time
import uuid

ROOT=Path(__file__).resolve().parents[1]
SOURCE_PIN=dict(sha256='62d0d6999c575878bb00be4ac9db71a22a02cfa2a880919355ccdf6564f2e699',
    data_ranges=341,data_bytes=889188352,virtual_bytes=85899345920)
NORMAL='BC250-NORMAL'
TRIAL='BC250-STORAGE-TRIAL'

NORMAL_PROBE=r'''import json,os,subprocess,sys
from pathlib import Path
sys.path.insert(0,'/opt/bc250-recovery')
import recovery_boot_guard as guard
cfg=guard.load_config(Path('/opt/bc250-recovery/config.json'))
guard.require(cfg['mode']=='vm','VM-only helper')
guard.require(subprocess.check_output(['systemd-detect-virt','--vm'],text=True).strip()=='qemu','VM-only helper')
guard.require(guard.root_identity()==cfg['working_identity'],'Wrong normal root')
guard.require(os.uname().release==cfg['kernel_release'],'Wrong normal kernel')
guard.require(Path('/proc/1/comm').read_text().strip()=='systemd','Not real PID 1')
guard.boot_context(cfg,selected_entry=cfg['normal_entry'])
guard.require(subprocess.check_output(['systemctl','is-active','multi-user.target'],text=True).strip()=='active','Unusable normal target')
guard.require(not subprocess.check_output(['systemctl','--failed','--plain','--no-legend','--no-pager'],text=True).strip(),'Failed normal units')
state=Path('/var/lib/bc250-normal-probe')
boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
if not state.exists():
 state.mkdir(mode=0o700)
 guard.ownership.atomic_json(state/'armed.json',dict(boot_id=boot,nonce=cfg['nonce']))
 subprocess.run(['bootctl','set-oneshot',cfg['trial_entry']],check=True,timeout=20)
 guard.require(guard.efi_text('LoaderEntryOneShot')==cfg['trial_entry'],'One-shot write not observed')
 print('BC250_NORMAL_ARMED='+json.dumps(dict(boot_id=boot,nonce=cfg['nonce'])),flush=True)
 guard.request_reboot()
else:
 armed=json.loads((state/'armed.json').read_text());guard.require(armed['nonce']==cfg['nonce'] and armed['boot_id']!=boot,'No reboot occurred')
 point=Path('/run/bc250-trial-inspection');point.mkdir(mode=0o700)
 subprocess.run(['mount','-t','btrfs','-o','ro,nosuid,nodev,noexec,subvolid=5','UUID='+cfg['trial_uuid'],str(point)],check=True,timeout=30)
 try:
  guard.require('ro' in subprocess.check_output(['findmnt','-n','-o','OPTIONS','--target',str(point)],text=True).strip().split(','),'Inspection not read-only')
  fixture=point/'opt/bc250-recovery-fixture.bin';guard.require(guard.digest(fixture)==cfg['fixture_sha256'],'Trial fixture changed')
  result=point/'var/lib/bc250-recovery/result.json'
  if cfg['expected_refusal']:
   guard.require(not result.parent.exists(),'Refused root was written')
   trial=None
  else:
   trial=json.loads(result.read_text());guard.require(trial['passed'] and trial['nonce']==cfg['nonce'] and trial['boot_id'] not in (armed['boot_id'],boot),'Missing distinct trial boot')
  report=dict(passed=True,expected_refusal=cfg['expected_refusal'],normal_return_verified=True,one_shot_consumed=True,
    fixture_unchanged=True,normal_boot_ids_distinct=True,trial=trial,kernel=os.uname().release,real_systemd_pid1=True,failed_units=0)
  guard.ownership.atomic_json(state/'result.json',report)
  print('BC250_UEFI_RESULT='+json.dumps(report),flush=True)
 finally:
  subprocess.run(['umount',str(point)],check=True,timeout=30);point.rmdir()
 subprocess.run(['systemctl','poweroff','--no-block'],check=True,timeout=20)
'''


def require(value,message):
    if not value:raise RuntimeError(message)


def run(*args,timeout=300):
    return subprocess.check_output(list(map(str,args)),stderr=subprocess.STDOUT,text=True,timeout=timeout).strip()


def digest(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def unit(command,on_failure=None):
    return ('[Unit]\nDescription=Private recovery boot qualification\nDefaultDependencies=no\n'
        'After=multi-user.target\nConflicts=shutdown.target\nBefore=shutdown.target\n'+
        ('OnFailure='+on_failure+'\n' if on_failure else '')+
        '[Service]\nType=oneshot\nEnvironment=PYTHONDONTWRITEBYTECODE=1\nExecStart='+command+
        '\nStandardOutput=tty\nStandardError=tty\nTTYPath=/dev/ttyS0\nTimeoutStartSec=90\n'
        '[Install]\nWantedBy=multi-user.target\n')


def install_support(point,cfg,normal=False):
    support=point/'opt/bc250-recovery';require(not support.exists(),'Existing support preserved');support.mkdir(mode=0o700)
    for source in (ROOT/'tools/recovery_boot_guard.py',ROOT/'install_transaction.py'):
        shutil.copyfile(source,support/source.name);(support/source.name).chmod(0o600)
    cfg['support_sha256']={p.name:digest(p) for p in support.iterdir()}
    (support/'config.json').write_text(json.dumps(cfg));(support/'config.json').chmod(0o600)
    units=point/'etc/systemd/system'
    if normal:
        (support/'normal_probe.py').write_text(NORMAL_PROBE)
        name='bc250-normal-probe.service'
        text=unit('/usr/bin/python3 /opt/bc250-recovery/normal_probe.py')
    else:
        name='bc250-recovery-trial.service'
        base='/usr/bin/python3 /opt/bc250-recovery/recovery_boot_guard.py '
        text=unit(base+'trial --config /opt/bc250-recovery/config.json','bc250-recovery-return.service')
        (units/'bc250-recovery-return.service').write_text(unit(base+'return --config /opt/bc250-recovery/config.json'))
    (units/name).write_text(text)
    (units/'multi-user.target.wants'/name).symlink_to('../'+name)


def strip_probe(point):
    source=ROOT/'tools/vm_image_builder.py'
    assignments=[n for n in ast.parse(source.read_text()).body if isinstance(n,ast.Assign)
        and any(isinstance(t,ast.Name) and t.id=='PROBE' for t in n.targets)]
    require(len(assignments)==1,'Unfamiliar original probe')
    probe=ast.literal_eval(assignments[0].value)
    needle=' report.update(passed=True,kernel=os.uname().release,'
    checks=" assert subprocess.check_output(['systemctl','is-active','multi-user.target'],text=True).strip()=='active'\n"
    checks+=" assert not subprocess.check_output(['systemctl','--failed','--plain','--no-legend','--no-pager'],text=True).strip()\n"
    checks+=" report.update(usable_target_active=True,failed_guest_units=0)\n"
    path=point/'opt/bc250-vm-probe.py'
    require(path.read_text()==probe.replace(needle,checks+needle),'Unfamiliar VM poweroff probe preserved')
    units=point/'etc/systemd/system';name='bc250-vm-probe.service'
    link=units/'multi-user.target.wants'/name
    require(link.is_symlink() and os.readlink(link)=='../'+name,'Unfamiliar enabled probe preserved')
    link.unlink();(units/name).unlink();path.unlink()
    require(not (point/'var/lib/bc250-vm-probe').exists(),'Dirty source VM state')


def guest():
    area=Path('/vmlab');require(Path('/run/host').exists(),'Use private wrapper')
    parameters=json.loads((area/'parameters.json').read_text());cases=[]
    for label in ('valid','refused'):
        normal='normal' if label=='valid' else 'normal-refused'
        for name in (normal,label):
            run('qemu-img','create','-f','qcow2','-F','raw','-b',area/(name+'.raw'),area/(label+'-'+name+'.qcow2'))
        run('qemu-img','create','-f','qcow2','-F','raw','-b',area/'esp.raw',area/(label+'-esp.qcow2'))
        variables=area/(label+'-vars.fd');shutil.copyfile('/usr/share/edk2/x64/OVMF_VARS.4m.fd',variables)
        args=['qemu-system-x86_64','-accel','tcg,thread=multi','-machine','q35','-cpu','max','-smp','2','-m','1024',
            '-display','none','-vga','std','-nic','none','-serial','stdio','-monitor','none','-no-reboot',
            '-sandbox','on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny',
            '-drive','if=pflash,unit=0,format=raw,readonly=on,file=/usr/share/edk2/x64/OVMF_CODE.4m.fd',
            '-drive','if=pflash,unit=1,format=raw,file='+str(variables),
            '-device','qemu-xhci','-drive','file='+str(area/(label+'-esp.qcow2'))+',if=none,id=esp,format=qcow2',
            '-device','usb-storage,drive=esp,removable=on,bootindex=1']
        for name,serial in ((normal,'BC250_NORMAL'),(label,'BC250_TRIAL')):
            args+=['-drive','file='+str(area/(label+'-'+name+'.qcow2'))+',if=none,id='+serial+',format=qcow2,cache=writeback',
                '-device','nvme,serial='+serial+',drive='+serial]
        started=time.monotonic();lines=[]
        # Honour guest reboot requests by exiting QEMU, then launch a fresh
        # machine with the SAME overlays and private persistent EFI variables.
        # This tests durable boot selection across cold machine instances; it
        # deliberately does not claim QEMU's in-process warm reset works.
        for boot in range(3):
            log=area/(label+'-'+str(boot)+'.serial.log')
            with log.open('xb') as stream:
                proc=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=stream,stderr=subprocess.STDOUT,timeout=240)
            part=log.read_text(errors='replace').splitlines();lines+=part
            require(proc.returncode==0,'VM did not exit normally: '+log.name)
            wanted=('BC250_NORMAL_ARMED=' if boot==0 else
                ('BC250_RECOVERY_RETURN=' if label=='refused' else 'BC250_RECOVERY_TRIAL=') if boot==1 else 'BC250_UEFI_RESULT=')
            require(sum(wanted in s for s in part)==1,'Wrong selected boot phase: '+log.name)
        rows=[json.loads(s.split('BC250_UEFI_RESULT=',1)[1]) for s in lines if 'BC250_UEFI_RESULT=' in s]
        require(len(rows)==1 and rows[0]['passed'],'UEFI case failed; inspect '+log.name)
        row=rows[0];require(row['expected_refusal']==(label=='refused') and row['kernel']==parameters['kernel_release'],'Case identity mismatch')
        marker='BC250_RECOVERY_RETURN=' if label=='refused' else 'BC250_RECOVERY_TRIAL='
        require(sum(marker in s for s in lines)==1 and sum('BC250_NORMAL_ARMED=' in s for s in lines)==1,'Missing or repeated selected boot transition')
        if label=='refused':require(any('Selected root identity does not match the private candidate' in s for s in lines),'Wrong refusal cause')
        row.update(case=label,elapsed_s=time.monotonic()-started);cases.append(row)
        print(json.dumps(dict(case=label,passed=True,elapsed_s=row['elapsed_s'])),flush=True)
    (area/'guest-result.json').write_text(json.dumps(dict(passed=True,cases=cases),indent=2)+'\n')


def host(args):
    import native_trial_lab as trial
    import native_volume_lab as native
    import prepare_test_os as build
    import recovery_boot_guard as guard
    from vm_boot_probe import sparse_fingerprint
    from vm_cache_faults import logical_sparse_digest
    build.configure(args.workspace);build.guards();native.confined()
    source=args.baseline.absolute();area=args.output.absolute()
    native.private_area(area,creating=True);native.host_space(area.parent)
    require(source.resolve(strict=True)==source and stat.S_ISREG(source.lstat().st_mode)
        and source.stat().st_nlink==1 and source.stat().st_mode&0o222==0 and source.stat().st_size==native.SIZE,'Unsafe source')
    require(sparse_fingerprint(source)==SOURCE_PIN,'Source baseline differs from qualified bridge')
    reference=trial.safe_json(source.parent/'result.json')
    require(reference['passed'] and reference['vm_boots']==3 and reference['uses_running_host_kernel_bytes'],'Unqualified source')
    lock=os.open(build.AREA/'virtual-lab.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600);fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    area.mkdir(mode=0o700);point=area/'mount';point.mkdir();mounted=False
    qos=Path('/sys/class/nvme/nvme0/power/pm_qos_latency_tolerance_us');require(qos.read_text().strip()=='5000','Host policy changed')
    try:
        expected=logical_sparse_digest(source);ids={};identities={}
        for name in ('normal','valid'):
            image=area/(name+'.raw');trial.new_copy(source,image,expected)
            ids[name]=str(uuid.uuid4());run('btrfstune','-f','-U',ids[name],image)
            run('mount','-o','loop,nosuid,nodev,noexec',image,point);mounted=True
            require(run('findmnt','-n','-o','UUID','--target',point)==ids[name],'New image UUID not observed')
            strip_probe(point)
            old='UUID=cbe1c20f-5f17-42d7-b180-64f1d3076556 / btrfs defaults,compress=zstd:1 0 0\n'
            require((point/'etc/fstab').read_text()==old,'Unfamiliar guest mount policy')
            (point/'etc/fstab').write_text('UUID='+ids[name]+' / btrfs defaults,compress=zstd:1 0 0\n')
            fd=os.open(point,os.O_RDONLY|os.O_DIRECTORY)
            try:identities[name]=guard.ownership.persistent_identity(fd)
            finally:os.close(fd)
            if name=='valid':
                shutil.copyfile(point/'opt/bc250-vm-fixture.bin',point/'opt/bc250-recovery-fixture.bin')
                fixture_sha=digest(point/'opt/bc250-recovery-fixture.bin')
            run('sync','-f',point);run('umount',point);mounted=False
        esp=area/'esp.raw';fd=os.open(esp,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        try:os.ftruncate(fd,2*2**30)
        finally:os.close(fd)
        volume_id=uuid.uuid4().hex[:8].upper();esp_uuid=volume_id[:4]+'-'+volume_id[4:]
        require(stat.S_ISREG(esp.lstat().st_mode) and esp.stat().st_nlink==1,'ESP must be a new regular file')
        run('mkfs.fat','-F','32','-i',volume_id,esp)
        run('mount','-o','loop,nosuid,nodev,noexec',esp,point);mounted=True
        require(run('findmnt','-n','-o','UUID','--target',point)==esp_uuid,'ESP identity mismatch')
        (point/'EFI/BOOT').mkdir(parents=True);efi=Path('/boot/EFI/limine/limine_x64.efi')
        require(efi.is_file() and not efi.is_symlink() and efi.stat().st_size<2**20,'Unsafe installed Limine')
        shutil.copyfile(efi,point/'EFI/BOOT/BOOTX64.EFI');efi_sha=digest(efi)
        for name,sha in reference['boot_sha256'].items():
            require(digest(source.parent/name)==sha,'Bridge boot file changed');shutil.copyfile(source.parent/name,point/name)
        nonce=uuid.uuid4().hex
        config='timeout: 1\ndefault_entry: '+NORMAL+'\nremember_last_entry: no\ngraphics: no\nserial: yes\n'
        for name,title in (('normal',NORMAL),('valid',TRIAL)):
            cmd='root=UUID='+ids[name]+' rootfstype=btrfs rootflags=subvolid=5,compress=zstd:1 rw console=ttyS0 loglevel=4 systemd.show_status=no systemd.log_color=no systemd.mask=serial-getty@ttyS0.service'
            if name=='valid':cmd+=' bc250.recovery='+nonce
            config+='\n/'+title+'\n protocol: linux\n path: boot():/kernel\n module_path: boot():/initramfs.img\n cmdline: '+cmd+'\n'
        (point/'limine.conf').write_text(config);config_sha=digest(point/'limine.conf')
        run('sync','-f',point);run('umount',point);mounted=False
        cfg=dict(format=1,mode='vm',nonce=nonce,root_identity=identities['valid'],working_identity=identities['normal'],
            normal_menu_path=NORMAL,normal_entry=NORMAL,trial_entry=TRIAL,esp_uuid=esp_uuid,config_sha256=config_sha,
            fixture_sha256=fixture_sha,kernel_release=os.uname().release,trial_uuid=ids['valid'],expected_refusal=False)
        for name in ('normal','valid'):
            run('mount','-o','loop,nosuid,nodev,noexec',area/(name+'.raw'),point);mounted=True
            install_support(point,dict(cfg),normal=name=='normal')
            run('sync','-f',point);run('umount',point);mounted=False
            (area/(name+'.raw')).chmod(0o400)
        trial.new_copy(area/'valid.raw',area/'refused.raw',logical_sparse_digest(area/'valid.raw'))
        run('mount','-o','loop,nosuid,nodev,noexec',area/'refused.raw',point);mounted=True
        path=point/'opt/bc250-recovery/config.json';bad=json.loads(path.read_text())
        value=bad['root_identity']['handle'];bad['root_identity']['handle']=('ff' if value[:2]!='ff' else 'ee')+value[2:]
        path.write_text(json.dumps(bad));run('sync','-f',point);run('umount',point);mounted=False
        (area/'refused.raw').chmod(0o400)
        trial.new_copy(area/'normal.raw',area/'normal-refused.raw',logical_sparse_digest(area/'normal.raw'))
        run('mount','-o','loop,nosuid,nodev,noexec',area/'normal-refused.raw',point);mounted=True
        path=point/'opt/bc250-recovery/config.json';bad=json.loads(path.read_text());bad['expected_refusal']=True
        path.write_text(json.dumps(bad));run('sync','-f',point);run('umount',point);mounted=False
        (area/'normal-refused.raw').chmod(0o400)
        (area/'parameters.json').write_text(json.dumps(dict(kernel_release=os.uname().release)))
        shutil.copyfile(Path(__file__),area/'uefi_recovery_vm.py')
        protected={p.name:sparse_fingerprint(p) for p in area.glob('*.raw')};esp.chmod(0o400)
        identity=build.GUEST.stat()
        for p in area.iterdir():
            if p.is_file():os.chown(p,identity.st_uid,identity.st_gid)
        os.chown(area,identity.st_uid,identity.st_gid)
        command=[a for a in build.container_args() if not a.startswith('--property=')]
        command+=['--keep-unit','--bind='+str(area)+':/vmlab','/usr/bin/python3','/vmlab/uefi_recovery_vm.py','_guest']
        subprocess.run(command,check=True,timeout=1500);os.chown(area,0,0)
        results=json.loads((area/'guest-result.json').read_text());require(results['passed'],'Guest failed')
        require(all(sparse_fingerprint(area/name)==pin for name,pin in protected.items())
            and sparse_fingerprint(source)==SOURCE_PIN,'Protected image changed')
        report=dict(results,uefi_boots=6,cold_machine_instances=True,in_process_warm_reset_qualified=False,
            private_efi_variables_persist_across_machine_instances=True,
            actual_kernel_and_initramfs_bytes=True,installed_limine_sha256=efi_sha,
            uses_copied_limine=True,protected_images_unchanged=True,host_boot_setup_changed=False,
            physical_recovery_tested=False,physical_suspend_tested=False,no_guest_nic=True,host_nvme_qos_us=5000,
            source_sha256={name:digest(ROOT/name) for name in ('tools/uefi_recovery_vm.py','tools/recovery_boot_guard.py','install_transaction.py')},
            completed_unix=time.time())
        build.atomic_json(area/'result.json',report);print(json.dumps(dict(passed=True,report=str(area/'result.json'))),flush=True)
    finally:
        if mounted:run('umount',point)
        os.chown(area,0,0);os.close(lock);require(qos.read_text().strip()=='5000','Host policy changed')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('step',choices=('run','_host','_guest'))
    for name in ('workspace','baseline','output'):parser.add_argument('--'+name,type=Path)
    args=parser.parse_args()
    if args.step=='_guest':guest();return
    require(sys.platform=='linux' and os.geteuid()==0,'Requires Linux root')
    require(all((args.workspace,args.baseline,args.output)),'Specify all paths')
    if args.step=='_host':host(args);return
    name='bc250-uefi-recovery-'+uuid.uuid4().hex[:12];print(json.dumps(dict(parent_unit=name)),flush=True)
    command=['systemd-run','--quiet','--wait','--pipe','--collect','--unit='+name,
        '--property=Delegate=yes','--property=MemoryMax=2G','--property=MemoryHigh=1536M','--property=MemorySwapMax=0',
        '--property=CPUQuota=200%','--property=RuntimeMaxSec=2100','--property=TimeoutStopSec=30',
        '--property=KillMode=control-group','--property=LimitCORE=0:infinity',
        '/usr/bin/unshare','--mount','--propagation','private','/usr/bin/python3',str(Path(__file__).resolve()),'_host',
        '--workspace',str(args.workspace),'--baseline',str(args.baseline),'--output',str(args.output)]
    subprocess.run(command,check=True,timeout=2160)


if __name__=='__main__':main()
