#!/usr/bin/env python3
"""Prepare a separate recovery subvolume and PRIVATE proposed boot config.

This does not write /boot or EFI variables, select an entry, reboot or sleep.
The prepared root is a disposable minimal OS, not a clone of production home.
Apply and physical return qualification are separate subsequent operations.
"""
import argparse
import fcntl
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

import native_trial_lab as trial
import native_volume_lab as native
import recovery_boot_guard as guard
import uefi_recovery_vm as vm
from vm_boot_probe import sparse_fingerprint
from vm_cache_faults import logical_sparse_digest

ROOT=Path(__file__).resolve().parents[1]


def require(value,message):
    if not value:raise RuntimeError(message)


def identity(path):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:return guard.ownership.persistent_identity(fd)
    finally:os.close(fd)


def host(args):
    native.confined();area=args.output.absolute();source=args.baseline.absolute()
    native.private_area(area,creating=True);native.host_space(area.parent)
    require(source.resolve(strict=True)==source and stat.S_ISREG(source.lstat().st_mode)
        and source.stat().st_nlink==1 and source.stat().st_mode&0o222==0,'Unsafe protected source')
    require(sparse_fingerprint(source)==vm.SOURCE_PIN,'Unqualified protected bridge source')
    report=trial.safe_json(args.uefi_report.absolute())
    require(report.get('passed') and report.get('uefi_boots')==6 and report.get('protected_images_unchanged')
        and [r['expected_refusal'] for r in report['cases']]==[False,True],'Require passing UEFI guarded-return matrix')
    for name in ('tools/recovery_boot_guard.py','tools/uefi_recovery_vm.py','install_transaction.py'):
        require(guard.digest(ROOT/name)==report['source_sha256'][name],'UEFI-qualified support source changed')
    boot=Path('/boot/limine.conf');require(boot.is_file() and not boot.is_symlink(),'Unsafe boot configuration')
    original=boot.read_text();before=guard.digest(boot)
    for relative in ('EFI/limine/limine.conf','EFI/BOOT/limine.conf','boot/limine/limine.conf',
            'boot/limine.conf','limine/limine.conf'):
        shadow=Path('/boot')/relative
        require(not shadow.exists() and not shadow.is_symlink(),'Shadowing boot configuration preserved')
    require(original.startswith('timeout: 5\ndefault_entry: 2\nremember_last_entry: yes\n'),
        'Unknown original boot selection policy')
    normal='CachyOS/linux-cachyos-bore-bc250'
    selected=guard.efi_text('LoaderEntrySelected')
    require(selected=='CachyOS.linux-cachyos-bore-bc250','Prepare from known working boot only')
    require(guard.efi_text('LoaderEntryOneShot',missing=True) is None,'Pending boot request preserved')
    require(not re.search(r'^/BC250-STORAGE-TRIAL\s*$',original,re.M),'Existing trial entry preserved')
    release=os.uname().release
    require(release=='7.2.8-1.219-cachyos-bore-bc250','Unexpected physical kernel')
    machine=Path('/etc/machine-id').read_text().strip();bootdir=Path('/boot')/machine/'linux-cachyos-bore-bc250'
    boot_hash={name:guard.digest(bootdir/name) for name in ('vmlinuz','initramfs')}
    expected={'vmlinuz':'5f76cd2d1fbe450a38812e4af27bc279bcf41e1b51d8ffdc651a045c08a3a6e5',
        'initramfs':'0814d4f878a6623245bd3fd7e2fb14ac53fa380f527ed9482c10bd67b3a1354c'}
    require(boot_hash==expected,'Physical boot files changed since VM bridge')
    require(guard.digest(Path('/boot/EFI/limine/limine_x64.efi'))==report['installed_limine_sha256'],'Installed bootloader changed')
    qos=Path('/sys/class/nvme/nvme0/power/pm_qos_latency_tolerance_us');require(qos.read_text().strip()=='5000','Power policy changed')
    working=identity(Path('/'));host_uuid=str(uuid.UUID(working['fs_uuid']))
    area.mkdir(mode=0o700);point=area/'mount';point.mkdir();mounted=False
    lock=os.open(area/'preparation.lock',os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    try:
        image=area/'source-copy.raw';trial.new_copy(source,image,logical_sparse_digest(source))
        vm.run('mount','-o','loop,nosuid,nodev,noexec',image,point);mounted=True
        require(identity(point)['fs_uuid']!=working['fs_uuid'],'Source must not be working filesystem')
        vm.strip_probe(point)
        root=area/'root';vm.run('btrfs','subvolume','create',root)
        vm.run('cp','-a','--reflink=never','--no-preserve=xattr,context',str(point)+'/.',root,timeout=600)
        old_inventory=native.tree_manifest(point,0);new_inventory=native.tree_manifest(root,0)
        # Security xattrs are deliberately excluded from this transfer. Verify
        # content, hardlink groups, modes, owners, symlinks and regular mtimes.
        for inventory in (old_inventory,new_inventory):
            for row in inventory['rows']:row.pop('xattrs')
        require(old_inventory['rows']==new_inventory['rows'],'Recovery tree copy differs from source')
        vm.run('sync','-f',root);vm.run('umount',point);mounted=False;image.chmod(0o400)
        candidate=identity(root);require(candidate!=working and candidate['fs_uuid']==working['fs_uuid'],'Candidate identity mismatch')
        subvol=vm.run('btrfs','inspect-internal','rootid',root);require(subvol.isdecimal() and int(subvol)>256,'Invalid candidate root id')
        (root/'etc/fstab').write_text('UUID='+host_uuid+' / btrfs defaults,noatime,compress=zstd:1,subvolid='+subvol+' 0 0\n')
        fixture=root/'opt/bc250-recovery-fixture.bin';require(not fixture.exists(),'Existing recovery fixture preserved')
        shutil.copyfile(root/'opt/bc250-vm-fixture.bin',fixture)
        nonce=uuid.uuid4().hex
        proposed=re.sub(r'^default_entry: 2$', 'default_entry: '+normal,original,count=1,flags=re.M)
        proposed=re.sub(r'^remember_last_entry: yes$', 'remember_last_entry: no',proposed,count=1,flags=re.M)
        prefix='boot():/'+machine+'/linux-cachyos-bore-bc250/'
        # Preserve the byte-verified boot file hash syntax used by the working
        # entry; its 128-hex checksum is BLAKE2b-512, not SHA-512.
        paths={}
        import hashlib
        for name in ('vmlinuz','initramfs'):
            checksum=hashlib.blake2b((bootdir/name).read_bytes()).hexdigest()
            paths[name]=prefix+name+'#'+checksum
            require(paths[name] in original,'Existing boot path checksum not found')
        proposed+='\n/BC250-STORAGE-TRIAL\n  protocol: linux\n  path: '+paths['vmlinuz']+'\n  module_path: '+paths['initramfs']+'\n'
        proposed+='  cmdline: rw root=UUID='+host_uuid+' rootfstype=btrfs rootflags=subvolid='+subvol+' nowatchdog console=tty1 loglevel=4 systemd.show_status=no systemd.gpt_auto=no rd.systemd.gpt_auto=no bc250.recovery='+nonce+'\n'
        cfg=dict(format=1,mode='physical',nonce=nonce,root_identity=candidate,working_identity=working,
            normal_menu_path=normal,trial_entry=vm.TRIAL,esp_uuid=vm.run('findmnt','-n','-o','UUID','--target','/boot'),
            config_sha256=__import__('hashlib').sha256(proposed.encode()).hexdigest(),fixture_sha256=guard.digest(fixture),kernel_release=release)
        guard.validate_policy(proposed,cfg)
        vm.install_support(root,cfg)
        for name in ('bc250-recovery-trial.service','bc250-recovery-return.service'):
            p=root/'etc/systemd/system'/name;text=p.read_text()
            p.write_text(text.replace('StandardOutput=tty\nStandardError=tty\nTTYPath=/dev/ttyS0\n',
                'StandardOutput=journal+console\nStandardError=journal+console\n'))
        require(not (root/'opt/bc250-vm-probe.py').exists()
            and not (root/'etc/systemd/system/multi-user.target.wants/bc250-vm-probe.service').exists(),'VM poweroff helper remains')
        require((root/'etc/fstab').read_text().count('\n')==1,'Unexpected additional persistent mounts')
        require(not (root/'var/lib/bc250-storage-defaults').exists(),'Working storage state must not be inherited')
        require(not (root/'etc/systemd/system/bc250-btrfs-repack.service').exists(),'Unexpected maintenance service in recovery root')
        tree=native.tree_manifest(root,0)
        (area/'original-limine.conf').write_text(original);(area/'proposed-limine.conf').write_text(proposed)
        for name in ('original-limine.conf','proposed-limine.conf'):(area/name).chmod(0o600)
        vm.run('sync','-f',root);vm.run('sync','-f',area)
        require(guard.digest(boot)==before and all(guard.digest(bootdir/name)==sha for name,sha in boot_hash.items()),'Working boot files changed during preparation')
        require(sparse_fingerprint(source)==vm.SOURCE_PIN,'Protected source changed')
        result=dict(prepared=True,physical_boot_tested=False,root_identity=candidate,working_identity=working,
            root_subvolume_id=int(subvol),candidate_root=str(root),original_config_sha256=before,
            proposed_config_sha256=cfg['config_sha256'],kernel_release=release,boot_sha256=boot_hash,
            vm_poweroff_probe_removed=True,production_home_mounted=False,working_boot_setup_changed=False,
            guarded_return_installed=True,system_suspend_wake_supported=False,uefi_source_sha256=report['source_sha256'],
            candidate_tree_sha256=tree['sha256'],candidate_tree_nodes=tree['nodes'],
            copied_tree_content_links_modes_owners_verified=True,security_xattr_preservation_qualified=False,
            preparation_source_sha256=guard.digest(Path(__file__)),
            completed_unix=time.time())
        guard.ownership.atomic_json(area/'preparation-result.json',result)
        print(json.dumps(dict(prepared=True,host_boot_setup_changed=False,physical_boot_tested=False)),flush=True)
    finally:
        if mounted:vm.run('umount',point)
        os.close(lock);require(qos.read_text().strip()=='5000','Actual power policy changed')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('step',choices=('prepare','_host'))
    for name in ('baseline','uefi-report','output'):parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args();require(sys.platform=='linux' and os.geteuid()==0,'Requires Linux root')
    if args.step=='_host':host(args);return
    name='bc250-prepare-recovery-'+uuid.uuid4().hex[:12]
    command=['systemd-run','--quiet','--wait','--pipe','--collect','--unit='+name,
        '--property=MemoryMax=2G','--property=MemorySwapMax=0','--property=CPUQuota=200%',
        '--property=RuntimeMaxSec=1200','--property=TimeoutStopSec=30','--property=KillMode=control-group',
        '/usr/bin/unshare','--mount','--propagation','private','/usr/bin/python3',str(Path(__file__).resolve()),'_host',
        '--baseline',str(args.baseline),'--uefi-report',str(args.uefi_report),'--output',str(args.output)]
    subprocess.run(command,check=True,timeout=1260)


if __name__=='__main__':main()
