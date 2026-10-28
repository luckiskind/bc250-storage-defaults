#!/usr/bin/env python3
"""Validate copied physical boot artifacts against a minimal recovery OS in QEMU.

Copies only a protected regular-file lab image and the running kernel's boot
files/runtime modules. No physical boot selection, firmware, host service or
controller setting is changed. QEMU has no NIC or host block-device access.
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


def require(value,message):
    if not value:raise RuntimeError(message)


def digest(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def run(*args,timeout=300):
    return subprocess.check_output(list(map(str,args)),stderr=subprocess.STDOUT,text=True,timeout=timeout).strip()


def module_inventory(root):
    rows=[];total=0
    for p in sorted(root.rglob('*')):
        relative=p.relative_to(root)
        if relative.parts[0] in ('build','source'):continue
        s=p.lstat();require(stat.S_ISREG(s.st_mode) or stat.S_ISDIR(s.st_mode) or stat.S_ISLNK(s.st_mode),'Unexpected module node')
        row=dict(path=str(relative),mode=stat.S_IMODE(s.st_mode),uid=s.st_uid,gid=s.st_gid)
        if p.is_symlink():row['symlink']=os.readlink(p)
        elif p.is_file():
            total+=s.st_size;require(total<=2*2**30 and len(rows)<50000,'Runtime module bound')
            row.update(bytes=s.st_size,sha256=digest(p))
        rows.append(row)
    return dict(sha256=hashlib.sha256(json.dumps(rows,sort_keys=True).encode()).hexdigest(),entries=len(rows),logical_bytes=total)


def guest():
    area=Path('/vmlab');params=json.loads((area/'parameters.json').read_text())
    require(Path('/run/host').exists(),'Run only through the isolated host wrapper')
    for name,expected in params['boot_sha256'].items():require(digest(area/name)==expected,'Copied boot file changed')
    base=area/'baseline.raw'
    require(stat.S_ISREG(base.lstat().st_mode) and base.stat().st_mode&0o222==0,'Unsafe VM baseline')
    phases=[]
    for label,bus,reset in (('virtio-create','virtio',True),('nvme-persist','nvme',False),('nvme-reset','nvme',True)):
        overlay=area/('reset.qcow2' if label=='nvme-reset' else 'trial.qcow2')
        if reset:
            require(not overlay.exists() and not overlay.is_symlink(),'Existing overlay preserved')
            run('qemu-img','create','-f','qcow2','-F','raw','-b',base,overlay)
        args=['qemu-system-x86_64','-accel','tcg,thread=multi','-machine','q35','-cpu','max','-smp','2','-m','768',
            '-display','none','-vga','none','-nic','none','-serial','stdio','-monitor','none',
            '-sandbox','on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny',
            '-kernel',str(area/'kernel'),'-initrd',str(area/'initramfs.img')]
        if bus=='virtio':args+=['-drive','file='+str(overlay)+',if=virtio,format=qcow2,cache=writeback']
        else:args+=['-drive','file='+str(overlay)+',if=none,id=rootdisk,format=qcow2,cache=writeback',
                    '-device','nvme,serial=BC250_SANDBOX,drive=rootdisk']
        args+=['-append','root=UUID='+params['root_uuid']+' rootfstype=btrfs rootflags=subvolid=5,compress=zstd:1 rw '
            'console=ttyS0 systemd.show_status=no systemd.log_color=no loglevel=4 '
            'systemd.mask=serial-getty@ttyS0.service']
        log=area/(label+'.serial.log');started=time.monotonic()
        with log.open('xb') as stream:
            proc=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=stream,stderr=subprocess.STDOUT,timeout=300)
        reports=[json.loads(line.split('BC250_VM_RESULT=',1)[1]) for line in log.read_text(errors='replace').splitlines()
                 if 'BC250_VM_RESULT=' in line]
        require(proc.returncode==0 and len(reports)==1 and reports[0].get('passed') is True,
                'Guest failed; retain '+log.name)
        result=reports[0]
        require(result['kernel']==params['kernel_release'] and result['root_uuid']==params['root_uuid']
                and result['boot_id']!=params['host_boot_id'] and result['real_systemd_pid1']
                and result['usable_target_active'] and result['failed_guest_units']==0,'Guest identity/usable-state mismatch')
        result.update(phase=label,storage_bus=bus,elapsed_s=time.monotonic()-started)
        phases.append(result)
        (area/(label+'-private.json')).write_text(json.dumps(result,indent=2)+'\n')
        print(json.dumps(dict(phase=label,passed=True,kernel=result['kernel'],failed_guest_units=0)),flush=True)
    require([p['run_count'] for p in phases]==[1,2,1] and phases[0]['nonce']==phases[1]['nonce']!=phases[2]['nonce']
            and len({p['boot_id'] for p in phases})==3,'Persistence/reset sequence failed')
    (area/'guest-result-private.json').write_text(json.dumps(dict(passed=True,phases=phases),indent=2)+'\n')


def host(args):
    import native_trial_lab as trial
    import native_volume_lab as native
    import prepare_test_os as build
    import virtual_test_lab as virtual
    from vm_boot_probe import sparse_fingerprint
    from vm_cache_faults import logical_sparse_digest
    build.configure(args.workspace);build.guards();native.confined()
    area=args.output.absolute();native.private_area(area,creating=True);native.host_space(area.parent)
    reference=trial.safe_json(args.reference_report.absolute())
    require(reference.get('passed') is True and reference.get('base_fingerprint_unchanged') is True
            and reference.get('fresh_overlay_reset_passed') is True,'Use a passing protected reference report')
    source=args.baseline.absolute()
    require(source.resolve(strict=True)==source and source.is_relative_to(build.AREA/'artifacts')
            and stat.S_ISREG(source.lstat().st_mode) and source.stat().st_size==native.SIZE
            and source.stat().st_nlink==1 and source.stat().st_mode&0o222==0,'Unsafe protected source')
    lock=os.open(build.AREA/'virtual-lab.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    original=sparse_fingerprint(source);require(original==reference['base_sparse_fingerprint'],'Protected source changed')
    area.mkdir(mode=0o700)
    image=area/'baseline.raw';mounted=False;point=area/'mount';point.mkdir()
    qos=Path('/sys/class/nvme/nvme0/power/pm_qos_latency_tolerance_us');require(qos.read_text().strip()=='5000','Host policy changed')
    try:
        trial.new_copy(source,image,logical_sparse_digest(source))
        run('mount','-o','loop,nosuid,nodev,noexec',image,point);mounted=True
        root_uuid=run('findmnt','-n','-o','UUID','--target',point);uuid.UUID(root_uuid)
        require(root_uuid!=run('findmnt','-n','-o','UUID','--target',area.parent),'Guest filesystem must differ from host')
        require((point/'usr').stat().st_uid==0,'Expected unmapped VM root ownership')
        oldfstab='/dev/vda / btrfs defaults,compress=zstd:1 0 0\n'
        require((point/'etc/fstab').read_text()==oldfstab,'Unfamiliar baseline mount policy')
        builder=source.parent/'vm_image_builder.py'
        require(digest(builder)==reference['source_hashes']['vm_image_builder.py'],'Reference builder changed')
        assignments=[n for n in ast.parse(builder.read_text()).body if isinstance(n,ast.Assign)
                     and any(isinstance(t,ast.Name) and t.id=='PROBE' for t in n.targets)]
        require(len(assignments)==1,'Missing original guest probe')
        probe=ast.literal_eval(assignments[0].value)
        require((point/'opt/bc250-vm-probe.py').read_text()==probe,'Unfamiliar baseline guest probe')
        needle=' report.update(passed=True,kernel=os.uname().release,'
        require(probe.count(needle)==1,'Unfamiliar probe endpoint')
        checks=" assert subprocess.check_output(['systemctl','is-active','multi-user.target'],text=True).strip()=='active'\n"
        checks+=" assert not subprocess.check_output(['systemctl','--failed','--plain','--no-legend','--no-pager'],text=True).strip()\n"
        checks+=" report.update(usable_target_active=True,failed_guest_units=0)\n"
        unit=point/'etc/systemd/system/bc250-vm-probe.service';text=unit.read_text()
        require(text.count('After=multi-user.target\n')==1 and 'DefaultDependencies=' not in text,'Unfamiliar guest probe unit')
        unit.write_text(text.replace('After=multi-user.target\n','DefaultDependencies=no\nAfter=multi-user.target\nConflicts=shutdown.target\nBefore=shutdown.target\n'))
        (point/'opt/bc250-vm-probe.py').write_text(probe.replace(needle,checks+needle))
        (point/'etc/fstab').write_text('UUID='+root_uuid+' / btrfs defaults,compress=zstd:1 0 0\n')
        release=os.uname().release;modules=Path('/usr/lib/modules')/release
        before_modules=module_inventory(modules)
        target=point/'usr/lib/modules'/release;require(not target.exists(),'Existing matching kernel modules preserved')
        shutil.copytree(modules,target,symlinks=True,
            ignore=lambda directory,names:[n for n in names if Path(directory)==modules and n in ('build','source')])
        require(module_inventory(target)==before_modules==module_inventory(modules),'Runtime module copy mismatch')
        machine=Path('/etc/machine-id').read_text().strip();pkgbase=(modules/'pkgbase').read_text().strip()
        require(len(machine)==32 and all(c in '0123456789abcdef' for c in machine)
                and pkgbase and '/' not in pkgbase and pkgbase not in ('.','..'),'Unsafe boot path metadata')
        boot=Path('/boot')/machine/pkgbase
        boot_hashes={}
        for old,new in (('vmlinuz','kernel'),('initramfs','initramfs.img')):
            path=boot/old
            require(path.resolve(strict=True)==path and path.is_file() and path.stat().st_size<=256*2**20,'Unsafe boot artifact')
            shutil.copyfile(path,area/new);boot_hashes[new]=digest(area/new)
            require(boot_hashes[new]==digest(path),'Boot artifact changed during copying')
        run('sync','-f',point);run('umount',point);mounted=False
        image.chmod(0o400);protected=sparse_fingerprint(image)
        (area/'parameters.json').write_text(json.dumps(dict(kernel_release=release,root_uuid=root_uuid,
            host_boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),boot_sha256=boot_hashes)))
        shutil.copyfile(Path(__file__),area/'host_kernel_vm_probe.py')
        identity=build.GUEST.stat()
        for path in area.iterdir():
            if path.is_file():os.chown(path,identity.st_uid,identity.st_gid)
        os.chown(area,identity.st_uid,identity.st_gid)
        command=[a for a in build.container_args() if not a.startswith('--property=')]
        command+=['--keep-unit','--bind='+str(area)+':/vmlab','/usr/bin/python3','/vmlab/host_kernel_vm_probe.py','_guest']
        subprocess.run(command,check=True,timeout=1020)
        os.chown(area,0,0)
        results=json.loads((area/'guest-result-private.json').read_text());require(results['passed'],'Guest result failed')
        require(sparse_fingerprint(image)==protected and sparse_fingerprint(source)==original,'A protected image changed')
        require(qos.read_text().strip()=='5000','Actual host policy changed')
        phases=[]
        for row in results['phases']:
            phases.append({key:row[key] for key in ('phase','storage_bus','kernel','passed','run_count','previous_count',
                'fixture_sha256','real_systemd_pid1','usable_target_active','failed_guest_units','elapsed_s')})
        report=dict(passed=True,vm_boots=3,uses_running_host_kernel_bytes=True,uses_installed_physical_initramfs_bytes=True,
            matching_runtime_modules_verified=before_modules,boot_sha256=boot_hashes,phases=phases,
            original_protected_reference_unchanged=True,new_protected_baseline_unchanged=True,
            guest_filesystem_differs_from_host=True,guest_boots_distinct_from_host_and_each_other=True,
            persistence_across_storage_bus_change=True,fresh_overlay_reset_passed=True,
            no_guest_nic=True,software_cpu_emulation=True,physical_boot_tested=False,physical_recovery_tested=False,
            physical_device_or_firmware_compatibility_qualified=False,physical_power_loss_tested=False,
            host_boot_setup_changed=False,host_nvme_qos_us=5000,headers_and_module_sources_copied=False,
            copied_guest_security_xattrs_qualified=False,networking_qualified=False,
            source_sha256={name:digest(ROOT/name) for name in ('tools/host_kernel_vm_probe.py','tools/native_trial_lab.py',
                'tools/native_volume_lab.py','tools/prepare_test_os.py','tools/vm_cache_faults.py','tools/vm_boot_probe.py')},
            completed_unix=time.time())
        build.atomic_json(area/'result.json',report)
        print(json.dumps(dict(passed=True,vm_boots=3,kernel=release,report=str(area/'result.json'))),flush=True)
    finally:
        if mounted:run('umount',point)
        os.chown(area,0,0);require(qos.read_text().strip()=='5000','Host policy changed')
        os.close(lock)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('step',choices=('run','_host','_guest'))
    parser.add_argument('--workspace',type=Path)
    parser.add_argument('--baseline',type=Path)
    parser.add_argument('--reference-report',type=Path)
    parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    if args.step=='_guest':guest();return
    require(os.geteuid()==0 and sys.platform=='linux','Requires Linux root')
    require(all((args.workspace,args.baseline,args.reference_report,args.output)),'Specify all host inputs')
    if args.step=='_host':host(args);return
    unit='bc250-host-kernel-vm-'+uuid.uuid4().hex[:12]
    print(json.dumps(dict(parent_unit=unit)),flush=True)
    command=['systemd-run','--quiet','--wait','--pipe','--collect','--unit='+unit,
        '--property=Delegate=yes','--property=MemoryMax=2G','--property=MemoryHigh=1536M',
        '--property=MemorySwapMax=0','--property=CPUQuota=200%','--property=RuntimeMaxSec=1500',
        '--property=TimeoutStopSec=30','--property=KillMode=control-group','--property=LimitCORE=0:infinity',
        '/usr/bin/unshare','--mount','--propagation','private','/usr/bin/python3',str(Path(__file__).resolve()),'_host',
        '--workspace',str(args.workspace),'--baseline',str(args.baseline),'--reference-report',str(args.reference_report),
        '--output',str(args.output)]
    subprocess.run(command,check=True,timeout=1560)


if __name__=='__main__':main()
