#!/usr/bin/env python3
"""Prepare and run a separate-kernel virtual recovery lab in a dedicated test OS.

First use prepare_test_os.py extract/install-deps with a NEW workspace. This
wrapper installs signed VM tools only there. It never uses a host block device,
changes host boot configuration, exposes a guest network, or claims performance.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time
import uuid
import fcntl
import stat
import prepare_test_os as build
from vm_profile_guest import PACKAGE_FILES

SOURCE=Path(__file__).resolve().parent


def require(condition,message):
    if not condition:raise RuntimeError(message)


def label(value):
    require(re.fullmatch('[a-z0-9][a-z0-9_-]{0,63}',value) is not None,'Invalid private run label')
    return value


def container_args(network=False):
    args=[a.replace('MemoryMax=1G','MemoryMax=2G') for a in build.container_args(network)]
    return args+['--property=MemoryHigh=1536M','--property=MemorySwapMax=0']


def write_helper(path,data,owner,group):
    # Do not truncate a pre-existing node until its type/ownership is known.
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_NOFOLLOW|os.O_NONBLOCK,0o600)
    try:
        info=os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and
                info.st_uid in (os.geteuid(),owner),'Unsafe helper file; preserved')
        os.ftruncate(fd,0)
        with os.fdopen(os.dup(fd),'wb') as stream:
            stream.write(data);stream.flush();os.fsync(stream.fileno())
        os.fchown(fd,owner,group);os.fchmod(fd,0o644)
    finally:os.close(fd)


def stage(name,directory):
    require(not directory.is_symlink(),'Unsafe virtual lab directory')
    directory.mkdir(mode=0o700,exist_ok=True)
    identity=build.GUEST.stat()
    require(identity.st_uid>65535,'Guest must retain a distinct user range')
    os.chown(directory,identity.st_uid,identity.st_gid)
    source=SOURCE/name
    require(source.is_file() and not source.is_symlink(),'Unsafe helper source')
    path=directory/name
    write_helper(path,source.read_bytes(),identity.st_uid,identity.st_gid)
    return '/vmlab/'+name


def verify_profile_sources(directory):
    manifest=json.loads((directory/'image-build.json').read_text())
    require(manifest.get('storage_profile_fixture') is True,'Build a profile fixture first')
    for name,key in (('vm_image_builder.py','builder_source_sha256'),
                     ('vm_profile_guest.py','profile_guest_source_sha256')):
        require(hashlib.sha256((SOURCE/name).read_bytes()).hexdigest()==manifest.get(key),
                'Embedded guest source changed; rebuild profile under a new label')
    require(set(manifest['package_sha256'])==set(PACKAGE_FILES),'Unexpected embedded package files')
    for name,sha in manifest['package_sha256'].items():
        require(hashlib.sha256((SOURCE.parent/name).read_bytes()).hexdigest()==sha,
                'Package source changed; rebuild profile under a new label')


def load_calibration(path,area):
    path=path.absolute()
    require(path.resolve(strict=True)==path and path.is_relative_to(area),
            'Calibration report must be inside this private toolchain workspace')
    info=path.lstat()
    # prepare_test_os.atomic_json uses the root umask, commonly producing 0644
    # metadata under a 0700 workspace. Others may not MODIFY the trusted report.
    require(stat.S_ISREG(info.st_mode) and info.st_uid==os.geteuid() and info.st_mode&0o022==0
            and info.st_nlink==1 and info.st_size<=2**20,'Unsafe calibration report')
    calibration=json.loads(path.read_text())
    require(calibration.get('passed') is True and calibration.get('case_count')==4 and
            calibration.get('actual_backend_sigkill_tested') is True and len(calibration['cases'])==4 and
            calibration.get('armed_cache_cut_tested') is True and
            {c['case'] for c in calibration['cases']}=={'unflushed-loss','flush-survival','fua-isolation','backend-sigkill'} and
            all(c.get('passed') is True for c in calibration['cases']), 'Calibration did not pass completely')
    require(set(calibration['source_sha256'])=={'volatile_disk.py','calibrate_volatile_disk.py'},
            'Unexpected calibration source set')
    for name,digest in calibration['source_sha256'].items():
        require(hashlib.sha256((SOURCE/name).read_bytes()).hexdigest()==digest,
                'Disk model/client changed since calibration; recalibrate first')
    return calibration


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('step',choices=['packages','inventory','build','boot','diagnostic','profile-build','profile-test','cache-calibrate','cache-profile-test'])
    parser.add_argument('--workspace',type=Path,required=True)
    parser.add_argument('--run-label',type=label)
    parser.add_argument('--artifact-label',type=label,default='vm')
    parser.add_argument('--cases',nargs='+')
    parser.add_argument('--calibration-report',type=Path)
    args=parser.parse_args()
    build.configure(args.workspace);build.guards()
    require((build.AREA/'dependencies.json').is_file() and not (build.AREA/'INCOMPLETE').exists(),
            'Complete the dedicated userspace preparation first')
    require(not (build.GUEST/'qualification').exists(),
            'Use a dedicated VM toolchain; preserve the previously qualified service-test OS')
    lock=os.open(build.AREA/'virtual-lab.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    except BlockingIOError:raise RuntimeError('Another virtual-lab action is still running') from None
    if args.step=='packages':
        require(not (build.GUEST/'vmlab').exists(),'Do not update a toolchain after image construction starts')
        subprocess.run(container_args(True)+['/usr/bin/pacman','-Syu','--noconfirm','--needed',
                       'qemu-system-x86','qemu-img','linux','mkinitcpio','cpio'],check=True,timeout=900)
    if args.step in ('packages','inventory'):
        result=subprocess.run(container_args()+['/usr/bin/pacman','-Q'],check=True,
                              capture_output=True,text=True,timeout=60)
        build.atomic_json(build.AREA/'vm-toolchain-inventory.json',dict(packages=result.stdout.splitlines(),
                          inventory_only=True,host_boot_changed=False,host_kernel_changed=False))
        print(json.dumps({'inventory_saved':True}),flush=True)
        return
    require((build.AREA/'vm-toolchain-inventory.json').is_file(),'Record signed VM package preparation/inventory first')
    actual=Path('/sys/class/nvme/nvme0/power/pm_qos_latency_tolerance_us')
    before=actual.read_text().strip()
    require(before=='5000','Working host power policy unexpectedly changed')
    available=dict(line.split(':',1) for line in Path('/proc/meminfo').read_text().splitlines())
    require(int(available['MemAvailable'].split()[0])*1024>=6*2**30,'Need 6 GiB available host memory')
    constructing=args.step in ('build','profile-build')
    calibrating=args.step=='cache-calibrate'
    cache_profile=args.step=='cache-profile-test'
    helper=('vm_image_builder.py' if constructing else 'calibrate_volatile_disk.py' if calibrating
            else 'vm_cache_faults.py' if cache_profile
            else 'vm_profile_faults.py' if args.step=='profile-test' else 'vm_boot_probe.py')
    host_uuid=None
    if args.step in ('boot','profile-test','cache-profile-test'):
        host_uuid=subprocess.check_output(['findmnt','-n','-o','UUID','--target',str(build.AREA)],text=True).strip()
        uuid.UUID(host_uuid)
    artifacts=build.AREA/'artifacts'
    require(not artifacts.is_symlink(),'Unsafe artifacts directory')
    artifacts.mkdir(mode=0o700,exist_ok=True)
    directory=artifacts/args.artifact_label
    if not constructing and not calibrating:
        require(directory.is_dir() and (directory/'image-build.json').is_file(),'Build this artifact set first')
    if args.step in ('profile-test','cache-profile-test'):verify_profile_sources(directory)
    if args.step in ('profile-build','cache-calibrate'):
        require(not directory.exists(),'Use a new artifact label; previous artifacts preserved')
    target=stage(helper,directory)
    if args.step in ('profile-build','profile-test'):
        stage('vm_boot_probe.py',directory)
    if calibrating:
        stage('volatile_disk.py',directory)
        stage('vm_boot_probe.py',directory)
    if cache_profile:
        require(args.calibration_report is not None,'Pass a matching completed --calibration-report')
        calibration_path=args.calibration_report.absolute()
        calibration=load_calibration(calibration_path,build.AREA)
        for name in ('volatile_disk.py','calibrate_volatile_disk.py','vm_profile_faults.py','vm_boot_probe.py'):
            stage(name,directory)
        owner=build.GUEST.stat()
        write_helper(directory/'matched-cache-calibration.json',json.dumps(calibration).encode(),owner.st_uid,owner.st_gid)
    if args.step=='profile-build':
        stage('vm_profile_guest.py',directory)
        package=directory/'package';package.mkdir(mode=0o700)
        identity=build.GUEST.stat();os.chown(package,identity.st_uid,identity.st_gid)
        for name in PACKAGE_FILES:
            source=SOURCE.parent/name
            require(source.is_file() and not source.is_symlink(),'Unsafe package source')
            parent=(package/name).parent
            parent.mkdir(exist_ok=True);os.chown(parent,identity.st_uid,identity.st_gid)
            write_helper(package/name,source.read_bytes(),identity.st_uid,identity.st_gid)
    run_label=args.run_label or 'run-'+uuid.uuid4().hex
    command=['/usr/bin/python3',target]
    if not constructing:command+=['--run-label',run_label]
    if args.step=='profile-build':command+=['--profile-fixture']
    if args.step=='profile-test' and args.cases:command+=['--cases',*args.cases]
    if args.step=='diagnostic':command+=['--diagnostic']
    try:
        subprocess.run(container_args()+['--bind='+str(directory)+':/vmlab']+command,check=True,timeout=1200)
    finally:
        require(actual.read_text().strip()==before,'Host NVMe policy changed during virtual qualification')
    if calibrating:
        result=json.loads((directory/'runs'/run_label/'volatile-cache-calibration.json').read_text())
        require(result.get('passed') is True,'Volatile cache calibration did not pass')
        require(all(hashlib.sha256((SOURCE/name).read_bytes()).hexdigest()==digest
                    for name,digest in result['source_sha256'].items()),'Calibration source changed during execution')
        result.update(host_nvme_qos_unchanged=True,host_nvme_qos_us=int(before),host_reboot_tested=False,
            artifact_label=args.artifact_label,run_label=run_label,
            harness_source_sha256={name:hashlib.sha256((SOURCE/name).read_bytes()).hexdigest()
                                  for name in ('virtual_test_lab.py','vm_boot_probe.py','prepare_test_os.py')})
        build.atomic_json(build.AREA/('vm-cache-calibration-'+args.artifact_label+'-'+run_label+'.json'),result)
        print(json.dumps({'passed':True,'cache_calibration_cases':result['case_count']}),flush=True)
    if cache_profile:
        result=json.loads((directory/'runs'/run_label/'vm-cache-fault-result.json').read_text())
        require(result.get('passed') is True,'Cache-backed profile recovery did not pass')
        require(result['recovery']['root_uuid']!=host_uuid,'Expected a separate guest filesystem')
        require(all(hashlib.sha256((SOURCE/name).read_bytes()).hexdigest()==digest
                    for name,digest in result['source_sha256'].items()),'Executed cache-profile source changed')
        result.update(host_nvme_qos_unchanged=True,host_nvme_qos_us=int(before),host_filesystem_uuid_differs=True,
            host_reboot_tested=False,recorded_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),
            calibration_report_sha256=hashlib.sha256(calibration_path.read_bytes()).hexdigest(),
            harness_source_sha256=hashlib.sha256((SOURCE/'virtual_test_lab.py').read_bytes()).hexdigest(),
            artifact_label=args.artifact_label)
        build.atomic_json(build.AREA/('vm-cache-fault-'+args.artifact_label+'-'+run_label+'.json'),result)
        print(json.dumps({'passed':True,'cache_loss_exercised':result['volatile_device_write_loss_exercised']}),flush=True)
    if args.step=='boot':
        result=json.loads((directory/'runs'/run_label/'vm-recovery-result.json').read_text())
        require(result.get('passed') is True,'Virtual recovery did not pass')
        require(all(b['root_uuid']!=host_uuid for b in result['boots']),
                'Guest Btrfs UUID must differ from the host workspace filesystem')
        result.update(schema_version=1,host_nvme_qos_unchanged=True,host_nvme_qos_us=int(before),
            host_filesystem_uuid_differs=True,
            host_reboot_tested=False,stock_guest_kernel_hardware_compatibility_qualified=False,
            recorded_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),
            artifact_label=args.artifact_label,
            image_build=json.loads((directory/'image-build.json').read_text()),
            source_hashes={name:hashlib.sha256((SOURCE/name).read_bytes()).hexdigest()
                for name in ('virtual_test_lab.py','vm_image_builder.py','vm_boot_probe.py','prepare_test_os.py')})
        build.atomic_json(build.AREA/('vm-recovery-'+args.artifact_label+'-'+run_label+'.json'),result)
        print(json.dumps({'passed':True,'run_label':run_label,'boot_checks':3}),flush=True)
    if args.step=='profile-test':
        result=json.loads((directory/'runs'/run_label/'vm-profile-fault-result.json').read_text())
        require(result.get('passed') is True,'Virtual profile recovery did not pass')
        require(all(c['recovery']['root_uuid']!=host_uuid for c in result['cases']),
                'Guest Btrfs UUID must differ from the host workspace filesystem')
        result.update(schema_version=1,host_nvme_qos_unchanged=True,host_nvme_qos_us=int(before),
            host_filesystem_uuid_differs=True,host_reboot_tested=False,
            stock_guest_kernel_hardware_compatibility_qualified=False,
            recorded_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),artifact_label=args.artifact_label,
            image_build=json.loads((directory/'image-build.json').read_text()),
            source_hashes={name:hashlib.sha256((SOURCE/name).read_bytes()).hexdigest()
                for name in ('virtual_test_lab.py','vm_image_builder.py','vm_boot_probe.py','vm_profile_guest.py',
                             'vm_profile_faults.py','prepare_test_os.py')})
        build.atomic_json(build.AREA/('vm-profile-'+args.artifact_label+'-'+run_label+'.json'),result)
        print(json.dumps({'passed':True,'run_label':run_label,'profile_cases':len(result['cases'])}),flush=True)


if __name__=='__main__':main()
