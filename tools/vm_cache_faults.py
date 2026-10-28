"""Apply a calibrated volatile-cache cut to a real, disposable installer VM."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import errno
import vm_boot_probe as probe
import vm_profile_faults as profile
from calibrate_volatile_disk import Backend

LAB=Path('/vmlab')


def logical_sparse_digest(path):
    """Canonical size + nonzero 4 KiB blocks, independent of allocated zero runs."""
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        size=os.fstat(fd).st_size;digest=hashlib.sha256(str(size).encode()+b'\n')
        offset=0;processed=0
        while offset<size:
            try:start=os.lseek(fd,offset,os.SEEK_DATA)
            except OSError as error:
                if error.errno==errno.ENXIO:break
                raise
            end=min(os.lseek(fd,start,os.SEEK_HOLE),size)
            position=max(start-start%4096,processed)
            while position<end:
                data=os.pread(fd,min(4096,size-position),position)
                probe.require(data,'Sparse image truncated')
                if any(data):digest.update(f'{position}:{len(data)}\n'.encode()+data)
                position+=4096
            processed=position;offset=end
        return dict(sha256=digest.hexdigest(),virtual_bytes=size,
                    format='v1: virtual size, offsets/lengths and bytes of nonzero 4 KiB logical blocks; not full-image SHA256')
    finally:os.close(fd)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-label',required=True,type=probe.validate_label)
    args=parser.parse_args()
    probe.require(Path('/run/host').exists(),'Run through virtual_test_lab.py')
    manifest=json.loads((LAB/'image-build.json').read_text())
    probe.require(manifest.get('storage_profile_fixture') is True,'Build the profile fixture first')
    # This prerequisite is exported by the host wrapper only after matching the
    # calibration's two executed source hashes to the staged model/client files.
    calibration=json.loads((LAB/'matched-cache-calibration.json').read_text())
    probe.require(calibration.get('passed') and calibration.get('actual_backend_sigkill_tested') and
                  calibration.get('armed_cache_cut_tested'),
                  'A matching independent cache calibration is required')
    for name,digest in calibration['source_sha256'].items():
        probe.require(hashlib.sha256((LAB/name).read_bytes()).hexdigest()==digest,'Disk model changed since calibration')
    base=LAB/'baseline.raw';probe.check_base(base);before=probe.sparse_fingerprint(base)
    runs=LAB/'runs';runs.mkdir(mode=0o700,exist_ok=True)
    probe.require(not runs.is_symlink(),'Unsafe runs directory')
    run=runs/args.run_label;run.mkdir(mode=0o700)
    stable=run/'stable.raw'
    probe.require(not stable.exists() and not stable.is_symlink(),'Existing stable image preserved')
    subprocess.run(['cp','--reflink=never','--sparse=always',str(base),str(stable)],check=True,timeout=120)
    stable.chmod(0o600)
    probe.require(stable.stat().st_size==base.stat().st_size,'Stable image has wrong capacity')
    logical=logical_sparse_digest(base)
    probe.require(logical_sparse_digest(stable)==logical,'New stable copy differs from protected baseline')
    backend=Backend(run,stable,'install-cut',cache_mib=64)
    try:
        witness={}
        def device_fault():
            witness['at_checkpoint']=backend.stats()
            witness['armed']=backend.arm()
            witness['cut']=backend.wait_armed_cut(timeout=60)
            return dict(method='armed-next-ordinary-NBD-write',dropped_bytes=witness['cut']['dropped_bytes'],
                        trigger_bytes=witness['cut']['cut_trigger_bytes'])
        interruption=profile.boot(None,run/'install-cut.serial.log','cut-install','after-timer-enable',
                                  nbd_socket=backend.socket,before_guest_kill=device_fault)
        pre_cut=witness['at_checkpoint'];cut=witness['cut']
        probe.require(cut['dropped_bytes']>0 and cut['cache_limit_errors']==0,
                      'Unexpected disk-cache cut or capacity exhaustion')
    finally:backend.close()
    backend=Backend(run,stable,'recover',cache_mib=64)
    try:
        recovery=profile.boot(None,run/'recover.serial.log','recover',nbd_socket=backend.socket)
        after_recovery=backend.stats()
        probe.require(after_recovery['dirty_bytes']==0 and after_recovery['cache_limit_errors']==0,
                      'Orderly recovery shutdown left unflushed model data or exhausted its cache')
        recovery_stop=backend.cut()
    finally:backend.close()
    probe.require(probe.sparse_fingerprint(base)==before,'Protected baseline changed')
    report=dict(passed=True,case='installer-after-timer-enable',interruption=interruption,
        before_device_cut=pre_cut,device_cut=cut,recovery=recovery,recovery_device=after_recovery,
        recovery_stop=recovery_stop,volatile_device_write_loss_exercised=cut['dropped_bytes']>0,
        calibrated_model=True,separate_guest_kernel=True,real_systemd_pid1=True,
        base_fingerprint_unchanged=True,base_sparse_fingerprint=before,
        initial_copy_logical_digest=logical,
        physical_power_loss_tested=False,torn_writes_modeled=False,
        worker_device_faults_tested=False,performance_tested=False,
        package_sha256=manifest['package_sha256'],run_label=args.run_label,
        fault_scope='Pause installer at acknowledged checkpoint; cut cache after the next ordinary NBD write reply, then kill guest; host remains powered',
        calibration_source_sha256=calibration['source_sha256'],
        source_sha256={name:hashlib.sha256((LAB/name).read_bytes()).hexdigest() for name in
            ('vm_cache_faults.py','volatile_disk.py','calibrate_volatile_disk.py','vm_profile_faults.py','vm_boot_probe.py')})
    (run/'vm-cache-fault-result.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'passed':True,'dropped_device_cache_bytes':cut['dropped_bytes'],
                      'volatile_device_write_loss_exercised':report['volatile_device_write_loss_exercised']}),flush=True)


if __name__=='__main__':main()
