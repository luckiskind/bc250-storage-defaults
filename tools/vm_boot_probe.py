"""Boot disposable qcow2 overlays against a read-only regular-file baseline."""
import hashlib
import argparse
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time
import re
import uuid

LAB=Path('/vmlab')
RUN=None


def require(condition,message):
    if not condition:raise RuntimeError(message)


def check_base(path):
    s=path.lstat()
    require(stat.S_ISREG(s.st_mode) and not path.is_symlink() and s.st_mode&0o222==0,
            'Baseline must be a read-only regular file')


def validate_label(label):
    require(re.fullmatch('[a-z0-9][a-z0-9_-]{0,63}',label) is not None,'Invalid private run label')
    return label


def sparse_fingerprint(path):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    digest=hashlib.sha256();ranges=0;data_bytes=0
    try:
        size=os.fstat(fd).st_size;digest.update(str(size).encode()+b'\n');offset=0
        while offset<size:
            try:start=os.lseek(fd,offset,os.SEEK_DATA)
            except OSError as error:
                if error.errno==6:break
                raise
            end=min(os.lseek(fd,start,os.SEEK_HOLE),size)
            digest.update(f'{start}:{end}\n'.encode());position=start
            while position<end:
                data=os.pread(fd,min(2**20,end-position),position)
                if not data:raise RuntimeError('Image truncated during fingerprinting')
                digest.update(data);position+=len(data)
            ranges+=1;data_bytes+=end-start;offset=end
        return dict(sha256=digest.hexdigest(),data_ranges=ranges,data_bytes=data_bytes,virtual_bytes=size)
    finally:os.close(fd)


def boot(overlay,label,diagnostic=False):
    manifest=json.loads((LAB/'image-build.json').read_text())
    log=RUN/(label+'.serial.log')
    for name,key in (('kernel','kernel_sha256'),('initramfs.img','initramfs_sha256')):
        with (LAB/name).open('rb') as stream:
            require(hashlib.file_digest(stream,'sha256').hexdigest()==manifest[key],'Boot artifact hash changed')
    args=['qemu-system-x86_64','-accel','tcg,thread=multi','-machine','q35','-cpu','max','-smp','2','-m','768',
          '-display','none','-vga','none','-nic','none','-serial','stdio','-monitor','none',
          '-sandbox','on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny',
          '-kernel',str(LAB/'kernel'),'-initrd',str(LAB/'initramfs.img'),
          '-drive','file='+str(overlay)+',if=virtio,format=qcow2,cache=writeback',
          '-object','rng-random,filename=/dev/urandom,id=rng0','-device','virtio-rng-pci,rng=rng0',
          '-append','root=/dev/vda rootfstype=btrfs rootflags=compress=zstd:1 rw console=ttyS0 '
                    'systemd.show_status=no systemd.log_color=no loglevel=4 '
                    'systemd.mask=serial-getty@ttyS0.service']
    started=time.monotonic()
    if diagnostic:args[-1]+=' systemd.log_target=console systemd.log_level=debug'
    with log.open('xb') as output:
        try:
            proc=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=output,stderr=subprocess.STDOUT,
                                timeout=120 if diagnostic else 300)
        except subprocess.TimeoutExpired:
            if not diagnostic:raise
            print(json.dumps({'diagnostic_boot':'deadline-reached','overlay_preserved':True}),flush=True)
            return
    results=[]
    for line in log.read_text(errors='replace').splitlines():
        if 'BC250_VM_RESULT=' in line:results.append(json.loads(line.split('BC250_VM_RESULT=',1)[1]))
    if proc.returncode or len(results)!=1 or not results[0].get('passed'):
        raise RuntimeError(f'{label} failed; inspect {log.name}; exit={proc.returncode}; results={results}')
    result=results[0]
    require(result['kernel']==manifest['kernel_release'] and result['kernel']!=os.uname().release,
            'Expected a separate pinned guest kernel')
    uuid.UUID(result['root_uuid'])
    result.update(elapsed_s=time.monotonic()-started,qemu_exit=proc.returncode)
    print(json.dumps({'boot':label,**result}),flush=True)
    return result


def new_overlay(path):
    if path.exists() or path.is_symlink():raise RuntimeError('Existing overlay is preserved')
    subprocess.run(['qemu-img','create','-f','qcow2','-F','raw','-b',str(LAB/'baseline.raw'),str(path)],check=True)
    assert stat.S_ISREG(path.lstat().st_mode) and not path.is_symlink()


def main():
    global RUN
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--diagnostic',action='store_true')
    parser.add_argument('--run-label',required=True)
    args=parser.parse_args()
    require(Path('/run/host').exists(),'Run through the private virtual_test_lab wrapper')
    validate_label(args.run_label)
    runs=LAB/'runs';runs.mkdir(mode=0o700,exist_ok=True)
    require(not runs.is_symlink(),'Unsafe runs directory')
    RUN=runs/args.run_label;RUN.mkdir(mode=0o700)
    base=LAB/'baseline.raw';check_base(base)
    if args.diagnostic:
        overlay=RUN/'diagnostic.qcow2';new_overlay(overlay)
        boot(overlay,'diagnostic-boot',diagnostic=True)
        return
    before=sparse_fingerprint(base)
    working=RUN/'working.qcow2';new_overlay(working)
    first=boot(working,'first-boot-qualified');assert first['previous_count']==0 and first['run_count']==1
    second=boot(working,'second-boot-qualified')
    assert second['previous_count']==1 and second['run_count']==2 and first['nonce']==second['nonce']
    assert first['boot_id']!=second['boot_id']
    reset=RUN/'reset.qcow2';new_overlay(reset)
    third=boot(reset,'reset-to-baseline-qualified')
    assert third['previous_count']==0 and third['run_count']==1 and third['nonce']!=first['nonce']
    assert sparse_fingerprint(base)==before
    require(len({b['root_uuid'] for b in (first,second,third)})==1,'Unexpected baseline volume identity')
    report=dict(passed=True,separate_guest_kernel=True,separate_btrfs_volume=True,
        real_systemd_pid1=True,software_cpu_emulation=True,physical_power_loss_tested=False,
        abrupt_guest_shutdown_tested=False,orderly_reboot_persistence_passed=True,
        fresh_overlay_reset_passed=True,base_fingerprint_unchanged=True,
        base_sparse_fingerprint=before,boots=[first,second,third],
        sparse_fingerprint_format='v1: virtual size, data range offsets/lengths and data bytes; not full-image SHA256',
        run_label=args.run_label,
        fault_model='none; orderly guest shutdown/restart and overlay reset only')
    (RUN/'vm-recovery-result.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report),flush=True)


if __name__=='__main__':main()
