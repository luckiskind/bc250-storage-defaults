"""Build a new file-backed Btrfs recovery OS; runs only in the prepared private userspace."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess

LAB=Path('/vmlab')
SIZE=80*2**30


def digest(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def run(*args):
    subprocess.run(list(map(str,args)),check=True,timeout=300)


PROBE=r'''import hashlib,json,os,subprocess,traceback,uuid
from pathlib import Path
root=Path('/var/lib/bc250-vm-probe');root.mkdir(exist_ok=True)
state=root/'durable.json'
report={'passed':False,'physical_power_loss_tested':False}
try:
 assert Path('/proc/1/comm').read_text().strip()=='systemd'
 fstype=subprocess.check_output(['findmnt','-n','-o','FSTYPE','/'],text=True).strip()
 assert fstype=='btrfs'
 free=os.statvfs('/');assert free.f_bavail*free.f_frsize>=64*2**30
 fixture=Path('/opt/bc250-vm-fixture.bin')
 actual=hashlib.sha256(fixture.read_bytes()).hexdigest()
 expected=json.loads(Path('/opt/bc250-vm-reference.json').read_text())['sha256']
 assert actual==expected
 boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
 old=json.loads(state.read_text()) if state.exists() else {'count':0}
 if old['count']:
  assert old['fixture_sha256']==actual and old['boot_id']!=boot_id
 count=old['count']+1
 record={'count':count,'fixture_sha256':actual,'boot_id':boot_id,'nonce':old.get('nonce',uuid.uuid4().hex)}
 temporary=state.with_suffix('.pending')
 with temporary.open('w') as stream:
  json.dump(record,stream);stream.flush();os.fsync(stream.fileno())
 os.replace(temporary,state)
 fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
 try:os.fsync(fd)
 finally:os.close(fd)
 report.update(passed=True,kernel=os.uname().release,root_fstype=fstype,
  root_uuid=subprocess.check_output(['findmnt','-n','-o','UUID','/'],text=True).strip(),
  run_count=count,previous_count=old['count'],nonce=record['nonce'],fixture_sha256=actual,
  boot_id=boot_id,free_bytes=free.f_bavail*free.f_frsize,real_systemd_pid1=True)
except BaseException as error:report.update(error=str(error),traceback=traceback.format_exc())
print('BC250_VM_RESULT='+json.dumps(report),flush=True)
subprocess.run(['systemctl','poweroff','--no-block'],check=True)
'''


def main():
    assert os.geteuid()==0 and LAB.is_dir() and Path('/run/host').exists()
    root=LAB/'rootfs'
    if root.exists():raise RuntimeError('Existing rootfs is preserved; use a fresh build area')
    root.mkdir()
    sources=[Path('/'+name) for name in ('usr','etc','opt','home','root','srv','boot')]
    # New ordinary copies; no reflinks or links back to the source tree. Security
    # xattrs from a mapped container are not transferable host credentials.
    run('cp','-a','--reflink=never','--no-preserve=xattr,context',*sources,root)
    for name in ('var/lib','var/cache','var/log','var/tmp','dev','proc','sys','run','tmp','mnt'):
        (root/name).mkdir(parents=True,exist_ok=True)
    for name in ('tmp','var/tmp'):(root/name).chmod(0o1777)
    for name,target in {'bin':'usr/bin','sbin':'usr/bin','lib':'usr/lib','lib64':'usr/lib'}.items():
        (root/name).symlink_to(target)
    (root/'etc/machine-id').write_text('')
    (root/'etc/hostname').write_text('bc250-recovery-test\n')
    resolver=root/'etc/resolv.conf'
    if resolver.is_symlink():resolver.unlink()
    resolver.write_text('')
    (root/'etc/fstab').write_text('/dev/vda / btrfs defaults,compress=zstd:1 0 0\n')
    source=next(Path('/usr/lib').glob('libpython3.*.so.1.0')).resolve()
    fixture=root/'opt/bc250-vm-fixture.bin';shutil.copyfile(source,fixture)
    reference=dict(sha256=digest(fixture),bytes=fixture.stat().st_size)
    (root/'opt/bc250-vm-reference.json').write_text(json.dumps(reference))
    (root/'opt/bc250-vm-probe.py').write_text(PROBE)
    units=root/'etc/systemd/system'
    name='bc250-vm-probe.service'
    (units/name).write_text('''[Unit]
Description=Separate-kernel private Btrfs recovery probe
After=multi-user.target
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /opt/bc250-vm-probe.py
StandardOutput=tty
StandardError=tty
TTYPath=/dev/ttyS0
TimeoutStartSec=120
[Install]
WantedBy=multi-user.target
''')
    wants=units/'multi-user.target.wants';wants.mkdir(exist_ok=True)
    (wants/name).symlink_to('../'+name)
    versions=list(Path('/usr/lib/modules').glob('*/vmlinuz'))
    assert len(versions)==1
    kernel=versions[0]
    shutil.copyfile(kernel,LAB/'kernel')
    config=LAB/'mkinitcpio.conf'
    config.write_text('MODULES=(virtio_pci virtio_blk virtio_rng btrfs)\nBINARIES=()\nFILES=()\n'
                      'HOOKS=(base udev modconf block filesystems fsck)\nCOMPRESSION="zstd"\n'
                      'COMPRESSION_OPTIONS=(-T2 -3)\n')
    run('mkinitcpio','-k',kernel.parent.name,'-c',config,'-g',LAB/'initramfs.img')
    image=LAB/'baseline.raw'
    with image.open('xb') as stream:stream.truncate(SIZE)
    assert stat.S_ISREG(image.lstat().st_mode) and not image.is_symlink()
    run('mkfs.btrfs','--nodiscard','--data','single','--metadata','dup','--label','BC250_RECOVERY',
        '--rootdir',root,'--compress','zstd:1',image)
    image.chmod(0o400)
    report=dict(image_virtual_bytes=SIZE,kernel_release=kernel.parent.name,kernel_sha256=digest(LAB/'kernel'),
                initramfs_sha256=digest(LAB/'initramfs.img'),fixture=reference,
                rootdir_security_xattrs_copied=False,image_is_regular_file=True,
                host_device_formatted=False,guest_not_yet_booted=True)
    (LAB/'image-build.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report),flush=True)


if __name__=='__main__':main()
