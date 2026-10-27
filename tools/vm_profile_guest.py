"""Embed a storage-profile recovery fixture into a NEW virtual image, never a host root."""
import json
from pathlib import Path
import shutil

PACKAGE_FILES=('install.py','install_transaction.py','storage_defaults_power.py',
    'storage_defaults_repack.py','config.json','systemd/bc250-nvme-power.service',
    'systemd/bc250-btrfs-repack.service','systemd/bc250-btrfs-repack.timer',
    'systemd/90-bc250-nvme-power')

RESET=r'''import subprocess
from pathlib import Path
assert Path('/opt/bc250-profile-vm/fixture-marker').read_text()=='disposable-virtual-image\n'
subprocess.run(['modprobe','nvme'],check=True)
target=Path('/sys/class/nvme')
assert target.is_dir() and not list(target.iterdir()), 'Unexpected real NVMe controller in isolated VM'
source=Path('/opt/bc250-profile-vm/fake-class')
assert (source/'nvme0/qualification-fixture').read_text()=='isolated-stage0\n'
subprocess.run(['mount','--bind',str(source),str(target)],check=True)
Path('/sys/class/nvme/nvme0/power/pm_qos_latency_tolerance_us').write_text('100000')
'''

INSIDE=r'''import hashlib,json,os,subprocess,sys,time,traceback
from pathlib import Path
ROOT=Path('/opt/bc250-profile-vm')
sys.path.insert(0,str(ROOT/'package'))
import install as app
params=dict(p.split('=',1) for p in Path('/proc/cmdline').read_text().split() if '=' in p)
mode=params['bc250.mode'];point=params.get('bc250.point','none');token=params['bc250.token']
expected=params.get('bc250.expected','removed')
report=dict(passed=False,mode=mode,point=point,token=token)

def command(*args):
 p=subprocess.run(list(args),capture_output=True,text=True,timeout=150)
 if p.returncode:raise RuntimeError(repr(args)+': '+p.stdout[-4000:]+p.stderr[-4000:])
 return p.stdout.strip()

def cli(*args):return command('/usr/bin/python3',str(ROOT/'package/install.py'),*args)

def cut(name):
 if name!=point:return
 # Serial acknowledgement only. No disk marker, sync or orderly guest shutdown.
 print('BC250_VM_CUT='+json.dumps(dict(point=name,token=token,mode=mode)),flush=True)
 while True:time.sleep(1)

def instrument():
 oldrun=app.run
 def run(args):
  result=oldrun(args)
  if list(args)==['systemctl','enable','--now',app.POWER]:cut('after-power-enable')
  if list(args)==['systemctl','enable','--now',app.TIMER]:cut('after-timer-enable')
  return result
 app.run=run
 oldmanifest=app.write_manifest
 def manifest(data):
  oldmanifest(data)
  if point=='committed-missing-timer-link':
   # Explicit compatibility injection for the observed pre-fix failure. This
   # extra case is not counted as naturally occurring loss in the fixed build.
   link=app.UNIT_DIRECTORY/'timers.target.wants'/app.TIMER
   assert link.is_symlink() and link.resolve()==app.UNIT_DIRECTORY/app.TIMER
   link.unlink();app.sync_service_links()
   cut('committed-missing-timer-link')
  cut('committed-manifest')
 app.write_manifest=manifest
 olddelete=app.transaction.Transaction.delete_target
 count=0
 def delete(self,entry):
  nonlocal count
  olddelete(self,entry);count+=1
  if count==1:cut('deleted-1')
 app.transaction.Transaction.delete_target=delete
 oldwrite=app.write_new
 def write(path,data,mode):
  if point=='partial-stage-1':
   fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
   try:os.write(fd,data[:max(1,len(data)//2)])
   finally:os.close(fd)
   cut('partial-stage-1')
  oldwrite(path,data,mode)
 app.write_new=write

try:
 assert Path('/proc/1/comm').read_text().strip()=='systemd'
 assert (ROOT/'fixture-marker').read_text()=='disposable-virtual-image\n'
 qos=Path('/sys/class/nvme/nvme0/power/pm_qos_latency_tolerance_us')
 assert (qos.parent.parent/'qualification-fixture').read_text()=='isolated-stage0\n'
 assert command('findmnt','-n','-o','FSTYPE','/')=='btrfs'
 reference=json.loads(Path('/opt/bc250-vm-reference.json').read_text())
 assert hashlib.sha256(Path('/opt/bc250-vm-fixture.bin').read_bytes()).hexdigest()==reference['sha256']
 for name,sha in json.loads((ROOT/'package-sha256.json').read_text()).items():
  assert hashlib.sha256((ROOT/'package'/name).read_bytes()).hexdigest()==sha,name
 if mode=='cut-remove':cli()
 instrument()
 if mode=='cut-install':
  with app.transaction.installation_lock(app.STATE):app.install()
  raise RuntimeError('Requested installation checkpoint was not reached')
 elif mode=='cut-remove':
  with app.transaction.installation_lock(app.STATE):app.uninstall()
  raise RuntimeError('Requested removal checkpoint was not reached')
 elif mode=='cut-recover':
  with app.transaction.installation_lock(app.STATE):app.recover()
  raise RuntimeError('Requested recovery checkpoint was not reached')
 elif mode=='recover':
  assert app.transaction.pending_path(app.STATE).is_file(),'Expected an interrupted transaction'
  if params.get('bc250.case')=='manifest-committed':
   for unit in (app.POWER,app.TIMER):
    assert command('systemctl','is-enabled',unit)=='enabled'
    assert command('systemctl','is-active',unit)=='active'
   assert qos.read_text().strip()=='5000'
   report['committed_startup_before_recovery_verified']=True
  elif params.get('bc250.case')=='legacy-missing-timer-link':
   assert not (app.UNIT_DIRECTORY/'timers.target.wants'/app.TIMER).exists()
   assert subprocess.run(['systemctl','is-enabled','--quiet',app.TIMER]).returncode!=0
   report['missing_timer_link_before_recovery_verified']=True
  cli('--recover');cli('--recover')
  assert not app.transaction.pending_path(app.STATE).exists()
  assert all(not list(p.glob('.bc250-storage-*')) for p in {t.parent for t in app.payloads()})
  if expected=='installed':
   manifest=json.loads(app.MANIFEST.read_text());assert manifest['active']
   app.check_owned(manifest)
   for unit in (app.POWER,app.TIMER):
    assert command('systemctl','is-active',unit)=='active'
    assert command('systemctl','is-enabled',unit)=='enabled'
   assert qos.read_text().strip()=='5000'
   cli('--uninstall')
  else:assert expected=='removed'
  assert qos.read_text().strip()=='100000'
  assert all(not t.exists() for t in app.payloads())
  for unit in (app.POWER,app.TIMER):
   assert subprocess.run(['systemctl','is-active','--quiet',unit]).returncode!=0
   assert subprocess.run(['systemctl','is-enabled','--quiet',unit]).returncode!=0
  assert not json.loads(app.MANIFEST.read_text()).get('active') if app.MANIFEST.exists() else True
  report.update(passed=True,outcome=expected,repeat_recovery_passed=True,final_removed=True,
   root_uuid=command('findmnt','-n','-o','UUID','/'),kernel=os.uname().release,
   boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip())
 else:raise RuntimeError('Unknown VM mode')
except BaseException as error:report.update(error=str(error),traceback=traceback.format_exc())
print('BC250_VM_RESULT='+json.dumps(report),flush=True)
subprocess.run(['systemctl','poweroff','--no-block'],check=True)
'''


def prepare(root,package):
    import hashlib
    private=root/'opt/bc250-profile-vm'
    private.mkdir(mode=0o700)
    (private/'fixture-marker').write_text('disposable-virtual-image\n')
    dest=private/'package';dest.mkdir()
    hashes={}
    for name in PACKAGE_FILES:
        source=package/name
        if source.is_symlink() or not source.is_file():raise RuntimeError('Unsafe package source')
        target=dest/name;target.parent.mkdir(exist_ok=True)
        shutil.copyfile(source,target)
        hashes[name]=hashlib.sha256(target.read_bytes()).hexdigest()
    (private/'package-sha256.json').write_text(json.dumps(hashes))
    ctrl=private/'fake-class/nvme0'
    for name,value in {'model':'PNY CS2241 1TB SSD','device/current_link_speed':'5.0 GT/s PCIe',
            'device/current_link_width':'2','power/pm_qos_latency_tolerance_us':'100000',
            'qualification-fixture':'isolated-stage0\n'}.items():
        path=ctrl/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text(value)
    (private/'reset.py').write_text(RESET)
    (root/'opt/bc250-vm-probe.py').write_text(INSIDE)
    units=root/'etc/systemd/system'
    (units/'bc250-vm-reset.service').write_text('''[Unit]
Description=Reset simulated controller in isolated virtual image
Before=bc250-nvme-power.service bc250-vm-probe.service
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /opt/bc250-profile-vm/reset.py
[Install]
WantedBy=multi-user.target
''')
    (units/'multi-user.target.wants/bc250-vm-reset.service').symlink_to('../bc250-vm-reset.service')
    # Require successful attachment of the simulated controller before the probe.
    drop=units/'bc250-vm-probe.service.d';drop.mkdir()
    (drop/'fixture.conf').write_text('[Unit]\nRequires=bc250-vm-reset.service\nAfter=bc250-vm-reset.service\n')
