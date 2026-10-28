"""Real-systemd lifecycle in the private prepared Arch OS; host NVMe is never bound writable."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import shutil
import time
import argparse
import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import prepare_test_os as build

PACKAGE = ROOT

INSIDE = r'''import hashlib,json,os,shutil,subprocess,time,traceback
from pathlib import Path
OUT=Path('/var/lib/bc250-qualification');OUT.mkdir(exist_ok=True)
STATE=OUT/'phase.json'
QOS=Path('/sys/class/nvme/nvme0/power/pm_qos_latency_tolerance_us')
POWER='bc250-nvme-power.service';TIMER='bc250-btrfs-repack.timer';WORKER='bc250-btrfs-repack.service'
MANIFEST=Path('/var/lib/bc250-storage-defaults/installation.json')
def run(*a):
 p=subprocess.run(list(a),capture_output=True,text=True,timeout=150)
 if p.returncode:raise RuntimeError(repr(a)+': '+p.stdout[-10000:]+p.stderr[-10000:])
 return p.stdout.strip()
def cli(*a):return run('/usr/bin/python3','/pkg/install.py',*a)
def unit(name):
 return dict(line.split('=',1) for line in run('systemctl','show',name,'-p','ActiveState','-p','SubState','-p','Result','-p','UnitFileState').splitlines())
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def save(p,data):
 temp=p.with_suffix('.pending')
 with temp.open('w') as f:json.dump(data,f,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
 os.replace(temp,p)
 fd=os.open(p.parent,os.O_RDONLY|os.O_DIRECTORY)
 try:os.fsync(fd)
 finally:os.close(fd)
report=json.loads(STATE.read_text()) if STATE.exists() else {'checks':[],'phase':0,'passed':False}
try:
 assert Path('/proc/1/comm').read_text().strip()=='systemd'
 assert (QOS.parent.parent/'qualification-fixture').read_text()=='isolated-stage0\n'
 assert not Path('/run/host/run/systemd/private').exists()
 uidmap=Path('/proc/self/uid_map').read_text().strip()
 assert int(uidmap.split()[1])>65535
 if report['phase']==0:
  initial=QOS.read_text().strip()
  assert initial=='100000' and not MANIFEST.exists(), 'Unexpected initial state: qos='+repr(initial)+', manifest='+str(MANIFEST.exists())
  report.update(real_systemd=True,simulated_nvme_sysfs=True,separate_kernel=False,host_reboot_tested=False,
   uid_mapping_isolated=True,guest_python=run('python3','--version'),
   guest_systemd=run('/usr/lib/systemd/systemd','--version').splitlines()[0])
  cli('--check');cli();assert QOS.read_text().strip()=='5000'
  manifest=MANIFEST.read_bytes();cli();assert MANIFEST.read_bytes()==manifest
  assert unit(POWER)['ActiveState']=='active' and unit(TIMER)['ActiveState']=='active'
  report['checks']+=['fresh-install-real-systemd','repeat-apply','power-and-timer-active']
  run('systemctl','stop',POWER);assert QOS.read_text().strip()=='100000'
  run('systemctl','start',POWER);assert QOS.read_text().strip()=='5000'
  QOS.write_text('100000');run('/bin/sh','/usr/lib/systemd/system-sleep/90-bc250-nvme-power','post')
  assert QOS.read_text().strip()=='5000'
  report['checks']+=['real-service-stop-start','simulated-controller-reset-real-resume-hook']
  run('systemctl','stop',TIMER)
  fixture_dir=Path('/opt/bc250-qualification');fixture_dir.mkdir()
  fixture=fixture_dir/'libpython-fixture.so'
  source=next(Path('/usr/lib').glob('libpython3.*.so.1.0')).resolve()
  shutil.copyfile(source,fixture);fixture.chmod(0o644)
  before=digest(fixture)
  config=Path('/etc/bc250-storage-defaults.json');original=config.read_bytes()
  cfg=json.loads(original);cfg.update(roots=[str(fixture_dir)],quiet_seconds=0,max_load=100000,
      max_bytes_per_run=16*2**20,max_bytes_per_day=32*2**20,max_run_seconds=60)
  try:
   config.write_text(json.dumps(cfg))
   run('systemctl','start',WORKER)
   assert unit(WORKER)['Result']=='success'
   result=json.loads(Path('/var/lib/bc250-storage-defaults/last-run.json').read_text())
   assert result['verified_files']==1 and result['charged_bytes']<=cfg['max_bytes_per_run']
   assert digest(fixture)==before
   report['worker_fixture']={k:result[k] for k in ('verified_files','processed_bytes','charged_bytes','retry_bytes','counts')}
  finally:config.write_bytes(original)
  report['checks'].append('actual-worker-service-private-ELF')
  cli('--uninstall');assert QOS.read_text().strip()=='100000'
  cli('--uninstall');assert not json.loads(MANIFEST.read_text())['active']
  cli();assert QOS.read_text().strip()=='5000'
  report['checks']+=['real-service-undo','repeat-undo','reinstall']
  report.update(phase=1,reset_count_before=int((OUT/'reset-count').read_text()),
                first_init_start=Path('/proc/1/stat').read_text().split()[21])
  save(STATE,report)
  run('systemctl','reboot','--no-block')
 else:
  assert report['phase']==1
  assert int((OUT/'reset-count').read_text())==report['reset_count_before']+1
  assert Path('/proc/1/stat').read_text().split()[21]!=report['first_init_start']
  assert QOS.read_text().strip()=='5000'
  assert unit(POWER)['ActiveState']=='active' and unit(TIMER)['ActiveState']=='active'
  assert unit(POWER)['UnitFileState']=='enabled' and unit(TIMER)['UnitFileState']=='enabled'
  report['checks'].append('guest-reboot-enabled-services-reapply-policy')
  cli('--uninstall');assert QOS.read_text().strip()=='100000'
  report['checks'].append('undo-after-guest-reboot')
  report.pop('mount_diagnostic',None)
  report.update(phase=2,passed=True)
  save(STATE,report);save(OUT/'result.json',report)
  run('systemctl','poweroff','--no-block')
except BaseException as error:
 report.update(passed=False,error=str(error),traceback=traceback.format_exc())
 save(OUT/'result.json',report)
 subprocess.run(['journalctl','--no-pager','-u',WORKER,'-u',POWER,'-u','bc250-qualification-reset.service'],stdout=(OUT/'service-errors.log').open('w'))
 subprocess.run(['systemctl','poweroff','--no-block'])
 raise
'''

RESET = r'''from pathlib import Path
import subprocess
# nspawn assembles /sys/class after early custom mounts. Attach the private
# fixture inside the guest mount namespace once its own systemd has started.
subprocess.run(['mount','--bind','/qualification/fake-class','/sys/class/nvme'],check=True)
assert Path('/sys/class/nvme/nvme0/qualification-fixture').read_text()=='isolated-stage0\n'
p=Path('/var/lib/bc250-qualification');p.mkdir(exist_ok=True)
counter=p/'reset-count'
counter.write_text(str((int(counter.read_text()) if counter.exists() else 0)+1))
Path('/sys/class/nvme/nvme0/power/pm_qos_latency_tolerance_us').write_text('100000')
'''


def prepare(guest, private):
    for directory in ('device', 'power'):
        (private / directory).mkdir(parents=True, exist_ok=False)
    for name, value in {'model':'PNY CS2241 1TB SSD','device/current_link_speed':'5.0 GT/s PCIe',
                        'device/current_link_width':'2','power/pm_qos_latency_tolerance_us':'100000'}.items():
        (private/name).write_text(value)
    (private/'qualification-fixture').write_text('isolated-stage0\n')
    qualification = guest / 'qualification';qualification.mkdir()
    (qualification/'inside.py').write_text(INSIDE)
    (qualification/'reset.py').write_text(RESET)
    units = guest / 'etc/systemd/system'
    (units/'bc250-qualification-reset.service').write_text('''[Unit]
Description=Reset simulated NVMe policy in the qualification guest
Before=bc250-nvme-power.service bc250-qualification.service
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /qualification/reset.py
[Install]
WantedBy=multi-user.target
''')
    (units/'bc250-qualification.service').write_text('''[Unit]
Description=Private BC-250 storage lifecycle qualification
After=multi-user.target bc250-qualification-reset.service
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /qualification/inside.py
TimeoutStartSec=240
[Install]
WantedBy=multi-user.target
''')
    wants = units / 'multi-user.target.wants';wants.mkdir(exist_ok=True)
    for name in ('bc250-qualification-reset.service','bc250-qualification.service'):
        (wants/name).symlink_to('../'+name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace', type=Path, required=True)
    args = parser.parse_args()
    build.configure(args.workspace)
    build.guards()
    guest = build.GUEST
    require = build.require
    require((build.AREA/'dependencies.json').is_file() and not (build.AREA/'INCOMPLETE').exists(),
            'Complete signed guest dependency preparation first')
    require(not (guest/'qualification').exists(), 'Use a fresh prepared OS; failed qualification state is preserved')
    require(not (guest/'etc/bc250-storage-defaults.json').exists() and
            not (guest/'var/lib/bc250-storage-defaults').exists(), 'Guest is not a fresh storage baseline')
    source_files=['install.py','install_transaction.py','storage_defaults_power.py','storage_defaults_repack.py','config.json',
                  'systemd/bc250-nvme-power.service','systemd/bc250-btrfs-repack.service','systemd/bc250-btrfs-repack.timer',
                  'systemd/90-bc250-nvme-power']
    for name in source_files:
        require((PACKAGE/name).is_file() and not (PACKAGE/name).is_symlink(), 'Unsafe package source')
    actual = Path('/sys/class/nvme/nvme0/power/pm_qos_latency_tolerance_us')
    before = actual.read_text().strip()
    require(before=='5000', 'Working host drive policy must remain at 5000 us')
    private = build.AREA/'fake-nvme'
    prepare(guest,private)
    qualification = guest/'qualification'
    fake_class=qualification/'fake-class';fake_class.mkdir()
    shutil.copytree(private,fake_class/'nvme0')
    private_package=qualification/'package';private_package.mkdir()
    for name in source_files:
        target=private_package/name;target.parent.mkdir(exist_ok=True)
        shutil.copyfile(PACKAGE/name,target);target.chmod(0o644)
        require(target.read_bytes()==(PACKAGE/name).read_bytes(),'Package copy changed')
    # Dependency preparation already shifted the guest root. Newly staged test
    # files must use that same physical UID/GID; no host UID identity is shared.
    owner=guest.stat().st_uid;group=guest.stat().st_gid
    require(owner>65535 and owner==group, 'Guest must retain a distinct user range')
    for parent,dirs,files in os.walk(qualification,followlinks=False):
        for name in dirs+files:os.chown(Path(parent)/name,owner,group,follow_symlinks=False)
        os.chown(parent,owner,group,follow_symlinks=False)
    for name in ('bc250-qualification-reset.service','bc250-qualification.service'):
        os.chown(guest/'etc/systemd/system'/name,owner,group,follow_symlinks=False)
        os.chown(guest/'etc/systemd/system/multi-user.target.wants'/name,owner,group,follow_symlinks=False)
    command=build.container_args()+['--bind-ro='+str(private_package)+':/pkg','--boot',
                                   'systemd.show_status=no','systemd.dump_core=no']
    started=time.monotonic()
    try:
        proc=subprocess.run(command,timeout=420)
    finally:
        require(actual.read_text().strip()==before,'Host NVMe policy changed during isolated qualification')
    result_path=guest/'var/lib/bc250-qualification/result.json'
    require(result_path.is_file(),'Guest produced no result; preserve the workspace and inspect its log')
    result=json.loads(result_path.read_text())
    result.update(schema_version=1,container_exit=proc.returncode,elapsed_s=time.monotonic()-started,
        host_nvme_qos_unchanged=True,host_nvme_qos_us=int(before),
        user_namespace_ownership='chown',separate_volume=False,device_power_loss_tested=False,
        source_hashes={name:hashlib.sha256((PACKAGE/name).read_bytes()).hexdigest() for name in source_files},
        harness_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        builder_sha256=hashlib.sha256(Path(build.__file__).read_bytes()).hexdigest())
    build.atomic_json(build.AREA/'qualification-result.json',result)
    print(json.dumps(result),flush=True)
    require(proc.returncode==0 and result.get('passed'),'Guest qualification failed')


if __name__=='__main__':main()
