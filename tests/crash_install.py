#!/usr/bin/env python3
"""SIGKILL the actual installer at persistent boundaries, inside a private Btrfs root.

This is process-interruption testing, not a host reboot or device power-loss test.
Service management and controller sysfs are simulated by integration_install.py.
"""
import argparse
from pathlib import Path
from integration_install import run_isolated

BOOTSTRAP = r'''
import os,signal,sys
sys.path.insert(0,'/pkg')
import install as app
point=sys.argv.pop(1)
count=0
def die():os.kill(os.getpid(),signal.SIGKILL)
original_writer=app.write_new
def writer(path,data,mode):
    global count
    count+=1
    if point=='partial-stage-1' and count==1:
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        os.write(fd,data[:max(1,len(data)//2)]);os.fsync(fd)
        app.transaction.sync_directory(path.parent)
        die()
    original_writer(path,data,mode)
    if point=='staged-'+str(count):die()
app.write_new=writer
original_publish=app.transaction.Transaction.publish
published=0
def publish(self,*args,**kwargs):
    global published
    original_publish(self,*args,**kwargs);published+=1
    if point=='published-'+str(published):die()
app.transaction.Transaction.publish=publish
original_phase=app.transaction.Transaction.phase
def phase(self,name,**changes):
    original_phase(self,name,**changes)
    if point=='phase-'+name:die()
app.transaction.Transaction.phase=phase
original_run=app.run
def run(args):
    value=original_run(args)
    key=' '.join(map(str,args))
    if point=='after-power-enable' and key=='systemctl enable --now '+app.POWER:die()
    if point=='after-timer-enable' and key=='systemctl enable --now '+app.TIMER:die()
    if point=='after-timer-disable' and key=='systemctl disable --now '+app.TIMER:die()
    if point=='after-worker-stop' and key=='systemctl stop '+app.WORKER:die()
    if point=='after-power-disable' and key=='systemctl disable --now '+app.POWER:die()
    return value
app.run=run
original_manifest=app.write_manifest
def write_manifest(data):
    original_manifest(data)
    if point=='committed-manifest':die()
app.write_manifest=write_manifest
original_delete=app.transaction.Transaction.delete_target
deleted=0
def delete(self,entry):
    global deleted
    original_delete(self,entry);deleted+=1
    if point=='deleted-'+str(deleted):die()
app.transaction.Transaction.delete_target=delete
original_clean=app.transaction.Transaction.clean_stage
cleaned=0
def clean(self,entry):
    global cleaned
    original_clean(self,entry);cleaned+=1
    if point=='cleaned-'+str(cleaned):die()
app.transaction.Transaction.clean_stage=clean
app.main()
'''

INSIDE = r'''
import hashlib,json,os,signal,subprocess,sys,time
from pathlib import Path
sys.path.insert(0,'/pkg')
import install as app
bootstrap=Path('/kill-installer.py')
bootstrap.write_text(BOOTSTRAP)
qos=Path('/sys/class/nvme/nvme0/power/pm_qos_latency_tolerance_us')
pending=app.transaction.pending_path(app.STATE)
results=[]
def cli(*args):
    p=subprocess.run(['/usr/bin/python3','/pkg/install.py',*args],capture_output=True,text=True)
    if p.returncode:raise RuntimeError(p.stdout+p.stderr)
    return p
def assert_removed():
    assert qos.read_text()=='100000'
    assert not pending.exists()
    assert all(not target.exists() for target in app.payloads())
    assert all(not list(parent.glob('.bc250-storage-*')) for parent in {p.parent for p in app.payloads()})
    assert json.loads(Path('/run/fake-systemctl.json').read_text())['enabled']==[]
def kill(point,remove=False):
    args=['/usr/bin/python3',str(bootstrap),point]
    if remove:args.append('--uninstall')
    p=subprocess.run(args,capture_output=True,text=True,timeout=30)
    if p.returncode!=-signal.SIGKILL:raise RuntimeError(point+': '+p.stdout+p.stderr)
    assert pending.exists(),point
start=time.monotonic()
for point in (['partial-stage-1']+['staged-'+str(i) for i in range(1,8)]+
              ['published-'+str(i) for i in range(1,8)]+['phase-validating','phase-activating',
               'after-power-enable','after-timer-enable']):
    kill(point)
    cli('--recover')
    assert_removed()
    cli('--recover')
    assert_removed()
    results.append({'operation':'install','point':point,'outcome':'rolled-back'})
for point in ['committed-manifest']+['cleaned-'+str(i) for i in range(1,8)]:
    kill(point)
    cli('--recover')
    assert qos.read_text()=='5000'
    assert not pending.exists()
    assert all(target.is_file() for target in app.payloads())
    manifest=json.loads(app.MANIFEST.read_text());app.check_owned(manifest)
    cli('--uninstall');assert_removed()
    results.append({'operation':'install','point':point,'outcome':'committed-install-preserved'})
for point in (['after-timer-disable','after-worker-stop','after-power-disable','phase-removing']+
              ['deleted-'+str(i) for i in range(1,8)]+['committed-manifest']):
    cli()
    kill(point,remove=True)
    cli('--recover');assert_removed()
    cli('--recover');assert_removed()
    results.append({'operation':'remove','point':point,'outcome':'removal-completed'})
# A replaced destination with identical bytes is still not owned by the journal.
kill('published-1')
target=next(iter(app.payloads()));original=target.read_bytes();target.unlink();target.write_bytes(original);target.chmod(0o755)
before=json.loads(Path('/run/fake-systemctl.json').read_text())['calls']
p=subprocess.run(['/usr/bin/python3','/pkg/install.py','--recover'],capture_output=True,text=True)
assert p.returncode!=0 and 'Ownership changed' in p.stderr
assert target.read_bytes()==original and pending.exists()
assert json.loads(Path('/run/fake-systemctl.json').read_text())['calls']==before
results.append({'operation':'install','point':'administrator-identical-replacement','outcome':'refused-and-preserved'})
print(json.dumps({'passed':True,'case_count':len(results),'elapsed_s':time.monotonic()-start,
    'real_sigkill':True,'real_btrfs':True,'simulated_systemd_and_sysfs':True,
    'device_power_loss_tested':False,'cases':results}))
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scratch', type=Path, required=True)
    args = parser.parse_args()
    program = 'BOOTSTRAP = ' + repr(BOOTSTRAP) + '\n' + INSIDE
    print(run_isolated(program, args.scratch, timeout=300))


if __name__ == '__main__':
    main()
