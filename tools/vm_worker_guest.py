"""Embed an unchanged worker and isolated fixture/config into a NEW VM image."""
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil

BOOTSTRAP=r'''import hashlib,json,os,signal,sys,time
from pathlib import Path
ROOT=Path('/opt/bc250-worker-vm');DATA=Path('/opt/bc250-worker-data/fixture.so')
assert (ROOT/'fixture-marker').read_text()=='disposable-worker-image\n'
reference=json.loads((ROOT/'reference.json').read_text())
source=ROOT/'package/storage_defaults_repack.py'
assert hashlib.sha256(source.read_bytes()).hexdigest()==reference['worker_sha256']
sys.path.insert(0,str(source.parent))
import storage_defaults_repack as worker
point=sys.argv[1];assert point in ('none','reserved','range-sync-8','verified-before-finish')
params=dict(p.split('=',1) for p in Path('/proc/cmdline').read_text().split() if '=' in p)
worker.CONFIG=ROOT/'config.json';worker.STATE=Path('/var/lib/bc250-worker-vm/state')
mapped_reads=0;active=None;synced=0;ledger_policy=None

def mapped_path(*parts):
 global mapped_reads
 path=Path(*parts)
 if str(path)=='/sys/block/nvme0n1/stat':
  mapped_reads+=1;return Path('/sys/block/vda/stat')
 return path
worker.Path=mapped_path
signal.signal(signal.SIGTERM,worker.stop);signal.signal(signal.SIGINT,worker.stop)
original_open=worker.open_ledger
def open_ledger(path):
 global ledger_policy
 db=original_open(path)
 ledger_policy=dict(synchronous=db.execute('PRAGMA synchronous').fetchone()[0],
                    journal_mode=db.execute('PRAGMA journal_mode').fetchone()[0])
 assert ledger_policy['synchronous']==3 and ledger_policy['journal_mode'] in ('delete','wal')
 return db
worker.open_ledger=open_ledger

def witness(record=None):
 db,attempt,day,reserved=active
 assert not db.in_transaction
 row=db.execute('SELECT reserved_bytes,charged_bytes,status FROM attempts WHERE id=?',(attempt,)).fetchone()
 charge=db.execute('SELECT bytes FROM budget WHERE day=?',(day,)).fetchone()[0]
 assert row==(reserved,None,'started') and charge>=reserved and mapped_reads>=2
 s=DATA.stat()
 result=dict(attempt=attempt,day=day,reserved_bytes=reserved,budget_bytes=charge,
  status=row[2],mapped_stat_reads=mapped_reads,completed_range_syncs=synced,ledger_policy=ledger_policy,
  fixture_metadata=dict(bytes=s.st_size,mtime_ns=s.st_mtime_ns,uid=s.st_uid,gid=s.st_gid,mode=s.st_mode&0o7777))
 if record is not None:result['verified_record']=record
 return result

def pause(name,record=None):
 assert point==name and active is not None
 print('BC250_VM_CUT='+json.dumps(dict(point=name,mode=params['bc250.mode'],token=params['bc250.token'],
  worker_witness=witness(record))),flush=True)
 # No checkpoint file, added fsync, or orderly shutdown at the failure point.
 while True:time.sleep(1)

original_reserve=worker.reserve_budget
def reserve(db,day,path,sig,amount):
 global active
 attempt=original_reserve(db,day,path,sig,amount);active=(db,attempt,day,amount)
 if point=='reserved':pause(point)
 return attempt
worker.reserve_budget=reserve
original_sync=worker.libc.sync_file_range
def sync_range(*args):
 global synced
 result=original_sync(*args)
 if result==0:
  synced+=1
  if point=='range-sync-8' and synced==8:pause(point)
 return result
worker.libc.sync_file_range=sync_range
original_finish=worker.finish_budget
def finish(db,attempt,day,reserved,record):
 if point=='verified-before-finish':
  assert record['sha256']==reference['sha256'] and record['status'] in ('repacked','layout-not-achieved-verified')
  assert record['charged_bytes']<=reserved
  pause(point,record)
 return original_finish(db,attempt,day,reserved,record)
worker.finish_budget=finish
last=worker.STATE/'last-run.json'
old=last.stat().st_mtime_ns if last.exists() else None
sys.argv=['storage_defaults_repack.py'];worker.main()
assert point=='none','Worker did not reach the requested interruption point'
assert mapped_reads>=2 and last.is_file() and last.stat().st_mtime_ns!=old,'Worker deferred or produced no new report'
print('BC250_WORKER_RUN='+json.dumps(dict(mapped_stat_reads=mapped_reads,
 ledger_policy=ledger_policy,report=json.loads(last.read_text()))),flush=True)
'''

INSIDE=r'''import hashlib,json,os,sqlite3,subprocess,sys,time,traceback
from pathlib import Path
ROOT=Path('/opt/bc250-worker-vm');DATA=Path('/opt/bc250-worker-data/fixture.so')
STATE=Path('/var/lib/bc250-worker-vm/state')
params=dict(p.split('=',1) for p in Path('/proc/cmdline').read_text().split() if '=' in p)
mode=params['bc250.mode'];point=params.get('bc250.point','none');token=params['bc250.token']
report=dict(passed=False,mode=mode,point=point,token=token)

def command(*args):
 p=subprocess.run(list(args),capture_output=True,text=True,timeout=30)
 if p.returncode:raise RuntimeError(repr(args)+': '+p.stdout[-4000:]+p.stderr[-4000:])
 return p.stdout.strip()

def snapshot():
 with sqlite3.connect(STATE/'state.sqlite3') as db:
  assert db.execute('PRAGMA integrity_check').fetchall()==[('ok',)]
  attempts=[dict(id=i,day=d,reserved_bytes=r,charged_bytes=c,status=s) for i,d,r,c,s in
            db.execute('SELECT id,day,reserved_bytes,charged_bytes,status FROM attempts ORDER BY id')]
  budget=dict(db.execute('SELECT day,bytes FROM budget'))
 expected={}
 for a in attempts:
  charge=a['reserved_bytes'] if a['charged_bytes'] is None else a['charged_bytes']
  assert 0<=charge<=a['reserved_bytes']
  expected[a['day']]=expected.get(a['day'],0)+charge
 assert expected==budget,'Budget no longer matches conservative attempt charges'
 assert all(0<=v<=reference['max_bytes_per_day'] for v in budget.values())
 return dict(attempts=attempts,budget=budget)

def verify_fixture():
 assert DATA.stat().st_size==reference['bytes']
 assert hashlib.sha256(DATA.read_bytes()).hexdigest()==reference['sha256']
 assert not (STATE/'STOP').exists()

def cli():
 p=subprocess.run(['/usr/bin/python3',str(ROOT/'run-worker.py'),'none'],capture_output=True,text=True,timeout=300)
 if p.returncode:raise RuntimeError('Actual worker failed: '+p.stdout[-6000:]+p.stderr[-6000:])
 rows=[json.loads(s.split('BC250_WORKER_RUN=',1)[1]) for s in p.stdout.splitlines() if s.startswith('BC250_WORKER_RUN=')]
 assert len(rows)==1 and rows[0]['mapped_stat_reads']>=2 and rows[0]['ledger_policy']['synchronous']==3
 return rows[0]

try:
 assert Path('/proc/1/comm').read_text().strip()=='systemd'
 assert (ROOT/'fixture-marker').read_text()=='disposable-worker-image\n'
 assert command('findmnt','-n','-o','FSTYPE','/')=='btrfs'
 assert command('findmnt','-n','-o','SOURCE','/')=='/dev/vda'
 assert Path('/sys/block/vda/stat').is_file()
 reference=json.loads((ROOT/'reference.json').read_text())
 assert hashlib.sha256((ROOT/'package/storage_defaults_repack.py').read_bytes()).hexdigest()==reference['worker_sha256']
 sys.path.insert(0,str(ROOT/'package'))
 import storage_defaults_repack as worker
 cfg=json.loads((ROOT/'config.json').read_text())
 verify_fixture()
 fd=os.open(DATA,os.O_RDONLY)
 try:
  before_extents=worker.extents(fd,reference['bytes'])
  eligibility=worker.eligible(fd,cfg,time.time())
 finally:os.close(fd)
 if mode in ('worker-baseline','cut-worker'):
  assert eligibility is None,'Fresh fixture is not eligible: '+str(eligibility)
  assert not (STATE/'state.sqlite3').exists(),'Expected a fresh worker state'
 if mode=='cut-worker':
  subprocess.run(['/usr/bin/python3',str(ROOT/'run-worker.py'),point],check=True,timeout=300)
  raise RuntimeError('Worker returned without reaching its interruption checkpoint')
 elif mode in ('worker-baseline','worker-recover'):
  prior=snapshot() if mode=='worker-recover' else None
  if prior:
   assert len(prior['attempts'])==1
   first=prior['attempts'][0]
   assert first['status']=='started' and first['charged_bytes'] is None
   assert first['reserved_bytes']==reference['reserved_bytes']
   assert prior['budget'][first['day']]==first['reserved_bytes'],'Uncertain work was refunded or forgotten'
  run=cli();verify_fixture();after=snapshot()
  assert len(after['attempts']) in ((1,) if prior is None else (1,2))
  if prior:assert after['attempts'][0]==prior['attempts'][0],'Existing crash reservation changed'
  completed=after['attempts'][1:] if prior else after['attempts']
  assert all(a['charged_bytes'] is not None and a['status'] in ('repacked','layout-not-achieved-verified') for a in completed)
  assert all(a['status'] in ('started','repacked','layout-not-achieved-verified') for a in after['attempts'])
  # A bounded verified layout miss is explicit; it is not relabeled as success.
  counts=run['report']['counts']
  assert any(counts.get(s,0)==1 for s in ('repacked','layout-not-achieved-verified','already-small-compressed','unchanged'))
  repeat=cli();verify_fixture();again=snapshot()
  assert again==after,'Repeated maintenance unexpectedly consumed another budget reservation'
  fd=os.open(DATA,os.O_RDONLY)
  try:spans=worker.extents(fd,reference['bytes'])
  finally:os.close(fd)
  s=DATA.stat()
  report.update(passed=True,kernel=os.uname().release,root_uuid=command('findmnt','-n','-o','UUID','/'),
   boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),fixture_sha256=reference['sha256'],
   fixture_bytes=reference['bytes'],worker_sha256=reference['worker_sha256'],
   fixture_metadata=dict(bytes=s.st_size,mtime_ns=s.st_mtime_ns,uid=s.st_uid,gid=s.st_gid,mode=s.st_mode&0o7777),
   prior_ledger=prior,after_ledger=after,repeat_budget_unchanged=True,
   worker_run=run,repeat_run=repeat,initial_eligibility=eligibility,
   encoded_extent_max=max((n for _,n,f in spans if f&8),default=0),
   initial_encoded_extent_max=max((n for _,n,f in before_extents if f&8),default=0),
   live_virtual_disk_stat_adapter=True,physical_power_loss_tested=False)
 else:raise RuntimeError('Unknown worker VM mode')
except BaseException as error:report.update(error=str(error),traceback=traceback.format_exc())
print('BC250_VM_RESULT='+json.dumps(report),flush=True)
subprocess.run(['systemctl','poweroff','--no-block'],check=True)
'''


def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def prepare(root,package):
    private=root/'opt/bc250-worker-vm';private.mkdir(mode=0o700)
    (private/'fixture-marker').write_text('disposable-worker-image\n')
    target=private/'package';target.mkdir()
    source=package/'storage_defaults_repack.py'
    if source.is_symlink() or not source.is_file():raise RuntimeError('Unsafe worker source')
    shutil.copyfile(source,target/source.name)
    spec=importlib.util.spec_from_file_location('worker_fixture_source',source)
    worker=importlib.util.module_from_spec(spec);spec.loader.exec_module(worker)
    data=root/'opt/bc250-worker-data';data.mkdir(mode=0o700)
    fixture=data/'fixture.so';shutil.copyfile(root/'opt/bc250-vm-fixture.bin',fixture);fixture.chmod(0o644)
    reserved=fixture.stat().st_size+worker.MAX_LAYOUT_RETRY_BYTES
    config=dict(roots=['/opt/bc250-worker-data'],min_file_bytes=2**20,max_file_bytes=256*2**20,
        quiet_seconds=0,max_bytes_per_run=reserved,max_bytes_per_day=reserved*2,
        reserve_free_bytes=64*2**30,max_run_seconds=180,max_load=100000,
        sample_max_stored_ratio=.9,excluded_dir_names=['.git'],excluded_paths=[])
    reference=dict(sha256=digest(fixture),bytes=fixture.stat().st_size,worker_sha256=digest(source),
                   reserved_bytes=reserved,max_bytes_per_day=config['max_bytes_per_day'])
    (private/'reference.json').write_text(json.dumps(reference))
    (private/'config.json').write_text(json.dumps(config))
    (private/'run-worker.py').write_text(BOOTSTRAP)
    (root/'opt/bc250-vm-probe.py').write_text(INSIDE)
    (root/'var/lib/bc250-worker-vm').mkdir(mode=0o700)
    drop=root/'etc/systemd/system/bc250-vm-probe.service.d';drop.mkdir()
    (drop/'worker.conf').write_text('[Service]\nTimeoutStartSec=500\n')
    return reference
