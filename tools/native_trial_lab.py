#!/usr/bin/env python3
"""Qualify writable native trial copies, orderly persistence and reset.

Protected images are never mounted or rewritten. Only independently copied new
regular files are mounted, one filesystem UUID at a time. Guest systemd boots
on the host kernel with private user/PID/network namespaces. No physical reboot,
power change, global cache reset, or performance claim is made.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys
import time
import uuid

import native_volume_lab as native
from vm_cache_faults import logical_sparse_digest

ROOT = Path(__file__).resolve().parents[1]
SERVICE = 'bc250-native-trial.service'

PROBE = r'''import fcntl,hashlib,json,os,sqlite3,subprocess,traceback,uuid
from pathlib import Path
cfg=json.loads(Path('/run/native-trial/parameters.json').read_text())
phase=cfg['phase']; report=dict(passed=False,phase=phase,variant=cfg['variant'])
state=Path('/var/lib/bc250-native-trial')
fixture=Path('/opt/bc250-native-fixtures/incompressible.bin')
def digest(path):
 with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()
def save(path,data):
 temporary=path.with_suffix('.pending')
 with temporary.open('x') as stream:
  json.dump(data,stream);stream.flush();os.fsync(stream.fileno())
 os.replace(temporary,path)
 fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
 try:os.fsync(fd)
 finally:os.close(fd)
try:
 assert Path('/proc/1/comm').read_text().strip()=='systemd'
 assert Path('/run/systemd/container').read_text().strip()=='systemd-nspawn'
 assert os.geteuid()==0 and Path('/usr').stat().st_uid==0
 info=bytearray(1024);fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
 try:fcntl.ioctl(fd,0x8400941f,info,True)
 finally:os.close(fd)
 root_uuid=bytes(info[16:32]).hex();assert root_uuid==cfg['root_uuid_hex']
 mapping=list(map(int,Path('/proc/self/uid_map').read_text().splitlines()[0].split()))
 assert mapping[0]==0 and mapping[1]>65535 and mapping[2]==65536
 boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
 if phase in ('create','reset'):
  assert not state.exists(),'Earlier trial state was inherited'
  assert digest(fixture)==cfg['original_fixture_sha256']
  state.mkdir(mode=0o700)
  fd=os.open(state.parent,os.O_RDONLY|os.O_DIRECTORY)
  try:os.fsync(fd)
  finally:os.close(fd)
  count=1
  with fixture.open('r+b') as stream:
   stream.write(b'BC250-TRIAL-'+cfg['nonce'].encode());stream.flush();os.fsync(stream.fileno())
  mutated=digest(fixture)
  assert mutated!=cfg['original_fixture_sha256']
  prior=None
 elif phase=='persist':
  prior=json.loads((state/'durable.json').read_text())
  assert prior['nonce']==cfg['nonce'] and prior['count']==1
  assert prior['fixture_sha256']==digest(fixture)
  assert prior['container_boot_id']!=boot_id
  count=2;mutated=prior['fixture_sha256']
 else:raise RuntimeError('Unknown native trial phase')
 db=sqlite3.connect(state/'state.sqlite3')
 db.execute('PRAGMA synchronous=EXTRA')
 assert db.execute('PRAGMA synchronous').fetchone()[0]==3
 assert db.execute('PRAGMA journal_mode=DELETE').fetchone()[0]=='delete'
 assert db.execute('PRAGMA integrity_check').fetchone()[0]=='ok'
 if count==1:
  db.execute('CREATE TABLE state(nonce TEXT, count INTEGER)')
  db.execute('INSERT INTO state VALUES(?,?)',(cfg['nonce'],count))
 else:
  assert db.execute('SELECT nonce,count FROM state').fetchall()==[(cfg['nonce'],1)]
  db.execute('UPDATE state SET count=?',(count,))
 db.commit();db.close()
 save(state/'durable.json',dict(nonce=cfg['nonce'],count=count,
    fixture_sha256=mutated,container_boot_id=boot_id))
 # Launch a separately executed installed program as well as the Python probe.
 openssl=subprocess.run(['/usr/bin/openssl','version'],capture_output=True,text=True,check=True,timeout=20).stdout.strip()
 assert openssl.startswith('OpenSSL ')
 target=subprocess.run(['systemctl','is-active','multi-user.target'],capture_output=True,text=True,check=True,timeout=20).stdout.strip()
 assert target=='active'
 failures=subprocess.run(['systemctl','--failed','--plain','--no-legend','--no-pager'],
    capture_output=True,text=True,check=True,timeout=20).stdout.strip()
 assert not failures,'Unexpected failed guest units: '+failures
 report.update(passed=True,real_systemd_pid1=True,kernel=os.uname().release,
   root_uuid_hex=root_uuid,mapped_root=True,private_user_namespace=True,
   pid_namespace=os.readlink('/proc/self/ns/pid'),net_namespace=os.readlink('/proc/self/ns/net'),
   container_boot_id=boot_id,nonce=cfg['nonce'],durable_count=count,
   fixture_sha256=mutated,sqlite_integrity='ok',sqlite_synchronous=3,openssl=openssl,
   prior_state_absent=phase in ('create','reset'),usable_target_active=True,
   failed_guest_units=0,physical_boot_tested=False)
except BaseException as error:
 report.update(error=str(error),traceback=traceback.format_exc())
save(Path('/run/native-trial-results')/(phase+'.json'),report)
subprocess.run(['systemctl','poweroff','--no-block'],check=True)
'''


def require(value, message):
    native.require(value, message)


def safe_json(path, limit=2**20):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
            and info.st_mode & 0o022 == 0 and info.st_size <= limit, 'Unsafe lab metadata')
    return json.loads(path.read_text())


def baseline_manifest(directory):
    native.private_area(directory)
    require(not (directory/'INCOMPLETE').exists(), 'Incomplete baseline set')
    report = safe_json(directory/'result.json')
    require(report.get('passed') is True and report.get('logical_trees_equal') is True
            and set(report['variants']) == set(native.VARIANTS), 'Unqualified baseline set')
    # Interpret the recorded tree/layout using the exact producer and worker.
    for name in ('tools/native_volume_lab.py', 'storage_defaults_repack.py'):
        require(native.digest(ROOT/name) == report['source_sha256'][name], 'Baseline interpretation source changed')
    require(len({v['filesystem_uuid'] for v in report['variants'].values()}) == 3,
            'Baseline filesystems are not independent')
    for name, row in report['variants'].items():
        uuid.UUID(row['filesystem_uuid'])
        image = directory/(name+'.raw')
        info = image.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                and info.st_mode & 0o222 == 0 and info.st_size == native.SIZE, 'Unsafe protected baseline image')
        require(native.sparse_fingerprint(image) == row['image_fingerprint'], 'Protected baseline bytes changed')
    return report


def new_copy(source, target, expected):
    require(target.parent.resolve(strict=True) == target.parent and not target.is_symlink(), 'Unsafe trial path')
    fd = os.open(target, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        before = os.fstat(fd)
        flags = bytearray(8); fcntl.ioctl(fd, 0x80086601, flags, True)
        fcntl.ioctl(fd, 0x40086602, struct.pack('=Q', (struct.unpack('=Q', flags)[0] & ~4) | 0x800000))
        fcntl.ioctl(fd, 0x80086601, flags, True)
        require(struct.unpack('=Q', flags)[0] & 0x800000, 'Trial NOCOW flag was not established')
    finally:
        os.close(fd)
    # Destination exists only because this function exclusively created it.
    native.run('cp', '--reflink=never', '--sparse=always', source, target)
    info = target.lstat()
    require(stat.S_ISREG(info.st_mode) and (info.st_dev, info.st_ino) == (before.st_dev, before.st_ino)
            and info.st_uid == 0 and info.st_nlink == 1 and info.st_size == native.SIZE, 'Trial copy was replaced')
    target.chmod(0o600)
    require(logical_sparse_digest(target) == expected, 'Trial logical image differs from protected source')
    fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        spans = native.repack.extents(fd, native.SIZE)
        require(not any(flags & (8 | 0x2000) for _, _, flags in spans), 'Trial outer extents are compressed or shared')
    finally:
        os.close(fd)


def install_probe(point, id_base):
    unit = point/'etc/systemd/system'/SERVICE
    require(not unit.exists() and not unit.is_symlink(), 'Existing probe unit preserved')
    unit.write_text('''[Unit]
Description=Disposable native persistence and reset qualification
DefaultDependencies=no
After=multi-user.target
Conflicts=shutdown.target
Before=shutdown.target
[Service]
Type=oneshot
Environment=PYTHONDONTWRITEBYTECODE=1
ExecStart=/usr/bin/python3 /run/native-trial/probe.py
TimeoutStartSec=90
[Install]
WantedBy=multi-user.target
''')
    unit.chmod(0o644); os.chown(unit, id_base, id_base)
    wants = point/'etc/systemd/system/multi-user.target.wants'
    wants.mkdir(exist_ok=True); os.chown(wants, id_base, id_base)
    link = wants/SERVICE
    link.symlink_to('../'+SERVICE); os.lchown(link, id_base, id_base)
    native.run('sync', '-f', point)


def boot(point, area, variant, phase, nonce, row, id_base, fixture_sha):
    parameters = dict(variant=variant, phase=phase, nonce=nonce,
                      root_uuid_hex=uuid.UUID(row['filesystem_uuid']).hex, original_fixture_sha256=fixture_sha)
    runtime = area/(variant+'-'+phase+'-runtime'); runtime.mkdir(mode=0o700)
    runtime.chmod(0o755)
    (runtime/'probe.py').write_text(PROBE); (runtime/'probe.py').chmod(0o644)
    (runtime/'parameters.json').write_text(json.dumps(parameters)); (runtime/'parameters.json').chmod(0o644)
    results = area/(variant+'-'+phase+'-results'); results.mkdir(mode=0o700)
    os.chown(results, id_base, id_base)
    unit = 'bc250-native-phase-'+uuid.uuid4().hex[:12]
    container = ['systemd-nspawn', '--keep-unit', '--settings=no', '--register=no', '--console=pipe',
        '--machine=bc250-trial-'+uuid.uuid4().hex[:12], '--directory='+str(point),
        '--private-users='+str(id_base)+':65536', '--private-users-ownership=off',
        '--private-network', '--resolv-conf=off', '--link-journal=no', '--timezone=off',
        '--drop-capability=CAP_NET_ADMIN,CAP_NET_RAW', '--rlimit=RLIMIT_CORE=0:infinity',
        '--bind-ro='+str(runtime)+':/run/native-trial', '--bind='+str(results)+':/run/native-trial-results',
        '--boot', 'systemd.show_status=no', 'systemd.dump_core=no']
    # The phase service keeps all container descendants in its bounded unit.
    # nsenter joins only this live parent helper's private mount namespace.
    command = ['systemd-run', '--quiet', '--wait', '--pipe', '--collect', '--unit='+unit,
        '--property=Delegate=yes', '--property=MemoryMax=1G', '--property=MemorySwapMax=0',
        '--property=CPUQuota=200%', '--property=RuntimeMaxSec=240', '--property=TimeoutStopSec=20',
        '--property=KillMode=control-group', '--property=LimitCORE=0:infinity',
        '/usr/bin/nsenter', '--mount=/proc/'+str(os.getpid())+'/ns/mnt', '--', *container]
    started = time.monotonic()
    try:
        with (area/(variant+'-'+phase+'.log')).open('x') as log:
            subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=280)
    except BaseException:
        subprocess.run(['systemctl', 'stop', unit], capture_output=True, timeout=45)
        raise
    active = subprocess.run(['systemctl', 'is-active', '--quiet', unit], capture_output=True, timeout=15)
    require(active.returncode != 0, 'Native phase unit is still live; do not remount or restart')
    result = json.loads((results/(phase+'.json')).read_text())
    require(result.get('passed') is True, 'Guest phase failed; inspect retained result and log')
    require(result['kernel'] == os.uname().release and result['root_uuid_hex'] == parameters['root_uuid_hex']
            and result['real_systemd_pid1'] is True and result['private_user_namespace'] is True,
            'Native guest identity mismatch')
    private_pid = result.pop('pid_namespace') != os.readlink('/proc/self/ns/pid')
    private_network = result.pop('net_namespace') != os.readlink('/proc/self/ns/net')
    require(private_pid and private_network, 'Expected private native guest namespaces')
    return dict(result, private_pid_namespace=True, private_network=True,
                phase_unit_exited=True, elapsed_s=time.monotonic()-started)


def trial(baselines, area):
    native.private_area(area); native.confined(); native.host_space(area)
    baseline = baseline_manifest(baselines)
    lock = os.open(baselines/'trial.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    info = os.fstat(lock)
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1 and info.st_mode & 0o077 == 0,
            'Unsafe baseline trial lock')
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    qos = Path('/sys/class/nvme/nvme0/power/pm_qos_latency_tolerance_us')
    before_qos = qos.read_text().strip()
    report = dict(passed=False, variants={}, native_host_kernel=os.uname().release,
        physical_boot_tested=False, physical_power_loss_tested=False, performance_tested=False,
        host_cache_reset_performed=False, controller_settings_changed=False,
        construction_qos_us=int(before_qos), baseline_report_sha256=native.digest(baselines/'result.json'),
        source_sha256={name:native.digest(ROOT/name) for name in
            ('tools/native_trial_lab.py', 'tools/native_volume_lab.py', 'tools/vm_boot_probe.py',
             'tools/vm_cache_faults.py', 'storage_defaults_repack.py')})
    mounted = None
    try:
        for variant, row in baseline['variants'].items():
            native.host_space(area)
            source = baselines/(variant+'.raw')
            reference = safe_json(baselines/(variant+'-tree-private.json'), limit=64*2**20)
            require(reference['sha256'] == row['tree_sha256'], 'Private reference does not match baseline report')
            fixture = next(r for r in reference['rows'] if r['path'] == 'opt/bc250-native-fixtures/incompressible.bin')
            canonical = logical_sparse_digest(source)
            point = area/(variant+'-mount'); point.mkdir()
            first = area/(variant+'-first.raw')
            new_copy(source, first, canonical)
            native.run('mount', '-o', 'loop,compress=zstd:1,noatime,nosuid,nodev', first, point); mounted = point
            id_base = point.stat().st_uid
            require(id_base > 65535 and id_base % 65536 == 0, 'Expected shifted baseline root ownership')
            require(native.tree_manifest(point, id_base) == reference, 'Initial trial tree differs from baseline')
            install_probe(point, id_base)
            nonce = uuid.uuid4().hex
            created = boot(point, area, variant, 'create', nonce, row, id_base, fixture['sha256'])
            native.run('sync', '-f', point); native.run('umount', point); mounted = None
            native.run('mount', '-o', 'loop,compress=zstd:1,noatime,nosuid,nodev', first, point); mounted = point
            persisted = boot(point, area, variant, 'persist', nonce, row, id_base, fixture['sha256'])
            require(created['fixture_sha256'] == persisted['fixture_sha256']
                    and created['durable_count'] == 1 and persisted['durable_count'] == 2,
                    'Mutation or SQLite state did not survive native relaunch/remount')
            native.run('sync', '-f', point); native.run('umount', point); mounted = None
            require(native.sparse_fingerprint(source) == row['image_fingerprint'], 'Protected source changed during trial')
            reset = area/(variant+'-reset.raw')
            new_copy(source, reset, canonical)
            native.run('mount', '-o', 'loop,compress=zstd:1,noatime,nosuid,nodev', reset, point); mounted = point
            require(native.tree_manifest(point, id_base) == reference, 'Fresh reset inherited trial changes')
            require(not (point/'var/lib/bc250-native-trial').exists(), 'Reset inherited old durable state')
            install_probe(point, id_base)
            reset_nonce = uuid.uuid4().hex
            fresh = boot(point, area, variant, 'reset', reset_nonce, row, id_base, fixture['sha256'])
            require(fresh['prior_state_absent'] is True and fresh['durable_count'] == 1
                    and fresh['nonce'] != nonce, 'Reset did not start independently')
            native.run('sync', '-f', point); native.run('umount', point); mounted = None
            require(native.sparse_fingerprint(source) == row['image_fingerprint'], 'Reset altered protected source')
            report['variants'][variant] = dict(passed=True, create=created, persist=persisted, reset=fresh,
                initial_and_reset_tree_equal=True, independent_copy_verified=True,
                protected_baseline_unchanged=True, logical_source_image_digest=canonical)
            native.seed.atomic_json(area/'progress.json', report)
            print(json.dumps(dict(variant=variant, native_guest_launches=3, persistence=True, reset=True)), flush=True)
        require(qos.read_text().strip() == before_qos, 'Host controller policy changed')
        report.update(passed=True, native_guest_launches=9, protected_baselines_unchanged=True,
                      completed_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()))
        native.seed.atomic_json(area/'result.json', report)
        (area/'INCOMPLETE').unlink(); native.transaction.sync_directory(area)
    finally:
        if mounted is not None:
            native.run('umount', mounted)
        os.close(lock)
        require(qos.read_text().strip() == before_qos, 'Actual host policy changed during native trials')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('step', choices=('run', '_run'))
    parser.add_argument('--baselines', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    require(sys.platform == 'linux' and os.geteuid() == 0, 'Requires root on Linux')
    baselines = args.baselines.absolute(); area = args.output.absolute()
    require(not area.is_relative_to(baselines) and not baselines.is_relative_to(area), 'Separate baseline and trial directories')
    if args.step == '_run':
        native.private_area(area)
        require((area/'INCOMPLETE').read_text() == 'native-trial-qualification\n', 'Unknown trial output')
        result = trial(baselines, area)
    else:
        native.private_area(baselines); native.private_area(area, creating=True); native.host_space(area.parent)
        area.mkdir(mode=0o700); (area/'INCOMPLETE').write_text('native-trial-qualification\n')
        unit = 'bc250-native-trials-'+uuid.uuid4().hex[:12]
        print(json.dumps(dict(native_trial_unit=unit)), flush=True)
        command = ['systemd-run', '--quiet', '--wait', '--pipe', '--collect', '--unit='+unit,
            '--property=CPUQuota=200%', '--property=MemoryMax=1G', '--property=MemorySwapMax=0',
            '--property=RuntimeMaxSec=1800', '--property=TimeoutStopSec=30', '--property=KillMode=control-group',
            '--property=IOWeight=20', '--property=LimitCORE=0:infinity',
            '/usr/bin/unshare', '--mount', '--propagation', 'private', '/usr/bin/python3',
            str(Path(__file__).resolve()), '_run', '--baselines', str(baselines), '--output', str(area)]
        subprocess.run(command, check=True, timeout=1860)
        result = safe_json(area/'result.json')
        require(result['passed'] is True and not (area/'INCOMPLETE').exists(), 'Native trial qualification did not commit')
    print(json.dumps(dict(passed=result['passed'], output=str(area), native_guest_launches=9)), flush=True)


if __name__ == '__main__':
    main()
