#!/usr/bin/env python3
"""Build three independent native, loop-backed Btrfs userspace baselines.

Only new regular images are formatted. The working OS, bootloader and drive
policy are untouched. Images use an authenticated prepared OS, not user files.
CPU/memory are bounded; networking and host service control are not exposed to
the native worker container. These volumes are not physical-boot qualification.
"""
import argparse
import collections
import fcntl
import hashlib
import json
import os
from pathlib import Path
import random
import stat
import struct
import subprocess
import sys
import tarfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import install_transaction as transaction
import storage_defaults_repack as repack
import prepare_test_os as seed
from vm_boot_probe import sparse_fingerprint

SIZE = 80 * 2**30
HOST_FLOOR = 72 * 2**30
PAYLOAD_CAP = 8 * 2**30
SOURCE_DIRS = ('usr', 'etc', 'boot', 'var/lib/pacman')
VOLATILE = ('dev', 'proc', 'sys', 'run', 'tmp', 'var/tmp')
VARIANTS = ('B0', 'B1', 'B2')
KEYRING_SOCKETS = tuple('etc/pacman.d/gnupg/' + name for name in
    ('S.keyboxd', 'S.gpg-agent', 'S.gpg-agent.ssh', 'S.gpg-agent.extra', 'S.gpg-agent.browser', 'S.dirmngr'))

WORKER = r'''import importlib.util,json,os,sys
from pathlib import Path
spec=importlib.util.spec_from_file_location('worker','/run/native-worker.py')
worker=importlib.util.module_from_spec(spec);spec.loader.exec_module(worker)
worker.CONFIG=Path('/run/native-config.json');worker.STATE=Path('/run/native-state')
info=bytearray(1024)
fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
try:worker.fcntl.ioctl(fd,0x8400941f,info,True)
finally:os.close(fd)
mapping=list(map(int,Path('/proc/self/uid_map').read_text().splitlines()[0].split()))
environment=dict(kernel=os.uname().release,root_uuid_hex=bytes(info[16:32]).hex(),
    root_uid=os.geteuid(),usr_uid=Path('/usr').stat().st_uid,
    private_user_namespace=mapping[0]==0 and mapping[1]>65535 and mapping[2]==65536,
    net_namespace=os.readlink('/proc/self/ns/net'),
    nvme_counter_fields=len(list(map(int,Path('/sys/block/nvme0n1/stat').read_text().split()))))
(worker.STATE/'execution.json').write_text(json.dumps(environment))
sys.argv=['native-worker']
worker.main()
'''


def require(value, message):
    if not value:
        raise RuntimeError(message)


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def run(*args, timeout=600):
    return subprocess.run(list(map(str, args)), check=True, capture_output=True,
                          text=True, timeout=timeout).stdout.strip()


def host_space(area):
    space = os.statvfs(area)
    require(space.f_bavail * space.f_frsize >= HOST_FLOOR, 'Host free-space floor; preserve incomplete volumes')


def private_area(area, creating=False):
    require(area.is_absolute() and len(area.parts) >= 4 and area.parent.resolve(strict=True) == area.parent,
            'Use an absolute output below an existing directory without symlink components')
    if creating:
        require(not area.exists() and not area.is_symlink(), 'Existing output is never overwritten')
    else:
        info = area.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and info.st_mode & 0o077 == 0,
                'Output must be a root-owned private directory')


def confined():
    require(Path('/proc/self/ns/mnt').readlink() != Path('/proc/1/ns/mnt').readlink(),
            'A private mount namespace is required')
    require(not any('shared:' in line.split(' - ')[0] for line in
                    Path('/proc/self/mountinfo').read_text().splitlines()), 'Mount propagation must be private')
    relative = next(line.split('::', 1)[1] for line in Path('/proc/self/cgroup').read_text().splitlines()
                    if line.startswith('0::'))
    group = Path('/sys/fs/cgroup') / relative.lstrip('/')
    memory = (group / 'memory.max').read_text().strip()
    quota, period = (group / 'cpu.max').read_text().split()
    require(memory != 'max' and int(memory) <= 2 * 2**30 and quota != 'max'
            and int(quota) <= 2 * int(period) and (group/'memory.swap.max').read_text().strip() == '0',
            'Run through the bounded parent command')


def tree_manifest(root, id_base, prefix=''):
    """Private content/metadata inventory; never follows symbolic links."""
    rows = []
    total = 0
    hardlinks = {}
    stack = [(root, '')]
    while stack:
        path, relative = stack.pop()
        if relative and any(relative == p or relative.startswith(p + '/') for p in VOLATILE):
            continue
        info = path.lstat()
        full_name = (prefix + '/' + relative).strip('/')
        if stat.S_ISSOCK(info.st_mode) and full_name in KEYRING_SOCKETS:
            continue
        require(len(rows) < 100000 and len(path.relative_to(root).parts) <= 64, 'Tree inventory bound')
        def unshift(value):
            return value - id_base if id_base <= value < id_base + 65536 else value
        row = dict(path=relative, mode=stat.S_IMODE(info.st_mode),
                   uid=unshift(info.st_uid), gid=unshift(info.st_gid),
                   xattrs={name:hashlib.sha256(os.getxattr(path, name, follow_symlinks=False)).hexdigest()
                           for name in sorted(os.listxattr(path, follow_symlinks=False))})
        if stat.S_ISLNK(info.st_mode):
            row.update(kind='symlink', target=os.readlink(path))
        elif stat.S_ISDIR(info.st_mode):
            row['kind'] = 'directory'
            stack.extend((path / name, (relative + '/' + name).lstrip('/'))
                         for name in sorted(os.listdir(path), reverse=True))
        elif stat.S_ISREG(info.st_mode):
            require(info.st_size <= 512 * 2**20, 'Unexpected large source file')
            total += info.st_size
            require(total <= PAYLOAD_CAP, 'OS payload exceeds the 8 GiB logical bound')
            key = (info.st_dev, info.st_ino)
            hardlinks.setdefault(key, relative)
            row.update(kind='file', bytes=info.st_size, sha256=digest(path),
                       mtime_ns=info.st_mtime_ns, hardlink_group=hardlinks[key])
        else:
            raise RuntimeError('Unexpected special file in the durable OS tree')
        rows.append(row)
    canonical = json.dumps(rows, sort_keys=True, separators=(',', ':')).encode()
    return dict(rows=rows, logical_bytes=total, nodes=len(rows), sha256=hashlib.sha256(canonical).hexdigest())


def source_inventory(guest, id_base):
    inventories = {}
    for name in SOURCE_DIRS:
        path = guest / name
        require(path.resolve(strict=True) == path and path.is_dir(), 'Unsafe seed subtree')
        inventories[name] = tree_manifest(path, id_base, prefix=name)
    require(sum(v['logical_bytes'] for v in inventories.values()) <= PAYLOAD_CAP, 'Combined seed payload bound')
    return {name:dict(sha256=value['sha256'], logical_bytes=value['logical_bytes'], nodes=value['nodes'])
            for name, value in inventories.items()}


def new_image(area, variant):
    private_area(area)
    image = area / (variant + '.raw')
    fd = os.open(image, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        # Disable outer data COW/compression before allocating any image bytes.
        flags = bytearray(8)
        fcntl.ioctl(fd, 0x80086601, flags, True)
        value = struct.unpack('=Q', flags)[0]
        fcntl.ioctl(fd, 0x40086602, struct.pack('=Q', (value & ~4) | 0x800000))
        fcntl.ioctl(fd, 0x80086601, flags, True)
        require(struct.unpack('=Q', flags)[0] & 0x800000, 'Outer NOCOW flag was not established')
        os.ftruncate(fd, SIZE); os.fsync(fd)
    finally:
        os.close(fd)
    info = image.lstat()
    require(image.resolve() == image and stat.S_ISREG(info.st_mode) and info.st_uid == 0
            and info.st_nlink == 1 and info.st_size == SIZE, 'Refusing to format anything except the new regular image')
    run('mkfs.btrfs', '--quiet', '--nodiscard', '--data', 'single', '--metadata', 'dup', image)
    return image


def seed_archive(guest, area):
    archive = area/'seed-private.tar'
    require(not archive.exists(), 'Existing seed archive preserved')
    exclusions = []
    for name in KEYRING_SOCKETS:
        try:
            if stat.S_ISSOCK((guest/name).lstat().st_mode):
                exclusions.append(name)
        except FileNotFoundError:
            pass
    run('tar', '--create', '--file', archive, '--numeric-owner', '--acls', '--xattrs', '--xattrs-include=*',
        *('--exclude='+name for name in exclusions), '--directory', guest, *SOURCE_DIRS)
    archive.chmod(0o400)
    require(archive.stat().st_size <= PAYLOAD_CAP + 2**30, 'Seed archive exceeds bounds')
    names = {}
    total = 0
    with tarfile.open(archive) as stream:
        for member in stream:
            name = Path(member.name)
            require(not name.is_absolute() and '..' not in name.parts and
                    any(member.name == p or member.name.startswith(p+'/') for p in SOURCE_DIRS),
                    'Unsafe generated archive path')
            require(member.isfile() or member.isdir() or member.issym() or member.islnk(),
                    'Special file in generated seed archive')
            require(member.name not in names and len(names) < 100000, 'Repeated or excessive seed members')
            names[member.name] = member
            total += member.size
            require(total <= PAYLOAD_CAP, 'Generated seed payload exceeds bounds')
    for name, member in names.items():
        require(not any(str(p) in names and names[str(p)].issym() for p in Path(name).parents),
                'Generated archive writes through a symbolic-link ancestor')
        if member.islnk():
            link = Path(member.linkname)
            require(not link.is_absolute() and '..' not in link.parts and member.linkname in names
                    and names[member.linkname].isfile(), 'Unsafe generated hardlink')
    return archive, exclusions


def populate(archive, target, id_base, machine_id):
    os.chown(target, id_base, id_base); target.chmod(0o755)
    run('tar', '--extract', '--file', archive, '--directory', target, '--numeric-owner',
        '--same-owner', '--same-permissions', '--acls', '--xattrs', '--xattrs-include=*')
    for name in ('var/lib', 'var/cache', 'var/log', 'var/tmp', 'dev', 'proc', 'sys', 'run', 'tmp',
                 'mnt', 'home', 'opt', 'root', 'srv'):
        path = target / name
        path.mkdir(parents=True, exist_ok=True)
        os.chown(path, id_base, id_base)
        path.chmod(0o1777 if name in ('tmp', 'var/tmp') else 0o700 if name == 'root' else 0o755)
    os.chown(target/'var', id_base, id_base)
    for name, value in {'bin':'usr/bin', 'sbin':'usr/bin', 'lib':'usr/lib', 'lib64':'usr/lib'}.items():
        (target/name).symlink_to(value); os.lchown(target/name, id_base, id_base)
    for name, contents in {'machine-id':machine_id+'\n', 'hostname':'bc250-native-baseline\n',
                           'resolv.conf':'', 'fstab':''}.items():
        path = target/'etc'/name
        if path.is_symlink():
            path.unlink()
        path.write_text(contents)
        os.chown(path, id_base, id_base); path.chmod(0o644)
        os.utime(path, ns=(1700000000000000000, 1700000000000000000))
    fixtures = target/'opt/bc250-native-fixtures'
    fixtures.mkdir(); os.chown(fixtures, id_base, id_base)
    rng = random.Random(0xBC250)
    control = fixtures/'incompressible.bin'
    with control.open('xb') as stream:
        for _ in range(32):
            stream.write(rng.randbytes(2**20))
        stream.flush(); os.fsync(stream.fileno())
    os.chown(control, id_base, id_base); control.chmod(0o644)
    # Set a fixed mtime for generated fixtures so variant metadata compares exactly.
    os.utime(control, ns=(1700000000000000000, 1700000000000000000))


def layout_inventory(root, manifest):
    summary = collections.Counter()
    candidates = []
    seen = set()
    for row in manifest['rows']:
        if row['kind'] != 'file':
            continue
        fd = os.open(root/row['path'], os.O_RDONLY | os.O_NOFOLLOW)
        try:
            spans = repack.extents(fd, row['bytes'])
            require(not any(flags & 0x2000 for _, _, flags in spans), 'Unexpected shared file extents')
            summary['regular_files_checked'] += 1
            info = os.fstat(fd)
            identity = (info.st_dev, info.st_ino)
            if identity not in seen:
                summary['unique_regular_inodes'] += 1
                summary['allocated_file_bytes'] += info.st_blocks * 512
                seen.add(identity)
            if row['bytes'] >= 2**20 and os.pread(fd, 4, 0) == b'\x7fELF':
                encoded = [n for _, n, flags in spans if flags & 8]
                candidates.append(dict(path=row['path'], bytes=row['bytes'], sha256=row['sha256'],
                                       encoded_extent_max=max(encoded, default=0)))
        finally:
            os.close(fd)
    return dict(**summary, shared_extents=0, elf_candidates=candidates)


def worker_pass(area, target, id_base, fs_uuid):
    state = area/'B2-worker-state'; state.mkdir(mode=0o700)
    os.chown(state, id_base, id_base)
    config = json.loads((ROOT/'config.json').read_text())
    # Construction uses the production limits and idle policy. No host roots are scanned.
    config['roots'] = ['/usr', '/opt', '/home', '/srv']
    cfg = area/'worker-config.json'; cfg.write_text(json.dumps(config)); cfg.chmod(0o644)
    program = area/'run-worker.py'; program.write_text(WORKER); program.chmod(0o644)
    command = ['systemd-nspawn', '--settings=no', '--register=no', '--console=pipe',
        '--machine=bc250-native-'+uuid.uuid4().hex[:12], '--directory='+str(target),
        '--private-users='+str(id_base)+':65536', '--private-users-ownership=off',
        '--private-network', '--resolv-conf=off', '--link-journal=no', '--timezone=off',
        '--drop-capability=CAP_NET_ADMIN,CAP_NET_RAW', '--property=MemoryMax=1G',
        '--property=CPUQuota=200%', '--rlimit=RLIMIT_CORE=0:infinity',
        '--setenv=PYTHONDONTWRITEBYTECODE=1', '--setenv=LC_ALL=C',
        '--bind-ro='+str(ROOT/'storage_defaults_repack.py')+':/run/native-worker.py',
        '--bind-ro='+str(cfg)+':/run/native-config.json',
        '--bind='+str(state)+':/run/native-state',
        '--bind-ro='+str(program)+':/run/native-run.py',
        '/usr/bin/python3', '/run/native-run.py']
    # A separate native container uses the actual host-kernel disk counters.
    with (area/'worker.log').open('x') as log:
        subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=420)
    require((state/'last-run.json').is_file(), 'Worker deferred; preserve volumes instead of certifying B2')
    report = json.loads((state/'last-run.json').read_text())
    require(report['verified_files'] > 0 and report['charged_bytes'] <= config['max_bytes_per_run'],
            'B2 had no verified conversion or exceeded its allowance')
    require(not (state/'STOP').exists(), 'Worker verification STOP; preserve all artifacts')
    execution = json.loads((state/'execution.json').read_text())
    private_network = execution.pop('net_namespace') != os.readlink('/proc/self/ns/net')
    require(execution['kernel'] == os.uname().release and execution['root_uuid_hex'] == uuid.UUID(fs_uuid).hex
            and execution['root_uid'] == execution['usr_uid'] == 0
            and execution['private_user_namespace'] is True and private_network
            and execution['nvme_counter_fields'] >= 11, 'Native worker environment does not match its owned volume')
    report['execution'] = dict(execution, private_network=True)
    return report


def build(workspace, area):
    private_area(area); confined(); host_space(area)
    seed.configure(workspace); seed.guards()
    dependencies = json.loads((workspace/'dependencies.json').read_text())
    require(dependencies['signed_distribution_packages'] is True and not (workspace/'INCOMPLETE').exists(),
            'Use a completed authenticated prepared OS')
    guest = seed.GUEST
    id_base = guest.stat().st_uid
    require(id_base > 65535 and id_base % 65536 == 0 and guest.stat().st_gid == id_base, 'Expected a shifted guest UID range')
    qos = Path('/sys/class/nvme/nvme0/power/pm_qos_latency_tolerance_us')
    before_qos = qos.read_text().strip()
    host_uuid = run('findmnt', '-n', '-o', 'UUID', '--target', area)
    before = source_inventory(guest, id_base)
    seed.atomic_json(area/'source-inventory-private.json', before)
    archive, excluded_sockets = seed_archive(guest, area)
    report = dict(passed=False, variants={}, native_host_kernel=os.uname().release,
        separate_filesystems=True, native_io=True, loop_backed=True, physical_boot_qualified=False,
        controller_settings_changed=False, required_future_qos_us={'B0':100000,'B1':5000,'B2':5000},
        construction_qos_us=int(before_qos), source_seed_sha256=seed.SEED_SHA256,
        source_inventory=before, package_inventory_sha256=digest(workspace/'dependencies.json'),
        source_sha256={name:digest(ROOT/name) for name in
            ('storage_defaults_repack.py','config.json','tools/native_volume_lab.py','tools/prepare_test_os.py')},
        security_metadata_copied=True, host_device_formatted=False, host_settings_changed=False,
        excluded_source_runtime_sockets=excluded_sockets, seed_archive_sha256=digest(archive),
        control_bytes=32*2**20, image_virtual_bytes=SIZE,
        sparse_capacity_is_not_host_space_reservation=True)
    reference = None
    machine_id = uuid.uuid4().hex
    uuids = set()
    mounted = None
    try:
        for variant in VARIANTS:
            host_space(area)
            image = new_image(area, variant)
            point = area/(variant+'-mount'); point.mkdir()
            run('mount', '-o', 'loop,compress=zstd:1,noatime,nosuid,nodev', image, point)
            mounted = point
            fs_uuid = run('findmnt', '-n', '-o', 'UUID', '--target', point)
            uuid.UUID(fs_uuid)
            require(fs_uuid != host_uuid and fs_uuid not in uuids, 'Filesystem independence failed')
            uuids.add(fs_uuid)
            populate(archive, point, id_base, machine_id)
            run('sync', '-f', point)
            manifest = tree_manifest(point, id_base)
            if reference is None:
                reference = manifest
            require(manifest == reference, 'Fresh baseline trees differ in contents or supported metadata')
            initial_layout = layout_inventory(point, manifest)
            maintenance = worker_pass(area, point, id_base, fs_uuid) if variant == 'B2' else None
            final_manifest = tree_manifest(point, id_base)
            require(final_manifest == reference, 'Layout conversion changed contents, metadata or hardlink topology')
            final_layout = layout_inventory(point, final_manifest)
            if variant == 'B2':
                initial = {row['path']:row for row in initial_layout['elf_candidates']}
                improved = [row for row in final_layout['elf_candidates']
                            if initial[row['path']]['encoded_extent_max'] > 16384
                            and 0 < row['encoded_extent_max'] <= 16384]
                require(improved, 'B2 did not demonstrate any verified smaller-extent conversion')
            free = os.statvfs(point)
            require(free.f_bavail*free.f_frsize >= 64*2**30, 'Inner free-space floor failed')
            seed.atomic_json(area/(variant+'-tree-private.json'), final_manifest)
            run('sync', '-f', point); run('umount', point); mounted = None
            image.chmod(0o400)
            outer = os.open(image, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                spans = repack.extents(outer, SIZE)
                require(not any(flags & (8 | 0x2000) for _, _, flags in spans),
                        'Outer image is compressed or shared; baseline path would be confounded')
            finally:
                os.close(outer)
            report['variants'][variant] = dict(filesystem_uuid=fs_uuid, tree_sha256=manifest['sha256'],
                durable_nodes=manifest['nodes'], logical_file_bytes=manifest['logical_bytes'],
                initial_layout=initial_layout, final_layout=final_layout, maintenance=maintenance,
                image_fingerprint=sparse_fingerprint(image),
                outer_nocow=True, outer_encoded_or_shared_extents=0,
                allocated_image_bytes=image.stat().st_blocks*512, read_only_baseline=True)
            seed.atomic_json(area/'build-progress.json', report)
        require(source_inventory(guest, id_base) == before, 'Source OS changed during construction')
        require(qos.read_text().strip() == before_qos, 'Host drive policy changed during construction')
        report.update(passed=True, source_tree_unchanged=True, logical_trees_equal=True,
                      completed_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()))
        seed.atomic_json(area/'result.json', report)
        (area/'INCOMPLETE').unlink(); transaction.sync_directory(area)
    finally:
        if mounted is not None:
            run('umount', mounted)
        require(qos.read_text().strip() == before_qos, 'Host drive policy changed; inspect before continuing')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('step', choices=('build', '_build'))
    parser.add_argument('--workspace', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    require(sys.platform == 'linux' and os.geteuid() == 0, 'Requires root on Linux')
    seed.configure(args.workspace); seed.guards()
    area = args.output.absolute()
    if args.step == '_build':
        private_area(area)
        require((area/'INCOMPLETE').read_text() == 'native-volume-construction\n', 'Unrecognized incomplete output')
        report = build(args.workspace, area)
    else:
        private_area(area, creating=True); host_space(area.parent)
        area.mkdir(mode=0o700)
        (area/'INCOMPLETE').write_text('native-volume-construction\n')
        unit = 'bc250-native-build-'+uuid.uuid4().hex[:12]
        command = ['systemd-run', '--quiet', '--wait', '--pipe', '--collect', '--unit='+unit,
            '--property=CPUQuota=200%', '--property=MemoryMax=2G', '--property=MemorySwapMax=0',
            '--property=IOWeight=20', '--property=LimitCORE=0:infinity',
            '/usr/bin/unshare', '--mount', '--propagation', 'private',
            '/usr/bin/python3', str(Path(__file__).resolve()), '_build',
            '--workspace', str(args.workspace), '--output', str(area)]
        with (area/'build.log').open('x') as log:
            subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=1800)
        report = json.loads((area/'result.json').read_text())
        require(report.get('passed') is True and not (area/'INCOMPLETE').exists(), 'Native baseline build did not commit')
    print(json.dumps(dict(passed=report['passed'], output=str(area), variants=len(report['variants']))), flush=True)


if __name__ == '__main__':
    main()
