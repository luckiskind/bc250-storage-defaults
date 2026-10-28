#!/usr/bin/env python3
"""Prepare a dedicated Arch test OS tree for real-systemd qualification.

Requires host root, Python 3.14+ for zstd tar reading, systemd-nspawn, GNU tar,
zstd, and writable Btrfs with at least 72 GiB free. Never formats a device,
changes host startup, or boots the host. Preparation downloads signed packages
inside the guest; qualification later uses private networking.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import resource
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import install_transaction as ownership

SEED_SHA256 = '0c9c97b7a58a8a023c9e07f84cb307a9e8006e65d8fc4c17b83ddc8010b45c10'
SEED_NAME = 'archlinux-bootstrap-2026.10.01-x86_64.tar.zst'
AREA = GUEST = MACHINE = None


def require(value, message):
    if not value:
        raise RuntimeError(message)


def configure(workspace):
    global AREA, GUEST, MACHINE
    AREA = Path(workspace).absolute()
    GUEST = AREA / 'root.x86_64'
    MACHINE = 'bc250-test-' + hashlib.sha256(str(AREA).encode()).hexdigest()[:12]


def read_construction(area):
    marker = area/'construction.json'
    require(marker.is_file() and not marker.is_symlink(), 'Missing or unsafe construction marker')
    info = marker.lstat()
    require(info.st_uid == os.geteuid() and info.st_nlink == 1 and info.st_mode & 0o022 == 0
            and info.st_size <= 65536, 'Missing or unsafe construction marker')
    fd = os.open(marker, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        current = os.fstat(fd)
        require((current.st_dev, current.st_ino) == (info.st_dev, info.st_ino), 'Construction marker changed')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            contents = stream.read(65537)
        require(len(contents) <= 65536, 'Construction marker exceeds bounds')
    finally:
        os.close(fd)
    report = json.loads(contents)
    require(isinstance(report, dict), 'Invalid construction marker')
    return report, contents


def directory_identity(path, expected=None):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if expected is not None:
            require([info.st_dev, info.st_ino] == list(expected), 'Directory changed before identity capture')
        identity = ownership.persistent_identity(fd)
        current = path.lstat()
        require((current.st_dev, current.st_ino) == (info.st_dev, info.st_ino),
                'Directory changed during identity capture')
        return identity
    finally:
        os.close(fd)


def check_workspace(area, creating=False):
    """Validate the dedicated directory and recorded guest inode before any mutation."""
    require(area.is_absolute() and len(area.parts) >= 4, 'Use a dedicated absolute workspace below an existing directory')
    require(area.parent.resolve(strict=True) == area.parent, 'Workspace parent contains a symlink')
    require(not area.is_symlink(), 'Workspace must not be a symlink')
    if creating:
        require(not area.exists(), 'Existing workspace is never overwritten')
        return
    s = area.lstat()
    require(area.is_dir() and s.st_uid == os.geteuid() and s.st_mode & 0o077 == 0,
            'Workspace must be an owned private directory')
    report, _ = read_construction(area)
    require(report.get('private_os_tree') is True and report.get('seed_sha256') == SEED_SHA256,
            'Unrecognized test OS provenance')
    guest = area / 'root.x86_64'
    require(guest.resolve(strict=True) == guest and guest.is_dir(), 'Unsafe guest root')
    identity = guest.stat()
    version = report.get('provenance_format', 1)
    require(type(version) is int and version in (1, 2), 'Unsupported workspace provenance format')
    if version == 1:
        require([identity.st_dev, identity.st_ino] == report.get('guest_identity'),
                'Guest directory was replaced or its legacy device number changed; preserve it for inspection')
    else:
        for key in ('workspace_persistent_identity', 'guest_persistent_identity'):
            require(ownership.valid_identity(report.get(key)), 'Invalid persistent workspace identity')
        require(directory_identity(area) == report['workspace_persistent_identity'],
                'Workspace directory was replaced; preserve it for inspection')
        require(directory_identity(guest) == report['guest_persistent_identity'],
                'Guest directory was replaced; preserve it for inspection')


def verify_private_archive(area):
    archive = area/SEED_NAME
    fd = os.open(archive, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and info.st_nlink == 1
                and info.st_mode & 0o222 == 0 and info.st_size <= 160*2**20, 'Unsafe private seed archive')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        require(digest == SEED_SHA256, 'Private seed archive does not match the pinned source')
    finally:
        os.close(fd)
    return digest


def migrate_identity(area):
    # Legacy ownership must still match. An archive/content match alone never
    # permits upgrading a mismatched or replaced workspace after a restart.
    check_workspace(area)
    report, original = read_construction(area)
    if report.get('provenance_format') == 2:
        return dict(migrated=False, provenance_format=2)
    verify_private_archive(area)
    require('identity_migration' not in report, 'Ambiguous legacy migration metadata; preserve it')
    current = area.lstat()
    workspace_id = directory_identity(area, (current.st_dev, current.st_ino))
    guest_id = directory_identity(area/'root.x86_64', report['guest_identity'])
    # A fresh backup name keeps a failed partial backup from blocking an explicit retry.
    fd, name = tempfile.mkstemp(prefix='construction-v1-', suffix='.json', dir=area)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(original); stream.flush(); os.fchmod(stream.fileno(), 0o400); os.fsync(stream.fileno())
    ownership.sync_directory(area)
    report.update(provenance_format=2, workspace_persistent_identity=workspace_id,
        guest_persistent_identity=guest_id, identity_migration=dict(
            previous_marker_sha256=hashlib.sha256(original).hexdigest(), backup_name=Path(name).name,
            legacy_identity_matched=True, private_seed_verified=True,
            migrated_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())))
    require(len((json.dumps(report, indent=2)+'\n').encode()) <= 65536, 'Migrated marker exceeds bounds')
    require(directory_identity(area) == workspace_id and directory_identity(area/'root.x86_64') == guest_id,
            'Workspace changed before provenance commit')
    ownership.atomic_json(area/'construction.json', report)
    check_workspace(area)
    return dict(migrated=True, provenance_format=2, legacy_identity_matched=True,
                private_seed_verified=True, original_marker_backed_up=True)


def guards(creating=False):
    require(sys.platform == 'linux' and os.geteuid() == 0, 'Requires host root on Linux')
    require(AREA is not None, 'Configure the workspace first')
    check_workspace(AREA, creating)
    require(shutil.disk_usage(AREA.parent).free >= 72 * 2**30, 'Need 72 GiB host free space')
    fstype = subprocess.check_output(['findmnt', '-n', '-o', 'FSTYPE', '--target', str(AREA.parent)], text=True).strip()
    require(fstype == 'btrfs', 'The prepared OS must reside on writable Btrfs')


def atomic_json(path, report):
    temporary = path.with_suffix('.pending')
    with temporary.open('x') as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def validate_member(item):
    path = PurePosixPath(item.name)
    metadata = str(path) in ('pkglist.x86_64.txt', 'version')
    require(path.parts and not path.is_absolute() and '..' not in path.parts and
            (path.parts[0] == 'root.x86_64' or (metadata and item.isfile() and item.size <= 65536)),
            'Unsafe seed member path: ' + item.name)
    require(not item.isdev() and not item.isfifo(), 'Unexpected special seed member')
    if item.islnk():
        link = PurePosixPath(item.linkname)
        require(link.parts and not link.is_absolute() and '..' not in link.parts and link.parts[0] == 'root.x86_64',
                'Unsafe hard-link seed member')


def extract(archive):
    guards(creating=True)
    require(sys.version_info >= (3, 14), 'Seed extraction requires host Python 3.14+ for zstd tar support')
    archive = Path(archive).absolute()
    require(archive.is_file() and not archive.is_symlink() and archive.stat().st_size <= 160 * 2**20,
            'Unsafe or oversized seed archive')
    # Extract only a root-private verified copy, so later changes to the input
    # name or inode cannot alter bytes between verification and extraction.
    AREA.mkdir(mode=0o700)
    (AREA / 'INCOMPLETE').write_text('Guest dependencies and qualification are not complete.\n')
    fd = os.open(archive, os.O_RDONLY | os.O_NOFOLLOW)
    private_archive = AREA / SEED_NAME
    digest = hashlib.sha256()
    size = 0
    with os.fdopen(fd, 'rb') as source, private_archive.open('xb') as target:
        require(stat.S_ISREG(os.fstat(source.fileno()).st_mode), 'Seed must be a regular file')
        while block := source.read(2**20):
            size += len(block)
            require(size <= 160 * 2**20, 'Seed grew beyond the size bound')
            digest.update(block)
            target.write(block)
        target.flush()
        os.fsync(target.fileno())
    private_archive.chmod(0o400)
    require(digest.hexdigest() == SEED_SHA256, 'Pinned official seed checksum mismatch; workspace retained')
    total = count = 0
    with tarfile.open(private_archive, 'r:*') as stream:
        for item in stream:
            validate_member(item)
            total += item.size
            count += 1
            require(total <= 2 * 2**30 and count <= 100000, 'Seed extraction exceeds bounds')
    subprocess.run(['tar', '--extract', '--zstd', '--file', str(private_archive), '--directory', str(AREA),
                    '--numeric-owner', '--delay-directory-restore'], check=True, timeout=180)
    require((GUEST / 'usr/lib/systemd/systemd').is_file(), 'Missing guest systemd')
    identity = GUEST.stat()
    report = dict(seed_sha256=SEED_SHA256, seed_name=SEED_NAME, extracted_members=count,
                  extracted_logical_bytes=total, guest_identity=[identity.st_dev, identity.st_ino],
                  provenance_format=2, workspace_persistent_identity=directory_identity(AREA),
                  guest_persistent_identity=directory_identity(GUEST),
                  private_os_tree=True, separate_kernel=False, host_settings_changed=False,
                  created_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()))
    atomic_json(AREA / 'construction.json', report)
    print(json.dumps(report), flush=True)


def container_args(network=False):
    guards()
    # Permit guest systemd's soft-limit adjustment in this process tree only.
    # A zero inherited hard limit cannot be raised by a mapped guest root.
    resource.setrlimit(resource.RLIMIT_CORE, (0, resource.RLIM_INFINITY))
    args = ['systemd-nspawn', '--settings=no', '--register=no', '--machine=' + MACHINE,
            '--private-users=pick', '--private-users-ownership=chown', '--directory=' + str(GUEST),
            '--console=pipe', '--property=MemoryMax=1G', '--property=CPUQuota=200%',
            '--rlimit=RLIMIT_CORE=0:infinity', '--link-journal=no',
            '--drop-capability=CAP_NET_ADMIN,CAP_NET_RAW']
    return args + (['--resolv-conf=bind-host'] if network else ['--private-network', '--resolv-conf=off'])


def install_dependencies():
    args = container_args(network=True)
    (GUEST / 'etc/pacman.d/mirrorlist').write_text('Server = https://geo.mirror.pkgbuild.com/$repo/os/$arch\n')
    # Guest-only keyring, package DB, /run and root; never binds the host bus.
    subprocess.run(args + ['/bin/sh', '-ec', 'pacman-key --init; pacman-key --populate archlinux; '
                   'pacman -Syu --noconfirm --needed python btrfs-progs; python3 --version; '
                   'systemctl --version'], check=True, timeout=600)
    inventory = subprocess.run(container_args() + ['/usr/bin/pacman', '-Q'], check=True,
                               capture_output=True, text=True, timeout=60).stdout.splitlines()
    atomic_json(AREA / 'dependencies.json', dict(signed_distribution_packages=True, packages=inventory,
                preparation_used_outbound_network=True, guest_root_owner=GUEST.stat().st_uid))
    (AREA / 'INCOMPLETE').unlink()
    print(json.dumps({'dependencies_ready': True, 'packages': len(inventory)}), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('step', choices=['extract', 'probe', 'install-deps', 'migrate-identity'])
    parser.add_argument('--workspace', required=True, type=Path)
    parser.add_argument('--archive', type=Path)
    args = parser.parse_args()
    configure(args.workspace)
    if args.step == 'extract':
        require(args.archive is not None, 'Specify the pinned official --archive')
        extract(args.archive)
    elif args.step == 'probe':
        subprocess.run(container_args() + ['/bin/sh', '-ec', 'id; cat /proc/self/uid_map; '
                       'systemctl --version; findmnt -n -o FSTYPE /'], check=True, timeout=60)
    elif args.step == 'migrate-identity':
        guards()
        print(json.dumps(migrate_identity(AREA)), flush=True)
    else:
        require(not (AREA / 'dependencies.json').exists(), 'Dependencies already prepared; use a fresh OS for a new package baseline')
        install_dependencies()


if __name__ == '__main__':
    main()
