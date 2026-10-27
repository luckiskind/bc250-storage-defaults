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
import time

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
    marker = area / 'construction.json'
    require(marker.is_file() and not marker.is_symlink() and marker.stat().st_size <= 65536,
            'Missing or unsafe construction marker')
    report = json.loads(marker.read_text())
    require(report.get('private_os_tree') is True and report.get('seed_sha256') == SEED_SHA256,
            'Unrecognized test OS provenance')
    guest = area / 'root.x86_64'
    require(guest.resolve(strict=True) == guest and guest.is_dir(), 'Unsafe guest root')
    identity = guest.stat()
    require([identity.st_dev, identity.st_ino] == report.get('guest_identity'),
            'Guest directory was replaced; preserve it for inspection')


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
    parser.add_argument('step', choices=['extract', 'probe', 'install-deps'])
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
    else:
        require(not (AREA / 'dependencies.json').exists(), 'Dependencies already prepared; use a fresh OS for a new package baseline')
        install_dependencies()


if __name__ == '__main__':
    main()
