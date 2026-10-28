#!/usr/bin/env python3
"""Qualify installer identity across real Btrfs mount-order changes in disposable images.

Run as root through unshare --mount --propagation private. Only two NEW 1 GiB
sparse regular files are formatted/mounted. Installer destinations and state
are inside those images; service/controller operations are simulated. Images,
journals and failures are retained. This does not reboot the host.
"""
import argparse
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import install as app

CASES = ('published', 'committed', 'removing', 'same-content-replacement',
         'snapshot-replacement', 'legacy-published', 'legacy-removing')


def require(value, message):
    if not value:
        raise RuntimeError(message)


def command(*args):
    return subprocess.run(list(map(str, args)), check=True, capture_output=True,
                          text=True, timeout=60).stdout.strip()


def validate_environment(scratch):
    require(os.geteuid() == 0, 'Root is required for private loop mounts')
    require(Path('/proc/self/ns/mnt').readlink() != Path('/proc/1/ns/mnt').readlink(),
            'Run through unshare --mount --propagation private')
    # Refuse a shared mount namespace even when it is distinct from PID 1.
    require(not any('shared:' in line.split(' - ')[0] for line in
                    Path('/proc/self/mountinfo').read_text().splitlines()),
            'Mount propagation must be private')
    require(scratch.is_absolute() and len(scratch.parts) >= 4
            and scratch.resolve(strict=True) == scratch and scratch.is_dir(), 'Unsafe scratch directory')
    require(scratch.stat().st_mode & 0o022 == 0, 'Scratch must not be writable by other users')
    space = os.statvfs(scratch)
    require(space.f_bavail * space.f_frsize >= 72 * 2**30, 'Retain at least 72 GiB free before this lab')


def new_image(area, name):
    require(area.resolve(strict=True) == area and area.stat().st_uid == 0
            and area.stat().st_mode & 0o077 == 0, 'Unsafe private image directory')
    path = area / (name + '.img')
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.ftruncate(fd, 2**30)
        os.fsync(fd)
    finally:
        os.close(fd)
    info = path.lstat()
    require(path.resolve() == path and stat.S_ISREG(info.st_mode) and info.st_uid == 0
            and info.st_nlink == 1 and info.st_size == 2**30, 'Refusing to format anything except a new owned regular image')
    command('mkfs.btrfs', '-q', '-f', path)
    mountpoint = area / name
    mountpoint.mkdir()
    return path, mountpoint


def configure_fixture(root, payloads):
    app.BASE = root / 'usr/local/libexec/bc250-storage-defaults'
    app.STATE = root / 'var/lib/bc250-storage-defaults'
    app.MANIFEST = app.STATE / 'installation.json'
    app.UNIT_DIRECTORY = root / 'etc/systemd/system'
    app.CONFIG = root / 'etc/bc250-storage-defaults.json'
    files = {root / target.relative_to('/'): pair for target, pair in payloads.items()}
    app.payloads = lambda: files
    app.preflight = lambda: SimpleNamespace(TARGET='5000', info=lambda: {'latency_tolerance_us':'5000'})
    calls = []
    def run(args):
        require(str(args[0]) in ('systemctl', 'systemd-analyze', '/usr/bin/python3'),
                'Unexpected simulated service operation')
        calls.append(list(map(str, args)))
        return ''
    app.run = run
    return files, calls


def interrupt(operation, point):
    sys.stdout.flush(); sys.stderr.flush()
    pid = os.fork()
    if pid == 0:
        try:
            if point == 'committed':
                original = app.write_manifest
                def manifest(data):
                    original(data)
                    os.kill(os.getpid(), signal.SIGKILL)
                app.write_manifest = manifest
            else:
                method = 'delete_target' if point == 'removing' else 'publish'
                original = getattr(app.transaction.Transaction, method)
                def cut(self, *args, **kwargs):
                    original(self, *args, **kwargs)
                    os.kill(os.getpid(), signal.SIGKILL)
                setattr(app.transaction.Transaction, method, cut)
            operation()
            os._exit(90)
        except BaseException:
            os._exit(91)
    deadline = time.monotonic() + 180
    while True:
        ended, status = os.waitpid(pid, os.WNOHANG)
        if ended:
            break
        if time.monotonic() >= deadline:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
            raise RuntimeError('Installer checkpoint deadline; images retained')
        time.sleep(0.05)
    require(os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGKILL,
            'Installer did not reach its selected SIGKILL boundary')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scratch', type=Path, required=True)
    args = parser.parse_args()
    validate_environment(args.scratch)
    area = Path(tempfile.mkdtemp(prefix='bc250-remount-', dir=args.scratch))
    area.chmod(0o700)
    report = dict(passed=False, cases=[], host_reboot_tested=False, simulated_systemd=True,
                  simulated_controller=True, actual_btrfs_mount_order_change=True,
                  source_sha256={name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest()
                                 for name in ('install.py', 'install_transaction.py',
                                              'storage_defaults_repack.py', 'tests/remount_install.py')})
    mounts = []
    def mount(image, where):
        command('mount', '-o', 'loop,nosuid,nodev,noexec', image, where)
        mounts.append(where)
    def unmount(where):
        command('umount', where)
        mounts.remove(where)
    try:
        a, a_mount = new_image(area, 'a')
        b, b_mount = new_image(area, 'b')
        original_payloads = app.payloads()
        # Installer chatter is private; the public evidence records assertions.
        with contextlib.redirect_stdout(io.StringIO()):
            for case in CASES:
                mount(a, a_mount)
                root = a_mount / case
                command('btrfs', 'subvolume', 'create', root)
                files, calls = configure_fixture(root, original_payloads)
                removal = case in ('removing', 'legacy-removing')
                if removal:
                    app.install()
                point = 'removing' if removal else ('committed' if case == 'committed' else 'published')
                interrupt(app.uninstall if removal else app.install, point)
                tx = app.transaction.Transaction.load(app.STATE, files)
                require(tx is not None and tx.data['format_version'] == 2, 'Expected a new persistent-identity journal')
                if case.startswith('legacy-'):
                    tx.data['format_version'] = 1
                    for entry in tx.data['entries']:
                        if 'staged_identity' in entry:
                            s = Path(entry['staged']).stat()
                            entry['staged_identity'] = dict(device=s.st_dev, inode=s.st_ino)
                        entry.pop('identity', None)
                    tx.save()
                existing = next(p for p in files if p.exists())
                before = app.transaction.fingerprint(existing)
                unmount(a_mount)
                mount(b, b_mount)  # Occupies the released anonymous device number.
                mount(a, a_mount)
                after = app.transaction.fingerprint(existing)
                require(before['device'] != after['device'], 'No actual device-number change; inconclusive')
                require(before['identity'] == after['identity'] and before['sha256'] == after['sha256'],
                        'Original file identity/content changed during remount')
                if case == 'same-content-replacement':
                    tx = app.transaction.Transaction.load(app.STATE, files)
                    entry = tx.data['entries'][0]
                    target, stage = Path(entry['target']), Path(entry['staged'])
                    candidate = target.with_name('same-content-new-inode')
                    app.write_new(candidate, target.read_bytes(), entry['mode'])
                    stage.unlink()
                    os.link(candidate, stage)
                    os.replace(candidate, target)
                    app.transaction.sync_directory(target.parent)
                    require(target.stat().st_ino == stage.stat().st_ino, 'Replacement must preserve a live hardlink pair')
                elif case == 'snapshot-replacement':
                    snapshot = root.with_name(case + '-snapshot')
                    command('btrfs', 'subvolume', 'snapshot', root, snapshot)
                    root.rename(root.with_name(case + '-original'))
                    snapshot.rename(root)
                    app.transaction.sync_directory(root.parent)
                    changed = app.transaction.fingerprint(existing)
                    require(changed['inode'] == before['inode'] and changed['sha256'] == before['sha256']
                            and changed['identity']['fs_uuid'] == before['identity']['fs_uuid']
                            and changed['identity'] != before['identity'], 'Snapshot must isolate subvolume identity')
                negative = case.startswith('legacy-') or case.endswith('replacement')
                pending_bytes = app.transaction.pending_path(app.STATE).read_bytes()
                preserved = {}
                if negative:
                    for entry in app.transaction.Transaction.load(app.STATE, files).data['entries']:
                        for name in ('target', 'staged'):
                            if name in entry and Path(entry[name]).exists():
                                preserved[entry[name]] = app.transaction.fingerprint(Path(entry[name]))
                calls.clear()
                error = None
                try:
                    app.recover()
                except RuntimeError as caught:
                    error = str(caught).replace(str(area), '<private-lab>')
                if negative:
                    require(error is not None and 'ownership changed' in error.lower(), 'Expected strict ownership refusal')
                    require(not calls and app.transaction.pending_path(app.STATE).exists(),
                            'Ownership refusal must preserve the journal before service changes')
                    require(existing.is_file(), 'Ownership refusal removed a payload')
                    require(app.transaction.pending_path(app.STATE).read_bytes() == pending_bytes,
                            'Ownership refusal changed the pending journal')
                    require(all(app.transaction.fingerprint(Path(path)) == value
                                for path, value in preserved.items()),
                            'Ownership refusal changed a payload or ownership witness')
                else:
                    require(error is None and not app.transaction.pending_path(app.STATE).exists(),
                            'Recovery did not finish after remount: ' + str(error))
                    if case == 'committed':
                        app.check_owned(json.loads(app.MANIFEST.read_text()))
                        require(all(p.is_file() for p in files), 'Committed installation lost a file')
                    else:
                        require(all(not p.exists() for p in files), 'Rollback/removal left an installed payload')
                    count = len(calls)
                    app.recover()
                    require(len(calls) == count, 'Repeated recovery performed service operations')
                report['cases'].append(dict(case=case, passed=True,
                    before_device=before['device'], after_device=after['device'],
                    persistent_identity_unchanged_on_remount=True, actual_installer_sigkill=True,
                    recovery='refused-and-preserved' if negative else 'completed-and-idempotent',
                    refused_files_and_journal_byte_verified=negative,
                    service_calls_on_refusal=len(calls) if negative else None, expected_refusal=error))
                unmount(a_mount); unmount(b_mount)
        report.update(passed=True, case_count=len(report['cases']))
    finally:
        for where in reversed(mounts[:]):
            unmount(where)
        report.update(all_test_mounts_unmounted=not mounts, completed_unix=time.time())
        output = area / 'result.json'
        output.write_text(json.dumps(report, indent=2)+'\n'); output.chmod(0o600)
    print(json.dumps(dict(passed=report['passed'], report=str(output), case_count=len(report['cases']))))


if __name__ == '__main__':
    main()
