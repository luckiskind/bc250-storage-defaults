#!/usr/bin/python3
"""Install or remove the experimental BC-250 storage profile; no external Python packages."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import time
import install_transaction as transaction

SOURCE = Path(__file__).resolve().parent
BASE = Path('/usr/local/libexec/bc250-storage-defaults')
STATE = Path('/var/lib/bc250-storage-defaults')
MANIFEST = STATE / 'installation.json'
CONFIG = Path('/etc/bc250-storage-defaults.json')
POWER = 'bc250-nvme-power.service'
WORKER = 'bc250-btrfs-repack.service'
TIMER = 'bc250-btrfs-repack.timer'
UNITS = (POWER, WORKER, TIMER)
UNIT_DIRECTORY = Path('/etc/systemd/system')


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def run(args):
    result = subprocess.run(list(map(str, args)), capture_output=True, text=True, timeout=180)
    if result.returncode:
        raise RuntimeError(f'{args[0]} failed: {result.stdout.strip()} {result.stderr.strip()}')
    return result.stdout.strip()


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def payloads():
    files = {}
    for name in ('storage_defaults_power.py', 'storage_defaults_repack.py'):
        files[BASE / name] = (SOURCE / name, 0o755)
    files[CONFIG] = (SOURCE / 'config.json', 0o644)
    for name in UNITS:
        files[UNIT_DIRECTORY / name] = (SOURCE / 'systemd' / name, 0o644)
    files[Path('/usr/lib/systemd/system-sleep/90-bc250-nvme-power')] = (
        SOURCE / 'systemd/90-bc250-nvme-power', 0o755)
    return files


def load_module(name):
    spec = importlib.util.spec_from_file_location(name, SOURCE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def preflight():
    require(sys.platform == 'linux' and platform.machine() == 'x86_64', 'Requires x86_64 Linux')
    require(Path('/run/systemd/system').is_dir(), 'Requires a running systemd system')
    for command in ('systemctl', 'systemd-analyze', 'findmnt'):
        require(shutil.which(command), f'Missing dependency: {command}')
    for target, (source, mode) in payloads().items():
        require(source.is_file() and not source.is_symlink(), f'Missing package file: {source}')
        if source.suffix == '.py':
            compile(source.read_text(), str(source), 'exec')
    power = load_module('storage_defaults_power')
    info = power.info()
    require(info['model'] == power.MODEL and info['link_width'] == '2'
            and info['link_speed'].startswith('5.0 GT/s'),
            'This first release is qualified only for nvme0, PNY CS2241 1TB SSD, PCIe 2.0 x2: ' + str(info))
    # Importing checks that the kernel/libc and libzstd entry points are available.
    load_module('storage_defaults_repack')
    for directory in ('/', '/usr', '/home', '/var/lib'):
        require(run(['findmnt', '-n', '-o', 'FSTYPE', '--target', directory]) == 'btrfs',
                f'{directory} must be on Btrfs for this qualified profile')
        require(not os.statvfs(directory).f_flag & os.ST_RDONLY, f'Read-only filesystem: {directory}')
    cfg = json.loads((SOURCE / 'config.json').read_text())
    for directory in ('/', '/home', '/var/lib'):
        fs = os.statvfs(directory)
        require(fs.f_bavail * fs.f_frsize >= cfg['reserve_free_bytes'], f'Need 64 GiB free on {directory}')
    print(json.dumps({'preflight': 'passed', 'drive': info, 'config': cfg}, indent=2))
    return power


def write_new(path, data, mode):
    # Never follow an existing destination, including a dangling symlink.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    owned = os.fstat(fd)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fchmod(stream.fileno(), mode)
            os.fsync(stream.fileno())
        parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    except BaseException:
        # A failed write never reaches install()'s completed-file list. Remove
        # only the inode we created; preserve any administrator replacement.
        try:
            current = path.lstat()
            if (current.st_dev, current.st_ino) == (owned.st_dev, owned.st_ino):
                path.unlink()
        except OSError:
            pass
        raise


def write_manifest(data):
    # Parent is root-owned 0700. Atomic replace preserves the previous audit on failure.
    fd, temporary = tempfile.mkstemp(prefix='.manifest-', dir=STATE)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(data, stream, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, MANIFEST)
        transaction.sync_directory(STATE)
    finally:
        Path(temporary).unlink(missing_ok=True)


def check_owned(manifest):
    expected = set(map(str, payloads()))
    require(set(manifest['installed_files']) == expected, 'Unexpected paths in installation manifest')
    for name in expected:
        path = Path(name)
        require(path.is_file() and not path.is_symlink(), f'Missing or unsafe installed file: {path}')
        require(sha(path) == manifest['installed_sha256'][name],
                f'Administrator modified {path}; review before replacement/removal')


def stop_all():
    # Check each result. If stopping fails, keep files needed to restore the drive policy.
    run(['systemctl', 'disable', '--now', TIMER])
    run(['systemctl', 'stop', WORKER])
    run(['systemctl', 'disable', '--now', POWER])
    # A failed/stopped unit may not run ExecStop; retain helpers if restoration fails.
    run(['/usr/bin/python3', BASE / 'storage_defaults_power.py', 'restore'])
    sync_service_links()


def sync_service_links():
    # systemctl's successful enable/disable does not itself promise durable
    # directory entries. Persist link changes before committing their intent.
    for name in ('multi-user.target.wants', 'timers.target.wants'):
        directory = UNIT_DIRECTORY / name
        if directory.exists() or directory.is_symlink():
            require(directory.is_dir() and not directory.is_symlink(), 'Unsafe unit dependency directory')
            transaction.sync_directory(directory)
    transaction.sync_directory(UNIT_DIRECTORY)


def prepare_directories():
    BASE.mkdir(parents=True, exist_ok=True, mode=0o755)
    STATE.mkdir(parents=True, exist_ok=True, mode=0o700)
    require(not BASE.is_symlink() and BASE.stat().st_uid == 0, 'Unsafe helper directory')
    require(STATE.stat().st_uid == 0 and not STATE.is_symlink()
            and STATE.stat().st_mode & 0o077 == 0, 'State directory must be root-owned 0700')


def install():
    transaction.assert_no_pending(STATE)
    power = preflight()
    if MANIFEST.exists():
        old = json.loads(MANIFEST.read_text())
        if old.get('active', True):
            check_owned(old)
            require(all(sha(source) == old['installed_sha256'][str(target)]
                        for target, (source, _) in payloads().items()),
                    'A different version is installed; keep its checkout and run its undo.sh before applying this version')
            for unit in (POWER, TIMER):
                run(['systemctl', 'enable', '--now', unit])
            sync_service_links()
            print('Already applied; installed files verified and startup units enabled.')
            return
    for target in payloads():
        require(not target.exists() and not target.is_symlink(), f'Refusing to overwrite: {target}')
    require(not (STATE / 'STOP').exists(), 'A STOP marker exists; inspect the previous verification failure first')
    # Compile/validate units before touching system paths; missing not-yet-installed ExecStart
    # commands are avoided by validating after files are staged, before enabling anything.
    prepare_directories()
    tx = transaction.Transaction.begin(STATE, payloads(), 'install')
    try:
        for target, (source, mode) in payloads().items():
            tx.publish(target, source.read_bytes(), write_new)
        tx.phase('validating')
        run(['systemd-analyze', 'verify', *[Path('/etc/systemd/system') / unit for unit in UNITS]])
        # Exact shipped ioctl path, only on a fresh private disposable fixture.
        test = load_module('storage_defaults_repack').self_test(STATE)
        require(test['status'] == 'repacked', 'Disposable layout validation failed')
        installed = list(map(str, payloads()))
        manifest = dict(format_version=2, active=True, installed_at=time.time(), transaction_id=tx.data['id'],
                        original_nvme_qos_us=power.info()['latency_tolerance_us'],
                        installed_files=installed, installed_sha256={p: sha(Path(p)) for p in installed},
                        disposable_validation=test)
        tx.phase('activating', activation_started=True)
        run(['systemctl', 'daemon-reload'])
        run(['systemctl', 'enable', '--now', POWER])
        require(power.info()['latency_tolerance_us'] == power.TARGET, 'Drive did not accept the setting')
        run(['systemctl', 'enable', '--now', TIMER])
        sync_service_links()
        tx.phase('committing')
        write_manifest(manifest)
        tx.finish('installed')
        print('Applied. Drive cap: 5000 us. Gradual repacking starts after the next timer interval.')
    except BaseException:
        # SIGKILL/power loss leaves the same journal for an explicit --recover.
        recover()
        raise


def uninstall():
    transaction.assert_no_pending(STATE)
    if not MANIFEST.exists():
        print('No owned installation found. No changes made.')
        return
    manifest = json.loads(MANIFEST.read_text())
    if not manifest.get('active', True):
        print('Already removed. Audit state retained.')
        return
    check_owned(manifest)
    tx = transaction.Transaction.begin(STATE, payloads(), 'remove', manifest)
    complete_removal(tx, manifest)
    print('Removed services and restored the captured drive power setting. '
          'Repacked extents and audit state are retained; old layout/reflink sharing is not reconstructed.')


def complete_removal(tx, manifest):
    # Validate the complete remaining set before stopping anything or deleting a file.
    tx.audit_targets()
    if not tx.data['services_stopped']:
        stop_all()
        tx.phase('removing', services_stopped=True)
    for entry in reversed(tx.data['entries']):
        tx.delete_target(entry)
    run(['systemctl', 'daemon-reload'])
    tx.phase('committing')
    manifest.update(active=False, removed_at=time.time(), transaction_id=tx.data['id'])
    write_manifest(manifest)
    tx.finish('removed')


def recover():
    tx = transaction.Transaction.load(STATE, payloads())
    if tx is None:
        print('No interrupted transaction found. No installed files or services changed.')
        return
    manifest = json.loads(MANIFEST.read_text()) if MANIFEST.exists() else {}
    committed = manifest.get('transaction_id') == tx.data['id']
    if tx.data['operation'] == 'remove':
        if committed and not manifest.get('active', True):
            tx.finish('recovered-committed-removal')
        else:
            complete_removal(tx, manifest)
        print('Recovered interrupted removal; audit state retained.')
        return
    if committed and manifest.get('active') is True:
        check_owned(manifest)
        tx.audit_stages()
        # An older interrupted commit can retain the manifest while losing an
        # unsynchronized startup link. Complete the committed activation intent.
        run(['systemctl', 'daemon-reload'])
        for unit in (POWER, TIMER):
            run(['systemctl', 'enable', '--now', unit])
        sync_service_links()
        tx.finish('recovered-committed-install')
        print('Committed installation preserved; interrupted staging cleanup completed.')
        return
    tx.audit_targets()
    tx.audit_stages()
    if tx.data['activation_started'] and not tx.data['services_stopped']:
        stop_all()
    tx.phase('rolling-back', services_stopped=True)
    for entry in reversed(tx.data['entries']):
        tx.delete_target(entry)
    run(['systemctl', 'daemon-reload'])
    if tx.data['activation_started']:
        entries = tx.data['entries']
        write_manifest(dict(format_version=2, active=False, failed_install=True, transaction_id=tx.data['id'],
                            installed_files=[e['target'] for e in entries],
                            installed_sha256={e['target']: e['sha256'] for e in entries}))
    tx.finish('recovered-rolled-back-install')
    print('Interrupted installation rolled back; no previous extent layout was changed by recovery.')


def status():
    pending = transaction.Transaction.load(STATE, payloads())
    if pending:
        print('Interrupted transaction:', pending.data['operation'], pending.data['phase'],
              '(run sudo sh apply.sh --recover after inspection)')
    for unit in UNITS:
        result = subprocess.run(['systemctl', 'show', unit, '-p', 'LoadState', '-p', 'UnitFileState',
                                 '-p', 'ActiveState', '-p', 'SubState', '-p', 'Result'],
                                capture_output=True, text=True, timeout=10)
        print(f'{unit}\n{result.stdout.strip()}')
    path = Path('/sys/class/nvme/nvme0/power/pm_qos_latency_tolerance_us')
    print('Drive latency tolerance (us):', path.read_text().strip() if path.exists() else 'unavailable')
    if (STATE / 'STOP').exists():
        print('STOP marker present: inspect the journal before restarting maintenance.')
    if (STATE / 'last-run.json').exists():
        print((STATE / 'last-run.json').read_text())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--check', '--dry-run', dest='check', action='store_true', help='Read-only compatibility check')
    group.add_argument('--uninstall', action='store_true', help='Stop and remove owned defaults')
    group.add_argument('--status', action='store_true', help='Show units, live power setting and last pass')
    group.add_argument('--recover', action='store_true', help='Recover an owned interrupted install/removal')
    args = parser.parse_args()
    if args.check:
        preflight()
        return
    require(os.geteuid() == 0, 'Run with sudo (or use --check without installing)')
    if args.status:
        status()
        return
    with transaction.installation_lock(STATE):
        if args.recover:
            recover()
        elif args.uninstall:
            uninstall()
        else:
            install()


if __name__ == '__main__':
    try:
        main()
    except (OSError, RuntimeError, ValueError, KeyError, subprocess.SubprocessError) as error:
        sys.exit(str(error))
