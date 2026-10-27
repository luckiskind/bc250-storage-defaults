"""Durable seven-file installation transactions; no services are controlled here."""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import uuid


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_json(path, data):
    fd, temporary = tempfile.mkstemp(prefix='.transaction-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(data, stream, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        sync_directory(path.parent)
    finally:
        Path(temporary).unlink(missing_ok=True)


def private_state(state):
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    s = state.lstat()
    require(stat.S_ISDIR(s.st_mode) and s.st_uid == os.geteuid() and s.st_mode & 0o077 == 0,
            'Installation state must be an owned private directory')


@contextmanager
def installation_lock(state):
    import fcntl
    private_state(state)
    fd = os.open(state / 'installer.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        s = os.fstat(fd)
        require(stat.S_ISREG(s.st_mode) and s.st_uid == os.geteuid() and s.st_mode & 0o077 == 0,
                'Unsafe installer lock')
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError('Another installer/recovery process is running') from None
        yield
    finally:
        os.close(fd)


def pending_path(state):
    return state / 'transaction.json'


def assert_no_pending(state):
    path = pending_path(state)
    require(not path.exists() and not path.is_symlink(),
            'An interrupted transaction exists; inspect status and run sudo sh apply.sh --recover')


def bounded_bytes(path):
    with path.open('rb') as stream:
        data = stream.read(4 * 2**20 + 1)
    require(len(data) <= 4 * 2**20, f'Transaction metadata file exceeds the 4 MiB limit: {path}')
    return data


def fingerprint(path):
    s = path.lstat()
    require(stat.S_ISREG(s.st_mode) and s.st_uid == os.geteuid(), f'Unsafe transaction file: {path}')
    require(s.st_size <= 4 * 2**20, f'Transaction metadata file exceeds the 4 MiB limit: {path}')
    return dict(device=s.st_dev, inode=s.st_ino, mode=stat.S_IMODE(s.st_mode),
                sha256=hashlib.sha256(bounded_bytes(path)).hexdigest())


class Transaction:
    def __init__(self, state, data, files):
        self.state = state
        self.data = data
        self.files = files

    @classmethod
    def begin(cls, state, files, operation, manifest=None):
        private_state(state)
        assert_no_pending(state)
        token = uuid.uuid4().hex
        entries = []
        for index, (target, (source, mode)) in enumerate(files.items()):
            entry = dict(target=str(target), mode=mode)
            if operation == 'install':
                require(not target.exists() and not target.is_symlink(), f'Refusing to overwrite: {target}')
                contents = bounded_bytes(source)
                entry.update(sha256=hashlib.sha256(contents).hexdigest(), size=len(contents),
                             staged=str(target.parent / f'.bc250-storage-{token}-{index}'))
            elif operation == 'remove':
                identity = fingerprint(target)
                require(identity['sha256'] == manifest['installed_sha256'][str(target)] and identity['mode'] == mode,
                        f'Administrator modified {target}; review before removal')
                entry.update(identity)
            else:
                raise RuntimeError('Unknown transaction operation')
            entries.append(entry)
        data = dict(format_version=1, id=token, operation=operation,
                    phase='staging' if operation == 'install' else 'stopping',
                    activation_started=False, services_stopped=False, entries=entries)
        tx = cls(state, data, files)
        tx.save()
        return tx

    @classmethod
    def load(cls, state, files):
        private_state(state)
        path = pending_path(state)
        if not path.exists() and not path.is_symlink():
            return None
        s = path.lstat()
        require(stat.S_ISREG(s.st_mode) and s.st_uid == os.geteuid() and s.st_mode & 0o077 == 0,
                'Unsafe transaction journal')
        data = json.loads(bounded_bytes(path))
        require(isinstance(data, dict) and data.get('format_version') == 1
                and isinstance(data.get('id'), str) and re.fullmatch('[0-9a-f]{32}', data['id']),
                'Unsupported transaction journal')
        require(data.get('operation') in ('install', 'remove'), 'Invalid transaction operation')
        require(type(data.get('activation_started')) is bool and type(data.get('services_stopped')) is bool,
                'Invalid transaction service state')
        require(data.get('phase') in ('staging', 'validating', 'activating', 'committing', 'rolling-back', 'stopping', 'removing'),
                'Invalid transaction phase')
        entries = data.get('entries', [])
        require(isinstance(entries, list) and all(isinstance(e, dict) and isinstance(e.get('target'), str) for e in entries)
                and len(entries) == len(files) and {e['target'] for e in entries} == set(map(str, files)),
                'Unexpected paths in transaction journal')
        # Validate all paths and modes before inspecting any destination or staged file.
        for index, entry in enumerate(entries):
            target = Path(entry['target'])
            require(entry.get('mode') == files[target][1] and isinstance(entry.get('sha256'), str)
                    and re.fullmatch('[0-9a-f]{64}', entry['sha256']),
                    'Invalid transaction file metadata')
            if data['operation'] == 'install':
                expected = target.parent / f'.bc250-storage-{data["id"]}-{index}'
                require(entry.get('staged') == str(expected), 'Unexpected staging path')
                require(type(entry.get('size')) is int and 0 <= entry['size'] <= 4 * 2**20, 'Invalid staged size')
                if 'staged_identity' in entry:
                    require(isinstance(entry['staged_identity'], dict) and set(entry['staged_identity']) == {'device', 'inode'}
                            and all(type(v) is int for v in entry['staged_identity'].values()), 'Invalid staging identity')
            else:
                require(type(entry.get('inode')) is int and type(entry.get('device')) is int,
                        'Missing removal identity')
        return cls(state, data, files)

    def save(self):
        atomic_json(pending_path(self.state), self.data)

    def phase(self, phase, **changes):
        self.data.update(phase=phase, **changes)
        self.save()

    def publish(self, target, data, writer):
        entry = next(e for e in self.data['entries'] if e['target'] == str(target))
        require(hashlib.sha256(data).hexdigest() == entry['sha256'], 'Package changed during staging')
        target.parent.mkdir(parents=True, exist_ok=True)
        staged = Path(entry['staged'])
        writer(staged, data, entry['mode'])
        actual = fingerprint(staged)
        require(actual['sha256'] == entry['sha256'] and actual['mode'] == entry['mode'], 'Staging verification failed')
        entry['staged_identity'] = {k: actual[k] for k in ('device', 'inode')}
        self.save()
        sync_directory(staged.parent)
        # Stage and destination share a directory/filesystem. link never replaces
        # an existing target and leaves an inode-identity witness until commit.
        os.link(staged, target, follow_symlinks=False)
        sync_directory(target.parent)

    def check_target(self, entry):
        target = Path(entry['target'])
        if not target.exists() and not target.is_symlink():
            return False
        current = fingerprint(target)
        require(current['sha256'] == entry['sha256'] and current['mode'] == entry['mode'],
                f'Administrator modified {target}; recovery preserved all files')
        if self.data['operation'] == 'install':
            staged = Path(entry['staged'])
            require(staged.exists() and not staged.is_symlink(), f'Missing ownership witness for {target}')
            owner = staged.lstat()
            require((owner.st_dev, owner.st_ino) == (current['device'], current['inode']),
                    f'Ownership changed for {target}; recovery preserved all files')
        else:
            require((entry['device'], entry['inode']) == (current['device'], current['inode']),
                    f'Ownership changed for {target}; recovery preserved all files')
        return True

    def audit_targets(self):
        for entry in self.data['entries']:
            self.check_target(entry)

    def delete_target(self, entry):
        if self.check_target(entry):
            target = Path(entry['target'])
            target.unlink()
            sync_directory(target.parent)

    def clean_stage(self, entry):
        if 'staged' not in entry:
            return
        path = Path(entry['staged'])
        if not path.exists() and not path.is_symlink():
            return
        self.check_stage(entry)
        # Removing this known extra name does not remove the installed target.
        path.unlink()
        sync_directory(path.parent)

    def check_stage(self, entry):
        if 'staged' not in entry:
            return
        path = Path(entry['staged'])
        if not path.exists() and not path.is_symlink():
            return
        s = path.lstat()
        require(stat.S_ISREG(s.st_mode) and s.st_uid == os.geteuid() and s.st_size <= entry['size'],
                'Unsafe staging artifact; retained for inspection')
        identity = entry.get('staged_identity')
        if identity:
            require((s.st_dev, s.st_ino) == (identity['device'], identity['inode']),
                    'Staging ownership changed; artifact preserved')
            require(stat.S_IMODE(s.st_mode) == entry['mode'] and fingerprint(path)['sha256'] == entry['sha256'],
                    'Staging contents changed; artifact preserved')
        else:
            # An interrupted writer may not have recorded its inode yet. It
            # can be cleaned only if it contains a verified prefix of the same
            # package file. A changed checkout needs the matching old version.
            source = bounded_bytes(self.files[Path(entry['target'])][0])
            require(hashlib.sha256(source).hexdigest() == entry['sha256']
                    and bounded_bytes(path) == source[:s.st_size]
                    and stat.S_IMODE(s.st_mode) in (0o600, entry['mode']),
                    'Unknown partial staging data; preserve it and use the matching package checkout')

    def audit_stages(self):
        for entry in self.data['entries']:
            self.check_stage(entry)

    def finish(self, outcome):
        self.audit_stages()
        for entry in self.data['entries']:
            self.clean_stage(entry)
        atomic_json(self.state / 'last-transaction.json', dict(self.data, outcome=outcome))
        pending_path(self.state).unlink()
        sync_directory(self.state)
