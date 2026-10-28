#!/usr/bin/python3
"""Bounded automatic 16 KiB Btrfs repacking of stable compressible ELF files."""
import argparse, tempfile, collections, ctypes as C, ctypes.util, fcntl, hashlib, json, os, signal, sqlite3, stat, struct, time
from pathlib import Path
CONFIG = Path('/etc/bc250-storage-defaults.json')
STATE = Path('/var/lib/bc250-storage-defaults')
libc = C.CDLL(None, use_errno=True)
libc.sync_file_range.argtypes = [C.c_int, C.c_int64, C.c_int64, C.c_uint]
libc.sync_file_range.restype = C.c_int
zstd = C.CDLL(ctypes.util.find_library('zstd'))
zstd.ZSTD_compressBound.argtypes = [C.c_size_t]
zstd.ZSTD_compressBound.restype = C.c_size_t
zstd.ZSTD_compress.argtypes = [C.c_void_p, C.c_size_t, C.c_void_p, C.c_size_t, C.c_int]
zstd.ZSTD_compress.restype = C.c_size_t
zstd.ZSTD_isError.argtypes = [C.c_size_t]
zstd.ZSTD_isError.restype = C.c_uint
stopping = False
MAX_LAYOUT_RETRY_BYTES = 2 ** 20

def stop(*_):
    global stopping
    stopping = True

def extents(fd, size):
    answer = []
    start = 0
    while start < size:
        b = bytearray(32 + 56 * 256)
        struct.pack_into('=QQIIII', b, 0, start, size - start, 0, 0, 256, 0)
        fcntl.ioctl(fd, 0xC020660B, b, True)  # FS_IOC_FIEMAP
        n = struct.unpack_from('=I', b, 20)[0]
        if not n:
            break
        for i in range(n):
            e = struct.unpack_from('=QQQQQIIII', b, 32 + i * 56)
            answer.append((e[0], min(e[2], size - e[0]), e[5]))
        end = answer[-1][0] + answer[-1][1]
        if end <= start or answer[-1][2] & 1:
            break
        start = end
    return answer

def signature(s):
    return f'{s.st_dev}:{s.st_ino}:{s.st_size}:{s.st_mtime_ns}:{s.st_ctime_ns}'

def digest(fd):
    h = hashlib.sha256()
    off = 0
    limit = os.fstat(fd).st_size
    if not limit <= 256 * 2 ** 20:
        raise RuntimeError('File grew beyond the supported size')
    while off < limit:
        b = os.pread(fd, min(2 ** 20, limit - off), off)
        if not b:
            break
        h.update(b)
        off += len(b)
    return h.hexdigest()

def compression_sample(fd, size):
    stored = 0
    total = 0
    for off in sorted(set((0, size // 2 // 16384 * 16384, max(0, (size - 16384) // 16384 * 16384)))):
        b = os.pread(fd, min(16384, size - off), off)
        dest = C.create_string_buffer(zstd.ZSTD_compressBound(len(b)))
        n = zstd.ZSTD_compress(dest, len(dest), b, len(b), 1)
        if not not zstd.ZSTD_isError(n):
            raise RuntimeError('Safety check failed')
        stored += min((n + 4095) // 4096 * 4096, len(b))
        total += len(b)
    return stored / total

def eligible(fd, cfg, now):
    s = os.fstat(fd)
    if not stat.S_ISREG(s.st_mode) or s.st_nlink != 1:
        return 'not-single-regular'
    if not cfg['min_file_bytes'] <= s.st_size <= cfg['max_file_bytes']:
        return 'size'
    if now - s.st_mtime < cfg['quiet_seconds']:
        return 'recently-modified'
    if s.st_mode & (stat.S_ISUID | stat.S_ISGID):
        return 'privileged-binary'
    buf = bytearray(256)
    fcntl.ioctl(fd, 0x80086601, buf, True)  # FS_IOC_GETFLAGS on Linux x86_64
    flags = struct.unpack_from('=L', buf)[0]
    if flags & (16 | 32 | 8388608 | 1024):
        return 'protected-or-explicitly-uncompressed'
    magic = C.create_string_buffer(256)
    if libc.fstatfs(fd, magic) or C.c_long.from_buffer(magic).value != 2435016766:
        return 'not-btrfs'
    if os.pread(fd, 4, 0) != b'\x7fELF':
        return 'outside-validated-binary-class'
    spans = extents(fd, s.st_size)
    if not spans or sum((e[1] for e in spans)) < s.st_size:
        return 'sparse'
    if any((e[2] & (2 | 4 | 128 | 256 | 512 | 2048) for e in spans)):
        return 'unsupported-extent'
    if all((not e[2] & 8 or e[1] <= 16384 for e in spans)) and sum((e[1] for e in spans if e[2] & 8)) >= s.st_size * 0.8:
        return 'already-small-compressed'
    return None

def repack(fd, cfg, deadline, failure_state=None, byte_budget=None):
    before = os.fstat(fd)
    h = digest(fd)
    shared = any((e[2] & 8192 for e in extents(fd, before.st_size)))
    done = 0
    charged = 0
    retry_bytes = 0
    limit = before.st_size if byte_budget is None else byte_budget
    for off in range(0, before.st_size, 16384):
        length = min(16384, before.st_size - off)
        if stopping or time.monotonic() > deadline or charged + length > limit:
            break
        # BTRFS_IOC_DEFRAG_RANGE: COMPRESS|START_IO|COMPRESS_LEVEL, zstd:1.
        args = struct.pack('=QQQII4I', off, 16384, 7, 1, 0x103, 0, 0, 0, 0)
        fcntl.ioctl(fd, 0x40309410, args)
        if libc.sync_file_range(fd, off, 16384, 7):
            raise OSError(C.get_errno(), 'sync_file_range')
        done = min(before.st_size, off + 16384)
        charged += length
    os.fsync(fd)
    # A requested range is not a guaranteed extent boundary. Retry only residual
    # large compressed extents, once, with fsync between ranges and a byte cap.
    spans = extents(fd, before.st_size)
    residual = [(off, n) for off, n, flags in spans if flags & 8 and n > 16384 and off < done]
    for start, size in residual:
        for off in range(start, min(start + size, done), 16384):
            length = min(16384, before.st_size - off, done - off)
            if (stopping or time.monotonic() > deadline or charged + length > limit
                    or retry_bytes + length > MAX_LAYOUT_RETRY_BYTES):
                break
            fcntl.ioctl(fd, 0x40309410, struct.pack('=QQQII4I', off, length, 7, 1, 0x103, 0, 0, 0, 0))
            os.fsync(fd)
            charged += length
            retry_bytes += length
    os.fsync(fd)
    after = os.fstat(fd)
    h_after = digest(fd)
    if before.st_size != after.st_size or before.st_mtime_ns != after.st_mtime_ns:
        return {'status': 'changed-during-pass', 'processed_bytes': done, 'charged_bytes': charged, 'retry_bytes': retry_bytes}
    if h != h_after:
        ((failure_state or STATE) / 'STOP').write_text('Content verification failed; automatic processing stopped.\n')
        raise RuntimeError('SHA-256 mismatch; automatic repacking stopped')
    spans = extents(fd, after.st_size)
    large = [(off, n) for off, n, flags in spans if flags & 8 and n > 16384 and off < done]
    if not (before.st_uid, before.st_gid, stat.S_IMODE(before.st_mode)) == (after.st_uid, after.st_gid, stat.S_IMODE(after.st_mode)):
        raise RuntimeError('Safety check failed')
    status = 'partial-verified' if done != before.st_size else ('layout-not-achieved-verified' if large else 'repacked')
    return {'status': status, 'processed_bytes': done, 'charged_bytes': charged, 'retry_bytes': retry_bytes,
            'sha256': h, 'shared_before': shared, 'layout_target_met': not large,
            'large_extent_count': len(large), 'encoded_extent_max': max((n for _, n, f in spans if f & 8), default=0)}


def open_ledger(path):
    """Require explicit strong commit synchronization for the write-work ledger."""
    db = sqlite3.connect(path)
    try:
        # FULL in rollback-journal mode protects consistency but may lose the
        # last commit after power loss. EXTRA also syncs journal unlink metadata.
        db.execute('PRAGMA synchronous=EXTRA')
        if db.execute('PRAGMA synchronous').fetchone()[0] != 3:
            raise RuntimeError('Cannot establish strong ledger synchronization')
        if db.execute('PRAGMA journal_mode').fetchone()[0].lower() not in ('delete', 'wal'):
            raise RuntimeError('Unsupported ledger journal mode; no repacking performed')
        return db
    except BaseException:
        db.close()
        raise


def reserve_budget(db, day, path, sig, amount):
    """Commit a conservative reservation before any layout-changing syscall."""
    with db:
        db.execute('INSERT INTO budget VALUES(?,?) ON CONFLICT(day) DO UPDATE SET bytes=bytes+excluded.bytes', (day, amount))
        row = db.execute('INSERT INTO attempts(path,signature,day,reserved_bytes,status) VALUES(?,?,?,?,?)',
                         (path, sig, day, amount, 'started'))
    return row.lastrowid


def finish_budget(db, attempt, day, reserved, record):
    charged = record['charged_bytes']
    if not 0 <= charged <= reserved:
        raise RuntimeError('Attempt exceeded its reserved write-work budget')
    with db:
        db.execute('UPDATE budget SET bytes=bytes-? WHERE day=?', (reserved - charged, day))
        db.execute('UPDATE attempts SET charged_bytes=?,status=? WHERE id=?', (charged, record['status'], attempt))

def walk(cfg):

    def keep(base, name, dirfd, rootdev):
        try:
            p = os.path.join(base, name)
            s = os.stat(name, dir_fd=dirfd, follow_symlinks=False)
            return name not in cfg['excluded_dir_names'] and (not stat.S_ISLNK(s.st_mode)) and (s.st_dev == rootdev) and (not any((p == x or p.startswith(x + '/') for x in cfg['excluded_paths'])))
        except OSError:
            return False
    for root in cfg['roots']:
        if not Path(root).is_dir() or Path(root).is_symlink():
            continue
        rootdev = os.stat(root).st_dev
        for base, dirs, files, dirfd in os.fwalk(root, follow_symlinks=False, onerror=lambda _: None):
            dirs[:] = sorted((d for d in dirs if keep(base, d, dirfd, rootdev)))
            for name in sorted(files):
                yield (os.path.join(base, name), dirfd, name)

def self_test(directory):
    """Only mutate a newly created private fixture, never a caller-supplied file."""
    directory = directory.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix='bc250-layout-test-', dir=directory) as scratch:
        target = Path(scratch) / 'fixture.elf'
        block = b'\x7fELF' + bytes(range(256)) * 16 + b'\x00' * 12284
        with target.open('xb') as f:
            for _ in range(128):
                f.write(block)
            f.flush()
            os.fsync(f.fileno())
        fd = os.open(target, os.O_RDWR | os.O_NOFOLLOW)
        try:
            reason = eligible(fd, dict(min_file_bytes=2 ** 20, max_file_bytes=256 * 2 ** 20, quiet_seconds=0), time.time())
            if reason not in (None, 'already-small-compressed'):
                raise RuntimeError('Self-test requires a writable Btrfs directory: ' + str(reason))
            result = repack(fd, {}, time.monotonic() + 120, failure_state=Path(scratch),
                            byte_budget=os.fstat(fd).st_size + MAX_LAYOUT_RETRY_BYTES)
            if result['status'] != 'repacked' or result['encoded_extent_max'] != 16384:
                raise RuntimeError('Kernel did not produce verified 16 KiB compressed extents: ' + json.dumps(result))
            return result
        finally:
            os.close(fd)

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--dry-run', action='store_true')
    p.add_argument('--self-test', type=Path, metavar='BTRFS_DIRECTORY', help='Create and verify a disposable fixture in this directory')
    p.add_argument('--check-access', action='store_true')
    a = p.parse_args()
    if os.geteuid() != 0:
        raise RuntimeError('Run maintenance as root')
    if a.check_access:
        paths = ('/usr/bin', '/usr/lib', '/usr/share', '/usr/local', '/home')
        report = {p: bool(os.statvfs(p).f_flag & os.ST_RDONLY) for p in paths}
        print(json.dumps({'readonly_paths': report}))
        if any(report.values()):
            raise RuntimeError('Required binary directories are read-only')
        return
    if a.self_test:
        print(json.dumps(self_test(a.self_test)))
        return
    cfg = json.loads(CONFIG.read_text())
    STATE.mkdir(mode=0o700, exist_ok=True)
    # Persist a newly created state-directory name before durable reservations
    # inside it can authorize mutations elsewhere on the filesystem.
    parent = os.open(STATE.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)
    if (STATE / 'STOP').exists():
        raise SystemExit('Repacking disabled by STOP marker; inspect the journal')
    lock = os.open(STATE / 'lock', os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return
    db = open_ledger(STATE / 'state.sqlite3')
    db.execute('CREATE TABLE IF NOT EXISTS files(path TEXT PRIMARY KEY, signature TEXT, status TEXT, bytes INTEGER, day TEXT)')
    db.execute('CREATE TABLE IF NOT EXISTS budget(day TEXT PRIMARY KEY, bytes INTEGER)')
    db.execute('CREATE TABLE IF NOT EXISTS attempts(id INTEGER PRIMARY KEY, path TEXT, signature TEXT, day TEXT, reserved_bytes INTEGER, charged_bytes INTEGER, status TEXT)')
    db.commit()
    report = {'started': time.time(), 'dry_run': a.dry_run, 'counts': collections.Counter(), 'processed_bytes': 0,
              'charged_bytes': 0, 'retry_bytes': 0, 'verified_files': 0}
    day = time.strftime('%Y-%m-%d', time.gmtime())
    daily = db.execute('SELECT COALESCE(SUM(bytes),0) FROM budget WHERE day=?', (day,)).fetchone()[0]
    if not a.dry_run:
        if os.getloadavg()[0] > cfg['max_load']:
            print('Deferred: foreground CPU load')
            return
        quiet = False
        for _ in range(10):
            b = list(map(int, Path('/sys/block/nvme0n1/stat').read_text().split()))
            time.sleep(3)
            c = list(map(int, Path('/sys/block/nvme0n1/stat').read_text().split()))
            if (c[2] - b[2] + (c[6] - b[6])) * 512 <= 2 ** 20 and c[9] - b[9] <= 300:
                quiet = True
                break
            if stopping:
                return
        if not quiet:
            print('Deferred: storage active; timer will retry')
            return
    deadline = time.monotonic() + cfg['max_run_seconds']
    for path, dirfd, name in walk(cfg):
        if stopping or time.monotonic() > deadline:
            break
        if cfg['max_bytes_per_run'] - report['charged_bytes'] < cfg['min_file_bytes'] or cfg['max_bytes_per_day'] - daily < cfg['min_file_bytes']:
            break
        fs = os.fstatvfs(dirfd)
        if fs.f_bavail * fs.f_frsize < cfg['reserve_free_bytes']:
            report['counts']['free-space-floor'] += 1
            continue
        fd = None
        wr = None
        attempt = None
        try:
            s = os.stat(name, dir_fd=dirfd, follow_symlinks=False)
            if not stat.S_ISREG(s.st_mode) or not cfg['min_file_bytes'] <= s.st_size <= cfg['max_file_bytes']:
                continue
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=dirfd)
            os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_RANDOM)
            s = os.fstat(fd)
            sig = signature(s)
            known = db.execute('SELECT signature FROM files WHERE path=?', (path,)).fetchone()
            if known and known[0] == sig:
                report['counts']['unchanged'] += 1
                continue
            reason = eligible(fd, cfg, time.time())
            if reason:
                report['counts'][reason] += 1
                if not a.dry_run and reason in ('outside-validated-binary-class', 'sparse', 'already-small-compressed', 'protected-or-explicitly-uncompressed', 'not-single-regular', 'privileged-binary'):
                    db.execute('INSERT OR REPLACE INTO files VALUES(?,?,?,?,?)', (path, sig, reason, 0, day))
                    if db.total_changes % 128 == 0:
                        db.commit()
                continue
            ratio = compression_sample(fd, s.st_size)
            if ratio > cfg['sample_max_stored_ratio']:
                report['counts']['little-compression-benefit'] += 1
                if not a.dry_run:
                    db.execute('INSERT OR REPLACE INTO files VALUES(?,?,?,?,?)', (path, sig, 'little-compression-benefit', 0, day))
                    if db.total_changes % 128 == 0:
                        db.commit()
                continue
            available = min(cfg['max_bytes_per_run'] - report['charged_bytes'], cfg['max_bytes_per_day'] - daily)
            if s.st_size > available:
                continue
            report['counts']['eligible'] += 1
            if a.dry_run:
                continue
            wr = os.open(name, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=dirfd)
            if signature(os.fstat(wr)) != sig:
                report['counts']['changed-before-start'] += 1
                continue
            reserved = min(s.st_size + MAX_LAYOUT_RETRY_BYTES, available)
            attempt = reserve_budget(db, day, path, sig, reserved)
            # On any exception or process death the reservation remains charged.
            # It is deliberately not refunded using an uncertain progress estimate.
            rec = repack(wr, cfg, deadline, byte_budget=reserved)
            finish_budget(db, attempt, day, reserved, rec)
            report['processed_bytes'] += rec['processed_bytes']
            report['charged_bytes'] += rec['charged_bytes']
            report['retry_bytes'] += rec['retry_bytes']
            daily += rec['charged_bytes']
            report['counts'][rec['status']] += 1
            if rec['status'] in ('repacked', 'layout-not-achieved-verified'):
                if rec['status'] == 'repacked':
                    report['verified_files'] += 1
                db.execute('INSERT OR REPLACE INTO files VALUES(?,?,?,?,?)', (path, signature(os.fstat(wr)), rec['status'], rec['processed_bytes'], day))
                db.commit()
            print(json.dumps({'file': path, **rec}), flush=True)
            time.sleep(0.2)
        except (PermissionError, FileNotFoundError, IsADirectoryError):
            if attempt is not None:
                raise
            report['counts']['unavailable'] += 1
        except OSError as e:
            # A failure after a reservation must end this pass. Continuing with a
            # stale in-memory daily counter could otherwise overspend its budget.
            if attempt is not None:
                raise
            if e.errno in (1, 16, 26, 30, 40, 95):
                report['counts']['busy-or-protected'] += 1
            else:
                raise
        finally:
            if wr is not None:
                os.close(wr)
            if fd is not None:
                os.close(fd)
            attempt = None
    report['finished'] = time.time()
    db.commit()
    db.close()
    (STATE / 'last-run.json').write_text(json.dumps(report, indent=2))
    print(json.dumps(report), flush=True)
if __name__ == '__main__':
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    main()
