#!/usr/bin/env python3
"""Compare extent synchronization on fresh private copies; source is read-only."""
import argparse
import ctypes as C
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('repacker', ROOT / 'storage_defaults_repack.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def trial(source, scratch, clone, per_range_fsync):
    with tempfile.TemporaryDirectory(prefix='bc250-extent-repro-', dir=scratch) as temporary:
        target = Path(temporary) / 'copy.bin'
        if clone:
            subprocess.run(['cp', '--reflink=always', '--', str(source), str(target)], check=True)
        else:
            with source.open('rb') as src, target.open('xb') as dst:
                shutil.copyfileobj(src, dst)
                dst.flush()
                os.fsync(dst.fileno())
        fd = os.open(target, os.O_RDWR | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
            before = m.digest(fd)
            size = os.fstat(fd).st_size
            before_spans = m.extents(fd, size)
            start = time.monotonic()
            for off in range(0, size, 16384):
                fcntl.ioctl(fd, 0x40309410, struct.pack('=QQQII4I', off, 16384, 7, 1, 0x103, 0, 0, 0, 0))
                if per_range_fsync:
                    os.fsync(fd)
                elif m.libc.sync_file_range(fd, off, 16384, 7):
                    raise OSError(C.get_errno(), 'sync_file_range')
            os.fsync(fd)
            elapsed = time.monotonic() - start
            after = m.digest(fd)
            spans = m.extents(fd, size)
            if before != after:
                raise RuntimeError('Disposable-copy content mismatch')
            large = [e for e in spans if e[2] & 8 and e[1] > 16384]
            return dict(copy='reflink' if clone else 'byte-copy', sync='fsync' if per_range_fsync else 'sync_file_range',
                        bytes=size, elapsed_s=elapsed, sha256=after, hash_verified=True,
                        encoded_max_before=max((n for _, n, f in before_spans if f & 8), default=0),
                        encoded_max_after=max((n for _, n, f in spans if f & 8), default=0),
                        large_extents=large[:16], large_extent_count=len(large))
        finally:
            os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--scratch', type=Path, required=True)
    args = parser.parse_args()
    source = args.source.resolve(strict=True)
    scratch = args.scratch.resolve(strict=True)
    if not source.is_file() or source.stat().st_size > 256 * 2**20:
        raise SystemExit('Requires a regular source of at most 256 MiB')
    original = hashlib.sha256(source.read_bytes()).hexdigest()
    for clone, fsync in ((False, False), (True, False), (True, True)):
        print(json.dumps(trial(source, scratch, clone, fsync)), flush=True)
    if hashlib.sha256(source.read_bytes()).hexdigest() != original:
        raise RuntimeError('Source changed externally during the test')


if __name__ == '__main__':
    main()
