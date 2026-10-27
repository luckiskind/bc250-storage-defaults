#!/usr/bin/env python3
"""Build independent native-Btrfs data copies for layout/power experiments.

Never modifies source files, mount options, controller settings or an existing
output directory. These are data fixtures, not restored full-system baselines.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import random
import stat
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import storage_defaults_repack as repack

RESERVE = 64 * 2**30
MAX_SOURCE_BYTES = 256 * 2**20


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def copy_bytes(source, target):
    """Userspace read/write only: no reflink, copy_file_range or source metadata edits."""
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_size <= MAX_SOURCE_BYTES, 'Unsupported source file')
        digest = hashlib.sha256()
        out = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(out, 'wb') as stream:
            offset = 0
            while offset < before.st_size:
                block = os.pread(fd, min(2**20, before.st_size-offset), offset)
                require(block, 'Source truncated during copying')
                stream.write(block);digest.update(block);offset += len(block)
            stream.flush();os.fsync(stream.fileno())
        after = os.fstat(fd)
        require((before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                (after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'Source changed during copying')
        return digest.hexdigest()
    finally:
        os.close(fd)


def layout(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        s = os.fstat(fd)
        spans = repack.extents(fd, s.st_size)
        histogram = {}
        for offset, length, flags in spans:
            if flags & 8:
                histogram[str(length)] = histogram.get(str(length), 0) + 1
        return dict(bytes=s.st_size, sha256=repack.digest(fd), allocated_file_bytes=s.st_blocks*512,
                    extent_count=len(spans), encoded_logical_length_histogram=histogram,
                    encoded_extent_max=max((n for _, n, f in spans if f & 8), default=0),
                    shared_extent_count=sum(bool(f & 0x2000) for _, _, f in spans))
    finally:
        os.close(fd)


def atomic_report(path, report):
    temporary = path.with_suffix('.pending')
    with temporary.open('x') as stream:
        json.dump(report, stream, indent=2);stream.write('\n');stream.flush();os.fsync(stream.fileno())
    os.replace(temporary, path)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)


def build(output, sources, control_mib=32):
    require(not output.exists() and not output.is_symlink(), 'Output must be a new directory; existing data is never overwritten')
    parent = output.parent.resolve(strict=True)
    fs = os.statvfs(parent)
    require(fs.f_bavail*fs.f_frsize >= RESERVE + 3*(MAX_SOURCE_BYTES+64*2**20), 'Insufficient free space for bounded fixtures')
    raw = subprocess.check_output(['findmnt', '--json', '-o', 'FSTYPE,OPTIONS', '--target', str(parent)], text=True)
    mount = json.loads(raw)['filesystems'][0]
    require(mount['fstype'] == 'btrfs' and 'compress=zstd:1' in mount['options'].split(','),
            'This baseline builder requires the qualified Btrfs zstd:1 mount policy')
    require(1 <= control_mib <= 64, 'Control size must be 1–64 MiB')
    sources = [p.resolve(strict=True) for p in sources]
    require(sources and len(sources) <= 16, 'Provide 1–16 explicit source files')
    total = 0
    for source in sources:
        s = source.stat()
        require(stat.S_ISREG(s.st_mode) and 2**20 <= s.st_size <= MAX_SOURCE_BYTES, 'Source must be a regular 1–256 MiB file')
        with source.open('rb') as stream:
            require(stream.read(4) == b'\x7fELF', 'Source must be an ELF fixture')
        total += s.st_size
    require(total <= MAX_SOURCE_BYTES, 'Combined source payload is capped at 256 MiB')
    output.mkdir(mode=0o700)
    incomplete = output / 'INCOMPLETE'
    incomplete.write_text('Do not benchmark: fixture construction/verification has not committed.\n')
    for name in ('B0', 'B1', 'B2'):
        (output/name).mkdir(mode=0o700)
    provenance = dict(sources={f'elf-{i:02d}.bin':str(p) for i,p in enumerate(sources)},
                      note='Private source paths; do not redistribute this file without review')
    atomic_report(output/'source-paths-private.json', provenance)
    cases = []
    for index, source in enumerate(sources):
        name = f'elf-{index:02d}.bin'
        digest = copy_bytes(source, output/'B0'/name)
        cases.append(dict(name=name, kind='elf', sha256=digest))
    control = output/'B0/control.bin'
    rng = random.Random(0xBC250)
    with control.open('xb') as stream:
        for _ in range(control_mib):stream.write(rng.randbytes(2**20))
        stream.flush();os.fsync(stream.fileno())
    control.chmod(0o600)
    cases.append(dict(name='control.bin',kind='incompressible-control',sha256=layout(control)['sha256']))
    report = dict(schema_version=1, builder_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  created_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()), python=sys.version.split()[0],
                  kernel=os.uname().release, full_system_baseline=False, power_settings_changed=False,
                  source_paths_in_public_manifest=False, controller_policy_applied_to_host=False,
                  required_nvme_qos_us={'B0':100000,'B1':5000,'B2':5000},
                  budget_units='submitted logical layout work; not physical device writes',
                  note='Fresh byte copies under the recorded mount policy; not historical pre-study physical extents',
                  cases=cases, variants={})
    cfg=dict(min_file_bytes=2**20,max_file_bytes=MAX_SOURCE_BYTES,quiet_seconds=0)
    for variant in ('B0','B1','B2'):
        rows=[]
        for case in cases:
            target=output/variant/case['name']
            if variant!='B0':require(copy_bytes(output/'B0'/case['name'],target)==case['sha256'],'Copy hash mismatch')
            action=dict(status='native-mount-policy')
            if variant=='B2' and case['kind']=='elf':
                fd=os.open(target,os.O_RDWR|os.O_NOFOLLOW)
                try:
                    reason=repack.eligible(fd,cfg,time.time())
                    if reason:action=dict(status='bypassed',reason=reason)
                    elif repack.compression_sample(fd,os.fstat(fd).st_size)>.9:
                        action=dict(status='bypassed',reason='little-compression-benefit')
                    else:
                        action=repack.repack(fd,cfg,time.monotonic()+120,failure_state=output,
                                             byte_budget=os.fstat(fd).st_size+repack.MAX_LAYOUT_RETRY_BYTES)
                finally:os.close(fd)
            measured=layout(target)
            require(measured['sha256']==case['sha256'],'Fixture content mismatch')
            require(measured['shared_extent_count']==0,'Fixture sharing detected; independent-copy requirement failed')
            rows.append(dict(name=case['name'],action=action,layout=measured))
        report['variants'][variant]=rows
    # Recheck after all copies exist; a later clone/dedupe must not invalidate an earlier independence check.
    for variant, rows in report['variants'].items():
        for row in rows:
            current=layout(output/variant/row['name'])
            require(current['sha256']==row['layout']['sha256'] and current['shared_extent_count']==0,
                    'Fixture changed or became shared during construction')
            row['layout']=current
    atomic_report(output/'manifest.json',report)
    incomplete.unlink()
    fd=os.open(output,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)
    return report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--source',type=Path,action='append',required=True)
    parser.add_argument('--control-mib',type=int,default=32)
    args=parser.parse_args()
    report=build(args.output,args.source,args.control_mib)
    print(json.dumps(dict(complete=True,variants=len(report['variants']),cases=len(report['cases']),
                         power_settings_changed=False,full_system_baseline=False)))


if __name__=='__main__':main()
