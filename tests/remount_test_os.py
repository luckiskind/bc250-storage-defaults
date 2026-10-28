#!/usr/bin/env python3
"""Qualify private test-OS provenance using two NEW regular Btrfs images.

Root only; run through unshare --mount --propagation private. Uses the pinned
private seed only for migration authentication, never executes its contents.
Retains images and evidence, including on failure. Does not reboot the host.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'tools'))
import prepare_test_os as builder
from remount_install import command, new_image, require, validate_environment


def fixture(parent, name):
    area = parent/name; area.mkdir(mode=0o700)
    guest = area/'root.x86_64'; guest.mkdir()
    (guest/'payload').write_bytes(b'unchanged disposable payload\n')
    s = guest.stat()
    data = dict(private_os_tree=True, seed_sha256=builder.SEED_SHA256,
                guest_identity=[s.st_dev,s.st_ino], unrelated_field='preserve')
    (area/'construction.json').write_text(json.dumps(data)+'\n')
    return area


def refused(area, migrate=False):
    marker = (area/'construction.json').read_bytes()
    backups = sorted(p.name for p in area.glob('construction-v1-*'))
    try:
        (builder.migrate_identity if migrate else builder.check_workspace)(area)
    except RuntimeError as error:
        require('replaced' in str(error), 'Unexpected refusal: '+str(error))
    else:
        raise RuntimeError('Replaced or mismatched workspace was accepted')
    require((area/'construction.json').read_bytes() == marker and
            sorted(p.name for p in area.glob('construction-v1-*')) == backups,
            'Refusal changed provenance or created a backup')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scratch', type=Path, required=True)
    parser.add_argument('--seed-archive', type=Path, required=True)
    args = parser.parse_args()
    validate_environment(args.scratch)
    seed = args.seed_archive
    require(seed.is_absolute() and seed.resolve(strict=True) == seed and seed.is_file(), 'Unsafe seed path')
    area = Path(tempfile.mkdtemp(prefix='bc250-os-remount-',dir=args.scratch)); area.chmod(0o700)
    report = dict(passed=False, host_reboot_tested=False, actual_btrfs_mount_order_change=True,
        test_images=2, cases=[], source_sha256={name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest()
        for name in ('tools/prepare_test_os.py','install_transaction.py','tests/remount_test_os.py',
                     'tests/remount_install.py')})
    mounts = []
    def mount(image, where):
        command('mount','-o','loop,nosuid,nodev,noexec',image,where); mounts.append(where)
    def unmount(where):
        command('umount',where); mounts.remove(where)
    def passed(name, **details):
        report['cases'].append(dict(case=name,passed=True,**details))
    try:
        a, am = new_image(area,'a'); b, bm = new_image(area,'b')
        mount(a,am)
        source = am/'source'; command('btrfs','subvolume','create',source)
        positive = fixture(source,'positive'); legacy = fixture(source,'legacy')
        shutil.copyfile(seed,positive/builder.SEED_NAME); (positive/builder.SEED_NAME).chmod(0o400)
        original = (positive/'construction.json').read_bytes()
        require(builder.migrate_identity(positive)['migrated'], 'Migration did not occur')
        record = json.loads((positive/'construction.json').read_text())
        backup = positive/record['identity_migration']['backup_name']
        require(backup.read_bytes() == original and record['unrelated_field'] == 'preserve', 'Migration lost metadata')
        stable = (positive/'construction.json').read_bytes()
        require(not builder.migrate_identity(positive)['migrated'] and
                (positive/'construction.json').read_bytes() == stable and
                len(list(positive.glob('construction-v1-*'))) == 1, 'Migration was not idempotent')
        passed('authenticated-migration-and-idempotence',original_marker_byte_verified=True)
        before = (positive/'root.x86_64').stat().st_dev
        unmount(am); mount(b,bm)
        command('btrfs','subvolume','create',bm/'occupy-device')
        # Access it so the second anonymous device is actually instantiated.
        (bm/'occupy-device').stat()
        mount(a,am)
        after = (positive/'root.x86_64').stat().st_dev
        require(before != after, 'No actual device change; inconclusive')
        builder.check_workspace(positive)
        require((positive/'construction.json').read_bytes() == stable, 'Remount changed provenance')
        passed('persistent-identity-after-remount',device_number_changed=True,provenance_unchanged=True)
        refused(legacy,migrate=True)
        passed('legacy-mismatch-refuses-migration',marker_and_backups_unchanged=True)
        guest = positive/'root.x86_64'; guest.rename(positive/'original-guest'); guest.mkdir()
        shutil.copyfile(positive/'original-guest/payload',guest/'payload')
        refused(positive)
        require((guest/'payload').read_bytes() == (positive/'original-guest/payload').read_bytes(), 'Replacement fixture mismatch')
        guest.rename(positive/'replacement-guest'); (positive/'original-guest').rename(guest)
        builder.check_workspace(positive)
        passed('byte-identical-directory-replacement-refused',both_directories_preserved=True)
        snapshot = am/'snapshot'; command('btrfs','subvolume','snapshot',source,snapshot)
        require((snapshot/'positive/root.x86_64').stat().st_ino == guest.stat().st_ino,
                'Snapshot did not preserve the inode number')
        refused(snapshot/'positive'); builder.check_workspace(positive)
        passed('snapshot-directory-replacement-refused',same_inode_and_bytes=True,original_accepted=True)
        uid = guest.stat().st_uid
        os.chown(guest,1487011840,-1); builder.check_workspace(positive); os.chown(guest,uid,-1)
        require((guest/'payload').read_bytes() == b'unchanged disposable payload\n', 'Fixture payload changed')
        passed('legitimate-private-user-ownership-shift',persistent_identity_accepted=True,payload_unchanged=True)
        report.update(passed=True,case_count=len(report['cases']))
    finally:
        for where in reversed(mounts[:]): unmount(where)
        report.update(all_test_mounts_unmounted=not mounts,completed_unix=time.time())
        output = area/'result.json'; output.write_text(json.dumps(report,indent=2)+'\n'); output.chmod(0o600)
    print(json.dumps(dict(passed=report['passed'],report=str(output),case_count=len(report['cases']))))


if __name__ == '__main__':main()
