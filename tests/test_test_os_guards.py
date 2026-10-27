"""Filesystem guards for a privileged disposable-OS builder, without containers."""
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest

if sys.platform == 'linux':
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
    import prepare_test_os as builder


@unittest.skipUnless(sys.platform == 'linux', 'Linux qualification tool')
class TestOSGuards(unittest.TestCase):
    def test_existing_workspace_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'workspace';path.mkdir()
            original = path / 'keep';original.write_text('preserve')
            with self.assertRaisesRegex(RuntimeError, 'never overwritten'):
                builder.check_workspace(path, creating=True)
            self.assertEqual(original.read_text(), 'preserve')

    def test_symlink_parent_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory);real = root / 'real';real.mkdir()
            alias = root / 'alias';alias.symlink_to(real, target_is_directory=True)
            with self.assertRaisesRegex(RuntimeError, 'parent contains a symlink'):
                builder.check_workspace(alias / 'new', creating=True)

    def test_replaced_guest_directory_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            area = Path(directory)/'workspace';area.mkdir(mode=0o700)
            guest = area / 'root.x86_64';guest.mkdir()
            identity = guest.stat()
            report = dict(private_os_tree=True, seed_sha256=builder.SEED_SHA256,
                          guest_identity=[identity.st_dev, identity.st_ino])
            (area/'construction.json').write_text(json.dumps(report))
            builder.check_workspace(area)
            guest.rename(area/'preserved-original');guest.mkdir()
            with self.assertRaisesRegex(RuntimeError, 'directory was replaced'):
                builder.check_workspace(area)
            self.assertTrue((area/'preserved-original').is_dir())

    def test_public_workspace_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            area = Path(directory)/'workspace';area.mkdir(mode=0o755)
            with self.assertRaisesRegex(RuntimeError, 'private directory'):
                builder.check_workspace(area)

    def test_archive_paths_and_special_files_are_rejected(self):
        for name in ('/etc/shadow','../escape','root.x86_64/../../escape','unrelated/file'):
            with self.subTest(name=name), self.assertRaises(RuntimeError):
                builder.validate_member(tarfile.TarInfo(name))
        device = tarfile.TarInfo('root.x86_64/dev/unexpected');device.type=tarfile.CHRTYPE
        with self.assertRaises(RuntimeError):builder.validate_member(device)
        for name in ('root.x86_64/usr/bin/example','version','pkglist.x86_64.txt'):
            builder.validate_member(tarfile.TarInfo(name))


if __name__ == '__main__':unittest.main()
