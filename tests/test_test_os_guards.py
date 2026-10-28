"""Filesystem guards for a privileged disposable-OS builder, without containers."""
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

if sys.platform == 'linux':
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
    import prepare_test_os as builder


@unittest.skipUnless(sys.platform == 'linux', 'Linux qualification tool')
class TestOSGuards(unittest.TestCase):
    def workspace(self, directory):
        area = Path(directory)/'workspace'; area.mkdir(mode=0o700)
        guest = area/'root.x86_64'; guest.mkdir()
        s = guest.stat()
        marker = area/'construction.json'
        marker.write_text(json.dumps(dict(private_os_tree=True, seed_sha256=builder.SEED_SHA256,
            guest_identity=[s.st_dev,s.st_ino], original_field='preserve')))
        return area, guest, marker

    def fake_identity(self, path, expected=None):
        s = path.stat()
        if expected is not None:
            self.assertEqual([s.st_dev,s.st_ino],list(expected))
        return dict(kind='btrfs-fh-v1',fs_uuid='1'*32,handle_type=129,
                    handle=s.st_ino.to_bytes(16,'little').hex())

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

    def test_migration_backs_up_original_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as directory:
            area, guest, marker = self.workspace(directory)
            original = marker.read_bytes()
            with patch.object(builder,'directory_identity',side_effect=self.fake_identity), \
                    patch.object(builder,'verify_private_archive',return_value=builder.SEED_SHA256):
                self.assertTrue(builder.migrate_identity(area)['migrated'])
                first = marker.read_bytes()
                self.assertFalse(builder.migrate_identity(area)['migrated'])
            report = json.loads(first)
            self.assertEqual(report['original_field'],'preserve')
            self.assertEqual((area/report['identity_migration']['backup_name']).read_bytes(),original)
            self.assertEqual(marker.read_bytes(),first)
            self.assertEqual(len(list(area.glob('construction-v1-*.json'))),1)

    def test_mismatch_cannot_be_upgraded_from_archive_or_contents(self):
        with tempfile.TemporaryDirectory() as directory:
            area, guest, marker = self.workspace(directory)
            data = json.loads(marker.read_text()); data['guest_identity'][0] += 1
            marker.write_text(json.dumps(data)); before = marker.read_bytes()
            with patch.object(builder,'verify_private_archive') as archive, \
                    patch.object(builder,'directory_identity') as identity:
                with self.assertRaisesRegex(RuntimeError,'legacy device number changed'):
                    builder.migrate_identity(area)
            archive.assert_not_called(); identity.assert_not_called()
            self.assertEqual(marker.read_bytes(),before)
            self.assertEqual(list(area.glob('construction-v1-*')),[])

    def test_persistent_guard_ignores_the_obsolete_device_audit_pair(self):
        with tempfile.TemporaryDirectory() as directory:
            area, guest, marker = self.workspace(directory)
            with patch.object(builder,'directory_identity',side_effect=self.fake_identity), \
                    patch.object(builder,'verify_private_archive',return_value=builder.SEED_SHA256):
                builder.migrate_identity(area)
                data = json.loads(marker.read_text()); data['guest_identity'][0] += 1
                marker.write_text(json.dumps(data))
                builder.check_workspace(area)

    def test_persistent_guard_refuses_a_replaced_guest_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            area, guest, marker = self.workspace(directory)
            with patch.object(builder,'directory_identity',side_effect=self.fake_identity), \
                    patch.object(builder,'verify_private_archive',return_value=builder.SEED_SHA256):
                builder.migrate_identity(area)
                original = marker.read_bytes()
                guest.rename(area/'original-guest'); guest.mkdir()
                with self.assertRaisesRegex(RuntimeError,'Guest directory was replaced'):
                    builder.check_workspace(area)
            self.assertEqual(marker.read_bytes(),original)
            self.assertTrue((area/'original-guest').is_dir())

    def test_invalid_persistent_identity_is_rejected_before_lookup(self):
        with tempfile.TemporaryDirectory() as directory:
            area, guest, marker = self.workspace(directory)
            data = json.loads(marker.read_text()); data['provenance_format'] = 2
            marker.write_text(json.dumps(data))
            with patch.object(builder,'directory_identity') as lookup:
                with self.assertRaisesRegex(RuntimeError,'Invalid persistent workspace identity'):
                    builder.check_workspace(area)
            lookup.assert_not_called()

    def test_writable_construction_marker_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            area, guest, marker = self.workspace(directory)
            marker.chmod(0o666)
            with self.assertRaisesRegex(RuntimeError,'unsafe construction marker'):
                builder.check_workspace(area)

    def test_hardlinked_construction_marker_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            area, guest, marker = self.workspace(directory)
            os.link(marker,area/'alias')
            with self.assertRaisesRegex(RuntimeError,'unsafe construction marker'):
                builder.check_workspace(area)


if __name__ == '__main__':unittest.main()
