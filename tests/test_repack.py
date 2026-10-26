"""Repacker bounds and failure behavior using private files and mocked defrag ioctls."""
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

if sys.platform != 'linux':
    raise unittest.SkipTest('Linux Btrfs interfaces required')

spec = importlib.util.spec_from_file_location('repacker', Path(__file__).resolve().parents[1] / 'storage_defaults_repack.py')
repack = importlib.util.module_from_spec(spec)
spec.loader.exec_module(repack)


class LayoutChecks(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state = Path(self.tmp.name)
        file = self.state / 'fixture'
        file.write_bytes(b'x' * 32768)
        self.fd = os.open(file, os.O_RDWR)
        self.addCleanup(os.close, self.fd)

    def test_hash_mismatch_writes_stop_marker(self):
        with patch.object(repack, 'digest', side_effect=['before', 'after']), \
             patch.object(repack, 'extents', return_value=[(0, 32768, 0)]):
            with self.assertRaisesRegex(RuntimeError, 'SHA-256 mismatch'):
                repack.repack(self.fd, {}, time.monotonic() - 1, self.state)
        self.assertTrue((self.state / 'STOP').exists())

    def test_expired_deadline_does_not_issue_defrag(self):
        with patch.object(repack, 'extents', return_value=[(0, 32768, 0)]), \
             patch.object(repack.fcntl, 'ioctl') as ioctl:
            result = repack.repack(self.fd, {}, time.monotonic() - 1, self.state)
        self.assertEqual(result['status'], 'partial-verified')
        self.assertEqual(result['processed_bytes'], 0)
        ioctl.assert_not_called()

    def test_recent_files_and_hardlinks_excluded(self):
        cfg = dict(min_file_bytes=1, max_file_bytes=2**20, quiet_seconds=3600)
        self.assertEqual(repack.eligible(self.fd, cfg, time.time()), 'recently-modified')
        os.link(self.state / 'fixture', self.state / 'alias')
        self.assertEqual(repack.eligible(self.fd, cfg, time.time()), 'not-single-regular')

    def test_sparse_file_not_accepted_as_test_fixture(self):
        with patch.object(repack, 'eligible', return_value='sparse'):
            with self.assertRaisesRegex(RuntimeError, 'sparse'):
                repack.self_test(self.state)
        self.assertEqual(sorted(p.name for p in self.state.iterdir()), ['fixture'])


if __name__ == '__main__':
    unittest.main()
