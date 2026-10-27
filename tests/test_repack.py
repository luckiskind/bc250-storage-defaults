"""Repacker bounds and failure behavior using private files and mocked defrag ioctls."""
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
import sqlite3
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

    def fake_layout(self, final):
        return patch.object(repack, 'extents', side_effect=[[(0, 32768, 0)], [(0, 32768, 8)], final])

    def test_residual_large_extent_gets_one_bounded_retry(self):
        with self.fake_layout([(0, 16384, 8), (16384, 16384, 8)]), \
             patch.object(repack.fcntl, 'ioctl') as ioctl, \
             patch.object(repack.libc, 'sync_file_range', return_value=0), \
             patch.object(repack.os, 'fsync'):
            result = repack.repack(self.fd, {}, time.monotonic() + 30, self.state, byte_budget=65536)
        self.assertEqual(result['status'], 'repacked')
        self.assertEqual(result['processed_bytes'], 32768)
        self.assertEqual(result['charged_bytes'], 65536)
        self.assertEqual(result['retry_bytes'], 32768)
        self.assertEqual(ioctl.call_count, 4)

    def test_remaining_large_extent_is_reported_without_claiming_target(self):
        with self.fake_layout([(0, 32768, 8)]), patch.object(repack.fcntl, 'ioctl'), \
             patch.object(repack.libc, 'sync_file_range', return_value=0), patch.object(repack.os, 'fsync'):
            result = repack.repack(self.fd, {}, time.monotonic() + 30, self.state, byte_budget=65536)
        self.assertEqual(result['status'], 'layout-not-achieved-verified')
        self.assertFalse(result['layout_target_met'])
        self.assertEqual(result['encoded_extent_max'], 32768)
        self.assertEqual(result['charged_bytes'], 65536)
        self.assertFalse((self.state / 'STOP').exists())

    def test_retry_cannot_exceed_reservation(self):
        with self.fake_layout([(0, 32768, 8)]), patch.object(repack.fcntl, 'ioctl') as ioctl, \
             patch.object(repack.libc, 'sync_file_range', return_value=0), patch.object(repack.os, 'fsync'):
            result = repack.repack(self.fd, {}, time.monotonic() + 30, self.state, byte_budget=32768)
        self.assertEqual(result['charged_bytes'], 32768)
        self.assertEqual(result['retry_bytes'], 0)
        self.assertEqual(ioctl.call_count, 2)


class DurableBudget(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'ledger.sqlite3'
        self.db = sqlite3.connect(self.path)
        self.addCleanup(self.db.close)
        self.db.execute('CREATE TABLE budget(day TEXT PRIMARY KEY, bytes INTEGER)')
        self.db.execute('CREATE TABLE attempts(id INTEGER PRIMARY KEY, path TEXT, signature TEXT, day TEXT, reserved_bytes INTEGER, charged_bytes INTEGER, status TEXT)')
        self.db.commit()

    def test_reservation_survives_process_reopen_without_completion(self):
        repack.reserve_budget(self.db, 'day', '/fixture', 'signature', 65536)
        self.db.close()
        reopened = sqlite3.connect(self.path)
        self.addCleanup(reopened.close)
        self.assertEqual(reopened.execute('SELECT bytes FROM budget').fetchone()[0], 65536)
        self.assertEqual(reopened.execute('SELECT status FROM attempts').fetchone()[0], 'started')

    def test_completion_refunds_only_known_unused_work(self):
        attempt = repack.reserve_budget(self.db, 'day', '/fixture', 'signature', 65536)
        repack.finish_budget(self.db, attempt, 'day', 65536, dict(charged_bytes=49152, status='repacked'))
        self.assertEqual(self.db.execute('SELECT bytes FROM budget').fetchone()[0], 49152)
        self.assertEqual(self.db.execute('SELECT charged_bytes,status FROM attempts').fetchone(), (49152, 'repacked'))

    def test_overrun_refuses_refund_and_retains_conservative_reservation(self):
        attempt = repack.reserve_budget(self.db, 'day', '/fixture', 'signature', 65536)
        with self.assertRaisesRegex(RuntimeError, 'exceeded'):
            repack.finish_budget(self.db, attempt, 'day', 65536, dict(charged_bytes=65537, status='repacked'))
        self.assertEqual(self.db.execute('SELECT bytes FROM budget').fetchone()[0], 65536)


if __name__ == '__main__':
    unittest.main()
