"""Repacker bounds and failure behavior using private files and mocked defrag ioctls."""
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
import sqlite3
from unittest.mock import patch, Mock

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
        self.db = repack.open_ledger(self.path)
        self.addCleanup(self.db.close)
        self.db.execute('CREATE TABLE budget(day TEXT PRIMARY KEY, bytes INTEGER)')
        self.db.execute('CREATE TABLE attempts(id INTEGER PRIMARY KEY, path TEXT, signature TEXT, day TEXT, reserved_bytes INTEGER, charged_bytes INTEGER, status TEXT)')
        self.db.commit()

    def test_reservation_survives_process_reopen_without_completion(self):
        repack.reserve_budget(self.db, 'day', '/fixture', 'signature', 65536)
        self.db.close()
        reopened = repack.open_ledger(self.path)
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

    def test_strong_policy_is_reestablished_without_erasing_existing_reservations(self):
        self.assertEqual(self.db.execute('PRAGMA synchronous').fetchone()[0],3)
        self.assertEqual(self.db.execute('PRAGMA journal_mode').fetchone()[0],'delete')
        repack.reserve_budget(self.db,'day','/fixture','signature',65536)
        self.db.close()
        reopened=repack.open_ledger(self.path)
        try:
            self.assertEqual(reopened.execute('PRAGMA synchronous').fetchone()[0],3)
            self.assertEqual(reopened.execute('SELECT bytes FROM budget').fetchone()[0],65536)
        finally:
            reopened.close()

    def test_unenforced_sync_policy_fails_closed(self):
        db=Mock();db.execute.return_value.fetchone.return_value=(2,)
        with patch.object(repack.sqlite3,'connect',return_value=db):
            with self.assertRaisesRegex(RuntimeError,'strong ledger synchronization'):repack.open_ledger(self.path)
        db.close.assert_called_once()

    def test_unsafe_journal_mode_fails_closed(self):
        db=Mock()
        db.execute.side_effect=lambda sql:Mock(fetchone=lambda: (3,) if sql=='PRAGMA synchronous' else ('off',))
        with patch.object(repack.sqlite3,'connect',return_value=db):
            with self.assertRaisesRegex(RuntimeError,'Unsupported ledger journal mode'):repack.open_ledger(self.path)
        db.close.assert_called_once()

    def test_state_directory_sync_failure_prevents_any_ledger_or_layout_mutation(self):
        config=Path(self.tmp.name)/'config.json';config.write_text('{}')
        state=Path(self.tmp.name)/'new-state'
        with patch.object(repack,'CONFIG',config),patch.object(repack,'STATE',state), \
             patch.object(repack.os,'geteuid',return_value=0),patch.object(sys,'argv',['worker']), \
             patch.object(repack.os,'fsync',side_effect=OSError('directory sync failed')), \
             patch.object(repack,'open_ledger') as ledger,patch.object(repack,'repack') as mutate:
            with self.assertRaisesRegex(OSError,'directory sync failed'):repack.main()
        ledger.assert_not_called();mutate.assert_not_called()


if __name__ == '__main__':
    unittest.main()
