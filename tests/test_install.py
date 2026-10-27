"""Installer failure, idempotency and ownership tests: only temporary files/mock systemctl."""
import importlib.util
import json
from pathlib import Path
import tempfile
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('installer', ROOT / 'install.py')
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)


@unittest.skipUnless(sys.platform == 'linux', 'Linux file safety primitives required')
class Installation(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.state = root / 'state'
        self.state.mkdir(mode=0o700)
        source = root / 'payload'
        source.write_bytes(b'example payload\n')
        self.target = root / 'installed' / 'payload'
        self.manifest = self.state / 'installation.json'
        self.power = SimpleNamespace(TARGET='5000', info=lambda: {'latency_tolerance_us': '5000'})
        self.repack = SimpleNamespace(self_test=lambda _: {'status': 'repacked'})
        self.calls = []
        self.unit_directory = root / 'units'
        self.unit_directory.mkdir()
        fake_process = patch.object(app.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stdout='', stderr=''))
        fake_process.start()
        self.addCleanup(fake_process.stop)
        patches = {
            'BASE': root / 'helpers', 'STATE': self.state, 'MANIFEST': self.manifest,
            'UNIT_DIRECTORY': self.unit_directory,
            'payloads': lambda: {self.target: (source, 0o644)},
            'preflight': lambda: self.power, 'load_module': lambda _: self.repack,
            'prepare_directories': lambda: None, 'run': self.record,
        }
        for name, value in patches.items():
            change = patch.object(app, name, value)
            change.start()
            self.addCleanup(change.stop)

    def record(self, args):
        self.calls.append(list(map(str, args)))
        return ''

    def test_apply_twice_then_undo_twice(self):
        app.install()
        original = self.target.read_bytes()
        app.install()
        self.assertEqual(self.target.read_bytes(), original)
        self.assertEqual(len([x for x in self.calls if x[0] == 'systemd-analyze']), 1)
        app.uninstall()
        self.assertFalse(self.target.exists())
        self.assertFalse(json.loads(self.manifest.read_text())['active'])
        before = len(self.calls)
        app.uninstall()
        self.assertEqual(len(self.calls), before)

    def test_existing_file_is_preserved(self):
        self.target.parent.mkdir()
        self.target.write_bytes(b'belongs to someone else')
        with self.assertRaisesRegex(RuntimeError, 'overwrite'):
            app.install()
        self.assertEqual(self.target.read_bytes(), b'belongs to someone else')
        self.assertEqual(self.calls, [])

    def test_modified_file_blocks_undo_before_stopping_services(self):
        app.install()
        self.target.write_bytes(b'administrator edit')
        self.calls.clear()
        with self.assertRaisesRegex(RuntimeError, 'Administrator modified'):
            app.uninstall()
        self.assertEqual(self.calls, [])
        self.assertTrue(self.target.exists())

    def test_validation_failure_removes_staged_files(self):
        self.repack.self_test = lambda _: (_ for _ in ()).throw(RuntimeError('fixture failed'))
        with self.assertRaisesRegex(RuntimeError, 'fixture failed'):
            app.install()
        self.assertFalse(self.target.exists())
        self.assertFalse(self.manifest.exists())
        self.assertFalse(any('enable' in call for call in self.calls))

    def test_failed_enable_cleans_up_all_units_and_files(self):
        def fail(args):
            self.record(args)
            if args == ['systemctl', 'enable', '--now', app.TIMER]:
                raise RuntimeError('enable failed after writing a symlink')
            return ''
        with patch.object(app, 'run', fail):
            with self.assertRaisesRegex(RuntimeError, 'enable failed'):
                app.install()
        self.assertIn(['systemctl', 'disable', '--now', app.TIMER], self.calls)
        self.assertIn(['systemctl', 'disable', '--now', app.POWER], self.calls)
        self.assertFalse(self.target.exists())
        self.assertFalse(json.loads(self.manifest.read_text())['active'])

    def test_stop_failure_keeps_helpers_for_recovery(self):
        app.install()
        def fail(args):
            self.record(args)
            if args == ['systemctl', 'stop', app.WORKER]:
                raise RuntimeError('worker failed to stop')
            return ''
        with patch.object(app, 'run', fail):
            with self.assertRaisesRegex(RuntimeError, 'failed to stop'):
                app.uninstall()
        self.assertTrue(self.target.exists())
        self.assertTrue(json.loads(self.manifest.read_text())['active'])

    def test_unknown_manifest_path_is_never_deleted(self):
        app.install()
        data = json.loads(self.manifest.read_text())
        data['installed_files'].append('/unowned-path')
        self.manifest.write_text(json.dumps(data))
        self.calls.clear()
        with self.assertRaisesRegex(RuntimeError, 'Unexpected paths'):
            app.uninstall()
        self.assertEqual(self.calls, [])

    def test_partial_file_write_failure_does_not_leave_an_orphan(self):
        self.target.parent.mkdir()
        with patch.object(app.os, 'fsync', side_effect=OSError('injected storage failure')):
            with self.assertRaisesRegex(OSError, 'injected storage failure'):
                app.write_new(self.target, b'partially staged content', 0o644)
        self.assertFalse(self.target.exists())

    def test_exclusive_write_preserves_existing_destination(self):
        self.target.parent.mkdir()
        self.target.write_bytes(b'existing administrator file')
        with self.assertRaises(FileExistsError):
            app.write_new(self.target, b'candidate', 0o644)
        self.assertEqual(self.target.read_bytes(), b'existing administrator file')

    def test_pending_transaction_blocks_new_apply(self):
        app.transaction.Transaction.begin(self.state, app.payloads(), 'install')
        with self.assertRaisesRegex(RuntimeError, '--recover'):
            app.install()
        self.assertFalse(self.target.exists())

    def test_recover_uncommitted_published_file_and_activation(self):
        tx = app.transaction.Transaction.begin(self.state, app.payloads(), 'install')
        source, mode = app.payloads()[self.target]
        tx.publish(self.target, source.read_bytes(), app.write_new)
        tx.phase('activating', activation_started=True)
        app.recover()
        self.assertFalse(self.target.exists())
        self.assertFalse(app.transaction.pending_path(self.state).exists())
        self.assertIn(['systemctl', 'disable', '--now', app.POWER], self.calls)
        self.assertFalse(json.loads(self.manifest.read_text())['active'])

    def test_recovery_preserves_administrator_changes_before_any_service_action(self):
        tx = app.transaction.Transaction.begin(self.state, app.payloads(), 'install')
        source, mode = app.payloads()[self.target]
        tx.publish(self.target, source.read_bytes(), app.write_new)
        tx.phase('activating', activation_started=True)
        self.target.write_bytes(b'changed by an administrator')
        self.calls.clear()
        with self.assertRaisesRegex(RuntimeError, 'Administrator modified'):
            app.recover()
        self.assertEqual(self.calls, [])
        self.assertEqual(self.target.read_bytes(), b'changed by an administrator')
        self.assertTrue(app.transaction.pending_path(self.state).exists())

    def test_recovery_preserves_committed_install_after_cleanup_failure(self):
        with patch.object(app.transaction.Transaction, 'finish', side_effect=RuntimeError('cleanup interrupted')):
            with self.assertRaisesRegex(RuntimeError, 'cleanup interrupted'):
                app.install()
        self.assertTrue(json.loads(self.manifest.read_text())['active'])
        self.calls.clear()
        app.recover()
        self.assertIn(['systemctl', 'enable', '--now', app.POWER], self.calls)
        self.assertIn(['systemctl', 'enable', '--now', app.TIMER], self.calls)
        self.assertTrue(self.target.exists())
        self.assertFalse(app.transaction.pending_path(self.state).exists())

    def test_service_links_synced_children_before_parent(self):
        directories=[self.unit_directory / name for name in ('multi-user.target.wants','timers.target.wants')]
        for directory in directories:directory.mkdir()
        with patch.object(app.transaction,'sync_directory') as sync:
            app.sync_service_links()
        self.assertEqual([call.args[0] for call in sync.call_args_list],directories+[self.unit_directory])

    def test_committed_recovery_checks_staging_before_service_changes(self):
        with patch.object(app.transaction.Transaction,'finish',side_effect=RuntimeError('cleanup interrupted')):
            with self.assertRaisesRegex(RuntimeError,'cleanup interrupted'):app.install()
        tx=app.transaction.Transaction.load(self.state,app.payloads())
        stage=Path(tx.data['entries'][0]['staged'])
        stage.unlink();stage.write_bytes(b'administrator replacement')
        self.calls.clear()
        with self.assertRaises(RuntimeError):app.recover()
        self.assertEqual(self.calls,[])
        self.assertEqual(stage.read_bytes(),b'administrator replacement')
        self.assertTrue(app.transaction.pending_path(self.state).exists())

    def test_startup_link_sync_failure_prevents_active_commit(self):
        original=app.sync_service_links
        count=0
        def fail_once():
            nonlocal count
            count+=1
            if count==1:raise OSError('injected startup-link sync failure')
            original()
        with patch.object(app,'sync_service_links',fail_once):
            with self.assertRaisesRegex(OSError,'startup-link sync failure'):app.install()
        self.assertFalse(self.target.exists())
        self.assertFalse(json.loads(self.manifest.read_text())['active'])
        self.assertFalse(app.transaction.pending_path(self.state).exists())

    def test_recovery_completes_partial_removal_without_restarting_services(self):
        app.install()
        manifest = json.loads(self.manifest.read_text())
        tx = app.transaction.Transaction.begin(self.state, app.payloads(), 'remove', manifest)
        tx.phase('removing', services_stopped=True)
        tx.delete_target(tx.data['entries'][0])
        self.calls.clear()
        app.recover()
        self.assertFalse(self.target.exists())
        self.assertFalse(json.loads(self.manifest.read_text())['active'])
        self.assertFalse(any('enable' in call or 'disable' in call for call in self.calls))

    def test_invalid_journal_paths_are_rejected(self):
        app.transaction.Transaction.begin(self.state, app.payloads(), 'install')
        path = app.transaction.pending_path(self.state)
        data = json.loads(path.read_text())
        data['entries'][0]['target'] = '/unowned-file'
        path.write_text(json.dumps(data))
        with self.assertRaisesRegex(RuntimeError, 'Unexpected paths'):
            app.recover()
        self.assertEqual(self.calls, [])

    def test_installer_lock_rejects_a_second_writer(self):
        with app.transaction.installation_lock(self.state):
            with self.assertRaisesRegex(RuntimeError, 'Another installer'):
                with app.transaction.installation_lock(self.state):
                    self.fail('Second writer entered its critical section')

    def test_recovery_preserves_replaced_staging_file(self):
        tx = app.transaction.Transaction.begin(self.state, app.payloads(), 'install')
        source, mode = app.payloads()[self.target]
        tx.publish(self.target, source.read_bytes(), app.write_new)
        staged = Path(tx.data['entries'][0]['staged'])
        staged.unlink()
        staged.write_bytes(b'administrator staging replacement')
        self.calls.clear()
        with self.assertRaises(RuntimeError):
            app.recover()
        self.assertEqual(staged.read_bytes(), b'administrator staging replacement')
        self.assertTrue(self.target.exists())
        self.assertEqual(self.calls, [])

    def test_recovery_refuses_unknown_partial_staging_content(self):
        tx = app.transaction.Transaction.begin(self.state, app.payloads(), 'install')
        staged = Path(tx.data['entries'][0]['staged'])
        staged.parent.mkdir(parents=True, exist_ok=True)
        staged.write_bytes(b'X')
        staged.chmod(0o600)
        with self.assertRaisesRegex(RuntimeError, 'Unknown partial staging'):
            app.recover()
        self.assertEqual(staged.read_bytes(), b'X')
        self.assertFalse(self.target.exists())
        self.assertEqual(self.calls, [])

    def test_partial_staging_recovery_requires_matching_package(self):
        tx = app.transaction.Transaction.begin(self.state, app.payloads(), 'install')
        source, mode = app.payloads()[self.target]
        staged = Path(tx.data['entries'][0]['staged'])
        staged.parent.mkdir(parents=True, exist_ok=True)
        staged.write_bytes(source.read_bytes()[:3]);staged.chmod(0o600)
        source.write_bytes(b'a changed package version')
        with self.assertRaisesRegex(RuntimeError, 'matching package'):
            app.recover()
        self.assertTrue(staged.exists())
        self.assertEqual(self.calls, [])


if __name__ == '__main__':
    unittest.main()
