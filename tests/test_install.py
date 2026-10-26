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
        fake_process = patch.object(app.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stdout='', stderr=''))
        fake_process.start()
        self.addCleanup(fake_process.stop)
        patches = {
            'BASE': root / 'helpers', 'STATE': self.state, 'MANIFEST': self.manifest,
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


if __name__ == '__main__':
    unittest.main()
