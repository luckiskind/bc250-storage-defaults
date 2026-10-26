"""Power policy tests on a fake sysfs tree. Never writes real sysfs."""
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

if sys.platform != 'linux':
    raise unittest.SkipTest('Linux sysfs helper')

spec = importlib.util.spec_from_file_location('power', Path(__file__).resolve().parents[1] / 'storage_defaults_power.py')
power = importlib.util.module_from_spec(spec)
spec.loader.exec_module(power)


class PowerPolicy(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.ctrl = root / 'nvme0'
        (self.ctrl / 'device').mkdir(parents=True)
        (self.ctrl / 'power').mkdir()
        (self.ctrl / 'model').write_text(power.MODEL)
        (self.ctrl / 'device/current_link_width').write_text('2')
        (self.ctrl / 'device/current_link_speed').write_text('5.0 GT/s PCIe')
        self.qos = self.ctrl / 'power/pm_qos_latency_tolerance_us'
        self.qos.write_text('100000')
        self.state = root / 'state.json'
        for name, value in {'CTRL': self.ctrl, 'QOS': self.qos, 'STATE': self.state}.items():
            change = patch.object(power, name, value)
            change.start()
            self.addCleanup(change.stop)
        change = patch.object(power.os, 'geteuid', return_value=0)
        change.start()
        self.addCleanup(change.stop)

    def action(self, name):
        # Root-only production state is represented explicitly; all files remain private fixtures.
        real_lstat = Path.lstat
        def fixture_stat(path, *args, **kwargs):
            value = real_lstat(path, *args, **kwargs)
            if path == self.state:
                return SimpleNamespace(st_uid=0, st_mode=value.st_mode)
            return value
        with patch.object(sys, 'argv', ['power.py', name]), patch.object(Path, 'lstat', fixture_stat):
            power.main()

    def test_apply_resume_and_restore(self):
        self.action('apply')
        self.assertEqual(self.qos.read_text(), '5000')
        self.assertEqual(json.loads(self.state.read_text())['original'], '100000')
        self.qos.write_text('100000')  # Simulated controller reset on resume.
        self.action('apply')
        self.assertEqual(self.qos.read_text(), '5000')
        self.action('restore')
        self.assertEqual(self.qos.read_text(), '100000')
        self.assertFalse(self.state.exists())

    def test_external_policy_is_preserved(self):
        self.action('apply')
        self.qos.write_text('3000')
        with self.assertRaisesRegex(RuntimeError, 'Another policy'):
            self.action('restore')
        self.assertEqual(self.qos.read_text(), '3000')
        self.assertTrue(self.state.exists())

    def test_unowned_existing_cap_is_not_adopted(self):
        self.qos.write_text('5000')
        with self.assertRaisesRegex(RuntimeError, 'another policy'):
            self.action('apply')
        self.assertFalse(self.state.exists())

    def test_other_model_refused_without_write(self):
        (self.ctrl / 'model').write_text('different drive')
        with self.assertRaises(RuntimeError):
            self.action('apply')
        self.assertEqual(self.qos.read_text(), '100000')


if __name__ == '__main__':
    unittest.main()
