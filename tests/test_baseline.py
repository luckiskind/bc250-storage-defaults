"""Baseline captures must not expose unrelated paths or follow manifest file lists."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('baseline', Path(__file__).resolve().parents[1] / 'tools/capture_baseline.py')
baseline = importlib.util.module_from_spec(spec)
spec.loader.exec_module(baseline)


class BaselinePrivacy(unittest.TestCase):
    def test_mount_paths_and_unrecognized_options_are_removed(self):
        value = baseline.sanitize_mount(dict(filesystems=[dict(source='/dev/nvme0n1p2[/private/person]', fstype='btrfs',
                         options='rw,compress=zstd:1,subvol=/private/person,password=secret,discard=async')]))
        self.assertEqual(value, dict(source='/dev/nvme0n1p2', fstype='btrfs', options=['rw', 'compress=zstd:1', 'discard=async']))
        self.assertNotIn('secret', json.dumps(value))

    def test_manifest_cannot_add_arbitrary_files_to_audit(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = root / baseline.STATE.lstrip('/')
            state.mkdir(parents=True)
            (root / 'private').write_text('PRIVATE-CONTENT')
            (state / 'installation.json').write_text(json.dumps(dict(installed_files=['/private'], installed_sha256={'/private': 'anything'},
                                                                   config=dict(excluded_paths=['/private/person']))))
            result = baseline.audit_installation(baseline.Reader(root))
            self.assertEqual(set(result['installed_files']), set(baseline.INSTALLED))
            self.assertNotIn('PRIVATE-CONTENT', json.dumps(result))
            self.assertNotIn('/private', json.dumps(result))

    def test_unavailable_sources_are_explicit(self):
        with tempfile.TemporaryDirectory() as temporary:
            result = baseline.collect(baseline.Reader(Path(temporary)), runner=lambda _: None)
            self.assertFalse(result['installation']['manifest_readable'])
            self.assertEqual(result['nvme'], {})
            self.assertIsNone(result['mounts']['/'])


if __name__ == '__main__':
    unittest.main()
