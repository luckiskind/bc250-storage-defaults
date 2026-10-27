"""Trial-copy preservation and canonical-byte checks without mounts or containers."""
import os
from pathlib import Path
import sys
import tempfile
import unittest

if sys.platform == 'linux':
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
    import native_trial_lab as trial


@unittest.skipUnless(sys.platform == 'linux', 'Linux native trial tooling')
class NativeTrialGuards(unittest.TestCase):
    def test_embedded_guest_program_compiles(self):
        compile(trial.PROBE, '<native-trial-probe>', 'exec')

    def test_existing_trial_destination_is_preserved_before_any_copy(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); target = root/'trial.raw'; target.write_bytes(b'preserve')
            with self.assertRaises(FileExistsError):
                trial.new_copy(root/'missing-source', target, {})
            self.assertEqual(target.read_bytes(), b'preserve')

    def test_trial_destination_symlink_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); owned = root/'owned'; owned.write_bytes(b'preserve')
            link = root/'alias'; link.symlink_to(owned)
            with self.assertRaisesRegex(RuntimeError, 'Unsafe trial path'):
                trial.new_copy(root/'source', link, {})
            self.assertEqual(owned.read_bytes(), b'preserve')

    def test_metadata_symlink_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); metadata = root/'record'; metadata.write_text('{}')
            link = root/'alias'; link.symlink_to(metadata)
            with self.assertRaisesRegex(RuntimeError, 'Unsafe lab metadata'):
                trial.safe_json(link)

    def test_canonical_copy_digest_ignores_allocated_zero_runs_but_detects_changed_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); sparse = root/'sparse'; dense = root/'dense'
            with sparse.open('wb') as stream:
                stream.truncate(65536); stream.seek(8192); stream.write(b'x'*4096)
                stream.flush(); os.fsync(stream.fileno())
            dense.write_bytes(sparse.read_bytes())
            expected = trial.logical_sparse_digest(sparse)
            self.assertEqual(expected, trial.logical_sparse_digest(dense))
            with dense.open('r+b') as stream:
                stream.seek(65535); stream.write(b'z'); stream.flush(); os.fsync(stream.fileno())
            self.assertNotEqual(expected, trial.logical_sparse_digest(dense))


if __name__ == '__main__':
    unittest.main()
