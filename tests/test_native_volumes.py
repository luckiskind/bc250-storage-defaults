"""Native-volume guards and inventory semantics; no mounts or formatting in unit tests."""
import os
import socket
import tarfile
from pathlib import Path
import sys
import tempfile
import unittest

if sys.platform == 'linux':
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
    import native_volume_lab as native


@unittest.skipUnless(sys.platform == 'linux', 'Linux native-volume tool')
class NativeVolumeGuards(unittest.TestCase):
    def test_existing_output_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)/'output'; root.mkdir()
            keep = root/'keep'; keep.write_text('preserve')
            with self.assertRaisesRegex(RuntimeError, 'never overwritten'):
                native.private_area(root, creating=True)
            self.assertEqual(keep.read_text(), 'preserve')

    def test_symlink_component_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            real = root/'real'; real.mkdir()
            alias = root/'alias'; alias.symlink_to(real, target_is_directory=True)
            with self.assertRaisesRegex(RuntimeError, 'symlink components'):
                native.private_area(alias/'new', creating=True)
            self.assertFalse((real/'new').exists())

    def test_special_source_nodes_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            os.mkfifo(root/'fifo')
            with self.assertRaisesRegex(RuntimeError, 'special file'):
                native.tree_manifest(root, 0)

    def test_inventory_detects_broken_hardlink_topology(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            a = root/'a'; a.write_bytes(b'equal bytes')
            b = root/'b'; os.link(a, b)
            original = native.tree_manifest(root, 0)
            b.unlink(); b.write_bytes(a.read_bytes())
            os.utime(b, ns=(a.stat().st_atime_ns, a.stat().st_mtime_ns))
            changed = native.tree_manifest(root, 0)
            self.assertEqual(original['logical_bytes'], changed['logical_bytes'])
            self.assertNotEqual(original['sha256'], changed['sha256'])

    def test_inventory_excludes_volatile_files_but_detects_durable_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'usr').mkdir(); data = root/'usr/payload'; data.write_bytes(b'original')
            (root/'run').mkdir()
            original = native.tree_manifest(root, 0)
            (root/'run/transient').write_bytes(b'runtime')
            self.assertEqual(original, native.tree_manifest(root, 0))
            data.write_bytes(b'changed')
            self.assertNotEqual(original['sha256'], native.tree_manifest(root, 0)['sha256'])

    def test_only_known_keyring_socket_nodes_are_excluded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            node = root/'etc/pacman.d/gnupg/S.gpg-agent'
            node.parent.mkdir(parents=True)
            before = native.tree_manifest(root, 0)
            with socket.socket(socket.AF_UNIX) as endpoint:
                endpoint.bind(str(node))
                self.assertEqual(before, native.tree_manifest(root, 0))
            node.unlink(); node.write_bytes(b'durable regular file')
            self.assertNotEqual(before['sha256'], native.tree_manifest(root, 0)['sha256'])

    def test_archive_retains_same_named_regular_file_and_excludes_only_socket(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root/'source'; source.mkdir()
            output = root/'output'; output.mkdir()
            for name in native.SOURCE_DIRS:
                (source/name).mkdir(parents=True, exist_ok=True)
            keyring = source/'etc/pacman.d/gnupg'; keyring.mkdir(parents=True)
            (keyring/'S.gpg-agent').write_bytes(b'durable regular file')
            with socket.socket(socket.AF_UNIX) as endpoint:
                endpoint.bind(str(keyring/'S.keyboxd'))
                archive, excluded = native.seed_archive(source, output)
            self.assertEqual(excluded, ['etc/pacman.d/gnupg/S.keyboxd'])
            with tarfile.open(archive) as stream:
                self.assertNotIn('etc/pacman.d/gnupg/S.keyboxd', stream.getnames())
                self.assertEqual(stream.extractfile('etc/pacman.d/gnupg/S.gpg-agent').read(), b'durable regular file')


if __name__ == '__main__':
    unittest.main()
