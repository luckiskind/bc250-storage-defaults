"""Owned boot-file restoration refuses foreign edits and foreign root context."""
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

if sys.platform=='linux':
    sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
    import physical_recovery_trial as trial


@unittest.skipUnless(sys.platform=='linux','Linux physical recovery tool')
class PhysicalRecoveryFiles(unittest.TestCase):
    def test_checked_replacement_and_restoration(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'limine.conf';path.write_bytes(b'original')
            trial.replace_owned(path,b'original',b'temporary','a'*32)
            self.assertEqual(path.read_bytes(),b'temporary')
            trial.replace_owned(path,b'temporary',b'original','a'*32)
            self.assertEqual(path.read_bytes(),b'original')

    def test_changed_config_is_preserved_without_pending_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'limine.conf';path.write_bytes(b'admin edit')
            with self.assertRaisesRegex(RuntimeError,'administrator edits'):
                trial.replace_owned(path,b'old',b'trial','b'*32)
            self.assertEqual(path.read_bytes(),b'admin edit')
            self.assertEqual(len(list(Path(directory).iterdir())),1)

    def test_existing_pending_file_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);path=root/'limine.conf';path.write_bytes(b'old')
            pending=root/('.bc250-recovery-'+'c'*32+'.pending');pending.write_bytes(b'unrecognized')
            with self.assertRaises(FileExistsError):trial.replace_owned(path,b'old',b'trial','c'*32)
            self.assertEqual(path.read_bytes(),b'old');self.assertEqual(pending.read_bytes(),b'unrecognized')

    def test_config_symlink_is_not_followed(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);real=root/'real';real.write_bytes(b'keep')
            path=root/'limine.conf';path.symlink_to(real)
            with self.assertRaises(OSError):trial.replace_owned(path,b'keep',b'trial','d'*32)
            self.assertEqual(real.read_bytes(),b'keep');self.assertTrue(path.is_symlink())

    def test_edit_between_checks_preserves_both_files(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'limine.conf';path.write_bytes(b'old');original_read=trial.read;calls=0
            def racing_read(value):
                nonlocal calls
                calls+=1
                if calls==2:path.write_bytes(b'concurrent edit')
                return original_read(value)
            with patch.object(trial,'read',side_effect=racing_read),self.assertRaisesRegex(RuntimeError,'preserve both'):
                trial.replace_owned(path,b'old',b'trial','e'*32)
            self.assertEqual(path.read_bytes(),b'concurrent edit')
            self.assertEqual((path.parent/('.bc250-recovery-'+'e'*32+'.pending')).read_bytes(),b'trial')

    def test_invalid_token_cannot_escape_private_temporary_name(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'limine.conf';path.write_bytes(b'keep')
            with self.assertRaisesRegex(RuntimeError,'Invalid replacement token'):
                trial.replace_owned(path,b'keep',b'trial','../../escape')
            self.assertEqual(list(Path(directory).iterdir()),[path])

    def test_restore_refuses_wrong_root_before_firmware_or_boot_writes(self):
        with patch.object(trial.prepare,'identity',return_value={'root':'foreign'}), \
             patch.object(trial,'read') as read,patch.object(trial.subprocess,'run') as run:
            with self.assertRaisesRegex(RuntimeError,'original working root'):
                trial.restore_owned({'working_identity':{'root':'expected'}},b'old',b'new')
            read.assert_not_called();run.assert_not_called()


if __name__=='__main__':unittest.main()
