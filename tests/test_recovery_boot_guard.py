"""Refuse unsafe recovery selection before data writes or reboot requests."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

if sys.platform=='linux':
    sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
    import recovery_boot_guard as guard


@unittest.skipUnless(sys.platform=='linux','Linux recovery guard')
class RecoveryGuards(unittest.TestCase):
    def config(self):
        return dict(root_identity={'kind':'btrfs-fh-v1','fs_uuid':'1'*32,'handle_type':129,'handle':'01'},
            working_identity={'kind':'btrfs-fh-v1','fs_uuid':'2'*32,'handle_type':129,'handle':'02'},
            normal_menu_path='BC250-NORMAL',trial_entry='BC250-STORAGE-TRIAL',nonce='a'*32)

    def policy(self):
        return 'default_entry: BC250-NORMAL\nremember_last_entry: no\n/BC250-NORMAL\n protocol: linux\n/BC250-STORAGE-TRIAL\ncmdline: bc250.recovery='+'a'*32+'\n'

    def test_replaced_root_refused_before_mount_result_or_reboot(self):
        cfg=self.config()
        with patch.object(guard,'basic_context'),patch.object(guard,'root_identity',return_value=cfg['working_identity']), \
             patch.object(guard,'boot_context') as mount,patch.object(guard.ownership,'atomic_json') as save, \
             patch.object(guard,'request_reboot') as reboot:
            with self.assertRaisesRegex(RuntimeError,'root identity'):guard.trial(cfg)
            mount.assert_not_called();save.assert_not_called();reboot.assert_not_called()

    def test_failure_return_still_requires_independent_boot_verification(self):
        with patch.object(guard,'basic_context'), \
             patch.object(guard,'boot_context',side_effect=RuntimeError('Changed boot policy')), \
             patch.object(guard,'request_reboot') as reboot:
            with self.assertRaisesRegex(RuntimeError,'Changed boot policy'):guard.safe_return(self.config())
            reboot.assert_not_called()

    def test_policy_refuses_remembered_trial_duplicate_default_or_nonce(self):
        text=self.policy();guard.validate_policy(text,self.config())
        bad=[text.replace('remember_last_entry: no','remember_last_entry: yes'),
             text+'default_entry: BC250-STORAGE-TRIAL\n',text+'\n/BC250-STORAGE-TRIAL\n',
             text+'# bc250.recovery='+'a'*32+'\n',text.replace('default_entry: BC250-NORMAL','default_entry: Other'),
             text.replace('/BC250-NORMAL','/Other'),text.replace('protocol: linux','protocol: efi')]
        for value in bad:
            with self.subTest(value=value),self.assertRaises(RuntimeError):guard.validate_policy(value,self.config())

    def test_reads_boot_loader_interface_vendor_not_unrelated_variable(self):
        # Vendor GUID from systemd's public Boot Loader Interface specification.
        with tempfile.TemporaryDirectory() as directory,patch.object(guard,'EFI',Path(directory)):
            expected=Path(directory)/'LoaderEntrySelected-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f'
            expected.write_bytes(b'\x07\0\0\0'+('BC250-STORAGE-TRIAL\0').encode('utf-16-le'))
            self.assertEqual(guard.efi_text('LoaderEntrySelected'),'BC250-STORAGE-TRIAL')
            self.assertIsNone(guard.efi_text('LoaderEntryOneShot',missing=True))

    def test_indented_nested_normal_entry_resolves_uniquely(self):
        cfg=self.config();cfg['normal_menu_path']='CachyOS/linux-cachyos-bore-bc250'
        text=self.policy().replace('default_entry: BC250-NORMAL','default_entry: '+cfg['normal_menu_path'])
        text=text.replace('/BC250-NORMAL','/+CachyOS\n  //linux-cachyos-bore-bc250')
        guard.validate_policy(text,cfg)
        with self.assertRaises(RuntimeError):
            guard.validate_policy(text.replace('//linux-cachyos-bore-bc250','//Other'),cfg)


if __name__=='__main__':unittest.main()
