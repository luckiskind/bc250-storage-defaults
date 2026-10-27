"""A private browser fixture must not silently map its original selected files."""
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'bench'))
if sys.platform=='linux':from native_browser_inputs import source_path,copied_mappings,sandbox_log_accepted


@unittest.skipUnless(sys.platform=='linux','Linux native browser fixture')
class NativeBrowserInputs(unittest.TestCase):
    def rows(self):return [dict(target='/usr/lib/example',device=1,inode=20,original_device=1,original_inode=10)]

    def test_original_reference_rejected_even_under_another_displayed_path(self):
        with self.assertRaisesRegex(RuntimeError,'original source'):
            copied_mappings(self.rows(),[dict(path='/different/name',reference_device=1,reference_inode=10)])

    def test_selected_path_with_wrong_reference_refuses_and_unavailable_never_counts(self):
        with self.assertRaisesRegex(RuntimeError,'does not reference copied'):
            copied_mappings(self.rows(),[dict(path='/usr/lib/example',reference_device=2,reference_inode=30)])
        self.assertFalse(copied_mappings(self.rows(),[dict(path='/usr/lib/example',status='mapping_reference_unavailable')]))

    def test_copied_identity_qualifies_without_blind_path_prefix_stripping(self):
        self.assertEqual(copied_mappings(self.rows(),[dict(path='/private/view/usr/lib/example',reference_device=1,reference_inode=20)]),
            {'/usr/lib/example'})

    def test_input_root_escape_and_symlink_refuse(self):
        with tempfile.TemporaryDirectory() as a:
            root=Path(a);target=root/'file';target.write_bytes(b'x');link=root/'link';link.symlink_to(target)
            self.assertEqual(source_path(str(target),(str(root),)),target)
            for path in (str(link),str(root/'..'/'outside'),str(target).lstrip('/')):
                with self.subTest(path=path):
                    with self.assertRaises(RuntimeError):source_path(path,(str(root),))

    def test_browser_or_decoder_sandbox_fallback_never_qualifies(self):
        for text in ('WARNING: Glycin running without sandbox.', 'Sandbox: CanCreateUserNamespace() clone() failure: EPERM'):
            with self.assertRaisesRegex(RuntimeError,'sandbox fallback'):sandbox_log_accepted(text)
        sandbox_log_accepted('')


if __name__=='__main__':unittest.main()
