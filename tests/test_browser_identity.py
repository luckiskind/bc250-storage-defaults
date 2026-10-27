"""The privileged observer accepts only ordered requests from its own trial."""
from pathlib import Path
import sys
import unittest
from unittest import mock
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'bench'))
if sys.platform=='linux':from browser_identity import authorize,Rejected,translated_root_uid


@unittest.skipUnless(sys.platform=='linux','Linux desktop observer protocol')
class BrowserIdentity(unittest.TestCase):
    def cfg(self):return dict(uid=1000,nonce='secret')

    def test_schema_nonce_phase_and_uid_fail_before_scope_lookup(self):
        cases=[(dict(nonce='secret',phase='capture-0',pid=1),1000,'schema'),
            (dict(nonce='wrong',phase='capture-0'),1000,'nonce'),
            (dict(nonce=42,phase='capture-0'),1000,'nonce'),
            (dict(nonce='secret',phase='capture-1'),1000,'phase'),
            (dict(nonce='secret',phase='capture-0'),0,'uid')]
        for message,uid,reason in cases:
            with self.subTest(reason=reason):
                scoped=mock.Mock(return_value=True)
                with self.assertRaisesRegex(Rejected,'^'+reason+'$'):
                    authorize(message,uid,123,'capture-0',self.cfg(),scoped)
                scoped.assert_not_called()

    def test_outside_scope_and_different_controller_refuse(self):
        message=dict(nonce='secret',phase='capture-0')
        with self.assertRaisesRegex(Rejected,'scope'):authorize(message,1000,123,'capture-0',self.cfg(),lambda pid:False)
        scoped=mock.Mock(return_value=True)
        with self.assertRaisesRegex(Rejected,'controller'):
            authorize(message,1000,123,'capture-0',self.cfg(),scoped,controller=456)
        scoped.assert_not_called()

    def test_owned_current_controller_with_exact_phase_is_accepted(self):
        scoped=mock.Mock(return_value=True)
        authorize(dict(nonce='secret',phase='capture-1'),1000,123,'capture-1',self.cfg(),scoped,controller=123)
        scoped.assert_called_once_with(123)

    def test_root_uid_translation_requires_overflow_for_unmapped_root(self):
        with mock.patch.object(Path,'read_text',return_value='0 0 4294967295\n'):
            self.assertEqual(translated_root_uid(),0)
        with mock.patch.object(Path,'read_text',side_effect=['1000 1000 1\n','65534\n']):
            self.assertEqual(translated_root_uid(),65534)


if __name__=='__main__':unittest.main()
