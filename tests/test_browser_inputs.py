"""A reused or altered browser seed must not count as fresh private state."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'bench'))
if sys.platform=='linux':
    import browser_inputs as audit
    import browser_endpoint as browser


@unittest.skipUnless(sys.platform=='linux','Linux desktop input audit')
class BrowserInputs(unittest.TestCase):
    def seed(self,root):
        for name in ('profile','config','data','cache'):(root/name).mkdir(mode=0o700)
        (root/'profile/user.js').write_text(''.join('user_pref('+json.dumps(k)+','+json.dumps(v)+');\n'
            for k,v in browser.PREFS.items()))

    def test_fresh_seed_equal_across_paths_and_generated_state_rejected(self):
        with tempfile.TemporaryDirectory() as a,tempfile.TemporaryDirectory() as b:
            left,right=Path(a),Path(b);self.seed(left);self.seed(right)
            self.assertEqual(audit.seed_manifest(left),audit.seed_manifest(right))
            (right/'profile/prefs.js').write_text('generated')
            with self.assertRaisesRegex(RuntimeError,'unexpected inputs'):audit.seed_manifest(right)

    def test_changed_preferences_symlinks_and_large_seed_refuse(self):
        with tempfile.TemporaryDirectory() as a:
            root=Path(a);self.seed(root);pref=root/'profile/user.js'
            pref.write_text('changed')
            with self.assertRaisesRegex(RuntimeError,'preference seed changed'):audit.seed_manifest(root)
            pref.unlink();pref.symlink_to('/etc/passwd')
            with self.assertRaisesRegex(RuntimeError,'Symlink'):audit.seed_manifest(root)
            pref.unlink();pref.write_bytes(b'x'*(2**20+1))
            with self.assertRaisesRegex(RuntimeError,'Unexpected initial profile node'):audit.seed_manifest(root)

    def test_trace_symlinks_and_aggregate_bounds_refuse(self):
        with tempfile.TemporaryDirectory() as a:
            root=Path(a);trace=root/'trace-00-private.123';trace.symlink_to('/etc/passwd')
            with self.assertRaisesRegex(RuntimeError,'Unowned trace'):audit.trace_inventory(root)
            trace.unlink();trace.write_bytes(b'xx')
            with mock.patch.object(audit,'TRACE_BYTES',1):
                with self.assertRaisesRegex(RuntimeError,'Aggregate trace size'):audit.trace_inventory(root)
            with mock.patch.object(audit,'TRACE_FILES',0):
                with self.assertRaisesRegex(RuntimeError,'Trace file count'):audit.trace_inventory(root)

    def test_capture_failure_still_cleans_up_and_does_not_replace_endpoint_error(self):
        with tempfile.TemporaryDirectory() as a,mock.patch.object(audit,'capture_owned',side_effect=RuntimeError('capture failed')):
            proc=mock.Mock();proc.poll.return_value=None;cleanup=mock.Mock(return_value={'cleaned':True});errors=[]
            result=audit.capture_then_cleanup(proc,'owned-group',True,[],errors,Path(a),cleanup)
            self.assertEqual(result,{'cleaned':True});self.assertEqual(errors,['capture failed'])
            cleanup.assert_called_once_with(proc,'owned-group')
            self.assertTrue((Path(a)/'capture-error-01-private.json').is_file())


if __name__=='__main__':unittest.main()
