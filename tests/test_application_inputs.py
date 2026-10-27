"""Input selection cannot escape /usr or silently discard privileged context."""
import copy
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'bench'))
if sys.platform=='linux':
    from application_inputs import annotated_paths
    from copied_input_probe import select_records


@unittest.skipUnless(sys.platform=='linux','Application data probe requires Linux')
class ApplicationInputs(unittest.TestCase):
    def row(self,path='/usr/lib/example.so'):
        return dict(category='system_usr',regular_file=True,resolved_path=path,bytes=4096,mode=0o644,
            sha256='0'*64,device=1,inode=2,mtime_ns=3,ctime_ns=4)

    def test_escaped_paths_and_conflicting_aliases_refuse_selection(self):
        for path in ('/usr/../../home/other/file','/etc/passwd','usr/lib/file','/usr//lib/file'):
            with self.subTest(path=path):
                with self.assertRaises(RuntimeError):select_records(dict(records=[self.row(path)]))
        row=self.row();changed=copy.deepcopy(row);changed['sha256']='1'*64
        with self.assertRaisesRegex(RuntimeError,'Conflicting aliases'):select_records(dict(records=[row,changed]))

    def test_privileged_context_needs_explicit_exclusion_and_normal_files_cannot_use_exception(self):
        normal=self.row();priv=self.row('/usr/lib/example-helper');priv['mode']=0o2755
        manifest=dict(records=[normal,priv])
        with self.assertRaisesRegex(RuntimeError,'Privileged input'):select_records(manifest)
        self.assertEqual(select_records(manifest,[priv['resolved_path']]),[normal])
        with self.assertRaisesRegex(RuntimeError,'privileged inputs only'):select_records(manifest,[normal['resolved_path']])

    def test_failed_opens_and_exec_argv_do_not_invent_file_inputs(self):
        text='openat(3</usr/share>, "missing", O_RDONLY) = -1 ENOENT\n'
        text+='execve("/usr/bin/konsole", ["/not/an/input"], 0x0) = 0\n'
        text+='openat(AT_FDCWD, "lib", O_RDONLY) = 4</usr/lib/example.so>\n'
        paths,unresolved=annotated_paths(text)
        self.assertEqual(paths,{'/usr/bin/konsole','/usr/lib/example.so'})
        self.assertEqual(unresolved,0)


if __name__=='__main__':unittest.main()
