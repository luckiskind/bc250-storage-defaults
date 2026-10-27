"""Mapped objects need rooted identity proof; names alone cannot qualify them."""
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'bench'))
if sys.platform=='linux':
    import errno,mmap,os
    import mapped_identity as identity


@unittest.skipUnless(sys.platform=='linux','Linux mapping identity/openat2')
class MappedIdentity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scratch=tempfile.TemporaryDirectory();cls.lib=identity.compile_library(Path(cls.scratch.name)/'rooted.so')

    @classmethod
    def tearDownClass(cls):cls.scratch.cleanup()

    def test_deleted_escaped_zero_and_traversing_names_never_qualify(self):
        text='1000-2000 r--p 00000000 00:01 1 /a (deleted)\n'
        text+='2000-3000 r--p 00000000 00:01 2 /name\\012x\n'
        text+='3000-4000 r--p 00000000 00:01 0 /zero\n'
        text+='4000-5000 r--p 00000000 00:01 4 /a/../b\n'
        rows,skipped=identity.parse_maps(text)
        self.assertFalse(rows);self.assertEqual(sum(skipped.values()),4)
        with self.assertRaises(RuntimeError):identity.parse_maps('malformed')

    def test_absolute_symlink_stays_in_pinned_root_and_magiclink_refuses(self):
        with tempfile.TemporaryDirectory() as a:
            root=Path(a);target=root/'payload';target.write_bytes(b'private');(root/'alias').symlink_to('/payload')
            rootfd=os.open(root,os.O_PATH|os.O_DIRECTORY)
            try:
                fd=identity.open_rooted(self.lib,rootfd,'/alias')
                try:self.assertEqual(identity.identity(os.fstat(fd)),identity.identity(target.stat()))
                finally:os.close(fd)
            finally:os.close(rootfd)
            rootfd=os.open('/',os.O_PATH|os.O_DIRECTORY);datafd=os.open(target,os.O_RDONLY)
            try:
                with self.assertRaises(OSError) as failure:identity.open_rooted(self.lib,rootfd,f'/proc/self/fd/{datafd}')
                self.assertEqual(failure.exception.errno,errno.ELOOP)
            finally:os.close(datafd);os.close(rootfd)

    def test_real_self_mapping_matches_inode_and_unowned_target_refuses(self):
        with tempfile.TemporaryDirectory() as a:
            path=Path(a)/'file with space';path.write_bytes(b'x'*4096)
            with path.open('rb') as stream,mmap.mmap(stream.fileno(),0,access=mmap.ACCESS_READ):
                sample=identity.inspect(os.getpid(),lambda pid:pid==os.getpid(),self.lib)
                selected=[row for row in sample['records'] if row['path']==str(path)]
                self.assertEqual(len(selected),1)
                if selected[0]['status']=='mapping_reference_unavailable':
                    self.assertIn(selected[0]['errno'],(errno.EPERM,errno.EACCES))
                else:self.assertEqual(selected[0]['status'],'same_host_object')
            with self.assertRaisesRegex(RuntimeError,'Unowned'):
                identity.inspect(os.getpid(),lambda pid:False,self.lib)

    def test_reference_denial_never_falls_back_to_maps_device_and_inode(self):
        with tempfile.TemporaryDirectory() as a:
            path=Path(a)/'mapped';path.write_bytes(b'x'*4096);real_open=os.open
            def guarded_open(name,*args,**kwargs):
                if str(name).startswith('map_files/'):raise PermissionError(errno.EPERM,'reference denied')
                return real_open(name,*args,**kwargs)
            with path.open('rb') as stream,mmap.mmap(stream.fileno(),0,access=mmap.ACCESS_READ),\
                    mock.patch.object(os,'open',side_effect=guarded_open):
                sample=identity.inspect(os.getpid(),lambda pid:pid==os.getpid(),self.lib)
            selected=[row for row in sample['records'] if row['path']==str(path)]
            self.assertEqual(len(selected),1);self.assertEqual(selected[0]['status'],'mapping_reference_unavailable')

    def test_host_reference_identity_is_independent_of_any_process_root_path(self):
        with tempfile.TemporaryDirectory() as a:
            left,right=Path(a)/'left',Path(a)/'right';left.write_bytes(b'a');right.write_bytes(b'b')
            with left.open('rb') as source:
                actual=os.fstat(source.fileno())
                self.assertTrue(identity.compare_host_reference(str(left),actual)['host_identity_matches_mapping'])
                self.assertFalse(identity.compare_host_reference(str(right),actual)['host_identity_matches_mapping'])


if __name__=='__main__':unittest.main()
