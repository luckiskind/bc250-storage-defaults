"""Reject unsafe archive graphs and unauthorized cache-control requests."""
import json
from pathlib import Path
import socket
import sys
import tarfile
import tempfile
import threading
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'bench'))
if sys.platform=='linux':
    import os
    from native_application_inputs import validate_archive,serve_cache,inventory,namespace_processes


@unittest.skipUnless(sys.platform=='linux','Linux native input guards')
class NativeApplicationInputs(unittest.TestCase):
    def member(self,name,kind=tarfile.REGTYPE,target=''):
        row=tarfile.TarInfo(name);row.type=kind;row.linkname=target;return row

    def test_archive_escapes_duplicates_special_nodes_and_symlink_ancestors_refuse(self):
        cases=[[self.member('../escape')],[self.member('/absolute')],
            [self.member('a'),self.member('a')],[self.member('pipe',tarfile.FIFOTYPE)],
            [self.member('a',tarfile.SYMTYPE,'/tmp'),self.member('a/file')],
            [self.member('a',tarfile.LNKTYPE,'outside')]]
        for rows in cases:
            with self.subTest(names=[r.name for r in rows]):
                with self.assertRaises(RuntimeError):validate_archive(rows,{r.name for r in rows})
        good=[self.member('a'),self.member('b',tarfile.LNKTYPE,'a')]
        validate_archive(good,{'a','b'})

    def test_inventory_detects_broken_hardlink_relationship_and_mode(self):
        with tempfile.TemporaryDirectory() as name:
            root=Path(name);(root/'a').write_bytes(b'data');os.link(root/'a',root/'b')
            before=inventory(root,{'a','b'});(root/'b').unlink();(root/'b').write_bytes(b'data')
            self.assertNotEqual(inventory(root,{'a','b'}),before)
            before=inventory(root,{'a','b'});(root/'b').chmod(0o400)
            self.assertNotEqual(inventory(root,{'a','b'}),before)

    def test_cache_observer_rejects_wrong_identity_nonce_and_phase_without_file_access(self):
        for uid,nonce,phase in [(os.getuid()+1,'secret','cold-before'),
            (os.getuid(),'wrong','cold-before'),(os.getuid(),'secret','warm-before')]:
            with tempfile.TemporaryDirectory() as name,socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as server:
                path=str(Path(name)/'control');server.bind(path);server.listen(1);server.settimeout(2);errors=[]
                worker=threading.Thread(target=serve_cache,args=(server,Path('/nonexistent'),[],
                    dict(uid=uid,pid=os.getpid()),'secret',errors));worker.start()
                with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:
                    client.settimeout(2);client.connect(path)
                    client.sendall(json.dumps(dict(nonce=nonce,phase=phase)).encode()+b'\n')
                    try:self.assertEqual(client.recv(4096),b'')
                    except ConnectionResetError:pass
                worker.join(3);self.assertFalse(worker.is_alive());self.assertEqual(len(errors),1)

    def test_current_controller_namespace_is_never_a_cleanup_target(self):
        with self.assertRaisesRegex(RuntimeError,'controller namespace'):
            namespace_processes(os.readlink('/proc/self/ns/mnt'))


if __name__=='__main__':unittest.main()
