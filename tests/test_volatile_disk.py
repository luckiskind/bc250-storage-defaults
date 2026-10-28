"""Fault-model correctness and guards; no host devices or QEMU required."""
import errno
import os
from pathlib import Path
import socket
import struct
import sys
import tempfile
import threading
import unittest
from unittest import mock

if sys.platform=='linux':
    sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
    import volatile_disk as model


@unittest.skipUnless(sys.platform=='linux','Linux file-backed fault model')
class VolatileDiskTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.path=self.root/'stable.raw'
        self.path.write_bytes(bytes(16384));self.path.chmod(0o600)
        self.disk=model.VolatileDisk(self.path,cache_bytes=4096)
        self.addCleanup(self.disk.close)

    def test_unflushed_write_is_readable_but_absent_from_stable_file(self):
        self.disk.write(0,b'A'*512)
        self.assertEqual(self.disk.read(0,512),b'A'*512)
        self.assertEqual(self.path.read_bytes()[:512],bytes(512))
        self.assertEqual(self.disk.power_cut()['dropped_bytes'],512)
        self.assertEqual(self.path.read_bytes()[:512],bytes(512))

    def test_flush_preserves_last_overlapping_write_and_later_data_can_be_lost(self):
        self.disk.write(0,b'A'*1024);self.disk.write(512,b'B'*512);self.disk.flush()
        self.disk.write(0,b'C'*512);self.disk.power_cut()
        self.assertEqual(self.path.read_bytes()[:1024],b'A'*512+b'B'*512)

    def test_fua_invalidates_old_overlap_without_flushing_other_sectors(self):
        self.disk.write(0,b'A'*1024);self.disk.write(0,b'B'*512,fua=True)
        self.assertEqual(self.disk.read(0,1024),b'B'*512+b'A'*512)
        self.assertEqual(self.disk.snapshot()['dirty_bytes'],512)
        self.disk.power_cut()
        self.assertEqual(self.path.read_bytes()[:1024],b'B'*512+bytes(512))

    def test_write_after_fua_does_not_destroy_durable_version_before_flush(self):
        self.disk.write(0,b'A'*512,fua=True);self.disk.write(0,b'B'*512)
        self.disk.power_cut();self.assertEqual(self.path.read_bytes()[:512],b'A'*512)

    def test_flush_after_fua_cannot_resurrect_older_cached_version(self):
        self.disk.write(0,b'A'*1024);self.disk.write(0,b'B'*512,fua=True);self.disk.flush()
        self.assertEqual(self.path.read_bytes()[:1024],b'B'*512+b'A'*512)

    def test_capacity_failure_does_not_partially_mutate_the_cache(self):
        self.disk.write(0,b'A'*4096)
        with self.assertRaises(model.RequestError) as error:self.disk.write(0,b'B'*4608)
        self.assertEqual(error.exception.errno,errno.ENOSPC)
        self.assertEqual(self.disk.read(0,4096),b'A'*4096)
        self.assertEqual(self.path.read_bytes(),bytes(16384))

    def test_invalid_range_never_changes_data(self):
        for offset,length in ((-512,512),(1,512),(0,1),(16384,512),(0,0)):
            with self.subTest(offset=offset,length=length),self.assertRaises(model.RequestError):
                self.disk.write(offset,bytes(length))
        self.assertEqual(self.disk.snapshot()['dirty_bytes'],0)

    def test_backing_enospc_is_fatal_not_a_modeled_cache_error(self):
        self.disk.write(0,b'A'*512)
        with mock.patch.object(model.os,'pwrite',side_effect=OSError(errno.ENOSPC,'real I/O failure')):
            with self.assertRaises(OSError) as error:self.disk.flush()
        self.assertNotIsInstance(error.exception,model.RequestError)
        self.assertEqual(self.disk.snapshot()['dirty_bytes'],512)
        self.assertEqual(self.disk.snapshot()['flush_completed'],0)

    def test_fsync_failure_does_not_claim_fua_completion(self):
        with mock.patch.object(model.os,'fsync',side_effect=OSError(errno.EIO,'I/O failure')):
            with self.assertRaises(OSError):self.disk.write(0,b'A'*512,fua=True)
        self.assertEqual(self.disk.snapshot()['fua_completed'],0)

    def test_symlink_hardlink_and_public_directory_are_refused(self):
        link=self.root/'link';link.symlink_to(self.path)
        with self.assertRaises(OSError):model.VolatileDisk(link)
        link.unlink();os.link(self.path,link)
        with self.assertRaisesRegex(RuntimeError,'regular test file'):model.VolatileDisk(link)
        link.unlink();self.root.chmod(0o755)
        with self.assertRaisesRegex(RuntimeError,'private directory'):model.VolatileDisk(self.path)
        self.root.chmod(0o700)

    def test_second_backend_cannot_lock_the_same_file(self):
        with self.assertRaises(BlockingIOError):model.VolatileDisk(self.path)

    def test_short_pwrite_is_completed_without_losing_bytes(self):
        real=os.pwrite
        with mock.patch.object(model.os,'pwrite',side_effect=lambda fd,data,offset:real(fd,data[:97],offset)):
            self.disk.write(0,b'A'*512,fua=True)
        self.assertEqual(self.path.read_bytes()[:512],b'A'*512)

    def test_wire_write_ack_does_not_imply_durability(self):
        server,client=socket.socketpair();client.settimeout(2);errors=[]
        def target():
            try:model.transmission(server,self.disk)
            except BaseException as e:errors.append(e)
            finally:server.close()
        thread=threading.Thread(target=target);thread.start()
        try:
            client.sendall(struct.pack('>IHHQQI',0x25609513,0,1,123,0,512)+b'W'*512)
            self.assertEqual(struct.unpack('>IIQ',model.receive(client,16)),(0x67446698,0,123))
            self.assertEqual(self.path.read_bytes()[:512],bytes(512))
            client.sendall(struct.pack('>IHHQQI',0x25609513,0,3,124,0,0))
            self.assertEqual(struct.unpack('>IIQ',model.receive(client,16)),(0x67446698,0,124))
            self.assertEqual(self.path.read_bytes()[:512],b'W'*512)
            client.sendall(struct.pack('>IHHQQI',0x25609513,0,2,125,0,0))
        finally:client.close();thread.join(3)
        self.assertFalse(thread.is_alive());self.assertEqual(errors,[])

    def test_armed_wire_cut_preserves_fua_and_drops_the_next_ordinary_write(self):
        server,client=socket.socketpair();client.settimeout(2);errors=[]
        self.disk.arm_write_cut()
        def target():
            try:self.assertTrue(model.transmission(server,self.disk))
            except BaseException as e:errors.append(e)
            finally:server.close()
        thread=threading.Thread(target=target);thread.start()
        try:
            client.sendall(struct.pack('>IHHQQI',0x25609513,1,1,301,0,512)+b'F'*512)
            self.assertEqual(struct.unpack('>IIQ',model.receive(client,16)),(0x67446698,0,301))
            self.assertFalse(self.disk.snapshot()['powered_off'])
            client.sendall(struct.pack('>IHHQQI',0x25609513,0,1,302,512,512)+b'V'*512)
            self.assertEqual(struct.unpack('>IIQ',model.receive(client,16)),(0x67446698,0,302))
        finally:client.close();thread.join(3)
        self.assertFalse(thread.is_alive());self.assertEqual(errors,[])
        stats=self.disk.snapshot()
        self.assertTrue(stats['powered_off']);self.assertEqual(stats['dropped_bytes'],512)
        self.assertEqual(stats['cut_trigger_offset'],512)
        self.assertEqual(self.path.read_bytes()[:1024],b'F'*512+bytes(512))


if __name__=='__main__':unittest.main()
