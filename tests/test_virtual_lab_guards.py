"""Check file/label invariants without launching or formatting anything."""
import os
import json
import hashlib
import socket
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

if sys.platform=='linux':
    sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
    import vm_boot_probe as probe
    import virtual_test_lab as wrapper
    import vm_profile_faults as faults
    import vm_profile_guest as guest
    import vm_cache_faults as cache_profile


@unittest.skipUnless(sys.platform=='linux','Linux virtual qualification')
class VirtualLabGuards(unittest.TestCase):
    def test_readonly_regular_base_is_accepted(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'base.raw';path.write_bytes(b'known');path.chmod(0o400)
            probe.check_base(path)

    def test_writable_base_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'base.raw';path.write_bytes(b'preserve');path.chmod(0o600)
            with self.assertRaisesRegex(RuntimeError,'read-only regular'):
                probe.check_base(path)
            self.assertEqual(path.read_bytes(),b'preserve')

    def test_symlink_base_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            target=Path(directory)/'target';target.write_bytes(b'preserve');target.chmod(0o400)
            path=Path(directory)/'base.raw';path.symlink_to(target)
            with self.assertRaisesRegex(RuntimeError,'read-only regular'):
                probe.check_base(path)

    def test_existing_overlay_is_preserved_without_external_calls(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'overlay.qcow2';path.write_bytes(b'preserve')
            with mock.patch.object(probe.subprocess,'run') as run:
                with self.assertRaisesRegex(RuntimeError,'preserved'):probe.new_overlay(path)
                run.assert_not_called()
            self.assertEqual(path.read_bytes(),b'preserve')

    def test_sparse_fingerprint_detects_changed_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'base.raw'
            with path.open('xb') as stream:
                stream.truncate(8*2**20);stream.seek(2**20);stream.write(b'first');stream.flush();os.fsync(stream.fileno())
            first=probe.sparse_fingerprint(path)
            self.assertEqual(first,probe.sparse_fingerprint(path))
            with path.open('r+b') as stream:
                stream.seek(2**20);stream.write(b'other');stream.flush();os.fsync(stream.fileno())
            self.assertNotEqual(first['sha256'],probe.sparse_fingerprint(path)['sha256'])

    def test_run_labels_cannot_escape_the_private_directory(self):
        for label in ('../outside','/absolute','a/b','a b','UPPER','', 'x'*65):
            with self.subTest(label=label),self.assertRaises(RuntimeError):probe.validate_label(label)
        self.assertEqual(probe.validate_label('run-123_test'),'run-123_test')

    def test_helper_hardlink_cannot_overwrite_another_file(self):
        with tempfile.TemporaryDirectory() as directory:
            target=Path(directory)/'keep';target.write_bytes(b'preserve')
            path=Path(directory)/'helper.py';os.link(target,path)
            with self.assertRaisesRegex(RuntimeError,'Unsafe helper'):
                wrapper.write_helper(path,b'replacement',os.geteuid(),os.getegid())
            self.assertEqual(target.read_bytes(),b'preserve')

    def test_virtual_acknowledgement_rejects_another_run_token(self):
        with self.assertRaisesRegex(RuntimeError,'token'):
            faults.acknowledged('BC250_VM_CUT={"token":"other"}','BC250_VM_CUT=','expected')
        self.assertIsNone(faults.acknowledged('console text BC250_VM_CUT={}','BC250_VM_CUT=','expected'))
        self.assertEqual(faults.acknowledged('BC250_VM_CUT={"token":"expected"}\r',
                                            'BC250_VM_CUT=','expected')['token'],'expected')
        self.assertEqual(faults.acknowledged('\x1bP+q6E616D65\x1b\\BC250_VM_RESULT={"token":"expected"}',
                                            'BC250_VM_RESULT=','expected')['token'],'expected')

    def test_embedded_guest_programs_compile_before_image_construction(self):
        compile(guest.RESET,'guest reset','exec')
        compile(guest.INSIDE,'guest recovery','exec')

    def profile_sources(self,root):
        source=root/'tools';source.mkdir()
        manifest=dict(storage_profile_fixture=True,package_sha256={})
        for name,key in (('vm_image_builder.py','builder_source_sha256'),
                         ('vm_profile_guest.py','profile_guest_source_sha256')):
            path=source/name;path.write_bytes(b'fixture builder')
            manifest[key]=hashlib.sha256(path.read_bytes()).hexdigest()
        for name in wrapper.PACKAGE_FILES:
            path=root/name;path.parent.mkdir(exist_ok=True);path.write_bytes(b'package fixture')
            manifest['package_sha256'][name]=hashlib.sha256(path.read_bytes()).hexdigest()
        artifact=root/'artifact';artifact.mkdir()
        (artifact/'image-build.json').write_text(json.dumps(manifest))
        return source,artifact

    def test_profile_requires_matching_package_before_launch(self):
        with tempfile.TemporaryDirectory() as directory:
            source,artifact=self.profile_sources(Path(directory))
            with mock.patch.object(wrapper,'SOURCE',source):
                wrapper.verify_profile_sources(artifact)
                (source.parent/'install.py').write_bytes(b'changed package')
                with self.assertRaisesRegex(RuntimeError,'Package source changed'):
                    wrapper.verify_profile_sources(artifact)

    def test_profile_requires_matching_embedded_guest_program(self):
        with tempfile.TemporaryDirectory() as directory:
            source,artifact=self.profile_sources(Path(directory))
            with mock.patch.object(wrapper,'SOURCE',source):
                (source/'vm_profile_guest.py').write_bytes(b'changed guest')
                with self.assertRaisesRegex(RuntimeError,'Embedded guest source changed'):
                    wrapper.verify_profile_sources(artifact)

    def test_cache_disk_requires_a_private_run_socket(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);run=root/'runs/run-1';run.mkdir(parents=True,mode=0o700)
            path=run/'disk.nbd'
            with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as sock:
                sock.bind(str(path));path.chmod(0o600)
                with mock.patch.object(faults,'LAB',root):
                    self.assertIn('format=raw',faults.nbd_drive(path))
                    path.chmod(0o666)
                    with self.assertRaisesRegex(RuntimeError,'private NBD socket'):faults.nbd_drive(path)

    def test_cache_disk_rejects_paths_outside_the_lab_before_launch(self):
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(faults,'LAB',Path(directory)/'lab'):
                with self.assertRaisesRegex(RuntimeError,'private lab runs'):
                    faults.nbd_drive(Path(directory)/'outside.nbd')

    def test_logical_digest_ignores_allocated_zero_runs_but_detects_changed_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);sparse=root/'sparse';dense=root/'dense'
            with sparse.open('wb') as stream:stream.truncate(2**20);stream.seek(32768);stream.write(b'A'*4096)
            dense.write_bytes(sparse.read_bytes())
            self.assertEqual(cache_profile.logical_sparse_digest(sparse),cache_profile.logical_sparse_digest(dense))
            with dense.open('r+b') as stream:stream.seek(65536);stream.write(b'changed')
            self.assertNotEqual(cache_profile.logical_sparse_digest(sparse),cache_profile.logical_sparse_digest(dense))

    def test_calibration_report_accepts_private_workspace_metadata_but_rejects_other_writers(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);tools=root/'tools';tools.mkdir()
            names=('volatile_disk.py','calibrate_volatile_disk.py')
            for name in names:(tools/name).write_bytes(b'known source')
            report=dict(passed=True,case_count=4,actual_backend_sigkill_tested=True,armed_cache_cut_tested=True,
                cases=[dict(case=c,passed=True) for c in ('unflushed-loss','flush-survival','fua-isolation','backend-sigkill')],
                source_sha256={n:hashlib.sha256((tools/n).read_bytes()).hexdigest() for n in names})
            path=root/'report.json';path.write_text(json.dumps(report));path.chmod(0o644)
            with mock.patch.object(wrapper,'SOURCE',tools):
                self.assertTrue(wrapper.load_calibration(path,root)['passed'])
                path.chmod(0o666)
                with self.assertRaisesRegex(RuntimeError,'Unsafe calibration report'):wrapper.load_calibration(path,root)
                path.chmod(0o644);(tools/names[0]).write_bytes(b'changed source')
                with self.assertRaisesRegex(RuntimeError,'changed since calibration'):wrapper.load_calibration(path,root)


if __name__=='__main__':unittest.main()
