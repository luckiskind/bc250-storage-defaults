"""Reject package inputs that could escape the disposable data-only fixture."""
import io
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'bench'))
import package_update as fixture


class PackageInputGuards(unittest.TestCase):
    def archive(self,folder,extra=(),metadata=''):
        path=Path(folder)/'package.tar'
        with tarfile.open(path,'w') as archive:
            data=('pkgname = tzdata\npkgver = 2026d-1.1\narch = x86_64_v3\n'+metadata).encode()
            row=tarfile.TarInfo('.PKGINFO');row.size=len(data);archive.addfile(row,io.BytesIO(data))
            row=tarfile.TarInfo('usr/share/zoneinfo/UTC');row.size=4;archive.addfile(row,io.BytesIO(b'TZif'))
            for row,data in extra:archive.addfile(row,io.BytesIO(data) if data is not None else None)
        return path

    def rejected(self,row,metadata='',message=None):
        with tempfile.TemporaryDirectory() as folder:
            path=self.archive(folder,() if row is None else [(row,None)],metadata)
            with self.assertRaisesRegex(RuntimeError,message or '.'):
                fixture.package(path)

    def test_data_manifest_excludes_archive_metadata(self):
        with tempfile.TemporaryDirectory() as folder:
            value=fixture.package(self.archive(folder))
            self.assertEqual(set(value['nodes']),{'usr/share/zoneinfo/UTC'})
            self.assertEqual(value['logical_bytes'],4)
            self.assertEqual(value['nodes']['usr/share/zoneinfo/UTC']['sha256'],fixture.hashlib.sha256(b'TZif').hexdigest())

    def test_absolute_and_parent_paths_refuse(self):
        for name in ('/usr/share/zoneinfo/x','../etc/passwd','usr/../etc/passwd','usr//bad'):
            with self.subTest(name=name):self.rejected(tarfile.TarInfo(name),message='Unsafe package path')

    def test_duplicates_refuse_before_payload_installation(self):
        self.rejected(tarfile.TarInfo('usr/share/zoneinfo/UTC'),message='Repeated')

    def test_scripts_hooks_dependencies_and_wrong_package_refuse(self):
        self.rejected(tarfile.TarInfo('.INSTALL'),message='install script')
        self.rejected(tarfile.TarInfo('usr/share/libalpm/hooks/test.hook'),message='transaction hooks')
        self.rejected(None,'depend = glibc\n',message='required dependencies')
        self.rejected(None,'pkgname = different\n',message='metadata')

    def test_special_nodes_and_outside_payload_refuse(self):
        row=tarfile.TarInfo('usr/share/zoneinfo/fifo');row.type=tarfile.FIFOTYPE
        self.rejected(row,message='Special package node')
        self.rejected(tarfile.TarInfo('etc/host-file'),message='payload root')

    def test_hardlinks_require_in_archive_regular_target(self):
        for target in ('../../etc/passwd','missing','/usr/share/zoneinfo/UTC'):
            row=tarfile.TarInfo('usr/share/zoneinfo/link');row.type=tarfile.LNKTYPE;row.linkname=target
            with self.subTest(target=target):self.rejected(row,message='hardlink')

    def test_symlink_ancestor_is_not_an_install_path(self):
        link=tarfile.TarInfo('usr/share/zoneinfo');link.type=tarfile.SYMTYPE;link.linkname='/etc'
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaisesRegex(RuntimeError,'Symlink package ancestor'):
                fixture.package(self.archive(folder,[(link,None)]))


if __name__=='__main__':unittest.main()
