"""Check the actual C geometry against unbounded integer interval arithmetic."""
from pathlib import Path
import random
import shutil
import subprocess
import sys
import tempfile
import unittest

MAX=(1<<64)-1


def oracle(v):
    f,p,index,pages,offset,length,cursor,original,limit=v
    if not f or not p or f%64 or p%64 or not pages or pages>1<<20 or pages&(pages-1) or index>MAX//4096 or not 0<length<1<<32 or offset>2*((1<<32)-1) or not limit:
        return (-1,0,0,0,0)
    folio_start=f//64*4096;vector_start=p//64*4096+offset
    a=max(folio_start,vector_start);b=min(folio_start+pages*4096,vector_start+length)
    if b<=a:return (0,0,0,0,0)
    logical=cursor+a-vector_start;in_folio=a-folio_start
    if logical>MAX:return (-1,0,0,0,0)
    if logical>=limit:return (0,0,0,0,0)
    wanted=index*4096+in_folio;actual=original+logical
    if wanted>MAX or actual>MAX:return (-1,0,0,0,0)
    if wanted!=actual:return (0,0,0,0,0)
    size=min(b-a,limit-logical);flags=int((offset+length+4095)//4096>1)|2*int(pages>1)|4*int(in_folio>0 or size<pages*4096)
    return (1,logical,size,in_folio,flags)


@unittest.skipUnless(sys.platform=='linux' and shutil.which('cc'),'Native geometry compiler required')
class FolioVectorMath(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory(prefix='bc250-vector-math-');cls.binary=Path(cls.temp.name)/'probe'
        source=Path(__file__).resolve().parents[1]/'bench/folio_vector_math_probe.c'
        subprocess.run(['cc','-O2','-Wall','-Wextra','-Werror',str(source),'-o',str(cls.binary)],check=True,capture_output=True,timeout=30)

    @classmethod
    def tearDownClass(cls):cls.temp.cleanup()

    def check(self,cases):
        r=subprocess.run([str(self.binary)],input=''.join(' '.join(map(str,c))+'\n' for c in cases),capture_output=True,text=True,timeout=10)
        self.assertEqual(r.returncode,0,r.stderr);rows=[tuple(map(int,line.split())) for line in r.stdout.splitlines()]
        self.assertEqual(len(rows),len(cases))
        for v,got in zip(cases,rows):self.assertEqual(got,oracle(v),v)

    def test_large_multi_page_partial_and_trimmed_vectors(self):
        f=0xffffea0100000000
        self.check([(f,f,16,1,0,4096,0,65536,4096),
            (f,f-64,16,4,2048,32768,0,63488,32768),
            (f,f+64,16,4,1024,8192,0,70656,8192),
            (f,f-128,16,4,12288,4096,0,69632,4096),
            (f,f,16,4,0,65536,0,65536,8192),
            (f,f,16,4,0,65536,0,65537,8192)])

    def test_deterministic_independent_interval_matrix(self):
        rng=random.Random(256);f=0xffffea0100000000;cases=[]
        for _ in range(600):
            pages=rng.choice([1,2,4,16,64,1024]);p=f+rng.randint(-128,128)*64;offset=rng.randrange(0,65537);length=rng.randrange(1,1024*1024)
            index=5000;cursor=rng.randrange(0,256*1024);fs=f//64*4096;vs=p//64*4096+offset;a=max(fs,vs);b=min(fs+pages*4096,vs+length)
            original=0;limit=rng.randrange(1,1024*1024)
            if b>a:
                original=index*4096+(a-fs)-cursor-(a-vs);limit=cursor+(a-vs)+rng.randrange(1,1024*1024)
                if rng.randrange(3)==0:original+=1
            cases.append((f,p,index,pages,offset,length,cursor,original,limit))
        self.check(cases)

    def test_invalid_layout_sizes_and_overflows_refuse(self):
        f=0xffffea0100000000;valid=[f,f,16,1,0,4096,0,65536,4096];cases=[]
        for field,value in [(0,0),(1,f+1),(3,0),(3,3),(3,1<<21),(2,(MAX>>12)+1),(4,1<<33),(5,0),(5,1<<32),(8,0)]:
            v=valid.copy();v[field]=value;cases.append(v)
        cases += [(f,f-64,16,1,0,8192,MAX,0,MAX),(f,f,(MAX>>12),4,4096,4096,0,MAX,4096)]
        self.check(cases)

    def test_empty_probe_input_refuses(self):
        self.assertEqual(subprocess.run([str(self.binary)],input='',capture_output=True,text=True,timeout=5).returncode,2)


if __name__=='__main__':unittest.main()
