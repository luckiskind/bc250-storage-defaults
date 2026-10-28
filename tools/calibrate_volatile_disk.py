"""Calibrate the RAM-cache disk with QEMU's independent block client, not a mock."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import pty
import re
import select
import signal
import socket
import subprocess
import sys
import time
import vm_boot_probe as guards

LAB=Path('/vmlab')


def require(condition,message):
    if not condition:raise RuntimeError(message)


def control(path,command):
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as peer:
        peer.settimeout(5);peer.connect(str(path));peer.sendall(command.encode()+b'\n')
        data=bytearray()
        while b'\n' not in data:
            chunk=peer.recv(8192)
            require(chunk,'Control peer closed before its response');data.extend(chunk)
            require(len(data)<=8192,'Oversized control response')
    result=json.loads(data)
    require('error' not in result,'Control command failed')
    return result


class Backend:
    def __init__(self,run,stable,label,cache_mib=4):
        self.socket=run/(label+'.nbd');self.control=run/(label+'.ctl')
        self.report=run/(label+'.server.json')
        self.log=(run/(label+'.server.log')).open('xb')
        self.proc=subprocess.Popen([sys.executable,str(LAB/'volatile_disk.py'),'--stable',str(stable),
            '--socket',str(self.socket),'--control',str(self.control),'--report',str(self.report),
            '--cache-mib',str(cache_mib)],stdin=subprocess.DEVNULL,stdout=self.log,stderr=subprocess.STDOUT)
        try:
            start=time.monotonic()
            while True:
                require(self.proc.poll() is None,'Backend exited during startup; inspect its private log')
                try:self.initial=control(self.control,'stats');break
                except (ConnectionError,FileNotFoundError):
                    require(time.monotonic()-start<10,'Backend startup deadline');time.sleep(.02)
        except BaseException:self.close();raise

    def stats(self):return control(self.control,'stats')

    def arm(self):
        answer=control(self.control,'arm-write-cut')
        require(answer['armed_for_volatile_write'],'Disk did not arm its cut')
        return answer

    def wait_armed_cut(self,timeout=60):
        deadline=time.monotonic()+timeout
        while self.proc.poll() is None:
            require(time.monotonic()<deadline,'No volatile write arrived before the armed-cut deadline')
            time.sleep(.02)
        require(self.proc.returncode==0,'Armed cache cut failed; inspect private report/log')
        record=json.loads(self.report.read_text());stats=record['stats']
        require(record['reason']=='armed-volatile-write-cut' and not record['errors'] and
                stats['power_cuts']==1 and stats['cut_trigger_bytes']>0 and stats['dropped_bytes']>0,
                'No verified volatile write loss at the armed boundary')
        self.log.close();return stats

    def cut(self):
        answer=control(self.control,'power-cut');code=self.proc.wait(timeout=10)
        require(code==0,'Modeled power cut failed')
        record=json.loads(self.report.read_text())
        require(not record['errors'] and record['stats']==answer,'Cut report disagrees with its acknowledgement')
        self.log.close();return answer

    def kill(self):
        before=self.stats();self.proc.kill();code=self.proc.wait(timeout=10)
        require(code==-signal.SIGKILL,'Backend was not killed')
        require(not self.report.exists(),'A SIGKILL must not fabricate a final server report')
        self.log.close();return before

    def close(self):
        if self.proc.poll() is None:self.proc.kill();self.proc.wait(timeout=10)
        if not self.log.closed:self.log.close()


class QemuIO:
    def __init__(self,run,backend,label):
        self.log=(run/(label+'.qemuio.log')).open('xb');self.closed=False
        master,slave=pty.openpty();self.master=master;self.buffer=b'';self.total=0
        try:
            self.proc=subprocess.Popen(['/usr/bin/qemu-io','-t','writeback','-f','raw',
                'nbd+unix:///?socket='+str(backend.socket)],stdin=slave,stdout=slave,stderr=slave)
        except BaseException:os.close(master);self.log.close();raise
        finally:os.close(slave)
        try:self.prompt()
        except BaseException:self.close(abrupt=True);raise

    def prompt(self):
        deadline=time.monotonic()+15
        while b'qemu-io> ' not in self.buffer:
            require(time.monotonic()<deadline,'QEMU I/O prompt deadline; inspect private log')
            require(self.proc.poll() is None,'QEMU I/O client exited unexpectedly')
            if not select.select([self.master],[],[],.25)[0]:continue
            data=os.read(self.master,16384);require(data,'QEMU I/O console closed')
            self.total+=len(data);require(self.total<=4*2**20,'QEMU I/O console exceeded bound')
            self.log.write(data);self.log.flush();self.buffer+=data
        result,self.buffer=self.buffer.split(b'qemu-io> ',1)
        return result.decode(errors='replace')

    def command(self,text,operation=None,length=None):
        os.write(self.master,text.encode()+b'\n');result=self.prompt()
        require(not re.search(r'failed|error|invalid|not supported',result,re.I),
                'QEMU I/O command failed; inspect private log: '+text)
        if operation:
            word='wrote' if operation=='write' else 'read'
            require(re.search(r'\b'+word+r'\s+'+str(length)+'/'+str(length)+r'\s+bytes',result),
                    'QEMU I/O did not report a complete operation: '+text)
        return result

    def write(self,offset,length,pattern,fua=False):
        return self.command(f'write {"-f " if fua else ""}-P {pattern} {offset} {length}','write',length)

    def read(self,offset,length,pattern):
        return self.command(f'read -P {pattern} {offset} {length}','read',length)

    def close(self,abrupt=False):
        if self.closed:return
        try:
            if self.proc.poll() is None:
                if abrupt:self.proc.kill()
                else:os.write(self.master,b'quit\n')
                code=self.proc.wait(timeout=10)
                if not abrupt:require(code==0,'QEMU I/O did not close cleanly')
        finally:
            if self.proc.poll() is None:self.proc.kill();self.proc.wait(timeout=10)
            os.close(self.master);self.log.close();self.closed=True


def stable_bytes(path,offset,length,pattern):
    with path.open('rb') as stream:stream.seek(offset);data=stream.read(length)
    require(data==bytes([pattern])*length,'Stable bytes disagree with the expected durability boundary')


def verify_restart(run,stable,label,ranges):
    backend=Backend(run,stable,label);client=None
    try:
        client=QemuIO(run,backend,label)
        for offset,length,pattern in ranges:client.read(offset,length,pattern)
        client.close();stats=backend.cut()
        require(stats['dirty_bytes']==0 and stats['dropped_bytes']==0,'Readback unexpectedly left pending writes')
        require(stats['read_requests']>=len(ranges),'Independent client did not reach the backend')
        return stats
    finally:
        if client:client.close(abrupt=True)
        backend.close()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-label',required=True,type=guards.validate_label)
    args=parser.parse_args()
    require(Path('/run/host').exists(),'Run through virtual_test_lab.py')
    runs=LAB/'runs';runs.mkdir(mode=0o700,exist_ok=True)
    require(not runs.is_symlink(),'Unsafe calibration runs directory')
    run=runs/args.run_label;run.mkdir(mode=0o700)
    stable=run/'stable.raw'
    with stable.open('xb') as stream:stream.truncate(32*2**20);stream.flush();os.fsync(stream.fileno())
    stable.chmod(0o600)
    results=[]
    scenarios=['unflushed-loss','flush-survival','fua-isolation','backend-sigkill']
    for name in scenarios:
        backend=Backend(run,stable,name);client=None
        try:
            client=QemuIO(run,backend,name)
            if name=='unflushed-loss':
                client.write(0,4096,17);client.read(0,4096,17)
                expected=[(0,8192,0)];dirty=4096
            elif name=='flush-survival':
                client.write(8192,4096,34);client.command('flush')
                require(backend.stats()['flush_completed']>=1,'FLUSH did not reach the disk model')
                client.write(12288,4096,51)
                expected=[(8192,4096,34),(12288,4096,0)];dirty=4096
            elif name=='fua-isolation':
                client.write(16384,8192,68);client.write(16384,4096,85,fua=True)
                require(backend.stats()['fua_completed']==1,'FUA did not reach the disk model')
                client.write(16384,512,102);client.write(24576,4096,119)
                client.read(16384,512,102);client.read(16896,3584,85);client.read(20480,4096,68)
                expected=[(16384,4096,85),(20480,4096,0),(24576,4096,0)];dirty=8704
            else:
                client.write(32768,4096,136);client.command('flush')
                client.write(36864,4096,153,fua=True);client.write(40960,4096,170)
                expected=[(32768,4096,136),(36864,4096,153),(40960,4096,0)];dirty=4096
            before=backend.stats()
            require(before['dirty_bytes']==dirty and before['cache_limit_errors']==0,'Unexpected volatile state')
            if name=='unflushed-loss':
                backend.arm();acknowledged=True
                try:client.write(4096,4096,18)
                except RuntimeError:acknowledged=False  # A power cut may race delivery of the triggering reply.
                after=backend.wait_armed_cut(timeout=10)
                require(after['dropped_bytes']==8192 and after['cut_trigger_bytes']==4096,
                        'Armed cut did not discard both the previously acknowledged and triggering write')
                cut=dict(method='armed-next-ordinary-write',after=after,trigger_command_completed=acknowledged,
                         earlier_write_acknowledged_and_read_back=True)
            elif name=='backend-sigkill':
                killed=backend.kill();require(killed==before,'Dirty state changed before SIGKILL')
                cut=dict(method='actual-backend-SIGKILL',exit_code=-9,pre_kill_dirty_bytes=dirty)
            else:
                after=backend.cut();require(after['dropped_bytes']==dirty,'Power cut did not discard expected bytes')
                cut=dict(method='explicit-cache-power-cut',after=after)
            client.close(abrupt=True)
            for offset,length,pattern in expected:stable_bytes(stable,offset,length,pattern)
            restart=verify_restart(run,stable,name+'-restart',expected)
            result=dict(case=name,passed=True,before=before,cut=cut,
                        stable_readback_verified=True,independent_qemu_readback_after_restart=True,
                        restart_stats=restart,expected_ranges=[dict(offset=o,bytes=n,pattern=p) for o,n,p in expected])
            results.append(result);print(json.dumps({'case':name,'passed':True}),flush=True)
        finally:
            if client:client.close(abrupt=True)
            backend.close()
    report=dict(passed=True,schema_version=1,case_count=len(results),cases=results,
        independent_qemu_io_client=True,actual_backend_sigkill_tested=True,
        armed_cache_cut_tested=True,
        guest_kernel_tested=False,installer_or_worker_device_faults_tested=False,
        physical_power_loss_tested=False,torn_writes_modeled=False,performance_tested=False,
        stable_file_bytes=stable.stat().st_size,
        qemu_io_version=subprocess.check_output(['/usr/bin/qemu-io','--version'],text=True).splitlines()[0],
        recorded_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),
        source_sha256={n:hashlib.sha256((LAB/n).read_bytes()).hexdigest()
                       for n in ('volatile_disk.py','calibrate_volatile_disk.py')},
        fault_scope='Bounded volatile sector cache; completed FLUSH/FUA persist; cuts between backend requests')
    (run/'volatile-cache-calibration.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'passed':True,'case_count':len(results)}),flush=True)


if __name__=='__main__':main()
