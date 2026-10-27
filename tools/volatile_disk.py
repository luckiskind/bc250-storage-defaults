"""Private lab NBD disk with bounded RAM write cache and explicit durability.

Never a production cache. Only an owned, private, regular-file test disk is
accepted. Ordinary writes stay exclusively in RAM until FLUSH. FUA persists
only its write; a modeled power cut discards RAM. No torn-write model is implied.
"""
import argparse
import errno
import fcntl
import json
import os
from pathlib import Path
import socket
import stat
import struct
import threading
import time

SECTOR=512
MAX_REQUEST=32*2**20
OPTION_MAGIC=0x49484156454f5054
REPLY_MAGIC=0x3e889045565a9
TRANSMISSION_FLAGS=1|4|8  # HAS_FLAGS, SEND_FLUSH, SEND_FUA; no multi-connection claim.


class RequestError(OSError):
    """Rejected before persistence; unlike an actual backing-file I/O failure."""


def require(condition,message):
    if not condition:raise RuntimeError(message)


def private_parent(path):
    path=Path(path).absolute()
    require(path.parent.resolve(strict=True)==path.parent,'Symlink/alias parent refused')
    info=path.parent.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid==os.geteuid() and info.st_mode&0o077==0,
            'Test disk/socket parent must be an owned private directory')
    return path


def pwrite_all(fd,data,offset):
    view=memoryview(data)
    while view:
        count=os.pwrite(fd,view,offset)
        if count<=0:raise OSError(errno.EIO,'Short persistent write')
        offset+=count;view=view[count:]


class VolatileDisk:
    def __init__(self,path,cache_bytes=64*2**20):
        require(SECTOR<=cache_bytes<=256*2**20 and cache_bytes%SECTOR==0,'Invalid bounded cache size')
        self.path=private_parent(path)
        fd=os.open(self.path,os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            info=os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_uid==os.geteuid()
                    and info.st_mode&0o077==0 and info.st_mode&0o200,
                    'Only a private owned writable regular test file is accepted')
            require(SECTOR<=info.st_size<=128*2**30 and info.st_size%SECTOR==0,'Invalid test disk capacity')
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BaseException:os.close(fd);raise
        self.fd=fd;self.size=info.st_size;self.cache_bytes=cache_bytes
        self.dirty={};self.closed=False;self.lock=threading.Lock()
        self.stats=dict(read_requests=0,write_requests=0,volatile_write_bytes=0,
            flush_completed=0,flush_persisted_bytes=0,fua_completed=0,fua_persisted_bytes=0,
            power_cuts=0,dropped_bytes=0,peak_dirty_bytes=0,cache_limit_errors=0,
            armed_for_volatile_write=False,cut_trigger_offset=-1,cut_trigger_bytes=0)

    def validate(self,offset,length):
        if self.closed:raise RequestError(errno.EIO,'Device powered off')
        if not (type(offset) is int and type(length) is int and offset>=0 and
                0<length<=MAX_REQUEST and offset%SECTOR==0 and length%SECTOR==0 and offset+length<=self.size):
            raise RequestError(errno.EINVAL,'Invalid aligned test request')

    def read(self,offset,length):
        with self.lock:
            self.validate(offset,length)
            data=bytearray(os.pread(self.fd,length,offset))
            require(len(data)==length,'Stable file was truncated')
            for position in range(offset,offset+length,SECTOR):
                cached=self.dirty.get(position)
                if cached is not None:data[position-offset:position-offset+SECTOR]=cached
            self.stats['read_requests']+=1
            return bytes(data)

    def write(self,offset,data,fua=False):
        with self.lock:
            self.validate(offset,len(data))
            positions=range(offset,offset+len(data),SECTOR)
            if fua:
                pwrite_all(self.fd,data,offset);os.fsync(self.fd)
                # A later flush must not resurrect older cached versions.
                for position in positions:self.dirty.pop(position,None)
                self.stats['fua_completed']+=1;self.stats['fua_persisted_bytes']+=len(data)
            else:
                additional=sum(position not in self.dirty for position in positions)*SECTOR
                if len(self.dirty)*SECTOR+additional>self.cache_bytes:
                    self.stats['cache_limit_errors']+=1
                    raise RequestError(errno.ENOSPC,'Bounded model cache exhausted; no implicit eviction/flush')
                for position in positions:self.dirty[position]=bytes(data[position-offset:position-offset+SECTOR])
                self.stats['volatile_write_bytes']+=len(data)
                self.stats['peak_dirty_bytes']=max(self.stats['peak_dirty_bytes'],len(self.dirty)*SECTOR)
            self.stats['write_requests']+=1

    def flush(self):
        with self.lock:
            if self.closed:raise RequestError(errno.EIO,'Device powered off')
            positions=sorted(self.dirty);count=len(positions)*SECTOR
            index=0
            while index<len(positions):
                start=positions[index];payload=bytearray(self.dirty[start]);index+=1
                while index<len(positions) and positions[index]==start+len(payload) and len(payload)<2**20:
                    payload.extend(self.dirty[positions[index]]);index+=1
                pwrite_all(self.fd,payload,start)
            os.fsync(self.fd)
            self.dirty.clear();self.stats['flush_completed']+=1
            self.stats['flush_persisted_bytes']+=count

    def snapshot(self):
        with self.lock:return dict(**self.stats,dirty_bytes=len(self.dirty)*SECTOR,capacity_bytes=self.size,
                                   cache_limit_bytes=self.cache_bytes,powered_off=self.closed)

    def power_cut(self):
        with self.lock:
            require(not self.closed,'Device already powered off')
            self._cut_locked()
        return self.snapshot()

    def _cut_locked(self):
        self.stats['power_cuts']+=1;self.stats['dropped_bytes']+=len(self.dirty)*SECTOR
        self.dirty.clear();self.closed=True

    def arm_write_cut(self):
        with self.lock:
            require(not self.closed and not self.stats['armed_for_volatile_write'],'Cannot arm powered-off/already armed disk')
            self.stats['armed_for_volatile_write']=True
        return self.snapshot()

    def after_acknowledged_write(self,offset,length,fua):
        with self.lock:
            if self.stats['armed_for_volatile_write'] and not fua and not self.closed:
                self.stats.update(cut_trigger_offset=offset,cut_trigger_bytes=length)
                self._cut_locked();return True
        return False

    def close(self):
        # Closing never calls FLUSH or writes buffered sectors to the stable file.
        if self.fd is not None:os.close(self.fd);self.fd=None


def receive(sock,length):
    data=bytearray()
    while len(data)<length:
        chunk=sock.recv(length-len(data))
        if not chunk:raise EOFError('NBD peer disconnected')
        data.extend(chunk)
    return bytes(data)


def option_reply(sock,option,kind,data=b''):
    sock.sendall(struct.pack('>QIII',REPLY_MAGIC,option,kind,len(data))+data)


def negotiate(sock,disk):
    sock.sendall(struct.pack('>QQH',0x4e42444d41474943,OPTION_MAGIC,3))
    client,=struct.unpack('>I',receive(sock,4))
    require(client&1 and client&~3==0,'Unsupported fixed-newstyle client flags')
    for _ in range(32):
        magic,option,length=struct.unpack('>QII',receive(sock,16))
        require(magic==OPTION_MAGIC and length<=4096,'Invalid/bounded NBD option')
        data=receive(sock,length)
        if option==2:
            option_reply(sock,option,1);return False
        if option==1:
            require(data==b'','Only the unnamed private export exists')
            sock.sendall(struct.pack('>QH',disk.size,TRANSMISSION_FLAGS)+(b'' if client&2 else bytes(124)))
            return True
        if option in (6,7):
            valid=len(data)>=6
            if valid:
                name_length,=struct.unpack('>I',data[:4]);valid=name_length==0
                n,=struct.unpack('>H',data[4:6]);valid=valid and len(data)==6+2*n
            if not valid:
                option_reply(sock,option,0x80000003);continue
            option_reply(sock,option,3,struct.pack('>HQH',0,disk.size,TRANSMISSION_FLAGS))
            option_reply(sock,option,3,struct.pack('>HIII',3,SECTOR,4096,MAX_REQUEST))
            option_reply(sock,option,1)
            if option==7:return True
        else:option_reply(sock,option,0x80000001)
    raise RuntimeError('Too many NBD negotiation options')


def transmission(sock,disk):
    while True:
        magic,flags,kind,cookie,offset,length=struct.unpack('>IHHQQI',receive(sock,28))
        require(magic==0x25609513 and length<=MAX_REQUEST,'Invalid/bounded NBD request')
        # Consume bounded WRITE data even for an invalid request, preserving framing.
        data=receive(sock,length) if kind==1 else b''
        if kind==2:
            require(flags&~1==0 and offset==0 and length==0,'Invalid NBD disconnect')
            return
        result=b'';error=0
        try:
            if flags&~1:raise RequestError(errno.EINVAL,'Unsupported request flags')
            if kind==0:result=disk.read(offset,length)
            elif kind==1:disk.write(offset,data,fua=bool(flags&1))
            elif kind==3:
                if offset or length:raise RequestError(errno.EINVAL,'Invalid FLUSH range')
                disk.flush()
            else:raise RequestError(errno.EINVAL,'Unadvertised NBD operation')
        except RequestError as failure:
            # Validation/cache exhaustion are modeled request errors. An actual
            # stable-file I/O failure invalidates the run rather than faking durability.
            error=failure.errno
        sock.sendall(struct.pack('>IIQ',0x67446698,error,cookie)+(result if error==0 else b''))
        if kind==1 and error==0 and disk.after_acknowledged_write(offset,length,bool(flags&1)):
            return True


def new_socket(path):
    path=private_parent(path)
    require(not path.exists() and not path.is_symlink(),'Existing socket path preserved')
    sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
    try:sock.bind(str(path));os.chmod(path,0o600);sock.listen(1);sock.settimeout(.25)
    except BaseException:sock.close();raise
    return sock


def serve(disk,data_socket,control_socket,report):
    stopped=threading.Event();errors=[];active=[]
    def nbd():
        try:
            while not stopped.is_set():
                try:peer,_=data_socket.accept()
                except socket.timeout:continue
                active.append(peer)
                try:
                    peer.settimeout(300)
                    if negotiate(peer,disk) and transmission(peer,disk):stopped.set()
                except (EOFError,ConnectionError,socket.timeout):pass
                except OSError:
                    if not stopped.is_set():raise
                finally:peer.close();active.remove(peer)
        except BaseException as error:errors.append(repr(error));stopped.set()
    thread=threading.Thread(target=nbd,daemon=True);thread.start()
    reason='error'
    try:
        while not stopped.is_set():
            try:peer,_=control_socket.accept()
            except socket.timeout:continue
            with peer:
                peer.settimeout(2);request=bytearray()
                while b'\n' not in request and len(request)<=1024:
                    chunk=peer.recv(1024)
                    if not chunk:break
                    request.extend(chunk)
                command=bytes(request).strip()
                if command==b'stats':answer=disk.snapshot()
                elif command==b'arm-write-cut':answer=disk.arm_write_cut()
                elif command==b'power-cut':
                    stopped.set();answer=disk.power_cut();reason='modeled-power-cut'
                else:answer={'error':'Expected stats, arm-write-cut or power-cut'}
                peer.sendall(json.dumps(answer).encode()+b'\n')
    finally:
        stopped.set()
        for peer in list(active):
            try:peer.shutdown(socket.SHUT_RDWR)
            except OSError:pass
        thread.join(timeout=5);require(not thread.is_alive(),'NBD thread did not stop')
        final=disk.snapshot()
        if final['cut_trigger_bytes']>0:reason='armed-volatile-write-cut'
        result=dict(reason=reason,stats=final,errors=errors,
            volatile_cache_modeled=True,torn_writes_modeled=False,
            cut_boundary='between backend requests; in-progress FLUSH/FUA finish before the cut lock')
        fd=os.open(report,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'w') as stream:json.dump(result,stream,indent=2);stream.write('\n')
    require(not errors,'NBD server error: '+repr(errors))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stable',type=Path,required=True)
    parser.add_argument('--socket',type=Path,required=True)
    parser.add_argument('--control',type=Path,required=True)
    parser.add_argument('--report',type=Path,required=True)
    parser.add_argument('--cache-mib',type=int,default=64)
    args=parser.parse_args()
    report=private_parent(args.report)
    require(not report.exists() and not report.is_symlink(),'Existing report preserved')
    disk=VolatileDisk(args.stable,args.cache_mib*2**20)
    data=control=None
    try:
        data=new_socket(args.socket);control=new_socket(args.control)
        print(json.dumps({'ready':True,'capacity_bytes':disk.size}),flush=True)
        serve(disk,data,control,report)
    finally:
        if data:data.close()
        if control:control.close()
        disk.close()


if __name__=='__main__':main()
