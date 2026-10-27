#!/usr/bin/env python3
"""Read-only sampled mapping identity; path strings alone never qualify aliases.

All process IDs, paths, device/inode identities and namespace IDs stay private.
This is not an atomic snapshot, complete input closure or a content validator.
"""
import collections
import ctypes
import os
from pathlib import Path,PurePosixPath
import re
import select
import stat
import subprocess

import terminal_endpoint as terminal

MAP_LIMIT=2**20


def compile_library(output):
    subprocess.run(['cc','-O2','-Wall','-Wextra','-Werror','-shared','-fPIC',
        str(Path(__file__).with_suffix('.c')),'-o',str(output)],check=True,timeout=30)
    return library(output)


def library(path):
    lib=ctypes.CDLL(str(path),use_errno=True)
    lib.bc_open_rooted.argtypes=[ctypes.c_int,ctypes.c_char_p];lib.bc_open_rooted.restype=ctypes.c_int
    return lib


def open_rooted(lib,rootfd,path):
    fd=lib.bc_open_rooted(rootfd,os.fsencode(path))
    if fd<0:
        error=ctypes.get_errno();raise OSError(error,os.strerror(error))
    return fd


def parse_maps(text):
    rows={};skipped=collections.Counter()
    for line in text.splitlines():
        fields=line.split(maxsplit=5)
        terminal.require(len(fields)>=5,'Malformed maps record')
        if len(fields)<6 or not fields[5].startswith('/'):
            skipped['non_absolute_or_anonymous']+=1;continue
        path=fields[5]
        if path.endswith(' (deleted)'):skipped['deleted']+=1;continue
        if '\\' in path:skipped['escaped_path']+=1;continue
        parsed=PurePosixPath(path)
        if '..' in parsed.parts or str(parsed)!=path:skipped['noncanonical_path']+=1;continue
        terminal.require(re.fullmatch('[0-9a-f]+:[0-9a-f]+',fields[3]) is not None and fields[4].isdigit(),
            'Malformed maps identity')
        major,minor=(int(n,16) for n in fields[3].split(':'));inode=int(fields[4])
        if not inode:skipped['zero_inode']+=1;continue
        terminal.require(re.fullmatch('[0-9a-f]+-[0-9a-f]+',fields[0]) is not None,'Malformed mapping range')
        key=(path,os.makedev(major,minor),inode,fields[0])
        rows[key]=dict(path=path,device=key[1],inode=inode,mapping_range=fields[0])
    terminal.require(len(rows)<=8192,'Mapping object bound')
    return rows,dict(skipped)


def maps_at(procfd):
    fd=os.open('maps',os.O_RDONLY|os.O_CLOEXEC,dir_fd=procfd)
    try:
        data=b''
        while True:
            block=os.read(fd,min(65536,MAP_LIMIT+1-len(data)))
            if not block:break
            data+=block;terminal.require(len(data)<=MAP_LIMIT,'Oversized maps snapshot')
    finally:os.close(fd)
    terminal.require(len(data)<=MAP_LIMIT and data.endswith(b'\n'),'Truncated or oversized maps snapshot')
    return parse_maps(data.decode('utf-8',errors='strict'))


def identity(info):return info.st_dev,info.st_ino


def inspect(pid,owned,lib):
    """Pin PID/root/mapping reference; compare rooted lookup and host lookup.

    `owned` must restrict the PID to this caller's own trial. No process is
    stopped, injected, entered or modified. Unresolved objects remain explicit.
    """
    terminal.require(owned(pid),'Unowned mapping observation')
    pidfd=os.pidfd_open(pid);poll=select.poll();poll.register(pidfd,select.POLLIN)
    try:
        terminal.require(not poll.poll(0),'Mapping process already exited')
        procfd=os.open(f'/proc/{pid}',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
        try:
            namespace=os.readlink('ns/mnt',dir_fd=procfd)
            rootfd=os.open('root',os.O_PATH|os.O_DIRECTORY|os.O_CLOEXEC,dir_fd=procfd)
            try:
                before,skipped=maps_at(procfd);records=[]
                for key,row in sorted(before.items()):
                    result=dict(row);reference=None
                    try:
                        reference=os.open('map_files/'+row['mapping_range'],os.O_PATH|os.O_CLOEXEC,dir_fd=procfd)
                        actual=os.fstat(reference)
                        result.update(reference_device=actual.st_dev,reference_inode=actual.st_ino,
                            maps_device_matches_reference=row['device']==actual.st_dev)
                    except OSError as exc:
                        if reference is not None:os.close(reference)
                        result.update(status='mapping_reference_unavailable',errno=exc.errno)
                        records.append(result);continue
                    try:
                        fd=open_rooted(lib,rootfd,row['path'])
                        try:view=os.fstat(fd)
                        finally:os.close(fd)
                        result.update(view_device=view.st_dev,view_inode=view.st_ino)
                        result['view_identity_matches_mapping']=identity(view)==identity(actual)
                        if not stat.S_ISREG(view.st_mode):result['status']='nonregular_view'
                        elif not result['view_identity_matches_mapping']:result['status']='view_path_mismatch'
                        else:
                            try:
                                hostfd=os.open(row['path'],os.O_PATH|os.O_CLOEXEC)
                                try:host=os.fstat(hostfd)
                                finally:os.close(hostfd)
                                same=stat.S_ISREG(host.st_mode) and identity(host)==identity(actual)
                            except OSError:same=False
                            result['status']='same_host_object' if same else 'different_host_object'
                    except OSError as exc:result.update(status='unresolved_view',errno=exc.errno)
                    finally:os.close(reference)
                    records.append(result)
                after,_=maps_at(procfd)
                for row in records:
                    key=(row['path'],row['device'],row['inode'],row['mapping_range'])
                    if key not in after:row['status']='mapping_changed_during_observation'
                terminal.require(os.readlink('ns/mnt',dir_fd=procfd)==namespace,'Process mount namespace changed')
                terminal.require(not poll.poll(0) and owned(pid),'Mapping process exited or left owned scope')
                return dict(pid=pid,mount_namespace=namespace,records=records,skipped=skipped,
                    process_identity_pinned=True,root_descriptor_pinned=True,atomic_snapshot=False)
            finally:os.close(rootfd)
        finally:os.close(procfd)
    finally:os.close(pidfd)


def summarize(samples):
    counts=collections.Counter();skipped=collections.Counter();objects=set();namespaces=set()
    for sample in samples:
        namespaces.add(sample['mount_namespace']);skipped.update(sample['skipped'])
        for row in sample['records']:
            counts[row['status']]+=1
            if row['status']=='same_host_object':objects.add((row['reference_device'],row['reference_inode']))
    return dict(process_samples=len(samples),mount_namespace_count=len(namespaces),statuses=dict(counts),
        skipped=dict(skipped),unique_verified_same_host_objects=len(objects),atomic_snapshot=False,
        complete_application_input_closure=False)
