#!/usr/bin/env python3
"""Read-only application candidates, anonymized by default; no account/save data.

Package/build IDs and suffix counts are selection evidence, not frozen inputs.
No application starts, cache eviction, profile/configuration reads or writes.
"""
import collections
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess


def command(*args):
    result=subprocess.run(args,capture_output=True,text=True,timeout=10)
    return result.stdout.strip() if result.returncode==0 else None


def suffixes(root):
    counts=collections.Counter();files=0;truncated=False
    for directory,children,names in os.walk(root,followlinks=False):
        depth=len(Path(directory).relative_to(root).parts)
        if depth>=4:children[:]=[]
        for name in names:
            counts[Path(name).suffix.lower() or '<none>']+=1;files+=1
            if files>=10000:truncated=True;break
        if truncated:break
    return dict(file_suffix_counts=dict(counts),files_examined=files,depth_limit=4,file_limit=10000,truncated=truncated)


def main():
    tools=('steam','konsole','dolphin','kate','gwenview','firefox','mpv','qdbus6','gdbus','spectacle','mangohud')
    packages=('kwin','plasma-workspace','konsole','dolphin','kate','gwenview','firefox','mpv','steam','mangohud','gamescope','vulkan-radeon')
    report=dict(schema_version=1,source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        tools_available={name:shutil.which(name) is not None for name in tools},
        packages={name:command('pacman','-Q',name) for name in packages},steam_libraries=[])
    environment=command('systemctl','--user','show-environment') or ''
    values=dict(line.partition('=')[::2] for line in environment.splitlines() if '=' in line)
    report['session']=dict(type=values.get('XDG_SESSION_TYPE'),desktop=values.get('XDG_CURRENT_DESKTOP'),
        wayland_display_available=bool(values.get('WAYLAND_DISPLAY')))
    steam=Path.home()/'.local/share/Steam/steamapps';libraries={steam};vdf=steam/'libraryfolders.vdf'
    if vdf.is_file() and vdf.stat().st_size<262144:
        libraries.update(Path(p)/'steamapps' for p in re.findall(r'"path"\s*"([^"\n]+)"',vdf.read_text()))
    for index,library in enumerate(sorted(libraries)):
        games=[]
        for manifest in sorted(library.glob('appmanifest_*.acf')):
            if manifest.stat().st_size>262144:continue
            fields=dict(re.findall(r'"([^"\n]+)"\s*"([^"\n]*)"',manifest.read_text()))
            selected={key:fields.get(key) for key in ('appid','name','buildid','StateFlags','SizeOnDisk')}
            install=fields.get('installdir','__missing__');directory=library/'common'/install
            # Never walk a manifest path outside its library's common tree.
            safe=not Path(install).is_absolute() and '..' not in Path(install).parts
            safe=safe and directory.resolve().is_relative_to((library/'common').resolve())
            selected['install_directory_exists']=safe and directory.is_dir()
            if selected['install_directory_exists']:selected.update(suffixes(directory))
            games.append(selected)
        report['steam_libraries'].append(dict(library_index=index,applications=games))
    build=Path('/usr/lib/modules')/os.uname().release/'build'
    report['kernel_sources_available']={str(p.relative_to(build)):p.is_file() for p in
        (build/'block/blk-flush.c',build/'block/blk-mq.c',build/'kernel/bpf/syscall.c')}
    types=build/'include/linux/blk_types.h'
    if types.is_file():
        text=types.read_text()
        bits=re.search(r'#define\s+REQ_OP_BITS\s+(\d+)',text)
        flush=re.search(r'REQ_OP_FLUSH\s*=\s*(?:\(__force\s+blk_opf_t\))?(\d+)\s*,',text)
        report['installed_block_operation_header']=dict(sha256=hashlib.sha256(types.read_bytes()).hexdigest(),
            req_op_bits=int(bits.group(1)) if bits else None,
            req_op_flush=int(flush.group(1)) if flush else None,
            operation_encoding_recognized=bool(bits and flush))
    report.update(kernel=os.uname().release,applications_launched=False,cache_eviction_performed=False,
        private_paths_included=False,application_profiles_or_saves_read=False,suite_freeze_complete=False)
    print(json.dumps(report,indent=2))


if __name__=='__main__':main()
