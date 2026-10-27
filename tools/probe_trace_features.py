#!/usr/bin/env python3
"""Read tracing capabilities without enabling events or changing trace state."""
import hashlib
import json
from pathlib import Path
import re
import shutil
import time

TRACE=Path('/sys/kernel/tracing')
EVENTS=('block:block_rq_insert','block:block_rq_issue','block:block_rq_complete',
    'block:block_rq_requeue','block:block_rq_merge','exceptions:page_fault_user',
    'filemap:mm_filemap_fault','filemap:mm_filemap_get_pages','filemap:mm_filemap_map_pages',
    'filemap:mm_filemap_add_to_page_cache','filemap:mm_filemap_delete_from_page_cache',
    'btrfs:btrfs_sync_file_enter','btrfs:btrfs_sync_file_exit','sched:sched_switch')


def fields(text):
    rows=[]
    for line in text.splitlines():
        match=re.fullmatch(r'\s*field:(.*?);\s*offset:(\d+);\s*size:(\d+);\s*signed:([01]);\s*',line)
        if not match:continue
        name=re.search(r'([a-zA-Z_]\w*)(?:\[[^\]]*\])?$',match[1].strip())
        if name:rows.append(dict(name=name[1],declaration=match[1],offset=int(match[2]),
            bytes=int(match[3]),signed=match[4]=='1'))
    return rows


def snapshot():
    # Observing formats must not turn on or clear someone else's trace buffer.
    return {name:(TRACE/name).read_text().strip() for name in ('tracing_on','current_tracer','trace_clock')}


def collect():
    before=snapshot();available=set((TRACE/'available_events').read_text().split());events={}
    for event in EVENTS:
        if event not in available:events[event]=dict(available=False);continue
        group,name=event.split(':');text=(TRACE/'events'/group/name/'format').read_text()
        rows=fields(text)
        if not rows or not any(row['name']=='common_pid' for row in rows):
            raise RuntimeError('Unrecognized event format: '+event)
        events[event]=dict(available=True,format_sha256=hashlib.sha256(text.encode()).hexdigest(),fields=rows)
    functions=TRACE/'available_filter_functions';decompression=[]
    if functions.is_file():
        # Publish function names only, never kernel addresses.
        for line in functions.read_text().splitlines():
            name=line.split()[0]
            if re.fullmatch(r'[A-Za-z_]\w*(?:\.\w+)*',name) and ('decompress' in name.lower() or 'readahead' in name.lower()):
                decompression.append(name)
    after=snapshot()
    if after!=before:raise RuntimeError('Trace state changed during read-only probe; preserve and investigate')
    names=lambda event:{row['name'] for row in events.get(event,{}).get('fields',[])}
    issue=names('block:block_rq_issue');complete=names('block:block_rq_complete')
    identifiers=sorted(issue & complete & {'rq','request','rq_addr','request_ptr'})
    return dict(schema_version=1,kind='bc250-trace-feature-probe',kernel=Path('/proc/sys/kernel/osrelease').read_text().strip(),
        collected_unix=time.time(),events=events,btf_available=Path('/sys/kernel/btf/vmlinux').is_file(),
        userspace_tools={name:shutil.which(name) is not None for name in ('perf','bpftrace','trace-cmd','bpftool','clang','gcc')},
        available_function_names=sorted(set(decompression)),trace_state_unchanged=True,events_enabled_by_probe=False,
        shared_issue_complete_identifier_fields=identifiers,
        request_pairing_from_sector_dev_alone_is_unambiguous=False,
        issue_pid_is_proven_foreground_owner=False,
        latency_or_performance_measured=False,
        source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())


if __name__=='__main__':print(json.dumps(collect(),indent=2))
