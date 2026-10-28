"""Checked omission of optional unlock logging; all causal probes stay."""
import json
import re
from combined_wait_loader import generate as full_generate


def generate(source):
    original=re.search(r'const char \*names\[\]=\{[^;]+\};',source)
    if not original or original[0].count('"unlock_call"')!=1:raise ValueError('Reference optional hook name differs')
    result=full_generate(source)
    def change(old,new):
        nonlocal result
        if result.count(old)!=1:raise ValueError('Combined loader template differs: '+old[:70])
        result=result.replace(old,new)
    change('#define PROGRAMS 29','#define PROGRAMS 28')
    change('if(bpf_object__load(object))goto cleanup;',
        'struct bpf_program *omitted=bpf_object__find_program_by_name(object,"unlock_call");\n'
        '    if(!omitted || bpf_program__set_autoload(omitted,0))goto cleanup;\n'
        '    if(bpf_object__load(object))goto cleanup;')
    names=re.search(r'const char \*names\[\]=\{[^;]+\};',result)
    if not names or names[0].count(',"unlock_call"')!=1:raise ValueError('Exactly one optional unlock hook required')
    change(names[0],names[0].replace(',"unlock_call"',''))
    change('BC250_COMBINED_WAIT_READY','BC250_COMPACT_WAIT_READY')
    change('bc250-combined-wait-diagnostic','bc250-compact-wait-diagnostic')
    change(r'\"links_detached\":true',r'\"unlock_hook_loaded\":false,\"links_detached\":true')
    return result


def ready_ids(log):
    for line in log.split(b'\n')[:-1]:
        if line.startswith(b'BC250_COMPACT_WAIT_READY '):
            ids=json.loads(line.split(b' ',1)[1])['program_ids']
            if len(ids)!=28 or len(set(ids))!=28 or any(type(n) is not int or n<=0 for n in ids):raise ValueError('Twenty-eight distinct owned program IDs required')
            return ids
    return None
