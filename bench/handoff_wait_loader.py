"""Checked scheduler-entry clock revision with frozen causal proof work."""
import json
from compact_wait_loader import generate as compact_generate
from combined_wait_loader import folio_extension as combined_folio


def replace_once(source,old,new):
    if source.count(old)!=1:raise ValueError('Handoff reference template differs: '+old[:70])
    return source.replace(old,new)


def vector_extension(source):
    source=replace_once(source,'/* Opt-in combined diagnostic. All addresses/generations remain private. */\n#include "request_bio_lineage.bpf.c"\n#include "folio_vector_math.h"\n',
        '/* Frozen vector proof, shared by the handoff diagnostic. */\n')
    return replace_once(source,'#include "combined_folio.generated.h"','')


def folio_extension(source):
    source=combined_folio(source)
    source=replace_once(source,'__u64 state,__u64 preempt){','__u64 state,__u64 preempt,__u64 hook_entry_ns){')
    source=replace_once(source,'fw_wake(struct task_struct *task,__u32 stage){','fw_wake(struct task_struct *task,__u32 stage,__u64 hook_entry_ns){')
    old='fw_emit(&c,stage,0,0,bpf_ktime_get_ns());'
    if source.count(old)!=2:raise ValueError('Expected exactly two scheduler emit sites')
    source=source.replace(old,'fw_emit(&c,stage,0,0,hook_entry_ns);')
    source=replace_once(source,'int fw_sched_switch(struct bpf_raw_tracepoint_args *ctx){\n    if(!enabled())return 0;',
        'int fw_sched_switch(struct bpf_raw_tracepoint_args *ctx){\n    __u64 hook_entry_ns=bpf_ktime_get_ns();if(!enabled())return 0;')
    source=replace_once(source,'FW_SWITCH_OUT,ctx->args[3],!!ctx->args[0]);','FW_SWITCH_OUT,ctx->args[3],!!ctx->args[0],hook_entry_ns);')
    source=replace_once(source,'FW_SWITCH_IN,0,0);','FW_SWITCH_IN,0,0,hook_entry_ns);')
    for suffix,stage in [('waking','FW_WAKING'),('wakeup','FW_WAKEUP')]:
        source=replace_once(source,'int fw_sched_'+suffix+'(struct bpf_raw_tracepoint_args *ctx){if(!enabled())return 0;return fw_wake((void *)ctx->args[0],'+stage+');}',
            'int fw_sched_'+suffix+'(struct bpf_raw_tracepoint_args *ctx){__u64 hook_entry_ns=bpf_ktime_get_ns();if(!enabled())return 0;return fw_wake((void *)ctx->args[0],'+stage+',hook_entry_ns);}')
    return source


def generate(source):
    result=compact_generate(source)
    for old,new in [('BC250_COMPACT_WAIT_READY','BC250_HANDOFF_WAIT_READY'),('bc250-compact-wait-diagnostic','bc250-handoff-wait-diagnostic'),
        (r'\"schema_version\":1',r'\"schema_version\":2'),
        (r'\"unlock_hook_loaded\":false',r'\"scheduler_timestamp_basis\":\"hook-entry-v1\",\"unlock_hook_loaded\":false')]:
        result=replace_once(result,old,new)
    return result


def ready_ids(log):
    for line in log.split(b'\n')[:-1]:
        if line.startswith(b'BC250_HANDOFF_WAIT_READY '):
            ids=json.loads(line.split(b' ',1)[1])['program_ids']
            if len(ids)!=28 or len(set(ids))!=28 or any(type(n) is not int or n<=0 for n in ids):raise ValueError('Twenty-eight distinct owned program IDs required')
            return ids
    return None
