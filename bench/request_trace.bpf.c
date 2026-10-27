/* Read-only observer: no request/device/tracefs writes, pins or perf hooks. */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-declarations"
#include "vmlinux.h"
#pragma clang diagnostic pop
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "request_trace.h"

struct request_key { __u64 address,generation; };
struct request_state {
    struct bc250_event event;
};
struct {
    __uint(type,BPF_MAP_TYPE_HASH);
    __uint(max_entries,TRACE_MAP_LIMIT);
    __type(key,struct request_key);
    __type(value,struct request_state);
} pending SEC(".maps");
struct {
    __uint(type,BPF_MAP_TYPE_ARRAY); __uint(max_entries,1);
    __type(key,__u32); __type(value,struct trace_config);
} bc250_config SEC(".maps");
struct {
    __uint(type,BPF_MAP_TYPE_ARRAY); __uint(max_entries,TRACE_STAT_COUNT);
    __type(key,__u32); __type(value,__u64);
} counters SEC(".maps");
struct {
    __uint(type,BPF_MAP_TYPE_ARRAY); __uint(max_entries,1);
    __type(key,__u32); __type(value,__u64);
} sequence SEC(".maps");
struct {
    __uint(type,BPF_MAP_TYPE_RINGBUF); __uint(max_entries,4*1024*1024);
} events SEC(".maps");

static __always_inline void inc(__u32 name) {
    __u64 *value=bpf_map_lookup_elem(&counters,&name);
    if (value)__sync_fetch_and_add(value,1);
}
static __always_inline bool identify(struct request *rq,struct request_key *key) {
    __u32 zero=0;
    struct trace_config *cfg=bpf_map_lookup_elem(&bc250_config,&zero);
    if (!cfg || !cfg->enabled)return false;
    if (BPF_CORE_READ(rq,q,disk,major)!=cfg->major ||
        BPF_CORE_READ(rq,q,disk,first_minor)!=cfg->minor)return false;
    key->address=(__u64)rq;
    key->generation=BPF_CORE_READ(rq,start_time_ns);
    if (!key->generation) {inc(ST_ZERO_GENERATION);return false;}
    return true;
}
static __always_inline struct request_state *create(struct request_key *key,__u64 inserted) {
    struct request_state initial={};initial.event.insert_ns=inserted;
    if (bpf_map_update_elem(&pending,key,&initial,BPF_NOEXIST)) {
        inc(ST_MAP_UPDATE_FAIL);return 0;
    }
    return bpf_map_lookup_elem(&pending,key);
}
SEC("raw_tp/block_rq_insert")
int inserted(struct bpf_raw_tracepoint_args *ctx) {
    struct request *rq=(void *)ctx->args[0];struct request_key key={};
    if (!identify(rq,&key))return 0;
    inc(ST_INSERT);
    struct request_state *old=bpf_map_lookup_elem(&pending,&key);
    if (old) {old->event.flags|=F_REPEAT_INSERT;inc(ST_REPEAT_INSERT);}
    else create(&key,bpf_ktime_get_ns());
    return 0;
}
SEC("raw_tp/block_rq_issue")
int issued(struct bpf_raw_tracepoint_args *ctx) {
    struct request *rq=(void *)ctx->args[0];struct request_key key={};
    if (!identify(rq,&key))return 0;
    inc(ST_ISSUE);__u64 now=bpf_ktime_get_ns();
    struct request_state *state=bpf_map_lookup_elem(&pending,&key);
    if (!state)state=create(&key,0);
    if (!state)return 0;
    if (state->event.issue_ns) {state->event.flags|=F_DUPLICATE;inc(ST_DUPLICATE_ISSUE);}
    else {
        __u32 zero=0;__u64 *seq=bpf_map_lookup_elem(&sequence,&zero);
        if (seq)state->event.sequence=__sync_fetch_and_add(seq,1)+1;
        state->event.issue_ns=now;
        state->event.bytes=BPF_CORE_READ(rq,__data_len);
        /* Running kernel's blk_types.h verifies REQ_OP_BITS == 8. */
        state->event.operation=BPF_CORE_READ(rq,cmd_flags)&255;
        if (!state->event.insert_ns)state->event.flags|=F_NO_INSERT;
        if (!state->event.bytes)state->event.flags|=F_ZERO_BYTES;
    }
    return 0;
}
SEC("raw_tp/block_rq_requeue")
int requeued(struct bpf_raw_tracepoint_args *ctx) {
    struct request *rq=(void *)ctx->args[0];struct request_key key={};
    if (!identify(rq,&key))return 0;
    inc(ST_REQUEUE);struct request_state *state=bpf_map_lookup_elem(&pending,&key);
    if (state)state->event.flags|=F_REQUEUE;
    else inc(ST_ORPHAN_REQUEUE);
    return 0;
}
SEC("raw_tp/block_rq_complete")
int completed(struct bpf_raw_tracepoint_args *ctx) {
    struct request *rq=(void *)ctx->args[0];struct request_key key={};
    if (!identify(rq,&key))return 0;
    struct request_state *state=bpf_map_lookup_elem(&pending,&key);
    if (!state) {inc(ST_ORPHAN_COMPLETE);return 0;}
    if (!state->event.issue_ns) {inc(ST_NO_ISSUE);bpf_map_delete_elem(&pending,&key);return 0;}
    __u32 bytes=ctx->args[2];
    __u32 done=__sync_fetch_and_add(&state->event.completed_bytes,bytes)+bytes;
    if (ctx->args[1])state->event.flags|=F_ERROR;
    if (done<state->event.bytes) {state->event.flags|=F_PARTIAL;inc(ST_PARTIAL);return 0;}
    if (done>state->event.bytes) {state->event.flags|=F_OVERSHOOT;inc(ST_OVERSHOOT);}
    struct bc250_event event=state->event;event.complete_ns=bpf_ktime_get_ns();
    if (event.complete_ns<event.issue_ns || (event.insert_ns && event.issue_ns<event.insert_ns)) {
        event.flags|=F_BAD_TIME;inc(ST_BAD_TIME);
    }
    /* Only the successful delete owns the final event. Concurrent completion
     * cannot publish the same map entry twice; generation separates reuse. */
    if (bpf_map_delete_elem(&pending,&key)) {inc(ST_DELETE_RACE);return 0;}
    inc(ST_FINAL);
    if (bpf_ringbuf_output(&events,&event,sizeof(event),0))inc(ST_RING_LOST);
    return 0;
}
char LICENSE[] SEC("license")="GPL";
