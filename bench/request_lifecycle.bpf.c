/* Read-only short-lived lifecycle diagnostic; no request/device writes. */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-declarations"
#include "vmlinux.h"
#pragma clang diagnostic pop
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "request_lifecycle.h"

struct life_key { __u64 address,generation; };
struct life_state { __u64 id,ordinal; };
struct {
    __uint(type,BPF_MAP_TYPE_HASH);__uint(max_entries,LIFE_KEYS);
    __type(key,struct life_key);__type(value,struct life_state);
} identities SEC(".maps");
struct {
    __uint(type,BPF_MAP_TYPE_ARRAY);__uint(max_entries,1);
    __type(key,__u32);__type(value,struct life_config);
} bc_life_cfg SEC(".maps");
struct {
    __uint(type,BPF_MAP_TYPE_ARRAY);__uint(max_entries,LIFE_STATS);
    __type(key,__u32);__type(value,__u64);
} counters SEC(".maps");
struct {
    __uint(type,BPF_MAP_TYPE_ARRAY);__uint(max_entries,1);
    __type(key,__u32);__type(value,__u64);
} sequence SEC(".maps");
struct {
    __uint(type,BPF_MAP_TYPE_RINGBUF);__uint(max_entries,4*1024*1024);
} events SEC(".maps");

static __always_inline void inc(__u32 index) {
    __u64 *value=bpf_map_lookup_elem(&counters,&index);
    if(value)__sync_fetch_and_add(value,1);
}
static __always_inline int observe(struct request *rq,__u32 stage,__u32 done,__u32 status) {
    __u32 zero=0;struct life_config *cfg=bpf_map_lookup_elem(&bc_life_cfg,&zero);
    if(!cfg || !cfg->enabled)return 0;
    if(BPF_CORE_READ(rq,q,disk,major)!=cfg->major || BPF_CORE_READ(rq,q,disk,first_minor)!=cfg->minor)return 0;
    inc(0);
    struct life_key key={.address=(__u64)rq,.generation=BPF_CORE_READ(rq,start_time_ns)};
    if(!key.generation){inc(3);return 0;}
    struct life_state *state=bpf_map_lookup_elem(&identities,&key);
    if(!state) {
        __u64 *next=bpf_map_lookup_elem(&sequence,&zero);
        if(!next){inc(2);return 0;}
        struct life_state initial={.id=__sync_fetch_and_add(next,1)+1};
        bpf_map_update_elem(&identities,&key,&initial,BPF_NOEXIST);
        state=bpf_map_lookup_elem(&identities,&key);
        if(!state){inc(2);return 0;}
    }
    struct life_event event={.id=state->id,.ordinal=__sync_fetch_and_add(&state->ordinal,1)+1,
        .time_ns=bpf_ktime_get_ns(),.stage=stage,.completed_bytes=done,.status=status};
    event.cmd_flags=BPF_CORE_READ(rq,cmd_flags);event.operation=event.cmd_flags&255;
    event.rq_flags=BPF_CORE_READ(rq,rq_flags);event.data_bytes=BPF_CORE_READ(rq,__data_len);
    event.bio_present=BPF_CORE_READ(rq,bio)!=0;event.flush_seq=BPF_CORE_READ(rq,flush.seq);
    event.internal_flush=rq==BPF_CORE_READ(rq,mq_hctx,fq,flush_rq);
    if(bpf_ringbuf_output(&events,&event,sizeof(event),0))inc(1);
    return 0;
}
SEC("raw_tp/block_rq_insert")
int inserted(struct bpf_raw_tracepoint_args *ctx){return observe((void *)ctx->args[0],LIFE_INSERT,0,0);}
SEC("raw_tp/block_rq_issue")
int issued(struct bpf_raw_tracepoint_args *ctx){return observe((void *)ctx->args[0],LIFE_ISSUE,0,0);}
SEC("raw_tp/block_rq_requeue")
int requeued(struct bpf_raw_tracepoint_args *ctx){return observe((void *)ctx->args[0],LIFE_REQUEUE,0,0);}
SEC("raw_tp/block_rq_complete")
int completed(struct bpf_raw_tracepoint_args *ctx){return observe((void *)ctx->args[0],LIFE_COMPLETE,ctx->args[2],ctx->args[1]);}
SEC("fentry/blk_insert_flush")
int BPF_PROG(flush_enter,struct request *rq){return observe(rq,LIFE_FLUSH_ENTER,0,0);}
SEC("fexit/blk_insert_flush")
int BPF_PROG(flush_return,struct request *rq,bool consumed){return observe(rq,LIFE_FLUSH_RETURN,0,consumed);}
char LICENSE[] SEC("license")="GPL";
