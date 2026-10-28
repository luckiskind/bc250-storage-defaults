/* Separate lifecycle-aware observer. No device/request writes or BPF pins. */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-declarations"
#include "vmlinux.h"
#pragma clang diagnostic pop
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "request_trace_v2.h"
#include "trace2_protocol.h"

struct v2_key { __u64 address,generation; };
struct v2_return_key { __u64 address,task; };
struct v2_state {
    struct v2_event event;
    struct trace2_phase phase;
    __u64 completion_claimed;
    __u32 software,consumed;
};
struct {__uint(type,BPF_MAP_TYPE_HASH);__uint(max_entries,V2_KEYS);__type(key,struct v2_key);__type(value,struct v2_state);} pending SEC(".maps");
struct {__uint(type,BPF_MAP_TYPE_HASH);__uint(max_entries,V2_KEYS);__type(key,struct v2_return_key);__type(value,__u64);} returns SEC(".maps");
struct {__uint(type,BPF_MAP_TYPE_ARRAY);__uint(max_entries,1);__type(key,__u32);__type(value,struct v2_config);} bc_v2_cfg SEC(".maps");
struct {__uint(type,BPF_MAP_TYPE_ARRAY);__uint(max_entries,V2_STATS);__type(key,__u32);__type(value,__u64);} counters SEC(".maps");
struct {__uint(type,BPF_MAP_TYPE_ARRAY);__uint(max_entries,1);__type(key,__u32);__type(value,__u64);} sequence SEC(".maps");
struct {__uint(type,BPF_MAP_TYPE_RINGBUF);__uint(max_entries,4*1024*1024);} events SEC(".maps");
static __always_inline void inc(__u32 name){__u64 *p=bpf_map_lookup_elem(&counters,&name);if(p)__sync_fetch_and_add(p,1);}
static __always_inline struct v2_config *configuration(void){__u32 zero=0;return bpf_map_lookup_elem(&bc_v2_cfg,&zero);}
static __always_inline bool identify(struct request *rq,struct v2_key *key){
    struct v2_config *cfg=configuration();if(!cfg || !cfg->enabled)return false;
    struct gendisk *disk=BPF_CORE_READ(rq,q,disk);
    if(BPF_CORE_READ(disk,major)!=cfg->major || BPF_CORE_READ(disk,first_minor)!=cfg->minor)return false;
    key->address=(__u64)rq;key->generation=BPF_CORE_READ(rq,start_time_ns);
    if(!key->generation){inc(V_ZERO_GEN);return false;}return true;
}
static __always_inline __u64 next_id(void){__u32 zero=0;__u64 *p=bpf_map_lookup_elem(&sequence,&zero);return p?__sync_fetch_and_add(p,1)+1:0;}
static __always_inline struct v2_state *create(struct v2_key *key,__u64 inserted){
    struct v2_state state={};state.event.insert_ns=inserted;
    if(bpf_map_update_elem(&pending,key,&state,BPF_NOEXIST)){inc(V_MAP_FAIL);return 0;}
    return bpf_map_lookup_elem(&pending,key);
}
static __always_inline void emit(struct v2_key *key,struct v2_event *event){
    if(bpf_map_delete_elem(&pending,key)){inc(V_DELETE_RACE);return;}
    inc(V_FINAL);if(event->event_class==V_DEVICE_FLUSH)inc(V_INTERNAL_FINAL);
    if(bpf_ringbuf_output(&events,event,sizeof(*event),0))inc(V_RING_LOST);
}
static __always_inline void finish_software(struct v2_key *key,struct v2_state *state,__u64 bit){
    int close=trace2_ready(&state->phase,bit);
    if(close<0){inc(V_SW_ANOMALY);return;}if(!close)return;
    struct v2_event event=state->event;
    event.event_class=state->consumed?V_SOFTWARE_FLUSH:V_UNKNOWN_SEQUENCE;
    event.evidence=V_ENTERED|V_COMPLETED|(state->consumed?V_CONSUMED_TRUE:V_CONSUMED_FALSE);
    event.flags|=V_NO_INSERT|V_ZERO;
    if(!state->consumed)event.flags|=V_CONTRADICTION;
    if(event.enter_ns>event.return_ns || event.enter_ns>event.complete_ns){event.flags|=V_TIME;inc(V_BAD_TIME);}
    inc(V_SW_FINAL);emit(key,&event);
}
SEC("raw_tp/block_rq_insert")
int inserted(struct bpf_raw_tracepoint_args *ctx){
    struct request *rq=(void *)ctx->args[0];struct v2_key key={};if(!identify(rq,&key))return 0;inc(V_INSERT);
    struct v2_state *state=bpf_map_lookup_elem(&pending,&key);
    if(state){state->event.flags|=V_REPEAT;if(state->software){state->event.flags|=V_CONTRADICTION;inc(V_SW_ANOMALY);}inc(V_REPEAT_INSERT);}
    else create(&key,bpf_ktime_get_ns());return 0;
}
SEC("raw_tp/block_rq_issue")
int issued(struct bpf_raw_tracepoint_args *ctx){
    struct request *rq=(void *)ctx->args[0];struct v2_key key={};if(!identify(rq,&key))return 0;inc(V_ISSUE);
    struct v2_state *state=bpf_map_lookup_elem(&pending,&key);if(!state)state=create(&key,0);if(!state)return 0;
    if(state->software){state->event.flags|=V_CONTRADICTION;inc(V_SW_ANOMALY);return 0;}
    if(state->event.issue_ns){state->event.flags|=V_DUP;inc(V_DUP_ISSUE);return 0;}
    state->event.sequence=next_id();state->event.issue_ns=bpf_ktime_get_ns();
    state->event.bytes=BPF_CORE_READ(rq,__data_len);state->event.operation=BPF_CORE_READ(rq,cmd_flags)&255;
    if(!state->event.insert_ns)state->event.flags|=V_NO_INSERT;if(!state->event.bytes)state->event.flags|=V_ZERO;
    struct v2_config *cfg=configuration();
    if(cfg && cfg->internal && state->event.operation==2 && !state->event.bytes && !BPF_CORE_READ(rq,bio)
        && rq==BPF_CORE_READ(rq,mq_hctx,fq,flush_rq)){
        state->event.event_class=V_DEVICE_FLUSH;state->event.evidence=V_INTERNAL;
    }
    return 0;
}
SEC("raw_tp/block_rq_requeue")
int requeued(struct bpf_raw_tracepoint_args *ctx){
    struct v2_key key={};if(!identify((void *)ctx->args[0],&key))return 0;inc(V_REQUEUE);
    struct v2_state *state=bpf_map_lookup_elem(&pending,&key);if(state)state->event.flags|=V_REQUEUED;else inc(V_ORPHAN_REQUEUE);return 0;
}
SEC("raw_tp/block_rq_complete")
int completed(struct bpf_raw_tracepoint_args *ctx){
    struct request *rq=(void *)ctx->args[0];struct v2_key key={};if(!identify(rq,&key))return 0;
    struct v2_state *state=bpf_map_lookup_elem(&pending,&key);if(!state){inc(V_ORPHAN);return 0;}
    if(state->software){
        if(__sync_fetch_and_or(&state->completion_claimed,1)){inc(V_SW_ANOMALY);return 0;}
        state->event.complete_ns=bpf_ktime_get_ns();state->event.completed_bytes=ctx->args[2];state->event.status=ctx->args[1];
        if(ctx->args[1])state->event.flags|=V_ERROR;
        if(ctx->args[2] || BPF_CORE_READ(rq,__data_len) || (BPF_CORE_READ(rq,cmd_flags)&255)!=state->event.operation){state->event.flags|=V_CONTRADICTION;inc(V_SW_ANOMALY);}
        inc(V_SW_COMPLETE);finish_software(&key,state,2);return 0;
    }
    if(!state->event.issue_ns){inc(V_NO_ISSUE);bpf_map_delete_elem(&pending,&key);return 0;}
    __u32 done=__sync_fetch_and_add(&state->event.completed_bytes,(__u32)ctx->args[2])+(__u32)ctx->args[2];
    if(ctx->args[1]){state->event.flags|=V_ERROR;state->event.status=ctx->args[1];}
    if(done<state->event.bytes){state->event.flags|=V_PART;inc(V_PARTIAL);return 0;}
    if(done>state->event.bytes){state->event.flags|=V_OVER;inc(V_OVERSHOOT);}
    struct v2_event event=state->event;event.complete_ns=bpf_ktime_get_ns();if(event.event_class==V_DEVICE_FLUSH)event.evidence|=V_COMPLETED;
    if(event.complete_ns<event.issue_ns || (event.insert_ns && event.issue_ns<event.insert_ns)){event.flags|=V_TIME;inc(V_BAD_TIME);}
    emit(&key,&event);return 0;
}
SEC("fentry/blk_insert_flush")
int BPF_PROG(flush_enter,struct request *rq){
    struct v2_config *cfg=configuration();if(!cfg || !cfg->enabled || !cfg->software)return 0;
    __u32 cmd=BPF_CORE_READ(rq,cmd_flags);if((cmd&255)!=1 || !(cmd&V2_PREFLUSH) || BPF_CORE_READ(rq,__data_len))return 0;
    struct v2_key key={};if(!identify(rq,&key))return 0;
    struct v2_return_key context={.address=(__u64)rq,.task=bpf_get_current_pid_tgid()};
    if(bpf_map_update_elem(&returns,&context,&key.generation,BPF_NOEXIST)){inc(V_CONTEXT_FAIL);return 0;}
    struct v2_state state={.software=1};state.event.enter_ns=bpf_ktime_get_ns();state.event.sequence=next_id();
    state.event.operation=1;state.event.entry_cmd_flags=cmd;
    if(bpf_map_update_elem(&pending,&key,&state,BPF_NOEXIST)){inc(V_MAP_FAIL);bpf_map_delete_elem(&returns,&context);return 0;}
    inc(V_SW_ENTRY);return 0;
}
SEC("fexit/blk_insert_flush")
int BPF_PROG(flush_return,struct request *rq,bool consumed){
    struct v2_config *cfg=configuration();if(!cfg || !cfg->enabled || !cfg->software)return 0;
    /* No request dereference after return: it may already have completed. */
    struct v2_return_key context={.address=(__u64)rq,.task=bpf_get_current_pid_tgid()};
    __u64 *generation=bpf_map_lookup_elem(&returns,&context);if(!generation)return 0;
    struct v2_key key={.address=(__u64)rq,.generation=*generation};
    if(bpf_map_delete_elem(&returns,&context)){inc(V_CONTEXT_FAIL);return 0;}
    struct v2_state *state=bpf_map_lookup_elem(&pending,&key);
    if(!state || !state->software){inc(V_SW_ANOMALY);return 0;}
    state->consumed=consumed;state->event.return_ns=bpf_ktime_get_ns();inc(consumed?V_SW_TRUE:V_SW_FALSE);
    finish_software(&key,state,1);return 0;
}
char LICENSE[] SEC("license")="GPL";
