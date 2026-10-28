/* Separate opt-in witness: actual try_to_wake_up plus its waking trace. */
#include "handoff_wait.bpf.c"
struct tw_call {struct line_context c;__u64 owner;__u32 mask,flags;};
struct {__uint(type,BPF_MAP_TYPE_HASH);__uint(max_entries,LINE_KEYS);__type(key,__u64);__type(value,struct tw_call);} tw_calls SEC(".maps");
struct {__uint(type,BPF_MAP_TYPE_ARRAY);__uint(max_entries,16);__type(key,__u32);__type(value,__u64);} tw_counters SEC(".maps");
struct {__uint(type,BPF_MAP_TYPE_ARRAY);__uint(max_entries,1);__type(key,__u32);__type(value,__u32);} tw_cfg SEC(".maps");
static __always_inline void tw_inc(__u32 key){__u64 *p=bpf_map_lookup_elem(&tw_counters,&key);if(p)__sync_fetch_and_add(p,1);}
static __always_inline bool tw_enabled(void){__u32 z=0,*p=bpf_map_lookup_elem(&tw_cfg,&z);return p && *p;}
/* The two fields are separate reads, not an atomic joint snapshot. */
static __always_inline __u64 tw_state(struct task_struct *p){return (__u64)BPF_CORE_READ(p,on_cpu)|((__u64)BPF_CORE_READ(p,on_rq)<<8);}
SEC("fentry/try_to_wake_up") int BPF_PROG(tw_enter,struct task_struct *p,unsigned int state,int wake_flags){
    __u64 entry=bpf_ktime_get_ns();if(!enabled() || !tw_enabled())return 0;
    __u64 thread=bpf_get_current_pid_tgid(),owner=(__u64)p;
    struct bc_fw_call *wake=bpf_map_lookup_elem(&fw_calls,&thread);struct line_context *slot=bpf_map_lookup_elem(&fw_slots,&owner);
    if(!wake || !slot || wake->owner!=owner || wake->c.parent!=slot->id)return 0;
    struct tw_call call={.c={.id=next_id(),.parent=slot->id,.value=wake->c.id,.aux=tw_state(p)},.owner=owner,.mask=state,.flags=wake_flags};
    if(bpf_map_update_elem(&tw_calls,&thread,&call,BPF_NOEXIST)){tw_inc(3);return 0;}
    tw_inc(0);fw_emit(&call.c,31,state,wake_flags,entry);return 0;
}
SEC("raw_tp/sched_waking") int tw_waking(struct bpf_raw_tracepoint_args *ctx){
    __u64 entry=bpf_ktime_get_ns();if(!enabled() || !tw_enabled())return 0;
    __u64 thread=bpf_get_current_pid_tgid();struct tw_call *call=bpf_map_lookup_elem(&tw_calls,&thread);
    if(!call || call->owner!=ctx->args[0])return 0;
    struct line_context c=call->c;c.aux=tw_state((void *)ctx->args[0]);
    __u64 snapshot_done=bpf_ktime_get_ns();tw_inc(2);fw_emit(&c,33,snapshot_done,0,entry);return 0;
}
SEC("fexit/try_to_wake_up") int BPF_PROG(tw_exit,struct task_struct *p,unsigned int state,int wake_flags,int ret){
    (void)state;(void)wake_flags;__u64 entry=bpf_ktime_get_ns();if(!enabled() || !tw_enabled())return 0;
    __u64 thread=bpf_get_current_pid_tgid();struct tw_call *call=bpf_map_lookup_elem(&tw_calls,&thread);
    if(!call || call->owner!=(__u64)p)return 0;
    /* Task pointer comparison only; no task dereference after the call. */
    tw_inc(1);fw_emit(&call->c,32,ret,call->flags,entry);bpf_map_delete_elem(&tw_calls,&thread);return 0;
}
