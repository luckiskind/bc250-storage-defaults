/* Extend the frozen read diagnostic; its two sleep programs are not loaded.
 * All task/folio/wait addresses remain private and unpinned.
 */
#include "read_lineage.bpf.c"
enum bc_fw_stage { FW_MATCH_BEGIN=13,FW_MATCH_RETURN,FW_SWITCH_OUT,FW_SWITCH_IN,FW_WAKING,FW_WAKEUP };
struct bc_fw_call { struct line_context c; __u64 owner,wait_address; __u32 flags; int bit; };
struct { __uint(type,BPF_MAP_TYPE_HASH);__uint(max_entries,LINE_KEYS);__type(key,__u64);__type(value,struct line_context); } fw_slots SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_HASH);__uint(max_entries,LINE_KEYS);__type(key,__u64);__type(value,struct bc_fw_call); } fw_calls SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_ARRAY);__uint(max_entries,16);__type(key,__u32);__type(value,__u64); } fw_counters SEC(".maps");
static __always_inline void fw_inc(__u32 n){__u64 *v=bpf_map_lookup_elem(&fw_counters,&n);if(v)__sync_fetch_and_add(v,1);}
static __always_inline void fw_emit(struct line_context *c,__u32 stage,__s64 result,__u32 flags,__u64 time){
    struct line_event e={.id=c->id,.parent=c->parent,.time_ns=time,.value=c->value,.aux=c->aux,.result=result,.stage=stage,.flags=flags};
    inc(0);if(bpf_ringbuf_output(&events,&e,sizeof(e),0))inc(1);
}
SEC("fentry/io_schedule") int BPF_PROG(fw_sleep_enter){
    if(!enabled())return 0;__u64 thread=bpf_get_current_pid_tgid();struct line_context *d=bpf_map_lookup_elem(&demands,&thread);if(!d)return 0;
    __u64 time=bpf_ktime_get_ns(),task=(__u64)bpf_get_current_task_btf();struct line_context c={.id=next_id(),.parent=d->id};
    if(bpf_map_update_elem(&sleeps,&thread,&c,BPF_NOEXIST)){inc(3);return 0;}
    if(bpf_map_update_elem(&fw_slots,&task,&c,BPF_NOEXIST)){fw_inc(1);bpf_map_delete_elem(&sleeps,&thread);return 0;}
    fw_emit(&c,IO_SLEEP_BEGIN,0,0,time);return 0;
}
SEC("fexit/io_schedule") int BPF_PROG(fw_sleep_exit){
    if(!enabled())return 0;__u64 thread=bpf_get_current_pid_tgid(),task=(__u64)bpf_get_current_task_btf();
    struct line_context *c=bpf_map_lookup_elem(&sleeps,&thread);if(!c)return 0;struct line_context *slot=bpf_map_lookup_elem(&fw_slots,&task);
    if(!slot || slot->id!=c->id)fw_inc(2);
    fw_emit(c,IO_SLEEP_END,0,0,bpf_ktime_get_ns());bpf_map_delete_elem(&fw_slots,&task);bpf_map_delete_elem(&sleeps,&thread);return 0;
}
SEC("fentry/wake_page_function") int BPF_PROG(fw_match_enter,struct wait_queue_entry *wait,unsigned int mode,int sync,void *arg){
    (void)mode;(void)sync;if(!enabled())return 0;
    __u64 owner=(__u64)BPF_CORE_READ(wait,private);struct line_context *slot=bpf_map_lookup_elem(&fw_slots,&owner);if(!slot)return 0;
    struct wait_page_queue *queued=(void *)((char *)wait-bpf_core_field_offset(struct wait_page_queue,wait));
    struct wait_page_key *key=arg;struct folio *folio=BPF_CORE_READ(queued,folio);int bit=BPF_CORE_READ(queued,bit_nr);
    if(!folio || folio!=BPF_CORE_READ(key,folio) || bit!=BPF_CORE_READ(key,bit_nr) || bit!=PG_locked){fw_inc(5);return 0;}
    struct address_space *mapping=BPF_CORE_READ(folio,mapping);
    if(!mapping || ((__u64)mapping&3) || !selected_inode(BPF_CORE_READ(mapping,host))){fw_inc(5);return 0;}
    __u32 z=0;struct line_config *cfg=bpf_map_lookup_elem(&line_cfg,&z);if(!cfg || cfg->pad){fw_inc(6);return 0;}
    __u64 thread=bpf_get_current_pid_tgid(),index=BPF_CORE_READ(folio,index);struct line_context *bio=bpf_map_lookup_elem(&endings,&thread);
    /* Proof bits: exact queued folio/bit, selected inode, actual wait task,
     * and selected folio start inside the current original-bio range.
     * Large/partial folios outside this narrow range proof remain unresolved.
     */
    __u32 proof=0x70000;__u64 bio_id=0;
    if(bio && index<=(~0ULL>>12)){
        __u64 offset=index<<12;if(offset>=bio->aux && offset-bio->aux<bio->value){bio_id=bio->id;proof|=0x80000;}
    }
    struct bc_fw_call call={.c={.id=next_id(),.parent=slot->id,.value=bio_id,.aux=index},.owner=owner,.wait_address=(__u64)wait,
        .flags=BPF_CORE_READ(wait,flags)|proof,.bit=bit};
    if(bpf_map_update_elem(&fw_calls,&thread,&call,BPF_NOEXIST)){fw_inc(3);return 0;}
    fw_emit(&call.c,FW_MATCH_BEGIN,bit,call.flags,bpf_ktime_get_ns());return 0;
}
SEC("fexit/wake_page_function") int BPF_PROG(fw_match_exit,struct wait_queue_entry *wait,unsigned int mode,int sync,void *arg,int ret){
    (void)mode;(void)sync;(void)arg;if(!enabled())return 0;__u64 thread=bpf_get_current_pid_tgid();struct bc_fw_call *call=bpf_map_lookup_elem(&fw_calls,&thread);
    /* The queue entry may already be freed. Compare its value only. */
    if(!call || call->wait_address!=(__u64)wait)return 0;
    fw_emit(&call->c,FW_MATCH_RETURN,ret,call->flags,bpf_ktime_get_ns());bpf_map_delete_elem(&fw_calls,&thread);return 0;
}
static __always_inline int fw_switch(struct task_struct *task,__u32 stage,__u64 state,__u64 preempt){
    __u64 key=(__u64)task;struct line_context *slot=bpf_map_lookup_elem(&fw_slots,&key);if(!slot)return 0;
    struct line_context c={.id=next_id(),.parent=slot->id,.value=state,.aux=preempt};fw_emit(&c,stage,0,0,bpf_ktime_get_ns());return 0;
}
SEC("raw_tp/sched_switch") int fw_sched_switch(struct bpf_raw_tracepoint_args *ctx){
    if(!enabled())return 0;fw_switch((void *)ctx->args[1],FW_SWITCH_OUT,ctx->args[3],!!ctx->args[0]);
    return fw_switch((void *)ctx->args[2],FW_SWITCH_IN,0,0);
}
static __always_inline int fw_wake(struct task_struct *task,__u32 stage){
    __u64 owner=(__u64)task;struct line_context *slot=bpf_map_lookup_elem(&fw_slots,&owner);if(!slot)return 0;
    __u64 thread=bpf_get_current_pid_tgid();struct bc_fw_call *call=bpf_map_lookup_elem(&fw_calls,&thread);
    struct line_context c={.id=next_id(),.parent=slot->id,.value=call && call->owner==owner && call->c.parent==slot->id?call->c.id:0};
    fw_emit(&c,stage,0,0,bpf_ktime_get_ns());return 0;
}
SEC("raw_tp/sched_waking") int fw_sched_waking(struct bpf_raw_tracepoint_args *ctx){if(!enabled())return 0;return fw_wake((void *)ctx->args[0],FW_WAKING);}
SEC("raw_tp/sched_wakeup") int fw_sched_wakeup(struct bpf_raw_tracepoint_args *ctx){if(!enabled())return 0;return fw_wake((void *)ctx->args[0],FW_WAKEUP);}
