/* Capability/lifecycle diagnostic only; no request or critical-path claim. */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-declarations"
#include "vmlinux.h"
#pragma clang diagnostic pop
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
struct tc_context {__u64 id,token;__u32 closing;};
struct tc_event {__u64 id,token,time_ns,observed_ns,value,aux;__s64 result;__u32 stage,flags;};
struct tc_config {__u32 pid,enabled,create,control;};
struct {__uint(type,BPF_MAP_TYPE_TASK_STORAGE);__uint(map_flags,BPF_F_NO_PREALLOC);__type(key,int);__type(value,struct tc_context);} tc_slots SEC(".maps");
struct {__uint(type,BPF_MAP_TYPE_HASH);__uint(max_entries,64);__type(key,__u64);__type(value,struct tc_context);} tc_expected SEC(".maps");
struct {__uint(type,BPF_MAP_TYPE_HASH);__uint(max_entries,64);__type(key,__u64);__type(value,__u64);} tc_threads SEC(".maps");
struct {__uint(type,BPF_MAP_TYPE_ARRAY);__uint(max_entries,1);__type(key,__u32);__type(value,struct tc_config);} tc_cfg SEC(".maps");
struct {__uint(type,BPF_MAP_TYPE_ARRAY);__uint(max_entries,16);__type(key,__u32);__type(value,__u64);} tc_stats SEC(".maps");
struct {__uint(type,BPF_MAP_TYPE_ARRAY);__uint(max_entries,2);__type(key,__u32);__type(value,__u64);} tc_seq SEC(".maps");
struct {__uint(type,BPF_MAP_TYPE_RINGBUF);__uint(max_entries,4194304);} tc_events SEC(".maps");
static __always_inline __u64 *stat(__u32 n){return bpf_map_lookup_elem(&tc_stats,&n);}
static __always_inline void inc(__u32 n){__u64 *v=stat(n);if(v)__sync_fetch_and_add(v,1);}
static __always_inline __u64 seq(__u32 n){__u64 *v=bpf_map_lookup_elem(&tc_seq,&n);return v?__sync_fetch_and_add(v,1)+1:0;}
static __always_inline struct tc_config *tc_config_get(void){__u32 z=0;return bpf_map_lookup_elem(&tc_cfg,&z);}
static __always_inline bool selected(struct tc_config *c){return c && c->enabled && bpf_get_current_pid_tgid()>>32==c->pid;}
static __always_inline void emit(struct tc_context *c,__u32 stage,__u64 time,__u64 value,__u64 aux,__s64 ret,__u32 flags){
    struct tc_event e={.id=c->id,.token=c->token,.time_ns=time,.observed_ns=bpf_ktime_get_ns(),.value=value,.aux=aux,.result=ret,.stage=stage,.flags=flags};
    inc(0);if(bpf_ringbuf_output(&tc_events,&e,sizeof(e),0))inc(1);
}
static __always_inline void maximum(__u64 active){
    __u64 *v=stat(10);if(!v)return;
    for(int i=0;i<8;i++){__u64 old=*(volatile __u64 *)v;if(old>=active || __sync_val_compare_and_swap(v,old,active)==old)return;}
    inc(15);
}
static __always_inline int begin(struct tc_config *cfg,__u64 time){
    struct task_struct *task=bpf_get_current_task_btf();__u64 key=(__u64)task,thread=bpf_get_current_pid_tgid();
    if(bpf_map_lookup_elem(&tc_expected,&key)){inc(7);return 0;}
    __u64 *known=bpf_map_lookup_elem(&tc_threads,&thread),token=known?*known:0;
    if(!token){token=seq(1);if(bpf_map_update_elem(&tc_threads,&thread,&token,BPF_NOEXIST)){inc(7);return 0;}inc(9);}
    struct tc_context c={.id=seq(0),.token=token,.closing=1};
    if(bpf_map_update_elem(&tc_expected,&key,&c,BPF_NOEXIST)){inc(7);return 0;}
    struct tc_context *slot=cfg->create?bpf_task_storage_get(&tc_slots,task,&c,BPF_LOCAL_STORAGE_GET_F_CREATE):0;
    bool good=slot && slot->id==c.id && slot->token==c.token && slot->closing==1;
    if(good)inc(4);else if(cfg->create)inc(12);
    if(slot)slot->closing=0;
    struct tc_context *expected=bpf_map_lookup_elem(&tc_expected,&key);if(!expected){inc(7);return 0;}expected->closing=0;c.closing=0;
    __u64 *active=stat(11);if(active)maximum(__sync_add_and_fetch(active,1));
    inc(2);emit(&c,1,time,0,0,0,good);return 0;
}
static __always_inline int end(__u64 time){
    struct task_struct *task=bpf_get_current_task_btf();__u64 key=(__u64)task;
    struct tc_context *expected=bpf_map_lookup_elem(&tc_expected,&key);if(!expected){inc(7);return 0;}
    expected->closing=2;struct tc_context c=*expected;
    struct tc_context *slot=bpf_task_storage_get(&tc_slots,task,0,0);
    bool good=slot && slot->id==c.id && slot->token==c.token;
    if(!good)inc(6);
    if(slot)slot->closing=2;
    int result=bpf_task_storage_delete(&tc_slots,task);if(!result)inc(5);else if(good)inc(13);
    if(bpf_map_delete_elem(&tc_expected,&key))inc(8);
    __u64 *active=stat(11);if(active)__sync_fetch_and_sub(active,1);
    inc(3);emit(&c,2,time,0,0,result,good);return 0;
}
SEC("fentry/io_schedule") int BPF_PROG(tc_enter){__u64 time=bpf_ktime_get_ns();struct tc_config *c=tc_config_get();if(!selected(c) || c->control)return 0;return begin(c,time);}
SEC("fexit/io_schedule") int BPF_PROG(tc_exit){__u64 time=bpf_ktime_get_ns();struct tc_config *c=tc_config_get();if(!selected(c) || c->control)return 0;return end(time);}
static __always_inline int observe(struct task_struct *task,__u32 stage,__u64 time,__u64 value,__u64 aux){
    struct tc_config *cfg=tc_config_get();if(!cfg || !cfg->enabled)return 0;
    struct tc_context *slot=bpf_task_storage_get(&tc_slots,task,0,0);__u64 key=(__u64)task;
    struct tc_context *expected=bpf_map_lookup_elem(&tc_expected,&key);
    if(!expected){if(slot && slot->closing!=2)inc(6);return 0;}if(expected->closing || (slot && slot->closing))return 0;
    if(!slot)slot=bpf_task_storage_get(&tc_slots,task,0,0);
    if(expected->closing || (slot && slot->closing))return 0;
    bool good=slot && slot->id==expected->id && slot->token==expected->token && !slot->closing;
    if(!good)inc(6);struct tc_context c=*expected;emit(&c,stage,time,value,aux,0,good);return 0;
}
SEC("tp_btf/sched_switch") int BPF_PROG(tc_switch,bool preempt,struct task_struct *prev,struct task_struct *next,unsigned int state){
    __u64 time=bpf_ktime_get_ns();observe(prev,3,time,state,preempt);return observe(next,4,time,0,0);
}
SEC("tp_btf/sched_waking") int BPF_PROG(tc_waking,struct task_struct *task){return observe(task,5,bpf_ktime_get_ns(),0,0);}
SEC("tp_btf/sched_wakeup") int BPF_PROG(tc_wakeup,struct task_struct *task){return observe(task,6,bpf_ktime_get_ns(),0,0);}
/* Explicit test-only markers: x86_64 getpgid creates, getsid deletes. */
SEC("tp_btf/sys_enter") int BPF_PROG(tc_control,struct pt_regs *regs,long id){
    (void)regs;__u64 time=bpf_ktime_get_ns();struct tc_config *c=tc_config_get();if(!selected(c) || !c->control)return 0;
    if(id==121)return begin(c,time);if(id==124)return end(time);return 0;
}
char LICENSE[] SEC("license")="GPL";
