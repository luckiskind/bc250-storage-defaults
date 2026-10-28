/* Private diagnostic: actual inherited-file identity, asynchronous Btrfs lineage.
 * Addresses, task IDs and file descriptors stay in temporary kernel maps only.
 */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-declarations"
#include "vmlinux.h"
#pragma clang diagnostic pop
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "read_lineage.h"
struct line_context { __u64 id,parent,value,aux; __u32 kind; };
#define HASH(name) struct { __uint(type,BPF_MAP_TYPE_HASH);__uint(max_entries,LINE_KEYS);__type(key,__u64);__type(value,struct line_context); } name SEC(".maps")
HASH(demands);HASH(bios);HASH(decompressors);HASH(endings);HASH(sleeps);
struct { __uint(type,BPF_MAP_TYPE_ARRAY);__uint(max_entries,1);__type(key,__u32);__type(value,struct line_config); } line_cfg SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_ARRAY);__uint(max_entries,LINE_STATS);__type(key,__u32);__type(value,__u64); } counters SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_ARRAY);__uint(max_entries,2);__type(key,__u32);__type(value,__u64); } private_state SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_RINGBUF);__uint(max_entries,4*1024*1024); } events SEC(".maps");
static __always_inline void inc(__u32 n){__u64 *v=bpf_map_lookup_elem(&counters,&n);if(v)__sync_fetch_and_add(v,1);}
static __always_inline __u64 next_id(void){__u32 z=0;__u64 *v=bpf_map_lookup_elem(&private_state,&z);return v?__sync_fetch_and_add(v,1)+1:0;}
static __always_inline bool enabled(void){__u32 z=0;struct line_config *c=bpf_map_lookup_elem(&line_cfg,&z);return c && c->enabled;}
static __always_inline bool selected_inode(struct inode *inode){__u32 one=1;__u64 *v=bpf_map_lookup_elem(&private_state,&one);return v && *v && *v==(__u64)inode;}
static __always_inline bool selected_bio(struct btrfs_bio *bbio){
    struct btrfs_inode *inode=BPF_CORE_READ(bbio,inode);
    return inode && selected_inode((void *)((char *)inode+bpf_core_field_offset(struct btrfs_inode,vfs_inode)));
}
static __always_inline void emit(struct line_context *c,__u32 stage,__s64 result,__u32 flags){
    struct line_event e={.id=c->id,.parent=c->parent,.time_ns=bpf_ktime_get_ns(),.value=c->value,.aux=c->aux,.result=result,.stage=stage,.flags=flags};
    inc(0);if(bpf_ringbuf_output(&events,&e,sizeof(e),0))inc(1);
}
static __always_inline bool owned_file(struct file *file){
    __u32 z=0;struct line_config *c=bpf_map_lookup_elem(&line_cfg,&z);
    if(!c || !c->enabled || bpf_get_current_pid_tgid()>>32!=c->pid)return false;
    struct task_struct *task=bpf_get_current_task_btf();struct files_struct *files=BPF_CORE_READ(task,files);
    struct fdtable *fdt=BPF_CORE_READ(files,fdt);__u32 count=BPF_CORE_READ(fdt,max_fds);
    if(c->fd>=count || c->fd>=4096){inc(7);return false;}
    struct file **table=BPF_CORE_READ(fdt,fd),*wanted=0;
    if(bpf_probe_read_kernel(&wanted,sizeof(wanted),table+c->fd) || !file || file!=wanted){inc(7);return false;}
    struct inode *inode=BPF_CORE_READ(file,f_inode);__u32 one=1;__u64 *target=bpf_map_lookup_elem(&private_state,&one);
    if(!inode || !target){inc(2);return false;}
    __u64 previous=__sync_val_compare_and_swap(target,0,(__u64)inode);
    if(previous && previous!=(__u64)inode){inc(7);return false;}
    return true;
}
static __always_inline int demand_enter(struct file *file,__u32 kind,__u64 value){
    if(!owned_file(file))return 0;
    __u64 key=bpf_get_current_pid_tgid();struct line_context c={.id=next_id(),.kind=kind,.value=value};
    if(bpf_map_update_elem(&demands,&key,&c,BPF_NOEXIST)){inc(3);return 0;}
    emit(&c,DEMAND_BEGIN,kind,0);return 0;
}
static __always_inline int demand_exit(__u32 kind,__s64 ret){
    if(!enabled())return 0;
    __u64 key=bpf_get_current_pid_tgid();struct line_context *c=bpf_map_lookup_elem(&demands,&key);
    if(!c)return 0;
    if(c->kind!=kind){inc(3);return 0;}emit(c,DEMAND_END,ret,kind);bpf_map_delete_elem(&demands,&key);return 0;
}
SEC("fentry/filemap_read") int BPF_PROG(read_enter,struct kiocb *iocb,struct iov_iter *iter,long already){(void)already;return demand_enter(BPF_CORE_READ(iocb,ki_filp),1,BPF_CORE_READ(iter,count));}
SEC("fexit/filemap_read") int BPF_PROG(read_exit,struct kiocb *iocb,struct iov_iter *iter,long already,long ret){(void)iocb;(void)iter;(void)already;return demand_exit(1,ret);}
SEC("fentry/filemap_fault") int BPF_PROG(fault_enter,struct vm_fault *vmf){return demand_enter(BPF_CORE_READ(vmf,vma,vm_file),2,BPF_CORE_READ(vmf,pgoff));}
SEC("fexit/filemap_fault") int BPF_PROG(fault_exit,struct vm_fault *vmf,unsigned int ret){(void)vmf;return demand_exit(2,ret);}
SEC("fentry/filemap_map_pages") int BPF_PROG(map_enter,struct vm_fault *vmf,unsigned long start,unsigned long end){(void)end;return demand_enter(BPF_CORE_READ(vmf,vma,vm_file),3,start);}
SEC("fexit/filemap_map_pages") int BPF_PROG(map_exit,struct vm_fault *vmf,unsigned long start,unsigned long end,unsigned int ret){(void)vmf;(void)start;(void)end;return demand_exit(3,ret);}
SEC("fentry/submit_one_bio") int BPF_PROG(bio_enter,struct btrfs_bio_ctrl *ctrl){
    if(!enabled())return 0;struct btrfs_bio *bbio=BPF_CORE_READ(ctrl,bbio);
    if(!bbio || !selected_bio(bbio) || (BPF_CORE_READ(bbio,bio.bi_opf)&255)!=0)return 0;
    __u64 key=(__u64)bbio,task=bpf_get_current_pid_tgid();struct line_context *d=bpf_map_lookup_elem(&demands,&task);
    struct line_context c={.id=next_id(),.parent=d?d->id:0,.value=BPF_CORE_READ(bbio,bio.bi_iter.bi_size),.aux=BPF_CORE_READ(bbio,file_offset)};
    if(bpf_map_update_elem(&bios,&key,&c,BPF_NOEXIST)){inc(6);return 0;}emit(&c,BIO_SUBMIT,0,0);return 0;
}
static __always_inline struct line_context *tracked(struct btrfs_bio *bbio){
    __u64 key=(__u64)bbio;struct line_context *c=bpf_map_lookup_elem(&bios,&key);
    if(!c && selected_bio(bbio))inc(5);return c;
}
SEC("fentry/btrfs_submit_compressed_read") int BPF_PROG(compressed_enter,struct btrfs_bio *bbio){
    if(!enabled())return 0;struct line_context *c=tracked(bbio);if(c)emit(c,COMPRESSED_SUBMIT,0,0);return 0;
}
SEC("fentry/end_bbio_compressed_read") int BPF_PROG(compressed_done,struct btrfs_bio *bbio){
    if(!enabled() || !selected_bio(bbio))return 0;
    struct compressed_bio *cb=(void *)((char *)bbio-bpf_core_field_offset(struct compressed_bio,bbio));
    struct line_context *c=tracked(BPF_CORE_READ(cb,orig_bbio));if(c)emit(c,COMPRESSED_DEVICE_DONE,BPF_CORE_READ(bbio,bio.bi_status),0);return 0;
}
SEC("fentry/zstd_decompress_bio") int BPF_PROG(decomp_enter,struct list_head *ws,struct compressed_bio *cb){
    (void)ws;if(!enabled())return 0;struct btrfs_bio *orig=BPF_CORE_READ(cb,orig_bbio);
    if(!selected_bio(orig))return 0;struct line_context *bio=tracked(orig);if(!bio)return 0;
    __u64 key=bpf_get_current_pid_tgid();struct line_context c={.id=next_id(),.parent=bio->id,.value=BPF_CORE_READ(cb,len),.aux=BPF_CORE_READ(cb,start)};
    if(bpf_map_update_elem(&decompressors,&key,&c,BPF_NOEXIST)){inc(3);return 0;}emit(&c,DECOMP_BEGIN,0,0);return 0;
}
SEC("fexit/zstd_decompress_bio") int BPF_PROG(decomp_exit,struct list_head *ws,struct compressed_bio *cb,int ret){
    (void)ws;(void)cb;if(!enabled())return 0;__u64 key=bpf_get_current_pid_tgid();struct line_context *c=bpf_map_lookup_elem(&decompressors,&key);
    if(c){emit(c,DECOMP_END,ret,0);bpf_map_delete_elem(&decompressors,&key);}return 0;
}
SEC("fentry/end_bbio_data_read") int BPF_PROG(data_enter,struct btrfs_bio *bbio){
    if(!enabled() || !selected_bio(bbio))return 0;__u64 key=(__u64)bbio,task=bpf_get_current_pid_tgid();struct line_context *c=tracked(bbio);
    if(!c)return 0;if(bpf_map_update_elem(&endings,&task,c,BPF_NOEXIST)){inc(3);return 0;}
    emit(c,DATA_END_BEGIN,BPF_CORE_READ(bbio,bio.bi_status),0);bpf_map_delete_elem(&bios,&key);return 0;
}
SEC("fexit/end_bbio_data_read") int BPF_PROG(data_exit,struct btrfs_bio *bbio){
    (void)bbio;if(!enabled())return 0;__u64 key=bpf_get_current_pid_tgid();struct line_context *c=bpf_map_lookup_elem(&endings,&key);
    if(c){emit(c,DATA_END_RETURN,0,0);bpf_map_delete_elem(&endings,&key);}return 0;
}
SEC("fentry/io_schedule") int BPF_PROG(sleep_enter){
    if(!enabled())return 0;__u64 key=bpf_get_current_pid_tgid();struct line_context *d=bpf_map_lookup_elem(&demands,&key);if(!d)return 0;
    struct line_context c={.id=next_id(),.parent=d->id};if(bpf_map_update_elem(&sleeps,&key,&c,BPF_NOEXIST)){inc(3);return 0;}emit(&c,IO_SLEEP_BEGIN,0,0);return 0;
}
SEC("fexit/io_schedule") int BPF_PROG(sleep_exit){
    if(!enabled())return 0;__u64 key=bpf_get_current_pid_tgid();struct line_context *c=bpf_map_lookup_elem(&sleeps,&key);
    if(c){emit(c,IO_SLEEP_END,0,0);bpf_map_delete_elem(&sleeps,&key);}return 0;
}
SEC("fentry/folio_unlock") int BPF_PROG(unlock_call,struct folio *folio){
    if(!enabled())return 0;struct address_space *mapping=BPF_CORE_READ(folio,mapping);
    if(!mapping || ((__u64)mapping&3) || !selected_inode(BPF_CORE_READ(mapping,host)))return 0;
    __u64 key=bpf_get_current_pid_tgid();struct line_context *bio=bpf_map_lookup_elem(&endings,&key);
    struct line_context c={.id=next_id(),.parent=bio?bio->id:0,.value=BPF_CORE_READ(folio,index)};
    emit(&c,FOLIO_UNLOCK_CALL,0,0);return 0;
}
char LICENSE[] SEC("license")="GPL";
