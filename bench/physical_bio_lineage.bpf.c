/* Separate physical-bio bridge; the qualified logical observer is unchanged. */
#include "read_lineage.bpf.c"
struct pb_state { struct line_context event; __u64 remaining,offset; __u32 device,kind; };
struct pb_split { struct pb_state parent; __u64 address,bytes; };
struct pb_dev { __u32 major,minor; };
struct { __uint(type,BPF_MAP_TYPE_HASH);__uint(max_entries,LINE_KEYS);__type(key,__u64);__type(value,struct pb_state); } pb_bios SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_HASH);__uint(max_entries,LINE_KEYS);__type(key,__u64);__type(value,struct pb_split); } pb_splits SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_ARRAY);__uint(max_entries,1);__type(key,__u32);__type(value,__u64); } pb_identity SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_ARRAY);__uint(max_entries,1);__type(key,__u32);__type(value,struct pb_dev); } pb_device SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_ARRAY);__uint(max_entries,16);__type(key,__u32);__type(value,__u64); } pb_counters SEC(".maps");
static __always_inline void pb_inc(__u32 n){__u64 *v=bpf_map_lookup_elem(&pb_counters,&n);if(v)__sync_fetch_and_add(v,1);}
/* This hook is active while selection is disabled for the private calibration.
 * Only the target function's own IP is used, never its arguments or a guessed
 * container. The address stays in this unpinned map, never in the wire stream. */
SEC("fentry/end_bbio_compressed_read") int BPF_PROG(pb_witness,struct btrfs_bio *bbio){
    (void)bbio;__u32 z=0;__u64 *v=bpf_map_lookup_elem(&pb_identity,&z),ip=bpf_get_func_ip(ctx);
    if(!v || !ip){pb_inc(1);return 0;}__u64 old=__sync_val_compare_and_swap(v,0,ip);
    if(old && old!=ip)pb_inc(1);pb_inc(0);return 0;
}
SEC("fentry/btrfs_submit_bbio") int BPF_PROG(pb_root,struct btrfs_bio *bbio,int mirror){
    (void)mirror;if(!enabled() || !selected_bio(bbio) || (BPF_CORE_READ(bbio,bio.bi_opf)&255)!=0)return 0;
    __u64 key=(__u64)bbio;struct line_context *orig=bpf_map_lookup_elem(&bios,&key);__u32 kind=0;
    if(!orig){
        __u32 z=0;__u64 *identity=bpf_map_lookup_elem(&pb_identity,&z);struct line_config *cfg=bpf_map_lookup_elem(&line_cfg,&z);
        /* Positive callback identity must precede the compressed container cast. */
        if(!cfg || cfg->pad || !identity || !*identity || (__u64)BPF_CORE_READ(bbio,end_io)!=*identity){pb_inc(2);return 0;}
        struct compressed_bio *cb=(void *)((char *)bbio-bpf_core_field_offset(struct compressed_bio,bbio));
        key=(__u64)BPF_CORE_READ(cb,orig_bbio);orig=bpf_map_lookup_elem(&bios,&key);kind=1;
        if(!orig){pb_inc(2);return 0;}
    }
    __u64 address=(__u64)((char *)bbio+bpf_core_field_offset(struct btrfs_bio,bio));
    struct pb_state s={.event={.id=next_id(),.parent=orig->id,.value=BPF_CORE_READ(bbio,bio.bi_iter.bi_size)},.kind=kind};s.remaining=s.event.value;
    if(!s.remaining || bpf_map_update_elem(&pb_bios,&address,&s,BPF_NOEXIST)){pb_inc(3);return 0;}
    emit(&s.event,13,0,kind);return 0;
}
SEC("fentry/bio_split") int BPF_PROG(pb_split_enter,struct bio *bio,int sectors,unsigned int gfp,struct bio_set *bs){
    (void)gfp;(void)bs;if(!enabled())return 0;__u64 address=(__u64)bio,task=bpf_get_current_pid_tgid();
    struct pb_state *s=bpf_map_lookup_elem(&pb_bios,&address);if(!s)return 0;
    if(sectors<=0 || (__u64)sectors*512>=s->remaining || BPF_CORE_READ(bio,bi_iter.bi_size)!=s->remaining){pb_inc(5);return 0;}
    struct pb_split c={.parent=*s,.address=address,.bytes=(__u64)sectors*512};
    if(bpf_map_update_elem(&pb_splits,&task,&c,BPF_NOEXIST))pb_inc(6);return 0;
}
SEC("fexit/bio_split") int BPF_PROG(pb_split_exit,struct bio *bio,int sectors,unsigned int gfp,struct bio_set *bs,struct bio *ret){
    (void)bio;(void)sectors;(void)gfp;(void)bs;if(!enabled())return 0;__u64 task=bpf_get_current_pid_tgid();struct pb_split *saved=bpf_map_lookup_elem(&pb_splits,&task);if(!saved)return 0;
    struct pb_split c=*saved;bpf_map_delete_elem(&pb_splits,&task);
    if(!ret || (__u64)ret>=(__u64)-4095){pb_inc(5);return 0;}
    struct pb_state *parent=bpf_map_lookup_elem(&pb_bios,&c.address);
    if(!parent || parent->event.id!=c.parent.event.id || parent->remaining!=c.parent.remaining || parent->offset!=c.parent.offset || BPF_CORE_READ(ret,bi_iter.bi_size)!=c.bytes){pb_inc(6);return 0;}
    struct pb_state child={.event={.id=next_id(),.parent=parent->event.id,.value=c.bytes,.aux=parent->offset},.remaining=c.bytes,.offset=parent->offset,.device=parent->device,.kind=parent->kind};
    __u64 address=(__u64)ret;if(bpf_map_update_elem(&pb_bios,&address,&child,BPF_NOEXIST)){pb_inc(3);return 0;}
    parent->remaining-=c.bytes;parent->offset+=c.bytes;
    emit(&child.event,14,c.parent.remaining,child.kind|(child.device?256:0));return 0;
}
SEC("raw_tp/block_bio_queue") int pb_submit(struct bpf_raw_tracepoint_args *ctx){
    if(!enabled())return 0;pb_inc(13);struct bio *bio=(void *)ctx->args[0];__u64 address=(__u64)bio;struct pb_state *s=bpf_map_lookup_elem(&pb_bios,&address);if(!s)return 0;
    __u32 z=0;struct pb_dev *dev=bpf_map_lookup_elem(&pb_device,&z);struct gendisk *disk=BPF_CORE_READ(bio,bi_bdev,bd_disk);
    if(!dev || !disk || BPF_CORE_READ(disk,major)!=dev->major || BPF_CORE_READ(disk,first_minor)!=dev->minor || (BPF_CORE_READ(bio,bi_opf)&255)!=0 || BPF_CORE_READ(bio,bi_iter.bi_size)!=s->remaining){pb_inc(8);return 0;}
    /* Re-submission of a remaining suffix after block-layer splitting is an
     * explicit boundary visit, not another count of physical device bytes. */
    s->device=1;struct line_context e=s->event;e.value=s->remaining;e.aux=s->offset;emit(&e,15,0,s->kind|256);return 0;
}
SEC("raw_tp/block_rq_complete") int pb_complete(struct bpf_raw_tracepoint_args *ctx){
    if(!enabled())return 0;struct request *rq=(void *)ctx->args[0];__u32 z=0;struct pb_dev *dev=bpf_map_lookup_elem(&pb_device,&z);struct gendisk *disk=BPF_CORE_READ(rq,q,disk);
    if(!dev || !disk || BPF_CORE_READ(disk,major)!=dev->major || BPF_CORE_READ(disk,first_minor)!=dev->minor || (BPF_CORE_READ(rq,cmd_flags)&255)!=0)return 0;
    pb_inc(12);struct bio *bio=BPF_CORE_READ(rq,bio);__u64 remaining=ctx->args[2];__u32 status=ctx->args[1];
    /* The request callback precedes bio advancement/freeing. Walk the actual
     * completed prefix, never a PID/sector/time join. The kernel clears each
     * BIO_TRACE_COMPLETION flag here, so raw bio-complete is not a census. */
    for(int i=0;i<64;i++){
        if(!bio || !remaining)break;__u64 address=(__u64)bio,bytes=BPF_CORE_READ(bio,bi_iter.bi_size);struct pb_state *s=bpf_map_lookup_elem(&pb_bios,&address);
        if(!bytes){pb_inc(15);return 0;}
        if(s){
            if(remaining<bytes || bytes!=s->remaining){pb_inc(14);return 0;}
            if(!s->device)pb_inc(9);if(status)pb_inc(10);
            struct line_context e=s->event;e.value=s->remaining;e.aux=s->offset;emit(&e,16,status,s->kind|(s->device?256:0));
            if(bpf_map_delete_elem(&pb_bios,&address))pb_inc(11);
        }
        if(remaining<bytes)return 0;remaining-=bytes;bio=BPF_CORE_READ(bio,bi_next);
    }
    /* Conservatively fail a censored NVMe read prefix even when its unseen
     * suffix cannot yet be classified as selected or unrelated. */
    if(remaining)pb_inc(15);return 0;
}
