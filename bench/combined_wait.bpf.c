/* Opt-in combined diagnostic. All addresses/generations remain private. */
#include "request_bio_lineage.bpf.c"
#include "folio_vector_math.h"
struct cv_origin { __u64 id,address,vectors;__u32 first,done,count; };
struct cv_options { __u32 vector,folio; };
struct { __uint(type,BPF_MAP_TYPE_HASH);__uint(max_entries,LINE_KEYS);__type(key,__u64);__type(value,struct cv_origin); } cv_bookmarks SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_HASH);__uint(max_entries,LINE_KEYS);__type(key,__u64);__type(value,struct cv_origin); } cv_origins SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_ARRAY);__uint(max_entries,1);__type(key,__u32);__type(value,struct cv_options); } cv_cfg SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_ARRAY);__uint(max_entries,16);__type(key,__u32);__type(value,__u64); } cv_counters SEC(".maps");
static __always_inline void cv_add(__u32 n,__u64 amount){__u64 *v=bpf_map_lookup_elem(&cv_counters,&n);if(v)__sync_fetch_and_add(v,amount);}
static __always_inline bool cv_folio_enabled(void){__u32 z=0;struct cv_options *c=bpf_map_lookup_elem(&cv_cfg,&z);return c && c->folio;}
SEC("fentry/submit_one_bio") int BPF_PROG(cv_bio_enter,struct btrfs_bio_ctrl *ctrl){
    if(!enabled())return 0;struct btrfs_bio *bbio=BPF_CORE_READ(ctrl,bbio);
    if(!bbio || !selected_bio(bbio) || (BPF_CORE_READ(bbio,bio.bi_opf)&255)!=0)return 0;
    __u64 key=(__u64)bbio,task=bpf_get_current_pid_tgid();struct line_context *d=bpf_map_lookup_elem(&demands,&task);
    struct line_context c={.id=next_id(),.parent=d?d->id:0,.value=BPF_CORE_READ(bbio,bio.bi_iter.bi_size),.aux=BPF_CORE_READ(bbio,file_offset)};
    if(bpf_map_update_elem(&bios,&key,&c,BPF_NOEXIST)){inc(6);return 0;}
    struct cv_origin origin={.id=c.id,.address=key,.vectors=(__u64)BPF_CORE_READ(bbio,bio.bi_io_vec),.first=BPF_CORE_READ(bbio,bio.bi_iter.bi_idx),
        .done=BPF_CORE_READ(bbio,bio.bi_iter.bi_bvec_done),.count=BPF_CORE_READ(bbio,bio.bi_vcnt)};
    if(bpf_map_update_elem(&cv_bookmarks,&key,&origin,BPF_NOEXIST))cv_add(5,1);emit(&c,BIO_SUBMIT,0,0);return 0;
}
SEC("fentry/end_bbio_data_read") int BPF_PROG(cv_data_enter,struct btrfs_bio *bbio){
    if(!enabled() || !selected_bio(bbio))return 0;__u64 key=(__u64)bbio,task=bpf_get_current_pid_tgid();struct line_context *c=tracked(bbio);
    if(!c)return 0;if(bpf_map_update_elem(&endings,&task,c,BPF_NOEXIST)){inc(3);return 0;}
    struct cv_origin *origin=bpf_map_lookup_elem(&cv_bookmarks,&key);
    if(!origin || origin->id!=c->id || origin->address!=key)cv_add(5,1);
    else if(bpf_map_update_elem(&cv_origins,&task,origin,BPF_NOEXIST))cv_add(5,1);
    if(bpf_map_delete_elem(&cv_bookmarks,&key))cv_add(13,1);
    emit(c,DATA_END_BEGIN,BPF_CORE_READ(bbio,bio.bi_status),0);bpf_map_delete_elem(&bios,&key);return 0;
}
SEC("fexit/end_bbio_data_read") int BPF_PROG(cv_data_exit,struct btrfs_bio *bbio){
    (void)bbio;if(!enabled())return 0;__u64 task=bpf_get_current_pid_tgid();struct line_context *c=bpf_map_lookup_elem(&endings,&task);
    if(c){emit(c,DATA_END_RETURN,0,0);bpf_map_delete_elem(&endings,&task);if(bpf_map_delete_elem(&cv_origins,&task))cv_add(13,1);}return 0;
}
struct cv_scan { struct fv_input input;struct fv_output output;__u64 vectors;__u32 first,done,seen,found,error; };
/* A global subprogram is verified independently. Inlining the geometry into
 * every loop callback state exceeded the verifier complexity limit. The
 * identical pure helper remains covered by the independent native oracle. */
__noinline int cv_geometry(struct fv_input *input,struct fv_output *output){if(!input || !output)return -1;return fv_overlap(input,output);}
static long cv_scan_one(__u32 index,void *data){
    struct cv_scan *c=data;if(c->input.logical_cursor>=c->input.original_bytes)return 1;struct bio_vec vector={};
    __u64 address=c->vectors+((__u64)c->first+index)*sizeof(vector);c->seen++;
    if(bpf_probe_read_kernel(&vector,sizeof(vector),(void *)address)){c->error=4;return 1;}
    __u64 skip=index?0:c->done;if(!vector.bv_page || !vector.bv_len || skip>=vector.bv_len){c->error=4;return 1;}
    c->input.page=(__u64)vector.bv_page;c->input.vector_offset=(__u64)vector.bv_offset+skip;c->input.vector_bytes=vector.bv_len-skip;
    int r=cv_geometry(&c->input,&c->output);if(r<0){c->error=4;return 1;}if(r){c->found=1;return 1;}
    if(c->input.logical_cursor>~0ULL-c->input.vector_bytes){c->error=4;return 1;}c->input.logical_cursor+=c->input.vector_bytes;return 0;
}
static __noinline bool cv_vector_edge(struct folio *folio,__u64 wake_id,__u64 original_id){
    cv_add(0,1);__u32 z=0;struct cv_options *cfg=bpf_map_lookup_elem(&cv_cfg,&z);if(!cfg || !cfg->vector){cv_add(7,1);return false;}
    __u64 task=bpf_get_current_pid_tgid();struct cv_origin *saved=bpf_map_lookup_elem(&cv_origins,&task);struct line_context *original=bpf_map_lookup_elem(&endings,&task);
    if(!saved || !original || !original_id || saved->id!=original_id || original->id!=original_id){cv_add(5,1);return false;}
    struct cv_origin origin=*saved;struct btrfs_bio *bbio=(void *)origin.address;__u32 count=BPF_CORE_READ(bbio,bio.bi_vcnt);
    __u64 vector_address=(__u64)BPF_CORE_READ(bbio,bio.bi_io_vec),flags=BPF_CORE_READ(folio,flags.f),index=BPF_CORE_READ(folio,index);
    __u64 pages=(flags&(1ULL<<PG_head))?BPF_CORE_READ(folio,_nr_pages):1;
    if(bpf_core_type_size(struct page)!=64 || bpf_core_type_size(struct bio_vec)!=16 || (BPF_CORE_READ(folio,page.compound_info)&1)
       || !origin.vectors || vector_address!=origin.vectors || !origin.count || count<origin.count || count>256 || origin.first>=origin.count
       || !pages || pages>(1ULL<<20) || (pages&(pages-1))){cv_add(2,1);return false;}
    struct cv_scan scan={.input={.folio=(__u64)folio,.folio_index=index,.folio_pages=pages,.original_offset=original->aux,.original_bytes=original->value},
        .vectors=origin.vectors,.first=origin.first,.done=origin.done};
    if(bpf_loop(count-origin.first,cv_scan_one,&scan,0)<0 || scan.error){cv_add(4,1);return false;}cv_add(8,scan.seen);
    if(!scan.found){cv_add(3,1);return false;}
    __u64 after_flags=BPF_CORE_READ(folio,flags.f),after_pages=(after_flags&(1ULL<<PG_head))?BPF_CORE_READ(folio,_nr_pages):1;
    struct address_space *mapping=BPF_CORE_READ(folio,mapping);
    if(((flags^after_flags)&(1ULL<<PG_head)) || after_pages!=pages || BPF_CORE_READ(folio,index)!=index || !mapping || ((__u64)mapping&3)
        || !selected_inode(BPF_CORE_READ(mapping,host)) || (BPF_CORE_READ(folio,page.compound_info)&1)
        || (unsigned long long)BPF_CORE_READ(bbio,bio.bi_io_vec)!=origin.vectors || BPF_CORE_READ(bbio,bio.bi_vcnt)!=count){cv_add(6,1);return false;}
    cv_add(1,1);if(scan.output.flags&1)cv_add(10,1);if(scan.output.flags&2)cv_add(9,1);if(scan.output.flags&4)cv_add(11,1);if(origin.first || origin.done)cv_add(12,1);
    struct line_context e={.id=wake_id,.parent=original_id,.value=scan.output.original_byte,.aux=scan.output.bytes};
    emit(&e,30,(pages<<32)|scan.output.folio_byte,scan.output.flags);return true;
}
#include "combined_folio.generated.h"
