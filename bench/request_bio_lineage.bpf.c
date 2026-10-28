/* Separate request-generation extension; frozen physical and v2 sources stay intact. */
#include "physical_bio_lineage.bpf.c"
struct pr_key { __u64 address,generation; };
struct pr_request { __u64 id,total,remaining,busy; __u32 members,selected,issues,issued,status; };
struct pr_member { struct pr_key request; __u64 id,request_id,physical,initial,remaining,offset; __u32 status; };
struct pr_history { __u64 generation,id; };
struct { __uint(type,BPF_MAP_TYPE_HASH);__uint(max_entries,LINE_KEYS);__type(key,struct pr_key);__type(value,struct pr_request); } pr_requests SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_HASH);__uint(max_entries,LINE_KEYS);__type(key,__u64);__type(value,struct pr_member); } pr_members SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_ARRAY);__uint(max_entries,24);__type(key,__u32);__type(value,__u64); } pr_counters SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_HASH);__uint(max_entries,LINE_KEYS);__type(key,__u64);__type(value,struct pr_history); } pr_seen SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_ARRAY);__uint(max_entries,1);__type(key,__u32);__type(value,__u32); } pr_cfg SEC(".maps");
static __always_inline void pr_inc(__u32 n){__u64 *v=bpf_map_lookup_elem(&pr_counters,&n);if(v)__sync_fetch_and_add(v,1);}
static __always_inline bool pr_key_for(struct request *rq,struct pr_key *key){
    if(!enabled())return false;__u32 z=0;struct pb_dev *dev=bpf_map_lookup_elem(&pb_device,&z);struct gendisk *disk=BPF_CORE_READ(rq,q,disk);
    if(!dev || !disk || BPF_CORE_READ(disk,major)!=dev->major || BPF_CORE_READ(disk,first_minor)!=dev->minor || (BPF_CORE_READ(rq,cmd_flags)&255)!=0)return false;
    key->address=(__u64)rq;key->generation=BPF_CORE_READ(rq,start_time_ns);if(!key->generation){pr_inc(8);return false;}return true;
}
static __always_inline bool pr_same(struct pr_key *a,struct pr_key *b){return a->address==b->address && a->generation==b->generation;}
static __always_inline void pr_emit(__u64 id,__u64 parent,__u32 stage,__u64 value,__u64 aux,__s64 status,__u32 flags){
    struct line_context e={.id=id,.parent=parent,.value=value,.aux=aux};emit(&e,stage,status,flags);
}
struct pr_scan { __u64 bio,bytes; __u32 members,selected,error; };
static long pr_scan_one(__u32 index,void *data){
    (void)index;struct pr_scan *c=data;if(!c->bio)return 1;struct bio *bio=(void *)c->bio;__u64 address=c->bio,n=BPF_CORE_READ(bio,bi_iter.bi_size);
    if(!n){c->error=9;return 1;}if(bpf_map_lookup_elem(&pb_bios,&address))c->selected++;c->bytes+=n;c->members++;c->bio=(__u64)BPF_CORE_READ(bio,bi_next);return 0;
}
struct pr_binding { struct pr_key key;__u64 bio,request_id,bytes;__u32 reissue,members,selected,error; };
static long pr_bind_one(__u32 index,void *data){
    (void)index;struct pr_binding *c=data;if(!c->bio)return 1;struct bio *bio=(void *)c->bio;__u64 address=c->bio,n=BPF_CORE_READ(bio,bi_iter.bi_size);
    if(!n){c->error=9;return 1;}
    if(c->reissue){
        struct pr_member *m=bpf_map_lookup_elem(&pr_members,&address);
        if(!m || !pr_same(&m->request,&c->key) || m->request_id!=c->request_id || m->remaining!=n){c->error=11;return 1;}
        if(m->physical)c->selected++;
    }else{
        struct pb_state *p=bpf_map_lookup_elem(&pb_bios,&address);struct pr_member m={.request=c->key,.id=next_id(),.request_id=c->request_id,.initial=n,.remaining=n};
        if(p){if(!p->device || p->remaining!=n){c->error=11;return 1;}m.physical=p->event.id;m.offset=p->offset;c->selected++;pr_inc(3);}
        if(bpf_map_update_elem(&pr_members,&address,&m,BPF_NOEXIST)){c->error=10;return 1;}
        pr_inc(4);pr_emit(m.id,c->request_id,18,m.physical,n,0,m.physical?1:0);
    }
    c->members++;c->bytes+=n;c->bio=(__u64)BPF_CORE_READ(bio,bi_next);return 0;
}
struct pr_completion { struct pr_key key;__u64 bio,request_id,remaining;__u32 status,error; };
static long pr_complete_one(__u32 index,void *data){
    (void)index;struct pr_completion *c=data;if(!c->bio || !c->remaining)return 1;struct bio *bio=(void *)c->bio;__u64 address=c->bio,n=BPF_CORE_READ(bio,bi_iter.bi_size);
    struct pr_member *m=bpf_map_lookup_elem(&pr_members,&address);struct pb_state *p=bpf_map_lookup_elem(&pb_bios,&address);
    if(!n){c->error=9;return 1;}
    if(!c->request_id){if(m)pr_inc(14);if(p)pr_inc(14);if(c->remaining<n){c->remaining=0;return 1;}c->remaining-=n;c->bio=(__u64)BPF_CORE_READ(bio,bi_next);return 0;}
    struct pr_request *r=bpf_map_lookup_elem(&pr_requests,&c->key);
    if(!r || r->id!=c->request_id || !m || !pr_same(&m->request,&c->key) || m->request_id!=r->id || m->remaining!=n || (p?p->event.id:0)!=m->physical){c->error=11;return 1;}
    if(p && (p->remaining!=m->initial || p->offset!=m->offset || !p->device)){c->error=11;return 1;}
    __u64 chunk=c->remaining<n?c->remaining:n;pr_emit(m->id,r->id,21,chunk,m->remaining,c->status,m->physical?1:0);
    if(c->status){m->status=c->status;r->status=c->status;pr_inc(13);}if(chunk<n)pr_inc(6);m->remaining-=chunk;
    if(!m->remaining){
        if(p){struct line_context e=p->event;e.value=p->remaining;e.aux=p->offset;emit(&e,16,m->status,p->kind|256);if(bpf_map_delete_elem(&pb_bios,&address))pr_inc(11);}
        if(bpf_map_delete_elem(&pr_members,&address))pr_inc(11);
    }
    c->remaining-=chunk;if(chunk<n)return 1;c->bio=(__u64)BPF_CORE_READ(bio,bi_next);return 0;
}
SEC("raw_tp/block_rq_issue") int pr_issue(struct bpf_raw_tracepoint_args *ctx){
    struct request *rq=(void *)ctx->args[0];struct pr_key key={};if(!pr_key_for(rq,&key))return 0;
    struct pr_scan scan={.bio=(__u64)BPF_CORE_READ(rq,bio)};
    if(bpf_loop(64,pr_scan_one,&scan,0)<0 || scan.error || scan.bio || scan.members>64 || scan.selected>scan.members){pr_inc(9);return 0;}
    __u64 bytes=scan.bytes;__u32 members=scan.members,selected=scan.selected;struct pr_request *r=bpf_map_lookup_elem(&pr_requests,&key);
    if(!r && !selected)return 0;
    if(!members || bytes!=BPF_CORE_READ(rq,__data_len)){pr_inc(12);return 0;}
    if(r){
        if(__sync_val_compare_and_swap(&r->busy,0,1)){pr_inc(15);return 0;}
        if(r->issued || r->remaining!=bytes){pr_inc(12);r->busy=0;return 0;}
        struct pr_binding binding={.key=key,.bio=(__u64)BPF_CORE_READ(rq,bio),.request_id=r->id,.reissue=1};
        if(bpf_loop(64,pr_bind_one,&binding,0)<0 || binding.error || binding.bio || binding.members!=members || binding.selected!=selected || binding.bytes!=bytes){pr_inc(11);r->busy=0;return 0;}
        r->issued=1;r->issues++;pr_inc(1);pr_emit(r->id,0,20,r->remaining,r->issues,0,0);r->busy=0;return 0;
    }
    __u32 z=0,*proof=bpf_map_lookup_elem(&pr_cfg,&z);if(!proof || !*proof){pr_inc(7);return 0;}
    __u64 prior_id=0;struct pr_history *previous=bpf_map_lookup_elem(&pr_seen,&key.address);
    if(previous){
        if(previous->generation==key.generation){pr_inc(17);return 0;}
        struct pr_key old={.address=key.address,.generation=previous->generation};prior_id=previous->id;
        if(bpf_map_lookup_elem(&pr_requests,&old)){pr_inc(12);return 0;}
    }
    struct pr_request state={.id=next_id(),.total=bytes,.remaining=bytes,.busy=1,.members=members,.selected=selected,.issues=1,.issued=1};
    if(bpf_map_update_elem(&pr_requests,&key,&state,BPF_NOEXIST)){pr_inc(10);return 0;}
    struct pr_history history={.generation=key.generation,.id=state.id};
    if(bpf_map_update_elem(&pr_seen,&key.address,&history,BPF_ANY)){pr_inc(18);return 0;}
    pr_inc(0);pr_inc(1);pr_emit(state.id,0,17,bytes,members,selected,0);
    if(prior_id){pr_inc(16);pr_emit(state.id,prior_id,23,0,0,0,0);}
    struct pr_binding binding={.key=key,.bio=(__u64)BPF_CORE_READ(rq,bio),.request_id=state.id};
    if(bpf_loop(64,pr_bind_one,&binding,0)<0 || binding.error || binding.bio || binding.members!=members || binding.selected!=selected || binding.bytes!=bytes){pr_inc(binding.error?binding.error:11);return 0;}
    r=bpf_map_lookup_elem(&pr_requests,&key);if(!r){pr_inc(11);return 0;}r->busy=0;return 0;
}
SEC("raw_tp/block_rq_requeue") int pr_requeue(struct bpf_raw_tracepoint_args *ctx){
    struct request *rq=(void *)ctx->args[0];struct pr_key key={};if(!pr_key_for(rq,&key))return 0;struct pr_request *r=bpf_map_lookup_elem(&pr_requests,&key);if(!r)return 0;
    if(__sync_val_compare_and_swap(&r->busy,0,1)){pr_inc(15);return 0;}
    if(!r->issued || r->remaining!=BPF_CORE_READ(rq,__data_len)){pr_inc(12);r->busy=0;return 0;}
    r->issued=0;pr_inc(5);pr_emit(r->id,0,19,r->remaining,r->issues,0,0);r->busy=0;return 0;
}
SEC("raw_tp/block_rq_complete") int pr_complete(struct bpf_raw_tracepoint_args *ctx){
    struct request *rq=(void *)ctx->args[0];struct pr_key key={};if(!pr_key_for(rq,&key))return 0;
    struct pr_request *r=bpf_map_lookup_elem(&pr_requests,&key);__u64 remaining=ctx->args[2],reported=remaining;__u32 status=ctx->args[1];bool locked=false;
    if(r){
        if(__sync_val_compare_and_swap(&r->busy,0,1)){pr_inc(15);return 0;}locked=true;
        if(!r->issued || !remaining || remaining>r->remaining || BPF_CORE_READ(rq,__data_len)!=r->remaining){pr_inc(12);goto done;}
    }
    struct pr_completion completion={.key=key,.bio=(__u64)BPF_CORE_READ(rq,bio),.request_id=r?r->id:0,.remaining=remaining,.status=status};
    if(bpf_loop(64,pr_complete_one,&completion,0)<0 || completion.error || completion.remaining){pr_inc(completion.error?completion.error:9);goto done;}
    if(r){r->remaining-=reported;if(!r->remaining){pr_inc(2);pr_emit(r->id,0,22,r->total,r->issues,r->status,0);if(bpf_map_delete_elem(&pr_requests,&key))pr_inc(11);return 0;}}
done:
    if(locked)r->busy=0;return 0;
}
