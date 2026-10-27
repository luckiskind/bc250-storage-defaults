/* Temporary libbpf loader. Closing links detaches; nothing is pinned. */
#define _POSIX_C_SOURCE 200809L
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <time.h>
#include <unistd.h>
#include "request_trace.h"

static volatile sig_atomic_t stopped;
static volatile sig_atomic_t signal_seen;
static struct bc250_event *saved;
static size_t count,limit;
static uint64_t qualified,read_bytes,write_bytes,flagged,malformed,limit_discarded;
static uint64_t service_hist[64],queue_hist[64],service_ns,queue_ns;
static void stop(int signum) {signal_seen=signum;stopped=1;}
static uint64_t now_ns(void) {
    struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))exit(2);
    return (uint64_t)t.tv_sec*1000000000+t.tv_nsec;
}
static unsigned bucket(uint64_t n) {return n ? 63-__builtin_clzll(n) : 0;}
static int consume(void *ctx,void *data,size_t bytes) {
    (void)ctx;
    if(bytes!=sizeof(struct bc250_event)) {malformed++;return 0;}
    const struct bc250_event *e=data;
    if(count>=limit) {limit_discarded++;stopped=1;return 0;}
    if(saved)saved[count]=*e;
    count++;
    if(e->operation==0)read_bytes+=e->completed_bytes;
    if(e->operation==1)write_bytes+=e->completed_bytes;
    if(e->flags || !e->insert_ns || e->bytes!=e->completed_bytes || e->complete_ns<e->issue_ns || e->issue_ns<e->insert_ns) {
        flagged++;return 0;
    }
    qualified++;
    uint64_t service=e->complete_ns-e->issue_ns,queue=e->issue_ns-e->insert_ns;
    service_ns+=service;queue_ns+=queue;service_hist[bucket(service)]++;queue_hist[bucket(queue)]++;
    return 0;
}
static void histogram(const uint64_t *values) {
    putchar('[');for(unsigned i=0;i<64;i++)printf("%s%" PRIu64,i?",":"",values[i]);putchar(']');
}
int main(int argc,char **argv) {
    if(argc!=6 || geteuid()!=0) {
        fprintf(stderr,"Usage (root): request-trace OBJECT BLOCK_DEVICE SECONDS MAX_EVENTS SAVE_EVENTS_0_OR_1\n");return 2;
    }
    char *end;errno=0;long duration=strtol(argv[3],&end,10);
    if(errno || *end || duration<1 || duration>60)return 2;
    errno=0;long max=strtol(argv[4],&end,10);
    if(errno || *end || max<1 || max>200000)return 2;
    if(strcmp(argv[5],"0") && strcmp(argv[5],"1"))return 2;
    limit=max;
    if(!strcmp(argv[5],"1")) {saved=calloc(limit,sizeof(*saved));if(!saved)return 2;}
    struct stat s;if(stat(argv[2],&s) || !S_ISBLK(s.st_mode))return 2;
    struct trace_config cfg={.major=major(s.st_rdev),.minor=minor(s.st_rdev)};
    struct bpf_object *object=NULL;struct bpf_link *links[4]={};struct ring_buffer *ring=NULL;
    int status=1,cfgfd=-1;uint32_t zero=0;
    object=bpf_object__open_file(argv[1],NULL);
    if(libbpf_get_error(object)) {object=NULL;goto cleanup;}
    if(bpf_object__load(object))goto cleanup;
    cfgfd=bpf_object__find_map_fd_by_name(object,"bc250_config");
    int statsfd=bpf_object__find_map_fd_by_name(object,"counters");
    int pendingfd=bpf_object__find_map_fd_by_name(object,"pending");
    int eventfd=bpf_object__find_map_fd_by_name(object,"events");
    if(cfgfd<0 || statsfd<0 || pendingfd<0 || eventfd<0)goto cleanup;
    if(bpf_map_update_elem(cfgfd,&zero,&cfg,BPF_ANY))goto cleanup;
    ring=ring_buffer__new(eventfd,consume,NULL,NULL);if(!ring)goto cleanup;
    const char *programs[]={"completed","requeued","inserted","issued"};
    const char *targets[]={"block_rq_complete","block_rq_requeue","block_rq_insert","block_rq_issue"};
    uint32_t ids[4]={};
    for(unsigned i=0;i<4;i++) {
        struct bpf_program *program=bpf_object__find_program_by_name(object,programs[i]);
        if(!program)goto cleanup;
        links[i]=bpf_program__attach_raw_tracepoint(program,targets[i]);
        if(libbpf_get_error(links[i])) {links[i]=NULL;goto cleanup;}
        struct bpf_prog_info info={};uint32_t bytes=sizeof(info);
        if(bpf_obj_get_info_by_fd(bpf_program__fd(program),&info,&bytes))goto cleanup;
        ids[i]=info.id;
    }
    struct sigaction action={.sa_handler=stop};sigemptyset(&action.sa_mask);
    sigaction(SIGINT,&action,NULL);sigaction(SIGTERM,&action,NULL);
    uint64_t start=now_ns();cfg.enabled=1;
    if(bpf_map_update_elem(cfgfd,&zero,&cfg,BPF_ANY))goto cleanup;
    fprintf(stderr,"BC250_TRACE_READY {\"program_ids\":[%u,%u,%u,%u]}\n",ids[0],ids[1],ids[2],ids[3]);fflush(stderr);
    while(!stopped && now_ns()-start<(uint64_t)duration*1000000000) {
        int result=ring_buffer__poll(ring,50);
        if(result<0 && result!=-EINTR)goto cleanup;
    }
    cfg.enabled=0;if(bpf_map_update_elem(cfgfd,&zero,&cfg,BPF_ANY))goto cleanup;
    uint64_t finish=now_ns();
    for(unsigned i=0;i<4;i++) {bpf_link__destroy(links[i]);links[i]=NULL;}
    uint64_t detached=now_ns();
    while(ring_buffer__consume(ring)>0){}
    uint64_t stats[TRACE_STAT_COUNT]={};
    for(uint32_t i=0;i<TRACE_STAT_COUNT;i++)if(bpf_map_lookup_elem(statsfd,&i,&stats[i]))goto cleanup;
    struct {uint64_t address,generation;} key,next;bool have=false;unsigned inflight=0;
    while(!bpf_map_get_next_key(pendingfd,have?&key:NULL,&next)) {
        key=next;have=true;if(++inflight>TRACE_MAP_LIMIT)goto cleanup;
    }
    printf("{\"schema_version\":%d,\"kind\":\"bc250-request-trace\",\"libbpf\":\"%s\",",TRACE_SCHEMA,libbpf_version_string());
    printf("\"elapsed_ns\":%" PRIu64 ",\"start_monotonic_ns\":%" PRIu64 ",\"events\":%zu,\"qualified_full_requests\":%" PRIu64 ",",finish-start,start,count,qualified);
    printf("\"detached_monotonic_ns\":%" PRIu64 ",\"interrupted\":%s,\"limit_discarded_records\":%" PRIu64 ",",detached,signal_seen?"true":"false",limit_discarded);
    printf("\"read_completed_bytes\":%" PRIu64 ",\"write_completed_bytes\":%" PRIu64 ",\"flagged_events\":%" PRIu64 ",\"malformed_events\":%" PRIu64 ",",read_bytes,write_bytes,flagged,malformed);
    printf("\"service_sum_ns\":%" PRIu64 ",\"queue_sum_ns\":%" PRIu64 ",\"right_censored_requests\":%u,\"event_limit_reached\":%s,",service_ns,queue_ns,inflight,count>=limit?"true":"false");
    printf("\"kernel_counters\":[");for(unsigned i=0;i<TRACE_STAT_COUNT;i++)printf("%s%" PRIu64,i?",":"",stats[i]);printf("],\"service_log2_ns\":");histogram(service_hist);
    printf(",\"queue_log2_ns\":");histogram(queue_hist);printf(",\"records\":[");
    if(saved)for(size_t i=0;i<count;i++) {
        struct bc250_event *e=&saved[i];
        printf("%s{\"id\":%llu,\"insert_ns\":%llu,\"issue_ns\":%llu,\"complete_ns\":%llu,\"bytes\":%u,\"completed_bytes\":%u,\"operation\":%u,\"flags\":%u}",
            i?",":"",e->sequence,e->insert_ns,e->issue_ns,e->complete_ns,e->bytes,e->completed_bytes,e->operation,e->flags);
    }
    printf("],\"links_detached\":true,\"maps_pinned\":false,\"foreground_owner_known\":false}\n");
    status=0;
cleanup:
    if(cfgfd>=0) {cfg.enabled=0;bpf_map_update_elem(cfgfd,&zero,&cfg,BPF_ANY);}
    for(unsigned i=0;i<4;i++)bpf_link__destroy(links[i]);
    ring_buffer__free(ring);bpf_object__close(object);free(saved);return status;
}
