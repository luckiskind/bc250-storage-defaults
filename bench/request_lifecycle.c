/* Separate diagnostic wire format. All output is buffered until detachment. */
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
#include "request_lifecycle.h"

static volatile sig_atomic_t stopped;
static struct life_event *saved;
static unsigned count,limit,malformed,discarded;
static void stop(int sig){(void)sig;stopped=1;}
static uint64_t now_ns(void){struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))exit(2);return (uint64_t)t.tv_sec*1000000000+t.tv_nsec;}
static int consume(void *ctx,void *data,size_t size){
    (void)ctx;
    if(size!=sizeof(*saved)){malformed++;return 0;}
    if(count>=limit){discarded++;stopped=1;return 0;}
    saved[count++]=*(const struct life_event *)data;return 0;
}
int main(int argc,char **argv){
    if(argc!=5 || geteuid()!=0)return 2;
    char *end;errno=0;long duration=strtol(argv[3],&end,10);
    if(errno || *end || duration<1 || duration>15)return 2;
    errno=0;long maximum=strtol(argv[4],&end,10);
    if(errno || *end || maximum<1 || maximum>50000)return 2;
    limit=maximum;saved=calloc(limit,sizeof(*saved));if(!saved)return 2;
    struct stat s;if(stat(argv[2],&s) || !S_ISBLK(s.st_mode)){free(saved);return 2;}
    struct life_config cfg={.major=major(s.st_rdev),.minor=minor(s.st_rdev)};
    struct bpf_object *object=NULL;struct bpf_link *links[6]={};struct ring_buffer *ring=NULL;
    int status=1,cfgfd=-1;uint32_t zero=0,ids[6]={};
    object=bpf_object__open_file(argv[1],NULL);
    if(libbpf_get_error(object)){object=NULL;goto cleanup;}
    if(bpf_object__load(object))goto cleanup;
    cfgfd=bpf_object__find_map_fd_by_name(object,"bc_life_cfg");
    int statsfd=bpf_object__find_map_fd_by_name(object,"counters"),eventfd=bpf_object__find_map_fd_by_name(object,"events");
    if(cfgfd<0 || statsfd<0 || eventfd<0)goto cleanup;
    if(bpf_map_update_elem(cfgfd,&zero,&cfg,BPF_ANY))goto cleanup;
    ring=ring_buffer__new(eventfd,consume,NULL,NULL);if(!ring)goto cleanup;
    const char *names[]={"completed","requeued","inserted","issued","flush_enter","flush_return"};
    const char *targets[]={"block_rq_complete","block_rq_requeue","block_rq_insert","block_rq_issue"};
    for(unsigned i=0;i<6;i++){
        struct bpf_program *p=bpf_object__find_program_by_name(object,names[i]);if(!p)goto cleanup;
        links[i]=i<4?bpf_program__attach_raw_tracepoint(p,targets[i]):bpf_program__attach_trace(p);
        if(libbpf_get_error(links[i])){links[i]=NULL;goto cleanup;}
        struct bpf_prog_info info={};uint32_t size=sizeof(info);
        if(bpf_obj_get_info_by_fd(bpf_program__fd(p),&info,&size))goto cleanup;
        ids[i]=info.id;
    }
    struct sigaction action={.sa_handler=stop};sigemptyset(&action.sa_mask);sigaction(SIGINT,&action,NULL);sigaction(SIGTERM,&action,NULL);
    uint64_t start=now_ns();cfg.enabled=1;if(bpf_map_update_elem(cfgfd,&zero,&cfg,BPF_ANY))goto cleanup;
    fprintf(stderr,"BC250_LIFECYCLE_READY {\"program_ids\":[%u,%u,%u,%u,%u,%u]}\n",ids[0],ids[1],ids[2],ids[3],ids[4],ids[5]);fflush(stderr);
    while(!stopped && now_ns()-start<(uint64_t)duration*1000000000){int result=ring_buffer__poll(ring,25);if(result<0 && result!=-EINTR)goto cleanup;}
    cfg.enabled=0;if(bpf_map_update_elem(cfgfd,&zero,&cfg,BPF_ANY))goto cleanup;
    uint64_t finish=now_ns();for(unsigned i=0;i<6;i++){bpf_link__destroy(links[i]);links[i]=NULL;}
    uint64_t detached=now_ns();
    int drained;while((drained=ring_buffer__consume(ring))>0){}if(drained<0)goto cleanup;
    uint64_t stats[LIFE_STATS]={};for(uint32_t i=0;i<LIFE_STATS;i++)if(bpf_map_lookup_elem(statsfd,&i,&stats[i]))goto cleanup;
    printf("{\"schema_version\":1,\"kind\":\"bc250-request-lifecycle-diagnostic\",\"start_ns\":%" PRIu64 ",\"finish_ns\":%" PRIu64 ",\"events\":%u,\"malformed\":%u,\"discarded\":%u,\"interrupted\":%s,\"limit_reached\":%s,\"counters\":[",start,finish,count,malformed,discarded,stopped?"true":"false",count>=limit?"true":"false");
    for(unsigned i=0;i<LIFE_STATS;i++)printf("%s%" PRIu64,i?",":"",stats[i]);
    printf("],\"detached_ns\":%" PRIu64 ",\"records\":[",detached);
    for(unsigned i=0;i<count;i++){
        struct life_event *e=&saved[i];
        printf("%s{\"id\":%llu,\"ordinal\":%llu,\"time_ns\":%llu,\"stage\":%u,\"operation\":%u,\"data_bytes\":%u,\"completed_bytes\":%u,\"status\":%u,\"rq_flags\":%u,\"cmd_flags\":%u,\"internal_flush\":%u,\"flush_seq\":%u,\"bio_present\":%u}",i?",":"",e->id,e->ordinal,e->time_ns,e->stage,e->operation,e->data_bytes,e->completed_bytes,e->status,e->rq_flags,e->cmd_flags,e->internal_flush,e->flush_seq,e->bio_present);
    }
    printf("],\"links_detached\":true,\"maps_pinned\":false,\"performance_result\":false}\n");status=0;
cleanup:
    if(cfgfd>=0){cfg.enabled=0;bpf_map_update_elem(cfgfd,&zero,&cfg,BPF_ANY);}
    for(unsigned i=0;i<6;i++)bpf_link__destroy(links[i]);
    ring_buffer__free(ring);bpf_object__close(object);free(saved);return status;
}
