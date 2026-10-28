#define _POSIX_C_SOURCE 200809L
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include "read_lineage.h"
#define PROGRAMS 16
static volatile sig_atomic_t stopped;
static struct line_event *saved;
static unsigned count,limit,malformed,discarded;
static void stop(int sig){(void)sig;stopped=1;}
static uint64_t now(void){struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))exit(2);return (uint64_t)t.tv_sec*1000000000+t.tv_nsec;}
static int consume(void *ctx,void *data,size_t size){
    (void)ctx;if(size!=sizeof(*saved)){malformed++;return 0;}
    if(count>=limit){discarded++;stopped=1;return 0;}saved[count++]=*(struct line_event *)data;return 0;
}
static long number(const char *value,long low,long high){char *end;errno=0;long n=strtol(value,&end,10);return errno || *end || n<low || n>high?-1:n;}
int main(int argc,char **argv){
    _Static_assert(sizeof(struct line_event)==56,"wire size");
    if(argc!=6 || geteuid()!=0)return 2;
    long pid=number(argv[2],2,4194304),fd=number(argv[3],0,4095),duration=number(argv[4],1,15),maximum=number(argv[5],1,50000);
    if(pid<0 || fd<0 || duration<0 || maximum<0)return 2;
    char path[80];snprintf(path,sizeof(path),"/proc/%ld/fd/%ld",pid,fd);struct stat info;
    if(stat(path,&info) || !S_ISREG(info.st_mode))return 2;
    limit=maximum;saved=calloc(limit,sizeof(*saved));if(!saved)return 2;
    struct line_config cfg={.pid=pid,.fd=fd};struct bpf_object *object=NULL;
    struct bpf_link *links[PROGRAMS]={};struct ring_buffer *ring=NULL;uint32_t ids[PROGRAMS]={},zero=0;
    int status=1,cfgfd=-1;object=bpf_object__open_file(argv[1],NULL);if(libbpf_get_error(object)){object=NULL;goto cleanup;}
    if(bpf_object__load(object))goto cleanup;
    cfgfd=bpf_object__find_map_fd_by_name(object,"line_cfg");int eventfd=bpf_object__find_map_fd_by_name(object,"events"),statsfd=bpf_object__find_map_fd_by_name(object,"counters");
    if(cfgfd<0 || eventfd<0 || statsfd<0 || bpf_map_update_elem(cfgfd,&zero,&cfg,BPF_ANY))goto cleanup;
    ring=ring_buffer__new(eventfd,consume,NULL,NULL);if(!ring)goto cleanup;
    const char *names[]={"data_exit","decomp_exit","sleep_exit","read_exit","fault_exit","map_exit","data_enter","decomp_enter","sleep_enter","compressed_done","compressed_enter","bio_enter","read_enter","fault_enter","map_enter","unlock_call"};
    for(unsigned i=0;i<PROGRAMS;i++){
        struct bpf_program *p=bpf_object__find_program_by_name(object,names[i]);if(!p)goto cleanup;
        links[i]=bpf_program__attach_trace(p);if(libbpf_get_error(links[i])){links[i]=NULL;goto cleanup;}
        struct bpf_prog_info pi={};uint32_t size=sizeof(pi);if(bpf_obj_get_info_by_fd(bpf_program__fd(p),&pi,&size))goto cleanup;ids[i]=pi.id;
    }
    struct sigaction action={.sa_handler=stop};sigemptyset(&action.sa_mask);sigaction(SIGINT,&action,NULL);sigaction(SIGTERM,&action,NULL);
    uint64_t start=now();cfg.enabled=1;if(bpf_map_update_elem(cfgfd,&zero,&cfg,BPF_ANY))goto cleanup;
    fprintf(stderr,"BC250_READ_LINEAGE_READY {\"program_ids\":[");for(unsigned i=0;i<PROGRAMS;i++)fprintf(stderr,"%s%u",i?",":"",ids[i]);fprintf(stderr,"]}\n");fflush(stderr);
    while(!stopped && now()-start<(uint64_t)duration*1000000000){int r=ring_buffer__poll(ring,25);if(r<0 && r!=-EINTR)goto cleanup;}
    cfg.enabled=0;if(bpf_map_update_elem(cfgfd,&zero,&cfg,BPF_ANY))goto cleanup;uint64_t finish=now();
    for(unsigned i=0;i<PROGRAMS;i++){bpf_link__destroy(links[i]);links[i]=NULL;}uint64_t detached=now();
    int drained;while((drained=ring_buffer__consume(ring))>0){}if(drained<0)goto cleanup;
    uint64_t stats[LINE_STATS]={};for(uint32_t i=0;i<LINE_STATS;i++)if(bpf_map_lookup_elem(statsfd,&i,&stats[i]))goto cleanup;
    const char *maps[]={"demands","bios","decompressors","endings","sleeps"};unsigned pending[5]={};
    for(unsigned i=0;i<5;i++){
        int m=bpf_object__find_map_fd_by_name(object,maps[i]);uint64_t key=0,next=0;if(m<0)goto cleanup;
        int r=bpf_map_get_next_key(m,NULL,&key);
        while(!r){if(++pending[i]>LINE_KEYS)goto cleanup;r=bpf_map_get_next_key(m,&key,&next);key=next;}
        if(errno!=ENOENT)goto cleanup;
    }
    printf("{\"schema_version\":1,\"kind\":\"bc250-read-lineage-diagnostic\",\"libbpf\":\"%s\",\"start_ns\":%" PRIu64 ",\"finish_ns\":%" PRIu64 ",\"detached_ns\":%" PRIu64 ",\"events\":%u,\"malformed\":%u,\"discarded\":%u,\"interrupted\":%s,\"limit_reached\":%s,\"counters\":[",libbpf_version_string(),start,finish,detached,count,malformed,discarded,stopped?"true":"false",count>=limit?"true":"false");
    for(unsigned i=0;i<LINE_STATS;i++){printf("%s%" PRIu64,i?",":"",stats[i]);}printf("],\"pending_contexts\":[");
    for(unsigned i=0;i<5;i++){printf("%s%u",i?",":"",pending[i]);}printf("],\"records\":[");
    for(unsigned i=0;i<count;i++){
        struct line_event *e=&saved[i];printf("%s{\"id\":%llu,\"parent\":%llu,\"time_ns\":%llu,\"value\":%llu,\"aux\":%llu,\"result\":%lld,\"stage\":%u,\"flags\":%u}",i?",":"",e->id,e->parent,e->time_ns,e->value,e->aux,e->result,e->stage,e->flags);
    }
    printf("],\"links_detached\":true,\"maps_pinned\":false,\"critical_path_attribution_qualified\":false,\"overhead_qualified\":false}\n");status=0;
cleanup:
    if(cfgfd>=0){cfg.enabled=0;bpf_map_update_elem(cfgfd,&zero,&cfg,BPF_ANY);}
    for(unsigned i=0;i<PROGRAMS;i++){bpf_link__destroy(links[i]);}ring_buffer__free(ring);bpf_object__close(object);free(saved);return status;
}
