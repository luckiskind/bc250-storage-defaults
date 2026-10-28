#define _POSIX_C_SOURCE 200809L
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
struct tc_config {uint32_t pid,enabled,create,control;};
struct tc_event {uint64_t id,token,time_ns,observed_ns,value,aux;int64_t result;uint32_t stage,flags;};
static struct tc_event *saved;static unsigned count,limit,discarded,malformed;static volatile sig_atomic_t stopped;
static uint64_t now(void){struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))exit(2);return (uint64_t)t.tv_sec*1000000000+t.tv_nsec;}
static void stop(int sig){(void)sig;stopped=1;}
static long number(const char *s,long low,long high){char *end;errno=0;long n=strtol(s,&end,10);return errno || *end || n<low || n>high?-1:n;}
static int consume(void *ctx,void *data,size_t size){
    (void)ctx;if(size!=sizeof(*saved)){malformed++;return 0;}
    if(count>=limit){discarded++;stopped=1;return 0;}saved[count++]=*(struct tc_event *)data;return 0;
}
static int map_count(int fd,unsigned *out){
    uint64_t key=0,next=0;if(fd<0)return -1;int r=bpf_map_get_next_key(fd,NULL,&key);
    while(!r){if(++*out>64)return -1;r=bpf_map_get_next_key(fd,&key,&next);key=next;}
    return errno==ENOENT?0:-1;
}
int main(int argc,char **argv){
    _Static_assert(sizeof(struct tc_event)==64,"wire size");
    if(argc!=7 || geteuid()!=0)return 2;
    long pid=number(argv[2],2,4194304),create=number(argv[3],0,1),control=number(argv[4],0,1),duration=number(argv[5],1,15),maximum=number(argv[6],1,32768);
    if(pid<0 || create<0 || control<0 || duration<0 || maximum<0)return 2;
    limit=maximum;saved=calloc(limit,sizeof(*saved));if(!saved)return 2;
    struct bpf_object *object=NULL;struct bpf_link *links[6]={};struct ring_buffer *ring=NULL;uint32_t ids[6]={},zero=0;
    struct tc_config cfg={.pid=pid,.create=create,.control=control};int cfgfd=-1,status=1;
    object=bpf_object__open_file(argv[1],NULL);if(libbpf_get_error(object)){object=NULL;goto cleanup;}
    if(bpf_object__load(object))goto cleanup;
    cfgfd=bpf_object__find_map_fd_by_name(object,"tc_cfg");int eventfd=bpf_object__find_map_fd_by_name(object,"tc_events"),statsfd=bpf_object__find_map_fd_by_name(object,"tc_stats");
    if(cfgfd<0 || eventfd<0 || statsfd<0 || bpf_map_update_elem(cfgfd,&zero,&cfg,BPF_ANY))goto cleanup;
    ring=ring_buffer__new(eventfd,consume,NULL,NULL);if(!ring)goto cleanup;
    const char *names[]={"tc_enter","tc_exit","tc_switch","tc_waking","tc_wakeup","tc_control"};
    for(unsigned i=0;i<6;i++){
        struct bpf_program *p=bpf_object__find_program_by_name(object,names[i]);if(!p)goto cleanup;
        links[i]=bpf_program__attach_trace(p);if(libbpf_get_error(links[i])){links[i]=NULL;goto cleanup;}
        struct bpf_prog_info pi={};uint32_t size=sizeof(pi);if(bpf_obj_get_info_by_fd(bpf_program__fd(p),&pi,&size))goto cleanup;ids[i]=pi.id;
    }
    struct sigaction action={.sa_handler=stop};sigemptyset(&action.sa_mask);sigaction(SIGINT,&action,NULL);sigaction(SIGTERM,&action,NULL);
    uint64_t start=now();cfg.enabled=1;if(bpf_map_update_elem(cfgfd,&zero,&cfg,BPF_ANY))goto cleanup;
    fprintf(stderr,"BC250_TASK_CONTEXT_READY {\"program_ids\":[");for(unsigned i=0;i<6;i++)fprintf(stderr,"%s%u",i?",":"",ids[i]);fprintf(stderr,"]}\n");fflush(stderr);
    while(!stopped && count<limit && now()-start<(uint64_t)duration*1000000000){int r=ring_buffer__poll(ring,25);if(r<0 && r!=-EINTR)goto cleanup;}
    cfg.enabled=0;if(bpf_map_update_elem(cfgfd,&zero,&cfg,BPF_ANY))goto cleanup;uint64_t finish=now();
    for(unsigned i=0;i<6;i++){bpf_link__destroy(links[i]);links[i]=NULL;}uint64_t detached=now();
    int drained;while((drained=ring_buffer__consume(ring))>0){}if(drained<0)goto cleanup;
    uint64_t stats[16]={};for(uint32_t i=0;i<16;i++)if(bpf_map_lookup_elem(statsfd,&i,&stats[i]))goto cleanup;
    unsigned pending=0,threads=0;if(map_count(bpf_object__find_map_fd_by_name(object,"tc_expected"),&pending) || map_count(bpf_object__find_map_fd_by_name(object,"tc_threads"),&threads))goto cleanup;
    int slotfd=bpf_object__find_map_fd_by_name(object,"tc_slots");if(slotfd<0)goto cleanup;
    uint32_t opaque_key=0;errno=0;int iteration=bpf_map_get_next_key(slotfd,NULL,&opaque_key),iteration_errno=errno;
    printf("{\"schema_version\":1,\"kind\":\"bc250-task-context-feature\",\"start_ns\":%" PRIu64 ",\"finish_ns\":%" PRIu64 ",\"detached_ns\":%" PRIu64 ",\"events\":%u,\"discarded\":%u,\"malformed\":%u,\"interrupted\":%s,\"limit_reached\":%s,\"creation_enabled\":%s,\"controlled_markers\":%s,\"pending_expected\":%u,\"threads_seen\":%u,\"task_storage_iteration_result\":%d,\"task_storage_iteration_errno\":%d,\"counters\":[",start,finish,detached,count,discarded,malformed,stopped?"true":"false",count>=limit?"true":"false",create?"true":"false",control?"true":"false",pending,threads,iteration,iteration_errno);
    for(unsigned i=0;i<16;i++){printf("%s%" PRIu64,i?",":"",stats[i]);}printf("],\"records\":[");
    for(unsigned i=0;i<count;i++){
        struct tc_event *e=&saved[i];printf("%s{\"id\":%" PRIu64 ",\"token\":%" PRIu64 ",\"time_ns\":%" PRIu64 ",\"observed_ns\":%" PRIu64 ",\"value\":%" PRIu64 ",\"aux\":%" PRIu64 ",\"result\":%" PRId64 ",\"stage\":%u,\"flags\":%u}",i?",":"",e->id,e->token,e->time_ns,e->observed_ns,e->value,e->aux,e->result,e->stage,e->flags);
    }
    printf("],\"links_detached\":true,\"maps_pinned\":false,\"causal_attribution_qualified\":false,\"observer_cost_qualified\":false}\n");status=0;
cleanup:
    if(cfgfd>=0){cfg.enabled=0;bpf_map_update_elem(cfgfd,&zero,&cfg,BPF_ANY);}
    for(unsigned i=0;i<6;i++){bpf_link__destroy(links[i]);}ring_buffer__free(ring);bpf_object__close(object);free(saved);return status;
}
