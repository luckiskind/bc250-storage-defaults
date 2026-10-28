/* Private profiling helper. Opens owned references; never resets counters. */
#define _POSIX_C_SOURCE 200809L
#include <bpf/bpf.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
struct bc_sample {
    uint64_t begin_ns,end_ns,run_time_ns,run_cnt,recursion_misses;
    uint32_t id,type,info_length,xlated_bytes;
    char name[16];
};
static uint64_t now(void){struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))return 0;return (uint64_t)t.tv_sec*1000000000+t.tv_nsec;}
unsigned bc_sample_size(void){return sizeof(struct bc_sample);}
int bc_stats_open(void){return bpf_enable_stats(BPF_STATS_RUN_TIME);}
int bc_program_open(uint32_t id){return bpf_prog_get_fd_by_id(id);}
int bc_snapshot(int fd,uint32_t expected,struct bc_sample *out){
    struct bpf_prog_info info={};uint32_t size=sizeof(info);
    if(!out || !expected){errno=EINVAL;return -1;}
    memset(out,0,sizeof(*out));out->begin_ns=now();
    if(!out->begin_ns || bpf_obj_get_info_by_fd(fd,&info,&size))return -1;
    out->end_ns=now();
    if(size!=sizeof(info) || info.id!=expected || !info.type || !info.xlated_prog_len || !out->end_ns || out->end_ns<out->begin_ns){errno=EPROTO;return -1;}
    out->id=info.id;out->type=info.type;out->info_length=size;out->xlated_bytes=info.xlated_prog_len;
    out->run_time_ns=info.run_time_ns;out->run_cnt=info.run_cnt;out->recursion_misses=info.recursion_misses;
    memcpy(out->name,info.name,sizeof(out->name));return 0;
}
