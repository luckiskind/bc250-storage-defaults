/* Reads only aligned regular-file fixtures; never submits raw-device reads. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static int fd,operations,same;
static uint64_t blocks;
static pthread_barrier_t barrier;
struct worker {unsigned id,done;int error;};
static uint64_t now(void) {struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return (uint64_t)t.tv_sec*1000000000+t.tv_nsec;}
static void *read_blocks(void *data) {
    struct worker *w=data;void *buffer=NULL;int error=posix_memalign(&buffer,4096,4096);
    if(error)w->error=error;
    /* Populate the anonymous destination page before direct I/O. A cold
     * userspace page can otherwise take a filesystem fallback path. */
    if(!error)*((volatile unsigned char *)buffer)=0;
    pthread_barrier_wait(&barrier);
    if(error)return NULL;
    for(int i=0;i<operations;i++) {
        uint64_t block=same?0:((uint64_t)i+w->id*4096)%blocks;
        ssize_t n=pread(fd,buffer,4096,block*4096);
        if(n!=4096) {w->error=n<0?errno:EIO;break;}
        w->done++;
    }
    free(buffer);return NULL;
}
int main(int argc,char **argv) {
    if(argc!=5)return 2;
    char *end;long threads=strtol(argv[2],&end,10);
    if(*end || threads<1 || threads>8)return 2;
    long count=strtol(argv[3],&end,10);if(*end || count<1 || count>100000)return 2;
    operations=count;
    if(strcmp(argv[4],"same") && strcmp(argv[4],"stride"))return 2;
    same=!strcmp(argv[4],"same");
    fd=open(argv[1],O_RDONLY|O_DIRECT|O_NOFOLLOW);if(fd<0) {perror("fixture");return 1;}
    struct stat s;
    if(fstat(fd,&s) || !S_ISREG(s.st_mode) || s.st_nlink!=1 || s.st_uid!=geteuid() || s.st_size<4096 || s.st_size>1024*1024*1024) {close(fd);return 2;}
    blocks=s.st_size/4096;
    pthread_t tids[8];struct worker workers[8]={};
    if(pthread_barrier_init(&barrier,NULL,threads+1))return 1;
    for(long i=0;i<threads;i++) {
        workers[i].id=i;
        /* Exiting this standalone process also terminates already-started
         * threads if creation fails; none has passed the barrier yet. */
        if(pthread_create(&tids[i],NULL,read_blocks,&workers[i]))return 1;
    }
    uint64_t start=now();pthread_barrier_wait(&barrier);
    unsigned total=0;bool passed=true;
    for(long i=0;i<threads;i++) {pthread_join(tids[i],NULL);total+=workers[i].done;if(workers[i].error)passed=false;}
    uint64_t finish=now();close(fd);pthread_barrier_destroy(&barrier);
    printf("{\"passed\":%s,\"direct_io\":true,\"buffer_prefaulted\":true,\"threads\":%ld,\"operations\":%u,\"read_bytes\":%" PRIu64 ",\"start_monotonic_ns\":%" PRIu64 ",\"finish_monotonic_ns\":%" PRIu64 ",\"elapsed_ns\":%" PRIu64 "}\n",
        passed?"true":"false",threads,total,(uint64_t)total*4096,start,finish,finish-start);
    return passed && total==threads*count?0:1;
}
