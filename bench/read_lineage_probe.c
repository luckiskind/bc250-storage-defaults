#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
static uint64_t now(void){struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))exit(2);return (uint64_t)t.tv_sec*1000000000+t.tv_nsec;}
int main(int argc,char **argv){
    if(argc!=3 || (strcmp(argv[2],"read") && strcmp(argv[2],"mmap")))return 2;
    char *end;errno=0;long fd=strtol(argv[1],&end,10);if(errno || *end || fd<0 || fd>4095)return 2;
    const size_t size=2*1024*1024;struct stat st;if(fstat(fd,&st) || !S_ISREG(st.st_mode) || st.st_size<(off_t)size)return 2;
    if(posix_fadvise(fd,0,0,POSIX_FADV_RANDOM))return 2;
    unsigned char *data=NULL;int mapped=!strcmp(argv[2],"mmap");
    if(mapped){data=mmap(NULL,size,PROT_READ,MAP_PRIVATE,fd,0);if(data==MAP_FAILED)return 2;}
    else{data=malloc(size);if(!data)return 2;memset(data,0,size);}
    puts("BC250_READ_WORKER_READY");fflush(stdout);char command;if(read(0,&command,1)!=1 || command!='G')return 2;
    uint64_t start=now();size_t done=0;unsigned calls=0;
    if(!mapped)while(done<size){ssize_t n=pread(fd,data+done,size-done,(off_t)done);if(n<0 && errno==EINTR)continue;if(n<=0)return 2;done+=n;calls++;}
    uint64_t hash=14695981039346656037ULL;for(size_t i=0;i<size;i++){hash^=data[i];hash*=1099511628211ULL;}uint64_t finish=now();
    printf("{\"passed\":true,\"start_ns\":%" PRIu64 ",\"finish_ns\":%" PRIu64 ",\"logical_bytes\":%zu,\"read_calls\":%u,\"fnv64\":\"%016" PRIx64 "\"}\n",start,finish,size,calls,hash);fflush(stdout);
    if(read(0,&command,1)!=1 || command!='D')return 2;
    if(mapped)munmap(data,size);else free(data);return 0;
}
