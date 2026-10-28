/* Fixed private-file wake-overlap stimulus; no performance endpoint claim. */
#define _GNU_SOURCE
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
    const size_t whole=8*1024*1024,chunk=4096;const unsigned passes=64;struct stat st;
    if(sysconf(_SC_PAGESIZE)!=4096 || fstat(fd,&st) || !S_ISREG(st.st_mode) || st.st_size!=(off_t)whole || posix_fadvise(fd,0,0,POSIX_FADV_RANDOM))return 2;
    unsigned char data[4096],resident[2048];void *shadow=mmap(NULL,whole,PROT_NONE,MAP_PRIVATE,fd,0);
    if(shadow==MAP_FAILED)return 2;
    puts("BC250_READ_WORKER_READY");fflush(stdout);char command;if(read(0,&command,1)!=1 || command!='G')return 2;
    uint64_t start=now(),hash=14695981039346656037ULL;unsigned calls=0;
    for(unsigned pass=0;pass<passes;pass++){
        if(posix_fadvise(fd,0,0,POSIX_FADV_DONTNEED) || mincore(shadow,whole,resident))return 2;
        for(size_t i=0;i<sizeof(resident);i++)if(resident[i]&1)return 2;
        off_t offset=(off_t)((pass*37U)%2048U)*4096;
        if(!strcmp(argv[2],"read")){
            size_t done=0;while(done<chunk){ssize_t n=pread(fd,data+done,chunk-done,offset+(off_t)done);if(n<0 && errno==EINTR)continue;if(n<=0)return 2;done+=(size_t)n;calls++;}
        }else{
            void *mapping=mmap(NULL,chunk,PROT_READ,MAP_PRIVATE,fd,offset);if(mapping==MAP_FAILED || madvise(mapping,chunk,MADV_RANDOM))return 2;
            for(size_t i=0;i<chunk;i++)data[i]=((volatile unsigned char *)mapping)[i];
            if(munmap(mapping,chunk))return 2;
            calls++;
        }
        for(size_t i=0;i<chunk;i++){hash^=data[i];hash*=1099511628211ULL;}
        if(pass+1<passes){struct timespec pause={.tv_nsec=2000000};while(nanosleep(&pause,&pause))if(errno!=EINTR)return 2;}
    }
    uint64_t finish=now();printf("{\"passed\":true,\"start_ns\":%" PRIu64 ",\"finish_ns\":%" PRIu64 ",\"logical_bytes\":%zu,\"fnv64\":\"%016" PRIx64 "\",\"passes\":%u,\"zero_resident_checks\":%u,\"read_calls\":%u}\n",start,finish,chunk*passes,hash,passes,passes,calls);fflush(stdout);
    if(read(0,&command,1)!=1 || command!='D')return 2;
    if(munmap(shadow,whole))return 2;
    return 0;
}
