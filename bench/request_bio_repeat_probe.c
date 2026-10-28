/* Private-file serialized reads exercise request recycling, not performance. */
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
    if(argc!=3 || strcmp(argv[2],"repeat"))return 2;
    char *end;errno=0;long fd=strtol(argv[1],&end,10);if(errno || *end || fd<0 || fd>4095)return 2;
    const size_t size=2*1024*1024,whole=8*1024*1024;const unsigned passes=8;struct stat st;
    if(fstat(fd,&st) || !S_ISREG(st.st_mode) || st.st_size!=(off_t)whole || posix_fadvise(fd,0,0,POSIX_FADV_RANDOM))return 2;
    long page=sysconf(_SC_PAGESIZE);if(page!=4096)return 2;size_t pages=whole/(size_t)page;
    unsigned char *data=calloc(1,size),*resident=calloc(1,pages);void *mapping=mmap(NULL,whole,PROT_NONE,MAP_PRIVATE,fd,0);
    if(!data || !resident || mapping==MAP_FAILED)return 2;
    puts("BC250_READ_WORKER_READY");fflush(stdout);char command;if(read(0,&command,1)!=1 || command!='G')return 2;
    uint64_t start=now(),expected=0;unsigned calls=0;
    for(unsigned pass=0;pass<passes;pass++){
        if(posix_fadvise(fd,0,0,POSIX_FADV_DONTNEED) || mincore(mapping,whole,resident))return 2;
        for(size_t i=0;i<pages;i++)if(resident[i]&1)return 2;
        size_t done=0;while(done<size){ssize_t n=pread(fd,data+done,size-done,(off_t)done);if(n<0 && errno==EINTR)continue;if(n<=0)return 2;done+=(size_t)n;calls++;}
        uint64_t hash=14695981039346656037ULL;for(size_t i=0;i<size;i++){hash^=data[i];hash*=1099511628211ULL;}
        if(!pass)expected=hash;else if(hash!=expected)return 2;
        if(pass+1<passes){struct timespec delay={.tv_nsec=20000000};while(nanosleep(&delay,&delay))if(errno!=EINTR)return 2;}
    }
    uint64_t finish=now();printf("{\"passed\":true,\"start_ns\":%" PRIu64 ",\"finish_ns\":%" PRIu64 ",\"logical_bytes\":%zu,\"read_calls\":%u,\"fnv64\":\"%016" PRIx64 "\",\"passes\":%u,\"zero_resident_checks\":%u}\n",start,finish,size*passes,calls,expected,passes,passes);fflush(stdout);
    if(read(0,&command,1)!=1 || command!='D')return 2;
    munmap(mapping,whole);free(data);free(resident);return 0;
}
