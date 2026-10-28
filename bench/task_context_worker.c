/* Private task-storage capability stimulus. Marker waits are not I/O proof. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
static pthread_barrier_t start,held,release;
static int files[2],threads,failed;static const char *mode;
static uint64_t hashes[2];static unsigned cold_checks[2];
static void barrier(pthread_barrier_t *b){int r=pthread_barrier_wait(b);if(r && r!=PTHREAD_BARRIER_SERIAL_THREAD)_exit(2);}
static void *work(void *arg){
    size_t index=(size_t)arg;barrier(&start);
    if(!strcmp(mode,"hold") || !strcmp(mode,"none")){
        if(!strcmp(mode,"hold"))(void)syscall(SYS_getpgid,0);
        barrier(&held);barrier(&release);
        if(!strcmp(mode,"hold"))(void)syscall(SYS_getsid,0);
        return NULL;
    }
    const size_t whole=8*1024*1024,bytes=2*1024*1024;unsigned char resident[2048];
    void *shadow=mmap(NULL,whole,PROT_NONE,MAP_PRIVATE,files[index],0);unsigned char *data=malloc(bytes);
    if(shadow==MAP_FAILED || !data)_exit(2);
    uint64_t expected=0;
    for(unsigned pass=0;pass<8;pass++){
        if(posix_fadvise(files[index],0,0,POSIX_FADV_DONTNEED) || mincore(shadow,whole,resident))_exit(2);
        unsigned resident_pages=0;for(size_t i=0;i<sizeof(resident);i++)resident_pages+=!!(resident[i]&1);
        if(resident_pages){dprintf(2,"{\"cold_failure_thread\":%zu,\"pass\":%u,\"resident_pages\":%u}\n",index,pass,resident_pages);_exit(2);}
        cold_checks[index]++;
        unsigned char *source=data;
        if(!strcmp(mode,"mmap")){
            source=mmap(NULL,bytes,PROT_READ,MAP_PRIVATE,files[index],0);if(source==MAP_FAILED || madvise(source,bytes,MADV_RANDOM))_exit(2);
        }else{
            size_t done=0;while(done<bytes){ssize_t n=pread(files[index],data+done,bytes-done,(off_t)done);if(n<0 && errno==EINTR)continue;if(n<=0)_exit(2);done+=(size_t)n;}
        }
        uint64_t hash=14695981039346656037ULL;for(size_t i=0;i<bytes;i++){hash^=source[i];hash*=1099511628211ULL;}
        if(!pass)expected=hash;else if(hash!=expected)_exit(2);
        if(source!=data && munmap(source,bytes))_exit(2);
    }
    hashes[index]=expected;if(munmap(shadow,whole))_exit(2);free(data);return NULL;
}
int main(int argc,char **argv){
    _Static_assert(SYS_getpgid==121 && SYS_getsid==124,"x86_64 marker ABI");
    if(argc!=5 || (strcmp(argv[3],"read") && strcmp(argv[3],"mmap") && strcmp(argv[3],"hold") && strcmp(argv[3],"none")))return 2;
    mode=argv[3];threads=atoi(argv[4]);if(threads<1 || threads>2 || sysconf(_SC_PAGESIZE)!=4096)return 2;
    for(int i=0;i<2;i++){
        char *end;errno=0;long fd=strtol(argv[i+1],&end,10);if(errno || *end || fd<0 || fd>4095)return 2;files[i]=(int)fd;
        struct stat s;if(fstat(files[i],&s) || !S_ISREG(s.st_mode) || s.st_size!=8*1024*1024 || posix_fadvise(files[i],0,0,POSIX_FADV_RANDOM))return 2;
    }
    if(pthread_barrier_init(&start,NULL,threads+1) || pthread_barrier_init(&held,NULL,threads+1) || pthread_barrier_init(&release,NULL,threads+1))return 2;
    pthread_t workers[2];for(int i=0;i<threads;i++)if(pthread_create(&workers[i],NULL,work,(void *)(size_t)i))return 2;
    puts("BC250_TASK_WORKER_READY");fflush(stdout);char command;if(read(0,&command,1)!=1 || command!='G')return 2;barrier(&start);
    if(!strcmp(mode,"hold") || !strcmp(mode,"none")){
        barrier(&held);puts("BC250_TASK_CONTEXTS_HELD");fflush(stdout);
        if(read(0,&command,1)!=1 || command!='D')return 2;
        barrier(&release);
    }
    for(int i=0;i<threads;i++)if(pthread_join(workers[i],NULL))failed=1;
    printf("{\"passed\":%s,\"threads\":%d,\"passes_per_thread\":%d,\"logical_bytes\":%d,\"cold_checks\":[%u,%u],\"hashes\":[\"%016" PRIx64 "\",\"%016" PRIx64 "\"]}\n",failed?"false":"true",threads,(!strcmp(mode,"hold") || !strcmp(mode,"none"))?0:8,(!strcmp(mode,"hold") || !strcmp(mode,"none"))?0:threads*8*2*1024*1024,cold_checks[0],cold_checks[1],hashes[0],hashes[1]);fflush(stdout);
    if(strcmp(mode,"hold") && strcmp(mode,"none") && (read(0,&command,1)!=1 || command!='D'))return 2;
    for(int i=0;i<3;i++){pthread_barrier_t *b=i==0?&start:i==1?&held:&release;if(pthread_barrier_destroy(b))return 2;}
    return failed?2:0;
}
