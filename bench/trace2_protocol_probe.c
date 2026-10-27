/* Native concurrency control for the exact atomic helper used by BPF. */
#define _POSIX_C_SOURCE 200809L
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "trace2_protocol.h"
struct record {struct trace2_phase phase;unsigned returned,completed,published,errors;};
static struct record record;
static pthread_barrier_t barrier;
static const unsigned iterations=10000;
static void *actor(void *argument){
    unsigned long bit=(unsigned long)argument;
    for(unsigned i=1;i<=iterations;i++){
        pthread_barrier_wait(&barrier);
        if(bit==1)record.returned=i;else record.completed=i;
        int result=trace2_ready(&record.phase,bit);
        if(result<0)__sync_fetch_and_add(&record.errors,1);
        if(result==1){
            if(record.returned!=i || record.completed!=i)__sync_fetch_and_add(&record.errors,1);
            __sync_fetch_and_add(&record.published,1);
        }
        pthread_barrier_wait(&barrier);
    }
    return NULL;
}
int main(void){
    struct trace2_phase phase={};
    if(trace2_ready(&phase,0)!=-1 || trace2_ready(&phase,4)!=-1 || phase.ready || phase.closed)return 1;
    for(unsigned first=1;first<=2;first++){
        memset(&phase,0,sizeof(phase));
        if(trace2_ready(&phase,first)!=0 || trace2_ready(&phase,3-first)!=1 || phase.closed!=1)return 1;
        if(trace2_ready(&phase,first)!=-1 || trace2_ready(&phase,3-first)!=-1 || phase.closed!=1)return 1;
    }
    pthread_t threads[2];if(pthread_barrier_init(&barrier,NULL,3))return 1;
    if(pthread_create(&threads[0],NULL,actor,(void *)1UL) || pthread_create(&threads[1],NULL,actor,(void *)2UL))return 1;
    unsigned failures=0;
    for(unsigned i=1;i<=iterations;i++){
        memset(&record,0,sizeof(record));pthread_barrier_wait(&barrier);pthread_barrier_wait(&barrier);
        if(record.phase.ready!=3 || record.phase.closed!=1 || record.published!=1 || record.errors)failures++;
    }
    pthread_join(threads[0],NULL);pthread_join(threads[1],NULL);pthread_barrier_destroy(&barrier);
    printf("{\"passed\":%s,\"concurrent_pairs\":%u,\"failures\":%u,\"both_serial_orders_passed\":true,\"duplicate_and_invalid_bits_rejected\":true,\"kernel_bytecode_concurrency_proven\":false}\n",failures?"false":"true",iterations,failures);
    return failures?1:0;
}
