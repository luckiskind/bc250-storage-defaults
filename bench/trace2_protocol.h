#ifndef BC250_TRACE2_PROTOCOL_H
#define BC250_TRACE2_PROTOCOL_H
/* Each writer stores its own payload before publishing one ready bit.
 * Sequentially consistent atomics publish both payloads to the sole closer.
 * No spin lock: tracing programs must remain safe in their callback context. */
struct trace2_phase { unsigned long long ready,closed; };
static __inline__ __attribute__((always_inline)) int trace2_ready(struct trace2_phase *phase,unsigned long long bit) {
    if(bit!=1 && bit!=2)return -1;
    unsigned long long old=__sync_fetch_and_or(&phase->ready,bit);
    if(old&bit)return -1;
    if((old|bit)!=3)return 0;
    return __sync_bool_compare_and_swap(&phase->closed,0,1)?1:-1;
}
#endif
