/* Diagnostic callbacks, distinct from the frozen request-timing wire format. */
#ifndef BC250_REQUEST_LIFECYCLE_H
#define BC250_REQUEST_LIFECYCLE_H
#define LIFE_KEYS 8192
#define LIFE_STATS 4
struct life_config { unsigned int major,minor,enabled,reserved; };
struct life_event {
    unsigned long long id,ordinal,time_ns;
    unsigned int stage,operation,data_bytes,completed_bytes,status,rq_flags,cmd_flags;
    unsigned int internal_flush,flush_seq,bio_present;
};
enum life_stage { LIFE_INSERT=1,LIFE_ISSUE,LIFE_REQUEUE,LIFE_COMPLETE,LIFE_FLUSH_ENTER,LIFE_FLUSH_RETURN };
/* Counters: selected callbacks, ring loss, identity-map failure, zero generation. */
#endif
