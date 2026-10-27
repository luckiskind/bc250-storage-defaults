/* Shared wire layout. Kernel pointers/generation stamps never leave BPF maps. */
#ifndef BC250_REQUEST_TRACE_H
#define BC250_REQUEST_TRACE_H
#define TRACE_SCHEMA 1
#define TRACE_MAP_LIMIT 8192
#define TRACE_STAT_COUNT 16
enum trace_stat {
    ST_INSERT, ST_ISSUE, ST_FINAL, ST_ORPHAN_COMPLETE, ST_ZERO_GENERATION,
    ST_MAP_UPDATE_FAIL, ST_REPEAT_INSERT, ST_DUPLICATE_ISSUE, ST_REQUEUE,
    ST_PARTIAL, ST_OVERSHOOT, ST_RING_LOST, ST_DELETE_RACE, ST_NO_ISSUE,
    ST_BAD_TIME, ST_ORPHAN_REQUEUE
};
enum trace_flag {
    F_DUPLICATE=1, F_REQUEUE=2, F_ERROR=4, F_OVERSHOOT=8,
    F_NO_INSERT=16, F_BAD_TIME=32, F_PARTIAL=64, F_ZERO_BYTES=128,
    F_REPEAT_INSERT=256
};
struct trace_config { unsigned int major,minor,enabled,reserved; };
struct bc250_event {
    unsigned long long sequence,insert_ns,issue_ns,complete_ns;
    unsigned int bytes,completed_bytes,operation,flags;
};
#endif
