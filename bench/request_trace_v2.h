#ifndef BC250_TRACE_V2_H
#define BC250_TRACE_V2_H
#define V2_KEYS 8192
#define V2_STATS 24
#define V2_PREFLUSH (1U<<18)
enum v2_counter { V_INSERT,V_ISSUE,V_FINAL,V_ORPHAN,V_ZERO_GEN,V_MAP_FAIL,V_REPEAT_INSERT,V_DUP_ISSUE,
    V_REQUEUE,V_PARTIAL,V_OVERSHOOT,V_RING_LOST,V_DELETE_RACE,V_NO_ISSUE,V_BAD_TIME,V_ORPHAN_REQUEUE,
    V_SW_ENTRY,V_SW_TRUE,V_SW_FALSE,V_SW_COMPLETE,V_SW_FINAL,V_INTERNAL_FINAL,V_SW_ANOMALY,V_CONTEXT_FAIL };
enum v2_flag { V_DUP=1,V_REQUEUED=2,V_ERROR=4,V_OVER=8,V_NO_INSERT=16,V_TIME=32,V_PART=64,V_ZERO=128,V_REPEAT=256,V_CONTRADICTION=512 };
enum v2_class { V_DATA=0,V_DEVICE_FLUSH=1,V_SOFTWARE_FLUSH=2,V_UNKNOWN_SEQUENCE=3 };
enum v2_evidence { V_INTERNAL=1,V_ENTERED=2,V_CONSUMED_TRUE=4,V_COMPLETED=8,V_CONSUMED_FALSE=16 };
struct v2_config { unsigned int major,minor,enabled,software,internal; };
struct v2_event {
    unsigned long long sequence,insert_ns,issue_ns,complete_ns,enter_ns,return_ns;
    unsigned int bytes,completed_bytes,operation,flags,event_class,evidence,entry_cmd_flags,status;
};
#endif
