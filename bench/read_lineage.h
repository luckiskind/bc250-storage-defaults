#ifndef BC250_READ_LINEAGE_H
#define BC250_READ_LINEAGE_H
#define LINE_KEYS 4096
#define LINE_STATS 16
enum line_stage { DEMAND_BEGIN=1,DEMAND_END,BIO_SUBMIT,COMPRESSED_SUBMIT,COMPRESSED_DEVICE_DONE,
    DECOMP_BEGIN,DECOMP_END,DATA_END_BEGIN,DATA_END_RETURN,IO_SLEEP_BEGIN,IO_SLEEP_END,FOLIO_UNLOCK_CALL };
struct line_config { unsigned int enabled,pid,fd,pad; };
struct line_event { unsigned long long id,parent,time_ns,value,aux; long long result; unsigned int stage,flags; };
#endif
