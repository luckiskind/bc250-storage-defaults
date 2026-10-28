#ifndef BC250_FOLIO_VECTOR_MATH_H
#define BC250_FOLIO_VECTOR_MATH_H
/* Pure geometry over VMEMMAP metadata addresses; callers verify the layout.
 * No memory is dereferenced here. Native probes use synthetic addresses only. */
struct fv_input {
    unsigned long long folio,page,folio_index,folio_pages,vector_offset,vector_bytes;
    unsigned long long logical_cursor,original_offset,original_bytes;
};
struct fv_output { unsigned long long original_byte,bytes,folio_byte,flags; };
static __inline__ __attribute__((always_inline)) int fv_overlap(const struct fv_input *v,struct fv_output *out){
    const unsigned long long max=~0ULL;
    if(!v->folio || !v->page || (v->folio&63) || (v->page&63) || !v->folio_pages || v->folio_pages>(1ULL<<20)
       || (v->folio_pages&(v->folio_pages-1)) || v->folio_index>(max>>12) || !v->vector_bytes || v->vector_bytes>0xffffffffULL
       || v->vector_offset>0x1fffffffeULL || !v->original_bytes)return -1;
    unsigned long long pages,folio_bytes=v->folio_pages<<12;
    long long start;
    if(v->page>=v->folio){
        pages=(v->page-v->folio)>>6;if(pages>=v->folio_pages)return 0;
        start=(long long)((pages<<12)+v->vector_offset);
    }else{
        pages=(v->folio-v->page)>>6;
        if(pages>((v->vector_offset+v->vector_bytes+4095)>>12))return 0;
        start=(long long)v->vector_offset-(long long)(pages<<12);
    }
    long long end=start+(long long)v->vector_bytes,low=start>0?start:0,high=end<(long long)folio_bytes?end:(long long)folio_bytes;
    if(high<=low)return 0;
    unsigned long long delta=(unsigned long long)(low-start);
    if(v->logical_cursor>max-delta)return -1;
    unsigned long long logical=v->logical_cursor+delta;if(logical>=v->original_bytes)return 0;
    unsigned long long wanted=v->folio_index<<12;
    if(wanted>max-(unsigned long long)low || v->original_offset>max-logical)return -1;
    if(wanted+(unsigned long long)low!=v->original_offset+logical)return 0;
    unsigned long long length=(unsigned long long)(high-low),available=v->original_bytes-logical;
    if(length>available)length=available;
    out->original_byte=logical;out->bytes=length;out->folio_byte=(unsigned long long)low;
    out->flags=(((v->vector_offset+v->vector_bytes+4095)>>12)>1?1:0)|(v->folio_pages>1?2:0)|((low || length<folio_bytes)?4:0);
    return 1;
}
#endif
