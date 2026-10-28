/* Synthetic metadata geometry only: never accepts or reads a kernel pointer. */
#include <stdio.h>
#include "folio_vector_math.h"
int main(void){
    struct fv_input v;unsigned cases=0;
    while(scanf("%llu %llu %llu %llu %llu %llu %llu %llu %llu",&v.folio,&v.page,&v.folio_index,&v.folio_pages,&v.vector_offset,&v.vector_bytes,&v.logical_cursor,&v.original_offset,&v.original_bytes)==9){
        struct fv_output out={};int result=fv_overlap(&v,&out);
        printf("%d %llu %llu %llu %llu\n",result,out.original_byte,out.bytes,out.folio_byte,out.flags);cases++;
    }
    return cases && feof(stdin)?0:2;
}
