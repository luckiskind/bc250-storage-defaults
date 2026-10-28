"""Revised byte accounting over the frozen, strictly validated request graph.

No kernel collection or raw protocol changes. Old source/evidence stays intact.
"""
from request_bio_lineage import validate as reference_validate


def validate(raw):
    result=reference_validate(raw)
    requests={};members={};issued=0;reported=0;selected_issued=0;selected_reported=0;unknown=0;unknown_bytes=0
    # Retain the reference's stable ordering for equal timestamps. A chunk
    # before its parent snapshot must not acquire ownership from a later row.
    for row in sorted(raw['records'],key=lambda x:x['time_ns']):
        stage=row['stage']
        if stage==17:requests[row['id']]=row;issued+=row['value']
        elif stage==18 and row['parent'] in requests:
            members[row['id']]=row
            if row['value']:selected_issued+=row['aux']
        elif stage==21:
            member=members.get(row['id'])
            if member is None or member['parent']!=row['parent'] or row['parent'] not in requests:
                unknown+=1;unknown_bytes+=row['value'];continue
            reported+=row['value']
            if member['value']:selected_reported+=row['value']
    if result['stream_quality_passed']:
        if issued!=reported or selected_issued!=selected_reported or unknown:raise ValueError('Complete request accounting differs')
        if selected_reported!=result['physical_completed_bytes']:raise ValueError('Complete selected physical accounting differs')
    result.update(request_accounting_revision=1,request_issued_total_bytes=issued,request_reported_total_bytes=reported,
        selected_request_issued_member_bytes=selected_issued,selected_request_reported_member_bytes=selected_reported,
        unresolved_completion_chunk_records=unknown,unresolved_completion_chunk_bytes=unknown_bytes)
    return result
