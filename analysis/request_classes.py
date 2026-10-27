"""Offline operation/flag diagnostics. Never reclassifies a capture as qualified."""
import argparse
import collections
import json
from pathlib import Path

from request_trace import validate


def summarize(report,flush_operation):
    checked=validate(report)
    counts=collections.Counter((r['operation'],r['bytes'],r['completed_bytes'],r['flags']) for r in report['records'])
    flagged=[r for r in report['records'] if r['flags']]
    zero_flush=[r for r in flagged if r['operation']==flush_operation and not r['bytes'] and not r['completed_bytes']]
    return dict(schema_version=1,wire_consistent=checked['wire_consistent'],
        transport_complete=checked['transport_complete'],events=report['events'],
        classes=[dict(operation=op,bytes=size,completed_bytes=done,flags=flags,records=n)
            for (op,size,done,flags),n in sorted(counts.items())],
        supplied_flush_operation=flush_operation,flagged_records=len(flagged),
        flagged_zero_payload_flush_records=len(zero_flush),
        flagged_read_records=sum(r['operation']==0 for r in flagged),
        orphan_complete_total=checked['kernel_counters']['orphan_complete'],
        orphan_operation_or_cause_known=False,flush_lifecycle_qualified=False,
        existing_verdict_recomputed_or_changed=False,
        scope='Operation/size/flag counts only; matching global orphan counts do not identify their requests or cause')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--trace',type=Path,required=True);parser.add_argument('--flush-operation',type=int,required=True)
    args=parser.parse_args()
    if not 0<=args.flush_operation<=255:parser.error('Operation must fit the qualified eight-bit encoding')
    if args.trace.stat().st_size>64*2**20:parser.error('Trace exceeds the bounded offline input size')
    print(json.dumps(summarize(json.loads(args.trace.read_text()),args.flush_operation),indent=2))


if __name__=='__main__':main()
