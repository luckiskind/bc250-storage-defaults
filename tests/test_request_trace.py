"""Reject plausible-looking timing reports with ambiguous or missing events."""
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'analysis'))
from request_trace import validate


class TraceWire(unittest.TestCase):
    def report(self):
        service=[0]*64;service[5]=2;queue=[0]*64;queue[4]=2
        return dict(schema_version=1,kind='bc250-request-trace',events=2,
            records=[dict(id=1,insert_ns=100,issue_ns=120,complete_ns=180,bytes=4096,completed_bytes=4096,operation=0,flags=0),
                     dict(id=2,insert_ns=200,issue_ns=220,complete_ns=280,bytes=4096,completed_bytes=4096,operation=0,flags=0)],
            kernel_counters=[2,2,2]+[0]*13,limit_discarded_records=0,detached_monotonic_ns=300,start_monotonic_ns=90,
            read_completed_bytes=8192,write_completed_bytes=0,qualified_full_requests=2,flagged_events=0,
            service_log2_ns=service,queue_log2_ns=queue,service_sum_ns=120,queue_sum_ns=40,
            links_detached=True,maps_pinned=False,event_limit_reached=False,interrupted=False,malformed_events=0)

    def test_reused_identity_cannot_masquerade_as_two_fast_requests(self):
        report=self.report();self.assertTrue(validate(report)['transport_complete'])
        report['records'][1]['id']=1
        with self.assertRaisesRegex(ValueError,'request identity'):validate(report)

    def test_missing_final_event_is_not_ignored(self):
        report=self.report();report['kernel_counters'][2]=3
        with self.assertRaisesRegex(ValueError,'transport accounting'):validate(report)

    def test_explicit_cap_is_consistent_but_incomplete(self):
        report=self.report();report.update(event_limit_reached=True,limit_discarded_records=1)
        report['kernel_counters'][2]=3
        self.assertFalse(validate(report)['transport_complete'])

    def test_zero_payload_read_is_not_labeled_flush_or_used_to_erase_failure(self):
        from request_classes import summarize
        report=self.report();row=report['records'][1]
        row.update(operation=2,bytes=0,completed_bytes=0,flags=144,insert_ns=0)
        report.update(read_completed_bytes=4096,qualified_full_requests=1,flagged_events=1,
            service_sum_ns=60,queue_sum_ns=20)
        report['service_log2_ns'][5]=1;report['queue_log2_ns'][4]=1
        report['kernel_counters'][3]=1
        result=summarize(report,2)
        self.assertEqual(result['flagged_zero_payload_flush_records'],1)
        self.assertEqual(result['orphan_complete_total'],1)
        self.assertFalse(result['flush_lifecycle_qualified'])
        self.assertFalse(result['existing_verdict_recomputed_or_changed'])
        row['operation']=0
        result=summarize(report,2)
        self.assertEqual(result['flagged_zero_payload_flush_records'],0)
        self.assertEqual(result['flagged_read_records'],1)


if __name__=='__main__':unittest.main()
