"""Issued bytes cannot become reported bytes merely because capture stopped."""
import copy
import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'analysis'))
import test_request_bio_lineage as graphs
from request_bio_accounting import validate
from request_bio_lineage import validate as reference


class RequestBioAccounting(unittest.TestCase):
    def prefix(self):
        raw=graphs.RequestBioLineage().report();raw['records']=[e for e in raw['records'] if e['time_ns']<=120]
        raw['events']=raw['counters'][0]=len(raw['records']);raw['interrupted']=True;raw['pending_contexts']=[1]*9
        raw['request_counters']=[1,1,0,2,3,0,0]+[0]*17
        return raw

    def test_complete_graph_keeps_existing_qualified_totals(self):
        raw=graphs.RequestBioLineage().report();v=validate(raw);self.assertTrue(v['stream_quality_passed'])
        self.assertEqual((v['request_issued_total_bytes'],v['request_reported_total_bytes']),(5120,5120))
        self.assertEqual((v['selected_request_issued_member_bytes'],v['selected_request_reported_member_bytes']),(4096,4096))

    def test_censored_prefix_distinguishes_issued_from_reported(self):
        raw=self.prefix();old=reference(raw);v=validate(raw)
        self.assertFalse(v['stream_quality_passed']);self.assertEqual(old['request_reported_total_bytes'],5120)
        self.assertEqual((v['request_issued_total_bytes'],v['request_reported_total_bytes']),(5120,1024))
        self.assertEqual((v['selected_request_issued_member_bytes'],v['selected_request_reported_member_bytes']),(4096,1024))

    def test_orphan_chunk_is_explicitly_unresolved_without_later_ownership(self):
        raw=self.prefix();chunk=next(e for e in raw['records'] if e['stage']==21);chunk['time_ns']=115
        v=validate(raw);self.assertFalse(v['stream_quality_passed']);self.assertEqual(v['request_reported_total_bytes'],0)
        self.assertEqual((v['unresolved_completion_chunk_records'],v['unresolved_completion_chunk_bytes']),(1,1024))

    def test_status_error_reports_bytes_without_claiming_success(self):
        raw=graphs.RequestBioLineage().report();next(e for e in raw['records'] if e['stage']==21)['result']=1
        v=validate(raw);self.assertFalse(v['stream_quality_passed']);self.assertEqual(v['request_reported_total_bytes'],5120)

    def test_replay_does_not_mutate_reference_input(self):
        raw=self.prefix();before=copy.deepcopy(raw);validate(raw);self.assertEqual(raw,before)


if __name__=='__main__':unittest.main()
