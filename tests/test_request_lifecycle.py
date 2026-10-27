"""An unmatched callback is not explained by zero bytes or coincident counts."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'analysis'))
from request_lifecycle import summarize


class LifecycleDiagnostics(unittest.TestCase):
    def row(self,identity,ordinal,stage,operation=1,internal=0,size=0,status=0,bio=1):
        return dict(id=identity,ordinal=ordinal,time_ns=100+ordinal,stage=stage,operation=operation,
            data_bytes=size,completed_bytes=size if stage==4 else 0,status=status,rq_flags=0,cmd_flags=operation,
            internal_flush=internal,flush_seq=0,bio_present=bio)

    def report(self):
        rows=[self.row(1,i,s,2,1,bio=0) for i,s in enumerate((2,4),1)]
        rows+=[self.row(2,i,s,status=1 if s==6 else 0) for i,s in enumerate((5,6,4),1)]
        rows+=[self.row(3,i,s,0,size=4096) for i,s in enumerate((1,2,4),1)]
        return dict(schema_version=1,kind='bc250-request-lifecycle-diagnostic',start_ns=90,finish_ns=200,detached_ns=210,
            events=len(rows),malformed=0,discarded=0,interrupted=False,limit_reached=False,counters=[len(rows),0,0,0],
            records=rows,links_detached=True,maps_pinned=False,performance_result=False)

    def test_distinct_flush_lifecycles_and_read_control(self):
        result=summarize(self.report())
        self.assertEqual(result['internal_zero_payload_device_flush_groups'],1)
        self.assertEqual(result['zero_payload_consumed_sequence_groups'],1)
        self.assertEqual(result['ordinary_read_completed_bytes'],4096)
        self.assertEqual(result['unissued_completion_groups'],1)
        self.assertEqual(result['unexplained_completion_groups'],0)
        self.assertFalse(result['old_verdicts_changed'])
        self.assertFalse(result['historical_orphan_causes_proven'])

    def test_zero_bytes_and_operation_without_entry_return_proof_remain_unknown(self):
        report=self.report();report['records']=[self.row(1,1,4)]
        report.update(events=1,counters=[1,0,0,0]);result=summarize(report)
        self.assertEqual(result['zero_payload_consumed_sequence_groups'],0)
        self.assertEqual(result['unexplained_completion_groups'],1)

    def test_zero_payload_read_never_becomes_software_flush(self):
        report=self.report()
        for row in report['records']:
            if row['id']==2:row['operation']=0
        result=summarize(report)
        self.assertEqual(result['zero_payload_consumed_sequence_groups'],0)
        self.assertEqual(result['unexplained_completion_groups'],1)

    def test_internal_request_relation_must_be_positive(self):
        report=self.report()
        for row in report['records']:
            if row['id']==1:row['internal_flush']=0
        result=summarize(report)
        self.assertEqual(result['internal_zero_payload_device_flush_groups'],0)
        self.assertEqual(result['unexplained_completion_groups'],1)

    def test_explicit_loss_is_incomplete_and_does_not_qualify_patterns(self):
        report=self.report();report['counters'][0]+=1;report['counters'][1]=1
        result=summarize(report);self.assertFalse(result['transport_complete'])
        self.assertEqual(result['zero_payload_consumed_sequence_groups'],0)
        self.assertEqual(result['internal_zero_payload_device_flush_groups'],0)

    def test_unreported_loss_and_missing_or_duplicate_ordinals_refuse(self):
        report=self.report();report['counters'][0]+=1
        with self.assertRaisesRegex(ValueError,'accounting'):summarize(report)
        for ordinal in (1,3):
            report=self.report();report['records'][1]['ordinal']=ordinal
            with self.subTest(ordinal=ordinal):
                with self.assertRaisesRegex(ValueError,'ordinal'):summarize(report)

    def test_kernel_pointer_extra_field_and_noninteger_values_refuse(self):
        for field,value in (('request_pointer',1234),('id',True),('stage',-1)):
            report=self.report();report['records'][0][field]=value
            with self.subTest(field=field):
                with self.assertRaises(ValueError):summarize(report)

    def test_tail_callback_uses_detach_lifetime_not_disable_marker(self):
        report=self.report();report['records'][1]['time_ns']=205
        self.assertTrue(summarize(report)['transport_complete'])
        report['records'][1]['time_ns']=211
        with self.assertRaisesRegex(ValueError,'lifetime'):summarize(report)

    def test_nonconsumed_return_does_not_explain_unissued_completion(self):
        report=self.report();report['records'][3]['status']=0
        result=summarize(report)
        self.assertEqual(result['zero_payload_consumed_sequence_groups'],0)
        self.assertEqual(result['unexplained_completion_groups'],1)

    def test_completion_error_is_preserved_as_unexplained(self):
        report=self.report();report['records'][4]['status']=1
        result=summarize(report)
        self.assertEqual(result['completion_error_callbacks'],1)
        self.assertEqual(result['zero_payload_consumed_sequence_groups'],0)
        self.assertEqual(result['unexplained_completion_groups'],1)


if __name__=='__main__':unittest.main()
