"""V2 auxiliary records require identity and lifecycle proof, not zero bytes."""
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'analysis'))
from request_trace_v2 import validate


class TraceV2(unittest.TestCase):
    def report(self):
        row=dict(id=1,insert_ns=100,issue_ns=110,complete_ns=130,enter_ns=0,return_ns=0,bytes=4096,completed_bytes=4096,
            operation=0,flags=0,event_class=0,evidence=0,entry_cmd_flags=0,status=0)
        stats=[0]*24;stats[0]=stats[1]=stats[2]=1
        return dict(schema_version=2,kind='bc250-request-trace-v2',libbpf='v1.7.0',software_tracking_enabled=True,internal_tracking_enabled=True,
            preflush_mask=262144,start_ns=90,finish_ns=200,detached_ns=210,events=1,malformed=0,discarded=0,interrupted=False,
            limit_reached=False,right_censored_requests=0,return_contexts=0,counters=stats,records=[row],links_detached=True,maps_pinned=False,
            foreground_attribution_qualified=False,performance_result=False)

    def software(self):
        value=self.report();row=value['records'][0]
        row.update(insert_ns=0,issue_ns=0,enter_ns=100,return_ns=110,bytes=0,completed_bytes=0,operation=1,flags=144,event_class=2,evidence=14,entry_cmd_flags=264193)
        value['counters'][0]=value['counters'][1]=0
        for index in (16,17,19,20):value['counters'][index]=1
        return value

    def internal(self):
        value=self.report();row=value['records'][0];row.update(insert_ns=0,bytes=0,completed_bytes=0,operation=2,flags=144,event_class=1,evidence=9)
        value['counters'][0]=0;value['counters'][21]=1;return value

    def test_ordinary_data_and_both_proven_auxiliary_types(self):
        self.assertEqual(validate(self.report())['ordinary_full_requests'],1)
        for factory,field in ((self.software,'proven_software_sequences'),(self.internal,'proven_internal_flushes')):
            result=validate(factory());self.assertTrue(result['stream_quality_passed']);self.assertEqual(result[field],1)
            self.assertEqual(result['raw_flagged_records'],1)

    def test_completion_can_precede_return_but_never_entry(self):
        value=self.software();value['records'][0]['return_ns']=140
        self.assertTrue(validate(value)['stream_quality_passed'])
        value['records'][0]['enter_ns']=135
        with self.assertRaisesRegex(ValueError,'ordering'):validate(value)

    def test_software_claim_requires_every_proof_and_original_preflush(self):
        for field,entry in (('evidence',10),('entry_cmd_flags',2049),('enter_ns',0),('issue_ns',105)):
            value=self.software();value['records'][0][field]=entry
            with self.subTest(field=field):
                with self.assertRaises(ValueError):validate(value)

    def test_zero_byte_read_or_unproven_device_flush_stays_unresolved(self):
        for op in (0,2):
            value=self.report();value['records'][0].update(insert_ns=0,bytes=0,completed_bytes=0,operation=op,flags=144)
            result=validate(value);self.assertFalse(result['stream_quality_passed']);self.assertEqual(result['unresolved_records'],1)
        value=self.internal();value['records'][0]['evidence']=8
        with self.assertRaisesRegex(ValueError,'positive identity'):validate(value)

    def test_disabled_tracking_cannot_claim_a_proven_record(self):
        for factory,key in ((self.internal,'internal_tracking_enabled'),(self.software,'software_tracking_enabled')):
            value=factory();value[key]=False
            with self.subTest(key=key):
                with self.assertRaises(ValueError):validate(value)

    def test_false_return_and_errors_are_not_hidden_by_auxiliary_class(self):
        value=self.software();value['records'][0].update(event_class=3,evidence=26,flags=656)
        value['counters'][17]=0;value['counters'][18]=1
        self.assertFalse(validate(value)['stream_quality_passed'])
        value=self.software();value['records'][0].update(status=1,flags=148)
        result=validate(value);self.assertEqual(result['unresolved_records'],1);self.assertFalse(result['stream_quality_passed'])

    def test_orphans_and_unfinished_return_contexts_fail_quality(self):
        for field in ('return_contexts','right_censored_requests'):
            value=self.report();value[field]=1;self.assertFalse(validate(value)['stream_quality_passed'])
        value=self.report();value['counters'][3]=1;self.assertFalse(validate(value)['stream_quality_passed'])

    def test_delivery_loss_explicit_and_hidden_loss_rejected(self):
        value=self.report();value['counters'][2]+=1;value['counters'][11]=1
        self.assertFalse(validate(value)['transport_complete'])
        value['counters'][11]=0
        with self.assertRaisesRegex(ValueError,'delivery'):validate(value)

    def test_lifecycle_counter_claims_cannot_exceed_entries(self):
        value=self.software();value['counters'][16]=0
        with self.assertRaisesRegex(ValueError,'exceed entries'):validate(value)
        value=self.software();value['counters'][20]=0
        with self.assertRaisesRegex(ValueError,'Class counters'):validate(value)

    def test_private_fields_boolean_integers_and_reused_identity_refuse(self):
        for field,entry in (('request_pointer',123),('id',True)):
            value=self.report();value['records'][0][field]=entry
            with self.subTest(field=field):
                with self.assertRaises(ValueError):validate(value)
        value=self.report();value['records']*=2;value['events']=2;value['counters'][2]=2
        with self.assertRaisesRegex(ValueError,'identity'):validate(value)

    def test_tail_bounded_by_actual_detachment(self):
        value=self.report();value['records'][0]['complete_ns']=205
        self.assertTrue(validate(value)['stream_quality_passed'])
        value['records'][0]['complete_ns']=211
        with self.assertRaisesRegex(ValueError,'outside capture'):validate(value)

    def test_legacy_schema_cannot_be_silently_promoted(self):
        value=self.report();value['schema_version']=1;value['kind']='bc250-request-trace'
        with self.assertRaisesRegex(ValueError,'Wrong v2 schema'):validate(value)


if __name__=='__main__':unittest.main()
