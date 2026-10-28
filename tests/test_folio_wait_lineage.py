"""Require positive queue identity and scheduler evidence, including ret=0."""
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'analysis'))
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'bench'))
import test_read_lineage as samples
from folio_wait_lineage import validate
from folio_wait_loader import generate


class FolioWait(unittest.TestCase):
    def report(self):
        raw=samples.ReadLineage().report();raw.update(kind='bc250-folio-wait-diagnostic',folio_proof_enabled=True,wait_counters=[0]*16)
        raw['pending_contexts']+=[0,0]
        raw['records'][-1]['time_ns']=171
        def row(identity,stage,time,value=0,aux=0,result=0,flags=0,parent=4):
            return dict(id=identity,parent=parent,stage=stage,time_ns=time,value=value,aux=aux,result=result,flags=flags)
        raw['records'] += [row(6,13,172,value=2,flags=0xf0000),row(6,14,178,value=2,flags=0xf0000),
            row(7,15,125,value=2),row(8,16,182),row(9,17,174,value=6),row(10,18,175,value=6)]
        raw['events']=raw['counters'][0]=len(raw['records']);return raw

    def test_shared_zero_return_requires_and_accepts_full_scheduler_proof(self):
        result=validate(self.report());self.assertTrue(result['stream_quality_passed'])
        self.assertEqual((result['blocked_switch_segments'],result['resolved_folio_blocked_segments']),(1,1))
        self.assertEqual((result['proven_blocked_until_waking_union_ns'],result['wake_delivery_union_ns'],result['runnable_after_wakeup_union_ns']),(49,1,7))
        self.assertFalse(result['device_request_edges_qualified']);self.assertFalse(result['whole_application_critical_path_qualified'])

    def test_missing_folio_proof_cannot_be_replaced_by_wakeup_timing(self):
        raw=self.report();raw['folio_proof_enabled']=False
        raw['records']=[r for r in raw['records'] if r['stage'] not in (13,14)]
        for r in raw['records']:
            if r['stage'] in (17,18):r['value']=0
        raw['events']=raw['counters'][0]=len(raw['records'])
        result=validate(raw);self.assertFalse(result['stream_quality_passed']);self.assertEqual(result['unresolved_wait_edges'],1)

    def test_exclusive_return_has_different_success_semantics(self):
        raw=self.report()
        for r in raw['records']:
            if r['stage'] in (13,14):r['flags']|=1
        self.assertFalse(validate(raw)['stream_quality_passed'])
        for r in raw['records']:
            if r['stage']==14:r['result']=1
        self.assertTrue(validate(raw)['stream_quality_passed'])

    def test_owner_may_resume_before_waker_returns_without_return_dereference(self):
        raw=self.report()
        for r in raw['records']:
            if r['stage']==11:r['time_ns']=183
            if r['stage']==14:r['time_ns']=193
            if r['stage']==9:r['time_ns']=195
        result=validate(raw);self.assertTrue(result['stream_quality_passed']);self.assertEqual(result['wait_return_after_caller_resumed'],1)

    def test_bad_bio_range_parent_and_slot_clocks_refuse(self):
        for kind in ('range','parent','clock'):
            raw=self.report()
            for r in raw['records']:
                if r['stage'] in (13,14):
                    if kind=='range':r['aux']=4096
                    if kind=='parent':r['parent']=999
                    if kind=='clock' and r['stage']==13:r['time_ns']=119
            with self.assertRaises(ValueError):validate(raw)

    def test_preemption_is_not_classified_as_blocked_folio_wait(self):
        raw=self.report()
        for r in raw['records']:
            if r['stage']==15:r['aux']=1
        result=validate(raw);self.assertTrue(result['stream_quality_passed']);self.assertEqual(result['blocked_switch_segments'],0)
        self.assertEqual(result['other_runnable_switch_union_ns'],57)

    def test_unlinked_waking_or_missing_wakeup_stays_unresolved(self):
        for kind in ('unlinked','missing'):
            raw=self.report()
            if kind=='unlinked':
                for r in raw['records']:
                    if r['stage']==17:r['value']=999
            else:raw['records']=[r for r in raw['records'] if r['stage']!=18]
            raw['events']=raw['counters'][0]=len(raw['records'])
            self.assertFalse(validate(raw)['stream_quality_passed'])

    def test_loss_pending_context_or_extension_error_is_not_waived(self):
        for kind in ('loss','pending','error'):
            raw=self.report()
            if kind=='loss':raw['counters'][0]+=1;raw['counters'][1]+=1
            elif kind=='pending':raw['pending_contexts'][6]=1
            else:raw['wait_counters'][3]=1
            self.assertFalse(validate(raw)['stream_quality_passed'])

    def test_boolean_header_or_private_extra_fields_refuse(self):
        raw=self.report();raw['schema_version']=True
        with self.assertRaises(ValueError):validate(raw)
        raw=self.report();raw['records'][-1]['task_pointer']=123
        with self.assertRaises(ValueError):validate(raw)


class DerivedLoader(unittest.TestCase):
    def test_reference_drift_is_rejected_before_build(self):
        source=(Path(__file__).resolve().parents[1]/'bench/read_lineage.c').read_text()
        output=generate(source);self.assertIn('#define PROGRAMS 21',output)
        for changed in (source.replace('#define PROGRAMS 16','#define PROGRAMS 17'),source.replace('links[i]=bpf_program__attach_trace(p);','changed();')):
            with self.assertRaises(ValueError):generate(changed)


if __name__=='__main__':unittest.main()
