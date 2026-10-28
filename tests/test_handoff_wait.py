"""Handoff timing must not invent blocked time or reuse causal wake edges."""
import copy
import json
from pathlib import Path
import sys
import unittest
sys.path[:0]=[str(Path(__file__).resolve().parents[1]/n) for n in ('analysis','bench')]
from handoff_wait import validate
from compact_wait import validate as old_validate
from handoff_wait_loader import generate,folio_extension,vector_extension,ready_ids
import test_compact_wait as samples


def report(early=False):
    r=samples.CompactWait().report()
    r.update(kind='bc250-handoff-wait-diagnostic',schema_version=2,scheduler_timestamp_basis='hook-entry-v1')
    if early:
        for e in r['records']:
            if e['stage']==26:e['time_ns']=176
            if e['stage']==29:e.update(time_ns=179,value=0)
    return r


def recount(r):r['events']=r['counters'][0]=len(r['records'])


class HandoffWait(unittest.TestCase):
    def test_normal_wait_retains_positive_accounting_without_mutation(self):
        r=report();saved=copy.deepcopy(r);v=validate(r)
        self.assertEqual(r,saved);self.assertTrue(v['stream_quality_passed'])
        self.assertEqual((v['normal_post_switch_wake_segments'],v['early_wake_handoff_segments']),(1,0))
        self.assertEqual((v['proven_blocked_until_waking_union_ns'],v['wake_delivery_union_ns'],v['runnable_after_wakeup_union_ns']),(49,1,7))
        self.assertTrue(v['storage_blocked_interval_accounting_complete']);self.assertIsNone(v['early_wake_storage_blocked_ns'])

    def test_early_wake_is_classified_without_claiming_storage_duration(self):
        v=validate(report(True));self.assertTrue(v['stream_quality_passed'])
        self.assertEqual((v['early_wake_handoff_segments'],v['resolved_request_folio_blocked_segments']),(1,1))
        self.assertEqual((v['early_wake_off_cpu_union_ns'],v['early_wake_delivery_overlap_union_ns']),(6,3))
        self.assertEqual((v['proven_blocked_until_waking_union_ns'],v['wake_delivery_union_ns'],v['runnable_after_wakeup_union_ns']),(0,3,3))
        self.assertFalse(v['storage_blocked_interval_accounting_complete']);self.assertIsNone(v['early_wake_storage_blocked_ns'])
        self.assertFalse(v['minimal_hardware_service_time_qualified']);self.assertFalse(v['whole_application_critical_path_qualified'])

    def test_both_readers_reject_other_protocol_and_old_refusal_is_frozen(self):
        old=samples.CompactWait().report()
        for e in old['records']:
            if e['stage']==26:e['time_ns']=176
            if e['stage']==29:e.update(time_ns=179,value=0)
        self.assertFalse(old_validate(old)['stream_quality_passed'])
        with self.assertRaises(ValueError):validate(old)
        with self.assertRaises(ValueError):old_validate(report())
        for key,value in [('schema_version',True),('schema_version',1),('scheduler_timestamp_basis','after-proof'),('unlock_hook_loaded',0)]:
            r=report();r[key]=value
            with self.assertRaises(ValueError):validate(r)

    def test_proof_loss_pending_and_all_counter_errors_remain_disqualifying(self):
        for field,index in [('counters',1),('pending_contexts',12),('vector_counters',5),('wait_counters',3),('request_counters',13)]:
            r=report(True);r[field][index]+=1
            if field=='counters':r['counters'][0]+=1
            self.assertFalse(validate(r)['stream_quality_passed'],field)
        r=report(True);r['records']=[e for e in r['records'] if e['stage']!=30];recount(r)
        r['vector_counters'][1]=0;r['vector_counters'][7]=1;r['vector_proof_enabled']=False
        v=validate(r);self.assertFalse(v['stream_quality_passed']);self.assertEqual(v['resolved_request_folio_blocked_segments'],0)

    def test_unrelated_duplicate_or_missing_wake_cannot_be_consumed(self):
        for kind in ('unrelated','duplicate','missing','failed-return'):
            r=report(True)
            if kind=='unrelated':next(e for e in r['records'] if e['stage']==28)['value']=999
            if kind=='duplicate':
                e=copy.deepcopy(next(e for e in r['records'] if e['stage']==28));e['id']=100;e['time_ns']=173;r['records'].append(e)
            if kind=='missing':r['records']=[e for e in r['records'] if e['stage']!=29]
            if kind=='failed-return':next(e for e in r['records'] if e['stage']==25)['result']=1
            recount(r);self.assertFalse(validate(r)['stream_quality_passed'],kind)

    def test_wakeup_before_out_and_ambiguous_clock_ties_stay_unresolved(self):
        for stage,time in [(29,175),(28,176),(29,176),(29,182)]:
            r=report(True);next(e for e in r['records'] if e['stage']==stage)['time_ns']=time
            self.assertFalse(validate(r)['stream_quality_passed'],(stage,time))

    def test_same_wake_cannot_resolve_a_second_switch_segment(self):
        r=report(True)
        for identity,stage,time,value in [(100,26,183,2),(101,27,184,0)]:
            r['records'].append(dict(id=identity,parent=4,stage=stage,time_ns=time,value=value,aux=0,result=0,flags=0))
        recount(r);v=validate(r);self.assertFalse(v['stream_quality_passed']);self.assertEqual(v['early_wake_handoff_segments'],1)
        self.assertEqual(v['blocked_switch_segments'],2)

    def test_cross_cpu_delivery_may_have_no_current_waker_reference(self):
        r=report();next(e for e in r['records'] if e['stage']==29)['value']=0
        self.assertTrue(validate(r)['stream_quality_passed'])
        next(e for e in r['records'] if e['stage']==29)['value']=999
        self.assertFalse(validate(r)['stream_quality_passed'])

    def test_return_may_follow_resumption_without_dereferencing_waiter(self):
        r=report(True)
        for e in r['records']:
            if e['stage']==11:e['time_ns']=183
            if e['stage']==25:e['time_ns']=193
            if e['stage']==9:e['time_ns']=195
        v=validate(r);self.assertTrue(v['stream_quality_passed']);self.assertEqual(v['wait_return_after_caller_resumed'],1)


class HandoffLoader(unittest.TestCase):
    def test_exact_scheduler_entry_clock_sites_preserve_proof_emit_time(self):
        root=Path(__file__).resolve().parents[1]/'bench';original=(root/'folio_wait_lineage.bpf.c').read_text();s=folio_extension(original)
        self.assertEqual(s.count('__u64 hook_entry_ns=bpf_ktime_get_ns();'),3)
        self.assertEqual(s.count('fw_emit(&c,stage,0,0,hook_entry_ns);'),2)
        self.assertIn('cv_vector_edge(folio,call.c.id,bio_id);',s)
        self.assertIn('fw_emit(&call.c,FW_MATCH_BEGIN,bit,call.flags,bpf_ktime_get_ns());',s)
        self.assertIn('FW_SWITCH_OUT,ctx->args[3],!!ctx->args[0],hook_entry_ns)',s)
        self.assertIn('FW_SWITCH_IN,0,0,hook_entry_ns)',s)
        with self.assertRaises(ValueError):folio_extension(original.replace('__u64 state,__u64 preempt){','__u64 state){'))
        vector=vector_extension((root/'combined_wait.bpf.c').read_text());self.assertIn('cv_vector_edge',vector);self.assertNotIn('combined_folio.generated.h',vector)
        with self.assertRaises(ValueError):vector_extension(vector)

    def test_versioned_loader_and_fragmented_readiness(self):
        root=Path(__file__).resolve().parents[1]/'bench';source=(root/'read_lineage.c').read_text();s=generate(source)
        self.assertIn(r'\"schema_version\":2',s);self.assertIn('hook-entry-v1',s);self.assertIn('#define PROGRAMS 28',s)
        ids=list(range(1,29));line=b'BC250_HANDOFF_WAIT_READY '+json.dumps(dict(program_ids=ids)).encode()+b'\n'
        for n in range(len(line)):self.assertIsNone(ready_ids(line[:n]))
        self.assertEqual(ready_ids(line),ids)
        with self.assertRaises(ValueError):ready_ids(line.replace(b'[1, 2,',b'[1, 1,'))


if __name__=='__main__':unittest.main()
