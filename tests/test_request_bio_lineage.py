"""Generation/member joins must retain unselected bytes and exact prefix order."""
import copy
import json
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'analysis'))
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'bench'))
import test_physical_bio_lineage as physical_tests
from request_bio_lineage import validate
from request_bio_loader import generate,ready_ids


class RequestBioLineage(unittest.TestCase):
    def report(self):
        r=physical_tests.PhysicalBioLineage().report(True)
        for e in r['records']:
            if e['id']==7 and e['stage']==16:e['time_ns']=121
        def row(i,p,s,t,n=0,aux=0,result=0,flags=0):return dict(id=i,parent=p,stage=s,time_ns=t,value=n,aux=aux,result=result,flags=flags)
        r['records'] += [row(8,0,17,116,5120,3,2),row(9,8,18,117,7,1024,flags=1),row(10,8,18,118,6,3072,flags=1),row(11,8,18,119,0,1024),
            row(9,8,21,120,1024,1024,flags=1),row(10,8,21,122,1024,3072,flags=1),row(10,8,21,124,2048,2048,flags=1),row(11,8,21,126,1024,1024),row(8,0,22,127,5120,1)]
        r.update(kind='bc250-request-bio-diagnostic',request_counters=[1,1,1,2,3,0,1]+[0]*17,pending_contexts=[0]*9,issue_proof_enabled=True)
        r['events']=r['counters'][0]=len(r['records']);return r

    def test_shared_request_preserves_selected_and_unselected_bytes(self):
        v=validate(self.report());self.assertTrue(v['stream_quality_passed'])
        self.assertEqual((v['request_generations'],v['issued_request_members'],v['selected_request_members'],v['unselected_request_members']),(1,3,2,1))
        self.assertEqual((v['request_reported_total_bytes'],v['selected_request_member_bytes']),(5120,4096))
        self.assertEqual(v['request_partial_member_chunks'],1);self.assertTrue(v['selected_physical_bio_request_generations_qualified'])
        self.assertFalse(v['merge_history_qualified']);self.assertFalse(v['broader_native_requeue_partial_reuse_qualified'])

    def test_partial_then_requeue_requires_matching_reissue(self):
        r=self.report()
        def event(s,issues):return dict(id=8,parent=0,stage=s,time_ns=123,value=3072,aux=issues,result=0,flags=0)
        r['records'] += [event(19,1),event(20,2)]
        next(e for e in r['records'] if e['stage']==22)['aux']=2;r['request_counters'][1]=2;r['request_counters'][5]=1
        r['events']=r['counters'][0]=len(r['records']);self.assertTrue(validate(r)['stream_quality_passed'])
        r['records']=[e for e in r['records'] if e['stage']!=20];r['events']=r['counters'][0]=len(r['records'])
        with self.assertRaises(ValueError):validate(r)

    def test_completion_cannot_skip_or_replace_the_issued_prefix(self):
        for kind in ('order','parent','bytes','remaining','selected'):
            r=self.report();e=next(e for e in r['records'] if e['stage']==21)
            if kind=='order':e['id']=10
            if kind=='parent':e['parent']=999
            if kind=='bytes':e['value']=1025
            if kind=='remaining':e['aux']=1023
            if kind=='selected':e['flags']=0
            with self.assertRaises(ValueError):validate(r)

    def test_issue_snapshot_must_match_request_and_physical_ranges(self):
        for kind in ('total','count','selected','physical','size','clock'):
            r=self.report();e=next(e for e in r['records'] if e['stage']==17);m=next(e for e in r['records'] if e['stage']==18)
            if kind=='total':e['value']=5121
            if kind=='count':e['aux']=4
            if kind=='selected':e['result']=1
            if kind=='physical':m['value']=999
            if kind=='size':m['aux']=1023
            if kind=='clock':e['time_ns']=109;m['time_ns']=110
            with self.assertRaises(ValueError):validate(r)

    def test_duplicate_generation_member_or_final_report_refuses(self):
        for stage in (17,18,22):
            r=self.report();e=copy.deepcopy(next(e for e in r['records'] if e['stage']==stage));e['time_ns']+=1;r['records'].append(e);r['events']=r['counters'][0]=len(r['records'])
            with self.assertRaises(ValueError):validate(r)

    def test_disabled_issue_proof_or_uncovered_bio_never_passes(self):
        r=self.report();r['issue_proof_enabled']=False
        with self.assertRaises(ValueError):validate(r)
        r=self.report();r['records']=[e for e in r['records'] if e['stage']<=16];r['request_counters']=[0]*24;r['events']=r['counters'][0]=len(r['records'])
        self.assertFalse(validate(r)['stream_quality_passed']);self.assertEqual(validate(r)['request_uncovered_physical_bios'],2)

    def test_status_pending_and_every_request_error_counter_fail_closed(self):
        for n in list(range(7,16))+list(range(17,24)):
            r=self.report();r['request_counters'][n]=1;self.assertFalse(validate(r)['stream_quality_passed'])
        r=self.report();r['pending_contexts'][8]=1;self.assertFalse(validate(r)['stream_quality_passed'])
        r=self.report();next(e for e in r['records'] if e['stage']==21)['result']=1;self.assertFalse(validate(r)['stream_quality_passed'])

    def test_counter_mismatch_and_unknown_fields_are_not_silently_waived(self):
        r=self.report();r['request_counters'][3]=3;self.assertFalse(validate(r)['stream_quality_passed'])
        r=self.report();r['records'][-1]['request_address']=1
        with self.assertRaises(ValueError):validate(r)
        r=self.report();r['records'][-1]['time_ns']=127.0
        with self.assertRaises(ValueError):validate(r)

    def test_loader_keeps_reference_frozen_and_waits_for_complete_readiness(self):
        source=(Path(__file__).resolve().parents[1]/'bench/read_lineage.c').read_text();self.assertIn('pr_requests',generate(source))
        with self.assertRaises(ValueError):generate(source.replace('#define PROGRAMS 16','#define PROGRAMS 17'))
        ids=list(range(1,25));line=b'BC250_REQUEST_BIO_READY '+json.dumps(dict(program_ids=ids)).encode()+b'\n'
        for n in range(len(line)):self.assertIsNone(ready_ids(line[:n]))
        self.assertEqual(ready_ids(line),ids)

    def recycled(self):
        r=self.report();second=copy.deepcopy(r['records'])
        for e in second:
            e['id']+=20
            if e['parent']:e['parent']+=20
            if e['stage']==18 and e['value']:e['value']+=20
            e['time_ns']+=220
        r['records']+=second+[dict(id=28,parent=8,stage=23,time_ns=336,value=0,aux=0,result=0,flags=0)]
        r['finish_ns']=420;r['detached_ns']=430;r['request_counters']=[v*2 for v in r['request_counters']];r['request_counters'][16]=1
        r['events']=r['counters'][0]=len(r['records']);return r

    def test_recycled_address_requires_a_distinct_closed_prior_generation(self):
        r=self.recycled();v=validate(r);self.assertTrue(v['stream_quality_passed']);self.assertEqual(v['request_address_reuses_with_changed_generation'],1)
        for parent in (0,28,999):
            r=self.recycled();next(e for e in r['records'] if e['stage']==23)['parent']=parent
            with self.assertRaises(ValueError):validate(r)
        r=self.recycled();r['records']=[e for e in r['records'] if not(e['id']==8 and e['stage']==22)];r['events']=r['counters'][0]=len(r['records'])
        with self.assertRaises(ValueError):validate(r)


if __name__=='__main__':unittest.main()
