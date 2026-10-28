"""Physical byte partitions and callback proof must survive adversarial graphs."""
import copy
import json
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'analysis'))
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'bench'))
import test_read_lineage as logical_tests
from physical_bio_lineage import validate
from physical_bio_loader import generate,ready_ids


class PhysicalBioLineage(unittest.TestCase):
    def report(self,split=False):
        r=logical_tests.ReadLineage().report();r.update(kind='bc250-physical-bio-diagnostic',physical_counters=[1]+[0]*15,
            pending_contexts=[0]*7,callback_identity_witnessed=True,callback_proof_enabled=True)
        def row(i,p,s,t,n=4096,offset=0,result=0,flags=257):
            return dict(id=i,parent=p,stage=s,time_ns=t,value=n,aux=offset,result=result,flags=flags)
        r['records'] += [row(6,2,13,112,flags=1),row(6,2,15,113),row(6,2,16,125,n=3072 if split else 4096,offset=1024 if split else 0)]
        if split:r['records'] += [row(7,6,14,115,1024,result=4096),row(7,6,16,123,1024)]
        r['events']=r['counters'][0]=len(r['records']);return r

    def test_unsplit_and_inherited_device_split_conserve_bytes(self):
        for split in (False,True):
            r=validate(self.report(split));self.assertTrue(r['stream_quality_passed'])
            self.assertEqual(r['physical_completed_bytes'],4096);self.assertEqual(r['split_child_bios'],int(split))
            self.assertTrue(r['selected_original_to_physical_bio_edges_qualified'])
            self.assertFalse(r['physical_bio_request_edges_qualified']);self.assertFalse(r['overhead_qualified'])

    def test_split_before_device_boundary_requires_both_device_edges(self):
        r=self.report(True)
        for e in r['records']:
            if e['id']==7 and e['stage']==14:e.update(time_ns=113,flags=1)
            if e['id']==6 and e['stage']==15:e.update(time_ns=114,value=3072,aux=1024)
        self.assertFalse(validate(r)['stream_quality_passed'])
        r['records'].append(dict(id=7,parent=6,stage=15,time_ns=114,value=1024,aux=0,result=0,flags=257));r['events']=r['counters'][0]=len(r['records'])
        self.assertTrue(validate(r)['stream_quality_passed'])

    def test_missing_callback_witness_or_disabled_proof_never_passes(self):
        r=self.report();r['callback_identity_witnessed']=False;self.assertFalse(validate(r)['stream_quality_passed'])
        r=self.report();r['callback_proof_enabled']=False
        with self.assertRaises(ValueError):validate(r)

    def test_missing_physical_edges_remain_unknown(self):
        r=self.report();r['records']=[x for x in r['records'] if x['stage']<=12];r['events']=r['counters'][0]=len(r['records'])
        v=validate(r);self.assertFalse(v['stream_quality_passed']);self.assertEqual(v['uncovered_original_bios'],1)

    def test_inconsistent_split_parent_size_offset_or_type_refuses(self):
        for field,value in [('parent',999),('result',4095),('aux',512),('value',4096),('flags',256)]:
            r=self.report(True);next(x for x in r['records'] if x['stage']==14)[field]=value
            with self.assertRaises(ValueError):validate(r)

    def test_reuse_extra_completion_or_duplicate_boundary_refuses(self):
        for stage in (13,15,16):
            r=self.report();e=copy.deepcopy(next(x for x in r['records'] if x['stage']==stage));e['time_ns']+=1;r['records'].append(e)
            r['events']=r['counters'][0]=len(r['records'])
            with self.assertRaises(ValueError):validate(r)

    def test_bad_byte_range_or_callback_order_refuses(self):
        for field,value in [('value',4095),('aux',512),('time_ns',131),('parent',1)]:
            r=self.report();next(x for x in r['records'] if x['stage']==16)[field]=value
            with self.assertRaises(ValueError):validate(r)

    def test_unknown_device_status_pending_or_counter_fail_closed(self):
        for kind in ('device','status','pending','counter'):
            r=self.report()
            if kind=='device':next(x for x in r['records'] if x['stage']==16)['flags']=1
            if kind=='status':next(x for x in r['records'] if x['stage']==16)['result']=1
            if kind=='pending':r['pending_contexts'][5]=1
            if kind=='counter':r['physical_counters'][2]=1
            self.assertFalse(validate(r)['stream_quality_passed'])

    def test_all_error_and_reserved_counters_fail_but_background_counts_do_not(self):
        for n in range(1,16):
            r=self.report();r['physical_counters'][n]=1
            self.assertEqual(validate(r)['stream_quality_passed'],n in (12,13))

    def test_delivery_unknown_fields_and_rounded_values_refuse(self):
        for kind in ('delivery','private','float'):
            r=self.report()
            if kind=='delivery':r['events']+=1
            if kind=='private':r['records'][-1]['address']=1
            if kind=='float':r['records'][-1]['value']=4096.0
            with self.assertRaises(ValueError):validate(r)

    def test_derived_loader_refuses_reference_drift(self):
        source=(Path(__file__).resolve().parents[1]/'bench/read_lineage.c').read_text()
        self.assertIn('BC250_PHYSICAL_SEED_READY',generate(source))
        with self.assertRaises(ValueError):generate(source.replace('#define PROGRAMS 16','#define PROGRAMS 17'))

    def test_readiness_waits_for_complete_pipe_line_and_distinct_owned_ids(self):
        ids=list(range(1,23));line=b'BC250_PHYSICAL_BIO_READY '+json.dumps(dict(program_ids=ids)).encode()+b'\n'
        for n in range(len(line)):self.assertIsNone(ready_ids(b'BC250_PHYSICAL_SEED_READY\n'+line[:n]))
        self.assertEqual(ready_ids(line),ids)
        with self.assertRaises(ValueError):ready_ids(line.replace(b'[1, 2,',b'[1, 1,'))


if __name__=='__main__':unittest.main()
