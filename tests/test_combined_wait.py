"""Actual vector evidence must bridge both graphs, never coincident timing."""
import copy
import json
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'analysis'))
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'bench'))
import test_request_bio_lineage as requests
from combined_wait import validate
from combined_wait_loader import generate,folio_extension,ready_ids


class CombinedWait(unittest.TestCase):
    def report(self):
        r=requests.RequestBioLineage().report()
        def row(i,p,s,t,value=0,aux=0,result=0,flags=0):return dict(id=i,parent=p,stage=s,time_ns=t,value=value,aux=aux,result=result,flags=flags)
        r['records'] += [row(20,4,24,172,2,flags=0xf0000),row(20,4,25,178,2,flags=0xf0000),
            row(21,4,26,125,2),row(22,4,27,182),row(23,4,28,174,20),row(24,4,29,175,20),row(20,2,30,171,0,4096,1<<32)]
        vc=[0]*16;vc[0]=vc[1]=vc[8]=1
        r.update(kind='bc250-combined-wait-diagnostic',wait_counters=[0]*16,vector_counters=vc,vector_proof_enabled=True,folio_proof_enabled=True,pending_contexts=[0]*13)
        r['events']=r['counters'][0]=len(r['records']);return r

    def test_actual_vector_links_split_member_reports_to_blocked_reader(self):
        r=self.report();before=copy.deepcopy(r);v=validate(r);self.assertEqual(r,before)
        self.assertTrue(v['stream_quality_passed']);self.assertTrue(v['selected_worker_request_folio_wait_edges_qualified'])
        self.assertEqual((v['actual_vector_edges'],v['request_backed_matched_wakes'],v['resolved_request_folio_blocked_segments']),(1,1,1))
        self.assertEqual((v['request_issued_total_bytes'],v['request_reported_total_bytes']),(5120,5120))
        for name in ('whole_application_critical_path_qualified','minimal_hardware_service_time_qualified','overhead_qualified'):self.assertFalse(v[name])

    def test_old_range_proof_cannot_replace_actual_vector(self):
        r=self.report();r['records']=[e for e in r['records'] if e['stage']!=30];r['vector_counters'][1]=0;r['vector_counters'][7]=1
        r['vector_proof_enabled']=False;r['events']=r['counters'][0]=len(r['records'])
        v=validate(r);self.assertFalse(v['stream_quality_passed']);self.assertEqual(v['missing_vector_edges'],1)
        self.assertEqual(v['resolved_folio_blocked_segments'],1);self.assertEqual(v['resolved_request_folio_blocked_segments'],0)

    def test_vector_wrong_identity_offset_size_shape_or_time_refuses(self):
        for field,value in [('id',999),('parent',1),('value',1),('aux',4097),('result',0),('result',3<<32),('flags',2),('flags',8),('time_ns',169),('time_ns',173)]:
            with self.subTest(field=field,value=value):
                r=self.report();next(e for e in r['records'] if e['stage']==30)[field]=value
                with self.assertRaises(ValueError):validate(r)

    def test_duplicate_disabled_private_or_rounded_vector_refuses(self):
        for kind in ('duplicate','disabled','private','float'):
            r=self.report();e=next(e for e in r['records'] if e['stage']==30)
            if kind=='duplicate':r['records'].append(copy.deepcopy(e));r['events']=r['counters'][0]=len(r['records'])
            if kind=='disabled':r['vector_proof_enabled']=False
            if kind=='private':e['page_pointer']=123
            if kind=='float':e['result']=float(1<<32)
            with self.assertRaises(ValueError):validate(r)

    def test_every_vector_error_pending_and_prior_failure_remains_visible(self):
        for n in list(range(2,8))+list(range(13,16)):
            r=self.report();r['vector_counters'][n]=1;self.assertFalse(validate(r)['stream_quality_passed'])
        for n in range(13):
            r=self.report();r['pending_contexts'][n]=1;self.assertFalse(validate(r)['stream_quality_passed'])
        r=self.report();r['request_counters'][13]=1;self.assertFalse(validate(r)['stream_quality_passed'])
        r=self.report();r['wait_counters'][3]=1;self.assertFalse(validate(r)['stream_quality_passed'])
        r=self.report();r['counters'][0]+=1;r['counters'][1]+=1;self.assertFalse(validate(r)['stream_quality_passed'])

    def test_folio_proof_disabled_cannot_be_supplied_by_vector_flag(self):
        r=self.report();r['folio_proof_enabled']=False;r['records']=[e for e in r['records'] if e['stage'] not in (24,25,30)]
        for e in r['records']:
            if e['stage'] in (28,29):e['value']=0
        r['vector_counters']=[0]*16;r['events']=r['counters'][0]=len(r['records'])
        self.assertFalse(validate(r)['stream_quality_passed'])

    def test_delivery_and_anonymous_identity_collision_refuse(self):
        r=self.report();r['events']+=1
        with self.assertRaises(ValueError):validate(r)
        r=self.report()
        for e in r['records']:
            if e['id']==20:e['id']=8
            if e['stage'] in (28,29):e['value']=8
        with self.assertRaises(ValueError):validate(r)


class CombinedLoader(unittest.TestCase):
    def test_checked_composition_and_fragmented_readiness(self):
        root=Path(__file__).resolve().parents[1]/'bench';source=(root/'read_lineage.c').read_text()
        loader=generate(source);self.assertIn('#define PROGRAMS 29',loader);self.assertIn('cv_origins',loader)
        extension=folio_extension((root/'folio_wait_lineage.bpf.c').read_text());self.assertIn('FW_MATCH_BEGIN=24',extension)
        self.assertIn('cv_vector_edge(folio,call.c.id,bio_id);',extension)
        with self.assertRaises(ValueError):generate(source.replace('#define PROGRAMS 16','#define PROGRAMS 17'))
        with self.assertRaises(ValueError):folio_extension(extension)
        ids=list(range(1,30));line=b'BC250_COMBINED_WAIT_READY '+json.dumps(dict(program_ids=ids)).encode()+b'\n'
        for n in range(len(line)):self.assertIsNone(ready_ids(line[:n]))
        self.assertEqual(ready_ids(line),ids)
        with self.assertRaises(ValueError):ready_ids(line.replace(b'[1, 2,',b'[1, 1,'))


if __name__=='__main__':unittest.main()
