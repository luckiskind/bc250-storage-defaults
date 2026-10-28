"""Task destruction cannot manufacture a successful context close."""
import copy
from pathlib import Path
import sys,unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'analysis'))
from task_context import validate


def report():
    def row(i,t,s,time,value=0):return dict(id=i,token=t,stage=s,time_ns=time,observed_ns=time,value=value,aux=0,result=0,flags=1)
    rows=[row(1,1,1,110),row(2,2,1,115),row(1,1,3,120,2),row(2,2,3,125,2),row(1,1,5,140),row(1,1,6,145),row(1,1,4,150),row(1,1,2,160),row(2,2,5,165),row(2,2,6,170),row(2,2,4,175),row(2,2,2,180)]
    c=[0]*16;c[0]=len(rows);c[2]=c[3]=c[4]=c[5]=c[9]=c[10]=2
    return dict(kind='bc250-task-context-feature',schema_version=1,start_ns=100,finish_ns=200,detached_ns=210,events=len(rows),discarded=0,malformed=0,
        interrupted=False,limit_reached=False,creation_enabled=True,controlled_markers=False,pending_expected=0,threads_seen=2,
        task_storage_iteration_result=-1,task_storage_iteration_errno=524,counters=c,records=rows,links_detached=True,maps_pinned=False,causal_attribution_qualified=False,observer_cost_qualified=False)


class TaskContext(unittest.TestCase):
    def test_two_task_contexts_preserve_identity_and_complete_independently(self):
        r=report();saved=copy.deepcopy(r);v=validate(r);self.assertEqual(r,saved);self.assertTrue(v['stream_quality_passed'])
        self.assertEqual((v['threads_observed'],v['max_simultaneous_contexts'],v['blocked_switch_outs']),(2,2,2))
        self.assertFalse(v['io_causality_qualified']);self.assertFalse(v['observer_cost_qualified'])

    def test_automatic_task_storage_free_does_not_close_expected_contexts(self):
        r=report();r['records']=[e for e in r['records'] if e['stage']!=2];r['events']=r['counters'][0]=len(r['records']);r['counters'][3]=r['counters'][5]=0
        r['pending_expected']=r['counters'][11]=2
        v=validate(r);self.assertTrue(v['transport_complete']);self.assertFalse(v['contexts_complete']);self.assertFalse(v['stream_quality_passed']);self.assertEqual(v['partial_contexts'],2)

    def test_creation_omission_and_lookup_mismatch_stay_disqualifying(self):
        r=report();r['creation_enabled']=False;r['counters'][4]=r['counters'][5]=0
        for e in r['records']:
            e['flags']=0
            if e['stage']==2:e['result']=-2
        self.assertFalse(validate(r)['stream_quality_passed'])
        r=report();r['counters'][6]=1;self.assertFalse(validate(r)['stream_quality_passed'])

    def test_lost_cap_pending_and_error_counters_are_not_waived(self):
        for kind in ('lost','cap','pending','error'):
            r=report()
            if kind=='lost':r['counters'][0]+=1;r['counters'][1]+=1
            if kind=='cap':r['limit_reached']=True
            if kind=='pending':r['pending_expected']=1
            if kind=='error':r['counters'][7]=1
            self.assertFalse(validate(r)['stream_quality_passed'],kind)

    def test_changed_identity_private_fields_and_clock_inversion_refuse(self):
        for kind in ('token','private','clock','duplicate'):
            r=report()
            if kind=='token':r['records'][2]['token']=99
            if kind=='private':r['records'][2]['task_pointer']=123
            if kind=='clock':r['records'][2].update(time_ns=109,observed_ns=109)
            if kind=='duplicate':r['records'].append(copy.deepcopy(r['records'][0]));r['events']=r['counters'][0]=len(r['records'])
            with self.assertRaises(ValueError):validate(r)

    def test_marker_control_cannot_claim_io_causality(self):
        r=report();r['controlled_markers']=True;v=validate(r)
        self.assertTrue(v['stream_quality_passed']);self.assertTrue(v['controlled_markers']);self.assertFalse(v['io_causality_qualified'])

    def test_lookup_brackets_may_overlap_publication_without_inventing_point_order(self):
        r=report();r['records'][2].update(time_ns=109,observed_ns=112)
        self.assertTrue(validate(r)['stream_quality_passed'])
        r['records'][2]['observed_ns']=108
        with self.assertRaises(ValueError):validate(r)


if __name__=='__main__':unittest.main()
