"""Lineage proof cannot be replaced by coincident timing or an inode number."""
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'analysis'))
from read_lineage import validate,union_ns


class ReadLineage(unittest.TestCase):
    def report(self):
        def row(identity,parent,stage,time,value=4096,result=0,flags=0):
            return dict(id=identity,parent=parent,stage=stage,time_ns=time,value=value,aux=0,result=result,flags=flags)
        rows=[row(1,0,1,100,result=1),row(1,0,2,190,result=4096,flags=1),
              *[row(2,1,s,t) for s,t in [(3,110),(4,111),(5,130),(8,170),(9,180)]],
              row(3,2,6,135),row(3,2,7,165),row(4,1,10,120,value=0),row(4,1,11,185,value=0),row(5,2,12,175,value=0)]
        counts=[0]*16;counts[0]=len(rows)
        return dict(schema_version=1,kind='bc250-read-lineage-diagnostic',libbpf='v1.7.0',start_ns=90,finish_ns=200,detached_ns=210,
            events=len(rows),malformed=0,discarded=0,interrupted=False,limit_reached=False,counters=counts,pending_contexts=[0]*5,
            records=rows,links_detached=True,maps_pinned=False,critical_path_attribution_qualified=False,overhead_qualified=False)

    def test_graph_keeps_lineage_and_wait_claims_separate(self):
        result=validate(self.report());self.assertTrue(result['stream_quality_passed'])
        self.assertEqual((result['original_data_bios'],result['compressed_original_bios'],result['decompression_spans']),(1,1,1))
        self.assertEqual(result['buffered_read_returned_bytes'],4096)
        self.assertEqual(result['io_schedule_interval_union_ns'],65)
        self.assertFalse(result['io_schedule_wall_time_is_storage_critical_path'])
        self.assertFalse(result['decompression_cpu_time_qualified'])

    def test_overlap_uses_union_not_sum(self):
        self.assertEqual(union_ns([(10,30),(20,40),(12,15),(50,60)]),40)

    def test_warm_fault_around_is_a_distinct_demand_kind(self):
        value=self.report();value['records']=value['records'][:2];value['events']=value['counters'][0]=2
        value['records'][0]['result']=3;value['records'][1]['flags']=3;value['records'][1]['result']=256
        result=validate(value);self.assertTrue(result['stream_quality_passed'])
        self.assertEqual(result['fault_around_attempts'],1);self.assertEqual(result['filemap_fault_attempts'],0)

    def test_missing_or_wrong_parent_rejects_complete_graph(self):
        for parent in (0,999,1):
            value=self.report()
            for row in value['records']:
                if row['id']==3:row['parent']=parent
            with self.assertRaises(ValueError):validate(value)

    def test_sleep_and_decompression_must_nest_in_their_actual_parent(self):
        for identity,time in [(3,175),(4,195),(5,181)]:
            value=self.report()
            for row in value['records']:
                if row['id']==identity and row['stage'] in (7,11,12):row['time_ns']=time
            with self.assertRaises(ValueError):validate(value)

    def test_duplicate_lifecycle_or_private_identity_field_refuses(self):
        value=self.report();value['records'][0]['inode_pointer']=123
        with self.assertRaises(ValueError):validate(value)
        value=self.report();value['records'].append(dict(value['records'][0]));value['events']+=1;value['counters'][0]+=1
        with self.assertRaises(ValueError):validate(value)

    def test_loss_pending_or_unknown_selected_bio_is_not_waived(self):
        value=self.report();value['counters'][0]+=1;value['counters'][1]+=1
        self.assertFalse(validate(value)['stream_quality_passed'])
        value=self.report();value['pending_contexts'][1]=1
        self.assertFalse(validate(value)['stream_quality_passed'])
        value=self.report();value['counters'][5]=1
        self.assertFalse(validate(value)['stream_quality_passed'])

    def test_rounded_clocks_boolean_ids_and_unsupported_claims_refuse(self):
        value=self.report();value['records'][0]['id']=True
        with self.assertRaises(ValueError):validate(value)
        value=self.report();value['start_ns']=90.0
        with self.assertRaises(ValueError):validate(value)
        value=self.report();value['critical_path_attribution_qualified']=True
        with self.assertRaises(ValueError):validate(value)

    def test_cap_is_explicit_and_partial_objects_remain_visible(self):
        value=self.report();value['records']=value['records'][:1];value['events']=1;value['counters'][0]=1;value['limit_reached']=True
        result=validate(value);self.assertFalse(result['transport_complete']);self.assertEqual(result['partial_objects'],1)


if __name__=='__main__':unittest.main()
