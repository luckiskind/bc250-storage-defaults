"""Program accounting must preserve ownership, ABI, windows and failures."""
import copy
from pathlib import Path
import sys,unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'analysis'))
from probe_cost import analyze


def samples():
    owned=[dict(id=i+1,name='probe_'+str(i)) for i in range(28)];rows=[]
    for i,item in enumerate(owned):
        before=dict(begin_ns=110+i,end_ns=140+i,run_time_ns=100,run_cnt=2,recursion_misses=0,
            id=item['id'],name=item['name'],type=26,info_length=256,xlated_bytes=128)
        after=dict(before,begin_ns=700+i,end_ns=730+i,run_time_ns=200+i,run_cnt=5)
        rows.append(dict(before=before,after=after))
    return rows,owned


class ProbeCost(unittest.TestCase):
    def test_exact_deltas_are_diagnostic_not_latency_or_foreground_claims(self):
        rows,owned=samples();saved=copy.deepcopy(rows);v=analyze(rows,owned,100,900,(200,600))
        self.assertEqual(rows,saved);self.assertTrue(v['accounting_quality_passed'])
        self.assertEqual(v['aggregate_owned_runtime_ns'],sum(100+i for i in range(28)))
        self.assertEqual(v['aggregate_owned_invocations'],84)
        self.assertTrue(v['profiling_overhead_present']);self.assertFalse(v['simultaneous_snapshots']);self.assertFalse(v['endpoint_speed_comparison'])

    def test_count_reset_overflow_boolean_and_unknown_fields_refuse(self):
        for kind in ('reset','overflow','boolean','private'):
            rows,owned=samples();s=rows[0]['after']
            if kind=='reset':s['run_cnt']=1
            if kind=='overflow':s['run_time_ns']=2**64
            if kind=='boolean':s['run_cnt']=True
            if kind=='private':s['kernel_address']=123
            with self.assertRaises(ValueError):analyze(rows,owned,100,900)

    def test_identity_abi_or_program_set_change_refuses(self):
        for field,value in [('id',999),('name','unrelated'),('info_length',128),('type',17),('xlated_bytes',256)]:
            rows,owned=samples();rows[0]['after'][field]=value
            with self.assertRaises(ValueError):analyze(rows,owned,100,900)
        rows,owned=samples();rows[-1]=copy.deepcopy(rows[0])
        with self.assertRaises(ValueError):analyze(rows,owned,100,900)
        rows,owned=samples()
        with self.assertRaises(ValueError):analyze(rows[:-1],owned,100,900)

    def test_stats_window_and_endpoint_must_be_enclosed_for_every_program(self):
        for field,value in [('begin_ns',99),('end_ns',1000)]:
            rows,owned=samples();rows[0]['before'][field]=value
            with self.assertRaises(ValueError):analyze(rows,owned,100,900)
        rows,owned=samples()
        with self.assertRaises(ValueError):analyze(rows,owned,100,900,(150,600))
        with self.assertRaises(ValueError):analyze(rows,owned,100,900,(200,710))

    def test_recursion_misses_remain_visible_and_disqualifying(self):
        rows,owned=samples();rows[0]['after']['recursion_misses']=1
        v=analyze(rows,owned,100,900);self.assertFalse(v['accounting_quality_passed']);self.assertEqual(v['recursion_misses'],1)

    def test_unsupported_zero_runtime_count_combination_refuses(self):
        rows,owned=samples();rows[0]['after']['run_cnt']=2
        with self.assertRaises(ValueError):analyze(rows,owned,100,900)


if __name__=='__main__':unittest.main()
