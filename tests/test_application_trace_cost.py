"""Freeze paired order and keep all quality failures independently of exclusion."""
import copy
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'analysis'))
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'bench'))
from application_trace_cost import CONTRACT, planned_order, summarize
if sys.platform=='linux':import measure_application_trace_cost as driver


class CostContract(unittest.TestCase):
    def rows(self):
        return [dict(item,workload=dict(elapsed_ns=100000000),environment_exclusions=[],capture_integrity=True)
                for item in planned_order()]

    def test_complete_order_is_balanced_and_reproducible(self):
        order=planned_order();self.assertEqual(len(order),100);self.assertEqual(order,planned_order())
        for scenario in CONTRACT['scenarios']:
            first=[r['condition'] for r in order if r['scenario']==scenario and not r['warmup']][::2]
            self.assertEqual(first.count('off'),12);self.assertEqual(first.count('v2'),12)

    def test_clean_result_only_qualifies_incremental_selected_fixture_cost(self):
        result=summarize(self.rows(),CONTRACT)
        self.assertTrue(result['fit_for_selected_application_screen'])
        self.assertTrue(result['selected_konsole_incremental_tracing_cost_qualified'])
        for field in ('application_tracing_qualified','absolute_wrapper_cost_qualified','foreground_attribution_qualified','stage1_gate_passed'):
            self.assertFalse(result[field])

    def test_missing_reordered_or_duplicate_conditions_refuse(self):
        for kind in ('missing','reorder','duplicate'):
            rows=self.rows()
            if kind=='missing':rows.pop()
            elif kind=='reorder':rows[2],rows[3]=rows[3],rows[2]
            else:rows[3]=copy.deepcopy(rows[2])
            with self.assertRaises(ValueError):summarize(rows,CONTRACT)

    def test_excluded_pair_does_not_hide_a_capture_failure(self):
        rows=self.rows();rows[2]['environment_exclusions']=['pre-workload-device-busy'];rows[3]['capture_integrity']=False
        result=summarize(rows,CONTRACT);value=result['scenarios']['selected-data-cold']
        self.assertEqual(value['capture_integrity_failed_pairs'],[dict(pair=0,conditions=[rows[3]['condition']])])
        self.assertEqual(len(value['valid_pairs']),23);self.assertFalse(result['fit_for_selected_application_screen'])

    def test_failed_warmup_remains_disqualifying(self):
        rows=self.rows();rows[0]['capture_integrity']=False
        result=summarize(rows,CONTRACT)
        self.assertEqual(result['scenarios']['selected-data-cold']['warmup_capture_failures'],['off'])
        self.assertFalse(result['fit_for_selected_application_screen'])

    def test_invalid_endpoint_duration_refuses(self):
        for value in (0,-1,True,1.5):
            rows=self.rows();rows[2]['workload']['elapsed_ns']=value
            with self.assertRaises(ValueError):summarize(rows,CONTRACT)


@unittest.skipUnless(sys.platform=='linux','Linux root/desktop broker')
class CostProtocol(unittest.TestCase):
    def test_wrong_peer_nonce_phase_or_extra_field_refuses(self):
        good=dict(nonce='owned',phase='measure-0-before');expected=dict(pid=123,uid=1000)
        driver.admit((123,1000,1000),good,expected,'owned','measure-0-before')
        for peer,message in [((124,1000,1000),good),((123,1001,1000),good),
            ((123,1000,1000),dict(good,nonce='wrong')),((123,1000,1000),dict(good,phase='measure-0-after')),
            ((123,1000,1000),dict(good,path='/etc/passwd'))]:
            with self.assertRaises(RuntimeError):driver.admit(peer,message,expected,'owned','measure-0-before')

    def test_protocol_has_exact_outer_cache_and_per_trial_boundaries(self):
        plan=driver.protocol(planned_order());self.assertEqual(len(plan),204)
        self.assertEqual(plan[0],('cold-before',None,'outer'))
        self.assertEqual(plan[101],('cold-after',None,'outer'))
        self.assertEqual(plan[102],('warm-before',None,'outer'))
        self.assertEqual(plan[-1],('warm-after',None,'outer'))
        self.assertEqual(len(set(p[0] for p in plan)),204)

    def test_environment_policy_and_throttle_are_explicit_exclusions(self):
        quiet=dict(cpu=[0]*8,disk=[0]*17,memory=dict(MemAvailable=4*2**30),cpu_policies={},cgroup_cpu_stat='nr_throttled 0\n')
        before=copy.deepcopy(quiet);before['cpu'][3]=100
        after=copy.deepcopy(before);after['cgroup_cpu_stat']='nr_throttled 1\n'
        after['cpu_policies']=dict(policy0=dict(scaling_governor='changed'))
        reasons,busy,pre,throttle=driver.exclusions(quiet,before,after)
        self.assertEqual(set(reasons),{'parent-cgroup-cpu-throttled','cpu-policy-changed'})
        self.assertEqual((busy,pre,throttle),(0,0,1))


if __name__=='__main__':unittest.main()
