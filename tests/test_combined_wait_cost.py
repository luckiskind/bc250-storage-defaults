"""A quality failure cannot disappear into exclusions or a shortened schedule."""
import copy
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'analysis'))
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'bench'))
from combined_wait_cost import CONTRACT,planned_order,summarize
if sys.platform=='linux':import measure_combined_wait_cost as driver


class CombinedCost(unittest.TestCase):
    def rows(self):return [dict(item,workload=dict(elapsed_ns=100000000),capture_integrity=True,environment_exclusions=[]) for item in planned_order()]

    def test_fixed_200_trial_order_is_balanced_and_reproducible(self):
        order=planned_order();self.assertEqual(len(order),200);self.assertEqual(order,planned_order())
        for scenario in CONTRACT['scenarios']:
            first=[r['condition'] for r in order if r['scenario']==scenario and not r['warmup']][::2]
            self.assertEqual(first.count('off'),12);self.assertEqual(first.count('combined'),12)

    def test_clean_result_is_only_a_selected_worker_cost_screen(self):
        r=summarize(self.rows(),CONTRACT);self.assertTrue(r['fit_for_selected_worker_screen']);self.assertEqual(r['instrumented_trials'],100)
        for k in ('application_tracing_qualified','absolute_wrapper_cost_qualified','whole_application_critical_path_qualified','accelerator_gain_comparison','stage1_gate_passed','pair_independence_established'):self.assertFalse(r[k])

    def test_missing_duplicate_or_reordered_schedule_refuses(self):
        for kind in ('missing','duplicate','reorder'):
            rows=self.rows()
            if kind=='missing':rows.pop()
            elif kind=='duplicate':rows[3]=copy.deepcopy(rows[2])
            else:rows[2],rows[3]=rows[3],rows[2]
            with self.assertRaises(ValueError):summarize(rows,CONTRACT)

    def test_environment_exclusion_never_hides_a_quality_failure(self):
        rows=self.rows();rows[2]['environment_exclusions']=['pre-workload-device-busy'];rows[3]['capture_integrity']=False
        r=summarize(rows,CONTRACT);v=r['scenarios']['plain-read'];self.assertFalse(r['fit_for_selected_worker_screen'])
        self.assertEqual(len(v['valid_pairs']),23);self.assertEqual(len(v['capture_integrity_failed_pairs']),1);self.assertEqual(len(v['environment_excluded_pairs']),1)

    def test_failed_warmup_is_disqualifying(self):
        rows=self.rows();rows[0]['capture_integrity']=False;r=summarize(rows,CONTRACT)
        self.assertFalse(r['fit_for_selected_worker_screen']);self.assertEqual(r['scenarios']['plain-read']['warmup_capture_failures'],['off'])

    def test_too_few_valid_pairs_cannot_pass_zero_overhead(self):
        rows=self.rows()
        for r in rows:
            if r['scenario']=='plain-read' and r['pair'] in range(5):r['environment_exclusions']=['pre-workload-cpu-busy']
        result=summarize(rows,CONTRACT);self.assertFalse(result['fit_for_selected_worker_screen']);self.assertEqual(len(result['scenarios']['plain-read']['valid_pairs']),19)

    def test_real_measured_regression_fails_without_adaptive_extension(self):
        rows=self.rows()
        for r in rows:
            if r['condition']=='combined':r['workload']['elapsed_ns']=110000000
        result=summarize(rows,CONTRACT);self.assertFalse(result['fit_for_selected_worker_screen'])
        self.assertAlmostEqual(result['scenarios']['plain-read']['estimate']['geometric_overhead'],.1)

    def test_rounded_boolean_nonpositive_and_quality_types_refuse(self):
        for bad in (0,-1,True,1.5):
            rows=self.rows();rows[2]['workload']['elapsed_ns']=bad
            with self.assertRaises(ValueError):summarize(rows,CONTRACT)
        rows=self.rows();rows[2]['capture_integrity']=1
        with self.assertRaises(ValueError):summarize(rows,CONTRACT)


@unittest.skipUnless(sys.platform=='linux','Linux private trial environment')
class CombinedEnvironment(unittest.TestCase):
    def test_same_io_policy_and_throttle_rules_apply_to_both_arms(self):
        quiet=dict(cpu=[0]*8,disk=[0]*17,memory=dict(MemAvailable=4*2**30),cpu_policies={},cgroup_cpu_stat='nr_throttled 0\n')
        before=copy.deepcopy(quiet);before['cpu'][3]=100;after=copy.deepcopy(before)
        after['disk'][2]=CONTRACT['timed_read_bytes_max']//512+1;after['disk'][6]=CONTRACT['timed_write_bytes_max']//512+1
        after['cgroup_cpu_stat']='nr_throttled 1\n';after['cpu_policies']=dict(policy0=dict(scaling_governor='changed'))
        reasons,value=driver.exclusions(quiet,before,after)
        self.assertEqual(set(reasons),{'timed-global-read-bound','timed-global-write-bound','parent-cgroup-cpu-throttled','cpu-policy-changed'})
        self.assertEqual(value['pre_workload_cpu_fraction'],0);self.assertEqual(value['parent_cgroup_throttled_periods_delta'],1)
        after['disk'][2]=-1
        with self.assertRaises(ValueError):driver.exclusions(quiet,before,after)


if __name__=='__main__':unittest.main()
