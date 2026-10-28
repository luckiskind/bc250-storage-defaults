"""Balance all three arms and retain block-wide failures and exclusions."""
import copy
from collections import Counter
import itertools
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.path[:0]=[str(Path(__file__).resolve().parents[1]/n) for n in ('analysis','bench')]
from compact_wait_cost import CONTRACT,planned_order,summarize
if sys.platform=='linux':import measure_compact_wait_cost as driver


class CompactCost(unittest.TestCase):
    def rows(self):return [dict(r,workload=dict(elapsed_ns=100000000),capture_integrity=True,environment_exclusions=[]) for r in planned_order()]

    def test_300_trials_balance_every_permutation_and_each_direct_order(self):
        order=planned_order();self.assertEqual(order,planned_order());self.assertEqual(len(order),300)
        for scenario in CONTRACT['scenarios']:
            rows=[r for r in order if r['scenario']==scenario and not r['warmup']]
            perms=Counter(tuple(r['condition'] for r in rows[i:i+3]) for i in range(0,len(rows),3))
            self.assertEqual(perms,Counter({p:4 for p in itertools.permutations(CONTRACT['conditions'])}))
            self.assertEqual(sum(p.index('full')<p.index('compact') for p in perms.elements()),12)

    def test_clean_result_has_only_scoped_absolute_cost_qualification(self):
        r=summarize(self.rows(),CONTRACT);self.assertTrue(r['compact_fit_for_selected_worker_screen']);self.assertTrue(r['full_fit_for_selected_worker_screen']);self.assertEqual(r['instrumented_trials'],200)
        for k in ('application_tracing_qualified','absolute_wrapper_cost_qualified','whole_application_critical_path_qualified','accelerator_gain_comparison','stage1_gate_passed','historical_results_pooled','pair_independence_established'):self.assertFalse(r[k])
        self.assertEqual(r['scenarios']['plain-read']['direct_compact_full_direction'],'unresolved')

    def test_direct_ratio_is_contemporaneous_and_separate_from_absolute_cost(self):
        rows=self.rows()
        for r in rows:
            if r['condition']=='full':r['workload']['elapsed_ns']=120000000
            if r['condition']=='compact':r['workload']['elapsed_ns']=102000000
        result=summarize(rows,CONTRACT);self.assertTrue(result['compact_fit_for_selected_worker_screen']);self.assertFalse(result['full_fit_for_selected_worker_screen'])
        v=result['scenarios']['plain-read'];self.assertAlmostEqual(v['estimates']['compact_over_full']['geometric_overhead'],-.15)
        self.assertAlmostEqual(v['estimates']['compact_over_off']['geometric_overhead'],.02);self.assertEqual(v['direct_compact_full_direction'],'compact-faster')

    def test_missing_duplicate_reordered_or_replaced_arm_refuses(self):
        for kind in ('missing','duplicate','reorder','arm'):
            rows=self.rows()
            if kind=='missing':rows.pop()
            elif kind=='duplicate':rows[4]=copy.deepcopy(rows[3])
            elif kind=='reorder':rows[3],rows[4]=rows[4],rows[3]
            else:rows[4]['condition']='unknown'
            with self.assertRaises(ValueError):summarize(rows,CONTRACT)

    def test_one_arm_environment_excludes_whole_block_for_all_ratios(self):
        rows=self.rows();rows[3]['environment_exclusions']=['pre-workload-device-busy'];v=summarize(rows,CONTRACT)['scenarios']['plain-read']
        self.assertEqual(len(v['valid_blocks']),23);self.assertEqual(len(v['environment_excluded_blocks']),1)
        self.assertEqual({e['pairs'] for e in v['estimates'].values()},{23})

    def test_failed_capture_is_not_hidden_by_an_exclusion(self):
        rows=self.rows();rows[3]['environment_exclusions']=['pre-workload-cpu-busy'];rows[4]['capture_integrity']=False
        r=summarize(rows,CONTRACT);self.assertFalse(r['compact_fit_for_selected_worker_screen']);self.assertFalse(r['full_fit_for_selected_worker_screen'])
        self.assertEqual(len(r['scenarios']['plain-read']['capture_integrity_failed_blocks']),1)

    def test_failed_warmup_is_disqualifying_for_the_three_arm_screen(self):
        rows=self.rows();rows[1]['capture_integrity']=False;r=summarize(rows,CONTRACT)
        self.assertFalse(r['compact_fit_for_selected_worker_screen']);self.assertEqual(r['scenarios']['plain-read']['warmup_capture_failures'],['full'])

    def test_five_excluded_blocks_prevent_a_pass_even_with_zero_overhead(self):
        rows=self.rows()
        for r in rows:
            if r['scenario']=='plain-read' and r['pair'] in range(5):r['environment_exclusions']=['pre-workload-device-busy']
        r=summarize(rows,CONTRACT);self.assertEqual(len(r['scenarios']['plain-read']['valid_blocks']),19);self.assertFalse(r['compact_fit_for_selected_worker_screen'])

    def test_invalid_endpoint_duration_refuses(self):
        for bad in (0,-1,True,1.5):
            rows=self.rows();rows[3]['workload']['elapsed_ns']=bad
            with self.assertRaises(ValueError):summarize(rows,CONTRACT)


@unittest.skipUnless(sys.platform=='linux','Linux shared native trial body')
class ArmDispatch(unittest.TestCase):
    def test_correct_reader_and_startup_are_bound_without_mutating_reference(self):
        original=driver.frozen.observer
        for arm in ('off','full','compact'):
            item=dict(scenario='plain-read',pair=0,condition=arm,warmup=False)
            def stub(area,device,expected,inventory,transformed):
                obs=driver.frozen.observer;self.assertTrue(callable(obs.base.line));self.assertTrue(callable(obs.start));self.assertTrue(callable(obs.validate))
                self.assertIs(obs,driver.COMPACT_OBSERVER if arm=='compact' else original)
                self.assertEqual(transformed['condition'],'off' if arm=='off' else 'combined');return dict(transformed),b'raw',b'log'
            with patch.object(driver.frozen,'trial',stub):
                row,_,_=driver.trial(None,None,None,None,item);self.assertEqual(row['condition'],arm)
            self.assertIs(driver.frozen.observer,original)


if __name__=='__main__':unittest.main()
