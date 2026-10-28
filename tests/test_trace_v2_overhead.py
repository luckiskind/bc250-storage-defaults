"""A fixed paired calibration cannot omit bad captures or whole planned pairs."""
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'analysis'))
from trace_v2_overhead import summarize


class V2Overhead(unittest.TestCase):
    def contract(self):return dict(scenarios={'serial':{}},pairs_per_scenario=6,minimum_valid_pairs=5,seed=253,point_limit=.03,upper_interval_limit=.05)
    def rows(self):
        warm=[dict(scenario='serial',pair=-1,condition=c,warmup=True,environment_exclusions=[],capture_integrity=True,workload=dict(elapsed_ns=100)) for c in ('off','v2')]
        return warm+[dict(scenario='serial',pair=i,condition=c,warmup=False,environment_exclusions=[],capture_integrity=True,workload=dict(elapsed_ns=n))
            for i in range(6) for c,n in [('off',100),('v2',102)]]

    def test_fixed_known_effect(self):
        result=summarize(self.rows(),self.contract())
        self.assertTrue(result['fit_for_control_screen'])
        self.assertAlmostEqual(result['scenarios']['serial']['estimate']['geometric_overhead'],.02)

    def test_excluded_failure_still_disqualifies_with_enough_other_pairs(self):
        rows=self.rows();rows[3]['environment_exclusions']=['busy'];rows[3]['capture_integrity']=False
        result=summarize(rows,self.contract())['scenarios']['serial']
        self.assertTrue(result['minimum_pairs_met']);self.assertFalse(result['fit_for_control_screen'])
        self.assertEqual(result['capture_integrity_failed_pairs'],[dict(pair=0,conditions=['v2'])])

    def test_missing_entire_pair_and_duplicate_condition_rejected(self):
        rows=self.rows()
        with self.assertRaisesRegex(ValueError,'planned pair'):summarize(rows[:2]+rows[4:],self.contract())
        rows[3]['condition']='off'
        with self.assertRaisesRegex(ValueError,'paired condition'):summarize(rows,self.contract())

    def test_bad_or_missing_warmup_cannot_disappear(self):
        rows=self.rows();rows[1]['capture_integrity']=False
        result=summarize(rows,self.contract())['scenarios']['serial']
        self.assertEqual(result['warmup_capture_failures'],['v2']);self.assertFalse(result['fit_for_control_screen'])
        with self.assertRaisesRegex(ValueError,'warmup'):summarize(rows[1:],self.contract())

    def test_scenarios_do_not_pool_and_missing_scenario_refuses(self):
        rows=self.rows();contract=self.contract();contract['scenarios']['parallel']={}
        with self.assertRaisesRegex(ValueError,'scenario'):summarize(rows,contract)
        rows += [dict(row,scenario='parallel',workload=dict(elapsed_ns=110 if row['condition']=='v2' else 100)) for row in self.rows()]
        result=summarize(rows,contract)
        self.assertTrue(result['scenarios']['serial']['fit_for_control_screen']);self.assertFalse(result['scenarios']['parallel']['fit_for_control_screen'])
        self.assertFalse(result['fit_for_control_screen'])


if __name__=='__main__':unittest.main()
