"""Pairing and failed-capture rules cannot turn missing data into a fast result."""
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'analysis'))
from trace_overhead import estimate,summarize


class OverheadEstimates(unittest.TestCase):
    def test_known_constant_ratio_and_scale_invariance(self):
        a=estimate([(10,12),(100,120),(1000,1200)])
        b=estimate([(100,120),(1000,1200),(10000,12000)])
        self.assertAlmostEqual(a['geometric_overhead'],.2)
        self.assertEqual(a['paired_percentile_95'],b['paired_percentile_95'])
        for value in a['paired_percentile_95']:self.assertAlmostEqual(value,.2)

    def records(self):
        return [dict(scenario='control',pair=i,condition=c,warmup=False,environment_exclusions=[],
            capture_integrity=True,workload=dict(elapsed_ns=100)) for i in range(8) for c in ('off','on')]

    def contract(self):return dict(scenarios=['control'],seed=250,minimum_valid_pairs=6,point_limit=.03,upper_interval_limit=.05)

    def test_one_broken_capture_cannot_be_discarded_to_pass(self):
        rows=self.records();self.assertTrue(summarize(rows,self.contract())['fit_for_control_screen'])
        rows[1]['capture_integrity']=False;rows[1]['workload']['elapsed_ns']=1
        result=summarize(rows,self.contract())
        self.assertFalse(result['fit_for_control_screen'])
        self.assertEqual(result['scenarios']['control']['capture_integrity_failed_pairs'],[0])

    def test_duplicate_condition_cannot_be_averaged_into_a_pair(self):
        rows=self.records();rows[1]['condition']='off'
        with self.assertRaisesRegex(ValueError,'pair'):summarize(rows,self.contract())


if __name__=='__main__':unittest.main()
