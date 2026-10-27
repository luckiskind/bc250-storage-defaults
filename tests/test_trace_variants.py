"""Reject incomplete blocks and preserve a failed condition in the verdict."""
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'analysis'))
from trace_variants import summarize


class VariantComparison(unittest.TestCase):
    def rows(self):
        return [dict(pair=i,condition=c,warmup=False,environment_exclusions=[],capture_integrity=True,
            workload=dict(elapsed_ns=value)) for i in range(6) for c,value in [('off',100),('raw',110),('batched',102)]]

    def contract(self):return dict(blocks=6,minimum_valid_blocks=5,seed=250,point_limit=.03,upper_interval_limit=.05)

    def test_shared_blocks_recover_known_effects(self):
        result=summarize(self.rows(),self.contract())
        self.assertAlmostEqual(result['comparisons']['batched_over_off']['geometric_overhead'],.02)
        self.assertAlmostEqual(result['comparisons']['batched_over_raw']['geometric_overhead'],102/110-1)
        self.assertEqual(result['fit_for_control_screen'],dict(raw=False,batched=True))

    def test_failed_excluded_condition_cannot_disappear(self):
        rows=self.rows();rows[2]['capture_integrity']=False;rows[2]['environment_exclusions']=['busy']
        result=summarize(rows,self.contract())
        self.assertEqual(result['valid_blocks'],[1,2,3,4,5])
        self.assertFalse(result['fit_for_control_screen']['batched'])
        self.assertEqual(result['capture_screen_failed_blocks'],[dict(block=0,conditions=['batched'])])

    def test_missing_entire_block_or_duplicate_condition_is_rejected(self):
        rows=self.rows()
        with self.assertRaisesRegex(ValueError,'planned block'):summarize(rows[3:],self.contract())
        rows[2]['condition']='raw'
        with self.assertRaisesRegex(ValueError,'condition'):summarize(rows,self.contract())


if __name__=='__main__':unittest.main()
