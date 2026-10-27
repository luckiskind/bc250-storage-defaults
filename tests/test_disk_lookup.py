"""Keep the original observer immutable and every failed capture disqualifying."""
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'analysis'))
from disk_lookup import summarize


class DiskLookupComparison(unittest.TestCase):
    def contract(self):return dict(blocks=6,minimum_valid_blocks=5,seed=252,point_limit=.03,upper_interval_limit=.05)
    def rows(self):
        return [dict(pair=i,condition=c,warmup=False,environment_exclusions=[],capture_integrity=True,
            workload=dict(elapsed_ns=v)) for i in range(6) for c,v in [('off',100),('raw',110),('shared',102)]]

    def test_known_effect_and_comparison_are_preserved(self):
        value=summarize(self.rows(),self.contract())
        self.assertAlmostEqual(value['comparisons']['shared_over_off']['geometric_overhead'],.02)
        self.assertAlmostEqual(value['comparisons']['shared_over_raw']['geometric_overhead'],102/110-1)
        self.assertEqual(value['fit_for_control_screen'],dict(raw=False,shared=True))

    def test_failed_condition_stays_disqualifying_when_block_is_excluded(self):
        rows=self.rows();rows[2]['capture_integrity']=False;rows[2]['environment_exclusions']=['busy']
        value=summarize(rows,self.contract())
        self.assertTrue(value['minimum_blocks_met']);self.assertFalse(value['fit_for_control_screen']['shared'])
        self.assertEqual(value['capture_screen_failed_blocks'],[dict(block=0,conditions=['shared'])])

    def test_missing_blocks_or_duplicate_conditions_refuse(self):
        rows=self.rows()
        with self.assertRaisesRegex(ValueError,'planned block'):summarize(rows[3:],self.contract())
        rows[2]['condition']='raw'
        with self.assertRaisesRegex(ValueError,'condition'):summarize(rows,self.contract())

    @unittest.skipUnless(sys.platform=='linux','Frozen observer source derivation imports Linux controls')
    def test_derivation_cannot_silently_replace_drifted_or_multiple_anchors(self):
        sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'bench'))
        from qualify_shared_disk import derive,OLD,NEW
        source=(Path(__file__).resolve().parents[1]/'bench/request_trace.bpf.c').read_text()
        self.assertEqual(derive(source).replace(NEW,OLD),source)
        for text in (source.replace(OLD,''),source+'\n'+OLD):
            with self.assertRaisesRegex(ValueError,'frozen disk lookup'):derive(text)


if __name__=='__main__':unittest.main()
