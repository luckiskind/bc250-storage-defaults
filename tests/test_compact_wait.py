"""Omitting informational records cannot waive the combined causal proofs."""
import copy
import json
from pathlib import Path
import re
import sys
import unittest
sys.path[:0]=[str(Path(__file__).resolve().parents[1]/n) for n in ('analysis','bench')]
import test_combined_wait as full_tests
from combined_wait import validate as full_validate
from compact_wait import validate
from compact_wait_loader import generate,ready_ids
from combined_wait_loader import generate as full_generate


def compact(raw):
    r=copy.deepcopy(raw);r.update(kind='bc250-compact-wait-diagnostic',unlock_hook_loaded=False)
    r['records']=[e for e in r['records'] if e['stage']!=12];removed=len(raw['records'])-len(r['records']);r['events']-=removed;r['counters'][0]-=removed;return r


class CompactWait(unittest.TestCase):
    def report(self):return compact(full_tests.CombinedWait().report())

    def test_same_causal_result_and_explicit_unavailable_unlock_count(self):
        original=full_tests.CombinedWait().report();expected=full_validate(original);raw=compact(original);saved=copy.deepcopy(raw);got=validate(raw)
        self.assertEqual(raw,saved);self.assertTrue(got['stream_quality_passed'])
        for k in expected:
            if k not in ('folio_unlock_calls','unparented_unlock_calls'):self.assertEqual(got[k],expected[k],k)
        self.assertIsNone(got['folio_unlock_calls']);self.assertIsNone(got['unparented_unlock_calls']);self.assertFalse(got['folio_unlock_count_available'])

    def test_omission_flag_cannot_be_missing_true_rounded_or_string(self):
        for value in (None,True,0,'false'):
            raw=self.report();raw['unlock_hook_loaded']=value
            with self.assertRaises(ValueError):validate(raw)
        raw=self.report();raw.pop('unlock_hook_loaded')
        with self.assertRaises(ValueError):validate(raw)

    def test_full_format_or_actual_unlock_record_is_not_compact(self):
        with self.assertRaises(ValueError):validate(full_tests.CombinedWait().report())
        raw=full_tests.CombinedWait().report();raw.update(kind='bc250-compact-wait-diagnostic',unlock_hook_loaded=False)
        with self.assertRaises(ValueError):validate(raw)

    def test_loss_pending_and_proof_errors_remain_disqualifying(self):
        for kind in ('loss','pending','request','vector','wait'):
            raw=self.report()
            if kind=='loss':raw['counters'][0]+=1;raw['counters'][1]+=1
            if kind=='pending':raw['pending_contexts'][12]=1
            if kind=='request':raw['request_counters'][13]=1
            if kind=='vector':raw['vector_counters'][5]=1
            if kind=='wait':raw['wait_counters'][3]=1
            self.assertFalse(validate(raw)['stream_quality_passed'])

    def test_range_proof_without_vector_still_fails(self):
        raw=self.report();raw['records']=[e for e in raw['records'] if e['stage']!=30];raw['events']=raw['counters'][0]=len(raw['records'])
        raw['vector_proof_enabled']=False;raw['vector_counters'][1]=0;raw['vector_counters'][7]=1
        got=validate(raw);self.assertFalse(got['stream_quality_passed']);self.assertEqual(got['missing_vector_edges'],1)

    def test_bad_actual_byte_coordinate_still_refuses(self):
        raw=self.report();next(e for e in raw['records'] if e['stage']==30)['value']=1
        with self.assertRaises(ValueError):validate(raw)

    def test_observed_early_waking_order_stays_unresolved_in_this_revision(self):
        # Synthetic reproduction of the newly observed ordering, without
        # publishing a private capture. All vector/request proofs still hold.
        raw=self.report()
        for e in raw['records']:
            if e['stage']==26:e['time_ns']=176
            if e['stage']==29:e.update(time_ns=179,value=0)
        got=validate(raw);self.assertTrue(got['transport_complete']);self.assertEqual(got['actual_vector_edges'],1)
        self.assertEqual(got['request_backed_matched_wakes'],1);self.assertEqual(got['unresolved_wait_edges'],1)
        self.assertFalse(got['stream_quality_passed']);self.assertEqual(got['proven_blocked_until_waking_union_ns'],0)


class CompactLoader(unittest.TestCase):
    def test_only_optional_hook_is_removed_and_reference_drift_refuses(self):
        source=(Path(__file__).resolve().parents[1]/'bench/read_lineage.c').read_text();before=full_generate(source);after=generate(source)
        pattern=r'const char \*names\[\]=\{([^;]+)\};';old=re.search(pattern,before)[1];new=re.search(pattern,after)[1]
        self.assertEqual(new,old.replace(',"unlock_call"',''));self.assertIn('#define PROGRAMS 28',after);self.assertIn('bpf_program__set_autoload(omitted,0)',after)
        with self.assertRaises(ValueError):generate(source.replace('"unlock_call"','"changed_hook"'))

    def test_complete_readiness_has_28_distinct_owned_ids(self):
        ids=list(range(1,29));line=b'BC250_COMPACT_WAIT_READY '+json.dumps(dict(program_ids=ids)).encode()+b'\n'
        for n in range(len(line)):self.assertIsNone(ready_ids(line[:n]))
        self.assertEqual(ready_ids(line),ids)
        with self.assertRaises(ValueError):ready_ids(line.replace(b'[1, 2,',b'[1, 1,'))


if __name__=='__main__':unittest.main()
