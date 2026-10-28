"""Wake-function witness must be actual, unique, and bound before switch-out."""
import copy,json
from pathlib import Path
import sys,unittest
sys.path[:0]=[str(Path(__file__).resolve().parents[1]/n) for n in ('analysis','bench')]
import test_handoff_wait as handoff
from wake_witness import validate
from wake_witness_loader import generate,ready_ids


def report(early=False):
    r=handoff.report(early)
    next(e for e in r['records'] if e['stage']==29)['time_ns']=179
    def row(stage,time,aux=0,result=0):return dict(id=100,parent=4,value=20,aux=aux,result=result,stage=stage,time_ns=time,flags=0)
    r['records'] += [row(31,173,1,3),row(33,174,1,175),row(32,177,1,1)]
    r.update(kind='bc250-wake-witness-diagnostic',witness_enabled=True,witness_counters=[1,1,1]+[0]*13)
    r['pending_contexts'].append(0);handoff.recount(r);return r


class WakeWitness(unittest.TestCase):
    def test_normal_and_early_with_real_attempt_structure(self):
        for early in (False,True):
            r=report(early);saved=copy.deepcopy(r);v=validate(r)
            self.assertEqual(r,saved);self.assertTrue(v['stream_quality_passed']);self.assertEqual(v['wake_function_attempts'],1)
            self.assertEqual(v['early_wake_overlap_witness_segments'],int(early))
            self.assertEqual(v['early_wake_overlap_independently_witnessed'],early)
            self.assertIsNone(v['early_wake_storage_blocked_ns']);self.assertFalse(v['hardware_wait_duration_qualified'])

    def test_on_cpu_zero_or_snapshot_after_out_cannot_prove_early_overlap(self):
        for field,value in [('aux',0),('result',176)]:
            r=report(True);next(e for e in r['records'] if e['stage']==33)[field]=value
            v=validate(r);self.assertFalse(v['stream_quality_passed']);self.assertEqual(v['early_wake_overlap_witness_missing'],1)

    def test_normal_wake_does_not_require_target_still_on_cpu(self):
        r=report();next(e for e in r['records'] if e['stage']==33)['aux']=0
        self.assertTrue(validate(r)['stream_quality_passed'])

    def test_missing_disabled_failed_or_lost_witness_stays_unqualified(self):
        for kind in ('missing','disabled','failure','loss','pending','counter'):
            r=report(True)
            if kind=='missing':r['records']=[e for e in r['records'] if e['stage']!=33];r['witness_counters'][2]=0;handoff.recount(r)
            if kind=='disabled':r['witness_enabled']=False
            if kind=='failure':next(e for e in r['records'] if e['stage']==32)['result']=0
            if kind=='loss':r['counters'][0]+=1;r['counters'][1]+=1
            if kind=='pending':r['pending_contexts'][13]=1
            if kind=='counter':r['witness_counters'][3]=1
            self.assertFalse(validate(r)['stream_quality_passed'],kind)

    def test_bad_identity_callback_bounds_snapshot_or_private_field_refuses(self):
        for field,value in [('parent',999),('value',999),('time_ns',171),('aux',2),('result',0)]:
            r=report(True);next(e for e in r['records'] if e['stage']==31)[field]=value
            with self.assertRaises(ValueError):validate(r)
        r=report();next(e for e in r['records'] if e['stage']==33)['task_address']=123
        with self.assertRaises(ValueError):validate(r)
        r=report();next(e for e in r['records'] if e['stage']==33)['result']=178
        with self.assertRaises(ValueError):validate(r)

    def test_duplicate_function_attempt_is_ambiguous(self):
        r=report(True);r['records'] += [dict(e,id=101) for e in r['records'] if e['stage']>30]
        r['witness_counters'][:3]=[2,2,2];handoff.recount(r)
        self.assertFalse(validate(r)['stream_quality_passed'])

    def test_unbacked_causal_proof_still_fails_even_with_on_cpu_witness(self):
        r=report(True);r['vector_counters'][5]=1
        v=validate(r);self.assertFalse(v['stream_quality_passed']);self.assertFalse(v['early_wake_overlap_independently_witnessed'])


class WitnessLoader(unittest.TestCase):
    def test_three_witness_probes_and_fourteen_context_maps(self):
        source=(Path(__file__).resolve().parents[1]/'bench/read_lineage.c').read_text();s=generate(source)
        self.assertIn('#define PROGRAMS 31',s);self.assertIn('unsigned pending[14]',s);self.assertIn('tw_waking',s);self.assertIn('witness_option',s)
        with self.assertRaises(ValueError):generate(source.replace('"unlock_call"','"other"'))

    def test_fragmented_readiness_never_accepts_partial_or_repeated_ids(self):
        ids=list(range(1,32));line=b'BC250_WAKE_WITNESS_READY '+json.dumps(dict(program_ids=ids)).encode()+b'\n'
        for n in range(len(line)):self.assertIsNone(ready_ids(line[:n]))
        self.assertEqual(ready_ids(line),ids)
        with self.assertRaises(ValueError):ready_ids(line.replace(b'[1, 2,',b'[1, 1,'))


if __name__=='__main__':unittest.main()
