"""Do not turn application envelopes into foreground attribution or waive loss."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'analysis'))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'bench'))
import test_request_trace_v2 as samples
from application_trace_v2 import review_capture
if sys.platform == 'linux':
    import qualify_application_trace_v2 as driver


class ApplicationReview(unittest.TestCase):
    def data(self):
        return (samples.TraceV2().report(), dict(start_ns=95, finish_ns=190),
            dict(passed=True, normal_close_verified=True, owned_terminal_gone=True, cpu_policy_unchanged=True,
                 before=dict(monotonic_ns=100), after=dict(monotonic_ns=150)))

    def test_clean_capture_keeps_device_totals_distinct_from_demand_and_wait(self):
        result = review_capture(*self.data())
        self.assertTrue(result['capture_integration_passed'])
        self.assertEqual(result['device_read_bytes_inside_snapshot_envelope'], 4096)
        self.assertFalse(result['device_bytes_are_foreground_demand'])
        self.assertFalse(result['critical_path_wait_qualified'])
        self.assertFalse(result['endpoint_latency_used_as_performance_result'])

    def test_late_start_early_finish_or_bad_nesting_cannot_pass(self):
        for field, value in [('start_ns', 89), ('finish_ns', 201)]:
            raw, envelope, trial = self.data()
            envelope[field] = value
            self.assertFalse(review_capture(raw, envelope, trial)['capture_integration_passed'])
        raw, envelope, trial = self.data()
        trial['after']['monotonic_ns'] = 191
        self.assertFalse(review_capture(raw, envelope, trial)['capture_integration_passed'])

    def test_loss_or_unclosed_context_and_failed_cleanup_stay_disqualifying(self):
        for field in ('return_contexts', 'right_censored_requests'):
            raw, envelope, trial = self.data()
            raw[field] = 1
            self.assertFalse(review_capture(raw, envelope, trial)['capture_integration_passed'])
        for field in ('passed', 'normal_close_verified', 'owned_terminal_gone', 'cpu_policy_unchanged'):
            raw, envelope, trial = self.data()
            trial[field] = False
            self.assertFalse(review_capture(raw, envelope, trial)['capture_integration_passed'])

    def test_crossing_request_is_counted_separately_and_not_prorated(self):
        raw, envelope, trial = self.data()
        trial['before']['monotonic_ns'] = 120
        result = review_capture(raw, envelope, trial)
        self.assertEqual(result['device_requests_crossing_snapshot_envelope'], 1)
        self.assertEqual(result['device_read_bytes_inside_snapshot_envelope'], 0)

    def test_invalid_or_boolean_envelope_refuses(self):
        for field, value in [('start_ns', True), ('start_ns', 190), ('finish_ns', 0)]:
            raw, envelope, trial = self.data()
            envelope[field] = value
            with self.assertRaises(ValueError):
                review_capture(raw, envelope, trial)


@unittest.skipUnless(sys.platform == 'linux', 'Linux fixture adapter')
class AdapterGuards(unittest.TestCase):
    def test_only_exact_native_view_child_is_rerouted(self):
        target = Path('/private/adapter.py')
        command = ['unshare', '--mount', '--propagation', 'private', 'python3',
                   str(Path(driver.native.__file__).resolve()), '_view', '--output', '/private/test']
        result = driver.view_command(command, target)
        self.assertEqual(result[5], str(target))
        self.assertEqual(result[6:], command[6:])
        for other in [['/usr/bin/firefox'], command[:6] + ['run'], ['sh', '-c', 'echo nope']]:
            self.assertEqual(driver.view_command(other, target), other)

    def test_failed_cache_precondition_never_attaches_and_extra_calls_refuse(self):
        gate = driver.CaptureGate(Path('/private'), Path('/desktop'), Path('/dev/nvme0n1'),
            lambda: dict(resident_bytes=4096, page_rounded_bytes=4096))
        with patch.object(driver.observer, 'start') as start:
            with self.assertRaisesRegex(RuntimeError, 'cache condition'):
                gate()
            start.assert_not_called()
            gate.index = 4
            with self.assertRaisesRegex(RuntimeError, 'final phase'):
                gate()
            start.assert_not_called()


if __name__ == '__main__':
    unittest.main()
