"""Review whole-device v2 captures against a conservative application envelope."""
from request_trace_v2 import validate


def review_capture(raw, envelope, trial):
    checked = validate(raw)
    start, finish = envelope['start_ns'], envelope['finish_ns']
    if not (type(start) is int and type(finish) is int and 0 < start < finish):
        raise ValueError('Invalid application envelope')
    before, after = trial['before']['monotonic_ns'], trial['after']['monotonic_ns']
    nested = start <= before < after <= finish
    covered = raw['start_ns'] <= start < finish <= raw['finish_ns']
    functional = bool(trial['passed'] and trial['normal_close_verified'] and trial['owned_terminal_gone']
                      and trial['cpu_policy_unchanged'])
    # Count only full ordinary requests inside the broad launch/ready envelope.
    # Boundary crossings are explicit, not silently assigned to the foreground.
    ordinary = [r for r in raw['records'] if r['event_class'] == 0]
    inside = [r for r in ordinary if before <= r['issue_ns'] <= r['complete_ns'] <= after and r['issue_ns']]
    crossing = [r for r in ordinary if r['issue_ns'] and r['issue_ns'] < after and r['complete_ns'] > before
                and not (before <= r['issue_ns'] <= r['complete_ns'] <= after)]
    return dict(capture_integration_passed=bool(checked['stream_quality_passed'] and nested and covered and functional),
        validation=checked, capture_covers_trial_envelope=covered, endpoint_snapshots_nested=nested,
        endpoint_functional_and_normal_close=functional, capture_events=raw['events'],
        trial_envelope_ns=finish-start, endpoint_snapshot_envelope_ns=after-before,
        device_read_bytes_inside_snapshot_envelope=sum(r['completed_bytes'] for r in inside if r['operation'] == 0),
        device_write_bytes_inside_snapshot_envelope=sum(r['completed_bytes'] for r in inside if r['operation'] == 1),
        device_requests_inside_snapshot_envelope=len(inside), device_requests_crossing_snapshot_envelope=len(crossing),
        right_censored_requests=raw['right_censored_requests'], return_contexts=raw['return_contexts'],
        software_tracking_enabled=raw['software_tracking_enabled'], internal_tracking_enabled=raw['internal_tracking_enabled'],
        device_bytes_are_foreground_demand=False, critical_path_wait_qualified=False,
        endpoint_latency_used_as_performance_result=False)
