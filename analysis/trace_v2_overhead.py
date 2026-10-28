"""Fixed paired v2 control screen; preserve missing blocks and every failure."""
from trace_overhead import estimate


def summarize(records,contract):
    scenarios=set(contract['scenarios'])
    if {r['scenario'] for r in records}!=scenarios:raise ValueError('Missing/unexpected scenario')
    result={}
    for scenario in sorted(scenarios):
        rows=[r for r in records if r['scenario']==scenario and not r['warmup']]
        warmup=[r for r in records if r['scenario']==scenario and r['warmup']]
        if len(warmup)!=2 or {r['condition'] for r in warmup}!={'off','v2'} or any(r['pair']!=-1 for r in warmup):
            raise ValueError('Missing/duplicate warmup condition')
        expected=set(range(contract['pairs_per_scenario']))
        if {r['pair'] for r in rows}!=expected:raise ValueError('Missing/unexpected planned pair')
        valid=[];excluded=[];failed=[];durations=[]
        for pair in sorted(expected):
            group=[r for r in rows if r['pair']==pair]
            if len(group)!=2 or {r['condition'] for r in group}!={'off','v2'}:raise ValueError('Missing/duplicate paired condition')
            reasons=sorted({reason for r in group for reason in r['environment_exclusions']})
            bad=[r['condition'] for r in group if not r['capture_integrity']]
            if bad:failed.append(dict(pair=pair,conditions=bad))
            if reasons:excluded.append(dict(pair=pair,reasons=reasons))
            if not reasons and not bad:
                by={r['condition']:r['workload']['elapsed_ns'] for r in group}
                durations.append((by['off'],by['v2']));valid.append(pair)
        warmup_bad=[r['condition'] for r in warmup if not r['capture_integrity']]
        value=estimate(durations,seed=contract['seed']) if durations else None
        enough=len(valid)>=contract['minimum_valid_pairs']
        fit=bool(enough and not failed and not warmup_bad and value
            and value['geometric_overhead']<=contract['point_limit'] and value['paired_percentile_95'][1]<=contract['upper_interval_limit'])
        result[scenario]=dict(valid_pairs=valid,minimum_pairs_met=enough,environment_excluded_pairs=excluded,
            capture_integrity_failed_pairs=failed,warmup_capture_failures=warmup_bad,estimate=value,fit_for_control_screen=fit)
    return dict(scenarios=result,fit_for_control_screen=all(r['fit_for_control_screen'] for r in result.values()),
        application_tracing_qualified=False,stage1_gate_passed=False,
        scope='Two direct-read synthetic controls on one fixture, fixed paired experiment; no application overhead or accelerator gain')
