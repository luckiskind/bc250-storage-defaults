"""Three-condition blocked comparison; preserve exclusions and failed screens."""
from trace_overhead import estimate


def summarize(rows,contract):
    measured=[r for r in rows if not r['warmup']]
    expected=set(range(contract['blocks']))
    if {r['pair'] for r in measured}!=expected:raise ValueError('Missing or unexpected planned block')
    valid=[];excluded=[];failed=[]
    for block in sorted(expected):
        group=[r for r in measured if r['pair']==block]
        if len(group)!=3 or {r['condition'] for r in group}!={'off','raw','shared'}:
            raise ValueError('Missing or duplicate block condition')
        reasons=sorted({reason for r in group for reason in r['environment_exclusions']})
        bad=[r['condition'] for r in group if not r['capture_integrity']]
        if bad:failed.append(dict(block=block,conditions=bad))
        if reasons:excluded.append(dict(block=block,reasons=reasons))
        if not reasons and not bad:valid.append((block,{r['condition']:r['workload']['elapsed_ns'] for r in group}))
    comparisons={}
    for numerator,denominator in [('raw','off'),('shared','off'),('shared','raw')]:
        comparisons[numerator+'_over_'+denominator]=estimate(
            [(r[denominator],r[numerator]) for _,r in valid],seed=contract['seed']) if valid else None
    enough=len(valid)>=contract['minimum_valid_blocks']
    screens={}
    for variant in ('raw','shared'):
        value=comparisons[variant+'_over_off']
        screens[variant]=bool(enough and not failed and value
            and value['geometric_overhead']<=contract['point_limit']
            and value['paired_percentile_95'][1]<=contract['upper_interval_limit'])
    relative=comparisons['shared_over_raw']
    return dict(valid_blocks=[block for block,_ in valid],minimum_blocks_met=enough,
        environment_excluded_blocks=excluded,capture_screen_failed_blocks=failed,comparisons=comparisons,
        fit_for_control_screen=screens,
        shared_relative_upper_interval_below_zero=bool(relative and relative['paired_percentile_95'][1]<0),
        application_tracing_qualified=False,stage1_gate_passed=False,
        scope='One synthetic serial workload, same physical fixture, exploratory blocked estimates; no accelerator gain')
