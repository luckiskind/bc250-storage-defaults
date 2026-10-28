"""Paired exploratory overhead estimates; never an application speed claim."""
import math
import random
import statistics


def estimate(pairs,seed=250,draws=5000):
    if not pairs:raise ValueError('No valid pairs')
    ratios=[]
    for off,on in pairs:
        if off<=0 or on<=0:raise ValueError('Durations must be positive')
        ratios.append(math.log(on/off))
    rng=random.Random(seed);n=len(ratios)
    samples=sorted(math.exp(sum(rng.choices(ratios,k=n))/n)-1 for _ in range(draws))
    return dict(pairs=n,geometric_overhead=math.expm1(statistics.mean(ratios)),
        median_pair_overhead=math.expm1(statistics.median(ratios)),
        paired_percentile_95=[samples[int(.025*(draws-1))],samples[int(.975*(draws-1))]],
        bootstrap_draws=draws,bootstrap_seed=seed,
        interval_scope='Exploratory resampling of pairs; does not establish independence or application overhead')


def summarize(records,contract):
    result={}
    for scenario in contract['scenarios']:
        rows=[r for r in records if r['scenario']==scenario and not r['warmup']]
        pair_ids=sorted({r['pair'] for r in rows});valid=[];invalid=[];integrity=[]
        for pair in pair_ids:
            members=[r for r in rows if r['pair']==pair]
            if len(members)!=2 or {r['condition'] for r in members}!={'off','on'}:
                raise ValueError('Incomplete or duplicate pair')
            by={r['condition']:r for r in members}
            issues=sorted({reason for r in members for reason in r['environment_exclusions']})
            if any(not r['capture_integrity'] for r in members):integrity.append(pair)
            if issues:invalid.append(dict(pair=pair,reasons=issues));continue
            if all(r['capture_integrity'] for r in members):
                valid.append((by['off']['workload']['elapsed_ns'],by['on']['workload']['elapsed_ns']))
        stats=estimate(valid,seed=contract['seed']) if valid else None
        enough=len(valid)>=contract['minimum_valid_pairs']
        fit=bool(stats and enough and not integrity and stats['geometric_overhead']<=contract['point_limit']
            and stats['paired_percentile_95'][1]<=contract['upper_interval_limit'])
        result[scenario]=dict(estimate=stats,environment_excluded_pairs=invalid,
            capture_integrity_failed_pairs=integrity,minimum_pairs_met=enough,fit_for_control_screen=fit)
    return dict(scenarios=result,fit_for_control_screen=all(r['fit_for_control_screen'] for r in result.values()),
        application_tracing_qualified=False,stage1_gate_passed=False)
