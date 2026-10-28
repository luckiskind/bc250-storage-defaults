"""Three-arm blocked comparison: absolute cost and direct compact/full ratio."""
import copy
import itertools
import random
from combined_wait_cost import CONTRACT as FULL_CONTRACT
from trace_overhead import estimate

CONTRACT=copy.deepcopy(FULL_CONTRACT)
CONTRACT.update(version=2,seed=256,conditions=['off','full','compact'],warmup_trials_per_scenario=3,parent_runtime_seconds=1800,
    hypothesis='Compact retains all causal proof and meets the unchanged absolute cost limits; its direct ratio to full is measured in the same blocks',
    ordering='All six three-arm permutations occur four times per scenario, shuffled before collection',
    exclusion_scope='Whole block across all three arms; every capture failure remains disqualifying independently of exclusions',
    scope='Four cold selected-worker endpoints, contemporaneous off/full/compact; not application overhead or accelerator gain')


def planned_order(contract=CONTRACT):
    if contract['conditions']!=['off','full','compact'] or contract['pairs_per_scenario']%6:raise ValueError('Three arms and complete balanced permutations required')
    rng=random.Random(contract['seed']);order=[]
    for scenario in contract['scenarios']:
        order.extend(dict(scenario=scenario,pair=-1,condition=c,warmup=True) for c in contract['conditions'])
        blocks=list(itertools.permutations(contract['conditions']))*(contract['pairs_per_scenario']//6);rng.shuffle(blocks)
        for pair,arms in enumerate(blocks):order.extend(dict(scenario=scenario,pair=pair,condition=c,warmup=False) for c in arms)
    return order


def summarize(rows,contract):
    expected=planned_order(contract)
    if len(rows)!=len(expected) or any({k:r[k] for k in item}!=item for r,item in zip(rows,expected)):raise ValueError('Incomplete/reordered three-arm collection')
    for r in rows:
        if type(r['workload']['elapsed_ns']) is not int or r['workload']['elapsed_ns']<=0 or type(r['capture_integrity']) is not bool:raise ValueError('Invalid three-arm endpoint/quality')
        if not isinstance(r['environment_exclusions'],list) or any(type(s) is not str for s in r['environment_exclusions']):raise ValueError('Invalid three-arm exclusions')
    results={}
    for scenario in contract['scenarios']:
        selected=[r for r in rows if r['scenario']==scenario];valid=[];excluded=[];failed=[];data={c:[] for c in ('full_over_off','compact_over_off','compact_over_full')}
        warmup_bad=[r['condition'] for r in selected if r['warmup'] and not r['capture_integrity']]
        for pair in range(contract['pairs_per_scenario']):
            group=[r for r in selected if r['pair']==pair and not r['warmup']]
            reasons=sorted({reason for r in group for reason in r['environment_exclusions']});bad=[r['condition'] for r in group if not r['capture_integrity']]
            if reasons:excluded.append(dict(pair=pair,reasons=reasons))
            if bad:failed.append(dict(pair=pair,conditions=bad))
            if not reasons and not bad:
                by={r['condition']:r['workload']['elapsed_ns'] for r in group};valid.append(pair)
                for name,a,b in [('full_over_off','off','full'),('compact_over_off','off','compact'),('compact_over_full','full','compact')]:data[name].append((by[a],by[b]))
        values={name:estimate(pairs,seed=contract['seed'],draws=contract['bootstrap_draws']) if pairs else None for name,pairs in data.items()}
        clean=not failed and not warmup_bad;enough=len(valid)>=contract['minimum_valid_pairs']
        def fit(v):return bool(clean and enough and v and v['geometric_overhead']<=contract['point_limit'] and v['paired_percentile_95'][1]<=contract['upper_interval_limit'])
        direct=values['compact_over_full'];direction='unresolved'
        if clean and enough and direct:
            if direct['paired_percentile_95'][1]<0:direction='compact-faster'
            elif direct['paired_percentile_95'][0]>0:direction='compact-slower'
        results[scenario]=dict(valid_blocks=valid,environment_excluded_blocks=excluded,capture_integrity_failed_blocks=failed,
            warmup_capture_failures=warmup_bad,minimum_blocks_met=enough,estimates=values,
            full_fit_for_selected_worker_screen=fit(values['full_over_off']),compact_fit_for_selected_worker_screen=fit(values['compact_over_off']),
            direct_compact_full_direction=direction)
    return dict(scenarios=results,total_trials=len(rows),instrumented_trials=sum(r['condition']!='off' for r in rows),
        full_fit_for_selected_worker_screen=all(v['full_fit_for_selected_worker_screen'] for v in results.values()),
        compact_fit_for_selected_worker_screen=all(v['compact_fit_for_selected_worker_screen'] for v in results.values()),
        historical_results_pooled=False,application_tracing_qualified=False,absolute_wrapper_cost_qualified=False,
        whole_application_critical_path_qualified=False,accelerator_gain_comparison=False,stage1_gate_passed=False,
        pair_independence_established=False,scope=contract['scope'])
